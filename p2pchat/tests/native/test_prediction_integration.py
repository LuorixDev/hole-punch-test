"""Port prediction wired into the real attempt: sample exchange, simultaneous probe, hit.

Controlled loopback endpoints and scripted NAT models only. Neither a real home
symmetric NAT nor a real two-device run is claimed here (NOT_RUN).
"""
import asyncio
import json
import secrets
import socket
import struct
import uuid

import pytest

from p2pchat.native.adapter import (
    NAT_SAMPLES_TYPE,
    NativeAdapter,
    samples_digest,
    samples_proof,
    validate_samples_message,
)
from p2pchat.native.auth import Auth, packed
from p2pchat.native.stun import COOKIE
from p2pchat.tests.native.test_port_prediction import IncrementalAllocator, ScriptedStun, xor_attribute

ROOM = "test"
SECRET = "test-secret-128-bit"
PROBE_PREFIX = b"P2POBS1"
EXTERNAL_IP = "203.0.113.7"


def params(mechanism, role, cid, aid, timeout_ms=4000, prediction=True):
    local, remote = ("a", "b") if role == "offerer" else ("b", "a")
    return dict(connectionId=cid, attemptId=aid, peerId=remote, mechanism=mechanism,
                profile=mechanism, role=role, timeoutMs=timeout_ms, prediction=prediction,
                auth=dict(room=ROOM, localPeerId=local, secret=SECRET))


class EimAllocator:
    """Endpoint-independent model: one external port per local port."""

    def __init__(self, start=42000):
        self.next_port = start
        self.ports = {}

    def port_for(self, local, destination):
        if local not in self.ports:
            self.ports[local] = self.next_port
            self.next_port += 1
        return self.ports[local]


async def scripted_points(allocator, hosts=("127.0.0.1", "127.0.0.1")):
    loop = asyncio.get_running_loop()
    transports, responders = [], []
    for host in hosts:
        holder = {}

        def factory(holder=holder, host=host):
            holder["responder"] = ScriptedStun(allocator, (host, 0))
            return holder["responder"]

        transport, _ = await loop.create_datagram_endpoint(factory, local_addr=(host, 0))
        holder["responder"].address = (host, transport.get_extra_info("sockname")[1])
        transports.append(transport)
        responders.append(holder["responder"])
    points = tuple(responder.address for responder in responders)
    return transports, responders, points


class PeerMapping(asyncio.DatagramProtocol):
    """Stands in for the peer's NAT mapping at one predicted port (mirrors Auth)."""

    def __init__(self, peer_id="b", local_id="a", filter_name=None):
        self.peer_id, self.local_id = peer_id, local_id
        self.received = []
        self.greeted = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append(data)
        if not data.startswith(PROBE_PREFIX):
            return
        try:
            frame = json.loads(data[len(PROBE_PREFIX):])
        except ValueError:
            return
        auth = Auth(ROOM, SECRET, frame.get("connectionId"), frame.get("attemptId"),
                    self.peer_id, self.local_id)
        try:
            response = auth.receive(frame)
        except ValueError:
            return
        if frame.get("kind") == "hello":
            if response:
                self.transport.sendto(PROBE_PREFIX + packed(response), addr)
            if not self.greeted:
                self.greeted = True
                self.transport.sendto(PROBE_PREFIX + packed(auth.frame()), addr)


async def start_mapping(port=0, **kwargs):
    loop = asyncio.get_running_loop()
    responder = PeerMapping(**kwargs)
    transport, _ = await loop.create_datagram_endpoint(lambda: responder, local_addr=("127.0.0.1", port))
    return transport, responder, transport.get_extra_info("sockname")[1]


def prediction_config(points, enabled=True, **overrides):
    config = {"enabled": enabled, "points": list(points), "localPorts": 2, "repeats": 1, "timeout": .3,
              "limits": {"total_timeout": 2.0, "max_candidates": 4, "min_interval": .02,
                         "per_candidate_timeout": .1, "min_samples": 4}}
    config.update(overrides)
    return config


def dead_port():
    """A closed loopback port: stands in for a symmetric NAT dropping the signaled tuple."""
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


async def prediction_pair(points, enabled=True, mechanism="udp-probe", timeout_ms=4000, override_peer_port=None):
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    config = prediction_config(points, enabled)
    a = NativeAdapter("127.0.0.1", prediction=dict(config))
    b = NativeAdapter("127.0.0.1", prediction=dict(config))
    events = {"a": [], "b": []}
    a.subscribe(lambda kind, data: events["a"].append((kind, data)))
    b.subscribe(lambda kind, data: events["b"].append((kind, data)))
    await a.start(params(mechanism, "offerer", cid, aid, timeout_ms, enabled))
    await b.start(params(mechanism, "answerer", cid, aid, timeout_ms, enabled))
    for target, key, sender in ((a, "b", "b"), (b, "a", "a")):
        for kind, event in list(events[key]):
            if kind == "candidate":
                payload = {**event, "from": sender}
                if override_peer_port is not None and sender == "b":
                    payload["nativeCandidate"] = {**event["nativeCandidate"], "port": override_peer_port}
                await target.signal(payload)
    return a, b, aid, cid, events


async def wait_for(predicate, timeout=6):
    async with asyncio.timeout(timeout):
        while True:
            if predicate():
                return True
            await asyncio.sleep(.02)


def samples_message(connection, attempt, ports, sender="b", receiver="a", nonce=None,
                    proof=None, mechanism="udp-probe", destinations=None):
    payload = []
    for index, port in enumerate(ports):
        destination = (destinations or [("203.0.113.1", 3478)])[index % len(destinations or [("203.0.113.1", 3478)])]
        payload.append({"sequence": index, "localPort": 40001 + index,
                        "destination": [destination[0], destination[1]], "mappedPort": port})
    nonce = nonce or secrets.token_hex(24)
    digest = samples_digest(payload)
    value = proof if proof is not None else samples_proof(SECRET.encode(), ROOM, connection, attempt,
                                                          sender, receiver, nonce, digest)
    return {"v": 1, "type": NAT_SAMPLES_TYPE, "to": receiver, "connectionId": connection, "attemptId": attempt,
            "mechanism": mechanism, "profile": mechanism, "nonce": nonce, "proof": value, "samples": payload,
            "from": sender}


@pytest.mark.asyncio
async def test_default_disabled_contacts_no_observation_point_and_sends_nothing():
    allocator = IncrementalAllocator()
    transports, responders, points = await scripted_points(allocator)
    a = b = None
    try:
        a, b, aid, _, _ = await prediction_pair(points, enabled=False, timeout_ms=600)
        await asyncio.sleep(.3)
        assert a.attempts[aid].prediction["state"] == "disabled"
        assert a.attempts[aid].prediction["sends"] == 0
        assert all(responder.requests == 0 for responder in responders)
        capability = a.prediction_capability()
        assert capability["status"] == "disabled" and capability["enabled"] is False
        assert "端口预测" in capability["hitRateNote"] and "IPv6" in capability["hitRateNote"]
        assert capability["failureStates"] == ["NO_AUTHENTICATED_REPLY", "REPLIES_REJECTED",
                                               "DEADLINE_REACHED", "SEND_FAILED"]
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in transports:
            transport.close()


@pytest.mark.asyncio
async def test_samples_exchange_predicts_and_hits_the_predicted_port():
    allocator = IncrementalAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    mapping_transport, mapping, port = await start_mapping()
    third_transport, third, _ = await start_mapping()
    a = b = None
    try:
        # The peer's signaled tuple is unreachable (symmetric NAT): only prediction can hit.
        a, b, aid, connection, events = await prediction_pair(points, timeout_ms=5000,
                                                              override_peer_port=dead_port())
        attempt = a.attempts[aid]
        assert await wait_for(lambda: attempt.prediction["state"] == "waiting-samples"), attempt.prediction
        assert attempt.prediction["localSymmetric"] is True
        assert all(responder.requests > 0 for responder in responders)  # sampling really happened
        outbound = next(data["message"] for kind, data in events["a"] if kind == "prediction.samples")
        assert outbound["type"] == NAT_SAMPLES_TYPE and outbound["proof"] and len(outbound["samples"]) >= 4
        assert EXTERNAL_IP not in json.dumps(outbound)  # mapped addresses never travel

        # The peer's samples arrive signed; they predict the next ports after port-1.
        message = samples_message(connection, aid, [port - 4, port - 3, port - 2, port - 1])
        await a.prediction_signal({**message})
        assert attempt.peer_samples and len(attempt.peer_samples) == 4
        assert await wait_for(lambda: attempt.prediction["state"] == "hit", 6), attempt.stats()["prediction"]
        assert attempt.predicted_hit is True and attempt.selected is True
        stats = attempt.stats()
        assert stats["remoteCandidateType"] == "predicted-port"
        assert stats["remoteTuple"] == ["127.0.0.1", port]
        assert attempt.prediction["candidates"][0] == port
        assert attempt.prediction["sends"] <= 2 * len(attempt.prediction["candidates"])
        assert {target[0] for target in attempt.predicted_targets} == {"127.0.0.1"}
        assert mapping.received and mapping.greeted
        assert third.received == []  # only the signaled peer address is ever probed
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in (mapping_transport, third_transport, *stun_transports):
            transport.close()


@pytest.mark.asyncio
async def test_unpredictable_peer_samples_never_probe():
    allocator = IncrementalAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    mapping_transport, mapping, port = await start_mapping()
    a = b = None
    try:
        a, b, aid, connection, events = await prediction_pair(points, timeout_ms=3000)
        attempt = a.attempts[aid]
        assert await wait_for(lambda: attempt.prediction["state"] == "waiting-samples")
        random_ports = [1024 + index * 7000 for index in range(5)]
        await a.prediction_signal(samples_message(connection, aid, random_ports))
        assert await wait_for(lambda: attempt.prediction["state"] == "unpredictable"), attempt.prediction
        assert attempt.predicted_targets == {} and attempt.prediction["sends"] == 0
        assert mapping.received == []
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in (mapping_transport, *stun_transports):
            transport.close()


@pytest.mark.asyncio
async def test_non_symmetric_network_is_not_enabled():
    allocator = EimAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    mapping_transport, mapping, port = await start_mapping()
    a = b = None
    try:
        a, b, aid, connection, events = await prediction_pair(points, timeout_ms=2000)
        attempt = a.attempts[aid]
        assert await wait_for(lambda: attempt.prediction["state"] == "not-symmetric", 5), attempt.prediction
        assert attempt.prediction["localSymmetric"] is False
        assert attempt.prediction["reason"] == "NOT_SYMMETRIC_MAPPING_BEHAVIOR"
        assert attempt.prediction["sends"] == 0 and attempt.predicted_targets == {}
        assert not any(kind == "prediction.samples" for kind, _ in events["a"])
        assert mapping.received == []
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in (mapping_transport, *stun_transports):
            transport.close()


@pytest.mark.asyncio
async def test_samples_without_a_valid_proof_or_replayed_are_refused():
    allocator = IncrementalAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    a = b = None
    try:
        a, b, aid, connection, events = await prediction_pair(points, timeout_ms=3000)
        attempt = a.attempts[aid]
        assert await wait_for(lambda: attempt.prediction["state"] == "waiting-samples")
        with pytest.raises(ValueError, match="SAMPLES_PROOF_MISMATCH"):
            await a.prediction_signal(samples_message(connection, aid, [43000, 43001], proof="00" * 32))
        with pytest.raises(ValueError, match="SIGNAL_IDENTITY_MISMATCH"):
            await a.prediction_signal(samples_message(str(uuid.uuid4()), aid, [43000, 43001]))
        valid = samples_message(connection, aid, [43000, 43001, 43002, 43003])
        await a.prediction_signal(valid)
        with pytest.raises(ValueError, match="SAMPLES_REPLAY"):
            await a.prediction_signal(valid)
        replay = samples_message(connection, aid, [43100, 43101, 43102, 43103],
                                 nonce=valid["nonce"])
        with pytest.raises(ValueError, match="SAMPLES_REPLAY"):
            await a.prediction_signal(replay)
        assert attempt.prediction["sends"] == 0 or attempt.prediction["state"] in {"probing", "no-hit", "hit"}
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in stun_transports:
            transport.close()


def test_malformed_and_oversize_samples_are_rejected_locally():
    connection, attempt = str(uuid.uuid4()), str(uuid.uuid4())
    with pytest.raises(ValueError, match="SAMPLES_LIMIT"):
        validate_samples_message(samples_message(connection, attempt, list(range(43000, 43065))))
    hurt = samples_message(connection, attempt, [43000, 43001])
    hurt["chat"] = "hello"
    with pytest.raises(ValueError, match="INVALID_SAMPLES"):
        validate_samples_message(hurt)
    bad = samples_message(connection, attempt, [43000, 43001])
    bad["samples"][0]["destination"] = ["224.0.0.1", 3478]
    with pytest.raises(ValueError):
        validate_samples_message(bad)
    bad = samples_message(connection, attempt, [43000, 43001])
    bad["samples"][0]["mappedPort"] = 0
    with pytest.raises(ValueError, match="INVALID_SAMPLES"):
        validate_samples_message(bad)
    bad = samples_message(connection, attempt, [43000, 43001])
    bad["proof"] = "nope"
    with pytest.raises(ValueError, match="INVALID_SAMPLES"):
        validate_samples_message(bad)


@pytest.mark.asyncio
async def test_capability_reports_available_only_with_two_explicit_points():
    allocator = IncrementalAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    try:
        adapter = NativeAdapter("127.0.0.1", prediction=prediction_config(points, enabled=True))
        capability = adapter.prediction_capability()
        assert capability["status"] == "available" and capability["observationPoints"] == 2
        assert capability["priority"] == ["ipv6-direct", "gateway-optin", "port-prediction"]
        assert capability["limits"]["maxCandidates"] == 4
        adapter = NativeAdapter("127.0.0.1", prediction=prediction_config((points[0],), enabled=True))
        capability = adapter.prediction_capability()
        assert capability["status"] == "unavailable"
        assert capability["reason"] == "OBSERVATION_POINTS_REQUIRED"
        with pytest.raises(ValueError):
            NativeAdapter("127.0.0.1", prediction={"enabled": True, "points": points,
                                                   "limits": {"max_candidates": 0}}).prediction_capability()
    finally:
        for transport in stun_transports:
            transport.close()


@pytest.mark.asyncio
async def test_peer_samples_timeout_leaves_the_attempt_honest():
    allocator = IncrementalAllocator()
    stun_transports, responders, points = await scripted_points(allocator)
    a = b = None
    try:
        a, b, aid, connection, events = await prediction_pair(points, timeout_ms=700)
        attempt = a.attempts[aid]
        assert await wait_for(lambda: attempt.prediction["state"] == "waiting-samples")
        # No peer samples arrive: bounded wait, explicit terminal reason, no probing.
        assert await wait_for(lambda: attempt.prediction["state"] == "timeout", 4), attempt.prediction
        assert attempt.prediction["reason"] == "PEER_SAMPLES_TIMEOUT"
        assert attempt.prediction["sends"] == 0 and attempt.predicted_targets == {}
    finally:
        for adapter in (a, b):
            if adapter is not None:
                await adapter.shutdown()
        for transport in stun_transports:
            transport.close()
