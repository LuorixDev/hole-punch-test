"""LAN direct discovery: authentication, bounds, candidate boundary and real sockets.

Every socket here is a real UDP socket. Live tests use restricted loopback
multicast (an explicit test mode) and one test drives a second OS process; none
of this is evidence of a real two-device Wi-Fi LAN, which stays NOT_RUN.
"""
import asyncio
import base64
import json
import os
import secrets
import socket
import sys
import time
import types
import uuid
from pathlib import Path

import pytest

from p2pchat.backend.protocol import ProtocolError, signal as protocol_signal
from p2pchat.native.adapter import NativeAdapter, validate_candidate
from p2pchat.native.lan_discovery import (
    FRESHNESS, GROUP4, MAX_DATAGRAM, MAX_PEERS, MAX_RESPONSE_PER_SECOND, MAX_SEEN_NONCES, MAX_SEND_PER_SECOND,
    MAX_SOURCES, LanDiscovery, LanPeer, LanPolicy, LanRejected, _Rate, announce_mac, build_announce, derive_key,
    lan_candidate, lan_capability, lan_socket_id, parse_announce, room_scope,
)

ROOM = "lan-test-room"
SECRET = "lan-room-secret-128-bit"
CHAT = "chat-content-must-never-appear"
REPO_ROOT = Path(__file__).resolve().parents[3]


def policy(listen_port, discovery_port, **overrides):
    base = dict(room=ROOM, secret=SECRET, peer_id="a", listen_port=listen_port, discovery_port=discovery_port,
                interface="127.0.0.1", restricted_local=True, announce_interval=0.5)
    base.update(overrides)
    return LanPolicy(**base)


def keys(secret=SECRET, room=ROOM):
    key = derive_key(secret)
    return key, room_scope(key, room)


def fresh_announce(port, secret=SECRET, room=ROOM, identity=None, nonce=None, ts=None):
    key, scope = keys(secret, room)
    return build_announce(key=key, scope=scope, nonce=nonce or secrets.token_hex(32),
                          ts=int(time.time()) if ts is None else ts, port=port,
                          identity=identity or secrets.token_hex(32))


def group_sender():
    """Helper socket that multicasts on the loopback interface (never a relay)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1"))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    return sock


def target(discovery_port):
    return (GROUP4, discovery_port)


async def open_discovery(listen_port, discovery_port, **overrides):
    instance = LanDiscovery(policy(listen_port, discovery_port, **overrides))
    await instance.start()
    return instance


async def wait_peer(instance, count=1, timeout=10):
    async with asyncio.timeout(timeout):
        while len(instance.peers()) < count:
            await asyncio.sleep(0.02)
    return instance.peers()


async def settle(seconds=0.3):
    await asyncio.sleep(seconds)


# --- capability surface ------------------------------------------------------

def test_capability_reports_unsupported_instead_of_pretending():
    browser = lan_capability(runtime="browser")
    assert browser["mechanism"] == "lan-direct" and browser["status"] == "unsupported"
    assert browser["reason"] == "NO_UDP_MULTICAST_API" and browser["canMessage"] is False
    no_api = lan_capability(runtime="native", sockmod=types.SimpleNamespace())
    assert no_api["status"] == "unsupported" and no_api["reason"] == "NO_UDP_MULTICAST_API"
    native = lan_capability()
    assert native["status"] == "available" and native["reason"] is None and native["canMessage"] is True
    assert native["family"] == 4 and native["knownLimitation"] == "IPV4_ONLY_LINK_LOCAL_UNUSABLE"
    assert native["limits"]["maxPeers"] == MAX_PEERS and native["limits"]["announcePerSecond"] == MAX_SEND_PER_SECOND
    assert SECRET not in json.dumps(native)


@pytest.mark.asyncio
async def test_service_reports_unsupported_instead_of_starting_a_fake_transport():
    discovery = LanDiscovery(policy(43000, 41519), runtime="browser")
    with pytest.raises(NotImplementedError, match="NO_UDP_MULTICAST_API"):
        await discovery.start()
    assert discovery.stats()["status"] == "unsupported" and discovery.stats()["reason"] == "NO_UDP_MULTICAST_API"
    assert discovery.sock is None and discovery.candidates() == []
    await discovery.close()


# --- wire format and authentication -----------------------------------------

def test_announce_carries_only_minimal_authenticated_fields():
    identity = secrets.token_hex(32)
    payload = fresh_announce(41234, identity=identity)
    key, scope = keys()
    info = parse_announce(payload, key=key, scope=scope, now=time.time())
    assert info["port"] == 41234 and info["identity"] == identity
    frame = json.loads(payload)
    assert set(frame) == {"v", "scope", "nonce", "ts", "port", "identity", "mac"}
    assert payload.count(b'"') >= 14 and len(payload) <= MAX_DATAGRAM
    for forbidden in (SECRET.encode(), ROOM.encode(), CHAT.encode(), b"add" + b"ress"):
        assert forbidden not in payload
    assert frame["scope"] == scope and frame["scope"] != key.hex() and frame["mac"] != key.hex()
    assert frame["mac"] == announce_mac(key, scope, frame["nonce"], frame["ts"], frame["port"], identity)


def test_every_field_is_mac_bound_and_bad_input_is_rejected():
    now = time.time()
    key, scope = keys()
    payload = fresh_announce(41234, ts=int(now))
    frame = json.loads(payload)
    for field, value in [("scope", "0" * 32), ("nonce", secrets.token_hex(32)), ("ts", int(now) + 1),
                         ("port", 41235), ("identity", secrets.token_hex(32))]:
        tampered = dict(frame, **{field: value})
        with pytest.raises(LanRejected) as exc:
            parse_announce(json.dumps(tampered).encode(), key=key, scope=scope, now=now)
        assert exc.value.reason in {"mac", "scope"}
    with pytest.raises(LanRejected, match="malformed"):
        parse_announce(b"{}", key=key, scope=scope, now=now)
    with pytest.raises(LanRejected, match="malformed"):
        parse_announce(b"not json at all", key=key, scope=scope, now=now)
    with pytest.raises(LanRejected, match="malformed"):
        parse_announce(b"x" * (MAX_DATAGRAM + 1), key=key, scope=scope, now=now)
    with pytest.raises(LanRejected, match="malformed"):
        parse_announce(json.dumps(dict(frame, extra=1)).encode(), key=key, scope=scope, now=now)
    # A sender cannot stuff an address into the wire format: the peer address is
    # only ever the observed datagram source, never payload-claimed.
    for claimed in ({"address": "10.0.0.9"}, {"endpoint": ["10.0.0.9", 5000]}, {"ip": "10.0.0.9"}):
        with pytest.raises(LanRejected, match="malformed"):
            parse_announce(json.dumps(dict(frame, **claimed)).encode(), key=key, scope=scope, now=now)
    with pytest.raises(LanRejected, match="malformed"):
        parse_announce(json.dumps(dict(frame, ts="123", port=1)).encode(), key=key, scope=scope, now=now)


def test_freshness_window_is_bounded_both_ways():
    key, scope = keys()
    now = time.time()
    assert parse_announce(fresh_announce(41234, ts=int(now)), key=key, scope=scope, now=now)["port"] == 41234
    for offset in (-(FRESHNESS + 5), FRESHNESS + 5):
        with pytest.raises(LanRejected, match="stale"):
            parse_announce(fresh_announce(41234, ts=int(now) + offset), key=key, scope=scope, now=now)


def test_cross_room_key_and_scope_are_rejected():
    key, scope = keys()
    now = time.time()
    other_key, other_scope = keys("another-room-secret", ROOM)
    with pytest.raises(LanRejected, match="scope"):
        parse_announce(fresh_announce(41234, secret="another-room-secret"), key=key, scope=scope, now=now)
    with pytest.raises(LanRejected, match="scope"):
        parse_announce(fresh_announce(41234, room="other-room"), key=key, scope=scope, now=now)
    # Same room name, different key: scope tags differ, and a forged tag still needs the MAC.
    forged = json.loads(fresh_announce(41234, secret="another-room-secret"))
    forged["scope"] = scope
    with pytest.raises(LanRejected, match="mac"):
        parse_announce(json.dumps(forged).encode(), key=key, scope=scope, now=now)
    assert other_scope != scope and other_key != key


# --- policy / lifecycle ------------------------------------------------------

@pytest.mark.asyncio
async def test_policy_explicit_opt_in_and_limits():
    with pytest.raises(PermissionError, match="LAN_DISCOVERY_DISABLED"):
        policy(4001, 41520, enabled=False).validate()
    with pytest.raises(PermissionError, match="LAN_DISCOVERY_DISABLED"):
        await LanDiscovery(policy(4001, 41520, enabled=False)).start()
    with pytest.raises(PermissionError, match="LOOPBACK_REQUIRES_RESTRICTED_LOCAL"):
        policy(4001, 41520, restricted_local=False).validate()
    with pytest.raises(PermissionError, match="RESTRICTED_LOCAL_MUST_BE_LOOPBACK"):
        policy(4001, 41520, interface="192.168.1.50").validate()
    with pytest.raises(NotImplementedError, match="LAN_IPV6_LINK_LOCAL_UNUSABLE"):
        policy(4001, 41520, family=6).validate()
    for group in ("224.0.0.1", "8.8.8.8", "255.255.255.255"):
        with pytest.raises(ValueError, match="LAN_GROUP_NOT_LINK_SCOPED"):
            policy(4001, 41520, group=group).validate()
    with pytest.raises(ValueError, match="INVALID_LAN_SECRET"):
        policy(4001, 41520, secret="short").validate()
    with pytest.raises(ValueError, match="INVALID_LAN_PORT"):
        policy(0, 41520).validate()
    with pytest.raises(ValueError, match="INVALID_LAN_INTERVAL"):
        policy(4001, 41520, announce_interval=0.1).validate()
    resolved = policy(4001, 41520).validate()
    assert resolved == GROUP4


@pytest.mark.asyncio
async def test_explicit_close_is_final_and_releases_key_material():
    discovery = await open_discovery(43001, 41521)
    try:
        assert discovery.closed is False and discovery.sock is not None
        assert discovery.stats()["status"] == "running"
    finally:
        await discovery.close()
    assert discovery.closed is True and discovery.sock is None
    assert discovery.key == b"" and discovery._identity_key is None
    assert discovery.peers() == [] and discovery.stats()["status"] == "closed"
    assert SECRET not in json.dumps(discovery.stats())
    with pytest.raises(ValueError, match="LAN_DISCOVERY_CLOSED"):
        await discovery.announce_once()
    with pytest.raises(ValueError, match="LAN_DISCOVERY_CLOSED"):
        await discovery.start()
    # A valid announce arriving after close must not resurrect the service.
    sender = group_sender()
    try:
        sender.sendto(fresh_announce(43001), target(41521))
        await settle(0.3)
    finally:
        sender.close()
    assert discovery.peers() == []


# --- live socket negatives ---------------------------------------------------

@pytest.mark.asyncio
async def test_live_forged_cross_room_and_unauthenticated_are_rejected():
    discovery = await open_discovery(43002, 41522)
    sender = group_sender()
    sink = []
    discovery.subscribe(lambda event, params: sink.append((event, params)))
    try:
        sender.sendto(fresh_announce(43002, identity=secrets.token_hex(32))[:20], target(41522))  # truncated
        sender.sendto(b"{\"v\":1}", target(41522))                                             # malformed
        forged = json.loads(fresh_announce(43002, identity=secrets.token_hex(32)))
        forged["mac"] = "0" * 64
        sender.sendto(json.dumps(forged).encode(), target(41522))                              # forged MAC
        sender.sendto(fresh_announce(43002, secret="attacker-secret", identity=secrets.token_hex(32)),
                      target(41522))                                                           # cross room
        wrong_key = json.loads(fresh_announce(43002, secret="attacker-secret", identity=secrets.token_hex(32)))
        wrong_key["scope"] = keys()[1]
        sender.sendto(json.dumps(wrong_key).encode(), target(41522))                           # right scope, wrong key
        await settle(0.5)
        rejected = discovery.stats()["rejected"]
        assert rejected["malformed"] == 2 and rejected["mac"] == 2 and rejected["scope"] == 1
        assert discovery.peers() == [] and discovery.candidates() == []
        # A rejected peer must never surface as an event or leak into diagnostics.
        assert not [params for event, params in sink if event == "lan-peer"]
        assert SECRET not in json.dumps(sink) and CHAT not in json.dumps(sink)
    finally:
        sender.close()
        await discovery.close()


@pytest.mark.asyncio
async def test_live_stale_and_replayed_announce_are_rejected():
    discovery = await open_discovery(43003, 41523)
    sender = group_sender()
    try:
        identity = secrets.token_hex(32)
        sender.sendto(fresh_announce(43003, identity=identity, ts=int(time.time()) - 3600), target(41523))
        await settle(0.3)
        assert discovery.stats()["rejected"]["stale"] == 1 and discovery.peers() == []
        once = fresh_announce(43003, identity=identity)
        sender.sendto(once, target(41523))
        await wait_peer(discovery)
        sender.sendto(once, target(41523))
        await settle(0.3)
        assert discovery.stats()["rejected"]["replay"] == 1
        assert len(discovery.peers()) == 1 and discovery.peers()[0].identity == identity
    finally:
        sender.close()
        await discovery.close()


@pytest.mark.asyncio
async def test_self_announce_is_not_a_peer():
    discovery = await open_discovery(43004, 41524)
    try:
        await settle(0.5)  # the announce loop's own multicast loops back
        assert discovery.peers() == []
        assert discovery.stats()["rejected"]["selfAnnounce"] >= 1
        assert discovery.announces_sent >= 1
    finally:
        await discovery.close()


# --- bounds ------------------------------------------------------------------

@pytest.mark.asyncio
async def test_flood_is_bounded_and_receiver_stays_responsive():
    discovery = await open_discovery(43005, 41525)
    sender, second = group_sender(), group_sender()
    try:
        flooder = secrets.token_hex(32)
        for start in range(0, 400, 25):
            for index in range(start, start + 25):
                sender.sendto(fresh_announce(43005, identity=flooder, nonce="%064x" % index), target(41525))
            await asyncio.sleep(0.01)  # let the receiver drain, like a real flood over time
        await settle(0.5)
        stats = discovery.stats()
        assert stats["rejected"]["rateLimited"] >= 300, stats["rejected"]
        assert len(stats["peers"]) == 1 and len(discovery.peers()) <= MAX_PEERS
        assert len(discovery.seen) <= MAX_SEEN_NONCES
        assert len(discovery._response_source.keys) <= MAX_SOURCES
        assert len(discovery._inbound_source.keys) <= MAX_SOURCES
        assert discovery.responses_sent <= MAX_RESPONSE_PER_SECOND  # bounded, no amplification loop
        # After the window resets a genuine peer is still served: no lockout, no runaway.
        await asyncio.sleep(1.1)
        second.sendto(fresh_announce(43005, identity=secrets.token_hex(32)), target(41525))
        await wait_peer(discovery, count=2)
        assert len(discovery.peers()) == 2
    finally:
        sender.close()
        second.close()
        await discovery.close()


def test_bounded_structures_never_grow_without_limit():
    limiter = _Rate(limit=1, window=1.0, max_keys=4)
    for index in range(200):
        limiter.allow("source-%d" % index, 100.0)
    assert len(limiter.keys) <= 4
    discovery = LanDiscovery(policy(43006, 41526))
    now = time.time()
    for index in range(200):
        discovery._insert_peer(LanPeer("127.0.0.1", 41000 + index, "%064x" % index, 4, now, now + index))
    assert len(discovery._peers) == MAX_PEERS
    assert all(peer.port >= 41000 + 200 - MAX_PEERS for peer in discovery._peers.values())


@pytest.mark.asyncio
async def test_send_rate_is_capped_and_recovers_after_the_window():
    clock = {"now": 1000.0}
    discovery = LanDiscovery(policy(43007, 41527), monotonic=lambda: clock["now"], wall=time.time)
    await discovery.start()
    try:
        assert discovery.announces_sent == 1  # start announces once
        sent = sum([await discovery.announce_once() for _ in range(40)])
        assert sent == MAX_SEND_PER_SECOND - 1 and discovery.announces_sent == MAX_SEND_PER_SECOND
        clock["now"] += 1.0
        assert await discovery.announce_once() is True
        assert discovery.announces_sent == MAX_SEND_PER_SECOND + 1
    finally:
        await discovery.close()


# --- candidate boundary ------------------------------------------------------

def test_discovered_candidate_obeys_existing_rules_without_exemption():
    for address, port in [("192.168.1.23", 5000), ("10.0.0.5", 1), ("127.0.0.1", 65535)]:
        candidate = lan_candidate(address, port)
        validate_candidate(candidate)  # same function the signaling path uses, no exemption
        assert validate_candidate(candidate) == validate_candidate(dict(candidate))
        assert candidate["kind"] == "host" and candidate["transport"] == "udp"
    rejects = [("0.0.0.0", 5000), ("224.0.0.1", 5000), ("239.255.42.99", 5000), ("255.255.255.255", 5000),
               ("169.254.10.1", 5000), ("fe80::1%eth0", 5000), ("192.168.1.23", 0), ("192.168.1.23", 65536),
               ("192.168.1.23", True), ("192.168.1.23", "5000")]
    for address, port in rejects:
        with pytest.raises(ValueError):
            lan_candidate(address, port, family=6 if ":" in str(address) else 4)
    with pytest.raises(ValueError):
        lan_candidate("192.168.1.23", 5000, transport="sctp")
    with pytest.raises(ValueError):
        lan_candidate("192.168.1.23", 5000, kind="relay")
    with pytest.raises(ValueError):
        lan_candidate("192.168.1.23", 5000, socket_id="")
    with pytest.raises(ValueError):
        lan_candidate("192.168.1.23", 5000, certificate_fingerprint="not-a-fingerprint")
    # Link-local is the documented LAN limitation: the existing rule refuses it.
    with pytest.raises(ValueError):
        lan_candidate("fe80::1", 5000, family=6)
    identity = secrets.token_hex(32)
    assert lan_socket_id(identity) == "lan-" + identity[:32] and identity not in lan_socket_id(identity)


def test_discovered_candidate_passes_the_signaling_schema_too():
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    candidate = lan_candidate("192.168.1.23", 5000, socket_id=lan_socket_id(secrets.token_hex(32)))
    envelope = {"v": 1, "type": "signal", "to": "b", "connectionId": cid, "attemptId": aid,
                "mechanism": "udp-probe", "profile": "direct", "nativeCandidate": candidate}
    assert protocol_signal(dict(envelope))["nativeCandidate"]["address"] == "192.168.1.23"
    for address in ("0.0.0.0", "224.0.0.1", "169.254.1.2", "255.255.255.255"):
        with pytest.raises(ProtocolError):
            protocol_signal(dict(envelope, nativeCandidate=dict(candidate, address=address)))


# --- real sockets: discovery + direct connection -----------------------------

CHILD = r'''
import asyncio, json, sys
from p2pchat.native.adapter import NativeAdapter
from p2pchat.native.lan_discovery import LanDiscovery, LanPolicy

async def wait_peer(discovery):
    async with asyncio.timeout(15):
        while not discovery.peers():
            await asyncio.sleep(0.02)
    return discovery.peers()[0]

async def wait_state(adapter, attempt):
    async with asyncio.timeout(15):
        while True:
            state = (await adapter.stats({"attemptId": attempt}))["state"]
            if state in {"direct", "failed", "timeout", "unsupported"}:
                return state
            await asyncio.sleep(0.02)

async def main(config):
    out, discovery, adapter = {}, None, NativeAdapter("127.0.0.1")
    try:
        await adapter.start({"connectionId": config["connectionId"], "attemptId": config["attemptId"],
                             "peerId": config["remotePeerId"], "mechanism": "udp-probe", "profile": "lan-link",
                             "role": "answerer", "timeoutMs": 20000,
                             "auth": {"room": config["room"], "localPeerId": config["localPeerId"],
                                      "secret": config["secret"]}})
        port = adapter.attempts[config["attemptId"]].candidate["port"]
        out["listenPort"] = port
        discovery = LanDiscovery(LanPolicy(room=config["room"], secret=config["secret"],
                                           peer_id=config["localPeerId"], listen_port=port,
                                           discovery_port=config["discoveryPort"], interface="127.0.0.1",
                                           restricted_local=True, announce_interval=0.5))
        await discovery.start()
        out["identity"] = discovery.identity
        peer = await wait_peer(discovery)
        out["discovered"] = [peer.address, peer.port]
        out["peerIdentity"] = peer.identity
        await adapter.signal({"connectionId": config["connectionId"], "attemptId": config["attemptId"],
                              "from": config["remotePeerId"], "nativeCandidate": peer.candidate()})
        out["state"] = await wait_state(adapter, config["attemptId"])
    except BaseException as error:
        out["error"] = type(error).__name__
    finally:
        print(json.dumps(out), flush=True)
        if discovery is not None:
            await discovery.close()
        await adapter.shutdown()
    return 0 if out.get("state") == "direct" else 2

sys.exit(asyncio.run(main(json.loads(sys.stdin.readline()))))
'''


async def spawn_child(config):
    process = await asyncio.create_subprocess_exec(
        sys.executable, "-c", CHILD, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE, cwd=str(REPO_ROOT),
        env={**os.environ, "PYTHONPATH": str(REPO_ROOT)})
    process.stdin.write(json.dumps(config).encode() + b"\n")
    await process.stdin.drain()
    process.stdin.close()
    return process


async def collect_child(process, timeout=30):
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout)
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        raise
    return process.returncode, stdout.decode(), stderr.decode()


def adapter_params(mechanism, role, cid, aid):
    local, remote = ("a", "b") if role == "offerer" else ("b", "a")
    return dict(connectionId=cid, attemptId=aid, peerId=remote, mechanism=mechanism, profile="lan-link",
                role=role, timeoutMs=8000, auth=dict(room=ROOM, localPeerId=local, secret=SECRET))


@pytest.mark.asyncio
async def test_cross_process_multicast_discovery_and_direct_connection():
    cid, aid, discovery_port = str(uuid.uuid4()), str(uuid.uuid4()), 41536
    parent = NativeAdapter("127.0.0.1")
    discovery = None
    process = None
    try:
        await parent.start(adapter_params("udp-probe", "offerer", cid, aid))
        parent_port = parent.attempts[aid].candidate["port"]
        discovery = await open_discovery(parent_port, discovery_port)
        process = await spawn_child({"room": ROOM, "secret": SECRET, "connectionId": cid,
                                     "attemptId": aid, "localPeerId": "b", "remotePeerId": "a",
                                     "discoveryPort": discovery_port})
        # The parent must answer while the child is still probing: both sides learn
        # each other's port only from multicast discovery.
        peers = await wait_peer(discovery)
        assert [peers[0].address, peers[0].port] == ["127.0.0.1", peers[0].port]
        await parent.signal({"connectionId": cid, "attemptId": aid, "from": "b",
                             "nativeCandidate": peers[0].candidate()})
        code, stdout, stderr = await collect_child(process)
        child = json.loads([line for line in stdout.splitlines() if line.strip()][-1])
        assert code == 0, f"child exit={code} out={child} stderr={stderr[-800:]}"
        assert child["state"] == "direct" and child.get("error") is None, child
        assert child["discovered"] == ["127.0.0.1", parent_port], child
        assert peers[0].port == child["listenPort"]
        assert peers[0].identity == child["identity"] and child["peerIdentity"] == discovery.identity
        async with asyncio.timeout(10):
            while (await parent.stats({"attemptId": aid}))["state"] != "direct":
                await asyncio.sleep(0.02)
        assert (await parent.stats({"attemptId": aid}))["state"] == "direct"
        assert SECRET not in stdout and ROOM not in stdout
    finally:
        if process is not None and process.returncode is None:
            process.kill()
            await process.wait()
        if discovery is not None:
            await discovery.close()
        await parent.shutdown()


@pytest.mark.asyncio
async def test_discovered_candidate_carries_a_message_lane():
    cid, aid, discovery_port = str(uuid.uuid4()), str(uuid.uuid4()), 41537
    a, b = NativeAdapter("127.0.0.1"), NativeAdapter("127.0.0.1")
    events = {"a": [], "b": []}
    a.subscribe(lambda kind, data: events["a"].append((kind, data)))
    b.subscribe(lambda kind, data: events["b"].append((kind, data)))
    discs = []
    try:
        await a.start(adapter_params("quic", "offerer", cid, aid))
        await b.start(adapter_params("quic", "answerer", cid, aid))
        port_a = a.attempts[aid].candidate["port"]
        port_b = b.attempts[aid].candidate["port"]
        disc_a = await open_discovery(port_a, discovery_port)
        disc_b = await open_discovery(port_b, discovery_port)
        discs = [disc_a, disc_b]
        peers_a, peers_b = await asyncio.gather(wait_peer(disc_a), wait_peer(disc_b))
        # The endpoint came only from multicast discovery: address from the datagram
        # source, port from the authenticated announce.
        assert [peers_a[0].address, peers_a[0].port] == ["127.0.0.1", port_b]
        assert [peers_b[0].address, peers_b[0].port] == ["127.0.0.1", port_a]
        described = {name: next(event for kind, event in events[name]
                                if kind == "candidate" and "description" in event) for name in events}
        fingerprints = {name: next(event["nativeCandidate"]["certificateFingerprint"] for kind, event in events[name]
                                   if kind == "candidate" and "nativeCandidate" in event) for name in events}
        for side, adapter, remote, peer in [("a", a, "b", peers_a[0]), ("b", b, "a", peers_b[0])]:
            await adapter.signal({"connectionId": cid, "attemptId": aid, "from": remote,
                                  "description": described[remote]["description"]})
            await adapter.signal({"connectionId": cid, "attemptId": aid, "from": remote,
                                  "nativeCandidate": peer.candidate(transport="quic",
                                                                    certificate_fingerprint=fingerprints[remote])})
        async with asyncio.timeout(10):
            while True:
                states = [(await x.stats({"attemptId": aid}))["state"] for x in (a, b)]
                if all(state in {"direct", "failed", "timeout"} for state in states):
                    break
                await asyncio.sleep(0.02)
        assert states == ["direct", "direct"], states
        payload = os.urandom(4096)
        for source in (a, b):
            await source.send(dict(attemptId=aid, lane="chat", data=payload))
        async with asyncio.timeout(5):
            while not all(any(kind == "data" for kind, _ in events[name]) for name in events):
                await asyncio.sleep(0.02)
        for name in events:
            received = next(data["dataB64"] for kind, data in events[name] if kind == "data")
            assert received.encode() == base64.b64encode(payload)
        assert SECRET not in json.dumps(discs[0].stats()) and CHAT not in json.dumps(events)
    finally:
        for disc in discs:
            await disc.close()
        await a.shutdown()
        await b.shutdown()
