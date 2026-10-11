"""Symmetric-NAT port prediction tests: scripted STUN observations + scripted peer probes.

Controlled loopback endpoints only. These results are not real home-network
symmetric-NAT evidence; that stays NOT_RUN until a user runs the tool on a real
network.
"""
import asyncio
import ipaddress
import json
import socket
import struct

import pytest

from p2pchat.native.adapter import validate_candidate
from p2pchat.native.auth import Auth, packed
from p2pchat.native.nat_behavior import (
    MAPPING_ADDRESS_AND_PORT_DEPENDENT,
    MAPPING_ENDPOINT_INDEPENDENT,
    UNDETERMINED,
    MappingSample,
    NatProbeConfig,
    NatProfile,
    StunObservationPoint,
)
from p2pchat.native.port_prediction import (
    HONESTY_NOTE,
    OUTCOME_HIT,
    OUTCOME_REJECTED,
    PATTERN_BLOCK,
    PATTERN_HASH,
    PATTERN_INCREMENTAL,
    PATTERN_RANDOM,
    PATTERN_UNDETERMINED,
    PROBE_PREFIX,
    REASON_INSUFFICIENT_SAMPLES,
    REASON_NOT_SYMMETRIC,
    REASON_UNPREDICTABLE,
    STATE_HIT,
    STATE_NOT_ATTEMPTED,
    STATE_NO_HIT,
    AllocationSample,
    PeerAuthContext,
    PredictionLimits,
    PredictionPuncher,
    collect_samples,
    infer_allocation,
    plan_from_profile,
    predict_candidates,
    punch_with_prediction,
)
from p2pchat.native.stun import COOKIE

EXTERNAL_IP = "203.0.113.7"
AUTH = PeerAuthContext(room="room", secret="shared-room-secret", connection="c-1", attempt="a-1",
                       local_id="offerer", peer_id="answerer")


def samples_from_ports(ports, *, first_local=5001, destination=("192.0.2.10", 3478)):
    return tuple(AllocationSample(index, first_local + index, destination, port)
                 for index, port in enumerate(ports))


def profile_from_samples(samples, mapping=MAPPING_ADDRESS_AND_PORT_DEPENDENT):
    observations = [MappingSample(sample.local_port, sample.destination, (EXTERNAL_IP, sample.mapped_port), 0)
                    for sample in samples]
    return NatProfile(mapping=mapping, mapping_evidence="test", mapping_partial=None, filtering=UNDETERMINED,
                      filtering_evidence="test", reachability="low", guidance="test", observations=observations)


# --- allocation law inference -------------------------------------------------

def test_incremental_allocation_is_predicted():
    model = infer_allocation(samples_from_ports([40000, 40001, 40002, 40003, 40004, 40005]))
    assert (model.pattern, model.predictable) == (PATTERN_INCREMENTAL, True)
    assert model.step == 1
    assert predict_candidates(model, PredictionLimits(max_candidates=4)) == (40006, 40007, 40008, 40009)


def test_incremental_with_larger_step_and_window():
    samples = samples_from_ports([40000, 40003, 40006, 40009])
    model = infer_allocation(samples)
    assert (model.pattern, model.step) == (PATTERN_INCREMENTAL, 3)
    limits = PredictionLimits(max_candidates=8, max_span=10)
    candidates = predict_candidates(model, limits)
    assert candidates == (40012, 40015, 40018)  # bounded by max_span from the anchor, never wider
    assert all(abs(port - model.last_mapped_port) <= limits.max_span for port in candidates)


def test_block_allocation_is_predicted():
    ports = []
    for group in range(3):
        ports.extend([40000 + group * 16 + offset for offset in range(3)])
    samples = tuple(AllocationSample(index, 5001 + index % 3,
                                     ("192.0.2.%d" % (10 + index // 3), 3478), port)
                    for index, port in enumerate(ports))
    model = infer_allocation(samples)
    assert (model.pattern, model.predictable) == (PATTERN_BLOCK, True)
    assert model.block_size == 16 and model.group_size == 3 and model.last_base == 40032
    assert predict_candidates(model, PredictionLimits(max_candidates=8, max_span=64)) == (40048, 40049, 40050)


def test_hash_like_allocation_is_not_extrapolated():
    model = infer_allocation(samples_from_ports([40013, 40057, 40002, 40041, 40029, 40008]))
    assert model.pattern == PATTERN_HASH
    assert model.predictable is False
    assert model.reason == REASON_UNPREDICTABLE
    assert predict_candidates(model) == ()


def test_random_allocation_is_not_extrapolated():
    model = infer_allocation(samples_from_ports([1024, 31000, 8000, 45000, 20000, 60000]))
    assert model.pattern == PATTERN_RANDOM
    assert model.predictable is False
    assert predict_candidates(model) == ()


def test_insufficient_samples_do_not_predict():
    model = infer_allocation(samples_from_ports([40000, 40001, 40002]))
    assert (model.pattern, model.predictable, model.reason) == (PATTERN_UNDETERMINED, False,
                                                                REASON_INSUFFICIENT_SAMPLES)
    assert predict_candidates(model) == ()
    assert infer_allocation(()).reason == REASON_INSUFFICIENT_SAMPLES


def test_conflicting_regularity_does_not_predict():
    model = infer_allocation(samples_from_ports([40000, 40001, 40002, 45000, 45001, 45002]))
    assert model.predictable is False
    assert model.pattern in {PATTERN_HASH, PATTERN_RANDOM, PATTERN_UNDETERMINED}
    assert predict_candidates(model) == ()


def test_prediction_never_wraps_past_the_port_range():
    model = infer_allocation(samples_from_ports([65530, 65531, 65532, 65533, 65534]))
    candidates = predict_candidates(model, PredictionLimits(max_candidates=8, max_span=64))
    assert candidates == (65535,)
    assert all(1 <= port <= 65535 for port in candidates)


def test_plan_from_a_non_symmetric_profile_predicts_nothing():
    profile = profile_from_samples(samples_from_ports([40000, 40001, 40002, 40003]),
                                   mapping=MAPPING_ENDPOINT_INDEPENDENT)
    model, candidates, _ = plan_from_profile(profile)
    assert (model.predictable, candidates) == (False, ())
    assert model.reason == REASON_NOT_SYMMETRIC


# --- t10 integration: real multi-observer sampling ----------------------------

def xor_attribute(attribute, endpoint, transaction):
    packed_address = ipaddress.ip_address(endpoint[0]).packed
    mask = struct.pack("!I", COOKIE) + transaction
    value = (struct.pack("!BBH", 0, 1 if len(packed_address) == 4 else 2, endpoint[1] ^ (COOKIE >> 16))
             + bytes(a ^ b for a, b in zip(packed_address, mask)))
    return struct.pack("!HH", attribute, len(value)) + value


class IncrementalAllocator:
    """Symmetric NAT model: one new external port per new (local port, destination)."""

    def __init__(self, start=40000):
        self.next_port = start
        self.ports = {}

    def port_for(self, local, destination):
        key = (local, destination)
        if key not in self.ports:
            self.ports[key] = self.next_port
            self.next_port += 1
        return self.ports[key]


class ScriptedStun(asyncio.DatagramProtocol):
    def __init__(self, allocator, address):
        self.allocator = allocator
        self.address = tuple(address)
        self.requests = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if len(data) < 20:
            return
        kind, size, cookie, transaction = struct.unpack("!HHI12s", data[:20])
        if kind != 0x0001 or cookie != COOKIE or size != len(data) - 20:
            return
        self.requests += 1
        port = self.allocator.port_for((addr[0], addr[1]), self.address)
        attributes = xor_attribute(0x0020, (EXTERNAL_IP, port), transaction)
        self.transport.sendto(struct.pack("!HHI12s", 0x0101, len(attributes), COOKIE, transaction) + attributes, addr)


@pytest.mark.asyncio
async def test_collect_samples_uses_several_destinations_and_local_ports():
    loop = asyncio.get_running_loop()
    allocator = IncrementalAllocator()
    transports = []
    for host in ("127.0.0.1", "127.0.0.2", "127.0.0.1"):
        holder = {}

        def factory(holder=holder, host=host):
            holder["responder"] = ScriptedStun(allocator, (host, 0))
            return holder["responder"]

        transport, _ = await loop.create_datagram_endpoint(factory, local_addr=(host, 0))
        holder["responder"].address = (host, transport.get_extra_info("sockname")[1])
        transports.append((host, transport))
    points = tuple(StunObservationPoint(host, transport.get_extra_info("sockname")[1])
                   for host, transport in transports)
    try:
        report = await collect_samples(NatProbeConfig("127.0.0.1", points, local_ports=3, repeats=2, timeout=.3))
        assert report.symmetric is True
        assert report.profile.mapping == MAPPING_ADDRESS_AND_PORT_DEPENDENT
        assert len({sample.destination for sample in report.samples}) == 3
        assert len({sample.local_port for sample in report.samples}) == 3
        assert len(report.samples) == 9  # 3 local ports x 3 destinations, repeats collapsed
        assert [sample.sequence for sample in report.samples] == list(range(9))
        ports = [sample.mapped_port for sample in report.samples]
        assert ports == sorted(ports) and len(set(ports)) == 9  # a new port per symmetric mapping
        model = infer_allocation(report.samples)
        assert (model.pattern, model.predictable, model.step) == (PATTERN_INCREMENTAL, True, 1)
        assert predict_candidates(model)[0] == ports[-1] + 1
        assert report.report()["symmetric"] is True
        payload = json.dumps(report.report())
        assert EXTERNAL_IP not in payload  # sampled public endpoints stay local
        assert '"observations"' not in payload and '"mappedEndpoints"' not in payload
    finally:
        for _, transport in transports:
            transport.close()


# --- authenticated probing ----------------------------------------------------

class PeerResponder(asyncio.DatagramProtocol):
    """Scripted peer that answers the prediction probe exactly like the adapter does."""

    def __init__(self, context, mode="reply"):
        self.context = context
        self.mode = mode
        self.received = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.received.append((addr, data))
        if self.mode == "silent" or not data.startswith(PROBE_PREFIX):
            return
        if self.mode == "garbage":
            self.transport.sendto(PROBE_PREFIX + b"{not-json", addr)
            return
        try:
            frame = json.loads(data[len(PROBE_PREFIX):])
        except ValueError:
            return
        auth = Auth(self.context.room, self.context.secret, self.context.connection, self.context.attempt,
                    self.context.peer_id, self.context.local_id)
        try:
            response = auth.receive(frame)
        except ValueError:
            return
        if response is None:
            return
        if self.mode == "forged":
            response["proof"] = "0" * 64
        self.transport.sendto(PROBE_PREFIX + packed(response), addr)


async def start_peer(address, mode="reply"):
    loop = asyncio.get_running_loop()
    family = socket.AF_INET6 if ":" in address[0] else socket.AF_INET
    responder = PeerResponder(AUTH, mode)
    transport, _ = await loop.create_datagram_endpoint(lambda: responder, local_addr=address, family=family)
    return transport, responder, transport.get_extra_info("sockname")[1]


def fast_limits(**overrides):
    values = dict(max_candidates=4, max_span=32, probes_per_candidate=2, min_interval=0.02,
                  per_candidate_timeout=0.05, total_timeout=2.0, min_samples=4, hash_window=64)
    values.update(overrides)
    return PredictionLimits(**values)


@pytest.mark.asyncio
async def test_punch_hits_the_predicted_port():
    transport, responder, port = await start_peer(("127.0.0.1", 0))
    try:
        samples = samples_from_ports([port - 4, port - 3, port - 2, port - 1])
        profile = profile_from_samples(samples)
        limits = fast_limits()
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1", limits=limits)
        assert report.state == STATE_HIT and report.hit is True
        assert report.candidates[0] == ("127.0.0.1", port)
        assert report.outcomes[0].state == OUTCOME_HIT
        assert report.outcomes[0].reason == "AUTHENTICATED_HIT"
        assert report.outcomes[0].target == ("127.0.0.1", port)
        assert len(report.outcomes) == 1  # stop at the first authenticated hit, no further scanning
        assert report.sends <= limits.probes_per_candidate
        assert report.duration_ms < limits.total_timeout * 1000
        assert len(report.candidates) <= limits.max_candidates
        assert all(abs(candidate[1] - (port - 1)) <= limits.max_span for candidate in report.candidates)
    finally:
        transport.close()




@pytest.mark.asyncio
async def test_forged_reply_is_rejected_and_not_a_hit():
    transport, responder, port = await start_peer(("127.0.0.1", 0), mode="forged")
    try:
        profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]))
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1",
                                             limits=fast_limits())
        assert report.state == STATE_NO_HIT
        assert report.outcomes[0].state == OUTCOME_REJECTED
        assert report.outcomes[0].reason == "REPLIES_REJECTED"
        assert report.hit is False  # a forged proof is never a hit
        assert report.sends == len(report.outcomes) * 2  # bounded retries only, then terminal
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_malformed_reply_is_rejected():
    transport, responder, port = await start_peer(("127.0.0.1", 0), mode="garbage")
    try:
        profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]))
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1",
                                             limits=fast_limits())
        assert report.hit is False
        assert report.outcomes[0].state == OUTCOME_REJECTED
    finally:
        transport.close()


def test_expansion_over_several_signaled_addresses_stays_capped():
    puncher = PredictionPuncher(("127.0.0.1", "127.0.0.2"), AUTH, fast_limits(max_candidates=3),
                                bind_host="127.0.0.1", anchor_port=40000)
    targets = puncher.expand((40001, 40002, 40003, 40004, 40005))
    assert len(targets) == 3
    assert {address for address, _ in targets} <= {"127.0.0.1", "127.0.0.2"}
    assert {port for _, port in targets} <= {40001, 40002, 40003, 40004, 40005}
    # sequential single-socket probing: no concurrent bursts beyond the configured rate
    puncher.validate_candidates(targets)


@pytest.mark.asyncio
async def test_blackhole_has_a_terminal_state_and_no_infinite_retry():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]))
    limits = fast_limits(max_candidates=3, probes_per_candidate=2)
    report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1", limits=limits)
    assert report.state == STATE_NO_HIT
    assert report.reason in {"NO_AUTHENTICATED_REPLY", "DEADLINE_REACHED"}
    assert len(report.outcomes) == 3
    assert report.sends == 3 * limits.probes_per_candidate  # exact budget, then terminal
    assert report.duration_ms < limits.total_timeout * 1000


@pytest.mark.asyncio
async def test_probing_is_rate_limited():
    probe = socket.socket()
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]))
    limits = fast_limits(max_candidates=3, probes_per_candidate=2, min_interval=0.05, per_candidate_timeout=0.05,
                         total_timeout=3.0)
    report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1", limits=limits)
    assert report.sends == 6
    assert report.duration_ms >= 5 * limits.min_interval * 1000 - 20  # >= 5 gaps between 6 sends


async def start_consecutive_peers(count=2, mode="silent"):
    """Two listening ports P and P+1 so consecutive predicted candidates both land."""
    loop = asyncio.get_running_loop()
    for _ in range(50):
        seed = socket.socket()
        seed.bind(("127.0.0.1", 0))
        start = seed.getsockname()[1]
        seed.close()
        made = []
        try:
            for offset in range(count):
                responder = PeerResponder(AUTH, mode)
                transport, _ = await loop.create_datagram_endpoint(lambda r=responder: r,
                                                                   local_addr=("127.0.0.1", start + offset))
                made.append((transport, responder))
        except OSError:
            for transport, _ in made:
                transport.close()
            continue
        return made, start
    raise RuntimeError("no consecutive ports available")


@pytest.mark.asyncio
async def test_each_predicted_candidate_uses_an_independent_nonce():
    made, start = await start_consecutive_peers(2)
    try:
        responders = [responder for _, responder in made]
        profile = profile_from_samples(samples_from_ports([start - 4, start - 3, start - 2, start - 1]))
        limits = fast_limits(max_candidates=2, probes_per_candidate=1)
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1", limits=limits)
        assert [candidate[1] for candidate in report.candidates] == [start, start + 1]
        assert all(responder.received for responder in responders)
        nonces = [json.loads(responder.received[0][1][len(PROBE_PREFIX):])["nonce"] for responder in responders]
        assert len(set(nonces)) == 2 and all(len(nonce) == 64 for nonce in nonces)
    finally:
        for transport, _ in made:
            transport.close()


def test_unsignaled_addresses_and_unbounded_ports_are_refused():
    puncher = PredictionPuncher(("127.0.0.1",), AUTH, fast_limits(), bind_host="127.0.0.1", anchor_port=40000)
    with pytest.raises(ValueError, match="UNSIGNALED_TARGET_ADDRESS"):
        puncher.validate_candidates([("127.0.0.2", 40001)])
    with pytest.raises(ValueError, match="PREDICTION_WINDOW_EXCEEDED"):
        puncher.validate_candidates([("127.0.0.1", 40000 + 33)])
    with pytest.raises(ValueError, match="CANDIDATE_LIMIT"):
        puncher.validate_candidates([("127.0.0.1", 40000 + index) for index in range(1, 6)])
    with pytest.raises(ValueError):
        puncher.validate_candidates([("127.0.0.1", 0)])
    with pytest.raises(ValueError):
        PredictionPuncher(("0.0.0.0",), AUTH, fast_limits(), bind_host="127.0.0.1")
    with pytest.raises(ValueError):
        PredictionPuncher(("fe80::1",), AUTH, fast_limits(), bind_host="127.0.0.1")
    with pytest.raises(ValueError, match="INVALID_CANDIDATE_LIMIT"):
        PredictionLimits(max_candidates=0).validate()
    with pytest.raises(ValueError, match="INVALID_TOTAL_TIMEOUT"):
        PredictionLimits(total_timeout=99).validate()


def test_predicted_candidates_still_satisfy_the_existing_candidate_validation():
    model = infer_allocation(samples_from_ports([40000, 40001, 40002, 40003]))
    candidates = predict_candidates(model)
    assert candidates
    for port in candidates:
        candidate = {"id": "x", "family": 4, "transport": "udp", "address": "192.0.2.10", "port": port,
                     "kind": "host", "socketId": "x"}
        assert validate_candidate(candidate) == ("192.0.2.10", port)  # unchanged identity rule accepts it
    for bad_address in ("0.0.0.0", "224.0.0.1", "169.254.1.2", "255.255.255.255"):
        with pytest.raises(ValueError):
            validate_candidate({"id": "x", "family": 4, "transport": "udp", "address": bad_address, "port": 40000,
                                "kind": "host", "socketId": "x"})
    # a predicted port must not be smuggled into signaling as a new candidate kind
    with pytest.raises(ValueError):
        validate_candidate({"id": "x", "family": 4, "transport": "udp", "address": "192.0.2.10", "port": 40000,
                            "kind": "predicted", "socketId": "x"})


@pytest.mark.asyncio
async def test_non_symmetric_profile_never_probes():
    transport, responder, port = await start_peer(("127.0.0.1", 0))
    try:
        profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]),
                                       mapping=MAPPING_ENDPOINT_INDEPENDENT)
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1",
                                             limits=fast_limits())
        assert report.state == STATE_NOT_ATTEMPTED
        assert report.reason == REASON_NOT_SYMMETRIC
        assert report.candidates == () and report.sends == 0
        assert responder.received == []
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_insufficient_samples_never_probe():
    transport, responder, port = await start_peer(("127.0.0.1", 0))
    try:
        profile = profile_from_samples(samples_from_ports([port - 1, port]))
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1",
                                             limits=fast_limits())
        assert report.state == STATE_NOT_ATTEMPTED
        assert report.reason == REASON_INSUFFICIENT_SAMPLES
        assert report.sends == 0 and responder.received == []
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_report_is_honest_about_limited_success_and_priority():
    transport, responder, port = await start_peer(("127.0.0.1", 0), mode="silent")
    try:
        profile = profile_from_samples(samples_from_ports([port - 4, port - 3, port - 2, port - 1]))
        report = await punch_with_prediction(profile, ("127.0.0.1",), AUTH, bind_host="127.0.0.1",
                                             limits=fast_limits(max_candidates=2, probes_per_candidate=1))
        payload = report.report()
        assert payload["note"] == HONESTY_NOTE
        assert "命中概率有限" in payload["note"] and "失败是正常结果" in payload["note"]
        assert "IPv6" in payload["note"] and "UPnP" in payload["note"]
        assert "must still pass the normal candidate authentication" in payload["inferenceNote"]
        assert "candidates" not in payload and "outcomes" not in payload
        local = report.report(include_endpoints=True)
        assert local["candidates"] and local["outcomes"]
    finally:
        transport.close()
