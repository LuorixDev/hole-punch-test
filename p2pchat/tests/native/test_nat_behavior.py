"""Controlled NAT-behavior tests: scripted STUN responders, never real-NAT evidence.

The responders simulate a NAT model (mapping function + inbound filter) on real
loopback sockets, so the probe exercises real sockets, the real RFC 5389/5780
wire formats and the Windows four-field address form, while the NAT behavior
itself is scripted. A green run here is controlled-endpoint evidence only; real
home-network NAT behavior stays NOT_RUN until a user runs the probe on it.
"""
import asyncio
import argparse
import ipaddress
import json
import socket
import struct

import pytest

from p2pchat.native.nat_behavior import (
    ATTR_CHANGE_REQUEST,
    ATTR_OTHER_ADDRESS,
    ATTR_XOR_MAPPED_ADDRESS,
    BINDING_REQUEST,
    BINDING_SUCCESS,
    CHANGE_IP,
    CHANGE_PORT,
    COOKIE,
    FILTERING_ADDRESS_AND_PORT_DEPENDENT,
    FILTERING_ADDRESS_DEPENDENT,
    FILTERING_ENDPOINT_INDEPENDENT,
    MAPPING_ADDRESS_AND_PORT_DEPENDENT,
    MAPPING_ADDRESS_DEPENDENT,
    MAPPING_ENDPOINT_INDEPENDENT,
    REACHABILITY_HIGH,
    REACHABILITY_LOW,
    REACHABILITY_MEDIUM,
    UNDETERMINED,
    FilteringEvidence,
    MappingSample,
    NatBehaviorProbe,
    NatProbeConfig,
    StunObservationPoint,
    _parse_point,
    classify_filtering,
    classify_mapping,
    main,
    probe_nat_behavior,
)
from p2pchat.native.stun import canonical_endpoint

EXTERNAL_IP = "203.0.113.7"


def xor_attribute(attribute, endpoint, transaction):
    packed = ipaddress.ip_address(endpoint[0]).packed
    mask = struct.pack("!I", COOKIE) + transaction
    value = (struct.pack("!BBH", 0, 1 if len(packed) == 4 else 2, endpoint[1] ^ (COOKIE >> 16))
             + bytes(a ^ b for a, b in zip(packed, mask)))
    return struct.pack("!HH", attribute, len(value)) + value


def build_success(transaction, mapped, other=None, forge=None):
    tid = b"\0" * 12 if forge == "bad-tid" else transaction
    attributes = b""
    if forge != "no-xor":
        attributes += xor_attribute(ATTR_XOR_MAPPED_ADDRESS, mapped, tid)
    if other is not None:
        attributes += xor_attribute(ATTR_OTHER_ADDRESS, other, tid)
    return struct.pack("!HHI12s", BINDING_SUCCESS, len(attributes),
                       0 if forge == "bad-cookie" else COOKIE, tid) + attributes


def parse_request(data):
    if len(data) < 20:
        return None
    kind, size, cookie, transaction = struct.unpack("!HHI12s", data[:20])
    if kind != BINDING_REQUEST or cookie != COOKIE or size != len(data) - 20:
        return None
    change = 0
    position = 20
    while position + 4 <= len(data):
        attribute, length = struct.unpack("!HH", data[position:position + 4])
        if attribute == ATTR_CHANGE_REQUEST and length == 4:
            change = struct.unpack("!I", data[position + 4:position + 8])[0]
        position += 4 + ((length + 3) // 4) * 4
    return transaction, change


class FakeNat:
    """Scripted NAT model: mapped endpoint as a function of internal port and destination."""

    def __init__(self, mapping="endpoint-independent", filtering="endpoint-independent",
                 external_ip=EXTERNAL_IP, unstable=False, suppress_at=(), forge=None,
                 spoof_source=None, advertise_other=None, advertise_at=None):
        self.mapping = mapping
        self.filtering = filtering
        self.external_ip = external_ip
        self.unstable = unstable
        self.suppress_at = set(suppress_at)
        self.forge = forge
        self.spoof_source = spoof_source
        self.advertise_other = advertise_other
        self.advertise_at = advertise_at
        self.alternate_address = None
        self.alternate_port = None
        self.ports = {}
        self.next_port = 41000

    def mapped(self, local, destination, counter=0):
        if self.unstable:
            return self.external_ip, 42000 + (counter % 97)
        if self.mapping == "endpoint-independent":
            key = (local,)
        elif self.mapping == "address-dependent":
            key = (local, destination[0])
        else:
            key = (local, destination[0], destination[1])
        if key not in self.ports:
            self.ports[key] = self.next_port
            self.next_port += 1
        return self.external_ip, self.ports[key]

    def filter_allows(self, source, destination):
        if self.filtering == "endpoint-independent":
            return True
        if self.filtering == "address-dependent":
            return source[0] == destination[0]
        return source == destination

    def advertised_other(self, address):
        return self.advertise_other if self.advertise_at == address else None


class ScriptedStun(asyncio.DatagramProtocol):
    def __init__(self, nat, address, transports, family):
        self.nat = nat
        self.address = tuple(address)
        self.transports = transports
        self.family = family
        self.requests = []
        self.count = 0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        parsed = parse_request(data)
        if parsed is None:
            return
        transaction, change = parsed
        self.count += 1
        self.requests.append(((addr[0], addr[1]), change))
        if self.address in self.nat.suppress_at:
            return
        if self.nat.forge == "spoof-source":
            reply_from = tuple(self.nat.spoof_source)
        elif change & (CHANGE_IP | CHANGE_PORT):
            reply_from = self.address
            if change & CHANGE_IP and change & CHANGE_PORT and self.nat.alternate_address:
                reply_from = tuple(self.nat.alternate_address)
            elif change & CHANGE_PORT and self.nat.alternate_port:
                reply_from = tuple(self.nat.alternate_port)
        else:
            reply_from = self.address
        # The inbound filter is the NAT's behavior: a dropped reply is simply not delivered.
        if not self.nat.filter_allows(reply_from, self.address):
            return
        mapped = self.nat.mapped((addr[0], addr[1]), self.address, self.count)
        payload = build_success(transaction, mapped, self.nat.advertised_other(self.address), self.nat.forge)
        self.transports[reply_from].sendto(payload, addr)


class ScriptedNet:
    def __init__(self, nat, loop):
        self.nat = nat
        self.loop = loop
        self.transports = {}
        self.responders = {}

    async def add(self, host, port=0):
        family = socket.AF_INET6 if ":" in host else socket.AF_INET
        responder = ScriptedStun(self.nat, (host, port), self.transports, family)
        transport, _ = await self.loop.create_datagram_endpoint(
            lambda: responder, local_addr=(host, port), family=family)
        address = canonical_endpoint(transport.get_extra_info("sockname"), family)
        responder.address = address
        self.transports[address] = transport
        self.responders[address] = responder
        return address

    def close(self):
        for transport in self.transports.values():
            transport.close()


def point(address, **kwargs):
    return StunObservationPoint(address[0], address[1], **kwargs)


async def three_point_scenario(mapping, **nat_kwargs):
    nat = FakeNat(mapping=mapping, **nat_kwargs)
    net = ScriptedNet(nat, asyncio.get_running_loop())
    a = await net.add("127.0.0.1")
    b = await net.add("127.0.0.2")
    c = await net.add("127.0.0.1")
    return nat, net, (point(a), point(b), point(c))


@pytest.mark.asyncio
async def test_mapping_endpoint_independent():
    nat, net, points = await three_point_scenario("endpoint-independent")
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=2, repeats=2, timeout=.3))
        assert profile.mapping == MAPPING_ENDPOINT_INDEPENDENT
        assert "does not depend on the destination" in profile.mapping_evidence
        assert profile.mapping_partial is None
        assert not profile.errors
        assert len({sample.local_port for sample in profile.observations}) == 2  # several local ports used
        assert len(profile.observations) == 12  # 2 local ports x 3 points x 2 repeats
        assert profile.reachability == REACHABILITY_MEDIUM  # mapping known, filtering not testable here
    finally:
        net.close()


@pytest.mark.asyncio
async def test_mapping_address_dependent():
    nat, net, points = await three_point_scenario("address-dependent")
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=2, repeats=1, timeout=.3))
        assert profile.mapping == MAPPING_ADDRESS_DEPENDENT
        assert "depends on the destination address only" in profile.mapping_evidence
        # the two ports of 127.0.0.1 must have produced the same mapped endpoint per local port
        for local_port in {sample.local_port for sample in profile.observations}:
            by_point = {sample.destination: sample.mapped for sample in profile.observations
                        if sample.local_port == local_port}
            same_ip = [mapped for destination, mapped in by_point.items() if destination[0] == "127.0.0.1"]
            assert len(set(same_ip)) == 1
    finally:
        net.close()


@pytest.mark.asyncio
async def test_mapping_address_and_port_dependent():
    nat, net, points = await three_point_scenario("address-and-port-dependent")
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=2, repeats=1, timeout=.3))
        assert profile.mapping == MAPPING_ADDRESS_AND_PORT_DEPENDENT
        assert "depends on the destination port" in profile.mapping_evidence
        assert profile.reachability == REACHABILITY_LOW
        assert "IPv6" in profile.guidance and "对称" in profile.guidance
    finally:
        net.close()


@pytest.mark.asyncio
async def test_mapping_undetermined_with_one_destination_address():
    nat = FakeNat(mapping="address-dependent")
    net = ScriptedNet(nat, asyncio.get_running_loop())
    try:
        a = await net.add("127.0.0.1")
        c = await net.add("127.0.0.1")
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(c)), timeout=.3))
        assert profile.mapping == UNDETERMINED
        assert profile.mapping_partial == "endpoint-independent-or-address-dependent"
        assert "same destination address" in profile.mapping_evidence
        assert profile.reachability == "unknown"
        assert "不足以判断" in profile.guidance
    finally:
        net.close()


@pytest.mark.asyncio
async def test_mapping_undetermined_on_incomplete_observations():
    nat = FakeNat()
    net = ScriptedNet(nat, asyncio.get_running_loop())
    a = await net.add("127.0.0.1")
    b = await net.add("127.0.0.2")
    c = await net.add("127.0.0.1")
    nat.suppress_at = {b}
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(b), point(c)),
                                                         local_ports=2, repeats=1, timeout=.2))
        assert profile.mapping == UNDETERMINED
        assert "incomplete observations" in profile.mapping_evidence
        assert any(error.startswith("PROBE_TIMEOUT:127.0.0.2") for error in profile.errors)
        assert all(sample.destination != b for sample in profile.observations)
    finally:
        net.close()


@pytest.mark.asyncio
async def test_mapping_undetermined_on_unstable_repeats():
    nat = FakeNat(unstable=True)
    net = ScriptedNet(nat, asyncio.get_running_loop())
    try:
        a = await net.add("127.0.0.1")
        b = await net.add("127.0.0.2")
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(b)),
                                                          local_ports=1, repeats=2, timeout=.3))
        assert profile.mapping == UNDETERMINED
        assert "unstable" in profile.mapping_evidence
    finally:
        net.close()


def test_classify_mapping_edges():
    behavior, evidence, partial = classify_mapping([], [("127.0.0.1", 1), ("127.0.0.2", 1)])
    assert (behavior, partial) == (UNDETERMINED, None)
    assert "no Binding response" in evidence
    samples = [MappingSample(5001, ("127.0.0.1", 40111), ("203.0.113.7", 41000), 0),
               MappingSample(5001, ("127.0.0.2", 40112), ("203.0.113.7", 41000), 0)]
    assert classify_mapping(samples, [("127.0.0.1", 40111), ("127.0.0.2", 40112)])[0] == \
        MAPPING_ENDPOINT_INDEPENDENT
    samples.append(MappingSample(5001, ("127.0.0.1", 40111), ("203.0.113.7", 41001), 1))
    assert classify_mapping(samples, [("127.0.0.1", 40111), ("127.0.0.2", 40112)])[0] == UNDETERMINED


def test_classify_filtering_edges():
    primary = ("127.0.0.1", 5000)
    assert classify_filtering(FilteringEvidence(primary, None, None, None, None, True))[0] == UNDETERMINED
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.2", 5000), ("127.0.0.1", 5001),
                                                ("127.0.0.2", 5000), None, True))[0] == \
        FILTERING_ENDPOINT_INDEPENDENT
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.2", 5000), ("127.0.0.1", 5001),
                                                None, ("127.0.0.1", 5001), True))[0] == FILTERING_ADDRESS_DEPENDENT
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.2", 5000), ("127.0.0.1", 5001),
                                                None, None, True))[0] == FILTERING_ADDRESS_AND_PORT_DEPENDENT
    # a reply from the primary address to a CHANGE-REQUEST means the server ignored the request
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.2", 5000), ("127.0.0.1", 5001),
                                                primary, None, True))[0] == UNDETERMINED
    # a dead path must not be reported as address-and-port-dependent filtering
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.2", 5000), ("127.0.0.1", 5001),
                                                None, None, False))[0] == UNDETERMINED
    # an alternate that shares the primary address is not evidence of endpoint-independent filtering
    assert classify_filtering(FilteringEvidence(primary, ("127.0.0.1", 5002), ("127.0.0.1", 5001),
                                                ("127.0.0.1", 5002), None, True))[0] == UNDETERMINED


async def filtering_scenario(filtering, explicit=True, **nat_kwargs):
    nat = FakeNat(filtering=filtering, **nat_kwargs)
    net = ScriptedNet(nat, asyncio.get_running_loop())
    a = await net.add("127.0.0.1")
    b = await net.add("127.0.0.2")
    c = await net.add("127.0.0.1", b[1])  # same address as A, same port as B: the change-port source
    nat.alternate_address, nat.alternate_port = b, c
    if explicit:
        points = (point(a, alternate_address=b, alternate_port=c), point(b))
    else:
        nat.advertise_other, nat.advertise_at = b, a
        points = (point(a), point(b))
    profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=1, repeats=1, timeout=.25))
    return net, profile


@pytest.mark.asyncio
async def test_filtering_endpoint_independent():
    net, profile = await filtering_scenario("endpoint-independent")
    try:
        assert profile.filtering == FILTERING_ENDPOINT_INDEPENDENT
        assert "not restricted to the addresses already contacted" in profile.filtering_evidence
        assert profile.mapping == MAPPING_ENDPOINT_INDEPENDENT
        assert profile.reachability == REACHABILITY_HIGH
        assert "成功率较高" in profile.guidance
    finally:
        net.close()


@pytest.mark.asyncio
async def test_filtering_address_dependent():
    net, profile = await filtering_scenario("address-dependent")
    try:
        assert profile.filtering == FILTERING_ADDRESS_DEPENDENT
        assert "restricted to the contacted address" in profile.filtering_evidence
        assert profile.reachability == REACHABILITY_MEDIUM
        assert "同时" in profile.guidance
    finally:
        net.close()


@pytest.mark.asyncio
async def test_filtering_address_and_port_dependent():
    net, profile = await filtering_scenario("address-and-port-dependent")
    try:
        assert profile.filtering == FILTERING_ADDRESS_AND_PORT_DEPENDENT
        assert "contacted address and port" in profile.filtering_evidence
        assert profile.reachability == REACHABILITY_MEDIUM
    finally:
        net.close()


@pytest.mark.asyncio
async def test_filtering_uses_advertised_other_address():
    net, profile = await filtering_scenario("address-dependent", explicit=False)
    try:
        assert profile.filtering == FILTERING_ADDRESS_DEPENDENT
    finally:
        net.close()


@pytest.mark.asyncio
async def test_filtering_undetermined_without_alternate_or_other_address():
    nat = FakeNat()
    net = ScriptedNet(nat, asyncio.get_running_loop())
    try:
        a = await net.add("127.0.0.1")
        b = await net.add("127.0.0.2")
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(b)), timeout=.25))
        assert profile.filtering == UNDETERMINED
        assert "no alternate source is known" in profile.filtering_evidence
    finally:
        net.close()


@pytest.mark.asyncio
async def test_filtering_undetermined_when_server_ignores_change_request():
    nat = FakeNat()
    net = ScriptedNet(nat, asyncio.get_running_loop())
    try:
        a = await net.add("127.0.0.1")
        b = await net.add("127.0.0.2")
        c = await net.add("127.0.0.1")
        nat.alternate_address, nat.alternate_port = None, None  # responder keeps answering from primary
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1",
                                                          (point(a, alternate_address=b, alternate_port=c), point(b)),
                                                          local_ports=1, repeats=1, timeout=.25))
        assert profile.filtering == UNDETERMINED
        assert "RFC 5780 filtering test" in profile.filtering_evidence
    finally:
        net.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("forge", ["bad-tid", "bad-cookie", "no-xor", "spoof-source"])
async def test_forged_or_malformed_responses_never_count(forge):
    nat = FakeNat(forge=forge)
    net = ScriptedNet(nat, asyncio.get_running_loop())
    a = await net.add("127.0.0.1")
    b = await net.add("127.0.0.2")
    spoof = await net.add("127.0.0.3")
    nat.spoof_source = spoof
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(b)),
                                                          local_ports=1, repeats=1, timeout=.2))
        assert profile.mapping == UNDETERMINED
        assert not profile.observations
        assert any(error.startswith("RESPONSE_REJECTED") for error in profile.errors)
    finally:
        net.close()


@pytest.mark.asyncio
async def test_only_configured_points_are_contacted():
    nat = FakeNat()
    net = ScriptedNet(nat, asyncio.get_running_loop())
    a = await net.add("127.0.0.1")
    b = await net.add("127.0.0.2")
    third = await net.add("127.0.0.3")
    try:
        await probe_nat_behavior(NatProbeConfig("127.0.0.1", (point(a), point(b)), local_ports=1,
                                                 repeats=1, timeout=.25))
        assert net.responders[a].requests and net.responders[b].requests
        assert net.responders[third].requests == []  # no discovery, no third-party STUN
    finally:
        net.close()


@pytest.mark.asyncio
async def test_report_keeps_observations_and_inference_apart_and_redacts_by_default():
    nat, net, points = await three_point_scenario("endpoint-independent")
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=1, repeats=1, timeout=.3))
        report = profile.report()
        assert report["mapping"] == MAPPING_ENDPOINT_INDEPENDENT
        assert report["distinctMappedEndpointCount"] == len(profile.mapped_endpoints) == 1
        assert "not the mapped addresses themselves" in report["inferenceNote"]
        assert "mappedEndpoints" not in report
        assert EXTERNAL_IP not in json.dumps(report)  # public mapped addresses stay local by default
        local = profile.report(include_mappings=True)
        assert local["mappedEndpointsIncluded"] is True
        assert [endpoint[0] for endpoint in local["mappedEndpoints"]] == [EXTERNAL_IP]
        assert len(local["observations"]) == len(profile.observations)
    finally:
        net.close()


def test_config_and_cli_reject_unusable_inputs():
    a = StunObservationPoint("127.0.0.1", 40001)
    b = StunObservationPoint("127.0.0.2", 40001)
    with pytest.raises(ValueError, match="INSUFFICIENT_OBSERVATION_POINTS"):
        NatProbeConfig("127.0.0.1", (a,)).validate()
    with pytest.raises(ValueError, match="INSUFFICIENT_OBSERVATION_POINTS"):
        NatProbeConfig("127.0.0.1", (a, StunObservationPoint("127.0.0.1", 40001))).validate()
    with pytest.raises(ValueError, match="EXPLICIT_BIND_REQUIRED"):
        NatProbeConfig("0.0.0.0", (a, b)).validate()
    with pytest.raises(ValueError):
        NatProbeConfig("127.0.0.1", (StunObservationPoint("stun.example.com", 3478), b)).validate()
    with pytest.raises(ValueError, match="ENDPOINT_FAMILY_MISMATCH"):
        NatProbeConfig("127.0.0.1", (StunObservationPoint("::1", 3478), b)).validate()
    with pytest.raises(ValueError, match="INVALID_LOCAL_PORT_COUNT"):
        NatProbeConfig("127.0.0.1", (a, b), local_ports=0).validate()
    with pytest.raises(ValueError, match="INVALID_TIMEOUT"):
        NatProbeConfig("127.0.0.1", (a, b), timeout=0).validate()
    # alternates must actually be alternatives of that point, or the filtering test would mislead
    with pytest.raises(ValueError, match="ALTERNATE_IS_PRIMARY"):
        NatProbeConfig("127.0.0.1", (StunObservationPoint("127.0.0.1", 40001, alternate_address=("127.0.0.1", 40001)), b),
                       ).validate()
    with pytest.raises(ValueError, match="ALTERNATE_ADDRESS_MUST_DIFFER_IN_ADDRESS"):
        NatProbeConfig("127.0.0.1", (StunObservationPoint("127.0.0.1", 40001, alternate_address=("127.0.0.1", 40002)),
                                     b)).validate()
    with pytest.raises(ValueError, match="ALTERNATE_PORT_MUST_SHARE_ADDRESS"):
        NatProbeConfig("127.0.0.1", (StunObservationPoint("127.0.0.1", 40001, alternate_port=("127.0.0.2", 40002)),
                                     b)).validate()
    assert NatBehaviorProbe(NatProbeConfig("127.0.0.1", (a, b))).config.points == (a, b)
    with pytest.raises(argparse.ArgumentTypeError):
        _parse_point("127.0.0.1")
    with pytest.raises(SystemExit):
        main(["--server", "127.0.0.1:3478", "--bind", "127.0.0.1"])


def test_cli_emitter_survives_a_chinese_payload(capsys):
    from p2pchat.native.nat_behavior import _emit
    _emit({"summary": "你的网络：映射行为=无法判定（观测不足）", "mapping": UNDETERMINED})
    output = capsys.readouterr().out
    assert "无法判定" in output
    assert json.loads(output)["mapping"] == UNDETERMINED


@pytest.mark.asyncio
async def test_summary_is_user_readable_and_labels_the_inference():
    nat, net, points = await three_point_scenario("address-and-port-dependent")
    try:
        profile = await probe_nat_behavior(NatProbeConfig("127.0.0.1", points, local_ports=1, repeats=1, timeout=.3))
        assert profile.mapping_label == "地址+端口相关（对称型）"
        assert "映射行为=地址+端口相关（对称型）" in profile.summary
        assert "直连打洞预期成功率=低" in profile.summary
        assert "IPv6" in profile.summary
        report = profile.report()
        assert report["mappingLabel"] == profile.mapping_label
        assert report["summary"] == profile.summary
        assert report["reachabilityLabel"] == "低"
        assert EXTERNAL_IP not in json.dumps(report, ensure_ascii=False)
    finally:
        net.close()
