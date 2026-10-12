"""Net-env health check: reuse of nat_behavior/ipv6_reach, honest verdicts, bounds, redaction.

Controlled sources cover the classification branches (they are injected, not measured);
two tests use real loopback sockets with a controlled STUN responder, and the t48 module
is exercised for real once. Real home-network NAT type and real IPv6 inbound allowance
stay NOT_RUN and are asserted to be listed as unmeasured.
"""
import asyncio
import ipaddress
import json
import socket
import time
import types
import uuid

import pytest

from p2pchat.backend.protocol import fields as protocol_fields
from p2pchat.backend.telemetry import validate_event
from p2pchat.native import ipv6_reach as reach
from p2pchat.native import nat_behavior as nat
from p2pchat.native import net_env as env
from p2pchat.native.net_env import NetEnvConfig, NetEnvError, Sources
from p2pchat.server import stun_binding as server_stun_reply

CID = str(uuid.uuid4())
AID = str(uuid.uuid4())
SESSION = str(uuid.uuid4())

ROUTE4_DEFAULT_WITH_GATEWAY = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "wlan0\t00000000\t0101A8C0\t0003\t0\t0\t600\t00000000\t0\t0\t0\n"
    "wlan0\t0001A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n")
ROUTE4_DEFAULT_NO_GATEWAY = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "eth0\t00000000\t00000000\t0001\t0\t0\t100\t00000000\t0\t0\t0\n")
ROUTE4_NO_DEFAULT = (
    "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
    "eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n")
ROUTE6_DEFAULT_ZERO_GW = ("0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 32
                          + " 00000100 00000001 00000000 00000001 wlan0\n")
ROUTE6_DEFAULT_WITH_GW = ("0" * 32 + " 00 " + "0" * 32 + " 00 " + "0" * 31 + "1"
                          + " 00000100 00000001 00000000 00000001 wlan0\n")
ROUTE6_NONE = ("fe800000000000000000000000000000 40 " + "0" * 32 + " 00 " + "0" * 32
               + " 00000100 00000001 00000000 00000001 wlan0\n")


def v6(address, *, scope="global", temporary=None, prefix=64, interface="wlan0", deprecated=False, dynamic=False):
    return reach.Ipv6Address(address=address, interface=interface, scope=scope, temporary=temporary,
                             prefix_length=prefix, deprecated=deprecated, dynamic=dynamic)


V4 = [{"address": "192.168.1.20", "interface": "wlan0", "prefixLength": 24, "temporary": None}]
V6_STABLE = [v6("2606:4700:1::5", temporary=False)]
V6_TEMP = [v6("2606:4700:1::dead", temporary=True)]
V6_MIXED = [v6("2606:4700:1::5", temporary=False), v6("2606:4700:1::dead", temporary=True),
            v6("fe80::1", scope="link", temporary=False), v6("fd00::1", scope="global", temporary=False),
            v6("::1", scope="host", temporary=False)]


def point(host, port):
    return nat.StunObservationPoint(host, port)


def stun_reply(address="203.0.113.7", port=40000, family=4, observation=None):
    return {"address": address, "port": port, "family": family,
            "rttMs": 12.0, "observation": observation or "mapped-address-only-not-nat-type"}


async def answer(sock, server, timeout):
    """Controlled Binding answer: no third party, no socket of its own."""
    return stun_reply(family=6 if ":" in str(server[0]) else 4)


def profile(mapping, filtering, reachability=None):
    mapping_evidence = nat.classify_mapping([], ())[1]
    filtering_evidence = nat.classify_filtering(nat.FilteringEvidence(("192.0.2.1", 3478), None, None, None, None, True))[1]
    return nat.NatProfile(mapping, mapping_evidence, None, filtering, filtering_evidence,
                          reachability or nat.reachability_for(mapping, filtering),
                          nat.guidance_for(mapping, filtering, reachability or nat.reachability_for(mapping, filtering), None))


def sources(**overrides):
    base = dict(platform="linux", ipv4_addresses=lambda: list(V4), ipv6_addresses=lambda: list(V6_STABLE),
                ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY, ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW)
    base.update(overrides)
    return Sources(**base)


async def check(config=None, *, src=None, **source_overrides):
    return await env.health_check(config or NetEnvConfig(), sources=src or sources(**source_overrides))


# --- ① addresses -------------------------------------------------------------

@pytest.mark.asyncio
async def test_address_list_marks_scope_globalness_and_temporary_state():
    report = await check(src=Sources(platform="linux", ipv4_addresses=lambda: list(V4),
                                     ipv6_addresses=lambda: list(V6_MIXED),
                                     ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY,
                                     ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW))
    component = report.component("addresses")
    assert (component.status, component.reason) == (env.DETERMINED, "LOCAL_ADDRESSES_ENUMERATED")
    summary = component.detail
    assert (summary["ipv4"], summary["ipv6"]) == (1, 5)
    assert (summary["globalV6Stable"], summary["globalV6Temporary"], summary["linkLocal"], summary["ula"]) == (1, 1, 1, 1)
    assert summary["hasGlobalV6Stable"] is True and summary["hasGlobalV6TemporaryOnly"] is False
    records = {record["address"]: record for record in summary["records"]}
    assert records["2606:4700:1::5"]["stability"] == "stable" and records["2606:4700:1::5"]["isGlobal"] is True
    assert records["2606:4700:1::dead"]["stability"] == "temporary"
    assert records["fe80::1"]["scope"] == "link-local" and records["fe80::1"]["stability"] == "not-global"
    # IPv4 has no RFC 4941 concept: never reported as "stable".
    assert records["192.168.1.20"]["temporary"] is None and records["192.168.1.20"]["stability"] == "unverified"
    assert env.redact_interface("wlan0") != "wlan0" and len(env.redact_interface("wlan0")) == 8
    assert summary["temporaryConcept"].startswith("RFC 4941")


@pytest.mark.asyncio
async def test_temporary_only_v6_is_visible_and_not_called_stable():
    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478), point("192.0.2.2", 3478)),
                                             bind_host_v4="127.0.0.1"),
                         ipv6_addresses=lambda: list(V6_TEMP), udp_binding=lambda *args: None)
    summary = report.component("addresses").detail
    assert summary["hasGlobalV6TemporaryOnly"] is True and summary["hasGlobalV6Stable"] is False
    item = next(entry for entry in report.recommendations if entry["method"] == env.IPV6_DIRECT)
    assert (item["status"], item["reason"]) == (env.POSSIBLE, "ONLY_TEMPORARY_GLOBAL_V6")


# --- ② routes ---------------------------------------------------------------

def test_routes_are_parsed_per_family_including_gateway_presence():
    assert env.parse_ipv4_routes(ROUTE4_DEFAULT_WITH_GATEWAY) == {
        "present": True, "gatewayPresent": True, "interface": "wlan0", "gateway": "192.168.1.1"}
    assert env.parse_ipv4_routes(ROUTE4_DEFAULT_NO_GATEWAY)["gatewayPresent"] is False
    assert env.parse_ipv4_routes(ROUTE4_NO_DEFAULT)["present"] is False
    assert env.parse_ipv6_routes(ROUTE6_DEFAULT_ZERO_GW) == {
        "present": True, "gatewayPresent": False, "interface": "wlan0", "gateway": None}
    assert env.parse_ipv6_routes(ROUTE6_DEFAULT_WITH_GW)["gatewayPresent"] is True
    assert env.parse_ipv6_routes(ROUTE6_NONE)["present"] is False
    assert env.parse_ipv4_routes(None) is None and env.parse_ipv6_routes(None) is None


@pytest.mark.asyncio
async def test_routes_component_keeps_families_separate():
    report = await check()
    routes = report.component("routes")
    assert (routes.status, routes.reason) == (env.DETERMINED, "ROUTES_READ")
    assert routes.detail["ipv4Default"] is True and routes.detail["ipv6Default"] is True
    assert routes.detail["ipv4GatewayPresent"] is True and routes.detail["ipv6GatewayPresent"] is False
    assert routes.detail["ipv4GatewayAddress"] == "192.168.1.1"
    # The IPv6 default-route answer comes from t48's module, not a second rule here.
    assert routes.detail["ipv6DefaultSource"] == "ipv6_reach.has_default_v6_route"
    assert routes.detail["ipv6Default"] == reach.has_default_v6_route(ROUTE6_DEFAULT_ZERO_GW)

    without_module = types.SimpleNamespace(enumerate_addresses=lambda: list(V6_STABLE))
    report = await check(reach_module=without_module)
    routes = report.component("routes")
    assert routes.detail["ipv6DefaultSource"] == "local-route-table-parse"
    assert routes.detail["ipv6Default"] is True and routes.detail["ipv6GatewayPresent"] is False


# --- ④ UDP egress -----------------------------------------------------------

@pytest.mark.asyncio
async def test_udp_egress_determined_and_rtt_is_labelled_probe_only():
    calls = []

    async def fake_binding(sock, server, timeout):
        calls.append((server, timeout, sock.getsockname()))
        return stun_reply()

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478),),
                                             bind_host_v4="127.0.0.1"),
                         udp_binding=fake_binding)
    egress = report.component("udpEgress")
    assert (egress.status, egress.reason) == (env.DETERMINED, "UDP_OUTBOUND_CONFIRMED")
    assert egress.detail["answeredPoints"] == 1 and egress.detail["probeRttMs"] >= 0
    assert "not-chat-latency" in egress.detail["probeRttMeaning"]
    assert calls and calls[0][0] == ("192.0.2.1", 3478) and calls[0][2][1] != 0
    flat = json.dumps(report.local_report())
    assert '"latency"' not in flat and '"chatRtt"' not in flat and '"rttMs"' not in flat
    assert report.center_report()["redaction"]["probeRtt"] == "probe-round-trip-only-not-chat-latency"
    assert "127.0.0.1" not in json.dumps(report.center_report())


@pytest.mark.asyncio
async def test_no_observation_point_opens_no_socket_and_stays_not_tested():
    def explode(*args, **kwargs):
        raise AssertionError("没有观测点时不允许发起任何外部探测")

    report = await check(config=NetEnvConfig(), udp_binding=explode, nat_probe=explode, reach_probe=explode)
    assert report.component("udpEgress") == env.not_tested(
        "udpEgress", "NO_OBSERVATION_POINT", "没有配置任何观测点，因此没有做 UDP 出站探测")
    assert (report.component("natBehavior").status, report.component("natBehavior").reason) == (
        env.NOT_TESTED, "NO_OBSERVATION_POINT")
    assert report.identity == {"session": None, "connectionId": None, "attemptId": None}


@pytest.mark.asyncio
async def test_unreachable_observation_point_is_insufficient_not_blocked():
    async def no_response(sock, server, timeout):
        raise asyncio.TimeoutError()

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478),),
                                             bind_host_v4="127.0.0.1"),
                         udp_binding=no_response)
    egress = report.component("udpEgress")
    assert (egress.status, egress.reason) == (env.INSUFFICIENT, "NO_RESPONSE_FROM_OBSERVATION_POINT")
    assert egress.status != env.UNAVAILABLE
    assert "不能据此断言" in egress.evidence

    async def send_failed(sock, server, timeout):
        raise OSError(13, "permission denied")

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478),),
                                             bind_host_v4="127.0.0.1"),
                         udp_binding=send_failed)
    assert (report.component("udpEgress").status, report.component("udpEgress").reason) == (
        env.UNAVAILABLE, "UDP_SEND_FAILED")

    report = await check(config=NetEnvConfig(observation_points=(point("2606:4700:1::9", 3478),)),
                         ipv6_addresses=lambda: None, udp_binding=no_response)
    assert report.component("udpEgress").reason == "NO_USABLE_LOCAL_ADDRESS"
    assert report.component("udpEgress").status == env.NOT_TESTED


@pytest.mark.asyncio
async def test_real_loopback_stun_responder_proves_the_udp_path():
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    responder.setblocking(False)
    port = responder.getsockname()[1]
    seen = []

    async def serve():
        loop = asyncio.get_running_loop()
        while True:
            try:
                data, address = await loop.sock_recvfrom(responder, 2048)
            except (OSError, asyncio.CancelledError):
                return
            reply = server_stun_reply(data, address)
            if reply:
                seen.append(address)
                await loop.sock_sendto(responder, reply, address)

    task = asyncio.create_task(serve())
    try:
        report = await check(config=NetEnvConfig(observation_points=(point("127.0.0.1", port),),
                                                 bind_host_v4="127.0.0.1", udp_probe_timeout=0.5),
                             ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY)
        egress = report.component("udpEgress")
        assert (egress.status, egress.reason) == (env.DETERMINED, "UDP_OUTBOUND_CONFIRMED")
        assert egress.detail["answeredPoints"] == 1 and egress.detail["probeRttMs"] > 0
        assert egress.detail["mappedScopes"] == ["loopback"] and seen
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        responder.close()


# --- ③ NAT behavior (reuse) --------------------------------------------------

@pytest.mark.asyncio
async def test_nat_behavior_is_called_with_a_real_config_and_undetermined_is_never_symmetric():
    captured = {}

    async def spy(config):
        captured["config"] = config
        return profile(nat.UNDETERMINED, nat.UNDETERMINED)

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478), point("192.0.2.2", 3478)),
                                             bind_host_v4="127.0.0.1"),
                         nat_probe=spy)
    nat_component = report.component("natBehavior")
    assert (nat_component.status, nat_component.reason) == (env.INSUFFICIENT, "NAT_BEHAVIOR_UNDETERMINED")
    assert isinstance(captured["config"], nat.NatProbeConfig)
    assert captured["config"].bind_host == "127.0.0.1" and captured["config"].points[1].host == "192.0.2.2"
    assert nat_component.detail["mapping"] == nat.UNDETERMINED
    assert nat_component.detail["mappingLabel"] == nat.MAPPING_LABELS[nat.UNDETERMINED]
    assert nat_component.detail["summary"] == profile(nat.UNDETERMINED, nat.UNDETERMINED).summary
    item = next(entry for entry in report.recommendations if entry["method"] == env.PORT_PREDICTION)
    assert (item["status"], item["reason"]) == (env.UNKNOWN, "NAT_BEHAVIOR_EVIDENCE_INSUFFICIENT")
    assert "对称" not in item["plain"] and "可打洞" not in item["plain"]
    assert "symmetric" not in json.dumps(report.center_report()).lower()


@pytest.mark.asyncio
async def test_symmetric_mapping_enables_port_prediction_only_as_fallback():
    async def spy(config):
        return profile(nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT, nat.FILTERING_ADDRESS_DEPENDENT)

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478), point("192.0.2.2", 3478)),
                                             bind_host_v4="127.0.0.1"),
                         nat_probe=spy)
    assert report.component("natBehavior").status == env.DETERMINED
    item = next(entry for entry in report.recommendations if entry["method"] == env.PORT_PREDICTION)
    assert (item["status"], item["reason"]) == (env.POSSIBLE, "SYMMETRIC_MAPPING_OBSERVED")


@pytest.mark.asyncio
async def test_single_observation_point_is_insufficient_without_calling_anything():
    calls = []

    async def spy(config):
        calls.append(config)
        return profile(nat.MAPPING_ENDPOINT_INDEPENDENT, nat.FILTERING_ENDPOINT_INDEPENDENT)

    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478),)),
                         nat_probe=spy)
    assert (report.component("natBehavior").status, report.component("natBehavior").reason) == (
        env.INSUFFICIENT, "INSUFFICIENT_OBSERVATION_POINTS")
    assert calls == []
    # The rule itself belongs to nat_behavior and is reused, not re-implemented.
    with pytest.raises(ValueError, match="INSUFFICIENT_OBSERVATION_POINTS"):
        nat.NatProbeConfig("127.0.0.1", (point("192.0.2.1", 3478),)).validate()


@pytest.mark.asyncio
async def test_real_nat_behavior_module_stays_undetermined_on_one_address():
    """Two real loopback responders, one destination address: honest UNDETERMINED.

    This exercises the real nat_behavior code path over real sockets (no stub), and
    asserts the module copies its verdict instead of inventing a NAT type.
    """
    responders, ports = [], []
    for _ in range(2):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sock.setblocking(False)
        responders.append(sock)
        ports.append(sock.getsockname()[1])

    async def serve(sock):
        loop = asyncio.get_running_loop()
        while True:
            try:
                data, address = await loop.sock_recvfrom(sock, 2048)
            except (OSError, asyncio.CancelledError):
                return
            reply = server_stun_reply(data, address)
            if reply:
                await loop.sock_sendto(sock, reply, address)

    tasks = [asyncio.create_task(serve(sock)) for sock in responders]
    try:
        report = await check(config=NetEnvConfig(observation_points=(point("127.0.0.1", ports[0]),
                                                                     point("127.0.0.1", ports[1])),
                                                 bind_host_v4="127.0.0.1", nat_local_ports=1, nat_repeats=1,
                                                 nat_timeout=0.4, udp_probe_timeout=0.4),
                             udp_binding=lambda *args: None, ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY)
        nat_component = report.component("natBehavior")
        assert nat_component.status in {env.DETERMINED, env.INSUFFICIENT}
        if nat_component.status == env.INSUFFICIENT:
            assert nat_component.detail["mapping"] == nat.UNDETERMINED
            assert "same destination address" in nat_component.detail["mappingEvidence"]
        item = next(entry for entry in report.recommendations if entry["method"] == env.PORT_PREDICTION)
        assert item["reason"] in {"NAT_BEHAVIOR_EVIDENCE_INSUFFICIENT", "SYMMETRIC_MAPPING_OBSERVED"}
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for sock in responders:
            sock.close()


# --- ⑤ IPv6-only / NAT64 ----------------------------------------------------

@pytest.mark.asyncio
async def test_ipv6_only_detection_uses_addresses_and_routes_together():
    report = await check(ipv4_addresses=lambda: None, ipv6_addresses=lambda: list(V6_STABLE),
                         ipv4_routes=lambda: ROUTE4_NO_DEFAULT, ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW)
    assert report.component("ipv6Only").detail == {"likelyIpv6Only": True}
    assert report.component("ipv6Only").reason == "IPV6_ONLY_LIKELY"

    report = await check()
    assert report.component("ipv6Only").detail == {"likelyIpv6Only": False}
    assert report.component("ipv6Only").reason == "IPV4_PATH_PRESENT"

    report = await check(ipv4_addresses=lambda: [], ipv6_addresses=lambda: [],
                         ipv4_routes=lambda: ROUTE4_NO_DEFAULT, ipv6_routes=lambda: ROUTE6_NONE)
    assert (report.component("ipv6Only").status, report.component("ipv6Only").reason) == (
        env.DETERMINED, "NO_IP_PATH_OBSERVED")


@pytest.mark.asyncio
async def test_nat64_signs_are_reported_only_with_evidence():
    only_v6 = dict(ipv4_addresses=lambda: None, ipv4_routes=lambda: ROUTE4_NO_DEFAULT,
                   ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW)

    targets = []

    async def answered(sock, server, timeout):
        targets.append(server)
        return stun_reply(family=6)

    async def silent(sock, server, timeout):
        targets.append(server)
        raise asyncio.TimeoutError()

    report = await check(config=NetEnvConfig(observation_points=(point("203.0.113.9", 3478),),
                                             nat64_probe=True, bind_host_v4="127.0.0.1",
                                             bind_host_v6="::1"),
                         udp_binding=answered, **only_v6)
    assert (report.component("nat64").status, report.component("nat64").reason) == (
        env.DETERMINED, "NAT64_SIGNS_PRESENT")
    assert report.component("nat64").detail["probeAttempted"] is True
    assert any(str(target[0]).startswith("64:ff9b::") for target in targets), targets

    report = await check(config=NetEnvConfig(observation_points=(point("203.0.113.9", 3478),),
                                             nat64_probe=True, bind_host_v4="127.0.0.1",
                                             bind_host_v6="::1"),
                         udp_binding=silent, **only_v6)
    assert (report.component("nat64").status, report.component("nat64").reason) == (
        env.INSUFFICIENT, "NAT64_SYNTHESIZED_PROBE_NO_RESPONSE")

    report = await check(config=NetEnvConfig(observation_points=(point("203.0.113.9", 3478),)), **only_v6)
    assert (report.component("nat64").status, report.component("nat64").reason) == (
        env.NOT_TESTED, "NAT64_PROBE_NOT_REQUESTED")

    report = await check()
    assert (report.component("nat64").status, report.component("nat64").reason) == (
        env.NOT_APPLICABLE, "IPV4_PATH_PRESENT")

    report = await check(ipv6_addresses=lambda: [v6("64:ff9b::c000:201", temporary=False)], **only_v6)
    assert (report.component("nat64").status, report.component("nat64").reason) == (
        env.DETERMINED, "NAT64_WELL_KNOWN_PREFIX_ADDRESS")


# --- inbound reachability (t48 reuse) ---------------------------------------

class FakeReach:
    REACHED_BY_SERVER = reach.REACHED_BY_SERVER
    TIMEOUT = reach.TIMEOUT
    REFUSED_BY_LOCAL_POLICY = reach.REFUSED_BY_LOCAL_POLICY
    NO_GLOBAL_V6 = reach.NO_GLOBAL_V6
    NO_V6_ROUTE = reach.NO_V6_ROUTE
    ADDRESS_ROTATED = reach.ADDRESS_ROTATED
    ReachOptions = reach.ReachOptions

    def __init__(self, verdict, note="地址可能轮换，回连结果只对当前时刻成立", throws=None):
        self.verdict, self.note, self.throws = verdict, note, throws
        self.calls = []

    def probe_reachability(self, options):
        self.calls.append(options)

        async def run():
            if self.throws:
                raise self.throws
            return types.SimpleNamespace(verdict=self.verdict, address_type="stable", note=self.note,
                                         offer={"token": "SECRET-TOKEN"}, port=12345)
        return run()

    def enumerate_addresses(self):
        return list(V6_STABLE)


def inbound_config(**overrides):
    base = dict(observation_points=(point("192.0.2.1", 3478),), bind_host_v4="127.0.0.1",
                inbound_probe=True, consent=True, session=SESSION, connection_id=CID, attempt_id=AID)
    base.update(overrides)
    return NetEnvConfig(**base)


@pytest.mark.asyncio
@pytest.mark.parametrize("verdict,status,reason", [
    (reach.REACHED_BY_SERVER, env.DETERMINED, "INBOUND_REACHED_BY_SERVER"),
    (reach.TIMEOUT, env.INSUFFICIENT, "INBOUND_NOT_PROVEN"),
    (reach.ADDRESS_ROTATED, env.INSUFFICIENT, "ADDRESS_ROTATED"),
    (reach.NO_GLOBAL_V6, env.DETERMINED, reach.NO_GLOBAL_V6),
    (reach.NO_V6_ROUTE, env.DETERMINED, reach.NO_V6_ROUTE),
    (reach.REFUSED_BY_LOCAL_POLICY, env.DETERMINED, "REFUSED_BY_LOCAL_POLICY"),
    ("SOMETHING_NEW", env.INSUFFICIENT, "UNKNOWN_REACH_VERDICT"),
])
async def test_inbound_verdicts_are_mapped_honestly(verdict, status, reason):
    fake = FakeReach(verdict)
    report = await check(config=inbound_config(), reach_module=fake, udp_binding=lambda *args: None)
    component = report.component("inboundReachability")
    assert (component.status, component.reason) == (status, reason)
    assert fake.calls and fake.calls[0].consent is True
    if verdict == reach.TIMEOUT:
        assert "不能证明" in component.evidence
    flat = json.dumps(report.local_report()) + json.dumps(report.center_report())
    assert "SECRET-TOKEN" not in flat and "token" not in json.dumps(report.center_report())


@pytest.mark.asyncio
async def test_inbound_requires_request_and_consent_and_context():
    fake = FakeReach(reach.REACHED_BY_SERVER)
    report = await check(config=inbound_config(inbound_probe=False), reach_module=fake, udp_binding=lambda *args: None)
    assert (report.component("inboundReachability").status, report.component("inboundReachability").reason) == (
        env.NOT_TESTED, "INBOUND_PROBE_NOT_REQUESTED")
    assert fake.calls == []

    fake = FakeReach(reach.REACHED_BY_SERVER)
    report = await check(config=inbound_config(consent=False), reach_module=fake, udp_binding=lambda *args: None)
    assert (report.component("inboundReachability").status, report.component("inboundReachability").reason) == (
        env.NOT_TESTED, "CONSENT_REQUIRED")
    assert fake.calls == []

    fake = FakeReach(reach.REACHED_BY_SERVER)
    report = await check(config=inbound_config(session="", connection_id="", attempt_id=""),
                         reach_module=fake, udp_binding=lambda *args: None)
    assert report.component("inboundReachability").reason == "REACH_CONTEXT_REQUIRED"
    assert fake.calls == []

    fake = FakeReach(reach.REACHED_BY_SERVER)
    report = await check(config=NetEnvConfig(inbound_probe=True, consent=True, session=SESSION,
                                             connection_id=CID, attempt_id=AID),
                         reach_module=fake, udp_binding=lambda *args: None)
    # Inbound reachability needs no observation point: it must still run, and it must
    # not invent a mapped-endpoint observation to get there.
    assert (report.component("inboundReachability").status, report.component("inboundReachability").reason) == (
        env.DETERMINED, "INBOUND_REACHED_BY_SERVER")
    assert len(fake.calls) == 1 and report.component("udpEgress").reason == "NO_OBSERVATION_POINT"


@pytest.mark.asyncio
async def test_missing_t48_module_and_missing_entry_point_are_not_guessed(monkeypatch):
    monkeypatch.setattr(env, "reach", None)
    report = await check(ipv6_addresses=lambda: None, udp_binding=lambda *args: None)
    assert (report.component("inboundReachability").status, report.component("inboundReachability").reason) == (
        env.NOT_TESTED, "IPV6_REACH_MODULE_UNAVAILABLE")

    stub = types.SimpleNamespace(enumerate_addresses=lambda: list(V6_STABLE))
    report = await check(config=inbound_config(), reach_module=stub, udp_binding=lambda *args: None)
    assert (report.component("inboundReachability").status, report.component("inboundReachability").reason) == (
        env.NOT_TESTED, "IPV6_REACH_PROBE_MISSING")


@pytest.mark.asyncio
async def test_real_t48_module_is_exercised_without_a_callback():
    """Real module, real config: this host has no global v6 (or no callback), and the
    mapping must stay honest instead of claiming a reachable inbound path."""
    report = await check(config=inbound_config(total_budget_seconds=3.0), udp_binding=lambda *args: None)
    component = report.component("inboundReachability")
    assert component.reason in {reach.NO_GLOBAL_V6, reach.NO_V6_ROUTE, "INBOUND_NOT_PROVEN", "ADDRESS_ROTATED",
                               "UNKNOWN_REACH_VERDICT"}
    assert component.status in {env.DETERMINED, env.INSUFFICIENT}
    if component.reason == "INBOUND_NOT_PROVEN":
        assert component.status == env.INSUFFICIENT
    assert report.component("inboundReachability").detail.get("verdict") is not None


# --- recommendations + bounds -----------------------------------------------

@pytest.mark.asyncio
async def test_recommendation_priority_is_fixed_and_never_guesses():
    report = await check(ipv6_addresses=lambda: [v6("fe80::1", scope="link", temporary=False)])
    assert [item["method"] for item in report.recommendations] == list(env.METHOD_ORDER)
    assert [item["rank"] for item in report.recommendations] == [1, 2, 3]
    item = next(entry for entry in report.recommendations if entry["method"] == env.IPV6_DIRECT)
    assert item["reason"] == "NO_GLOBAL_V6" and item["status"] == env.UNAVAILABLE
    assert all(entry["status"] in env.RECOMMENDATION_STATUSES for entry in report.recommendations)

    report = await check(ipv4_addresses=lambda: None, ipv6_addresses=lambda: None,
                         ipv4_routes=lambda: None, ipv6_routes=lambda: None)
    item = next(entry for entry in report.recommendations if entry["method"] == env.IPV6_DIRECT)
    assert (item["status"], item["reason"]) == (env.UNKNOWN, "ADDRESS_EVIDENCE_MISSING")
    assert item["status"] != env.RECOMMENDED


@pytest.mark.asyncio
async def test_gateway_mapping_follows_route_evidence():
    report = await check()
    item = next(entry for entry in report.recommendations if entry["method"] == env.GATEWAY_MAPPING)
    assert (item["status"], item["reason"]) == (env.POSSIBLE, "GATEWAY_PRESENT_OPT_IN_REQUIRED")
    assert "同意" in item["plain"]

    report = await check(ipv4_routes=lambda: None, ipv6_routes=lambda: None)
    item = next(entry for entry in report.recommendations if entry["method"] == env.GATEWAY_MAPPING)
    assert (item["status"], item["reason"]) == (env.UNKNOWN, "ROUTE_EVIDENCE_MISSING")

    report = await check(ipv4_routes=lambda: ROUTE4_DEFAULT_NO_GATEWAY, ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW)
    item = next(entry for entry in report.recommendations if entry["method"] == env.GATEWAY_MAPPING)
    assert (item["status"], item["reason"]) == (env.UNAVAILABLE, "NO_DEFAULT_GATEWAY")


@pytest.mark.asyncio
async def test_total_budget_bounds_a_hanging_probe():
    async def hang(config):
        await asyncio.sleep(5)
        return profile(nat.UNDETERMINED, nat.UNDETERMINED)

    started = time.monotonic()
    report = await check(config=NetEnvConfig(observation_points=(point("192.0.2.1", 3478), point("192.0.2.2", 3478)),
                                             bind_host_v4="127.0.0.1", total_budget_seconds=1.0,
                                             udp_probe_timeout=0.3),
                         nat_probe=hang, udp_binding=lambda *args: None)
    elapsed = time.monotonic() - started
    assert elapsed < 2.0, elapsed
    assert (report.component("natBehavior").status, report.component("natBehavior").reason) == (
        env.UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED")
    assert "TOTAL_BUDGET_EXCEEDED" not in report.component("addresses").reason
    assert report.errors_truncated is False and len(report.errors) <= env.MAX_ERRORS


def test_config_validation_is_bounded_and_explicit():
    with pytest.raises(NetEnvError, match="INVALID_OBSERVATION_POINTS"):
        NetEnvConfig(observation_points=tuple(point("192.0.2.%d" % index, 3478) for index in range(1, 7))).validate()
    with pytest.raises(NetEnvError, match="INVALID_OBSERVATION_POINTS"):
        NetEnvConfig(observation_points=("192.0.2.1:3478",)).validate()
    with pytest.raises(NetEnvError, match="INVALID_TIMEOUT"):
        NetEnvConfig(udp_probe_timeout=0.01).validate()
    with pytest.raises(NetEnvError, match="INVALID_TIMEOUT"):
        NetEnvConfig(nat_timeout=99).validate()
    with pytest.raises(NetEnvError, match="INVALID_TOTAL_BUDGET"):
        NetEnvConfig(total_budget_seconds=0.5).validate()
    with pytest.raises(NetEnvError, match="INVALID_TOTAL_BUDGET"):
        NetEnvConfig(total_budget_seconds=61).validate()
    with pytest.raises(NetEnvError, match="INVALID_NAT_PROBE_BOUNDS"):
        NetEnvConfig(nat_local_ports=9).validate()
    with pytest.raises(NetEnvError, match="EXPLICIT_BIND_REQUIRED"):
        NetEnvConfig(bind_host_v4="0.0.0.0").validate()
    with pytest.raises(NetEnvError, match="BIND_FAMILY_MISMATCH"):
        NetEnvConfig(bind_host_v4="::1").validate()
    with pytest.raises(ValueError):
        NetEnvConfig(observation_points=(point("stun.example.com", 3478),)).validate()


# --- center-log reporting ---------------------------------------------------

@pytest.mark.asyncio
async def test_center_events_are_schema_valid_bounded_and_credential_free():
    fake = FakeReach(reach.REACHED_BY_SERVER)
    report = await check(config=inbound_config(), reach_module=fake, udp_binding=answer)
    events = report.center_events(session=SESSION, connection_id=CID, attempt_id=AID, start_seq=7)
    assert 1 <= len(events) <= env.MAX_EVENTS
    for index, event in enumerate(events):
        validate_event(event, SESSION)  # the server-side allowlist, strict
        assert event["seq"] == 8 + index and event["connectionId"] == CID and event["attemptId"] == AID
        assert len(json.dumps(event).encode()) <= env.MAX_EVENT_BYTES
    assert events[0]["event"] == "client.boot" and events[0]["data"]["family"] == 4
    assert events[0]["data"]["ok"] is True and events[0]["data"]["canMessage"] is True
    assert any(event["event"] == "probe.ack" and event["data"]["ok"] is True for event in events)
    assert any(event["event"] == "stun.binding" and "responseBytes" not in event["data"] for event in events)
    flat = json.dumps(events)
    for forbidden in ("192.168.1.20", "192.0.2.1", "SECRET-TOKEN", "wlan0", "10.8.1.254", "203.0.113"):
        assert forbidden not in flat
    with pytest.raises(NetEnvError, match="INVALID_IDENTITY"):
        report.center_events(session="not-a-uuid")


@pytest.mark.asyncio
async def test_center_message_has_the_exact_wire_shape_the_server_accepts():
    report = await check(config=inbound_config(), reach_module=FakeReach(reach.REACHED_BY_SERVER),
                         udp_binding=answer)
    message = report.center_message(session=SESSION, connection_id=CID, attempt_id=AID)
    protocol_fields(message, {"v", "type", "clientSessionId", "events"})  # exact key set, like the server
    assert message["type"] == "telemetry" and message["clientSessionId"] == SESSION
    assert 1 <= len(message["events"]) <= 30
    for event in message["events"]:
        validate_event(event, SESSION)


@pytest.mark.asyncio
async def test_center_report_is_desensitised_while_the_local_view_keeps_detail():
    report = await check(config=inbound_config(), reach_module=FakeReach(reach.REACHED_BY_SERVER),
                         udp_binding=answer)
    center = json.dumps(report.center_report())
    for forbidden in ("192.168.1.20", "192.168.1.1", "wlan0", "SECRET-TOKEN", "2606:4700:1::5", "192.0.2"):
        assert forbidden not in center, forbidden
    assert report.center_report()["session"] == SESSION and report.center_report()["connectionId"] == CID
    assert report.center_report()["ingest"]["localOnlyFields"] and report.center_report()["ingest"]["allowlistFieldsNeeded"]
    assert set(report.center_report()["recommendations"][0]) == {"rank", "method", "status", "reason"}
    local = json.dumps(report.local_report())
    assert "192.168.1.20" in local and "wlan0" in local and "SECRET-TOKEN" not in local


@pytest.mark.asyncio
async def test_unmeasured_items_name_the_real_home_network_only_questions():
    report = await check()
    codes = [item["code"] for item in report.local_report()["unmeasured"]]
    assert codes == ["REAL_NAT_TYPE", "REAL_IPV6_INBOUND_ALLOWED", "REAL_PORT_PREDICTION_SUCCESS", "REAL_MULTIPLE_PATHS"]
    assert report.center_report()["unmeasured"] == codes


# --- module shape -----------------------------------------------------------

@pytest.mark.asyncio
async def test_module_is_ui_free_and_serialisable_and_reuses_the_existing_modules():
    from pathlib import Path
    source = Path(env.__file__).read_text(encoding="utf-8")
    for forbidden in ("tkinter", "PySide6", "PyQt", "electron", "subprocess.Popen"):
        assert forbidden not in source
    assert env.nat is nat and env.reach is reach  # same module objects: reuse, not a copy
    assert env.METHOD_ORDER == (env.IPV6_DIRECT, env.GATEWAY_MAPPING, env.PORT_PREDICTION)
    assert ipaddress.ip_address("127.0.0.1").is_loopback
    report = await check()
    assert json.dumps(report.local_report()) and json.dumps(report.center_report())
    assert await asyncio.to_thread(env.run_sync, NetEnvConfig()) is not None


@pytest.mark.asyncio
async def test_platform_without_tables_reports_not_tested_everywhere():
    report = await check(ipv4_addresses=lambda: None, ipv6_addresses=lambda: None,
                         ipv4_routes=lambda: None, ipv6_routes=lambda: None)
    assert (report.component("addresses").status, report.component("addresses").reason) == (
        env.NOT_TESTED, "ADDRESS_ENUMERATION_UNAVAILABLE")
    assert (report.component("routes").status, report.component("routes").reason) == (
        env.NOT_TESTED, "ROUTE_TABLE_UNREADABLE_ON_PLATFORM")
    assert report.overall["status"] == env.NOT_TESTED
    assert all(component.status in env.STATUSES for component in report.components.values())
    assert report.overall["coverage"] == {"determined": 0, "resolved": 1, "total": len(env.COMPONENTS)}
