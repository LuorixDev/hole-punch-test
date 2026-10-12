"""Net-env health check: reuse of nat_behavior/ipv6_reach, honest verdicts, bounds, redaction.

Controlled sources cover the classification branches (they are injected, not measured);
two tests use real loopback sockets with a controlled STUN responder, and the t48 module
is exercised for real once. Real home-network NAT type and real IPv6 inbound allowance
stay NOT_RUN and are asserted to be listed as unmeasured.
"""
import asyncio
import io
import ipaddress
import pathlib
import json
import re
import socket
import time
import types
import uuid

import pytest

from dataclasses import replace as dataclasses_replace

from p2pchat.backend.protocol import fields as protocol_fields
from p2pchat.backend import telemetry
from p2pchat.backend.telemetry import ENUMS, Store, export_session, safe_data, validate_event
from p2pchat.native import ipv6_reach as reach
from p2pchat.native import nat_behavior as nat
from p2pchat.native import net_env as env
from p2pchat.native.net_env import NetEnvConfig, NetEnvError, Sources
from p2pchat.server import INBOUND_CHECK_CLIENT_VERDICT, INBOUND_CHECK_LOG
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

# `ip -6 addr show` shape (stable global + temporary global + link-local + loopback).
IP_ADDR_SAMPLE = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet6 ::1/128 scope host
2: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet6 2606:4700:1::5/64 scope global dynamic mngtmpaddr
    inet6 fe80::1/64 scope link
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet6 2606:4700:1::dead/64 scope global temporary dynamic
"""


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


@pytest.mark.asyncio
async def test_default_ipv6_enumeration_is_encoding_explicit(monkeypatch):
    """The one subprocess on this module's path must pass an explicit encoding.

    t48's `run_ip_command`/`ipconfig` calls use `text=True` without an encoding, so the
    encoding gate flagged the default path of this module (CI run 38202969550). This
    module invokes the same command with `encoding="utf-8", errors="replace"` and keeps
    t48's parser; this test proves the kwargs and the parsed result.
    """
    calls = []

    class Result:
        returncode = 0
        stdout = IP_ADDR_SAMPLE
        stderr = ""

    def recording_run(command, **kwargs):
        calls.append((list(command), dict(kwargs)))
        return Result()

    monkeypatch.setattr(env.subprocess, "run", recording_run)
    records = env.default_ipv6_provider(reach)()
    assert calls and all(kwargs["encoding"] == "utf-8" for _, kwargs in calls)
    assert all(kwargs["errors"] == "replace" and kwargs["text"] is True for _, kwargs in calls)
    assert [record.address for record in records] == ["::1", "2606:4700:1::5", "fe80::1", "2606:4700:1::dead"]
    assert [record.address for record in records if record.temporary] == ["2606:4700:1::dead"]

    report = await env.health_check(NetEnvConfig(), sources=Sources(platform="linux", ipv4_addresses=lambda: list(V4),
                                                                   ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY,
                                                                   ipv6_routes=lambda: ROUTE6_DEFAULT_ZERO_GW))
    summary = report.component("addresses").detail
    assert (summary["globalV6Stable"], summary["globalV6Temporary"], summary["linkLocal"]) == (1, 1, 1)

    # Without the `ip` command the provider delegates to t48's own chain, not to a guess.
    def missing(command, **kwargs):
        raise FileNotFoundError(2, "no ip command")

    monkeypatch.setattr(env.subprocess, "run", missing)
    sentinel = [object()]
    stub = types.SimpleNamespace(parse_ip_addr_output=lambda text: [], enumerate_addresses=lambda: sentinel)
    assert env.run_ip_show_explicit_encoding() is None
    assert env.default_ipv6_provider(stub)() is sentinel


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
        assert egress.detail["answeredPoints"] == 1
        # A real loopback round trip is measured on the high-resolution clock. CI
        # (Windows) failed here with `assert (1 == 1 and 0.0 > 0)` because the *budget*
        # clock (time.monotonic, ~15.6 ms tick) cannot resolve this round trip; the
        # reported duration must not come from it.
        assert egress.detail["probeRttMs"] > 0 and egress.detail["probeRttClock"] == "perf_counter"
        assert report.duration_ms > 0
        assert egress.detail["mappedScopes"] == ["loopback"] and seen
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        responder.close()


@pytest.mark.asyncio
async def test_probe_rtt_is_measured_even_when_the_budget_clock_cannot_advance():
    """Platform-independent reproduction of the Windows CI failure.

    CI reported `assert (1 == 1 and 0.0 > 0)`: the reply arrived (answeredPoints == 1)
    but the round trip measured 0.0 ms. A 15.6 ms Windows timer tick makes every
    sub-tick exchange look like that; a frozen budget clock is the same condition, so
    the reported RTT must come from the high-resolution clock instead.
    """
    responder = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    responder.bind(("127.0.0.1", 0))
    responder.setblocking(False)
    port = responder.getsockname()[1]

    async def serve():
        loop = asyncio.get_running_loop()
        while True:
            try:
                data, address = await loop.sock_recvfrom(responder, 2048)
            except (OSError, asyncio.CancelledError):
                return
            reply = server_stun_reply(data, address)
            if reply:
                await loop.sock_sendto(responder, reply, address)

    frozen = {"now": 5_000_000.0}
    task = asyncio.create_task(serve())
    try:
        report = await check(config=NetEnvConfig(observation_points=(point("127.0.0.1", port),),
                                                 bind_host_v4="127.0.0.1", udp_probe_timeout=0.5),
                             ipv4_routes=lambda: ROUTE4_DEFAULT_WITH_GATEWAY,
                             monotonic=lambda: frozen["now"])
        assert frozen["now"] - frozen["now"] == 0.0  # the budget clock cannot resolve anything here
        egress = report.component("udpEgress")
        assert egress.detail["answeredPoints"] == 1
        assert egress.detail["probeRttMs"] > 0, egress.detail
        assert egress.detail["probeRttClock"] == "perf_counter"
        assert report.duration_ms > 0
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
] + [(verdict, status, reason) for verdict, (status, reason, _note) in env.INBOUND_REFUSAL_OUTCOMES.items()] + [
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


def test_inbound_refusal_vocabulary_matches_t58_and_the_server():
    """t58 认的三种拒绝与"看不懂"各有一个自己的名字；词表逐字来自 t58/服务端。"""
    # 解析器级的两个错码不是 verdict，但 t58 逐字就是这么抛的（这里当场复现，防止自己发明词）
    parser_codes = {"UNRECOGNIZED_REACH_CODE", "INCONSISTENT_REACH_VERDICT"}
    assert parser_codes <= set(env.INBOUND_REFUSAL_OUTCOMES)
    with pytest.raises(reach.ReachError, match="UNRECOGNIZED_REACH_CODE"):
        reach.parse_reach_verdict({"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": CID,
                                   "attemptId": AID, "code": "SOMETHING_NEW", "ok": True})
    with pytest.raises(reach.ReachError, match="INCONSISTENT_REACH_VERDICT"):
        reach.parse_reach_verdict({"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": CID,
                                   "attemptId": AID, "code": "REACHABLE", "ok": False})
    assert set(env.INBOUND_REFUSAL_OUTCOMES) - parser_codes <= set(reach.VERDICTS)
    assert set(INBOUND_CHECK_LOG) == set(reach.SERVER_RESULT_CODES)                 # 服务端六选一
    refusals = set(INBOUND_CHECK_LOG) - set(INBOUND_CHECK_CLIENT_VERDICT)           # 服务端刻意不给客户端词
    assert refusals == {"CONNECTION_REFUSED", "TOKEN_MISMATCH", "REJECTED_BY_POLICY"}
    assert {reach.SERVER_CODE_VERDICT[code] for code in refusals} == (
        set(env.INBOUND_REFUSAL_OUTCOMES) - {reach.RESULT_UNRECOGNIZED} - parser_codes)
    assert reach.RESULT_UNRECOGNIZED in env.INBOUND_REFUSAL_OUTCOMES
    reasons = [outcome[1] for outcome in env.INBOUND_REFUSAL_OUTCOMES.values()]
    assert len(set(reasons)) == len(reasons) and "UNKNOWN_REACH_VERDICT" not in reasons
    assert all(env.summary_token_ok(reason) for reason in reasons)                  # 都能过白名单形态


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
    """The real t48 probe runs end to end on deterministic inputs.

    Addresses and the route answer are injected so the test never shells out (that is
    also why the encoding gate is clean: t48's own `ip`/`ipconfig` calls pass
    ``text=True`` without an encoding, and this suite must not depend on them). With
    only loopback/link-local records the real `probe_reachability` must answer
    NO_GLOBAL_V6 on every platform without opening a listener.
    """
    local_only = [v6("::1", scope="host", temporary=False, interface="lo"),
                  v6("fe80::1", scope="link", temporary=False, interface="wlan0")]
    report = await check(config=inbound_config(total_budget_seconds=3.0), udp_binding=lambda *args: None,
                         ipv6_addresses=lambda: list(local_only),
                         reach_provider=lambda: list(local_only), reach_route_check=lambda: True)
    component = report.component("inboundReachability")
    assert (component.status, component.reason) == (env.DETERMINED, reach.NO_GLOBAL_V6)
    assert component.detail["verdict"] == reach.NO_GLOBAL_V6


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
    # The blocking wrapper is exercised with deterministic providers: the default v6
    # source is t48's `ip`/`ipconfig` chain, whose implicit-encoding subprocess calls
    # are outside this task's scope and must not be reached from this suite.
    async_report = await asyncio.to_thread(env.run_sync, None, sources=sources())
    assert async_report.component("addresses").status == env.DETERMINED
    assert json.dumps(async_report.center_report())


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


# --- t59: 体检结论真正上报中心（10 个 netEnv* 键，localOnly 边界不破） --------

SUMMARY_KEYS = frozenset(env.ALLOWLIST_FIELDS_NEEDED)
LOCAL_ONLY_LEAVES = frozenset({"records", "gatewayAddress", "interfaceNames", "mapping", "filtering",
                               "mappingEvidence", "filteringEvidence", "verdict", "note", "signs",
                               "bindings", "errors"})
FORBIDDEN_IN_EXPORT = ("LOCAL-ONLY-MARKER", "127.0.0.1", "127.0.0.2", "2606:4700", "192.168.1.20", "wlan0")


def loopback_points():
    """Two distinct loopback observation points: nat_behavior needs two to classify."""
    return point("127.0.0.1", 40001), point("127.0.0.2", 40001)


async def measured_report(**overrides):
    """A real health check whose NAT behaviour is really classified (profile injected)."""
    async def spy(config):
        return profile(nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT, nat.FILTERING_ADDRESS_DEPENDENT)

    return await check(config=NetEnvConfig(observation_points=loopback_points(), bind_host_v4="127.0.0.1",
                                           udp_probe_timeout=0.3),
                       nat_probe=spy, **overrides)


@pytest.mark.asyncio
async def test_center_summary_carries_the_ten_t50_keys_verbatim():
    report = await measured_report()
    center, summary = report.center_report(), report.center_summary()
    assert set(summary) == SUMMARY_KEYS
    assert summary["netEnvOverall"] == center["overall"]["status"]
    assert summary["netEnvComponent"] == "addresses"
    assert summary["netEnvStatus"] == center["components"]["addresses"]["status"]
    # Codes longer than 32 characters (NO_RESPONSE_FROM_OBSERVATION_POINT is 35) must be
    # carried verbatim: the receiving shape allows 48 per segment, and a 32 cap rejected
    # every real non-Linux report.
    long_code = "udpEgress:insufficient-evidence:NO_RESPONSE_FROM_OBSERVATION_POINT"
    assert long_code in center["overall"]["reasons"] and long_code in summary["netEnvReason"]
    assert summary["netEnvReason"] == [reason for reason in center["overall"]["reasons"]
                                       if env.summary_token_ok(reason)][:env.MAX_SUMMARY_REASONS]
    assert summary["netEnvMapping"] == nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT
    assert summary["netEnvFiltering"] == nat.FILTERING_ADDRESS_DEPENDENT
    assert summary["netEnvAddressStability"] == "stable"
    assert summary["netEnvNat64"] == center["components"]["nat64"]["reason"]
    assert summary["netEnvRecommendation"] == center["recommendations"][0]["method"]
    assert summary["netEnvUnmeasured"] == center["unmeasured"]
    assert len(summary["netEnvReason"]) <= env.MAX_SUMMARY_REASONS
    assert len(summary["netEnvUnmeasured"]) <= env.MAX_SUMMARY_UNMEASURED
    assert not set(summary) & LOCAL_ONLY_LEAVES
    assert safe_data(summary, True) == summary          # strict allowlist keeps every value
    event = report.center_events(session=SESSION, connection_id=CID, attempt_id=AID)[0]
    assert event["event"] == "client.boot"
    for key, value in summary.items():
        assert event["data"][key] == value, key
    validate_event(event, SESSION)


@pytest.mark.asyncio
async def test_center_summary_omits_what_was_not_measured_instead_of_guessing():
    report = await check(config=NetEnvConfig(udp_probe_timeout=0.3))   # default: no observation point
    summary = report.center_summary()
    assert report.component("natBehavior").status == env.NOT_TESTED
    assert "netEnvMapping" not in summary and "netEnvFiltering" not in summary
    # "not tested" must not be dressed up as nat_behavior's `undetermined`
    assert nat.UNDETERMINED not in json.dumps(summary)
    assert summary["netEnvOverall"] == env.INSUFFICIENT
    assert summary["netEnvStatus"] == env.DETERMINED and summary["netEnvAddressStability"] == "stable"
    assert set(summary) == SUMMARY_KEYS - {"netEnvMapping", "netEnvFiltering"}
    assert safe_data(summary, True) == summary
    # and an un-enumerated address list claims no scope at all
    blind = await check(config=NetEnvConfig(udp_probe_timeout=0.3), ipv4_addresses=lambda: None,
                        ipv6_addresses=lambda: None)
    assert blind.component("addresses").status == env.NOT_TESTED
    assert blind.address_stability() is None and "netEnvAddressStability" not in blind.center_summary()


@pytest.mark.asyncio
async def test_center_summary_keeps_undetermined_and_not_global_as_themselves():
    async def spy(config):
        return profile(nat.UNDETERMINED, nat.UNDETERMINED)

    report = await check(config=NetEnvConfig(observation_points=loopback_points(), bind_host_v4="127.0.0.1",
                                             udp_probe_timeout=0.3), nat_probe=spy)
    summary = report.center_summary()
    assert summary["netEnvMapping"] == nat.UNDETERMINED == "undetermined"
    assert summary["netEnvMapping"] != nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT
    assert "对称" not in json.dumps(summary) and "可打洞" not in json.dumps(summary)
    item = next(entry for entry in report.recommendations if entry["method"] == env.PORT_PREDICTION)
    assert (item["status"], item["reason"]) == (env.UNKNOWN, "NAT_BEHAVIOR_EVIDENCE_INSUFFICIENT")
    # only link-local/loopback addresses: the real module value is the `not-global` tier
    local_only = await check(config=NetEnvConfig(udp_probe_timeout=0.3),
                             ipv6_addresses=lambda: [v6("fe80::1", scope="link", temporary=False),
                                                     v6("::1", scope="host")])
    assert local_only.address_stability() == "not-global"
    assert local_only.center_summary()["netEnvAddressStability"] == "not-global"


@pytest.mark.asyncio
async def test_center_summary_bounds_and_shapes_match_the_receiving_allowlist():
    report = await check(ipv4_addresses=lambda: None, ipv6_addresses=lambda: None,
                         ipv4_routes=lambda: None, ipv6_routes=lambda: None)
    center = report.center_report()
    summary = report.center_summary()
    assert len(center["overall"]["reasons"]) > 4                    # 以前 32 段长会把这些全挡掉
    assert summary["netEnvReason"] == [reason for reason in center["overall"]["reasons"]
                                       if env.summary_token_ok(reason)][:env.MAX_SUMMARY_REASONS]
    assert len(summary["netEnvReason"]) <= env.MAX_SUMMARY_REASONS
    assert len(summary["netEnvUnmeasured"]) <= env.MAX_SUMMARY_UNMEASURED
    assert safe_data(summary, True) == summary


@pytest.mark.asyncio
async def test_real_health_check_conclusion_lands_in_store_and_export_verbatim(tmp_path):
    """真体检 → 真 center_message → 真 store → CLI 导出：10 个键一字不差。"""
    first = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    first.bind(("127.0.0.1", 0))
    first.setblocking(False)
    second = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    second.bind(("127.0.0.2", 0))
    second.setblocking(False)
    answered = []

    async def serve(sock):
        loop = asyncio.get_running_loop()
        while True:
            try:
                data, address = await loop.sock_recvfrom(sock, 2048)
            except (OSError, asyncio.CancelledError):
                return
            reply = server_stun_reply(data, address)
            if reply:
                answered.append(address)
                await loop.sock_sendto(sock, reply, address)

    tasks = [asyncio.create_task(serve(first)), asyncio.create_task(serve(second))]
    try:
        report = await env.health_check(NetEnvConfig(
            observation_points=(point("127.0.0.1", first.getsockname()[1]),
                                point("127.0.0.2", second.getsockname()[1])),
            bind_host_v4="127.0.0.1", udp_probe_timeout=0.5, nat_timeout=1.0))
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        first.close()
        second.close()
    assert answered, "两个真实回环响应器都必须收到探测包"
    summary = report.center_summary()
    assert set(summary) == SUMMARY_KEYS, sorted(summary)          # 真跑出来的十个键
    message = report.center_message(session=SESSION, connection_id=CID, attempt_id=AID)
    protocol_fields(message, {"v", "type", "clientSessionId", "events"})
    for event in message["events"]:
        validate_event(event, SESSION)
    store = Store(str(tmp_path))
    try:
        store.ingest("room-1", "peer-1", SESSION, message["events"])
        rows = [json.loads(body) for (body,) in
                store.db.execute("SELECT body FROM diagnostics WHERE session=?", (SESSION,))]
        landed = next(row for row in rows if row["event"] == "client.boot")
        assert set(landed["data"]) >= SUMMARY_KEYS
        for key, value in summary.items():
            assert landed["data"][key] == value, key
        out = io.StringIO()
        export_session(store, out, session=SESSION)
    finally:
        store.close()
    text = out.getvalue()
    exported = [json.loads(line) for line in text.splitlines() if line.strip()]
    entry = next(item for item in exported if item.get("event") == "client.boot")
    for key, value in summary.items():
        assert entry["data"][key] == value, key
    assert not set(entry["data"]) & LOCAL_ONLY_LEAVES
    for forbidden in FORBIDDEN_IN_EXPORT:
        assert forbidden not in text, forbidden


def test_export_never_prints_local_only_values_or_full_addresses(tmp_path):
    """把带标记的 localOnly 行硬塞进 store：导出端必须自己遮掉，值一个都不许出现。"""
    store = Store(str(tmp_path))
    try:
        marker = "LOCAL-ONLY-MARKER-9f3a"
        planted = {"v": 1, "id": str(uuid.uuid4()), "clientSessionId": SESSION, "seq": 1, "tsWallMs": 1.0,
                   "monoMs": 0.0, "connectionId": CID, "attemptId": AID, "event": "client.boot",
                   "data": {"state": "completed", "ok": True, "endpoint": "2606:4700:1::5",
                            **{leaf: marker for leaf in LOCAL_ONLY_LEAVES}}}
        store.db.execute("INSERT INTO diagnostics VALUES(?,?,?,?,?,?)",
                         ("room-1", SESSION, str(uuid.uuid4()), time.time(), "legacy-peer",
                          json.dumps(planted, sort_keys=True, separators=(",", ":"))))
        store.db.commit()
        out = io.StringIO()
        export_session(store, out, session=SESSION)
        text = out.getvalue()
        assert marker not in text
        assert "2606:4700:1::5" not in text                     # 完整地址按前缀遮掉
        entry = next(item for item in (json.loads(line) for line in text.splitlines() if line.strip())
                     if item.get("event") == "client.boot")
        for leaf in LOCAL_ONLY_LEAVES:
            assert entry["data"][leaf] == "[redacted]", leaf     # 键保留=显式标记，值不出现
    finally:
        store.close()


@pytest.mark.asyncio
async def test_win32_shaped_report_emits_its_long_reason_codes():
    """t60 的 Windows 现场：34/38/40 字符的原因码过去会被 32 段长上限整体挡死。"""
    report = await check(platform="win32", ipv4_addresses=lambda: list(V4),
                         ipv6_addresses=lambda: list(V6_STABLE),
                         ipv4_routes=lambda: None, ipv6_routes=lambda: None)
    reasons = report.center_report()["overall"]["reasons"]
    assert any("ROUTE_TABLE_UNREADABLE_ON_PLATFORM" in reason for reason in reasons)
    assert any("INSUFFICIENT_ADDRESS_OR_ROUTE_EVIDENCE" in reason for reason in reasons)
    summary = report.center_summary()                               # 以前这里直接抛
    assert summary["netEnvReason"] == [reason for reason in reasons
                                       if env.summary_token_ok(reason)][:env.MAX_SUMMARY_REASONS]
    assert any("ROUTE_TABLE_UNREADABLE_ON_PLATFORM" in reason for reason in summary["netEnvReason"])
    assert safe_data(summary, True) == summary
    for event in report.center_events(session=SESSION, connection_id=CID, attempt_id=AID):
        validate_event(event, SESSION)


@pytest.mark.asyncio
async def test_center_summary_omits_only_unrepresentable_reason_codes():
    report = await measured_report()
    report.overall["reasons"] = ["NOT A TOKEN", "deadbeefdeadbeef",
                                 "routes:not-tested:ROUTE_TABLE_UNREADABLE_ON_PLATFORM"]
    summary = report.center_summary()
    assert summary["netEnvReason"] == ["routes:not-tested:ROUTE_TABLE_UNREADABLE_ON_PLATFORM"]
    assert "NOT A TOKEN" not in json.dumps(summary) and "deadbeef" not in json.dumps(summary)
    assert all(env.summary_token_ok(code) for code in summary["netEnvReason"])


def reason_code_sample():
    """每个模块源码里出现的真实大写原因码，加上每个真实复合形式。"""
    raw = set()
    for module in (env, nat, telemetry, reach):
        source = pathlib.Path(module.__file__).read_text(encoding="utf-8")
        raw |= set(re.findall(r'["\']([A-Z][A-Z0-9_]{3,})["\']', source))
    raw |= {code for code, _ in env.UNMEASURED} | set(telemetry.ENUMS["reason"])
    raw = {code for code in raw if re.fullmatch(r"[A-Z][A-Z0-9_]{3,60}", code)}
    compounds = {f"{name}:{status}:{code}" for name in env.COMPONENTS
                 for status in env.STATUSES for code in raw}
    return sorted(raw), sorted(compounds)


def test_real_reason_codes_fit_the_sender_and_receiver_shapes_identically():
    raw, compounds = reason_code_sample()
    assert len(raw) >= 50, len(raw)
    for code in ("ALTERNATE_ADDRESS_MUST_DIFFER_IN_ADDRESS", "INSUFFICIENT_ADDRESS_OR_ROUTE_EVIDENCE",
                 "ROUTE_TABLE_UNREADABLE_ON_PLATFORM"):
        assert code in raw
    assert max(len(code) for code in raw) <= 48                 # 真实最长 40，48 段长一个都不丢
    for code in raw + compounds:
        assert env.summary_token_ok(code) == bool(telemetry.NET_ENV_TOKEN.match(code)
                                                  and not telemetry.NET_ENV_PURE_HEX.match(code)), code
    assert all(env.summary_token_ok(code) for code in raw)
    assert env.MAX_SUMMARY_REASONS == telemetry.LIST_KEYS["netEnvReason"][0] == 8
    assert env.MAX_SUMMARY_UNMEASURED == telemetry.LIST_KEYS["netEnvUnmeasured"][0] == 8
    assert env.SUMMARY_TOKEN.pattern == telemetry.NET_ENV_TOKEN.pattern
    assert env.SUMMARY_PURE_HEX.pattern == telemetry.NET_ENV_PURE_HEX.pattern
    for hexish in ("deadbeefdeadbeef", "0123456789abcdef0123456789abcdef"):
        assert not env.summary_token_ok(hexish)
        with pytest.raises(ValueError, match="SCHEMA_INVALID"):
            safe_data({"netEnvReason": [hexish]}, True)


@pytest.mark.asyncio
async def test_reverse_verification_summary_keys_and_shapes_are_load_bearing():
    """反向验证：抽掉一个键，接收端必须拒；破坏一个值形态，发送端必须拒。"""
    report = await measured_report()
    event = report.center_events(session=SESSION, connection_id=CID, attempt_id=AID)[0]
    validate_event(event, SESSION)
    with pytest.MonkeyPatch.context() as patch:
        patch.delitem(ENUMS, "netEnvOverall")                   # 白名单是承重的
        with pytest.raises(ValueError, match="SCHEMA_INVALID"):
            validate_event(event, SESSION)
    # 发送端也必须拒发：结论本身不可用时不许拼一份能过网的假摘要
    broken_status = await measured_report()
    broken_status.components["addresses"] = dataclasses_replace(broken_status.component("addresses"),
                                                                status="teleporting")
    with pytest.raises(NetEnvError, match="SUMMARY_NOT_ALLOWLISTED"):
        broken_status.center_summary()
    missing_nat64 = await measured_report()
    missing_nat64.components["nat64"] = dataclasses_replace(missing_nat64.component("nat64"), reason=None)
    with pytest.raises(NetEnvError, match="SUMMARY_NOT_ALLOWLISTED"):
        missing_nat64.center_summary()
    local_only = await check(config=NetEnvConfig(udp_probe_timeout=0.3),
                             ipv6_addresses=lambda: [v6("fe80::1", scope="link", temporary=False)])
    assert local_only.center_summary()["netEnvAddressStability"] == "not-global"
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(env, "ADDRESS_STABILITY_WORDS", ("stable",))
        with pytest.raises(NetEnvError, match="SUMMARY_NOT_ALLOWLISTED"):
            local_only.center_summary()
    # 接收端同样拒绝被改写过的值与破掉的形态
    with pytest.raises(ValueError, match="SCHEMA_INVALID"):
        safe_data({**report.center_summary(), "netEnvMapping": "symmetric"}, True)
    with pytest.raises(ValueError, match="SCHEMA_INVALID"):
        safe_data({**report.center_summary(), "netEnvReason": ["NOT A TOKEN"]}, True)
    with pytest.raises(ValueError, match="SCHEMA_INVALID"):
        safe_data({**report.center_summary(), "netEnvNat64": ["IPV4_PATH_PRESENT"]}, True)
