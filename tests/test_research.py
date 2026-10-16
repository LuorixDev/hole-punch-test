import asyncio
import ctypes.util
import os
import socket

import pytest

from p2plab.experiments import Experiments, build_plan, prediction_candidates
from p2plab.gateway import natpmp_request, parse_natpmp, parse_pcp, pcp_address, pcp_request
from p2plab.nat64 import Nat64Attempt, discover_prefixes, synthesize
from p2plab.native_ice import NativeIceAttempt
from p2plab.native_loader import load_library
from p2plab.native_utp import UtpAttempt, library_path
from p2plab.raw_probes import checksum, icmp_echo, icmp_error, ipv4_packet, synack
from p2plab.research import SocketPoolAttempt, Synchronizer
from p2plab.tcp_race import TcpRaceAttempt
from p2plab.udp import UdpAttempt
from tests.test_transports import specs


async def close_pair(peers, objects):
    await asyncio.gather(*(path.close() for owner in peers for path in owner.paths))
    await asyncio.gather(*(obj.close() for obj in objects))


async def test_research_plan_is_bounded_complete_by_mechanism_and_phase():
    coverage = {}
    plan = build_plan(["192.0.2.1", "2001:db8::1"], ["192.0.2.2", "2001:db8::2"],
                      ["fast"], research=True, coverage=coverage)
    methods = {spec["method"] for spec in plan}
    assert {"tcp-race", "tcp-sync", "tcp-ttl", "quic-sync", "quic-ttl", "udp-birthday",
            "udp-birthday-dual", "udp-port-search", "prediction-wide", "lan", "hairpin", "ice-tcp",
            "ice-native", "upnp-any", "upnp-any-tcp", "pinhole-tcp", "pcp-peer", "pcp-filter-tcp",
            "pcp-prefer", "natpmp-tcp", "utp", "pwnat", "natblaster"} <= methods
    assert [spec["phase"] for spec in plan] == sorted(spec["phase"] for spec in plan)
    assert not coverage["omitted"]


async def test_sync_uses_echo_rtt_and_not_wall_clocks(peers, task_scheduling):
    a, b = peers
    left, right = Synchronizer(a, "sync-test"), Synchronizer(b, "sync-test")
    a.signal, b.signal = right.handle, left.handle
    await asyncio.gather(left.synchronize(3), right.synchronize(3))
    assert len(left.rtts) == 3 and all(rtt >= 0 for rtt in left.rtts)
    assert right.go.is_set()


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
@pytest.mark.parametrize("offset", [0, 0.5])
async def test_tcp_same_port_listener_connect_tls_chat_file(peers, host, offset, task_scheduling, tmp_path):
    a, b = peers
    sa, sb = specs("tcp-race", host, offset=offset)
    left, right = TcpRaceAttempt(a, sa, host), TcpRaceAttempt(b, sb, host)
    a.signal, b.signal = right.handle, left.handle
    try:
        await asyncio.gather(left.prepare(), right.prepare())
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        pa, pb = await asyncio.wait_for(asyncio.gather(left.connect(), right.connect()), 10)
        assert left.choice == right.choice
        assert (await a.chat("race verified"))["mbps"] > 0
        assert await pa.ping() >= 0 and await pb.ping() >= 0
        source = tmp_path / "race.bin"
        source.write_bytes(bytes(1024 * 1024))
        assert (await a.transfers.send(pa, source))["bytes"] == source.stat().st_size
    finally:
        await close_pair(peers, (left, right))


@pytest.mark.parametrize("method", ["udp-birthday", "udp-birthday-dual", "udp-port-search"])
async def test_pool_winner_agreement_preserves_real_socket_quic(peers, method, task_scheduling):
    a, b = peers
    sa, sb = specs(method, "127.0.0.1", socket_count=16, target_count=16, rounds=2,
                   hard_side="a" if method == "udp-birthday" else "both")
    left, right = SocketPoolAttempt(a, sa, "127.0.0.1"), SocketPoolAttempt(b, sb, "127.0.0.1")
    a.signal, b.signal = right.handle, left.handle
    try:
        await asyncio.gather(left.open(), right.open())
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        await asyncio.wait_for(asyncio.gather(left.punch(3), right.punch(3)), 5)
        assert left.winner.nonce_for(left.remote) == right.winner.auth[right.remote]["nonce"]
        bound = left.winner.candidates[0]
        pa, pb = await asyncio.gather(left.start_quic(), right.start_quic())
        assert left.winner.candidates[0] == bound
        assert (await a.chat("pool verified"))["mbps"] > 0
        assert await pa.ping() >= 0 and await pb.ping() >= 0
    finally:
        await close_pair(peers, (left, right))


@pytest.mark.parametrize("method", ["ice-tcp", "ice-native"])
@pytest.mark.parametrize("profile", ["4", "6", "dual"])
async def test_libnice_real_no_relay_selected_transport_tls_chat_file(peers, method, profile, tmp_path):
    try:
        load_library("nice")
    except OSError:
        if os.environ.get("P2PLAB_REQUIRE_NATIVE"):
            raise
        pytest.skip("libnice is not installed")
    a, b = peers
    sa, sb = specs(method, "127.0.0.1", profile=profile)
    left, right = NativeIceAttempt(a, sa), NativeIceAttempt(b, sb)
    a.signal, b.signal = right.handle, left.handle
    try:
        pa, pb = await asyncio.wait_for(asyncio.gather(left.connect(), right.connect()), 20)
        assert pa.ready.is_set() and pb.ready.is_set()
        assert pa.family in (4, 6) and pb.family in (4, 6)
        assert (await a.chat("native verified"))["mbps"] > 0
        source = tmp_path / "native.bin"
        source.write_bytes(bytes(1024 * 1024))
        assert (await a.transfers.send(pa, source))["bytes"] == 1024 * 1024
        selected = [row["fields"]["candidates"] for row in a.log.query() if row["event"] == "native.ice_selected"]
        assert selected and all(" typ relay" not in candidate for pair in selected for candidate in pair)
        assert all((" TCP " in candidate.upper()) == (method == "ice-tcp") for pair in selected for candidate in pair)
    finally:
        await close_pair(peers, (left, right))


async def test_hairpin_challenge_reports_probe_only(peers):
    a, _ = peers
    sa, _ = specs("hairpin", "127.0.0.1")
    udp = UdpAttempt(a, sa, "127.0.0.1")
    try:
        await udp.open()
        evidence = await udp.hairpin(1)
        assert evidence["confirmed"] and not a.paths
    finally:
        await udp.close()


def test_gateway_wire_extensions_tcp_peer_filter_and_deletion():
    import struct

    nonce = bytes(12)
    remote = ("198.51.100.2", 30000)
    request = pcp_request("192.0.2.1", 10000, 20000, nonce, protocol=6, peer=remote)
    assert len(request) == 80 and request[1] == 2 and request[36] == 6
    response = bytes([2, 0x82, 0, 0]) + struct.pack("!II", 120, 5) + bytes(12) + request[24:44] + pcp_address("203.0.113.1") + request[60:]
    assert parse_pcp(response, nonce, 10000, protocol=6, peer=remote)["external"] == ("203.0.113.1", 20000)
    filtered = pcp_request("192.0.2.1", 10000, 20000, nonce, filter_remote=remote)
    assert filtered[60:64] == bytes([3, 0, 0, 20]) and filtered[65] == 128
    assert len(pcp_request("192.0.2.1", 10000, 20000, nonce, 0, filter_remote=remote)) == 60
    assert natpmp_request(10000, 20000, protocol=6)[1] == 2
    result = struct.pack("!BBHIHHI", 0, 130, 0, 1, 10000, 20000, 120)
    assert parse_natpmp(result, 10000, protocol=6)["port"] == 20000


async def test_chunked_research_plan_validates_and_reassembles(peers):
    _, b = peers
    b.network = {"addresses": [{"address": "127.0.0.1"}]}
    manager = Experiments(b)
    plan = build_plan(["127.0.0.1"], ["127.0.0.1"], ["fast"], research=True)
    total = (len(plan) + 15) // 16
    for index in reversed(range(total)):
        await manager.handle({"kind": "plan_part", "attempt": "setup", "index": index, "total": total,
                              "plan": plan[index * 16:(index + 1) * 16]})
    assert manager.plan_ready.is_set() and manager.plan == plan


def test_prediction_expands_multiple_observed_ips_and_keeps_bounds():
    samples = []
    for index, port in enumerate((40000, 40002, 50000, 50002)):
        for repeat in range(2):
            samples.append({"observer": [f"192.0.2.{index + 1}", 3478],
                            "mapped": ["198.51.100.1" if index < 2 else "198.51.100.2", port], "repeat": repeat})
    predicted = prediction_candidates(samples, window=16, radius=2)
    assert {ip for ip, _ in predicted} == {"198.51.100.1", "198.51.100.2"}
    assert len(predicted) <= 256 and all(1 <= port <= 65535 for _, port in predicted)


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_libutp_real_encrypted_chat_file_and_bidirectional_speed(peers, host, tmp_path, task_scheduling):
    from pathlib import Path

    if not Path(library_path()).exists() and not ctypes.util.find_library("utp"):
        if os.environ.get("P2PLAB_REQUIRE_NATIVE"):
            pytest.fail("required libutp unavailable")
        pytest.skip("optional libutp unavailable")
    a, b = peers
    sa, sb = specs("utp", host)
    left, right = UtpAttempt(a, sa, host), UtpAttempt(b, sb, host)
    try:
        await asyncio.gather(left.open(), right.open())
        for peer in (a, b):
            buffer_events = [row for row in peer.log.query() if row["event"] == "native.utp_socket_buffers"]
            assert buffer_events
            assert buffer_events[-1]["fields"]["actual"]["receive_bytes"] > 0
            assert buffer_events[-1]["fields"]["actual"]["send_bytes"] > 0
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        await asyncio.gather(left.punch(2), right.punch(2))
        pa, pb = await asyncio.wait_for(asyncio.gather(left.connect_stream(), right.connect_stream()), 15)
        assert (await a.chat("native utp"))["mbps"] > 0
        assert await pa.ping() >= 0 and await pb.ping() >= 0
        source = tmp_path / "utp.bin"
        source.write_bytes(bytes(1024 * 1024))
        assert (await a.transfers.send(pa, source))["bytes"] == 1024 * 1024
        for path in (pa, pb):
            assert (await path.speed(1024 * 1024))["mbps"] > 0
    finally:
        await close_pair(peers, (left, right))


@pytest.mark.parametrize("length", [32, 40, 48, 56, 64, 96])
def test_nat64_all_standard_prefix_lengths_and_paired_dns64_evidence(length):
    import ipaddress

    prefix = str(ipaddress.IPv6Network(f"2001:db8::/{length}"))
    answers = [synthesize(prefix, address) for address in ("192.0.0.170", "192.0.0.171")]
    assert prefix in discover_prefixes(answers)
    assert not discover_prefixes(answers[:1])
    raw = ipaddress.IPv6Address(synthesize(prefix, "203.0.113.42")).packed
    if length != 96:
        assert raw[8] == 0
    with pytest.raises(ValueError):
        synthesize("2001:db8::/72", "203.0.113.1")


async def test_nat64_cross_family_plan_and_candidate_conversion(peers):
    a, b = peers
    plan = build_plan(["2001:db8::1"], ["192.0.2.2"], ["fast"], research=True, gateway=False)
    cross = [spec for spec in plan if spec["method"] == "nat64"]
    assert len(cross) == 2
    b.network = {"addresses": [{"address": "192.0.2.2"}]}
    manager = Experiments(b)
    await manager.handle({"kind": "plan", "attempt": "setup", "plan": plan})
    sa, sb = specs("nat64", "2001:db8::1")
    left = Nat64Attempt(a, sa, "2001:db8::1")
    right = Nat64Attempt(b, sb, "192.0.2.2")
    left.set_candidates([["192.0.2.2", 5000]])
    assert not left.candidates_ready.is_set()
    left.prefixes = ["64:ff9b::/96"]
    left.set_candidates(left.pending_candidates)
    assert left.remote_candidates == [["64:ff9b::c000:202", 5000]]
    right.set_candidates([["2001:db8::1", 5001], ["192.0.2.1", 5002]])
    assert right.remote_candidates == [["192.0.2.1", 5002]]


def test_raw_wire_checksums_and_quoted_echo():
    echo = icmp_echo(12345)
    assert checksum(echo) == 0
    quote = ipv4_packet("192.0.2.1", "192.0.2.2", 1, echo)
    assert checksum(quote[:20]) == 0
    error = icmp_error(quote)
    assert checksum(error) == 0 and error[8:] == quote
    packet = synack(("192.0.2.1", 10000), ("192.0.2.2", 20000), 123, 456)
    assert checksum(packet[:20]) == 0
    pseudo = socket.inet_aton("192.0.2.1") + socket.inet_aton("192.0.2.2") + bytes([0, 6, 0, 20])
    assert checksum(pseudo + packet[20:]) == 0
    assert packet[33] == 0x12


async def test_raw_probes_report_disabled_without_fake_success(peers):
    from p2plab.external import ExternalAttempt

    a, _ = peers
    for method in ("pwnat", "natblaster"):
        spec, _ = specs(method, "127.0.0.1")
        with pytest.raises(ValueError, match="RAW_EXPERIMENT_DISABLED"):
            ExternalAttempt(a, spec)
    assert not a.paths


@pytest.mark.parametrize("options", [{"raw_probes": "false"}, {"comprehensive": 1},
                                      {"nat64_prefixes": "64:ff9b::/96"}, {"nat64_prefixes": ["2001:db8::/72"]}])
def test_research_configuration_rejects_ambiguous_boolean_and_prefixes(options, tmp_path):
    from p2plab.client import Client

    with pytest.raises(ValueError):
        Client({"experiment": options, "data_dir": str(tmp_path)}, "test", console=False)


@pytest.mark.parametrize("method", ["pwnat", "natblaster"])
async def test_raw_namespace_actual_handshake_and_chat(peers, method):
    from p2plab.external import ExternalAttempt

    if os.environ.get("P2PLAB_RAW_TEST") != "isolated":
        pytest.skip("run only under unshare -Urn with P2PLAB_RAW_TEST=isolated")
    a, b = peers
    for owner in peers:
        owner.config["experiment"]["raw_probes"] = True
    sa, sb = specs(method, "127.0.0.1", ttl=1)
    left, right = ExternalAttempt(a, sa), ExternalAttempt(b, sb)

    async def dispatch(obj, data):
        if data["kind"] == "candidate":
            obj.set_candidates(data["candidates"])
        else:
            await obj.handle(data)

    a.signal = lambda data: dispatch(right, data)
    b.signal = lambda data: dispatch(left, data)
    try:
        pa, pb = await asyncio.wait_for(asyncio.gather(left.connect(), right.connect()), 20)
        assert pa.ready.is_set() and pb.ready.is_set()
        assert (await a.chat("raw verified"))["mbps"] > 0
        assert await pa.ping() >= 0
    finally:
        await close_pair(peers, (left, right))


async def test_invalid_signed_hairpin_and_lan_datagrams_do_not_escape_callbacks(peers):
    from p2plab.lan import Discovery, LanAttempt
    from p2plab.udp import probe_packet

    a, _ = peers
    spec, _ = specs("hairpin", "127.0.0.1")
    obj = UdpAttempt(a, spec, "127.0.0.1")
    body = a.identity.sign({"kind": "hairpin", "v": 1, "pair": a.pair, "attempt": spec["attempt"],
                            "from": a.peer_id, "to": a.peer_id, "nonce": "a" * 32, "size": 512})
    body["nonce"] = "b" * 32
    obj.datagram_received(probe_packet(body), ("127.0.0.1", 5000))
    assert obj.rejected == 1
    lan = LanAttempt(a, spec, "127.0.0.1")
    from p2plab.common import packed

    Discovery(lan).datagram_received(packed(body), ("127.0.0.1", 5000))
    assert not lan.candidates_ready.is_set()


async def test_nat64_translated_namespace_quic_chat_and_file(peers, tmp_path):
    if os.environ.get("P2PLAB_RAW_TEST") != "isolated":
        pytest.skip("requires isolated synthetic-address setup")
    a, b = peers
    sa, sb = specs("nat64", "::1")
    left = Nat64Attempt(a, sa, "::1")
    right = Nat64Attempt(b, sb, "127.0.0.2")
    bridges = []

    class Bridge(asyncio.DatagramProtocol):
        def __init__(self, forward):
            self.forward = forward

        def datagram_received(self, data, source):
            self.forward(data)

    try:
        await asyncio.gather(left.open(), right.open())
        translated, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Bridge(lambda data: synthesized.sendto(data, tuple(left.candidates[0]))),
            local_addr=("127.0.0.1", 0))
        bridges.append(translated)
        synthesized, _ = await asyncio.get_running_loop().create_datagram_endpoint(
            lambda: Bridge(lambda data: translated.sendto(data, tuple(right.candidates[0]))),
            local_addr=("64:ff9b::7f00:2", right.candidates[0][1]))
        bridges.append(synthesized)
        left.prefixes = ["64:ff9b::/96"]
        left.candidates.append(list(translated.get_extra_info("sockname")[:2]))
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        await asyncio.gather(left.punch(2), right.punch(2))
        pa, pb = await asyncio.gather(left.start_quic(), right.start_quic())
        assert pa.family == 6 and pb.family == 4
        assert (await a.chat("cross family verified"))["mbps"] > 0
        assert await pa.ping() >= 0
        source = tmp_path / "cross-family.bin"
        source.write_bytes(bytes(1024 * 1024))
        assert (await a.transfers.send(pa, source))["bytes"] == 1024 * 1024
    finally:
        await close_pair(peers, (left, right))
        for bridge in bridges:
            bridge.close()


async def test_network_retry_replaces_pending_matrix_but_retains_live_paths(peers, monkeypatch):
    from unittest.mock import AsyncMock

    a, b = peers
    sa, sb = specs("quic", "127.0.0.1")
    left, right = UdpAttempt(a, sa, "127.0.0.1"), UdpAttempt(b, sb, "127.0.0.1")
    manager = Experiments(a)
    manager.plan = [{"attempt": sa["attempt"]}]
    manager.attempts = {sa["attempt"]: left}
    a.manager = manager
    a.paired.set()
    a.connected.set()
    a.network = {"addresses": [{"address": "127.0.0.1"}]}
    try:
        await asyncio.gather(left.open(), right.open())
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        await asyncio.gather(left.punch(2), right.punch(2))
        pa, _ = await asyncio.gather(left.start_quic(), right.start_quic())
        manager.task = asyncio.create_task(asyncio.sleep(60))
        a.signal = AsyncMock()
        a.collect_network = AsyncMock()
        a.inbound_supported = True
        a.inbound_check = AsyncMock()
        monkeypatch.setattr(Experiments, "start", AsyncMock())
        await a.restart_experiments(automatic=True)
        assert manager.closed and manager.task.cancelled()
        assert not pa.closed and pa.ready.is_set() and not left.closed
        assert await pa.ping() >= 0
        assert a.manager is not manager and sa["attempt"] in a.retired_attempts
        a.signal.assert_awaited_once_with({"kind": "phase", "attempt": "setup", "phase": "retry"})
        a.inbound_check.assert_awaited_once()
    finally:
        await close_pair(peers, (left, right))


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_stunt_rebind_then_reverse_tls_channel(peers, host):
    from p2plab.tcp_stunt import StuntAttempt

    a, b = peers
    sa, sb = specs("tcp-stunt", host, ttl=1)
    left, right = StuntAttempt(a, sa, host), StuntAttempt(b, sb, host)
    left.sync, right.sync = Synchronizer(a, sa["attempt"]), Synchronizer(b, sb["attempt"])
    a.signal, b.signal = right.sync.handle, left.sync.handle
    try:
        await asyncio.gather(left.prepare(), right.prepare())
        left.set_candidates(right.candidates)
        right.set_candidates(left.candidates)
        pa, pb = await asyncio.wait_for(asyncio.gather(left.connect(), right.connect()), 10)
        assert pa.mechanism == pb.mechanism == "tcp-stunt"
        assert (await a.chat("reverse verified"))["mbps"] > 0
    finally:
        await close_pair(peers, (left, right))


async def test_signed_lan_broadcast_discovers_only_paired_peer_and_upgrades_quic(peers):
    from p2plab.lan import LanAttempt

    a, b = peers
    reserve = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    reserve.bind(("0.0.0.0", 0))
    port = reserve.getsockname()[1]
    reserve.close()
    for owner in peers:
        owner.config["experiment"]["lan_port"] = port
    sa, sb = specs("lan", "127.0.0.1")
    left, right = LanAttempt(a, sa, "127.0.0.1"), LanAttempt(b, sb, "127.0.0.1")
    try:
        await asyncio.gather(left.open(), right.open())
        await asyncio.gather(left.discover(2), right.discover(2))
        assert left.remote_candidates == right.candidates and right.remote_candidates == left.candidates
        await asyncio.gather(left.punch(2), right.punch(2))
        pa, pb = await asyncio.gather(left.start_quic(), right.start_quic())
        assert pa.ready.is_set() and pb.ready.is_set()
        assert (await a.chat("LAN verified"))["mbps"] > 0
    finally:
        await close_pair(peers, (left, right))


async def test_integrated_mechanism_matrix_continues_after_success(peers, monkeypatch):
    import p2plab.experiments as module

    a, b = peers
    original = module.build_plan

    def selected_plan(*args, **kwargs):
        kwargs["research"], kwargs["coverage"] = True, None
        rows = original(*args, **kwargs)
        seen, selected = set(), []
        for spec in rows:
            if spec["method"] not in seen and spec["method"] != "nat64":
                seen.add(spec["method"])
                selected.append(spec)
        return selected

    monkeypatch.setattr(module, "build_plan", selected_plan)
    managers = [Experiments(owner) for owner in peers]
    for owner, manager in zip(peers, managers, strict=True):
        owner.network = {"addresses": [{"address": "127.0.0.1", "family": 4}]}
        owner.network_ready.set()
        owner.manager = manager
    a.signal = lambda data: dispatch(managers[1], data)
    b.signal = lambda data: dispatch(managers[0], data)

    async def dispatch(manager, data):
        manager.dispatch(data)

    try:
        await asyncio.gather(*(manager.start() for manager in managers))
        await asyncio.wait_for(asyncio.gather(*(manager.task for manager in managers)), 65)
        for manager in managers:
            assert len(manager.results) == len(manager.plan) >= 20
            results = {row["method"]: row for row in manager.results}
            assert results["quic"]["data_path"] and results["tcp-race"]["data_path"]
            assert results["lan"]["data_path"] and results["tcp-stunt"]["data_path"]
            assert results["pwnat"]["state"] == results["natblaster"]["state"] == "not-applicable"
            assert results["hairpin"]["data_path"] is False
            assert not any("ModuleNotFoundError" in row.get("reason", "") for row in manager.results)
        assert (await a.chat("matrix complete"))["mbps"] > 0
    finally:
        await asyncio.gather(*(manager.close() for manager in managers))
        await asyncio.gather(*(task for owner in peers for task in owner.tasks), return_exceptions=True)


async def test_socket_pool_partial_open_failure_releases_all_bound_sockets(peers, monkeypatch):
    a, _ = peers
    spec, _ = specs("udp-birthday-dual", "127.0.0.1", socket_count=16, target_count=16,
                    rounds=2, hard_side="both")
    obj = SocketPoolAttempt(a, spec, "127.0.0.1")
    original = UdpAttempt.open
    count = 0

    async def limited_open(udp):
        nonlocal count
        count += 1
        if count == 3:
            raise OSError("SIMULATED_FD_EXHAUSTION")
        await original(udp)

    monkeypatch.setattr(UdpAttempt, "open", limited_open)
    with pytest.raises(OSError, match="FD_EXHAUSTION"):
        await obj.open()
    assert obj.closed and len(obj.sockets) == 3 and all(udp.closed for udp in obj.sockets)
    assert all(not udp.transport or udp.transport.is_closing() for udp in obj.sockets)
    await obj.close()


async def test_closed_matrix_cannot_restart_after_delayed_pair_setup(peers):
    from unittest.mock import AsyncMock

    a, _ = peers
    a.signal = AsyncMock()
    manager = Experiments(a)
    await manager.close()
    await asyncio.wait_for(manager.start(), 0.1)
    assert manager.task is None
    a.signal.assert_not_awaited()
