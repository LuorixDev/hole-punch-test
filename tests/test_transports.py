import asyncio
import ipaddress
import secrets
import socket
import sys

import pytest

from p2plab.rtc import RtcAttempt
from p2plab.tcp import TcpAttempt
from p2plab.udp import UdpAttempt, dont_fragment_option


def specs(method, host, **params):
    base = {"attempt": secrets.token_hex(8), "method": method, "profile": "fast", **params}
    return (
        {**base, "host": host, "initiator": True, "tls_client": True},
        {**base, "host": host, "initiator": False, "tls_client": False},
    )


async def test_experiment_ping_failure_never_reports_a_verified_data_path(peers, monkeypatch):
    from p2plab.experiments import Experiments
    from p2plab.session import Path

    a, b = peers
    ma, mb = Experiments(a), Experiments(b)
    sa, sb = specs("tcp", "127.0.0.1", phase="baseline")
    ma.plan, mb.plan = [sa], [sb]
    sent = []

    async def from_a(data):
        sent.append(data)
        await mb.handle(data)

    async def from_b(data):
        await ma.handle(data)

    a.signal, b.signal = from_a, from_b
    original = Path.ping

    async def fail_verify(path, *args, **kwargs):
        if path.owner is a:
            raise TimeoutError("TEST_VERIFICATION_PONG_TIMEOUT")
        return await original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "ping", fail_verify)
    try:
        left, _ = await asyncio.wait_for(asyncio.gather(ma.execute(sa, 0), mb.execute(sb, 0)), 8)
        assert left["data_path"] is False and left["state"] == "failed"
        assert next(d for d in sent if d["kind"] == "done")["result"]["data_path"] is False
        assert all(path.closed for path in a.paths)
        assert not any(row["event"] == "path.verified" for row in a.log.query())
    finally:
        await asyncio.gather(ma.close(), mb.close())


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_udp_mutual_auth_and_directional_mtu(peers, host):
    a, b = peers
    sa, sb = specs("udp", host)
    ua, ub = UdpAttempt(a, sa, host), UdpAttempt(b, sb, host)
    try:
        await asyncio.gather(ua.open(), ub.open())
        ua.set_candidates(ub.candidates)
        ub.set_candidates(ua.candidates)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        results = await asyncio.gather(ua.mtu(), ub.mtu())
        assert all(r["confirmed"] == 2 for results_for_peer in results for r in results_for_peer)
        assert not a.paths and not b.paths
    finally:
        await asyncio.gather(ua.close(), ub.close())


@pytest.mark.parametrize(
    ("system", "family", "expected"),
    [
        ("linux", socket.AF_INET, (socket.IPPROTO_IP, 10, 2, "linux-ip-mtu-discover")),
        ("linux", socket.AF_INET6, (socket.IPPROTO_IPV6, 23, 2, "linux-ipv6-mtu-discover")),
        ("darwin", socket.AF_INET, (socket.IPPROTO_IP, 28, 1, "darwin-ip-dontfrag")),
        ("darwin", socket.AF_INET6, (socket.IPPROTO_IPV6, 62, 1, "darwin-ipv6-dontfrag")),
    ],
)
def test_dont_fragment_option_maps_each_platform(system, family, expected):
    assert dont_fragment_option(family, system=system) == expected


def test_dont_fragment_option_is_absent_where_the_kernel_has_no_switch():
    # Never guess a numeric option on an unverified kernel: opt-in must fail closed to "unsupported".
    assert dont_fragment_option(socket.AF_INET, system="freebsd13") is None
    assert dont_fragment_option(socket.AF_INET6, system="freebsd13") is None


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires an actual macOS host")
def test_darwin_dont_fragment_options_are_accepted_by_the_kernel():
    # Python does not export Darwin's IP_DONTFRAG, so the literal must be validated against the kernel.
    for family in (socket.AF_INET, socket.AF_INET6):
        level, option, value, _ = dont_fragment_option(family, system="darwin")
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(level, option, value)
            assert sock.getsockopt(level, option) == value


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_udp_open_records_the_dont_fragment_backend(peers, host):
    a, _ = peers
    ua = UdpAttempt(a, specs("udp", host)[0], host)
    try:
        await ua.open()
        option = dont_fragment_option(socket.AF_INET if ":" not in host else socket.AF_INET6)
        expected = option[3] if option else "unsupported"
        assert ua.dont_fragment == expected
        # The bound event must carry it, otherwise a weak PMTU verdict is not traceable to the kernel.
        assert a.log.query()[-1]["fields"]["dont_fragment"] == expected
    finally:
        await ua.close()


async def test_udp_mtu_evidence_reports_the_dont_fragment_backend(peers):
    a, b = peers
    host = "127.0.0.1"
    sa, sb = specs("udp", host)
    ua, ub = UdpAttempt(a, sa, host), UdpAttempt(b, sb, host)
    try:
        await asyncio.gather(ua.open(), ub.open())
        ua.set_candidates(ub.candidates)
        ub.set_candidates(ua.candidates)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        await ua.mtu()
        event = [r for r in a.log.query() if r["event"] == "mtu.directional"][-1]
        assert event["fields"]["dont_fragment"] == ua.dont_fragment
        assert ua.dont_fragment == dont_fragment_option(socket.AF_INET)[3]
    finally:
        await asyncio.gather(ua.close(), ub.close())




@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_udp_quic_chat_ping_and_speed(peers, host, task_scheduling):
    a, b = peers
    sa, sb = specs("quic", host)
    ua, ub = UdpAttempt(a, sa, host), UdpAttempt(b, sb, host)
    try:
        await asyncio.gather(ua.open(), ub.open())
        ua.set_candidates(ub.candidates)
        ub.set_candidates(ua.candidates)
        await asyncio.gather(ua.punch(2), ub.punch(2))
        pa, pb = await asyncio.gather(ua.start_quic(), ub.start_quic())
        assert pa.ready.is_set() and pb.ready.is_set()
        assert await pa.ping() >= 0
        await a.chat("this must not be in central diagnostics")
        assert not a.chat_acks
        result = await pa.speed(1024 * 1024)
        assert result["bytes"] == 1024 * 1024 and result["mbps"] > 0
        assert result["sender_runtime"]["transport"]["tx_datagrams"] > 0
        assert result["receiver_runtime"]["transport"]["rx_datagrams"] > 0
        assert result["sender_runtime"]["transport"]["socket_buffers"]["receive_bytes"] > 0
        reverse = await pb.speed(1024 * 1024)
        assert reverse["bytes"] == 1024 * 1024
        assert "this must not" not in str(a.log.query()) + str(b.log.query())
    finally:
        for peer in (a, b):
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ua.close(), ub.close())


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_tcp_tls_mutual_pin_chat_speed(peers, host):
    a, b = peers
    sa, sb = specs("tcp", host)
    ta, tb = TcpAttempt(a, sa, host), TcpAttempt(b, sb, host)
    try:
        await asyncio.gather(ta.prepare(), tb.prepare())
        ta.set_candidates(tb.candidates)
        tb.set_candidates(ta.candidates)
        pa, pb = await asyncio.gather(ta.connect(), tb.connect())
        assert await pa.ping() >= 0
        await b.chat("hello")
        result = await pb.speed(1024 * 1024)
        assert result["bytes"] == 1024 * 1024
    finally:
        for peer in (a, b):
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ta.close(), tb.close())


async def test_no_peer_never_reports_success(peers):
    a, _ = peers
    sa, _ = specs("udp", "127.0.0.1")
    udp = UdpAttempt(a, sa, "127.0.0.1")
    try:
        await udp.open()
        udp.set_candidates([["127.0.0.1", 9]])
        with pytest.raises(TimeoutError):
            await udp.punch(0.15)
        assert not udp.direct.is_set()
        assert not a.paths
    finally:
        await udp.close()


@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_tcp_listener_can_close_first_without_waiting_for_peer_shutdown(peers, host):
    a, b = peers
    sa, sb = specs("tcp", host)
    ta, tb = TcpAttempt(a, sa, host), TcpAttempt(b, sb, host)
    try:
        await asyncio.gather(ta.prepare(), tb.prepare())
        ta.set_candidates(tb.candidates)
        tb.set_candidates(ta.candidates)
        pa, pb = await asyncio.gather(ta.connect(), tb.connect())
        assert tb.server is not None
        await asyncio.wait_for(pb.close("SERVER_END_FIRST"), 4)
        assert tb.closed and tb.writer.is_closing()
    finally:
        for peer in (a, b):
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ta.close(), tb.close())


@pytest.mark.parametrize("profile", ["4", "6", "dual"])
async def test_webrtc_real_data_channels_mutual_auth_and_bidirectional_speed(peers, task_scheduling, profile):
    a, b = peers
    sa, sb = specs("webrtc", "127.0.0.1", profile=profile)
    ra, rb = RtcAttempt(a, sa), RtcAttempt(b, sb)
    a.observers = b.observers = []

    async def from_a(data):
        await rb.handle(data)

    async def from_b(data):
        await ra.handle(data)

    a.signal, b.signal = from_a, from_b
    try:
        pa, pb = await asyncio.gather(ra.connect(), rb.connect())
        assert pa.ready.is_set() and pb.ready.is_set()
        for rtc in (ra, rb):
            addresses = [ipaddress.ip_address(line.split()[4]) for line in rtc.local_sdp().splitlines()
                         if line.startswith("a=candidate:")]
            assert addresses and all(address.is_loopback for address in addresses)
            assert profile == "dual" or all(address.version == int(profile) for address in addresses)
        await a.chat("webrtc verified")
        assert (await pa.speed(1024 * 1024))["bytes"] == 1024 * 1024
        assert (await pa.reverse_speed(1024 * 1024))["bytes"] == 1024 * 1024
    finally:
        for peer in (a, b):
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ra.close(), rb.close())


async def test_webrtc_real_network_retains_normal_host_discovery(peers):
    client, _ = peers
    client.loopback = False
    spec, _ = specs("webrtc", "127.0.0.1", profile="4")
    rtc = RtcAttempt(client, spec)
    try:
        rtc.pc.createDataChannel("chat")
        connection = rtc.pc.sctp.transport.transport.iceGatherer._connection
        observed = []

        async def gather(component, addresses, timeout=5):
            observed.extend(addresses)
            return []

        connection.get_component_candidates = gather
        original = connection.get_component_candidates
        rtc.configure_gatherer()
        assert (connection.get_component_candidates == original) == (sys.platform != "win32")
        assert rtc.gatherer_configured == (sys.platform == "win32")
        addresses = ["192.0.2.1", "2001:db8::1"]
        await connection.get_component_candidates(component=1, addresses=addresses)
        assert observed == addresses
    finally:
        await rtc.close()


@pytest.mark.parametrize("kind", ["offer", "answer"])
async def test_webrtc_closed_attempt_ignores_late_signal(peers, task_scheduling, kind):
    a, _ = peers
    sa, _ = specs("webrtc", "127.0.0.1", profile="4")
    rtc = RtcAttempt(a, sa)
    await rtc.close()
    await rtc.handle({"kind": kind, "sdp": "invalid late SDP"})
    assert rtc.pc.signalingState == "closed"
    records = a.log.query()
    assert any(r["event"] == "webrtc.signal_ignored" and r["fields"]["kind"] == kind for r in records)
    assert not any(r["level"] == "ERROR" for r in records)


async def test_webrtc_close_serializes_with_gathering_and_does_not_send_offer(
    peers, task_scheduling, monkeypatch
):
    a, _ = peers
    sa, _ = specs("webrtc", "127.0.0.1", profile="4")
    rtc = RtcAttempt(a, sa)
    gathered, release = asyncio.Event(), asyncio.Event()
    original = rtc.pc.setLocalDescription
    sent = []

    async def delayed(description):
        await original(description)
        gathered.set()
        await release.wait()

    async def signal(data):
        sent.append(data)

    monkeypatch.setattr(rtc.pc, "setLocalDescription", delayed)
    a.signal = signal
    offer = asyncio.create_task(rtc.offer())
    closing = None
    try:
        await asyncio.wait_for(gathered.wait(), 3)
        closing = asyncio.create_task(rtc.close())
        await asyncio.sleep(0)
        assert rtc.closed and not closing.done()
        release.set()
        await asyncio.wait_for(asyncio.gather(offer, closing, rtc.close()), 3)
        assert sent == [] and rtc.pc.signalingState == "closed"
    finally:
        release.set()
        await asyncio.gather(offer, *([closing] if closing else []), return_exceptions=True)
        await rtc.close()


async def test_webrtc_immediate_close_after_answer_leaves_no_unhandled_connect_task(peers, task_scheduling):
    a, b = peers
    sa, sb = specs("webrtc", "127.0.0.1", profile="4")
    ra, rb = RtcAttempt(a, sa), RtcAttempt(b, sb)
    errors = []
    loop = asyncio.get_running_loop()
    previous = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(context))

    async def from_a(data):
        await rb.handle(data)

    async def from_b(data):
        await ra.handle(data)
        await asyncio.gather(ra.path.close("TEST_EARLY_CLOSE"), rb.path.close("TEST_EARLY_CLOSE"))

    a.signal, b.signal = from_a, from_b
    try:
        await asyncio.wait_for(ra.offer(), 15)
        await asyncio.sleep(0.1)
        assert errors == []
        assert ra.closed and rb.closed
    finally:
        await asyncio.gather(ra.close(), rb.close())
        loop.set_exception_handler(previous)


async def test_asyncio_error_journal_keeps_context_and_chains_handler(peers):
    a, _ = peers
    loop = asyncio.get_running_loop()
    seen = []
    context = {
        "message": "Future exception was never retrieved",
        "exception": RuntimeError("background failure"),
        "future": "future-object",
    }
    a.handle_asyncio_exception(loop, context, lambda active_loop, received: seen.append(received))
    record = next(row for row in a.log.query() if row["event"] == "runtime.asyncio_error")
    assert record["fields"]["exception"] == "RuntimeError"
    assert "future-object" in record["fields"]["asyncio_context"]["future"]
    assert seen == [context]




async def test_tcp_accept_timeout_has_explicit_reason(peers):
    a, _ = peers
    _, spec = specs("tcp", "127.0.0.1")
    tcp = TcpAttempt(a, spec, "127.0.0.1")
    tcp.candidates_ready.set()
    a.timeout = 0.01
    original_wait = asyncio.wait_for

    async def short_wait(awaitable, timeout):
        return await original_wait(awaitable, min(timeout, 0.01))

    from unittest.mock import patch

    try:
        with patch("p2plab.tcp.asyncio.wait_for", short_wait):
            with pytest.raises(TimeoutError, match="TCP_LISTEN_ACCEPT_TIMEOUT"):
                await tcp.connect()
    finally:
        await tcp.close()
