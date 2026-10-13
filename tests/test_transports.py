import asyncio
import ipaddress
import secrets

import pytest

from p2plab.rtc import RtcAttempt
from p2plab.tcp import TcpAttempt
from p2plab.udp import UdpAttempt


def specs(method, host, **params):
    base = {"attempt": secrets.token_hex(8), "method": method, "profile": "fast", **params}
    return (
        {**base, "host": host, "initiator": True, "tls_client": True},
        {**base, "host": host, "initiator": False, "tls_client": False},
    )


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


async def test_webrtc_real_network_gatherer_remains_unmodified(peers):
    client, _ = peers
    client.loopback = False
    spec, _ = specs("webrtc", "127.0.0.1", profile="4")
    rtc = RtcAttempt(client, spec)
    try:
        rtc.pc.createDataChannel("chat")
        connection = rtc.pc.sctp.transport.transport.iceGatherer._connection
        original = connection.get_component_candidates
        rtc.configure_loopback_gatherer()
        assert connection.get_component_candidates == original
        assert not rtc.loopback_gatherer_configured
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
        await asyncio.wait_for(ra.offer(), 5)
        await asyncio.sleep(0.1)
        assert errors == []
        assert ra.closed and rb.closed
    finally:
        await asyncio.gather(ra.close(), rb.close())
        loop.set_exception_handler(previous)


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
