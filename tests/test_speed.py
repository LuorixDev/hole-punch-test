import asyncio
import time
from types import SimpleNamespace

import pytest

from p2plab.common import BENCH_CHUNK
from p2plab.session import BENCH_CAPABILITY, BENCH_WINDOW, Path
from p2plab.tcp import TcpAttempt
from tests.test_transports import specs


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("coarse_clock", [False, True])
async def test_actual_tcp_speed_format_and_receiver_confirmations(peers, legacy, coarse_clock, monkeypatch):
    a, b = peers
    sa, sb = specs("tcp", "127.0.0.1")
    ta, tb = TcpAttempt(a, sa, "127.0.0.1"), TcpAttempt(b, sb, "127.0.0.1")
    try:
        await asyncio.gather(ta.prepare(), tb.prepare())
        ta.set_candidates(tb.candidates)
        tb.set_candidates(ta.candidates)
        pa, pb = await asyncio.gather(ta.connect(), tb.connect())
        if legacy:
            pa.remote_capabilities.clear()
        if coarse_clock:
            baseline = time.monotonic()
            monkeypatch.setattr("p2plab.session.time", SimpleNamespace(
                monotonic=lambda: baseline, perf_counter=time.perf_counter, process_time=time.process_time,
            ))
        result = await pa.speed(2 * 1024 * 1024 + 17)
        assert result["bytes"] == 2 * 1024 * 1024 + 17
        assert result["format"] == ("legacy-json-base64" if legacy else "binary-v1")
        assert result["window_bytes"] == (128 * 1024 if legacy else BENCH_WINDOW)
        assert result["chunk_bytes"] == (8192 if legacy else BENCH_CHUNK)
        assert result["sender_runtime"]["seconds"] > 0
        assert result["receiver_runtime"]["seconds"] > 0
        assert result["seconds"] > 0 and result["receiver_seconds"] > 0
        assert await pa.ping() > 0
        assert not pa.benches and not pb.receive_benches
        await asyncio.wait_for(pa.close(), 4)
    finally:
        for peer in peers:
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ta.close(), tb.close())


async def test_binary_requires_signed_capability_and_preserves_receive_limits(peers):
    a, _ = peers

    async def send(body):
        pass

    async def close():
        pass

    path = Path(a, "limits", "tcp", 4, send, close)
    path.ready.set()
    body = {"kind": "bench_start", "id": "1234567890abcdef", "bytes": 1024, "format": "binary-v1"}
    with pytest.raises(ValueError, match="NOT_NEGOTIATED"):
        await path.receive(body)
    path.remote_capabilities.add(BENCH_CAPABILITY)
    await path.receive(body)
    with pytest.raises(ValueError, match="DUPLICATE_ID"):
        await path.receive(body)
    with pytest.raises(ValueError, match="BINARY_REQUIRED"):
        await path.receive({"kind": "bench_chunk", "id": body["id"], "seq": 0, "data": "YWJj"})
    await path.receive({"kind": "bench_cancel", "id": body["id"]})
    assert path.receive_benches == {}


async def test_remote_wan_measurement_rejects_p2p_bench_without_closing_path(peers):
    a, b = peers
    sa, sb = specs("tcp", "127.0.0.1")
    ta, tb = TcpAttempt(a, sa, "127.0.0.1"), TcpAttempt(b, sb, "127.0.0.1")
    try:
        await asyncio.gather(ta.prepare(), tb.prepare())
        ta.set_candidates(tb.candidates)
        tb.set_candidates(ta.candidates)
        pa, pb = await asyncio.gather(ta.connect(), tb.connect())
        async with b.wan_lock:
            with pytest.raises(ConnectionError, match="PEER_WAN_TEST_RUNNING"):
                await asyncio.wait_for(pa.speed(1024 * 1024), 3)
            assert not pa.closed and not pb.closed and not pb.receive_benches
        assert (await pa.speed(1024 * 1024))["bytes"] == 1024 * 1024
    finally:
        for peer in peers:
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ta.close(), tb.close())


async def test_benchmark_path_close_wakes_waiter_immediately(peers):
    a, _ = peers
    started = asyncio.Event()

    async def send(body):
        if body["kind"] == "bench_start":
            started.set()

    async def close():
        pass

    path = Path(a, "close-bench", "tcp", 4, send, close)
    path.ready.set()
    path.remote_capabilities.add(BENCH_CAPABILITY)
    task = asyncio.create_task(path.speed(1024))
    await started.wait()
    await path.close("TEST_PATH_CLOSED")
    with pytest.raises(ConnectionError, match="TEST_PATH_CLOSED"):
        await asyncio.wait_for(task, 1)
    assert not path.benches


async def test_batch_speed_keeps_active_path_and_continues_after_failure(peers):
    client, _ = peers
    calls = []

    def make_path(index):
        ready = asyncio.Event()
        ready.set()

        async def speed(size):
            calls.append((index, "up", size))
            if index == 1:
                raise ConnectionError("FAILED_TEST_PATH")
            return {"bytes": size, "mbps": 123}

        async def reverse(size):
            calls.append((index, "down", size))
            return {"bytes": size, "mbps": 321}

        return SimpleNamespace(
            attempt=str(index), closed=False, ready=ready, speed=speed, reverse_speed=reverse, latest_speed={}
        )

    client.paths = [make_path(i) for i in range(3)]
    client.active_path = client.paths[2]
    await client.command("/speed-all 1")
    assert [(i, d) for i, d, _ in calls] == [(0, "up"), (0, "down"), (1, "up"), (2, "up"), (2, "down")]
    assert client.active_path is client.paths[2]
    assert client.batch_speed_state["completed"] == 3 and client.batch_speed_state["failed"] == 1
    assert client.paths[0].latest_speed["peer-to-local"]["mbps"] == 321
    logged = [r["fields"] for r in client.log.query() if r["event"] == "speed.result"]
    assert logged and all(r["bottleneck"]["state"] == "unknown" for r in logged)
    assert all(r["bottleneck"]["reason"] for r in logged)


async def test_visible_links_get_periodic_real_rtt_samples(peers):
    a, b = peers
    a.link_monitor_active = True
    a.rtt_monitor_enabled = True
    sa, sb = specs("tcp", "127.0.0.1")
    ta, tb = TcpAttempt(a, sa, "127.0.0.1"), TcpAttempt(b, sb, "127.0.0.1")
    try:
        await asyncio.gather(ta.prepare(), tb.prepare())
        ta.set_candidates(tb.candidates)
        tb.set_candidates(ta.candidates)
        pa, _ = await asyncio.gather(ta.connect(), tb.connect())
        samples = []
        async with asyncio.timeout(6):
            while not samples:
                await asyncio.sleep(0.01)
                samples = [r for r in a.log.query() if r["event"] == "path.rtt_sample"]
        assert pa.last_rtt >= 0 and pa.rtt_state == "measured"
        assert samples and samples[-1]["fields"]["interval_seconds"] == 2
    finally:
        for peer in peers:
            for path in peer.paths:
                await path.close()
        await asyncio.gather(ta.close(), tb.close())
