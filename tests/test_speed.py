import asyncio
import time
from types import SimpleNamespace

import pytest

from p2plab.common import BENCH_CHUNK
from p2plab.session import BENCH_CAPABILITY, BENCH_WINDOW, Path
from p2plab.tcp import TcpAttempt
from tests.test_transports import specs


@pytest.mark.parametrize("method", ["tcp", "quic"])
async def test_timed_speed_confirms_partial_sample_both_directions_and_keeps_chat(peers, monkeypatch, method):
    from tests.test_transfers import connected

    monkeypatch.setattr("p2plab.session.BENCH_SAMPLE_SECONDS", 0.12)
    async with connected(peers, method) as (pa, pb):
        for path in (pa, pb):
            original = path._send

            async def paced(body, original=original):
                if body["kind"] == "bench_chunk":
                    await asyncio.sleep(0.025)
                await original(body)

            monkeypatch.setattr(path, "_send", paced)
        requested = 4 * 1024 * 1024
        for operation in (pa.speed, pa.reverse_speed, pa.speed):
            result = await asyncio.wait_for(operation(requested), 3)
            assert 0 < result["bytes"] < requested
            assert result["requested_bytes"] == requested
            assert result["sample_limited"] == "duration"
            assert result["mbps"] == result["bytes"] * 8 / result["seconds"] / 1e6
            assert result["seconds"] >= 0.12
            assert not pa.receive_benches and not pb.receive_benches
            assert await asyncio.wait_for(pa.ping(), 1) > 0
        assert (await peers[0].chat("chat after repeated timed samples"))["bytes"] > 0
        assert not pa.closed and not pb.closed


async def test_quic_cancel_resets_only_benchmark_then_allows_next_speed_and_chat(peers, monkeypatch):
    from tests.test_transfers import connected, wait_until

    async with connected(peers, "quic") as (pa, pb):
        driver = pa._send.__self__
        original = pa._send
        sent = asyncio.Event()

        async def blocked(body):
            await original(body)
            if body["kind"] == "bench_chunk":
                sent.set()
                await asyncio.Event().wait()

        monkeypatch.setattr(pa, "_send", blocked)
        task = asyncio.create_task(pa.speed(16 * 1024 * 1024))
        try:
            await asyncio.wait_for(sent.wait(), 2)
            await wait_until(lambda: bool(pb.receive_benches))
            assert driver.bench_streams
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await wait_until(lambda: not pb.receive_benches)
            assert not driver.bench_streams
            assert any(r["event"] == "quic.benchmark_stream_reset" for r in peers[0].log.query())
            assert await asyncio.wait_for(pa.ping(), 1) > 0
            assert (await peers[0].chat("chat after QUIC stream reset"))["bytes"] > 0
            monkeypatch.setattr(pa, "_send", original)
            assert (await asyncio.wait_for(pa.speed(1024 * 1024), 3))["bytes"] == 1024 * 1024
            assert not pa.closed and not pb.closed
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_cancel_before_start_ignores_late_frames_even_with_two_live_benchmarks(peers):
    from p2plab.session import TIMED_BENCH_CAPABILITY

    a, _ = peers
    replies = []

    async def send(body):
        replies.append(body)

    async def close():
        pass

    path = Path(a, "reordered", "quic", 4, send, close)
    path.ready.set()
    path.remote_capabilities.update((BENCH_CAPABILITY, TIMED_BENCH_CAPABILITY))
    bid = "0123456789abcdef"
    try:
        await path.receive({"kind": "bench_cancel", "id": bid})
        for other in ("1111111111111111", "2222222222222222"):
            await path.receive({"kind": "bench_start", "id": other, "bytes": 1024, "format": "binary-v1"})
        await path.receive({"kind": "bench_start", "id": bid, "bytes": 1024, "format": "binary-v1", "timed": True})
        await path.receive({"kind": "bench_chunk", "id": bid, "seq": 0, "data": b"late data"})
        await path.receive({"kind": "bench_end", "id": bid, "bytes": 9})
        await path.receive({"kind": "ping", "id": "control"})
        assert replies[-1] == {"kind": "pong", "id": "control"}
        assert bid not in path.receive_benches and len(path.receive_benches) == 2
    finally:
        await path.close()


async def test_timed_partial_requires_capability_and_legacy_still_requires_all_bytes(peers):
    from p2plab.session import TIMED_BENCH_CAPABILITY

    a, _ = peers
    replies = []

    async def send(body):
        replies.append(body)

    async def close():
        pass

    path = Path(a, "compatibility", "tcp", 4, send, close)
    path.ready.set()
    path.remote_capabilities.add(BENCH_CAPABILITY)
    bid = "0123456789abcdef"
    body = {"kind": "bench_start", "id": bid, "bytes": 1024, "format": "binary-v1"}
    try:
        with pytest.raises(ValueError, match="TIMED_BENCH_NOT_NEGOTIATED"):
            await path.receive({**body, "timed": True})
        await path.receive(body)
        await path.receive({"kind": "bench_chunk", "id": bid, "seq": 0, "data": b"x" * 64})
        with pytest.raises(ValueError, match="BENCH_INCOMPLETE"):
            await path.receive({"kind": "bench_end", "id": bid, "bytes": 64})
        path.remote_capabilities.add(TIMED_BENCH_CAPABILITY)
        await path.receive({**body, "timed": True})
        await path.receive({"kind": "bench_chunk", "id": bid, "seq": 0, "data": b"x" * 64})
        assert replies[-1]["kind"] == "bench_ack" and replies[-1]["bytes"] == 64
        await path.receive({"kind": "bench_end", "id": bid, "bytes": 64})
        assert replies[-1]["kind"] == "bench_result" and replies[-1]["bytes"] == 64
    finally:
        await path.close()


@pytest.mark.parametrize("rtt_failure", [False, True])
async def test_measure_path_refreshes_rtt_once_without_invalidating_success(peers, monkeypatch, rtt_failure):
    from tests.test_transfers import connected

    a, _ = peers
    async with connected(peers, "quic") as (pa, _):
        pa.last_rtt = 1500
        calls = []
        original = pa.ping

        async def ping(timeout=5):
            calls.append(timeout)
            if rtt_failure:
                raise TimeoutError("TEST_POST_RTT_TIMEOUT")
            return await original(timeout)

        monkeypatch.setattr(pa, "ping", ping)
        await a.measure_path(pa, 1024 * 1024)
        assert pa.speed_state == "success" and calls == [2]
        assert len(pa.latest_speed) == 2 and not pa.closed
        if not rtt_failure:
            assert pa.last_rtt < 1500 and pa.rtt_measured_at is not None
        event = "speed.post_rtt_failed" if rtt_failure else "speed.post_rtt"
        assert any(r["event"] == event for r in a.log.query())


async def test_reverse_speed_cancel_releases_remote_lock_and_preserves_chat(peers, monkeypatch):
    from tests.test_transfers import connected, wait_until

    a, b = peers
    entered = asyncio.Event()

    async def slow(size):
        entered.set()
        await asyncio.Event().wait()

    async with connected(peers) as (pa, pb):
        monkeypatch.setattr(pb, "speed", slow)
        task = asyncio.create_task(pa.reverse_speed(1024))
        try:
            await asyncio.wait_for(entered.wait(), 2)
            assert b.speed_lock.locked() and pb.reverse_workers
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            await wait_until(lambda: not pb.reverse_workers and not b.speed_lock.locked())
            assert not pa.closed and not pb.closed and not pa.reverse_tests
            assert (await a.chat("chat after cancelling reverse speed"))["bytes"] > 0
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


async def test_total_speed_deadline_includes_final_ack_wait(peers, monkeypatch):
    a, _ = peers
    frames = []

    async def send(body):
        frames.append(body)
        if body["kind"] == "bench_start":
            path.benches[body["id"]].put_nowait({"kind": "bench_ready"})

    async def close():
        pass

    path = Path(a, "deadline", "tcp", 4, send, close)
    path.ready.set()
    path.remote_capabilities.add(BENCH_CAPABILITY)
    monkeypatch.setattr("p2plab.session.BENCH_TIMEOUT", 0.05)
    with pytest.raises(TimeoutError, match="BENCH_TOTAL_TIMEOUT"):
        await asyncio.wait_for(path.speed(1024), 1)
    assert not path.benches and not path.closed
    assert frames[-1]["kind"] == "bench_cancel"
    await path.close()


async def test_expired_benchmark_reports_error_and_ignores_only_its_late_frames(peers):
    a, _ = peers
    replies = []

    async def send(body):
        replies.append(body)

    async def close():
        pass

    path = Path(a, "expiry", "quic", 4, send, close)
    path.ready.set()
    path.remote_capabilities.add(BENCH_CAPABILITY)
    bid = "0123456789abcdef"
    try:
        await path.receive({"kind": "bench_start", "id": bid, "bytes": 1024, "format": "binary-v1"})
        path.receive_benches[bid]["progress"] -= 21
        await path.expire(time.monotonic())
        assert replies[-1] == {"kind": "bench_error", "id": bid, "reason": "BENCH_RECEIVE_TIMEOUT"}
        assert not path.receive_benches
        await path.expire(time.monotonic() + 3600)
        await path.receive({"kind": "bench_chunk", "id": bid, "seq": 0, "data": b"x"})
        await path.receive({"kind": "bench_end", "id": bid})
        await path.receive({"kind": "ping", "id": "still usable"})
        assert replies[-1]["kind"] == "pong"
        with pytest.raises(ValueError, match="BENCH_SEQUENCE_MISMATCH"):
            await path.receive({"kind": "bench_chunk", "id": "fedcba9876543210", "seq": 0, "data": b"x"})
    finally:
        await path.close()


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

        async def ping(timeout=5):
            return 10

        return SimpleNamespace(
            attempt=str(index), closed=False, ready=ready, speed=speed, reverse_speed=reverse,
            latest_speed={}, ping=ping,
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


async def test_speed_is_rejected_while_experiment_matrix_runs(peers):
    client, _ = peers
    client.manager = SimpleNamespace(task=asyncio.create_task(asyncio.Event().wait()))
    try:
        with pytest.raises(ValueError, match="WAIT_FOR_EXPERIMENT_MATRIX_TO_FINISH_BEFORE_SPEED"):
            await client.command("/speed 1")
        assert any(row["event"] == "speed.deferred" for row in client.log.query())
    finally:
        client.manager.task.cancel()
        await asyncio.gather(client.manager.task, return_exceptions=True)


async def test_reverse_speed_is_rejected_when_peer_matrix_is_running(peers):
    from tests.test_transfers import connected

    a, b = peers
    async with connected(peers) as (pa, _):
        blocker = asyncio.create_task(asyncio.Event().wait())
        b.manager = SimpleNamespace(task=blocker)
        try:
            with pytest.raises(ValueError, match="PEER_EXPERIMENT_MATRIX_BUSY"):
                await pa.reverse_speed(1024)
        finally:
            blocker.cancel()
            await asyncio.gather(blocker, return_exceptions=True)


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
