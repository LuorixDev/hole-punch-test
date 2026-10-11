"""Benchmark ack regression tests: progress window, bench-ack handling, loud failures.

Covers the t16 findings: the old hard 10 s window (receiver) vs the desktop's
~15 s budget (sender) closed the round silently at peer.py:225/228, and an inbound
bench-ack was treated as an illegal frame. Controlled stand-in data channels only;
this is not real WebRTC evidence.
"""
import asyncio
import uuid
import json

import pytest

from p2pchat.peer import BENCH_HARD_CEILING, BENCH_IDLE_TIMEOUT, Peer, frame


class FakeDC:
    def __init__(self, label="benchmark"):
        self.label = label
        self.readyState = "open"
        self.bufferedAmount = 0
        self.bufferedAmountLowThreshold = 0
        self.handlers = {}
        self.sent = []
        self.closed = False

    def on(self, event, callback=None):
        """aiortc-style: usable as `on(event, callback)` or as a decorator."""
        if callback is None:
            def decorator(function):
                self.handlers[event] = function
                return function
            return decorator
        self.handlers[event] = callback
        return callback

    def emit(self, event, *args):
        callback = self.handlers.get(event)
        if callback is not None:
            callback(*args)

    def send(self, data):
        self.sent.append(data)

    def close(self):
        self.closed = True
        self.readyState = "closed"
        self.emit("close")


class Clock:
    def __init__(self, start=1000.0):
        self.now = start

    def monotonic(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


def make_peer(tmp_path, name="p"):
    return Peer("ws://127.0.0.1:1", "room", "bench-secret-128-bit", name=name, log_dir=str(tmp_path / name), echo=False)


def make_path(peer):
    path = {"pc": None, "peer": "answerer", "profile": "quic", "attempt": str(uuid.uuid4()),
            "connectionId": str(uuid.uuid4()),
            "files": {}, "acks": {}, "hello": True, "nonce": "0" * 64, "remote_nonce": None,
            "ack_sent": False, "ack_received": False, "hello_sent": True, "tasks": set(), "closing": False,
            "low": asyncio.Event(), "benchmark_ready": asyncio.Event(), "created": 0.0, "dc": None,
            "bench": None, "bench_failure": None}
    peer.paths["answerer"] = path
    return path


def ack_sent(dc):
    return [json.loads(item) for item in dc.sent if isinstance(item, str) and json.loads(item).get("kind") == "bench-ack"]


def errors_sent(dc):
    return [json.loads(item) for item in dc.sent if isinstance(item, str) and json.loads(item).get("kind") == "bench-error"]


def failures(peer):
    return [event for event in peer.store.pending() if event.get("event") == "task.error"]


def failure_reasons(peer):
    return [event.get("data", {}).get("reason") for event in failures(peer)]


def test_normal_round_still_gets_an_ack(tmp_path):
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-1"}))
    dc.emit("message", frame("round-1", b"x" * 4096, 0))
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "round-1", "bytes": 4096}))
    acks = ack_sent(dc)
    assert len(acks) == 1 and acks[0]["bytes"] == 4096 and acks[0]["id"] == "round-1"
    assert not dc.closed and path["bench"] is None
    assert failures(peer) == []


def test_long_round_within_progress_window_still_gets_an_ack(tmp_path, monkeypatch):
    """A 12 s round whose drain was announced must not be cut off (the old 10 s bug)."""
    clock = Clock()
    monkeypatch.setattr("p2pchat.peer.time.monotonic", clock.monotonic)
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-2", "drainMs": 10000}))
    dc.emit("message", frame("round-2", b"y" * 1024, 0))
    clock.advance(12.0)  # inside idle window (max(20, 10+5) = 20 s)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "round-2", "bytes": 1024}))
    acks = ack_sent(dc)
    assert len(acks) == 1 and acks[0]["bytes"] == 1024
    assert not dc.closed and failures(peer) == []


def test_round_past_idle_window_reports_timeout_loudly(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("p2pchat.peer.time.monotonic", clock.monotonic)
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-3"}))
    clock.advance(BENCH_IDLE_TIMEOUT + 1)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "round-3", "bytes": 0}))
    assert ack_sent(dc) == []  # never a fabricated ack
    assert errors_sent(dc) and errors_sent(dc)[0]["code"] == "BENCH_TIMEOUT"
    assert failure_reasons(peer) == ["TIMEOUT"]
    assert dc.closed and path["bench"] is None


def test_data_after_idle_window_fails_with_an_event(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("p2pchat.peer.time.monotonic", clock.monotonic)
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-4"}))
    clock.advance(BENCH_IDLE_TIMEOUT + 1)
    dc.emit("message", frame("round-4", b"z" * 16, 0))
    assert errors_sent(dc) and errors_sent(dc)[0]["code"] == "BENCH_TIMEOUT"
    assert failure_reasons(peer) == ["TIMEOUT"] and dc.closed


def test_hard_ceiling_still_bounds_a_round(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("p2pchat.peer.time.monotonic", clock.monotonic)
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-5", "drainMs": 60000}))
    clock.advance(BENCH_HARD_CEILING + 1)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "round-5", "bytes": 0}))
    assert ack_sent(dc) == [] and errors_sent(dc)[0]["code"] == "BENCH_TIMEOUT"


def test_inbound_bench_ack_is_delivered_not_an_invalid_frame(tmp_path):
    """A sender must be able to receive its own ack without the channel being closed."""
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-ack", "id": "round-6", "bytes": 2048}))
    assert not dc.closed
    assert failures(peer) == []
    peer_id, message = peer.received.get_nowait()
    assert peer_id == "answerer" and message["kind"] == "bench-ack" and message["bytes"] == 2048


def test_inbound_bench_error_is_delivered(tmp_path):
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-error", "id": "round-7", "code": "BENCH_TIMEOUT"}))
    assert not dc.closed
    _, message = peer.received.get_nowait()
    assert message == {"v": 1, "kind": "bench-error", "id": "round-7", "code": "BENCH_TIMEOUT"}


def test_bench_end_without_a_round_is_an_explicit_failure(tmp_path):
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "ghost", "bytes": 0}))
    assert ack_sent(dc) == []
    assert errors_sent(dc)[0]["code"] == "BENCH_NOT_STARTED"
    assert len(failures(peer)) == 1  # loud diagnostic event, not a silent close


def test_watchdog_expires_a_silent_round_loudly(tmp_path, monkeypatch):
    clock = Clock()
    monkeypatch.setattr("p2pchat.peer.time.monotonic", clock.monotonic)
    peer = make_peer(tmp_path)
    path = make_path(peer)
    dc = FakeDC()
    path["benchmark"] = dc
    peer.install_benchmark(path, dc)
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-start", "id": "round-8"}))
    clock.advance(BENCH_IDLE_TIMEOUT + 1)
    # Drive one watchdog pass exactly like Peer.watchdog does with the same clock.
    bench = path.get("bench")
    assert bench is not None and peer.bench_expired(bench, clock.monotonic())
    path["bench_failure"] = {"id": bench["id"], "code": "BENCH_TIMEOUT", "at": clock.monotonic()}
    peer.bench_fail(path, dc, "BENCH_TIMEOUT", bench["id"])
    path["bench"] = None
    assert errors_sent(dc) and errors_sent(dc)[0]["code"] == "BENCH_TIMEOUT"
    # A late bench-end keeps the explicit reason instead of pretending it never started.
    dc.closed = False
    dc.readyState = "open"
    dc.emit("message", json.dumps({"v": 1, "kind": "bench-end", "id": "round-8", "bytes": 0}))
    assert errors_sent(dc)[-1]["code"] == "BENCH_TIMEOUT"


def test_silence_from_the_peer_is_a_timeout_not_a_fake_success(tmp_path, monkeypatch):
    """engine._webrtc_benchmark must report ACK_TIMEOUT and never invent a rate."""
    from p2pchat.python_desktop.engine import BENCHMARK_MAX_BYTES, DesktopEngine, EngineConfig

    engine = DesktopEngine(EngineConfig(url="ws://127.0.0.1:1", room="room", secret="bench-secret-128-bit"))

    class SilentDC:
        readyState = "open"
        bufferedAmount = 0

        def __init__(self):
            self.sent = []

        def send(self, data):
            self.sent.append(data)

    class SilentPeer:
        def __init__(self, dc):
            self.dc = dc

        async def wait_benchmark(self, path, timeout=5):
            return self.dc

    dc = SilentDC()
    engine.peer = SilentPeer(dc)

    async def no_answer(awaitable, timeout):
        raise asyncio.TimeoutError()

    monkeypatch.setattr("p2pchat.python_desktop.engine.asyncio.wait_for", no_answer)
    result = asyncio.run(engine._webrtc_benchmark({}, seconds=0.01, max_bytes=4096))
    assert result["ok"] is False and result["reason"] == "ACK_TIMEOUT"
    assert "mbps" not in result and result["bytes"] == 4096
    assert any(json.loads(item)["kind"] == "bench-start" for item in dc.sent if isinstance(item, str))
    assert any(json.loads(item)["kind"] == "bench-end" for item in dc.sent if isinstance(item, str))
    assert BENCHMARK_MAX_BYTES == 32 * 1024 * 1024
