import asyncio
import hashlib
import os
import struct
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from p2plab.common import BINARY_FLAGS, encode_frame, extract_frames, read_frame
from p2plab.rtc import RtcAttempt
from p2plab.tcp import TcpAttempt
from p2plab.transfers import (
    FILE_CAPABILITY,
    FILE_WINDOW,
    RECEIPT_CAPABILITY,
    open_source,
    receipt,
    validate_receipt,
)
from p2plab.udp import UdpAttempt
from tests.test_transports import specs


@asynccontextmanager
async def connected(peers, method="tcp", host="127.0.0.1"):
    a, b = peers
    sa, sb = specs(method, host, profile="4" if method == "webrtc" else "fast")
    if method == "webrtc":
        ta, tb = RtcAttempt(a, sa), RtcAttempt(b, sb)
        a.observers = b.observers = []

        async def from_a(data):
            await tb.handle(data)

        async def from_b(data):
            await ta.handle(data)

        a.signal, b.signal = from_a, from_b
    else:
        cls = TcpAttempt if method == "tcp" else UdpAttempt
        ta, tb = cls(a, sa, host), cls(b, sb, host)
    try:
        if method == "tcp":
            await asyncio.gather(ta.prepare(), tb.prepare())
            ta.set_candidates(tb.candidates)
            tb.set_candidates(ta.candidates)
            paths = await asyncio.gather(ta.connect(), tb.connect())
        elif method == "quic":
            await asyncio.gather(ta.open(), tb.open())
            ta.set_candidates(tb.candidates)
            tb.set_candidates(ta.candidates)
            await asyncio.gather(ta.punch(2), tb.punch(2))
            paths = await asyncio.gather(ta.start_quic(), tb.start_quic())
        else:
            paths = await asyncio.gather(ta.connect(), tb.connect())
        yield paths
    finally:
        await asyncio.gather(*(p.transfers.close() for p in peers))
        await asyncio.gather(*(p.close() for c in peers for p in c.paths))
        await asyncio.gather(ta.close(), tb.close())


async def wait_until(predicate):
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.01)


async def test_transfer_live_rates_elapsed_freeze_and_first_block_time(peers, tmp_path, monkeypatch):
    a, b = peers
    source = tmp_path / "one-block.bin"
    source.write_bytes(b"x" * 1024)
    async with connected(peers) as (pa, _):
        original = pa._send
        chunk = asyncio.Event()
        release = asyncio.Event()

        async def delay(body):
            if body["kind"] == "file_chunk":
                chunk.set()
                await release.wait()
            await original(body)

        monkeypatch.setattr(pa, "_send", delay)
        task = asyncio.create_task(a.transfers.send(pa, source))
        try:
            await asyncio.wait_for(chunk.wait(), 2)
            tid = next(iter(b.transfers.incoming))
            await asyncio.sleep(0.1)
            live = b.transfers.metrics(tid)
            assert live["elapsed_seconds"] >= 0.1 and live["average_mbps"] == 0
            assert b.transfers.records[tid]["started_at"]
            release.set()
            result = await asyncio.wait_for(task, 3)
            assert result["receiver_seconds"] >= 0.1
            assert result["mbps"] < 0.1
            before = b.transfers.metrics(tid)
            await asyncio.sleep(0.02)
            assert b.transfers.metrics(tid) == before
            assert a.transfers.records[tid]["mbps"] == b.transfers.records[tid]["mbps"]
            assert any("elapsed_seconds" in e["fields"] for e in b.log.query() if e["event"] == "file.progress")
        finally:
            release.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)


def test_transfer_rolling_speed_uses_confirmed_bytes_and_decays_when_stalled(peers, monkeypatch):
    a, _ = peers
    clock = [10.0]
    monkeypatch.setattr("p2plab.transfers.time.perf_counter", lambda: clock[0])
    tid = "0123456789abcdef"
    a.transfers.record(tid, state="sending", direction="send", attempt="speed", bytes=4_000_000, completed=0)
    clock[0] = 11
    a.transfers.progress(tid, 1_000_000)
    assert a.transfers.metrics(tid) == {"elapsed_seconds": 1, "average_mbps": 8, "current_mbps": 8}
    clock[0] = 14
    assert a.transfers.metrics(tid) == {"elapsed_seconds": 4, "average_mbps": 2, "current_mbps": 0}
    a.transfers.record(tid, state="failed", reason="TEST_CANCEL")
    clock[0] = 30
    assert a.transfers.metrics(tid)["elapsed_seconds"] == 4


def test_sparse_transfer_arrivals_show_a_rate_instead_of_zero(peers, monkeypatch):
    a, _ = peers
    clock = [10.0]
    monkeypatch.setattr("p2plab.transfers.time.perf_counter", lambda: clock[0])
    tid = "0123456789abcdef"
    a.transfers.record(tid, state="receiving", direction="receive", attempt="slow", bytes=1_000_000, completed=0)
    for tick, size in ((18.0, 61440), (33.0, 122880), (43.0, 184320)):
        clock[0] = tick
        a.transfers.progress(tid, size)
        assert a.transfers.metrics(tid)["current_mbps"] > 0
    clock[0] += 3
    assert a.transfers.metrics(tid)["current_mbps"] == 0


@pytest.mark.parametrize("method", ["tcp", "quic"])
async def test_slow_progress_below_byte_ack_threshold_keeps_transfer_alive(peers, tmp_path, monkeypatch, method):
    from p2plab.common import BENCH_CHUNK

    a, b = peers
    source = tmp_path / "slow.bin"
    source.write_bytes(os.urandom(BENCH_CHUNK * 5))
    monkeypatch.setattr("p2plab.transfers.FILE_WINDOW", BENCH_CHUNK * 2)
    monkeypatch.setattr("p2plab.transfers.IDLE_SECONDS", 0.15)
    monkeypatch.setattr("p2plab.transfers.FILE_ACK_SECONDS", 0.03, raising=False)
    async with connected(peers, method) as (pa, _):
        original = pa._send

        async def slow(body):
            if body["kind"] == "file_chunk":
                await asyncio.sleep(0.04)
            await original(body)

        monkeypatch.setattr(pa, "_send", slow)
        result = await asyncio.wait_for(a.transfers.send(pa, source), 3)
        assert result["sha256"] == hashlib.sha256(source.read_bytes()).hexdigest()
        assert b.transfers.records[result["id"]]["state"] == "completed"


async def test_file_ack_timeout_has_progress_and_transport_evidence(peers, tmp_path, monkeypatch):
    from p2plab.common import BENCH_CHUNK

    a, _ = peers
    source = tmp_path / "stalled.bin"
    source.write_bytes(bytes(BENCH_CHUNK * 5))
    monkeypatch.setattr("p2plab.transfers.FILE_WINDOW", BENCH_CHUNK * 2)
    monkeypatch.setattr("p2plab.transfers.IDLE_SECONDS", 0.1)
    async with connected(peers) as (pa, pb):
        original = pb._send

        async def no_ack(body):
            if body["kind"] != "file_ack":
                await original(body)

        monkeypatch.setattr(pb, "_send", no_ack)
        pa.transport_diagnostics = lambda: {"backend": "test", "cwnd_bytes": 12000}
        with pytest.raises(TimeoutError, match="FILE_ACK_TIMEOUT"):
            await a.transfers.send(pa, source)
        row = next(e for e in a.log.query() if e["event"] == "file.failed")
        assert row["fields"]["bytes_queued"] == BENCH_CHUNK * 2
        assert row["fields"]["bytes_confirmed"] == 0
        assert row["fields"]["transport"]["cwnd_bytes"] == 12000
        assert row["fields"]["exception"] == "TimeoutError"


@pytest.mark.parametrize("method", ["tcp", "quic", "webrtc"])
async def test_binary_duplex_file_and_chat_real_transports(peers, tmp_path, method, task_scheduling):
    a, b = peers
    content = b"PRIVATE_ATTACHMENT_PAYLOAD_" + os.urandom(FILE_WINDOW + 321)
    source = tmp_path / "test file.bin"
    source.write_bytes(content)
    displays = []
    a.chat_display = b.chat_display = lambda *args: displays.append(args)
    async with connected(peers, method) as (pa, pb):
        assert FILE_CAPABILITY in pa.remote_capabilities
        async with asyncio.timeout(40):
            left, right, chat, rtt = await asyncio.gather(
                a.command(f'/file "{source}"'),
                b.transfers.send(pb, source),
                a.chat("并发聊天正文"),
                pa.ping(),
            )
        for sender, receiver, result in ((a, b, left), (b, a, right)):
            item = receiver.transfers.records[result["id"]]
            assert Path(item["saved_path"]).read_bytes() == content
            assert result["sha256"] == hashlib.sha256(content).hexdigest()
            assert item["received_at"] == result["received_at"]
            assert item["mbps"] == result["mbps"] > 0
            assert sender.transfers.records[result["id"]]["state"] == "completed"
            assert not list(receiver.transfers.directory.glob("*.part"))
        assert rtt >= 0 and chat["mbps"] > 0
        received = next(entry for entry in displays if entry[1] == "并发聊天正文")
        assert received[2] == chat
        logs = str(a.log.query()) + str(b.log.query())
        assert "并发聊天正文" not in logs and "PRIVATE_ATTACHMENT_PAYLOAD_" not in logs
        assert not a.transfers.outgoing and not b.transfers.incoming


async def test_empty_images_same_names_no_overwrite_and_view(peers, tmp_path, monkeypatch):
    a, b = peers
    opened = []

    async def desktop(target):
        opened.append(target)

    monkeypatch.setattr(b, "open_desktop", desktop)
    image = tmp_path / "untrusted.desktop"
    image.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(32))
    empty = tmp_path / "empty"
    empty.touch()
    async with connected(peers) as (pa, _):
        first = await a.transfers.send(pa, image, image=True)
        second = await a.transfers.send(pa, image, image=True)
        blank = await a.transfers.send(pa, empty)
        one, two = (Path(b.transfers.records[r["id"]]["saved_path"]) for r in (first, second))
        assert one != two and one.suffix == two.suffix == ".png"
        assert one.read_bytes() == two.read_bytes() == image.read_bytes()
        assert Path(b.transfers.records[blank["id"]]["saved_path"]).read_bytes() == b""
        assert blank["bytes"] == 0 and blank["mbps"] == 0
        await b.command("/view " + first["id"])
        assert opened == [one]
        with pytest.raises(ValueError, match="IMAGE_NOT_RECEIVED"):
            await b.command("/view " + blank["id"])
        with pytest.raises(ValueError, match="IMAGE_FORMAT_UNSUPPORTED"):
            await a.transfers.send(pa, empty, image=True)
        pa.remote_capabilities.discard(FILE_CAPABILITY)
        with pytest.raises(ValueError, match="UNSUPPORTED"):
            await a.transfers.send(pa, image)


@pytest.mark.skipif(os.name == "nt", reason="Headless opener behavior is Unix-specific")
async def test_open_desktop_reports_headless_environment_without_spawn(peers, monkeypatch):
    a, _ = peers
    monkeypatch.setattr("p2plab.client.shutil.which", lambda _: "/usr/bin/xdg-open")
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    opened = await a.open_desktop(a.transfers.directory)
    assert opened is False
    event = next(row for row in a.log.query() if row["event"] == "file.open_unavailable")
    assert event["fields"]["launcher"] in ("open", "xdg-open")




@pytest.mark.parametrize("action", ["accept", "reject", "cancel", "disconnect"])
async def test_manual_receive_decisions_cleanup_and_chat_survives(peers, tmp_path, action):
    a, b = peers
    b.transfers.auto_accept = False
    source = tmp_path / "manual.txt"
    source.write_bytes(b"manual")
    async with connected(peers) as (pa, _):
        sending = asyncio.create_task(a.transfers.send(pa, source))
        await wait_until(lambda: b.transfers.incoming)
        tid = next(iter(b.transfers.incoming))
        if action == "accept":
            await b.command("/accept " + tid)
            assert (await sending)["bytes"] == 6
        elif action == "reject":
            await b.command("/reject " + tid)
            with pytest.raises(ConnectionError, match="FILE_REJECTED"):
                await sending
        elif action == "cancel":
            await a.command("/cancel " + tid)
            with pytest.raises(asyncio.CancelledError):
                await sending
            await wait_until(lambda: not b.transfers.incoming)
        else:
            await pa.close("TEST_DISCONNECT")
            with pytest.raises(ConnectionError):
                await asyncio.wait_for(sending, 3)
            await wait_until(lambda: not b.transfers.incoming)
        assert not a.transfers.outgoing and not b.transfers.incoming
        assert not list(b.transfers.directory.glob("*.part"))
        if action != "disconnect":
            assert (await a.chat("still working"))["mbps"] > 0


@pytest.mark.parametrize(
    "fault", ["checksum", "sequence", "oversize", "bad-name", "collision", "part-collision"]
)
async def test_malformed_transfer_isolated_and_existing_files_preserved(peers, fault):
    a, b = peers
    tid = "0123456789abcdef"
    async with connected(peers) as (pa, _):
        b.transfers.directory.mkdir(exist_ok=True)
        destination = b.transfers.directory / (tid + (".part" if fault == "part-collision" else "-file.txt"))
        if fault in ("collision", "part-collision"):
            destination.write_bytes(b"DO NOT OVERWRITE")
        await pa.send(
            {
                "kind": "file_offer",
                "id": tid,
                "name": None if fault == "bad-name" else "../../file.txt",
                "bytes": b.transfers.max_bytes + 1 if fault == "oversize" else 4,
                "media": "file",
            }
        )
        if fault not in ("oversize", "bad-name", "part-collision"):
            await wait_until(lambda: tid in b.transfers.incoming and b.transfers.incoming[tid]["stream"])
            await pa.send(
                {"kind": "file_chunk", "id": tid, "seq": 3 if fault == "sequence" else 0, "data": b"data"}
            )
            await pa.send(
                {
                    "kind": "file_end",
                    "id": tid,
                    "sha256": "bad" if fault == "checksum" else hashlib.sha256(b"data").hexdigest(),
                }
            )
        await a.chat("path is still usable")
        await wait_until(lambda: not b.transfers.incoming)
        if fault in ("collision", "part-collision"):
            assert destination.read_bytes() == b"DO NOT OVERWRITE"
        else:
            assert not destination.exists()
        if fault != "part-collision":
            assert not list(b.transfers.directory.glob("*.part"))
        assert pa.ready.is_set() and not pa.closed


async def test_cancel_serializes_with_active_disk_write(peers, tmp_path, monkeypatch):
    import p2plab.transfers as module

    a, b = peers
    source = tmp_path / "large"
    source.write_bytes(bytes(2 * 1024 * 1024))
    started, release = threading.Event(), threading.Event()
    original = module.open_partial

    class SlowFile:
        def __init__(self, wrapped):
            self.wrapped = wrapped

        def write(self, data):
            started.set()
            assert release.wait(5)
            assert not self.wrapped.closed
            return self.wrapped.write(data)

        def __getattr__(self, attr):
            return getattr(self.wrapped, attr)

    monkeypatch.setattr(module, "open_partial", lambda path: SlowFile(original(path)))
    async with connected(peers) as (pa, _):
        sending = asyncio.create_task(a.transfers.send(pa, source))
        await wait_until(started.is_set)
        tid = next(iter(b.transfers.incoming))
        cancel = asyncio.create_task(b.transfers.cancel(tid))
        await asyncio.sleep(0.02)
        assert not cancel.done()
        release.set()
        await cancel
        with pytest.raises(ConnectionError, match="CANCELLED"):
            await sending
        assert not list(b.transfers.directory.glob("*.part"))
        await a.chat("after cancellation")


@pytest.mark.parametrize("failure", ["no-space", "write", "fsync"])
async def test_filesystem_failures_report_and_leave_chat_usable(peers, tmp_path, monkeypatch, failure):
    import p2plab.transfers as module

    a, b = peers
    source = tmp_path / "disk-test"
    source.write_bytes(bytes(1024 * 1024))
    original = module.open_partial

    class BrokenWriter:
        def __init__(self, stream):
            self.stream = stream

        def write(self, data):
            raise OSError("TEST_DISK_FULL")

        def close(self):
            self.stream.close()
            raise OSError("TEST_FLUSH_FAILED")

        def __getattr__(self, attr):
            return getattr(self.stream, attr)

    if failure == "no-space":
        monkeypatch.setattr(module.shutil, "disk_usage", lambda path: SimpleNamespace(free=0))
    elif failure == "write":
        monkeypatch.setattr(module, "open_partial", lambda path: BrokenWriter(original(path)))
    else:

        def fail_sync(fd):
            raise OSError("TEST_FSYNC_FAILED")

        monkeypatch.setattr(module.os, "fsync", fail_sync)
    async with connected(peers) as (pa, _):
        with pytest.raises(ConnectionError):
            await asyncio.wait_for(a.transfers.send(pa, source), 5)
        assert not b.transfers.incoming and not list(b.transfers.directory.glob("*.part"))
        assert (await a.chat("filesystem error is isolated"))["mbps"] > 0
        assert any(r["event"] == "file.failed" for r in b.log.query())


async def test_send_concurrency_reservation_and_expiry(peers, tmp_path):
    a, b = peers
    source = tmp_path / "queue"
    source.write_bytes(b"queue")
    b.transfers.auto_accept = False
    async with connected(peers) as (pa, pb):
        first = asyncio.create_task(a.transfers.send(pa, source))
        second = asyncio.create_task(a.transfers.send(pa, source))
        await wait_until(lambda: len(b.transfers.incoming) == 2)
        with pytest.raises(ValueError, match="FILE_SEND_BUSY"):
            await a.transfers.send(pa, source)
        for item in b.transfers.incoming.values():
            item["progress"] -= 121
        await b.transfers.expire(pb)
        results = await asyncio.gather(first, second, return_exceptions=True)
        assert all(isinstance(result, ConnectionError) and "TIMEOUT" in str(result) for result in results)
        assert not a.transfers.outgoing and not b.transfers.incoming
        await a.chat("after expiry")


def test_nonregular_source_does_not_block(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    with pytest.raises(ValueError, match="FILE_NOT_REGULAR"):
        open_source(fifo, False)


def test_receipt_validation_rejects_boolean_and_nonfinite():
    good = receipt(1, 0.01)
    assert validate_receipt(good, 1) == good
    for field, value in (
        ("bytes", True),
        ("receiver_seconds", float("inf")),
        ("receiver_seconds", -1),
        ("received_at", "2026-10-13"),
    ):
        with pytest.raises(ValueError):
            validate_receipt({**good, field: value}, 1)


async def test_legacy_chat_metrics_are_not_fabricated(peers):
    a, b = peers
    async with connected(peers) as (pa, pb):
        pa.remote_capabilities.discard(RECEIPT_CAPABILITY)
        pb.remote_capabilities.discard(RECEIPT_CAPABILITY)
        assert await a.chat("legacy") is None
        assert list(b.chat_receipts.values())[-1]["mbps"] is None


async def test_attachment_binary_fragmentation_and_stream_read():
    chunk = {"kind": "file_chunk", "id": "0123456789abcdef", "seq": 3, "data": b"private\x00binary"}
    bench = {**chunk, "kind": "bench_chunk"}
    frame = encode_frame(chunk)
    buffer = bytearray(frame[:9])
    assert extract_frames(buffer) == []
    buffer.extend(frame[9:] + encode_frame(bench))
    assert extract_frames(buffer) == [chunk, bench]
    reader = asyncio.StreamReader()
    reader.feed_data(frame)
    assert await read_frame(reader) == chunk
    with pytest.raises(ValueError):
        extract_frames(bytearray(struct.pack("!I", BINARY_FLAGS | 12) + bytes(12)))
