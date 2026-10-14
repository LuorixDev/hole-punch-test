import asyncio
import sys
from types import SimpleNamespace

from p2plab.encrypted_stream import EncryptedStream
from tools.performance_lab import communicate_workers


async def test_benchmark_worker_failure_terminates_peer_and_returns_logs():
    failed = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import sys; print('worker failed'); sys.exit(2)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    waiting = await asyncio.create_subprocess_exec(
        sys.executable,
        "-c",
        "import time; print('waiting', flush=True); time.sleep(30)",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    outputs = await asyncio.wait_for(communicate_workers([failed, waiting]), 3)
    assert failed.returncode == 2
    assert waiting.returncode is not None
    assert b"worker failed" in outputs[0][0]
    assert b"waiting" in outputs[1][0]


async def test_native_tls_receive_queue_is_bounded_by_bytes_and_reports_overflow(monkeypatch):
    import p2plab.encrypted_stream as encrypted_stream

    monkeypatch.setattr(encrypted_stream, "NATIVE_RECEIVE_QUEUE_BYTES", 8)
    events, tasks = [], []

    async def close(reason):
        events.append(("closed", reason))

    stream = object.__new__(EncryptedStream)
    stream.closed = False
    stream.spec = {"attempt": "queue-test"}
    stream.queue = asyncio.Queue(maxsize=4)
    stream.queued_bytes = 0
    stream.owner = SimpleNamespace(
        log=SimpleNamespace(event=lambda *args, **kwargs: events.append((args, kwargs))),
        spawn=lambda coro, name: tasks.append(asyncio.create_task(coro)),
    )
    stream.path = SimpleNamespace(close=close)

    stream.feed(b"12345")
    stream.feed(b"6789")
    assert stream.queue.qsize() == 1
    assert stream.queued_bytes == 5
    assert events and events[0][0][0] == "native.receive_queue_overflow"
    await asyncio.gather(*tasks)
    assert events[-1] == ("closed", "NATIVE_RECEIVE_QUEUE_LIMIT")
