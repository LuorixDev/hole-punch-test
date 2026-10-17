from __future__ import annotations

import asyncio
import base64
import collections
import secrets
import time
import uuid

from .common import BENCH_CHUNK, MAX_TEXT, Identity
from .performance import BenchProbe
from .transfers import FILE_CAPABILITY, RECEIPT_CAPABILITY, receipt

BENCH_CAPABILITY = "bench-binary-v1"
TIMED_BENCH_CAPABILITY = "bench-timed-v1"
BENCH_STREAM_CAPABILITY = "bench-stream-v1"
REVERSE_CANCEL_CAPABILITY = "bench-reverse-cancel-v1"
PATH_LIFECYCLE_CAPABILITY = "cold-path-v1"
BENCH_WINDOW = 16 * 1024 * 1024
BENCH_ACK_BYTES = BENCH_CHUNK
BENCH_ACK_SECONDS = 1
BENCH_SAMPLE_SECONDS = 10
MAX_BENCH_BYTES = 1024 * 1024 * 1024
BENCH_TIMEOUT = 120


async def closed_send(body):
    raise ConnectionError("PATH_CLOSED")


async def closed_close():
    pass


class Path:
    """Mutually authenticated application session over a reliable encrypted transport."""

    def __init__(self, owner, attempt, mechanism, family, send, close):
        self.owner, self.attempt, self.mechanism, self.family = owner, attempt, mechanism, family
        self._send, self._close = send, close
        self.peer = dict(owner.peer)
        self.local_id, self.pair = owner.peer_id, owner.pair
        self.nonce = secrets.token_hex(16)
        self.ready = asyncio.Event()
        self.closed_event = asyncio.Event()
        self.received_hello = False
        self.acked = False
        self.closed = False
        self.last_rx = time.monotonic()
        self.last_tx = self.last_rx
        self.last_liveness = self.last_rx
        self.liveness_failures = 0
        self.last_rtt = None
        self.rtt_measured_at = None
        self.rtt_state = "not-measured"
        self.latest_speed = {}
        self.remote_capabilities = set()
        self.pings = {}
        self.benches = {}
        self.receive_benches = {}
        self.lock = asyncio.Lock()
        self.started = time.monotonic()
        self.handshake_task = None
        self.keepalive_task = None
        self.remote_nonce = None
        self.reverse_tests = {}
        self.reverse_workers = {}
        self.cancelled_benches = collections.OrderedDict()
        self.chat_starts = {}
        self.chat_ready = {}
        self.pool_managed = False
        self.parked = False
        self.source_attempt = attempt
        self.lifecycle_pins = 0
        self.ephemeral = False
        self.parking = False
        self.park_finished = asyncio.Event()
        self.park_finished.set()

    def proof(self, kind, **extra):
        return self.owner.identity.sign(
            {
                "v": 1,
                "kind": kind,
                "pair": self.pair,
                "attempt": self.attempt,
                "from": self.local_id,
                "to": self.peer["id"],
                "nonce": self.nonce,
                "capabilities": [BENCH_CAPABILITY, TIMED_BENCH_CAPABILITY, BENCH_STREAM_CAPABILITY,
                                 REVERSE_CANCEL_CAPABILITY, FILE_CAPABILITY, RECEIPT_CAPABILITY,
                                 PATH_LIFECYCLE_CAPABILITY],
                **extra,
            }
        )

    async def start(self):
        if self.handshake_task:
            return
        self.handshake_task = asyncio.create_task(self.handshake(), name=f"auth:{self.attempt}")

    async def wait_ready(self, timeout):
        ready = asyncio.create_task(self.ready.wait())
        closed = asyncio.create_task(self.closed_event.wait())
        try:
            done, _ = await asyncio.wait(
                (ready, closed), timeout=timeout, return_when=asyncio.FIRST_COMPLETED
            )
            if not done:
                raise TimeoutError("DATA_PATH_READY_TIMEOUT")
            if self.closed:
                raise ConnectionError("DATA_PATH_CLOSED_BEFORE_VERIFICATION")
        finally:
            ready.cancel()
            closed.cancel()
            await asyncio.gather(ready, closed, return_exceptions=True)

    async def handshake(self):
        try:
            deadline = time.monotonic() + 8
            while not self.ready.is_set() and not self.closed:
                if time.monotonic() >= deadline:
                    raise TimeoutError("APPLICATION_AUTH_TIMEOUT")
                await self.send(self.proof("hello"), authenticated=False)
                try:
                    await asyncio.wait_for(self.ready.wait(), 0.4)
                except TimeoutError:
                    continue
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("path.auth_failed", exc, attempt=self.attempt)
            await self.close("AUTH_FAILED")

    async def send(self, body, *, authenticated=True):
        if self.closed or (authenticated and not self.ready.is_set()):
            raise ConnectionError("PATH_NOT_AUTHENTICATED")
        async with self.lock:
            async with asyncio.timeout(5):
                await self._send(body)
                self.last_tx = time.monotonic()

    async def receive(self, body):
        if self.closed:
            return
        kind = body.get("kind")
        if not isinstance(kind, str):
            raise ValueError("FRAME_KIND_INVALID")
        if kind in ("hello", "hello_ack"):
            frame = Identity.verify(body, self.peer["public"])
            if any(
                frame.get(k) != v
                for k, v in (
                    ("pair", self.pair),
                    ("attempt", self.attempt),
                    ("from", self.peer["id"]),
                    ("to", self.local_id),
                    ("v", 1),
                )
            ):
                raise ValueError("APPLICATION_AUTH_CONTEXT_MISMATCH")
            nonce = frame.get("nonce")
            if not isinstance(nonce, str) or len(nonce) != 32:
                raise ValueError("APPLICATION_NONCE_FORMAT")
            if self.remote_nonce is not None and nonce != self.remote_nonce:
                raise ValueError("APPLICATION_NONCE_CHANGED")
            self.remote_nonce = nonce
            capabilities = frame.get("capabilities", [])
            if (
                not isinstance(capabilities, list)
                or len(capabilities) > 16
                or not all(isinstance(c, str) and len(c) <= 64 for c in capabilities)
            ):
                raise ValueError("APPLICATION_CAPABILITIES_FORMAT")
            self.remote_capabilities = set(capabilities)
            if kind == "hello":
                self.received_hello = True
                await self.send(self.proof("hello_ack", echo=nonce), authenticated=False)
            elif frame.get("echo") == self.nonce:
                self.acked = True
            else:
                raise ValueError("APPLICATION_CHALLENGE_MISMATCH")
            if self.received_hello and self.acked and not self.ready.is_set():
                self.ready.set()
                self.owner.path_opened(self)
        elif not self.ready.is_set():
            raise ValueError("DATA_BEFORE_AUTHENTICATION")
        elif kind.startswith("file_"):
            if FILE_CAPABILITY not in self.remote_capabilities:
                raise ValueError("FILE_FORMAT_NOT_NEGOTIATED")
            await self.owner.transfers.handle(self, body)
        elif kind == "chat_start":
            if RECEIPT_CAPABILITY not in self.remote_capabilities:
                raise ValueError("CHAT_RECEIPT_NOT_NEGOTIATED")
            mid, size = body.get("id"), body.get("bytes")
            uuid.UUID(mid)
            if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_TEXT:
                raise ValueError("CHAT_LIMIT")
            if len(self.chat_starts) >= 128 and mid not in self.chat_starts:
                raise ValueError("CHAT_RECEIPT_LIMIT")
            self.chat_starts[mid] = (time.perf_counter(), size)
            await self.send({"kind": "chat_ready", "id": mid})
        elif kind == "chat_ready":
            pending = self.chat_ready.get(body.get("id"))
            if pending and not pending.done():
                pending.set_result(True)
        elif kind == "chat":
            text, mid = body["text"], body["id"]
            if not isinstance(text, str) or len(text.encode()) > MAX_TEXT:
                raise ValueError("CHAT_LIMIT")
            uuid.UUID(mid)
            start = self.chat_starts.pop(mid, None)
            size = len(text.encode())
            if start and size != start[1]:
                raise ValueError("CHAT_RECEIPT_SIZE_MISMATCH")
            metrics = receipt(size, time.perf_counter() - start[0] if start else None)
            if self.owner.remember_chat(mid):
                self.owner.chat_receipts[mid] = metrics
                while len(self.owner.chat_receipts) > 10000:
                    self.owner.chat_receipts.popitem(last=False)
                self.owner.display_chat(self.peer["name"], text, metrics)
                self.owner.log.event(
                    "chat.received",
                    peer=self.peer["id"],
                    attempt=self.attempt,
                    message_id=mid,
                    **metrics,
                )
            metrics = self.owner.chat_receipts.get(mid, metrics)
            await self.send({"kind": "chat_ack", "id": mid, **metrics})
        elif kind == "chat_ack":
            pending = self.owner.chat_acks.get(body.get("id"))
            if pending and not pending.done():
                pending.set_result(body)
        elif kind == "ping":
            await self.send({"kind": "pong", "id": body["id"]})
        elif kind == "pong":
            entry = self.pings.pop(body.get("id"), None)
            if entry:
                started, future, measure = entry
                rtt = (time.perf_counter() - started) * 1000
                if measure:
                    self.last_rtt = rtt
                    self.rtt_measured_at = time.monotonic()
                    self.rtt_state = "measured"
                if not future.done():
                    future.set_result(rtt)
        elif kind == "bench_cancel":
            if BENCH_CAPABILITY not in self.remote_capabilities:
                raise ValueError("BENCH_FORMAT_NOT_NEGOTIATED")
            cancelled = self.receive_benches.pop(body.get("id"), None)
            if cancelled:
                cancelled["probe"].cancel()
            bid = body.get("id")
            if not isinstance(bid, str) or len(bid) != 16 or any(c not in "0123456789abcdef" for c in bid):
                raise ValueError("BENCH_ID_FORMAT")
            self.remember_cancelled_bench(bid)
        elif kind == "bench_start":
            size = body["bytes"]
            binary = body.get("format") == "binary-v1"
            if body.get("format") not in (None, "binary-v1") or (
                binary and BENCH_CAPABILITY not in self.remote_capabilities
            ):
                raise ValueError("BENCH_FORMAT_NOT_NEGOTIATED")
            maximum = MAX_BENCH_BYTES if binary else 64 * 1024 * 1024
            if isinstance(size, bool) or not isinstance(size, int) or not 1024 <= size <= maximum:
                raise ValueError("BENCH_SIZE_LIMIT")
            if not isinstance(body["id"], str) or len(body["id"]) != 16:
                raise ValueError("BENCH_ID_FORMAT")
            try:
                if bytes.fromhex(body["id"]).hex() != body["id"]:
                    raise ValueError("BENCH_ID_FORMAT")
            except ValueError as exc:
                raise ValueError("BENCH_ID_FORMAT") from exc
            if body["id"] in self.receive_benches:
                raise ValueError("BENCH_DUPLICATE_ID")
            if body["id"] in self.cancelled_benches:
                return
            if len(self.receive_benches) >= 2:
                raise ValueError("BENCH_CONCURRENCY_LIMIT")
            timed = body.get("timed", False)
            if type(timed) is not bool or (timed and TIMED_BENCH_CAPABILITY not in self.remote_capabilities):
                raise ValueError("TIMED_BENCH_NOT_NEGOTIATED")
            wan_lock = getattr(self.owner, "wan_lock", None)
            if wan_lock and wan_lock.locked():
                await self.send({"kind": "bench_error", "id": body["id"], "reason": "PEER_WAN_TEST_RUNNING"})
                self.owner.log.event("speed.deferred_by_wan", attempt=self.attempt)
                return
            self.receive_benches[body["id"]] = {
                "bytes": 0,
                "expected": size,
                "seq": 0,
                "start": time.perf_counter(),
                "progress": time.monotonic(),
                "binary": binary,
                "next_ack": BENCH_ACK_BYTES,
                "last_ack": time.monotonic(),
                "timed": timed,
                "probe": BenchProbe(self),
            }
            await self.send({"kind": "bench_ready", "id": body["id"]})
        elif kind in ("bench_ready", "bench_ack", "bench_result", "bench_error"):
            bench = self.benches.get(body.get("id"))
            if bench:
                if bench.full():
                    while not bench.empty():
                        bench.get_nowait()
                    body = {"kind": "bench_error", "reason": "BENCH_REPLY_QUEUE_LIMIT"}
                bench.put_nowait(body)
        elif kind == "bench_chunk":
            bench = self.receive_benches.get(body.get("id"))
            if not bench and body.get("id") in self.cancelled_benches:
                return
            if (
                not bench
                or isinstance(body.get("seq"), bool)
                or not isinstance(body.get("seq"), int)
                or body["seq"] != bench["seq"]
            ):
                raise ValueError("BENCH_SEQUENCE_MISMATCH")
            if bench["binary"]:
                if not isinstance(body["data"], bytes):
                    raise ValueError("BENCH_BINARY_REQUIRED")
                raw = body["data"]
            else:
                raw = base64.b64decode(body["data"], validate=True)
            if (
                not raw
                or len(raw) > (BENCH_CHUNK if bench["binary"] else 8192)
                or bench["bytes"] + len(raw) > bench["expected"]
            ):
                raise ValueError("BENCH_CHUNK_LIMIT")
            bench["bytes"] += len(raw)
            bench["seq"] += 1
            bench["progress"] = time.monotonic()
            ack_due = bench["bytes"] >= bench["next_ack"] if bench["binary"] else bench["seq"] % 16 == 0
            if (bench["timed"] or ack_due or bench["bytes"] == bench["expected"]
                    or time.monotonic() - bench["last_ack"] >= BENCH_ACK_SECONDS):
                await self.send({"kind": "bench_ack", "id": body["id"], "bytes": bench["bytes"]})
                bench["last_ack"] = time.monotonic()
                while bench["next_ack"] <= bench["bytes"]:
                    bench["next_ack"] += BENCH_ACK_BYTES
        elif kind == "bench_end":
            bench = self.receive_benches.pop(body.get("id"), None)
            if not bench and body.get("id") in self.cancelled_benches:
                return
            if bench:
                runtime = bench["probe"].finish()
            expected = body.get("bytes") if bench and bench["timed"] else bench["expected"] if bench else None
            if (not bench or type(expected) is not int or not 0 < expected <= bench["expected"]
                    or bench["bytes"] != expected):
                raise ValueError("BENCH_INCOMPLETE")
            duration = max(time.perf_counter() - bench["start"], 1e-9)
            result = {
                "kind": "bench_result",
                "id": body["id"],
                "bytes": bench["bytes"],
                "receiver_seconds": duration,
                "receiver_runtime": runtime,
            }
            await self.send(result)
            self.owner.log.event(
                "speed.received",
                attempt=self.attempt,
                bytes=bench["bytes"],
                seconds=duration,
                mbps=bench["bytes"] * 8 / max(duration, 1e-6) / 1e6,
                receiver_runtime=result["receiver_runtime"],
            )
        elif kind == "reverse_speed":
            size = body.get("bytes")
            if isinstance(size, bool) or not isinstance(size, int) or not 1024 <= size <= MAX_BENCH_BYTES:
                raise ValueError("REVERSE_BENCH_SIZE_LIMIT")
            rid = body.get("id")
            if not isinstance(rid, str) or len(rid) != 16 or any(c not in "0123456789abcdef" for c in rid):
                raise ValueError("REVERSE_BENCH_ID_FORMAT")
            if rid in self.reverse_workers or self.reverse_workers or self.owner.speed_lock.locked():
                await self.send({"kind": "reverse_speed_result", "id": rid, "error": "PEER_BENCH_BUSY"})
                return
            task = self.owner.spawn(self.answer_reverse_speed(rid, size), "reverse-speed")
            self.reverse_workers[rid] = task
            task.add_done_callback(lambda completed: self.reverse_workers.pop(rid, None))
        elif kind == "reverse_speed_cancel":
            task = self.reverse_workers.get(body.get("id"))
            if task:
                task.cancel()
        elif kind == "reverse_speed_result":
            future = self.reverse_tests.get(body.get("id"))
            if future and not future.done():
                future.set_result(body)
        else:
            raise ValueError("UNKNOWN_DATA_FRAME")
        self.last_rx = time.monotonic()

    async def begin_chat(self, mid, size):
        future = asyncio.get_running_loop().create_future()
        self.chat_ready[mid] = future
        try:
            await self.send({"kind": "chat_start", "id": mid, "bytes": size})
            await asyncio.wait_for(future, 5)
        finally:
            self.chat_ready.pop(mid, None)

    async def ping(self, timeout=5, *, measure=True):
        pid = secrets.token_hex(8)
        future = asyncio.get_running_loop().create_future()
        self.pings[pid] = (time.perf_counter(), future, measure)
        try:
            await self.send({"kind": "ping", "id": pid})
            return await asyncio.wait_for(future, timeout)
        except TimeoutError:
            if measure:
                self.rtt_state = "timeout"
            raise
        finally:
            self.pings.pop(pid, None)

    async def speed(self, size):
        try:
            async with asyncio.timeout(BENCH_TIMEOUT):
                return await self._speed(size)
        except TimeoutError as exc:
            raise TimeoutError(str(exc) or "BENCH_TOTAL_TIMEOUT") from exc

    async def _speed(self, size):
        binary = BENCH_CAPABILITY in self.remote_capabilities
        timed = binary and TIMED_BENCH_CAPABILITY in self.remote_capabilities
        maximum = MAX_BENCH_BYTES if binary else 64 * 1024 * 1024
        if isinstance(size, bool) or not isinstance(size, int) or not 1024 <= size <= maximum:
            raise ValueError("BENCH_SIZE_LIMIT_OR_LEGACY_PEER")
        if len(self.benches) >= 2:
            raise ValueError("BENCH_CONCURRENCY_LIMIT")
        bid = secrets.token_hex(8)
        queue = asyncio.Queue(maxsize=128)
        self.benches[bid] = queue
        chunk = BENCH_CHUNK if binary else 8192
        window = BENCH_WINDOW if binary else 16 * chunk
        current_window = min(window, 2 * chunk) if timed else window
        peak_window = current_window
        sent, seq, acknowledged = 0, 0, 0
        phase = "ready"
        # Encrypted transports do not compress. Prepare a random block before timing, then reuse it.
        payload = secrets.token_bytes(chunk * 16)
        started = time.monotonic()
        cpu_started = time.process_time()
        probe = None
        try:
            await self.send(
                {
                    "kind": "bench_start",
                    "id": bid,
                    "bytes": size,
                    **({"format": "binary-v1"} if binary else {}),
                    **({"timed": True} if timed else {}),
                }
            )
            ready = await asyncio.wait_for(queue.get(), 10)
            if ready.get("kind") == "bench_error":
                raise ConnectionError(ready.get("reason", "BENCH_PATH_CLOSED"))
            if ready.get("kind") != "bench_ready":
                raise ValueError("BENCH_READY_REQUIRED")
            def acknowledge(ack):
                nonlocal acknowledged, current_window, peak_window
                if ack.get("kind") == "bench_error":
                    raise ConnectionError(ack.get("reason", "BENCH_PATH_CLOSED"))
                count = ack.get("bytes")
                if (
                    ack.get("kind") != "bench_ack"
                    or isinstance(count, bool)
                    or not isinstance(count, int)
                    or not acknowledged < count <= sent
                ):
                    raise ValueError("BENCH_ACK_MISMATCH")
                acknowledged = count
                if timed:
                    rate = acknowledged / max(time.perf_counter() - started, 1e-6)
                    target_seconds = max(0.25, min(1.0, (self.last_rtt or 50) / 1000 * 4))
                    current_window = min(window, max(chunk, int(rate * target_seconds)))
                    peak_window = max(peak_window, current_window)

            started, cpu_started = time.perf_counter(), time.process_time()
            probe = BenchProbe(self)
            while sent < size:
                phase = "send"
                if timed and sent and time.perf_counter() - started >= BENCH_SAMPLE_SECONDS:
                    break
                while not queue.empty():
                    acknowledge(queue.get_nowait())
                if sent - acknowledged >= current_window:
                    phase = "progress"
                    acknowledge(await asyncio.wait_for(queue.get(), 20))
                    continue
                raw = payload[
                    (seq % 16) * chunk : (seq % 16) * chunk
                    + min(chunk, size - sent, current_window - (sent - acknowledged))
                ]
                await self.send(
                    {
                        "kind": "bench_chunk",
                        "id": bid,
                        "seq": seq,
                        "data": raw if binary else base64.b64encode(raw).decode(),
                    }
                )
                sent += len(raw)
                seq += 1
                if time.perf_counter() - started > 120:
                    raise TimeoutError("BENCH_HARD_DEADLINE")
            phase = "drain"
            while acknowledged < sent:
                acknowledge(await asyncio.wait_for(queue.get(), 20))
            await self.send({"kind": "bench_end", "id": bid, **({"bytes": sent} if timed else {})})
            phase = "result"
            result = await asyncio.wait_for(queue.get(), 20)
            if result.get("kind") == "bench_error":
                raise ConnectionError(result.get("reason", "BENCH_PATH_CLOSED"))
            if result["kind"] != "bench_result" or result.get("bytes") != acknowledged:
                raise ValueError("BENCH_RESULT_MISMATCH")
            seconds = result.get("receiver_seconds")
            if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 < seconds < float("inf"):
                raise ValueError("BENCH_RECEIVER_DURATION_INVALID")
            duration = max(time.perf_counter() - started, 1e-9)
            return {
                "bytes": acknowledged,
                "seconds": duration,
                "mbps": acknowledged * 8 / duration / 1e6,
                "receiver_seconds": result["receiver_seconds"],
                "format": "binary-v1" if binary else "legacy-json-base64",
                "chunk_bytes": chunk,
                "window_bytes": window,
                "window_peak_bytes": peak_window,
                "window_mode": "delivery-rate" if timed else "fixed",
                "requested_bytes": size,
                "sample_limited": "duration" if acknowledged < size else "bytes",
                "target_seconds": BENCH_SAMPLE_SECONDS if timed else None,
                "sender_cpu_seconds": time.process_time() - cpu_started,
                "sender_runtime": probe.finish(),
                "receiver_runtime": result.get("receiver_runtime"),
                "short_sample": duration < 1,
            }
        except BaseException as failure:
            abort = getattr(self, "abort_benchmark", None)
            if abort:
                try:
                    abort(bid)
                except Exception as exc:
                    self.owner.log.exception("speed.reset_cleanup_failed", exc, attempt=self.attempt)
            self.owner.log.event("speed.failed", str(failure) or type(failure).__name__, "WARNING",
                                 attempt=self.attempt, benchmark=bid, phase=phase, bytes_sent=sent,
                                 bytes_confirmed=acknowledged, requested_bytes=size,
                                 exception=type(failure).__name__)
            if binary and not self.closed:
                try:
                    async with asyncio.timeout(1):
                        await self.send({"kind": "bench_cancel", "id": bid})
                except (Exception, asyncio.CancelledError) as exc:
                    self.owner.log.event(
                        "speed.cancel_cleanup_failed", str(exc), "WARNING", attempt=self.attempt
                    )
            if isinstance(failure, TimeoutError):
                raise TimeoutError("BENCH_" + phase.upper() + "_TIMEOUT") from failure
            raise
        finally:
            if probe:
                probe.cancel()
            self.benches.pop(bid, None)
            finish = getattr(self, "finish_benchmark", None)
            if finish:
                finish(bid)

    async def reverse_speed(self, size):
        rid = secrets.token_hex(8)
        future = asyncio.get_running_loop().create_future()
        self.reverse_tests[rid] = future
        try:
            await self.send({"kind": "reverse_speed", "id": rid, "bytes": size})
            result = await asyncio.wait_for(future, BENCH_TIMEOUT + 10)
            if "error" in result:
                raise ValueError(result["error"])
            return result["result"]
        except BaseException:
            if REVERSE_CANCEL_CAPABILITY in self.remote_capabilities and not self.closed:
                try:
                    async with asyncio.timeout(1):
                        await self.send({"kind": "reverse_speed_cancel", "id": rid})
                except (Exception, asyncio.CancelledError) as exc:
                    self.owner.log.event("speed.cancel_cleanup_failed", str(exc), "WARNING", attempt=self.attempt)
            raise
        finally:
            self.reverse_tests.pop(rid, None)

    async def answer_reverse_speed(self, rid, size):
        if self.owner.experiment_matrix_running():
            await self.send({"kind": "reverse_speed_result", "id": rid,
                             "error": "PEER_EXPERIMENT_MATRIX_BUSY"})
            self.owner.log.event("speed.reverse_rejected", "Peer matrix is still running",
                                 "WARNING", attempt=self.attempt, reason="EXPERIMENT_MATRIX_RUNNING")
            return
        if self.owner.speed_lock.locked():
            await self.send({"kind": "reverse_speed_result", "id": rid, "error": "PEER_BENCH_BUSY"})
            return
        try:
            async with self.owner.speed_lock:
                result = await asyncio.wait_for(self.speed(size), 125)
                self.owner.log.event("speed.reverse_sender", attempt=self.attempt, **result)
                await self.send({"kind": "reverse_speed_result", "id": rid, "result": result})
        except Exception as exc:
            self.owner.log.exception("speed.reverse_failed", exc, attempt=self.attempt)
            if not self.closed:
                await self.send({"kind": "reverse_speed_result", "id": rid, "error": type(exc).__name__})

    def remember_cancelled_bench(self, bid):
        self.cancelled_benches[bid] = time.monotonic()
        while len(self.cancelled_benches) > 32:
            self.cancelled_benches.popitem(last=False)

    async def expire(self, now):
        for bid, bench in tuple(self.receive_benches.items()):
            if now - bench["progress"] > 20 or now - bench["start"] > 120:
                self.receive_benches.pop(bid)
                bench["probe"].cancel()
                self.remember_cancelled_bench(bid)
                self.owner.log.event("speed.expired", attempt=self.attempt, benchmark=bid)
                try:
                    await self.send({"kind": "bench_error", "id": bid, "reason": "BENCH_RECEIVE_TIMEOUT"})
                except (ConnectionError, TimeoutError, OSError) as exc:
                    self.owner.log.event("speed.expiry_notify_failed", str(exc), "WARNING", attempt=self.attempt)
        # Slow legacy streams can deliver queued bytes minutes after cancellation.
        # Keep the bounded ID history until replacement or connection close.
        for mid, (started, _) in tuple(self.chat_starts.items()):
            if now - started > 30:
                self.chat_starts.pop(mid, None)
        await self.owner.transfers.expire(self)

    async def close(self, reason="CLOSED"):
        if self.closed:
            return
        self.closed = True
        self.closed_event.set()
        for task in tuple(self.reverse_workers.values()):
            if task is not asyncio.current_task():
                task.cancel()
        for task in (self.handshake_task, self.keepalive_task):
            if task and task is not asyncio.current_task():
                task.cancel()
        for _, future, _ in self.pings.values():
            if not future.done():
                future.set_exception(ConnectionError(reason))
        self.pings.clear()
        for future in self.reverse_tests.values():
            if not future.done():
                future.set_exception(ConnectionError(reason))
        self.reverse_tests.clear()
        for future in self.chat_ready.values():
            if not future.done():
                future.set_exception(ConnectionError(reason))
        self.chat_starts.clear()
        await self.owner.transfers.path_closed(self, reason)
        for queue in self.benches.values():
            if not queue.full():
                queue.put_nowait({"kind": "bench_error", "reason": reason})
        for bench in self.receive_benches.values():
            bench["probe"].cancel()
        self.receive_benches.clear()
        self.cancelled_benches.clear()
        await self._close()
        await self.owner.release_path_resources(self)
        # History must not keep closed transports and their stream buffers alive.
        self._send, self._close = closed_send, closed_close
        self.owner.log.event("path.closed", attempt=self.attempt, reason=reason)
        maintenance = getattr(self.owner, "path_maintenance_task", None)
        if maintenance and maintenance is not asyncio.current_task() and not any(
            not p.closed for p in self.owner.paths
        ):
            maintenance.cancel()
        if self.ready.is_set() and reason in ("KEEPALIVE_FAILED", "TCP_IO_FAILED", "QUIC_TERMINATED", "LIBNICE_ICE_FAILED"):
            if not any(path.ready.is_set() and not path.closed for path in self.owner.paths) and not any(
                self.owner.can_reopen(path) for path in self.owner.paths
            ):
                self.owner.request_auto_retry("ALL_VERIFIED_PATHS_LOST")


class Dedup:
    def __init__(self):
        self.seen = collections.OrderedDict()

    def remember(self, mid):
        now = time.monotonic()
        while self.seen and (next(iter(self.seen.values())) < now - 600 or len(self.seen) >= 10000):
            self.seen.popitem(last=False)
        if mid in self.seen:
            return False
        self.seen[mid] = now
        return True
