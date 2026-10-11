"""In-process use of :mod:`p2pchat.native` for one peer pair and one method.

``NativeAdapter`` is imported and driven directly here — there is no stdio
bridge, no JSON-lines subprocess and no Node/Electron layer. The framed message
protocol implemented on top of the adapter's isolated ``chat`` lane mirrors the
data-channel semantics that :mod:`p2pchat.peer` already provides for WebRTC:
bounded text, bounded files with SHA-256 verification, authenticated ping/pong
latency and an explicitly isolated benchmark lane.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
import uuid

from p2pchat.native.adapter import MAX_FRAME, NativeAdapter

MAX_TEXT_BYTES = 16384
MAX_FILE_BYTES = 32 * 1024 * 1024
CHUNK_BYTES = 24576
MAX_ACTIVE_RECEIVES = 4
MAX_RESERVED_BYTES = 64 * 1024 * 1024
TERMINAL_STATES = {"closed", "failed", "timeout", "unsupported"}
HEX64 = re.compile("[0-9a-f]{64}")


def encode(frame: dict) -> bytes:
    return json.dumps(frame, ensure_ascii=False, separators=(",", ":")).encode()


class NativeSession:
    """One method, one peer. Owns exactly one adapter attempt."""

    def __init__(
        self,
        adapter: NativeAdapter,
        *,
        mechanism: str,
        room: str,
        secret: str,
        local_id: str,
        peer_id: str,
        connection_id: str,
        attempt_id: str,
        role: str,
        on_event,
        timeout_ms: int = 15000,
    ):
        self.adapter = adapter
        self.mechanism = mechanism
        self.room = room
        self.secret = secret
        self.local_id = local_id
        self.peer_id = peer_id
        self.connection = connection_id
        self.id = attempt_id
        self.role = role
        self.timeout_ms = timeout_ms
        self._on_event = on_event
        self.state = "pending"
        self.failure = None
        self.rtt: float | None = None
        self.tx = 0
        self.rx = 0
        self.capable = mechanism != "udp-probe"
        self.started = False
        self.last_receive = 0.0
        self.files: dict[str, dict] = {}
        self.reserved = 0
        self._pings: dict[str, float] = {}
        self._seen: dict[tuple, float] = {}
        self._bench: dict | None = None
        self.bench_role: str | None = None
        self._unsubscribe = None
        self._handshake: list[dict] = []
        self._handshake_open = True

    # ---------------------------------------------------------------- signaling
    def _params(self) -> dict:
        return {
            "connectionId": self.connection,
            "attemptId": self.id,
            "peerId": self.peer_id,
            "mechanism": self.mechanism,
            "profile": self.mechanism,
            "role": self.role,
            "timeoutMs": self.timeout_ms,
            "auth": {"room": self.room, "secret": self.secret, "localPeerId": self.local_id},
        }

    async def start(self) -> None:
        if self.started:
            return
        self._unsubscribe = self.adapter.subscribe(self._dispatch)
        self.started = True
        try:
            await self.adapter.start(self._params())
        except Exception as error:
            self.failure = getattr(error, "args", ["START_FAILED"])[0] or "START_FAILED"
            self.state = "failed"
            raise

    async def signal(self, frame: dict) -> None:
        # The adapter requires the authenticated sender id on every frame; the
        # envelope is built from the engine's signaling session, which is not
        # this session's id.
        await self.adapter.signal({**frame, "attemptId": self.id, "from": frame.get("from", self.peer_id)})

    async def prediction_signal(self, frame: dict) -> None:
        """Peer's HMAC-protected nat-samples frame for this attempt."""
        await self.adapter.prediction_signal({**frame, "attemptId": self.id, "from": frame.get("from", self.peer_id)})

    def envelope(self, **extra) -> dict:
        return {
            "mechanism": self.mechanism,
            "profile": self.mechanism,
            "connectionId": self.connection,
            "attemptId": self.id,
            **extra,
        }

    # ------------------------------------------------------------------- events
    def take_handshake(self) -> list[dict]:
        """Frames the peer must receive for this attempt; forwarded exactly once."""
        self._handshake_open = False
        frames = self._handshake
        self._handshake = []
        return frames

    def _dispatch(self, event: str, params: dict) -> None:
        if params.get("attemptId") != self.id:
            return
        if event == "state":
            self._on_state(params)
        elif event == "candidate":
            payload = {}
            if "description" in params:
                payload["description"] = params["description"]
            if "nativeCandidate" in params:
                payload["nativeCandidate"] = params["nativeCandidate"]
            if self._handshake_open:
                if len(self._handshake) < 8:
                    self._handshake.append(payload)
            else:
                self._on_event("peer-candidate", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "frames": [payload]})
        elif event == "data":
            lane = params.get("lane")
            try:
                payload = base64.b64decode(params.get("dataB64", ""), validate=True)
            except Exception:
                return
            self.last_receive = time.monotonic()
            self.rx += len(payload)
            task = asyncio.create_task(self._receive(lane, payload))
            task.add_done_callback(lambda t: t.exception())
        elif event == "diagnostic":
            self._on_event("diagnostic", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "code": params.get("code")})
        elif event == "prediction.state":
            # Honest state passthrough: no rate is ever derived from a prediction.
            self._on_event("prediction.state", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, **{k: v for k, v in params.items() if k in {"state", "reason", "hit", "localSymmetric", "peerSamples", "candidates", "sends"}}})
        elif event == "prediction.samples":
            message = params.get("message")
            if isinstance(message, dict):
                self._on_event("prediction.samples", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "message": message})
        elif event == "prediction.hit":
            self._on_event("prediction.hit", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "note": params.get("note")})

    def _on_state(self, params: dict) -> None:
        state = params.get("state")
        if state == "direct":
            self.state = "direct"
            self.last_receive = time.monotonic()
            if not self.capable:
                # METHODS-PLAIN.md: UDP 探测 only proves reachability.
                self.failure = "PROBE_ONLY"
        elif state in TERMINAL_STATES:
            self.state = "unsupported" if state == "unsupported" else "unavailable"
            self.failure = params.get("failureCode") or ("UNSUPPORTED_METHOD" if state == "unsupported" else "TIMEOUT")
        elif state in {"gathering", "probing", "authenticating"}:
            self.state = "trying"
        if params.get("rttMs") is not None:
            self.rtt = params["rttMs"]
        if params.get("txBytes") is not None:
            self.tx = params["txBytes"]
        if params.get("rxBytes") is not None:
            self.rx = params["rxBytes"]
        self._on_event("state", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "profile": self.mechanism, "state": self.state, "failureCode": self.failure, "rttMs": self.rtt, "direct": self.state == "direct", "canMessage": self.capable and self.state == "direct", "probeOnly": not self.capable})

    async def refresh_stats(self) -> dict:
        try:
            stats = await self.adapter.stats({"attemptId": self.id})
        except Exception:
            return {}
        if stats.get("rttMs") is not None:
            self.rtt = stats["rttMs"]
        self.tx, self.rx = stats.get("txBytes", self.tx), stats.get("rxBytes", self.rx)
        return stats

    # ------------------------------------------------------------------ sending
    async def _send_frame(self, frame: dict, lane: str = "chat") -> None:
        if not self.capable:
            raise RuntimeError("NOT_MESSAGE_CAPABLE")
        if self.state != "direct":
            raise RuntimeError("NO_DIRECT_PATH")
        try:
            await self.adapter.send({"attemptId": self.id, "lane": lane, "data": encode(frame)})
        except ValueError as error:
            code = str(error.args[0]) if error.args else "SEND_FAILED"
            if code == "BACKPRESSURE":
                await asyncio.sleep(0.05)
                await self.adapter.send({"attemptId": self.id, "lane": lane, "data": encode(frame)})
                return
            raise

    async def send_text(self, message_id: str, text: str) -> None:
        payload = text.encode()
        if len(payload) > MAX_TEXT_BYTES:
            raise ValueError("TEXT_LIMIT")
        await self._send_frame({"v": 1, "kind": "text", "id": message_id, "text": text})
        self.tx += len(payload)

    async def send_file(self, data: bytes, name: str, mime: str) -> str:
        if len(data) > MAX_FILE_BYTES:
            raise ValueError("FILE_TOO_LARGE")
        file_id = str(uuid.uuid4())
        digest = hashlib.sha256(data).hexdigest()
        await self._send_frame(
            {"v": 1, "kind": "file-start", "id": file_id, "name": name[:255], "mime": mime[:128], "size": len(data), "sha256": digest}
        )
        started = time.perf_counter_ns()
        for offset in range(0, len(data), CHUNK_BYTES):
            await self._send_frame(
                {"v": 1, "kind": "file-chunk", "id": file_id, "seq": offset // CHUNK_BYTES, "dataB64": base64.b64encode(data[offset : offset + CHUNK_BYTES]).decode()}
            )
        await self._send_frame({"v": 1, "kind": "file-end", "id": file_id})
        elapsed_ns = time.perf_counter_ns() - started
        self._on_event(
            "transfer.sent",
            {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "id": file_id, "bytes": len(data), "sha256": digest, "elapsedMs": None if elapsed_ns <= 0 else elapsed_ns / 1e6, "integrityOk": True},
        )
        return file_id

    async def ping(self) -> float | None:
        nonce = uuid.uuid4().hex
        self._pings[nonce] = time.monotonic()
        await self._send_frame({"v": 1, "kind": "ping", "nonce": nonce})
        async with asyncio.timeout(5):
            while nonce in self._pings:
                await asyncio.sleep(0.02)
        return self.rtt

    async def benchmark(self, seconds: float = 5.0, max_bytes: int = 8 * 1024 * 1024) -> dict:
        """Isolated-lane throughput. Application-layer speed, not line bandwidth."""
        if self.mechanism != "quic":
            raise RuntimeError("BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION")
        if self._bench is not None:
            raise RuntimeError("BENCH_BUSY")
        bench_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        done: asyncio.Future = loop.create_future()
        self._bench = {"id": bench_id, "done": done}
        self.bench_role = "sender"
        try:
            await self._send_frame({"v": 1, "kind": "bench-start", "id": bench_id}, lane="benchmark")
            block = bytes(CHUNK_BYTES)
            sequence = 0
            sent = 0
            started = time.perf_counter_ns()
            deadline = time.monotonic() + seconds
            while sent < max_bytes and time.monotonic() < deadline:
                await self._send_frame(
                    {"v": 1, "kind": "bench-chunk", "id": bench_id, "seq": sequence, "dataB64": base64.b64encode(block).decode()},
                    lane="benchmark",
                )
                sequence += 1
                sent += len(block)
            await self._send_frame({"v": 1, "kind": "bench-end", "id": bench_id, "bytes": sent}, lane="benchmark")
            try:
                ack = await asyncio.wait_for(done, 15)
            except asyncio.TimeoutError:
                return {"ok": False, "reason": "ACK_TIMEOUT", "bytes": sent}
            elapsed_ns = time.perf_counter_ns() - started
            elapsed_ms = None if elapsed_ns <= 0 else elapsed_ns / 1e6
            confirmed = int(ack.get("bytes", 0))
            speed = None
            if elapsed_ms and confirmed:
                speed = round(confirmed * 8 / 1_000_000 / (elapsed_ms / 1000), 2)
            return {
                "ok": ack.get("ok", False),
                "bytes": confirmed,
                "elapsedMs": elapsed_ms,
                "mbps": speed,
                "note": "应用层速度，不是线路带宽",
            }
        finally:
            self._bench = None
            self.bench_role = None

    # ---------------------------------------------------------------- receiving
    def duplicate(self, file_id: str) -> bool:
        now = time.monotonic()
        self._seen = {key: value for key, value in self._seen.items() if now - value < 600}
        key = (self.peer_id, file_id)
        if key in self._seen:
            return True
        if len(self._seen) >= 4096:
            self._seen.pop(next(iter(self._seen)))
        self._seen[key] = now
        return False

    async def _receive(self, lane: str, payload: bytes) -> None:
        try:
            frame = json.loads(payload)
        except ValueError:
            return
        if not isinstance(frame, dict) or frame.get("v") != 1:
            return
        kind = frame.get("kind")
        if lane == "benchmark":
            await self._receive_bench(frame)
            return
        if kind == "text":
            text = frame.get("text")
            if not isinstance(text, str) or len(text.encode()) > MAX_TEXT_BYTES:
                return
            await self._send_frame({"v": 1, "kind": "delivered", "id": frame.get("id")})
            if self.duplicate(str(frame.get("id"))):
                return
            self._on_event("chat.received", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "kind": "text", "text": text, "id": frame.get("id")})
        elif kind == "ping":
            await self._send_frame({"v": 1, "kind": "pong", "nonce": frame.get("nonce")})
        elif kind == "pong":
            started = self._pings.pop(str(frame.get("nonce")), None)
            if started is not None:
                self.rtt = (time.monotonic() - started) * 1000
                self._on_event("latency", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "rttMs": self.rtt})
        elif kind == "file-start":
            await self._receive_file_start(frame)
        elif kind == "file-chunk":
            await self._receive_file_chunk(frame)
        elif kind == "file-end":
            await self._receive_file_end(frame)
        elif kind in {"file-progress", "delivered"}:
            self._on_event("transfer.progress", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "id": frame.get("id"), "receivedBytes": frame.get("receivedBytes")})
        elif kind == "file-ack":
            self._on_event("transfer.ack", {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "id": frame.get("id"), "ok": frame.get("ok"), "bytes": frame.get("bytes")})

    async def _receive_bench(self, frame: dict) -> None:
        kind = frame.get("kind")
        if kind == "bench-start":
            if self.bench_role is not None and self.bench_role != "sender":
                return
            if self._bench is not None and self.bench_role == "sender":
                return
            self.bench_role = "receiver"
            self._bench = {"id": frame.get("id"), "received": 0, "sequence": 0}
        elif kind == "bench-chunk":
            if self.bench_role != "receiver" or self._bench is None:
                return
            if frame.get("id") != self._bench["id"] or frame.get("seq") != self._bench["sequence"]:
                return
            try:
                chunk = base64.b64decode(frame.get("dataB64", ""), validate=True)
            except Exception:
                return
            if len(chunk) > MAX_FRAME or self._bench["received"] + len(chunk) > MAX_FILE_BYTES:
                return
            self._bench["sequence"] += 1
            self._bench["received"] += len(chunk)
        elif kind == "bench-end":
            if self.bench_role != "receiver" or self._bench is None:
                return
            if frame.get("id") != self._bench["id"]:
                return
            received = self._bench["received"]
            self._bench = None
            self.bench_role = None
            await self._send_frame(
                {"v": 1, "kind": "bench-ack", "id": frame.get("id"), "bytes": received, "ok": received == frame.get("bytes")},
                lane="benchmark",
            )
        elif kind == "bench-ack":
            if self.bench_role == "sender" and self._bench is not None and self._bench.get("id") == frame.get("id"):
                done = self._bench.get("done")
                if done is not None and not done.done():
                    done.set_result({"ok": frame.get("ok"), "bytes": frame.get("bytes")})

    async def _receive_file_start(self, frame: dict) -> None:
        file_id = str(frame.get("id"))
        size = frame.get("size")
        digest = frame.get("sha256")
        valid = (
            isinstance(size, int)
            and not isinstance(size, bool)
            and 0 <= size <= MAX_FILE_BYTES
            and len(self.files) < MAX_ACTIVE_RECEIVES
            and self.reserved + size <= MAX_RESERVED_BYTES
            and file_id not in self.files
            and isinstance(digest, str)
            and bool(HEX64.fullmatch(digest))
            and isinstance(frame.get("name"), str)
            and len(frame["name"]) <= 255
            and isinstance(frame.get("mime"), str)
            and len(frame["mime"]) <= 128
        )
        if not valid:
            await self._send_frame({"v": 1, "kind": "file-ack", "id": file_id, "ok": False, "bytes": 0})
            return
        self.files[file_id] = {"name": frame["name"], "mime": frame["mime"], "size": size, "sha256": digest, "data": bytearray(), "seq": 0, "received": 0}
        self.reserved += size
        await self._send_frame({"v": 1, "kind": "file-progress", "id": file_id, "nextSequence": 0, "receivedBytes": 0})

    async def _receive_file_chunk(self, frame: dict) -> None:
        file_id = str(frame.get("id"))
        entry = self.files.get(file_id)
        if entry is None:
            return
        if frame.get("seq") != entry["seq"]:
            return
        try:
            chunk = base64.b64decode(frame.get("dataB64", ""), validate=True)
        except Exception:
            return
        if entry["received"] + len(chunk) > entry["size"]:
            self._release(file_id)
            await self._send_frame({"v": 1, "kind": "file-ack", "id": file_id, "ok": False, "bytes": entry["received"]})
            return
        entry["data"].extend(chunk)
        entry["received"] += len(chunk)
        entry["seq"] += 1
        if entry["seq"] % 16 == 0:
            await self._send_frame({"v": 1, "kind": "file-progress", "id": file_id, "nextSequence": entry["seq"], "receivedBytes": entry["received"]})

    async def _receive_file_end(self, frame: dict) -> None:
        file_id = str(frame.get("id"))
        entry = self._release(file_id)
        if entry is None:
            await self._send_frame({"v": 1, "kind": "file-ack", "id": file_id, "ok": False, "bytes": 0})
            return
        digest = hashlib.sha256(entry["data"]).hexdigest()
        ok = entry["received"] == entry["size"] and digest == entry["sha256"]
        await self._send_frame({"v": 1, "kind": "file-ack", "id": file_id, "ok": ok, "bytes": entry["received"]})
        if ok and not self.duplicate(file_id):
            self._on_event(
                "chat.received",
                {"connectionId": self.connection, "attemptId": self.id, "mechanism": self.mechanism, "kind": "file", "id": file_id, "name": entry["name"], "mime": entry["mime"], "bytes": entry["received"], "sha256": digest, "data": bytes(entry["data"])},
            )

    def _release(self, file_id: str) -> dict | None:
        entry = self.files.pop(file_id, None)
        if entry is not None:
            self.reserved -= entry["size"]
        return entry

    async def close(self) -> None:
        if self._unsubscribe is not None:
            self._unsubscribe()
            self._unsubscribe = None
        if self.started:
            try:
                await self.adapter.close({"attemptId": self.id, "reason": "USER_CLOSED"})
            except Exception:
                pass
        self.files.clear()
        self.reserved = 0
        if self.state not in TERMINAL_STATES:
            self.state = "closed"
