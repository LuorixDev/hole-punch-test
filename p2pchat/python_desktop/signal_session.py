"""Standalone signaling socket for methods that are not WebRTC.

Reused as-is: the framing, room authentication, retry and roster semantics are
the same server protocol that :mod:`p2pchat.peer` already speaks. Only the
mechanism routing differs, which is why this small session exists instead of a
second copy of the transport code.
"""
from __future__ import annotations

import asyncio
import base64
import json

from aiohttp import ClientError, ClientSession, WSMsgType

# This module depends on the v2 join handshake that lives in ``p2pchat.peer``.
# That API landed with t16 and is frozen together with peer.py; the dependency is
# pinned in docs/DESKTOP-PYTHON.md. Re-implementing the handshake here (or
# duplicating the HKDF/proof steps) would let the two copies drift, so the import
# is deliberate — but a peer.py without join_v2 must fail with something a human
# can act on instead of a bare ImportError.
JOIN_V2_REQUIREMENT = "桌面端依赖 p2pchat.peer.join_v2（v2 挑战-证明加入，随 t16 一并冻结）"
try:
    from p2pchat.peer import join_v2 as join_v2
except ImportError as error:  # pragma: no cover - exercised by tests/desktop
    raise ImportError(
        f"{JOIN_V2_REQUIREMENT}，但当前 p2pchat/peer.py 没有提供它。"
        "请先把 t16 的 join_v2 落定到工作树，或换用带 join_v2 的 peer.py。"
        f"（原始错误：{error}）"
    ) from error

if not callable(join_v2):  # pragma: no cover - exercised by tests/desktop
    raise ImportError(f"{JOIN_V2_REQUIREMENT}，但当前 p2pchat.peer.join_v2 不是可调用的加入函数。")

MAX_MESSAGE_BYTES = 131072
MAX_QUEUE = 64


class SignalSession:
    """One room membership used exclusively for non-WebRTC signaling frames."""

    def __init__(self, url: str, room: str, secret: str, name: str, capabilities, client_session_id: str, origin=None, factory=None):
        self.url = url
        self.room = room
        self.secret = secret
        self.name = name
        self.capabilities = list(capabilities)
        self.session = client_session_id
        self.origin = origin
        self.factory = factory
        self.id: str | None = None
        self.ws = None
        self.closed = False
        self.ice_servers: list = []
        self._queue: asyncio.Queue = asyncio.Queue(maxsize=MAX_QUEUE)
        self._task: asyncio.Task | None = None
        self.on_signal = None
        self.on_nat_samples = None
        self.on_error = None
        # 服务器的 v6-reach 权威结论（连接被拒/token 不符/策略拒绝/看不懂）走这个 hook。
        self.on_v6_reach_result = None
        # 结论要么进 hook，要么被明确记为“丢弃”，hook 抛错则单独记为“异常”：
        # 三者必须可区分，否则拒绝类结论会被静默吞掉（t62 修的就是这个）。
        self.dropped_frames = []
        self.hook_errors = []
        self.dropped_frame_count = 0
        self.hook_error_count = 0

    def _record_dropped_frame(self, frame_type: str) -> None:
        """Bounded, inspectable record of a frame that had nowhere to go."""
        self.dropped_frame_count += 1
        self.dropped_frames.append(str(frame_type)[:64])
        del self.dropped_frames[:-8]

    def _record_hook_error(self, frame_type: str, error: BaseException) -> None:
        """Bounded record of a hook failure: the frame *did* arrive, so this is not a drop."""
        self.hook_error_count += 1
        self.hook_errors.append({"type": str(frame_type)[:64], "error": type(error).__name__})
        del self.hook_errors[:-8]

    def _dispatch_v6_reach_result(self, data: dict) -> None:
        """Hand the server's authoritative conclusion to the hook (never silently)."""
        if self.on_v6_reach_result is None:
            self._record_dropped_frame(data.get("type", "v6-reach-result"))
            return
        try:
            self.on_v6_reach_result(data)
        except Exception as error:  # 保持既有风格：hook 异常不让会话崩，但会被记录
            self._record_hook_error(data.get("type", "v6-reach-result"), error)

    def _enqueue(self, frame: dict) -> None:
        if json.dumps(frame).encode().__len__() > MAX_MESSAGE_BYTES - 512:
            raise ValueError("LIMIT_EXCEEDED")
        try:
            self._queue.put_nowait(frame)
        except asyncio.QueueFull:
            raise RuntimeError("BACKPRESSURE") from None

    def send_signal(self, **payload) -> None:
        """Enqueue a signaling frame; the reader task owns the socket."""
        self._enqueue({"v": 1, "type": "signal", **payload})

    def send_nat_samples(self, **payload) -> None:
        """Enqueue a whitelisted nat-samples frame (HMAC-protected, forwarded unchanged)."""
        self._enqueue({"v": 1, "type": "nat-samples", **payload})

    async def _writer(self):
        while not self.closed and self.ws is not None and not self.ws.closed:
            try:
                frame = await asyncio.wait_for(self._queue.get(), 1)
            except asyncio.TimeoutError:
                continue
            await self.ws.send_json(frame)

    async def run(self):
        self._task = asyncio.create_task(self._writer())
        backoff = 1
        try:
            while not self.closed:
                try:
                    async with (self.factory() if self.factory is not None else ClientSession()) as session:
                        self.ws = await session.ws_connect(
                            self.url, heartbeat=20, max_msg_size=MAX_MESSAGE_BYTES, origin=self.origin
                        )
                        # Reuse the project's own join handshake (challenge +
                        # HKDF-derived proof). Hand-rolling a second one would
                        # drift from the server contract, and the raw secret
                        # must never be sent to the server.
                        await join_v2(
                            self.ws,
                            self.room,
                            self.secret,
                            self.name,
                            self.session,
                            tuple(self.capabilities),
                        )
                        backoff = 1
                        async for message in self.ws:
                            if message.type != WSMsgType.TEXT:
                                continue
                            data = json.loads(message.data)
                            if data.get("type") == "welcome":
                                self.id = data["id"]
                                self.ice_servers = data.get("iceServers", [])
                            elif data.get("type") == "signal":
                                if self.on_signal is not None:
                                    try:
                                        self.on_signal(data)
                                    except Exception:
                                        pass
                            elif data.get("type") == "nat-samples":
                                if self.on_nat_samples is not None:
                                    try:
                                        self.on_nat_samples(data)
                                    except Exception:
                                        pass
                            elif data.get("type") == "v6-reach-result":
                                # 服务器对 IPv6 入站回连的权威结论（含“连接被拒/token 不符/
                                # 策略拒绝/看不懂”）：必须分发到 hook，绝不静默丢弃。
                                self._dispatch_v6_reach_result(data)
                            elif data.get("type") == "error":
                                if self.on_error is not None:
                                    self.on_error(str(data.get("code")))
                except (ClientError, ConnectionError, OSError, asyncio.TimeoutError):
                    pass
                finally:
                    self.ws = None
                if not self.closed:
                    await asyncio.sleep(backoff)
                    backoff = min(30, backoff * 2)
        finally:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)

    async def close(self):
        self.closed = True
        if self.ws is not None and not self.ws.closed:
            await self.ws.close()
        if self._task is not None:
            self._task.cancel()
            await asyncio.gather(self._task, return_exceptions=True)


def encode_data(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def decode_data(encoded: str) -> bytes:
    return base64.b64decode(encoded, validate=True)
