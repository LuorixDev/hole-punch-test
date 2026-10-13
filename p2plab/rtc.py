from __future__ import annotations

import asyncio
import ipaddress

from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription

from .common import encode_frame, extract_frames
from .session import Path


def filter_sdp(sdp, profile, *, allow_loopback=False):
    result = []
    for line in sdp.splitlines():
        if line.startswith("a=candidate:"):
            bits = line.split()
            if len(bits) < 8 or bits[6] != "typ" or bits[7] not in ("host", "srflx", "prflx"):
                continue
            try:
                ip = ipaddress.ip_address(bits[4])
                if (
                    ip.is_unspecified
                    or ip.is_multicast
                    or ip.is_link_local
                    or ip.is_loopback
                    and not allow_loopback
                ):
                    continue
                if not 1 <= int(bits[5]) <= 65535:
                    continue
                version = ip.version
            except ValueError:
                # Unknown family is excluded from family-specific tests, not silently permitted.
                if profile != "dual" or not bits[4].endswith(".local"):
                    continue
                version = None
            if profile != "dual" and version != int(profile):
                continue
        result.append(line)
    return "\r\n".join(result) + "\r\n"


class RtcAttempt:
    def __init__(self, owner, spec):
        self.owner, self.spec = owner, spec
        self.attempt = spec["attempt"]
        servers = [RTCIceServer(urls="stun:" + value) for value in owner.observers[:2]]
        self.pc = RTCPeerConnection(RTCConfiguration(iceServers=servers))
        self.channels = {}
        self.buffers = {}
        self.path = Path(
            owner,
            self.attempt,
            "webrtc",
            None if spec["profile"] == "dual" else int(spec["profile"]),
            self.send,
            self.close,
        )
        self.queue = asyncio.Queue(maxsize=128)
        self.closed = False
        self.signaling_lock = asyncio.Lock()
        self.close_complete = asyncio.Event()
        self.writable = asyncio.Event()

        @self.pc.on("datachannel")
        def on_channel(channel):
            self.attach(channel)

        @self.pc.on("connectionstatechange")
        async def state_change():
            self.owner.log.event("webrtc.state", attempt=self.attempt, state=self.pc.connectionState)
            if self.pc.connectionState in ("failed", "closed") and not self.closed:
                await self.path.close("WEBRTC_" + self.pc.connectionState.upper())

        self.worker = asyncio.create_task(self.consume(), name=f"rtc-receive:{self.attempt}")

    def attach(self, channel):
        if self.closed or channel.label not in ("chat", "benchmark") or channel.label in self.channels:
            channel.close()
            return
        self.channels[channel.label] = channel
        self.buffers[channel.label] = bytearray()
        channel.bufferedAmountLowThreshold = 1024 * 1024

        @channel.on("bufferedamountlow")
        def writable():
            self.writable.set()

        @channel.on("open")
        async def opened():
            self.writable.set()
            if channel.label == "chat":
                await self.path.start()

        @channel.on("message")
        def message(data):
            try:
                if not isinstance(data, bytes):
                    raise ValueError("WEBRTC_BINARY_REQUIRED")
                buf = self.buffers[channel.label]
                buf.extend(data)
                for body in extract_frames(buf):
                    self.queue.put_nowait(body)
            except Exception as exc:
                self.owner.log.exception("webrtc.frame_failed", exc, attempt=self.attempt)
                asyncio.create_task(self.path.close("WEBRTC_FRAME_FAILED"))

        @channel.on("close")
        async def closed():
            if not self.closed:
                await self.path.close("WEBRTC_CHANNEL_CLOSED")

        # aiortc emits incoming "datachannel" after that channel is already open.
        if channel.label == "chat" and channel.readyState == "open":
            asyncio.create_task(self.path.start())

    def local_sdp(self):
        sdp = filter_sdp(
            self.pc.localDescription.sdp, self.spec["profile"], allow_loopback=self.owner.loopback
        )
        if "a=candidate:" not in sdp:
            raise ValueError("WEBRTC_PROFILE_NO_CANDIDATES")
        return sdp

    async def offer(self):
        async with self.signaling_lock:
            if self.closed:
                return
            try:
                self.attach(self.pc.createDataChannel("chat", ordered=True))
                self.attach(self.pc.createDataChannel("benchmark", ordered=True))
                await self.pc.setLocalDescription(await self.pc.createOffer())
                sdp = self.local_sdp()
            finally:
                # aiortc schedules ICE startup at the end of SDP setters; start it before close stops ICE.
                await asyncio.sleep(0)
        if not self.closed:
            await self.owner.signal({"kind": "offer", "attempt": self.attempt, "sdp": sdp})

    async def handle(self, data):
        response = None
        async with self.signaling_lock:
            if self.closed:
                self.owner.log.event(
                    "webrtc.signal_ignored", attempt=self.attempt, kind=data["kind"], reason="ATTEMPT_CLOSED"
                )
                return
            try:
                if data["kind"] == "offer":
                    if self.spec["initiator"]:
                        raise ValueError("WEBRTC_OFFER_ROLE")
                    await self.pc.setRemoteDescription(
                        RTCSessionDescription(
                            sdp=filter_sdp(
                                data["sdp"], self.spec["profile"], allow_loopback=self.owner.loopback
                            ),
                            type="offer",
                        )
                    )
                    if not self.closed:
                        await self.pc.setLocalDescription(await self.pc.createAnswer())
                        response = {"kind": "answer", "attempt": self.attempt, "sdp": self.local_sdp()}
                elif data["kind"] == "answer":
                    if not self.spec["initiator"]:
                        raise ValueError("WEBRTC_ANSWER_ROLE")
                    await self.pc.setRemoteDescription(
                        RTCSessionDescription(
                            sdp=filter_sdp(
                                data["sdp"], self.spec["profile"], allow_loopback=self.owner.loopback
                            ),
                            type="answer",
                        )
                    )
            finally:
                await asyncio.sleep(0)
        # Signaling may call the peer directly; do not hold the SDP lock over that round trip.
        if response and not self.closed:
            await self.owner.signal(response)

    async def connect(self):
        if self.spec["initiator"]:
            await self.offer()
        await self.path.wait_ready(self.owner.timeout + 12)
        return self.path

    async def consume(self):
        try:
            while not self.closed:
                await self.path.receive(await self.queue.get())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("webrtc.application_failed", exc, attempt=self.attempt)
            await self.path.close("WEBRTC_APPLICATION_FAILED")

    async def send(self, body):
        label = "benchmark" if body["kind"].startswith("bench_") or body["kind"] == "file_chunk" else "chat"
        channel = self.channels.get(label)
        deadline = asyncio.get_running_loop().time() + 5
        while not channel or channel.readyState != "open" or channel.bufferedAmount > 4 * 1024 * 1024:
            if self.closed or asyncio.get_running_loop().time() >= deadline:
                raise TimeoutError("WEBRTC_BACKPRESSURE_OR_CHANNEL_NOT_OPEN")
            self.writable.clear()
            await asyncio.wait_for(
                self.writable.wait(), max(0.001, deadline - asyncio.get_running_loop().time())
            )
            channel = self.channels.get(label)
        channel.send(encode_frame(body))

    async def close(self):
        if self.closed:
            if self.worker is not asyncio.current_task():
                await self.close_complete.wait()
            return
        self.closed = True
        self.writable.set()
        try:
            if self.worker is not asyncio.current_task():
                self.worker.cancel()
                await asyncio.gather(self.worker, return_exceptions=True)
            async with self.signaling_lock:
                await self.pc.close()
        finally:
            self.close_complete.set()
