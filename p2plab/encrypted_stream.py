from __future__ import annotations

import asyncio
import hashlib
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .common import encode_frame, extract_frames
from .session import Path


class EncryptedStream:
    """TLS over a reliable native transport; retain the common authenticated Path."""

    def __init__(self, owner, spec, send, close, family=None):
        self.owner, self.spec, self.raw_send, self.raw_close = owner, spec, send, close
        self.incoming, self.outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
        server = not spec["initiator"]
        context = owner.identity.context(owner.peer["certificate"], server=server)
        self.ssl = context.wrap_bio(self.incoming, self.outgoing, server_side=server,
                                   server_hostname=None if server else "p2p-peer")
        self.path = Path(owner, spec["attempt"], spec["method"], family, self.send, self.close)
        self.lock = asyncio.Lock()
        self.secure = asyncio.Event()
        self.buffer = bytearray()
        self.queue = asyncio.Queue(maxsize=128)
        self.started = self.closed = False
        self.worker = asyncio.create_task(self.consume(), name="native-tls:" + spec["attempt"])

    def feed(self, data):
        if self.closed:
            return
        try:
            self.queue.put_nowait(data)
        except asyncio.QueueFull:
            self.owner.spawn(self.path.close("NATIVE_RECEIVE_QUEUE_LIMIT"), "native-overflow")

    async def drain(self):
        while self.outgoing.pending:
            await self.raw_send(self.outgoing.read(min(self.outgoing.pending, 60 * 1024)))

    async def process(self, data=b""):
        async with self.lock:
            if data:
                self.incoming.write(data)
            if not self.secure.is_set():
                try:
                    self.ssl.do_handshake()
                    expected = x509.load_pem_x509_certificate(self.owner.peer["certificate"].encode()).fingerprint(hashes.SHA256())
                    if hashlib.sha256(self.ssl.getpeercert(binary_form=True)).digest() != expected:
                        raise ValueError("NATIVE_TLS_CERTIFICATE_PIN_MISMATCH")
                    self.secure.set()
                    self.owner.log.event("native.tls_verified", attempt=self.spec["attempt"], method=self.spec["method"])
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    pass
            if self.secure.is_set():
                while True:
                    try:
                        raw = self.ssl.read(64 * 1024)
                        if not raw:
                            raise ConnectionError("NATIVE_TLS_EOF")
                        self.buffer.extend(raw)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                        break
            frames = extract_frames(self.buffer)
            await self.drain()
        if self.secure.is_set() and not self.started:
            self.started = True
            await self.path.start()
        for frame in frames:
            await self.path.receive(frame)

    async def consume(self):
        try:
            while not self.closed:
                await self.process(await self.queue.get())
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("native.tls_failed", exc, attempt=self.spec["attempt"])
            await self.path.close("NATIVE_TLS_FAILED")

    async def start(self, timeout):
        await self.process()
        await self.path.wait_ready(timeout)
        return self.path

    async def send(self, body):
        if self.closed or not self.secure.is_set():
            raise ConnectionError("NATIVE_TLS_NOT_READY")
        async with self.lock:
            data = encode_frame(body)
            written = self.ssl.write(data)
            if written != len(data):
                raise ValueError("NATIVE_TLS_SHORT_WRITE")
            await self.drain()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.secure.set()
        if self.worker is not asyncio.current_task():
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
        await self.raw_close()
