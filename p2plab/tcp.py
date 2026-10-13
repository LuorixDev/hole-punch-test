from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket

from .common import encode_frame, endpoint, new_socket, packed, read_frame, sockaddr
from .session import Path


class TcpAttempt:
    def __init__(self, owner, spec, host):
        self.owner, self.spec, self.host = owner, spec, host
        self.attempt = spec["attempt"]
        self.sock = None
        self.server = None
        self.path = None
        self.candidates = []
        self.remote_candidates = []
        self.candidates_ready = asyncio.Event()
        self.connected = asyncio.Event()
        self.reader_task = None
        self.writer = None
        self.closed = False
        self.accepting = False
        self.observed = None

    async def prepare(self):
        self.sock = new_socket(self.host, socket.SOCK_STREAM, reuse_port=self.spec["method"] == "tcp-race")
        local = self.sock.getsockname()[:2]
        self.candidates = [list(local)]
        # TCP mapping must be observed with TCP, never borrowed from a UDP STUN response.
        if ":" not in self.host and self.owner.tcp_observer:
            port = local[1]
            try:
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_connect(self.sock, self.owner.tcp_observer), 2
                )
                reader, writer = await asyncio.open_connection(sock=self.sock)
                self.sock = None
                try:
                    writer.write(packed({"token": self.owner.observation_token}) + b"\n")
                    await writer.drain()
                    reply = json.loads(await asyncio.wait_for(reader.readline(), 2))
                    self.observed = list(endpoint(*reply["mapped"]))
                    if self.observed not in self.candidates:
                        self.candidates.append(self.observed)
                    self.owner.log.event(
                        "tcp.mapped",
                        attempt=self.attempt,
                        local=local,
                        mapped=self.observed,
                        evidence="tcp-observer-same-local-port-rebind-not-guaranteed",
                    )
                finally:
                    writer.close()
                    await writer.wait_closed()
            except Exception as exc:
                self.owner.log.event("tcp.observer_failed", str(exc), "WARNING", attempt=self.attempt)
            finally:
                if self.sock:
                    self.sock.close()
                self.sock = new_socket(self.host, socket.SOCK_STREAM, port, reuse_port=self.spec["method"] == "tcp-race")
        if (self.spec["method"] == "tcp" and not self.spec["initiator"]) or self.spec["method"] == "tcp-race":
            self.sock.listen(4)
            context = self.listener_context()
            self.server = await asyncio.start_server(
                self.accept,
                sock=self.sock,
                ssl=context,
                ssl_handshake_timeout=5 if context else None,
                limit=128 * 1024,
            )
            self.sock = None
        self.owner.log.event(
            "tcp.prepared",
            attempt=self.attempt,
            method=self.spec["method"],
            local=self.candidates[0],
            listening=self.server is not None,
        )

    def listener_context(self):
        return self.owner.identity.context(self.owner.peer["certificate"], server=True)

    def set_candidates(self, candidates):
        if not isinstance(candidates, list) or len(candidates) > 12:
            raise ValueError("TCP_CANDIDATE_LIMIT")
        self.remote_candidates = [endpoint(*item) for item in candidates]
        if not self.owner.loopback and any(
            ipaddress.ip_address(ep[0]).is_loopback for ep in self.remote_candidates
        ):
            raise ValueError("UNEXPECTED_LOOPBACK_CANDIDATE")
        if any(
            ipaddress.ip_address(ep[0]).version != ipaddress.ip_address(self.host).version
            for ep in self.remote_candidates
        ):
            raise ValueError("TCP_FAMILY_MISMATCH")
        self.candidates_ready.set()

    async def connect(self):
        try:
            await asyncio.wait_for(self.candidates_ready.wait(), self.owner.timeout)
        except TimeoutError as exc:
            raise TimeoutError("TCP_CANDIDATES_TIMEOUT") from exc
        if not self.spec["initiator"] and self.spec["method"] == "tcp":
            try:
                await asyncio.wait_for(self.connected.wait(), self.owner.timeout + 5)
            except TimeoutError as exc:
                raise TimeoutError("TCP_LISTEN_ACCEPT_TIMEOUT") from exc
        else:
            offset = self.spec.get("offset", 0) if not self.spec["initiator"] else 0
            await asyncio.sleep(offset)
            failures = []
            port = self.candidates[0][1]
            for target in self.remote_candidates:
                if self.closed:
                    raise ConnectionError("TCP_ATTEMPT_CLOSED")
                try:
                    if self.sock is None:
                        self.sock = new_socket(self.host, socket.SOCK_STREAM, port)
                    level = socket.IPPROTO_IPV6 if ":" in self.host else socket.IPPROTO_IP
                    option = socket.IPV6_UNICAST_HOPS if ":" in self.host else socket.IP_TTL
                    original_ttl = self.sock.getsockopt(level, option)
                    if self.spec.get("ttl"):
                        self.sock.setsockopt(level, option, self.spec["ttl"])
                    connecting = asyncio.create_task(asyncio.get_running_loop().sock_connect(self.sock, sockaddr(target)))
                    try:
                        if self.spec.get("ttl"):
                            await asyncio.sleep(0.15)
                            self.sock.setsockopt(level, option, original_ttl)
                            self.owner.log.event("tcp.ttl_warmup", attempt=self.attempt, ttl=self.spec["ttl"],
                                                 restored=original_ttl, target=target)
                        await asyncio.wait_for(connecting, max(1, self.owner.timeout / max(1, len(self.remote_candidates))))
                    finally:
                        if self.sock:
                            self.sock.setsockopt(level, option, original_ttl)
                        connecting.cancel()
                        await asyncio.gather(connecting, return_exceptions=True)
                    is_server = self.spec["method"] in ("tcp-simopen", "tcp-sync", "tcp-ttl") and not self.spec["tls_client"]
                    if is_server:
                        reader, writer = await self.accept_connected_socket(self.sock)
                    else:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(
                                sock=self.sock,
                                ssl=self.owner.identity.context(self.owner.peer["certificate"], server=False),
                                server_hostname="p2p-peer",
                                ssl_handshake_timeout=5,
                                limit=128 * 1024,
                            ),
                            6,
                        )
                    self.sock = None
                    await self.establish(reader, writer)
                    break
                except Exception as exc:
                    failures.append({"target": target, "reason": type(exc).__name__ + ":" + str(exc)})
                    if self.sock:
                        self.sock.close()
                        self.sock = None
            if self.path is None:
                self.owner.log.event(
                    "tcp.connect_failed",
                    attempt=self.attempt,
                    failures=failures,
                    reason="TCP_SIMOPEN_UNAVAILABLE"
                    if self.spec["method"] == "tcp-simopen"
                    else "TCP_UNAVAILABLE",
                )
                raise ConnectionError("TCP_CONNECT_FAILED")
        await self.path.wait_ready(8)
        return self.path

    async def accept_connected_socket(self, sock):
        # Simultaneous-open TLS server mode operates on the connected socket; no listen/accept fallback.
        loop = asyncio.get_running_loop()
        reader = asyncio.StreamReader(limit=128 * 1024)
        protocol = asyncio.StreamReaderProtocol(reader)
        transport, _ = await asyncio.wait_for(
            loop.connect_accepted_socket(
                lambda: protocol,
                sock,
                ssl=self.owner.identity.context(self.owner.peer["certificate"], server=True),
                ssl_handshake_timeout=5,
            ),
            6,
        )
        return reader, asyncio.StreamWriter(transport, protocol, reader, loop)

    async def accept(self, reader, writer):
        if self.closed or self.accepting:
            writer.close()
            await writer.wait_closed()
            return
        self.accepting = True
        try:
            await asyncio.wait_for(self.candidates_ready.wait(), self.owner.timeout)
            remote = writer.get_extra_info("peername")
            if remote[0] not in {ep[0] for ep in self.remote_candidates}:
                raise ValueError("TCP_UNSIGNALED_SOURCE")
            await self.establish(reader, writer)
            self.connected.set()
        except Exception as exc:
            self.owner.log.exception("tcp.accept_failed", exc, attempt=self.attempt)
            writer.close()
            await writer.wait_closed()
            self.accepting = False

    async def establish(self, reader, writer):
        cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes

        expected = (
            x509.load_pem_x509_certificate(self.owner.peer["certificate"].encode())
            .fingerprint(hashes.SHA256())
            .hex()
        )
        if not cert or hashlib.sha256(cert).hexdigest() != expected:
            writer.close()
            await writer.wait_closed()
            raise ValueError("TCP_CERTIFICATE_FINGERPRINT_MISMATCH")
        self.writer = writer
        self.path = Path(
            self.owner,
            self.attempt,
            self.spec["method"],
            ipaddress.ip_address(self.host).version,
            self.send,
            self.close,
        )
        self.owner.log.event(
            "tcp.tls_completed",
            attempt=self.attempt,
            local=writer.get_extra_info("sockname")[:2],
            remote=writer.get_extra_info("peername")[:2],
            mutual_certificate_pin=True,
        )
        self.reader_task = asyncio.create_task(self.receive(reader), name=f"tcp-receive:{self.attempt}")
        await self.path.start()

    async def receive(self, reader):
        try:
            while not self.closed:
                await self.path.receive(await read_frame(reader))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.event(
                "tcp.read_failed", str(exc), "WARNING", attempt=self.attempt, exception=type(exc).__name__
            )
            if self.path:
                await self.path.close("TCP_IO_FAILED")

    async def send(self, body):
        self.writer.write(encode_frame(body))
        await self.writer.drain()

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.server:
            self.server.close()
        if self.writer:
            self.writer.close()
        if self.reader_task and self.reader_task is not asyncio.current_task():
            self.reader_task.cancel()
            await asyncio.gather(self.reader_task, return_exceptions=True)
        if self.sock:
            self.sock.close()
        if self.writer:
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 2)
            except (TimeoutError, OSError):
                self.writer.transport.abort()
            except asyncio.CancelledError:
                self.writer.transport.abort()
                raise
        if self.server:
            # Python 3.12 also waits for accepted transports, not only the listener.
            try:
                await asyncio.wait_for(self.server.wait_closed(), 6)
            except TimeoutError:
                self.owner.log.event("tcp.close_timeout", level="WARNING", attempt=self.attempt)
