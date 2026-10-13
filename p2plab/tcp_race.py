from __future__ import annotations

import asyncio
import contextlib
import hashlib
import ipaddress
import socket

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from .common import encode_frame, new_socket, read_frame, sockaddr
from .session import Path
from .tcp import TcpAttempt


class TcpRaceAttempt(TcpAttempt):
    """Same-port listen/connect; choose the same authenticated edge at both peers."""

    def __init__(self, owner, spec, host):
        super().__init__(owner, spec, host)
        self.connections = {}
        self.tasks = set()
        self.edge_ready, self.choice_ready = asyncio.Event(), asyncio.Event()
        self.choice = None

    async def handle(self, data):
        if data.get("kind") != "race_choice" or data.get("choice") not in ("primary", "reverse"):
            raise ValueError("TCP_RACE_CHOICE_INVALID")
        self.choice = data["choice"]
        self.choice_ready.set()

    async def discard_writer(self, writer):
        writer.close()
        try:
            await asyncio.wait_for(writer.wait_closed(), 2)
        except (OSError, TimeoutError):
            writer.transport.abort()

    def listener_context(self):
        return None

    async def accept(self, reader, writer):
        task = asyncio.current_task()
        self.tasks.add(task)
        try:
            if self.closed or len(self.connections) >= 4:
                await self.discard_writer(writer)
                return
            prefix = await asyncio.wait_for(reader.readexactly(5), 2)
            if prefix != b"RACE" + bytes([not self.spec["initiator"]]):
                raise ValueError("TCP_RACE_ROLE_PREFIX_INVALID")
            writer.write(b"LIST" + bytes([self.spec["initiator"]]))
            await writer.drain()
            await writer.start_tls(self.owner.identity.context(self.owner.peer["certificate"], server=True),
                                   ssl_handshake_timeout=5)
            await self.attach_connection(reader, writer, "reverse" if self.spec["initiator"] else "primary")
        except BaseException as exc:
            await self.discard_writer(writer)
            if isinstance(exc, asyncio.CancelledError):
                raise
            self.owner.log.event("tcp.race_accept_failed", str(exc), "WARNING", attempt=self.attempt)
        finally:
            self.tasks.discard(task)

    async def attach_connection(self, reader, writer, edge):
        cert = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        expected = x509.load_pem_x509_certificate(self.owner.peer["certificate"].encode()).fingerprint(hashes.SHA256())
        if not cert or hashlib.sha256(cert).digest() != expected:
            raise ValueError("TCP_CERTIFICATE_FINGERPRINT_MISMATCH")
        if self.closed or edge in self.connections:
            await self.discard_writer(writer)
            return

        async def send(body):
            writer.write(encode_frame(body))
            await writer.drain()

        receive_task = None

        async def close():
            writer.close()
            if receive_task and receive_task is not asyncio.current_task():
                receive_task.cancel()
                await asyncio.gather(receive_task, return_exceptions=True)
            await self.discard_writer(writer)

        path = Path(self.owner, self.attempt, "tcp-race", ipaddress.ip_address(self.host).version, send, close)
        self.connections[edge] = path

        async def receive():
            try:
                while not path.closed:
                    await path.receive(await read_frame(reader))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.owner.log.event("tcp.race_read_failed", str(exc), "WARNING", attempt=self.attempt, edge=edge)
                await path.close("TCP_RACE_IO_FAILED")

        receive_task = asyncio.create_task(receive(), name="tcp-race-receive:" + edge)
        await path.start()
        await path.wait_ready(self.owner.timeout + 5)
        self.owner.log.event("tcp.race_edge_ready", attempt=self.attempt, edge=edge,
                             local=writer.get_extra_info("sockname")[:2], remote=writer.get_extra_info("peername")[:2])
        self.edge_ready.set()

    async def outbound(self, target):
        sock = new_socket(self.host, socket.SOCK_STREAM, self.candidates[0][1], reuse_port=True)
        writer = None
        try:
            delay = self.spec.get("offset", 0) if not self.spec["initiator"] else 0
            await asyncio.sleep(delay)
            await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, sockaddr(target)), self.owner.timeout)
            loop = asyncio.get_running_loop()
            await loop.sock_sendall(sock, b"RACE" + bytes([self.spec["initiator"]]))
            prefix = b""
            async with asyncio.timeout(2):
                while len(prefix) < 5:
                    raw = await loop.sock_recv(sock, 5 - len(prefix))
                    if not raw:
                        raise ConnectionError("TCP_RACE_PREFIX_EOF")
                    prefix += raw
            if prefix not in (b"LIST" + bytes([not self.spec["initiator"]]),
                              b"RACE" + bytes([not self.spec["initiator"]])):
                raise ValueError("TCP_RACE_ROLE_PREFIX_INVALID")
            simultaneous = prefix.startswith(b"RACE")
            edge = "primary" if simultaneous or self.spec["initiator"] else "reverse"
            if simultaneous and not self.spec["initiator"]:
                reader, writer = await self.accept_connected_socket(sock)
            else:
                reader, writer = await asyncio.open_connection(
                    sock=sock, ssl=self.owner.identity.context(self.owner.peer["certificate"], server=False),
                    server_hostname="p2p-peer", ssl_handshake_timeout=5, limit=128 * 1024,
                )
            sock = None
            self.owner.log.event("tcp.race_transport", attempt=self.attempt, simultaneous_open=simultaneous,
                                 tls_server=simultaneous and not self.spec["initiator"])
            await self.attach_connection(reader, writer, edge)
        except BaseException as exc:
            if writer:
                await self.discard_writer(writer)
            if isinstance(exc, asyncio.CancelledError):
                raise
            self.owner.log.event("tcp.race_connect_failed", str(exc), "WARNING", attempt=self.attempt, target=target)
        finally:
            if sock:
                sock.close()

    async def connect(self):
        await asyncio.wait_for(self.candidates_ready.wait(), self.owner.timeout)
        for target in self.remote_candidates[:8]:
            task = asyncio.create_task(self.outbound(target), name="tcp-race-connect")
            if not task.done():
                self.tasks.add(task)
                task.add_done_callback(self.tasks.discard)
        async with asyncio.timeout(self.owner.timeout + 10):
            if self.owner.leader:
                await self.edge_ready.wait()
                await asyncio.sleep(0.25)
                self.choice = next((edge for edge in ("primary", "reverse") if edge in self.connections
                    and self.connections[edge].ready.is_set() and not self.connections[edge].closed), None)
                if self.choice is None:
                    raise ConnectionError("TCP_RACE_NO_VERIFIED_EDGE")
                await self.owner.signal({"kind": "race_choice", "attempt": self.attempt, "choice": self.choice})
            else:
                await self.choice_ready.wait()
            while self.choice not in self.connections or not self.connections[self.choice].ready.is_set():
                await asyncio.sleep(0.01)
            self.path = self.connections[self.choice]
        await asyncio.gather(*(path.close("TCP_RACE_OTHER_EDGE") for edge, path in self.connections.items() if edge != self.choice))
        self.owner.log.event("tcp.race_selected", attempt=self.attempt, edge=self.choice,
                             evidence="mutual-TLS-and-application-authentication;coordinated-edge-choice")
        return self.path

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.server:
            self.server.close()
        for task in tuple(self.tasks):
            if task is not asyncio.current_task():
                task.cancel()
        await asyncio.gather(*(t for t in tuple(self.tasks) if t is not asyncio.current_task()), return_exceptions=True)
        await asyncio.gather(*(path.close("TCP_RACE_CLOSED") for path in self.connections.values()))
        if self.sock:
            self.sock.close()
        if self.server:
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self.server.wait_closed(), 6)
