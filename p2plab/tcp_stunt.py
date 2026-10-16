from __future__ import annotations

import asyncio
import socket
import struct
import sys

from .common import new_socket, sockaddr
from .tcp import TcpAttempt


class StuntAttempt(TcpAttempt):
    """STUNT #2: low-TTL connect state, then rebind for a coordinated reversed connection."""

    async def connect(self):
        await asyncio.wait_for(self.candidates_ready.wait(), self.owner.timeout)
        loop = asyncio.get_running_loop()
        level = socket.IPPROTO_IPV6 if ":" in self.host else socket.IPPROTO_IP
        option = socket.IPV6_UNICAST_HOPS if ":" in self.host else socket.IP_TTL
        self.sock.setsockopt(level, option, self.spec["ttl"])
        task = asyncio.create_task(loop.sock_connect(self.sock, sockaddr(self.remote_candidates[0])))
        try:
            await asyncio.sleep(0.2)
            state = "connected" if task.done() and task.exception() is None else "pending-or-rejected"
            self.owner.log.event("tcp.stunt_warmup", attempt=self.attempt, ttl=self.spec["ttl"],
                state=state, evidence="low-TTL-connect-then-rebind;NAT-state-preservation-not-guaranteed")
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            # A short route may complete the probe handshake. Reset this disposable
            # connection so TIME_WAIT does not prevent reusing its exact tuple.
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                                 struct.pack("HH" if sys.platform == "win32" else "ii", 1, 0))
            self.sock.close()
        self.sock = new_socket(self.host, socket.SOCK_STREAM, self.candidates[0][1])
        if not self.spec["initiator"]:
            self.sock.listen(4)
            self.server = await asyncio.start_server(self.accept, sock=self.sock, ssl=self.listener_context(),
                ssl_handshake_timeout=5, limit=128 * 1024)
            self.sock = None
        await self.sync.synchronize(self.owner.timeout + 5)
        method = self.spec["method"]
        self.spec = {**self.spec, "method": "tcp", "offset": 0}
        try:
            path = await super().connect()
            path.mechanism = method
            return path
        finally:
            self.spec["method"] = method
