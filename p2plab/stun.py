from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import struct

from .common import endpoint, new_socket, sockaddr

COOKIE = 0x2112A442
HEADER = struct.Struct("!HHI12s")
XOR_MAPPED, OTHER, CHANGE, ORIGIN = 0x0020, 0x802C, 0x0003, 0x802B


def attribute(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data + b"\0" * (-len(data) % 4)


def address_value(ep: tuple[str, int], tid: bytes, *, xor: bool) -> bytes:
    ip = ipaddress.ip_address(ep[0])
    port, raw = ep[1], ip.packed
    if xor:
        port ^= COOKIE >> 16
        raw = bytes(a ^ b for a, b in zip(raw, struct.pack("!I", COOKIE) + tid))
    return struct.pack("!BBH", 0, 1 if ip.version == 4 else 2, port) + raw


def decode_address(value: bytes, tid: bytes, *, xor: bool) -> tuple[str, int]:
    if len(value) < 4 or value[0] != 0 or value[1] not in (1, 2):
        raise ValueError("STUN_ADDRESS_FORMAT")
    if len(value) != (8 if value[1] == 1 else 20):
        raise ValueError("STUN_ADDRESS_LENGTH")
    port, raw = struct.unpack_from("!H", value, 2)[0], value[4:]
    if xor:
        port ^= COOKIE >> 16
        raw = bytes(a ^ b for a, b in zip(raw, struct.pack("!I", COOKIE) + tid))
    return endpoint(str(ipaddress.ip_address(raw)), port)


def attributes(data: bytes, tid: bytes, kind: int = 0x0101) -> dict[int, bytes]:
    if len(data) < 20:
        raise ValueError("STUN_TRUNCATED")
    actual, size, cookie, transaction = HEADER.unpack_from(data)
    if actual != kind or cookie != COOKIE or transaction != tid or size != len(data) - 20 or size % 4:
        raise ValueError("STUN_TRANSACTION_MISMATCH")
    result, offset = {}, 20
    while offset < len(data):
        if offset + 4 > len(data):
            raise ValueError("STUN_TRUNCATED")
        attr, length = struct.unpack_from("!HH", data, offset)
        offset += 4
        if offset + length > len(data):
            raise ValueError("STUN_TRUNCATED")
        result[attr] = data[offset : offset + length]
        offset += (length + 3) & ~3
    if offset != len(data):
        raise ValueError("STUN_PADDING")
    return result


def parse_response(data: bytes, tid: bytes) -> dict:
    attrs = attributes(data, tid)
    if XOR_MAPPED not in attrs:
        raise ValueError("STUN_NO_MAPPED_ADDRESS")
    result = {"mapped": decode_address(attrs[XOR_MAPPED], tid, xor=True)}
    # RFC 5780 OTHER-ADDRESS is MAPPED-ADDRESS format, never XOR format.
    for kind, key in ((OTHER, "other"), (ORIGIN, "origin")):
        if kind in attrs:
            result[key] = decode_address(attrs[kind], tid, xor=False)
    return result


async def resolve_observer(value: str, family=socket.AF_INET) -> tuple[str, int]:
    host, port = value.rsplit(":", 1)
    host = host.strip("[]")
    rows = await asyncio.get_running_loop().getaddrinfo(
        host, int(port), family=family, type=socket.SOCK_DGRAM
    )
    return endpoint(rows[0][4][0], int(port))


class StunMixin:
    def init_stun(self):
        self.stun_pending = {}

    def receive_stun(self, data: bytes, addr: tuple) -> bool:
        if len(data) < 20 or data[4:8] != struct.pack("!I", COOKIE):
            return False
        pending = self.stun_pending.get(data[8:20])
        if pending:
            future, accepted = pending
            source = (addr[0], addr[1])
            if source in accepted and not future.done():
                future.set_result((data, source))
        return True

    async def binding(self, target: tuple[str, int], timeout=2.0, change=0, accept=()) -> dict:
        tid = secrets.token_bytes(12)
        body = attribute(CHANGE, struct.pack("!I", change)) if change else b""
        request = HEADER.pack(1, len(body), COOKIE, tid) + body
        future = asyncio.get_running_loop().create_future()
        self.stun_pending[tid] = (future, {target, *accept})
        deadline = asyncio.get_running_loop().time() + timeout
        try:
            for wait in (0.1, 0.2, 0.4, 0.8, 1.6):
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    break
                self.transport.sendto(request, sockaddr(target))
                try:
                    data, source = await asyncio.wait_for(asyncio.shield(future), min(wait, remaining))
                    return {**parse_response(data, tid), "source": source}
                except TimeoutError:
                    continue
            raise TimeoutError("STUN_TIMEOUT")
        finally:
            self.stun_pending.pop(tid, None)
            if not future.done():
                future.cancel()


class FilteringObserver(asyncio.DatagramProtocol, StunMixin):
    """RFC 5780 filtering must use state not opened by mapping probes."""

    def __init__(self):
        self.init_stun()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.receive_stun(data, addr)

    async def test(self, host, target):
        sock = new_socket(host, socket.SOCK_DGRAM)
        try:
            await asyncio.get_running_loop().create_datagram_endpoint(lambda: self, sock=sock)
            baseline = await self.binding(target, timeout=1)
            alternate = baseline.get("other")
            if not alternate or alternate[0] == target[0]:
                return {"behavior": "undetermined", "reason": "NO_OTHER_ADDRESS", "fresh_socket": True}
            behavior = "undetermined"
            try:
                changed = await self.binding(target, timeout=1, change=6, accept=(alternate,))
                behavior = ("endpoint-independent-observed" if changed["source"] == alternate
                            else "observer-does-not-honor-change-request")
            except TimeoutError:
                same_ip = (target[0], alternate[1])
                try:
                    changed = await self.binding(target, timeout=1, change=4, accept=(same_ip,))
                    behavior = ("address-dependent-or-change-ip-loss" if changed["source"] == same_ip
                                else "observer-does-not-honor-change-request")
                except TimeoutError:
                    await self.binding(target, timeout=1)
                    behavior = "address-and-port-dependent-or-network-loss"
            return {"behavior": behavior, "fresh_socket": True, "local": list(sock.getsockname()[:2]),
                    "observer": list(target), "alternate": list(alternate),
                    "evidence": "fresh-socket;no-direct-traffic-to-alternate-before-change-test;loss-not-excluded"}
        finally:
            if self.transport:
                self.transport.close()
            else:
                sock.close()


class StunServer(asyncio.DatagramProtocol):
    def __init__(self, journal, hub: dict, key: tuple[str, int], alternate: tuple[str, int] | None):
        self.journal, self.hub, self.key, self.alternate = journal, hub, key, alternate
        self.transport = None
        self.count = 0
        self.window = 0.0
        self.sources = {}

    def connection_made(self, transport):
        self.transport = transport
        self.hub[self.key] = self

    def datagram_received(self, data, addr):
        now = asyncio.get_running_loop().time()
        if now - self.window >= 1:
            self.window, self.count, self.sources = now, 0, {}
        self.count += 1
        self.sources[addr[0]] = self.sources.get(addr[0], 0) + 1
        if self.count > 1000 or self.sources[addr[0]] > 80:
            return
        try:
            if len(data) > 1024 or len(data) < 20:
                return
            tid = data[8:20]
            attrs = attributes(data, tid, kind=1)
            change = struct.unpack("!I", attrs[CHANGE])[0] if CHANGE in attrs else 0
            if change & ~6:
                return
            host, port = self.key
            if change & 2:
                if not self.alternate:
                    return
                host = self.alternate[0]
            if change & 4:
                if not self.alternate:
                    return
                port = self.alternate[1]
            sender = self.hub.get((host, port))
            if not sender:
                return
            response = attribute(XOR_MAPPED, address_value((addr[0], addr[1]), tid, xor=True))
            if self.alternate:
                response += attribute(OTHER, address_value(self.alternate, tid, xor=False))
            # A wildcard listener is not an externally meaningful RESPONSE-ORIGIN.
            if not ipaddress.ip_address(host).is_unspecified:
                response += attribute(ORIGIN, address_value((host, port), tid, xor=False))
            sender.transport.sendto(HEADER.pack(0x0101, len(response), COOKIE, tid) + response, addr)
            self.journal.event(
                "stun.binding", source=[addr[0], addr[1]], observer=[host, port], change=change
            )
        except (ValueError, struct.error):
            self.journal.event("stun.rejected", level="WARNING", source=addr[0])
