"""RFC5389 Binding from the SAME explicitly supplied socket.

IPv4 mapped-address observation is NOT exact NAT classification. IPv6 stateful
firewall traversal uses peer bidirectional probes, not an assumption of NAT.
Call before the adapter's receive loop; never run competing readers on a socket.
"""
import asyncio
import ipaddress
import secrets
import socket
import struct
import time

COOKIE = 0x2112A442


def parse_binding(data, transaction):
    if len(data) < 20:
        raise ValueError("STUN_TRUNCATED")
    kind, size, cookie, tid = struct.unpack("!HHI12s", data[:20])
    if kind != 0x0101 or cookie != COOKIE or tid != transaction or size != len(data)-20 or size % 4:
        raise ValueError("STUN_TRANSACTION_MISMATCH")
    pos = 20
    while pos < len(data):
        atype, length = struct.unpack("!HH", data[pos:pos+4])
        value = data[pos+4:pos+4+length]
        if len(value) != length:
            raise ValueError("STUN_TRUNCATED")
        pos += 4 + ((length + 3) // 4) * 4
        if atype == 0x0020:
            if length not in {8, 20} or value[0] != 0 or value[1] not in {1, 2}:
                raise ValueError("STUN_INVALID_ADDRESS")
            if length != (8 if value[1] == 1 else 20):
                raise ValueError("STUN_INVALID_ADDRESS")
            port = struct.unpack("!H", value[2:4])[0] ^ (COOKIE >> 16)
            mask = struct.pack("!I", COOKIE) + transaction
            address = ipaddress.ip_address(bytes(a ^ b for a, b in zip(value[4:], mask)))
            if not port:
                raise ValueError("STUN_INVALID_PORT")
            return str(address), port
    raise ValueError("STUN_NO_XOR_MAPPED_ADDRESS")


async def binding(sock, server, timeout=2):
    """An explicit STUN server only; no scan/discovery. Does not close caller socket."""
    address = ipaddress.ip_address(server[0])
    if address.is_multicast or address.is_unspecified or not 1 <= server[1] <= 65535:
        raise ValueError("INVALID_STUN_SERVER")
    tid = secrets.token_bytes(12)
    request = struct.pack("!HHI12s", 1, 0, COOKIE, tid)
    loop, start = asyncio.get_running_loop(), time.monotonic()
    for wait in [.1, .2, .4, .8, 1.6]:
        remaining = timeout - (time.monotonic()-start)
        if remaining <= 0:
            break
        await loop.sock_sendto(sock, request, server)
        deadline = time.monotonic() + min(wait, remaining)
        while time.monotonic() < deadline:
            try:
                packet, remote = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), deadline-time.monotonic())
            except asyncio.TimeoutError:
                break
            if remote[:2] != tuple(server):
                continue
            try:
                mapped = parse_binding(packet, tid)
            except ValueError:
                continue
            return {"address": mapped[0], "port": mapped[1], "family": ipaddress.ip_address(mapped[0]).version,
                    "rttMs": (time.monotonic()-start)*1000,
                    "observation": "mapped-address-only-not-nat-type"}
    raise TimeoutError("STUN_TIMEOUT")
