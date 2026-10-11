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


def canonical_endpoint(endpoint, family=None):
    """Canonical numeric socket tuple without weakening the signaling boundary.

    IPv6 flowinfo is not endpoint identity. The current candidate schema does
    NOT negotiate interface scopes: reject nonzero scopes rather than silently
    drop them. Windows can include a harmless %0 textual zone and/or a 4-tuple.
    Never equate IPv4 with IPv4-mapped IPv6 (different socket families).
    """
    if not isinstance(endpoint, (tuple, list)) or len(endpoint) not in {2, 4}:
        raise ValueError("INVALID_ENDPOINT")
    host, port = endpoint[:2]
    if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ValueError("INVALID_ENDPOINT")
    address = ipaddress.ip_address(host)
    if family is not None and address.version != (4 if family == socket.AF_INET else 6 if family == socket.AF_INET6 else 0):
        raise ValueError("ENDPOINT_FAMILY_MISMATCH")
    if address.version == 6:
        zone = address.scope_id
        if zone not in {None, "0"} or (len(endpoint) == 4 and endpoint[3] != 0):
            raise ValueError("ENDPOINT_SCOPE_UNNEGOTIATED")
        address = ipaddress.IPv6Address(address.packed)
    elif len(endpoint) != 2:
        raise ValueError("INVALID_ENDPOINT")
    if address.is_multicast or address.is_unspecified or address.is_link_local or str(address) == "255.255.255.255":
        raise ValueError("INVALID_ENDPOINT")
    return str(address), port


def socket_address(endpoint, family):
    """OS-call form, distinct from the public two-field identity.

    CPython 3.12 Windows overlapped.parse_address dispatches by tuple length:
    two fields select AF_INET, four select AF_INET6. Always supply four fields
    for IPv6, also on POSIX so the contract is exercised on every platform.
    """
    host, port = canonical_endpoint(endpoint, family)
    return (host, port, 0, 0) if family == socket.AF_INET6 else (host, port)


def udp_unreachable(exc):
    """An ICMP unreachable is no response, not evidence of a peer or a lease.

    Windows reports a UDP ICMP port-unreachable as WSAECONNRESET (10054), which
    CPython surfaces as ConnectionResetError. POSIX (Linux/macOS) reports the same
    condition as ECONNREFUSED / ConnectionRefusedError. Both are swallowed only on
    the UDP paths that call this predicate: TCP connect errors keep their meaning.
    Permission, routing and invalid-argument errors still propagate.
    """
    return (isinstance(exc, (ConnectionResetError, ConnectionRefusedError))
            or getattr(exc, "winerror", None) == 10054
            or getattr(exc, "errno", None) == 10054)


async def receive_udp_retry(sock, size):
    """Caller supplies its existing deadline/cancellation; never extends it.

    Throttle repeated immediately-completed ICMP failures instead of busy-looping.
    Other OS errors (including WSAEINVAL 10022) remain errors.
    """
    loop = asyncio.get_running_loop()
    while True:
        try:
            return await loop.sock_recvfrom(sock, size)
        except OSError as exc:
            if not udp_unreachable(exc):
                raise
            await asyncio.sleep(.01)


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
    server = canonical_endpoint(server, sock.family)
    tid = secrets.token_bytes(12)
    request = struct.pack("!HHI12s", 1, 0, COOKIE, tid)
    loop, start = asyncio.get_running_loop(), time.monotonic()
    for wait in [.1, .2, .4, .8, 1.6]:
        remaining = timeout - (time.monotonic()-start)
        if remaining <= 0:
            break
        try:
            await loop.sock_sendto(sock, request, socket_address(server, sock.family))
        except OSError as exc:
            if not udp_unreachable(exc):
                raise
        deadline = time.monotonic() + min(wait, remaining)
        while time.monotonic() < deadline:
            try:
                packet, remote = await asyncio.wait_for(receive_udp_retry(sock, 2048), deadline-time.monotonic())
            except asyncio.TimeoutError:
                break
            try:
                if canonical_endpoint(remote, sock.family) != server:
                    continue
            except ValueError:
                continue
            try:
                mapped = parse_binding(packet, tid)
            except ValueError:
                continue
            return {"address": mapped[0], "port": mapped[1], "family": ipaddress.ip_address(mapped[0]).version,
                    "rttMs": (time.monotonic()-start)*1000,
                    "observation": "mapped-address-only-not-nat-type"}
    raise TimeoutError("STUN_TIMEOUT")
