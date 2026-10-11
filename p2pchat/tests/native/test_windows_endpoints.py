"""Endpoint-format regression tests run on Linux AND real Windows CI.
Expanded sockaddr injection changes formatting only; sockets/data remain real.
The raw loopback test prints bounded test-address metadata under pytest -s.
"""
import asyncio
import base64
import ipaddress
import json
import os
import socket
import struct
import sys

import pytest
from p2pchat.native.adapter import validate_candidate
from p2pchat.native.stun import canonical_endpoint, socket_address, binding, COOKIE
from p2pchat.native.gateway import Gateway, GatewayPolicy
from .test_transport import pair, wait_states


@pytest.mark.parametrize("address", ["::1", "0:0:0:0:0:0:0:1", "0000:0000:0000:0000:0000:0000:0000:0001", "::1%0"])
def test_equivalent_ipv6_and_flowinfo(address):
    assert canonical_endpoint((address, 1234, 99, 0), socket.AF_INET6) == ("::1", 1234)
    assert canonical_endpoint((address, 1234), socket.AF_INET6) == ("::1", 1234)


def test_endpoint_identity_and_scope_boundaries():
    assert canonical_endpoint(("2001:DB8:0:0:0:0:0:A", 443)) == ("2001:db8::a", 443)
    assert canonical_endpoint(("::2", 1234)) != canonical_endpoint(("::1", 1234))
    assert canonical_endpoint(("::1", 1235)) != canonical_endpoint(("::1", 1234))
    assert canonical_endpoint(("::ffff:127.0.0.1", 1234)) != canonical_endpoint(("127.0.0.1", 1234))
    for address in [("::1", 1234, 0, 2), ("::1%2", 1234), ("fe80::1%2", 1234, 0, 2),
                    ("ff02::1", 1234), ("::", 1234), ("224.0.0.1", 1234),
                    ("127.0.0.1", 0), ("127.0.0.1", True), ("localhost", 1234)]:
        with pytest.raises(ValueError):
            canonical_endpoint(address)
    with pytest.raises(ValueError, match="FAMILY_MISMATCH"):
        canonical_endpoint(("::ffff:127.0.0.1", 1234), socket.AF_INET)
    with pytest.raises(ValueError, match="FAMILY_MISMATCH"):
        canonical_endpoint(("127.0.0.1", 1234), socket.AF_INET6)
    for address in ["::1%2", "fe80::1", "ff02::1"]:
        with pytest.raises(ValueError):
            validate_candidate(dict(id="x", family=6, transport="udp", address=address, port=1234, kind="host", socketId="x"))


def expanded_sockaddr(addr):
    if ipaddress.ip_address(addr[0]).version != 6:
        return addr
    return (ipaddress.ip_address(addr[0].split('%')[0]).exploded, addr[1], 37, addr[3] if len(addr) == 4 else 0)


def inject_expanded_sockaddrs(monkeypatch):
    loop = asyncio.get_running_loop()
    receive, accept = loop.sock_recvfrom, loop.sock_accept
    async def expanded_receive(sock, size):
        data, addr = await receive(sock, size)
        return data, expanded_sockaddr(addr)
    async def expanded_accept(sock):
        connected, addr = await accept(sock)
        return connected, expanded_sockaddr(addr)
    monkeypatch.setattr(loop, "sock_recvfrom", expanded_receive)
    monkeypatch.setattr(loop, "sock_accept", expanded_accept)


@pytest.mark.asyncio
@pytest.mark.parametrize("mechanism", ["udp-probe", "quic", "tcp"])
async def test_real_ipv6_transports_with_expanded_kernel_address(monkeypatch, mechanism):
    inject_expanded_sockaddrs(monkeypatch)
    a, b, aid, ea, eb = await pair(mechanism, "::1")
    try:
        assert await wait_states(a, b, aid) == ["direct", "direct"], [x.attempts[aid].stats() for x in [a, b]]
        assert all(x.attempts[aid].remote[0] == "::1" for x in [a, b])
        if mechanism == "udp-probe":
            assert all(x.attempts[aid].auth.direct for x in [a, b])
            return
        payload = os.urandom(65536)
        for x in [a, b]:
            await x.send(dict(attemptId=aid, lane="chat", data=payload))
        async with asyncio.timeout(5):
            while not all(any(kind == "data" for kind, _ in events) for events in [ea, eb]):
                await asyncio.sleep(.01)
        for events in [ea, eb]:
            assert base64.b64decode(next(e['dataB64'] for k, e in events if k == 'data')) == payload
    finally:
        await a.shutdown()
        await b.shutdown()


@pytest.mark.asyncio
async def test_actual_loopback_sockaddr_diagnostic():
    """Do not skip: prints only test ::1 tuples and OS error numbers on failure."""
    loop = asyncio.get_running_loop()
    sockets = []
    try:
        for _ in range(2):
            sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
            sockets.append(sock)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setblocking(False)
            sock.bind(("::1", 0))
        target = ("::1", sockets[1].getsockname()[1])
        await loop.sock_sendto(sockets[0], b"native-ipv6-loopback", socket_address(target, socket.AF_INET6))
        data, addr = await asyncio.wait_for(loop.sock_recvfrom(sockets[1], 128), 3)
        assert data == b"native-ipv6-loopback"
        assert canonical_endpoint(addr, socket.AF_INET6) == ("::1", sockets[0].getsockname()[1])
        print(json.dumps({"diag": "native-ipv6-loopback", "platform": sys.platform,
                          "loop": type(loop).__name__, "sockaddr": list(addr),
                          "canonical": list(canonical_endpoint(addr)), "tupleLength": len(addr)}))
    except OSError as exc:
        print(json.dumps({"diag": "native-ipv6-loopback-error", "platform": sys.platform,
                          "errorClass": type(exc).__name__, "errno": exc.errno,
                          "winerror": getattr(exc, "winerror", None)}))
        raise
    finally:
        for sock in sockets:
            sock.close()


class IPv6StunResponder(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        tid = data[8:20]
        address = ipaddress.IPv6Address(addr[0]).packed
        mask = struct.pack("!I", COOKIE) + tid
        value = struct.pack("!BBH", 0, 2, addr[1] ^ (COOKIE >> 16)) + bytes(a ^ b for a, b in zip(address, mask))
        reply = struct.pack("!HHI12sHH", 0x101, 24, COOKIE, tid, 0x20, 20) + value
        self.transport.sendto(reply, addr)


@pytest.mark.asyncio
async def test_ipv6_stun_and_gateway_source_comparison(monkeypatch):
    inject_expanded_sockaddrs(monkeypatch)
    loop = asyncio.get_running_loop()
    transport, _ = await loop.create_datagram_endpoint(IPv6StunResponder, local_addr=("::1", 0))
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(("::1", 0))
    try:
        observed = await binding(sock, ("0:0:0:0:0:0:0:1", transport.get_extra_info('sockname')[1]))
        assert observed['address'] == '::1' and observed['port'] == sock.getsockname()[1]
        # Uses identical exact-source receive logic without performing a mapping.
        gateway = Gateway(GatewayPolicy("0:0:0:0:0:0:0:1", "::1", enabled=True, mock_loopback=True,
            port=transport.get_extra_info('sockname')[1]))
        reply = await gateway.exchange(struct.pack('!HHI12s', 1, 0, COOKIE, b'x'*12))
        assert reply[8:20] == b'x'*12
    finally:
        sock.close()
        transport.close()
