import asyncio
import socket

import pytest

from p2plab.common import new_socket
from p2plab.stun import COOKIE, HEADER, StunServer
from p2plab.udp import UdpAttempt

SECOND_LOOPBACK = "127.0.0.2"


def second_loopback_available():
    """Report whether this host has a second address inside 127.0.0.0/8.

    Linux makes the whole range local, so 127.0.0.2 is bindable there. macOS and Windows configure
    only 127.0.0.1, and a changed-source observer cannot be simulated without a second local address.
    """
    probe = socket.socket()
    try:
        probe.bind((SECOND_LOOPBACK, 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


requires_second_loopback = pytest.mark.skipif(
    not second_loopback_available(),
    reason=f"{SECOND_LOOPBACK} is not a local address on this platform",
)


class IgnoringChangeServer(StunServer):
    def datagram_received(self, data, addr):
        if len(data) >= 20:
            data = HEADER.pack(1, 0, COOKIE, data[8:20])
        super().datagram_received(data, addr)


@requires_second_loopback
async def test_fresh_filtering_socket_avoids_own_mapping_traffic_contamination(peers):
    a, _ = peers
    contacted, traces, hub, transports = {}, [], {}, []

    class FilteringTransport:
        def __init__(self, transport, key):
            self.transport, self.key = transport, key

        def sendto(self, data, remote):
            if self.key in contacted.get(remote[:2], set()):
                self.transport.sendto(data, remote)

    class Restricted(StunServer):
        def connection_made(self, transport):
            super().connection_made(transport)
            self.transport = FilteringTransport(transport, self.key)

        def datagram_received(self, data, source):
            contacted.setdefault(source[:2], set()).add(self.key)
            traces.append((source[:2], self.key))
            super().datagram_received(data, source)

    sockets = [new_socket("127.0.0.1", socket.SOCK_DGRAM) for _ in range(2)]
    ports = [sock.getsockname()[1] for sock in sockets]
    sockets += [new_socket("127.0.0.2", socket.SOCK_DGRAM, port) for port in ports]
    udp = UdpAttempt(a, {"attempt": "contaminated-filter"}, "127.0.0.1")
    try:
        for sock in sockets:
            host, port = sock.getsockname()[:2]
            alternate = ("127.0.0.2" if host == "127.0.0.1" else "127.0.0.1",
                         ports[1] if port == ports[0] else ports[0])
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda h=host, p=port, alt=alternate: Restricted(a.log, hub, (h, p), alt), sock=sock)
            transports.append(transport)
        await udp.open()
        await udp.observe([f"127.0.0.1:{ports[0]}"])
        evidence = next(row["fields"] for row in a.log.query() if row["event"] == "nat.filtering")
        assert evidence["fresh_socket"] and evidence["local"] != udp.candidates[0]
        assert evidence["behavior"] == "address-and-port-dependent-or-network-loss"
        filtered_source = tuple(evidence["local"])
        assert {target for source, target in traces if source == filtered_source} == {("127.0.0.1", ports[0])}
        assert any(target[0] == "127.0.0.2" for source, target in traces if list(source) == udp.candidates[0])
    finally:
        await udp.close()
        for transport in transports:
            transport.close()
        for sock in sockets:
            sock.close()


@requires_second_loopback
@pytest.mark.parametrize("ignore_change", [False, True])
async def test_four_observers_and_change_source_validation(peers, ignore_change):
    a, _ = peers
    transports, hub = [], {}
    sockets = [new_socket("127.0.0.1", socket.SOCK_DGRAM) for _ in range(2)]
    ports = [sock.getsockname()[1] for sock in sockets]
    for port in ports:
        sockets.append(new_socket("127.0.0.2", socket.SOCK_DGRAM, port))
    cls = IgnoringChangeServer if ignore_change else StunServer
    udp = UdpAttempt(a, {"attempt": "stun-source-validation"}, "127.0.0.1")
    try:
        for sock in sockets:
            host, port = sock.getsockname()[:2]
            alt = (
                "127.0.0.2" if host == "127.0.0.1" else "127.0.0.1",
                ports[1] if port == ports[0] else ports[0],
            )
            transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda h=host, p=port, alt=alt: cls(a.log, hub, (h, p), alt), sock=sock
            )
            transports.append(transport)
        await udp.open()
        await udp.observe([f"127.0.0.1:{ports[0]}"])
        filtering = [record for record in a.log.query() if record["event"] == "nat.filtering"]
        assert filtering
        expected = (
            "observer-does-not-honor-change-request" if ignore_change else "endpoint-independent-observed"
        )
        assert filtering[-1]["fields"]["behavior"] == expected
    finally:
        await udp.close()
        for transport in transports:
            transport.close()
        for sock in sockets:
            sock.close()
