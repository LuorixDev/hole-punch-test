from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import struct
import sys

from cryptography.exceptions import InvalidSignature

from .common import Identity, endpoint, new_socket, packed
from .udp import UdpAttempt


class Discovery(asyncio.DatagramProtocol):
    def __init__(self, owner):
        self.owner = owner

    def datagram_received(self, data, source):
        if len(data) > 4096:
            return
        try:
            body = Identity.verify(json.loads(data), self.owner.peer["public"])
            if any(body.get(key) != value for key, value in (("v", 1), ("kind", "lan"),
                ("pair", self.owner.pair), ("attempt", self.owner.attempt),
                ("from", self.owner.peer["id"]), ("to", self.owner.local_id))):
                return
            candidate = endpoint(*body["endpoint"])
            self.owner.set_candidates([list(candidate)])
            self.owner.owner.log.event("lan.discovered", attempt=self.owner.attempt, source=list(source[:2]),
                                       candidate=candidate, evidence="paired-peer-signed-LAN-beacon")
        except (ValueError, KeyError, TypeError, InvalidSignature):
            return


class LanAttempt(UdpAttempt):
    def __init__(self, owner, spec, host):
        super().__init__(owner, spec, host)
        self.discovery_transport = None
        self.destinations = []

    async def discover(self, timeout):
        port = self.owner.config.get("experiment", {}).get("lan_port", 45555)
        endpoint("127.0.0.1", port)
        ipv6 = ":" in self.host
        # Winsock broadcasts fan out to SO_REUSEADDR listeners; TCP still requires SO_REUSEPORT.
        sock = new_socket("::" if ipv6 else "0.0.0.0", socket.SOCK_DGRAM, port,
                          reuse_port=sys.platform != "win32", reuse_address=True)
        try:
            records = self.owner.network.get("address_inventory", self.owner.network.get("addresses", []))
            record = next((r for r in records if r["address"] == self.host), {})
            if ipv6:
                index = socket.if_nametoindex(record.get("interface", "lo" if self.owner.loopback else ""))
                group = socket.inet_pton(socket.AF_INET6, "ff02::114")
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, group + struct.pack("@I", index))
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
                self.destinations = [("ff02::114", port, 0, index)]
            else:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                prefix = record.get("prefixlen", 8 if self.owner.loopback else 24)
                broadcast = str(ipaddress.ip_network(f"{self.host}/{prefix}", strict=False).broadcast_address)
                self.destinations = [(broadcast, port), ("255.255.255.255", port)]
            self.discovery_transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                lambda: Discovery(self), sock=sock)
            beacon = packed(self.owner.identity.sign({"kind": "lan", "v": 1, "pair": self.pair,
                "attempt": self.attempt, "from": self.local_id, "to": self.peer["id"], "endpoint": self.candidates[0]}))
            async with asyncio.timeout(timeout):
                while not self.candidates_ready.is_set():
                    for destination in self.destinations:
                        self.discovery_transport.sendto(beacon, destination)
                    try:
                        await asyncio.wait_for(self.candidates_ready.wait(), 0.25)
                    except TimeoutError:
                        continue
                # Give a peer which started later a chance to receive our signed reply.
                for destination in self.destinations:
                    self.discovery_transport.sendto(beacon, destination)
        finally:
            if not self.discovery_transport:
                sock.close()

    async def close(self):
        if self.discovery_transport:
            self.discovery_transport.close()
        await super().close()
