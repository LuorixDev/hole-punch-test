from __future__ import annotations

import asyncio
import ipaddress
import socket

from .common import endpoint
from .stun import resolve_observer
from .udp import UdpAttempt

LENGTHS = (32, 40, 48, 56, 64, 96)


def synthesize(prefix, address):
    network = ipaddress.IPv6Network(prefix)
    if network.prefixlen not in LENGTHS:
        raise ValueError("NAT64_PREFIX_LENGTH")
    raw = bytearray(network.network_address.packed)
    positions = list(range(network.prefixlen // 8, 16))
    if network.prefixlen != 96:
        positions.remove(8)  # RFC 6052 reserved u octet.
    for position, byte in zip(positions, ipaddress.IPv4Address(address).packed, strict=False):
        raw[position] = byte
    return str(ipaddress.IPv6Address(bytes(raw)))


def discover_prefixes(addresses):
    found = {}
    for address in addresses:
        ip = ipaddress.IPv6Address(address)
        for length in LENGTHS:
            prefix = str(ipaddress.IPv6Network((ip, length), strict=False))
            for well_known in ("192.0.0.170", "192.0.0.171"):
                if synthesize(prefix, well_known) == str(ip):
                    found.setdefault(prefix, set()).add(well_known)
    return sorted(prefix for prefix, matches in found.items() if len(matches) == 2)


async def resolve_prefixes():
    rows = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
        "ipv4only.arpa", 0, family=socket.AF_INET6, type=socket.SOCK_DGRAM), 3)
    return discover_prefixes([row[4][0] for row in rows])


class Nat64Attempt(UdpAttempt):
    def __init__(self, owner, spec, host):
        super().__init__(owner, spec, host)
        self.prefixes = []
        self.pending_candidates = None

    async def observe(self, observers):
        if ":" not in self.host:
            return await super().observe(observers)
        configured = self.owner.config.get("experiment", {}).get("nat64_prefixes", [])
        if configured:
            self.prefixes = [str(ipaddress.IPv6Network(prefix)) for prefix in configured[:4]]
            for prefix in self.prefixes:
                synthesize(prefix, "192.0.0.170")
        else:
            try:
                self.prefixes = await resolve_prefixes()
            except (OSError, TimeoutError):
                self.prefixes = []
        self.owner.log.event("nat64.prefix", attempt=self.attempt, prefixes=self.prefixes,
                             source="configured" if configured else "RFC7050-DNS64-paired-answers")
        if not self.prefixes:
            raise ValueError("NAT64_PREFIX_UNAVAILABLE")
        if self.pending_candidates is not None:
            self.set_candidates(self.pending_candidates)
        samples = []
        for observer in observers[:4]:
            try:
                ip, port = await asyncio.wait_for(resolve_observer(observer), 3)
                for prefix in self.prefixes:
                    target = (synthesize(prefix, ip), port)
                    result = await self.binding(target, timeout=1.5)
                    mapped = list(result["mapped"])
                    if mapped not in self.candidates:
                        self.candidates.append(mapped)
                    samples.append({"observer": target, "mapped": mapped, "prefix": prefix})
                    self.owner.log.event("nat64.mapping", attempt=self.attempt, **samples[-1])
            except (OSError, ValueError, TimeoutError) as exc:
                self.owner.log.event("nat64.observer_failed", str(exc), "WARNING", attempt=self.attempt)
        if not any(ipaddress.ip_address(item[0]).version == 4 for item in self.candidates):
            raise ValueError("NAT64_IPV4_MAPPING_UNAVAILABLE")
        return samples

    def set_candidates(self, candidates):
        if not isinstance(candidates, list) or len(candidates) > 256:
            raise ValueError("NAT64_CANDIDATE_LIMIT")
        checked = [endpoint(*item) for item in candidates]
        if ":" in self.host and not self.prefixes:
            self.pending_candidates = candidates
            return
        converted = []
        for address, port in checked:
            if ipaddress.ip_address(address).version != 4:
                continue
            if ":" in self.host:
                converted.extend([synthesize(prefix, address), port] for prefix in self.prefixes)
            else:
                converted.append([address, port])
        if not converted:
            raise ValueError("NAT64_NO_IPV4_CANDIDATES")
        super().set_candidates(converted[:256])
