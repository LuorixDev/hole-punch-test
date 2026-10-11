"""Explicit opt-in gateway candidates. No discovery and no auto mapping at startup.

All mappings are unverified until an independent direct-peer external validator
succeeds. A loopback mock is protocol evidence, never router/NAT evidence.
"""
import asyncio
import ipaddress
import secrets
import socket
import struct
import sys
import time
import urllib.parse
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from xml.sax.saxutils import escape
import aiohttp
from .stun import canonical_endpoint


@dataclass(frozen=True)
class GatewayPolicy:
    gateway: str
    local_address: str
    enabled: bool = False
    mock_loopback: bool = False
    port: int = 5351
    timeout: float = 1.0

    def validate(self):
        if not self.enabled:
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        if not 1 <= self.port <= 65535 or not 0 < self.timeout <= 4:
            raise ValueError("INVALID_GATEWAY_BUDGET")
        gateway, local = ipaddress.ip_address(self.gateway), ipaddress.ip_address(self.local_address)
        if gateway.is_multicast or gateway.is_unspecified or local.is_unspecified or gateway.version != local.version:
            raise ValueError("INVALID_LOCAL_GATEWAY")
        if gateway.is_loopback:
            if self.mock_loopback and local.is_loopback:
                return
            raise PermissionError("MOCK_GATEWAY_NOT_AUTHORIZED")
        if self.mock_loopback:
            raise PermissionError("MOCK_MUST_BE_LOOPBACK")
        if sys.platform != "linux" or gateway.is_link_local:
            raise NotImplementedError("LOCAL_GATEWAY_VALIDATION_UNAVAILABLE")
        # Read-only OS routing evidence; no shell, route mutation, or trusting an arbitrary URL.
        if gateway.version == 4:
            routes = Path("/proc/net/route").read_text().splitlines()[1:]
            expected = socket.inet_aton(str(gateway))[::-1].hex().upper()
            valid = any(len(fields := row.split()) > 3 and fields[2] == expected and int(fields[3], 16) & 2 for row in routes)
        else:
            routes = Path("/proc/net/ipv6_route").read_text().splitlines()
            valid = any(len(fields := row.split()) >= 10 and fields[4] == gateway.packed.hex()
                        and int(fields[8], 16) & 2 for row in routes)
        if not valid:
            raise PermissionError("NOT_LOCAL_ROUTED_GATEWAY")
        # Binding proves this source address actually belongs to the host.
        probe = socket.socket(socket.AF_INET if local.version == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            probe.bind((str(local), 0))
        finally:
            probe.close()


@dataclass
class Lease:
    protocol: str
    internal_port: int
    external_port: int
    external_address: str | None
    lifetime: int
    created: float
    verified: bool = False
    nonce: bytes | None = None
    unique_id: str | None = None


class Gateway:
    def __init__(self, policy):
        self.policy = policy
        self.leases = []
        self.lock = asyncio.Lock()

    def check(self, internal, external, lifetime):
        self.policy.validate()
        if not 1 <= internal <= 65535 or not 0 <= external <= 65535 or not 0 <= lifetime <= 7200:
            raise ValueError("INVALID_MAPPING_REQUEST")
        if len(self.leases) >= 8 and lifetime:
            raise ValueError("MAPPING_LIMIT")

    async def exchange(self, data):
        self.policy.validate()
        family = socket.AF_INET6 if ":" in self.policy.gateway else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        sock.bind((self.policy.local_address, 0))
        remote = canonical_endpoint((self.policy.gateway, self.policy.port), family)
        loop = asyncio.get_running_loop()
        try:
            for multiplier in [1, 2, 4]:
                await loop.sock_sendto(sock, data, remote)
                deadline = time.monotonic() + min(4, self.policy.timeout * multiplier)
                while time.monotonic() < deadline:
                    try:
                        reply, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), deadline - time.monotonic())
                    except asyncio.TimeoutError:
                        break
                    try:
                        if canonical_endpoint(addr, family) == remote:
                            return reply
                    except ValueError:
                        continue
            raise TimeoutError("GATEWAY_TIMEOUT")
        finally:
            sock.close()

    async def verify(self, lease, validator):
        # Refuse unlimited, expired or arbitrarily huge router-granted lifetimes.
        if not 1 <= lease.lifetime <= 7200:
            await self.release(lease)
            raise ValueError("INVALID_GRANTED_LEASE")
        # validator must perform authenticated direct data/nonce exchange from an external peer.
        if validator is None:
            await self.release(lease)
            raise ValueError("EXTERNAL_VALIDATION_REQUIRED")
        try:
            valid = await asyncio.wait_for(validator(lease), 10)
            if valid is not True:
                raise ValueError("EXTERNAL_VALIDATION_FAILED")
        except BaseException:
            await self.release(lease)
            raise
        lease.verified = True
        self.leases.append(lease)
        return lease

    async def close(self):
        failures = []
        for lease in list(self.leases):
            try:
                await self.release(lease)
            except Exception:
                failures.append("MAPPING_RELEASE_FAILED")
        return failures


class PCP(Gateway):
    @staticmethod
    def encode(local, internal, external, lifetime, nonce, protocol=17):
        address = ipaddress.ip_address(local)
        if address.version == 4:
            address = ipaddress.IPv6Address("::ffff:" + str(address))
        return (struct.pack("!BBHI16s", 2, 1, 0, lifetime, address.packed) +
                struct.pack("!12sB3xHH16s", nonce, protocol, internal, external, b"\0" * 16))

    @staticmethod
    def decode(reply, internal, nonce):
        if len(reply) != 60 or reply[0] != 2 or reply[1] != 0x81:
            raise ValueError("PCP_INVALID_REPLY")
        if reply[3] != 0:
            raise ValueError("PCP_RESULT_" + str(reply[3]))
        lifetime = struct.unpack("!I", reply[4:8])[0]
        got_nonce, protocol, inport, export, address = struct.unpack("!12sB3xHH16s", reply[24:60])
        if got_nonce != nonce or protocol != 17 or inport != internal or not export:
            raise ValueError("PCP_TRANSACTION_MISMATCH")
        addr = ipaddress.IPv6Address(address)
        return lifetime, export, str(addr.ipv4_mapped or addr)

    async def map(self, internal, external=0, lifetime=120, validator=None):
        self.check(internal, external, lifetime)
        if lifetime < 30:
            raise ValueError("LEASE_TOO_SHORT")
        async with self.lock:
            nonce = secrets.token_bytes(12)
            reply = await self.exchange(self.encode(self.policy.local_address, internal, external, lifetime, nonce))
            ttl, port, address = self.decode(reply, internal, nonce)
            lease = Lease("pcp", internal, port, address, ttl, time.monotonic(), nonce=nonce)
            return await self.verify(lease, validator)

    async def release(self, lease):
        reply = await self.exchange(self.encode(self.policy.local_address, lease.internal_port, lease.external_port, 0, lease.nonce))
        ttl, _, _ = self.decode(reply, lease.internal_port, lease.nonce)
        if ttl:
            raise ValueError("PCP_DELETE_REJECTED")
        lease.verified = False
        if lease in self.leases:
            self.leases.remove(lease)

    async def renew(self, lease, validator, lifetime=120):
        self.check(lease.internal_port, lease.external_port, lifetime)
        reply = await self.exchange(self.encode(self.policy.local_address, lease.internal_port, lease.external_port, lifetime, lease.nonce))
        lease.lifetime, lease.external_port, lease.external_address = self.decode(reply, lease.internal_port, lease.nonce)
        if lease in self.leases:
            self.leases.remove(lease)
        lease.verified = False
        lease.created = time.monotonic()
        return await self.verify(lease, validator)


class NATPMP(Gateway):
    @staticmethod
    def encode(internal, external, lifetime):
        return struct.pack("!BBHHHI", 0, 1, 0, internal, external, lifetime)

    @staticmethod
    def decode(reply, internal):
        if len(reply) != 16:
            raise ValueError("NATPMP_INVALID_REPLY")
        version, opcode, result, epoch, inport, export, ttl = struct.unpack("!BBHIHHI", reply)
        if version != 0 or opcode != 129 or inport != internal or not export:
            raise ValueError("NATPMP_TRANSACTION_MISMATCH")
        if result:
            raise ValueError("NATPMP_RESULT_" + str(result))
        return export, ttl

    async def map(self, internal, external=0, lifetime=120, validator=None):
        self.check(internal, external, lifetime)
        if ":" in self.policy.gateway:
            raise ValueError("NATPMP_IPV4_ONLY")
        if lifetime < 30:
            raise ValueError("LEASE_TOO_SHORT")
        async with self.lock:
            reply = await self.exchange(b"\x00\x00")
            if len(reply) != 12 or reply[:4] != b"\x00\x80\x00\x00":
                raise ValueError("NATPMP_ADDRESS_FAILED")
            address = socket.inet_ntoa(reply[8:12])
            reply = await self.exchange(self.encode(internal, external, lifetime))
            port, ttl = self.decode(reply, internal)
            lease = Lease("natpmp", internal, port, address, ttl, time.monotonic())
            return await self.verify(lease, validator)

    async def release(self, lease):
        reply = await self.exchange(self.encode(lease.internal_port, lease.external_port, 0))
        _, ttl = self.decode(reply, lease.internal_port)
        if ttl:
            raise ValueError("NATPMP_DELETE_REJECTED")
        lease.verified = False
        if lease in self.leases:
            self.leases.remove(lease)

    async def renew(self, lease, validator, lifetime=120):
        self.check(lease.internal_port, lease.external_port, lifetime)
        reply = await self.exchange(self.encode(lease.internal_port, lease.external_port, lifetime))
        lease.external_port, lease.lifetime = self.decode(reply, lease.internal_port)
        if lease in self.leases:
            self.leases.remove(lease)
        lease.verified = False
        lease.created = time.monotonic()
        return await self.verify(lease, validator)


class UPnP(Gateway):
    SERVICES = {"urn:schemas-upnp-org:service:WANIPConnection:1", "urn:schemas-upnp-org:service:WANIPConnection:2",
                "urn:schemas-upnp-org:service:WANPPPConnection:1", "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1"}

    def __init__(self, policy, control_url, service):
        super().__init__(policy)
        self.url, self.service = control_url, service
        self.validate_url()

    def validate_url(self):
        url = urllib.parse.urlsplit(self.url)
        if (url.scheme != "http" or url.hostname != self.policy.gateway or url.username or url.password
                or url.fragment or self.service not in self.SERVICES):
            raise ValueError("UNTRUSTED_GATEWAY_CONTROL_URL")

    async def soap(self, action, arguments):
        self.policy.validate()
        self.validate_url()
        body = ('<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
                's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
                f'<u:{action} xmlns:u="{self.service}">' +
                ''.join(f'<{key}>{escape(str(value))}</{key}>' for key, value in arguments.items()) +
                f'</u:{action}></s:Body></s:Envelope>')
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=3), trust_env=False) as session:
            async with session.post(self.url, data=body, headers={"SOAPAction": f'"{self.service}#{action}"',
                                    "Content-Type": 'text/xml; charset="utf-8"'}, allow_redirects=False) as response:
                raw = await response.content.read(32769)
                if len(raw) > 32768 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                    raise ValueError("UPNP_XML_LIMIT")
                if response.status != 200:
                    raise ValueError("UPNP_ACTION_FAILED")
                root = ET.fromstring(raw)
                values = {element.tag.split("}")[-1]: element.text for element in root.iter()}
                if "Fault" in values or "errorCode" in values:
                    raise ValueError("UPNP_SOAP_FAULT")
                return values

    async def map(self, internal, external, lifetime=120, validator=None):
        self.check(internal, external, lifetime)
        if lifetime < 30 or external == 0 or "IPv6" in self.service:
            raise ValueError("INVALID_MAPPING_REQUEST")
        async with self.lock:
            address = (await self.soap("GetExternalIPAddress", {})).get("NewExternalIPAddress")
            ipaddress.IPv4Address(address)
            await self.soap("AddPortMapping", {"NewRemoteHost": "", "NewExternalPort": external,
                "NewProtocol": "UDP", "NewInternalPort": internal, "NewInternalClient": self.policy.local_address,
                "NewEnabled": 1, "NewPortMappingDescription": "p2pobs", "NewLeaseDuration": lifetime})
            lease = Lease("upnp", internal, external, address, lifetime, time.monotonic())
            return await self.verify(lease, validator)

    async def pinhole(self, internal, remote_address, remote_port, lifetime=120, validator=None):
        self.check(internal, internal, lifetime)
        if "IPv6FirewallControl" not in self.service or lifetime < 30:
            raise ValueError("UPNP_PINHOLE_UNSUPPORTED")
        remote = ipaddress.IPv6Address(remote_address)
        local = ipaddress.IPv6Address(self.policy.local_address)
        if remote.is_multicast or remote.is_unspecified or local.is_unspecified or not 1 <= remote_port <= 65535:
            raise ValueError("INVALID_PINHOLE")
        status = await self.soap("GetFirewallStatus", {})
        if status.get("InboundPinholeAllowed") != "1":
            raise ValueError("UPNP_PINHOLE_NOT_ALLOWED")
        result = await self.soap("AddPinhole", {"RemoteHost": str(remote), "RemotePort": remote_port,
            "InternalClient": str(local), "InternalPort": internal, "Protocol": 17, "LeaseTime": lifetime})
        unique = result.get("UniqueID")
        if unique is None or not unique.isdigit() or not 0 <= int(unique) <= 65535:
            raise ValueError("UPNP_INVALID_PINHOLE_ID")
        lease = Lease("upnp-pinhole", internal, internal, str(local), lifetime, time.monotonic(), unique_id=unique)
        return await self.verify(lease, validator)

    async def release(self, lease):
        if lease.unique_id is not None:
            await self.soap("DeletePinhole", {"UniqueID": lease.unique_id})
        else:
            await self.soap("DeletePortMapping", {"NewRemoteHost": "", "NewExternalPort": lease.external_port, "NewProtocol": "UDP"})
        lease.verified = False
        if lease in self.leases:
            self.leases.remove(lease)

    async def renew(self, lease, validator, lifetime=120):
        self.check(lease.internal_port, lease.external_port, lifetime)
        if lease.unique_id is not None:
            await self.soap("UpdatePinhole", {"UniqueID": lease.unique_id, "NewLeaseTime": lifetime})
        else:
            await self.soap("AddPortMapping", {"NewRemoteHost": "", "NewExternalPort": lease.external_port,
                "NewProtocol": "UDP", "NewInternalPort": lease.internal_port,
                "NewInternalClient": self.policy.local_address, "NewEnabled": 1,
                "NewPortMappingDescription": "p2pobs", "NewLeaseDuration": lifetime})
        if lease in self.leases:
            self.leases.remove(lease)
        lease.lifetime, lease.created, lease.verified = lifetime, time.monotonic(), False
        return await self.verify(lease, validator)
