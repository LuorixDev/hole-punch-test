from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import struct
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urljoin, urlsplit

import aiohttp
from defusedxml import ElementTree as SafeET

from .common import endpoint, new_socket, sockaddr

PCP_PORT = 5351
LEASE_SECONDS = 120
SERVICES = {
    "urn:schemas-upnp-org:service:WANIPConnection:1",
    "urn:schemas-upnp-org:service:WANIPConnection:2",
    "urn:schemas-upnp-org:service:WANPPPConnection:1",
    "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
}


def validate_mapping(internal, external, lifetime, *, deletion=True):
    endpoint("127.0.0.1", internal)
    if isinstance(external, bool) or not isinstance(external, int) or not 0 <= external <= 65535:
        raise ValueError("INVALID_EXTERNAL_PORT")
    if (
        isinstance(lifetime, bool)
        or not isinstance(lifetime, int)
        or not (deletion and lifetime == 0 or 30 <= lifetime <= 7200)
    ):
        raise ValueError("INVALID_LEASE_LIFETIME")


def pcp_address(value):
    address = ipaddress.ip_address(value)
    return address.packed if address.version == 6 else b"\0" * 10 + b"\xff\xff" + address.packed


def pcp_request(local, internal, external, nonce, lifetime=LEASE_SECONDS, *, protocol=17,
                peer=None, filter_remote=None, prefer_failure=False):
    validate_mapping(internal, external, lifetime)
    if len(nonce) != 12:
        raise ValueError("PCP_NONCE_FORMAT")
    if protocol not in (6, 17) or peer and (filter_remote or prefer_failure):
        raise ValueError("PCP_PROTOCOL_OR_OPTION_INVALID")
    header = struct.pack("!BBHI16s", 2, 2 if peer else 1, 0, lifetime, pcp_address(local))
    data = header + struct.pack("!12sB3xHH16s", nonce, protocol, internal, external, bytes(16))
    if peer:
        endpoint(*peer)
        data += struct.pack("!H2x16s", peer[1], pcp_address(peer[0]))
    if filter_remote and lifetime:
        endpoint(*filter_remote)
        data += struct.pack("!BBHBBH16s", 3, 0, 20, 0, 128, filter_remote[1], pcp_address(filter_remote[0]))
    if prefer_failure and lifetime:
        data += struct.pack("!BBH", 2, 0, 0)
    return data


def parse_pcp(data, nonce, internal, *, deleting=False, protocol=17, peer=None):
    if len(data) < (80 if peer else 60) or data[0] != 2 or data[1] != (0x82 if peer else 0x81):
        raise ValueError("PCP_RESPONSE_FORMAT")
    if data[3]:
        raise ValueError(f"PCP_RESULT_{data[3]}")
    lifetime, epoch = struct.unpack_from("!II", data, 4)
    if data[24:36] != nonce or data[36] != protocol or struct.unpack_from("!H", data, 40)[0] != internal:
        raise ValueError("PCP_TRANSACTION_MISMATCH")
    if peer and (struct.unpack_from("!H", data, 60)[0] != peer[1] or data[64:80] != pcp_address(peer[0])):
        raise ValueError("PCP_PEER_MISMATCH")
    if deleting:
        if lifetime != 0:
            raise ValueError("PCP_DELETE_NOT_CONFIRMED")
        return {"lifetime": 0, "epoch": epoch}
    if not 30 <= lifetime <= 7200:
        raise ValueError("PCP_LIFETIME_INVALID")
    port = struct.unpack_from("!H", data, 42)[0]
    ip = ipaddress.IPv6Address(data[44:60])
    address = ip.ipv4_mapped or ip
    return {"external": endpoint(str(address), port), "lifetime": lifetime, "epoch": epoch}


def natpmp_request(internal, external, lifetime=LEASE_SECONDS, *, protocol=17):
    validate_mapping(internal, external, lifetime)
    if protocol not in (6, 17):
        raise ValueError("NATPMP_PROTOCOL_INVALID")
    return struct.pack("!BBHHHI", 0, 2 if protocol == 6 else 1, 0, internal, external, lifetime)


def parse_natpmp(data, internal, *, deleting=False, protocol=17):
    if len(data) != 16:
        raise ValueError("NATPMP_RESPONSE_LENGTH")
    version, opcode, result, epoch, actual_internal, external, lifetime = struct.unpack("!BBHIHHI", data)
    if version != 0 or opcode != (130 if protocol == 6 else 129) or actual_internal != internal:
        raise ValueError("NATPMP_TRANSACTION_MISMATCH")
    if result:
        raise ValueError(f"NATPMP_RESULT_{result}")
    if deleting:
        if lifetime != 0:
            raise ValueError("NATPMP_DELETE_NOT_CONFIRMED")
    elif not 30 <= lifetime <= 7200 or not external:
        raise ValueError("NATPMP_LIFETIME_OR_PORT_INVALID")
    return {"port": external, "lifetime": lifetime, "epoch": epoch}


async def gateway_datagram(gateway, local, request, *, timeout=2):
    sock = new_socket(local, socket.SOCK_DGRAM)
    loop = asyncio.get_running_loop()
    host, _, interface = gateway.partition("%")
    target = (
        (host, PCP_PORT, 0, socket.if_nametoindex(interface)) if interface else sockaddr((host, PCP_PORT))
    )
    try:
        deadline = loop.time() + timeout
        for wait in (0.25, 0.5, 1.0):
            await loop.sock_sendto(sock, request, target)
            end = min(deadline, loop.time() + wait)
            while loop.time() < end:
                try:
                    data, source = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), end - loop.time())
                    if source[:2] == (host, PCP_PORT):
                        return data
                except TimeoutError:
                    break
        raise TimeoutError("GATEWAY_NO_RESPONSE")
    finally:
        sock.close()


def safe_control_url(url, gateway):
    parts = urlsplit(url)
    if parts.scheme != "http" or parts.username or parts.password or parts.fragment:
        raise ValueError("UNTRUSTED_GATEWAY_URL")
    try:
        if ipaddress.ip_address(parts.hostname.split("%")[0]) != ipaddress.ip_address(gateway.split("%")[0]):
            raise ValueError("GATEWAY_HOST_MISMATCH")
        if parts.port is not None and not 1 <= parts.port <= 65535:
            raise ValueError("GATEWAY_PORT_INVALID")
    except (ValueError, TypeError):
        raise ValueError("UNTRUSTED_GATEWAY_URL") from None
    return url


async def bounded_response(response, limit=32768):
    data = bytearray()
    async for chunk in response.content.iter_chunked(4096):
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("GATEWAY_HTTP_RESPONSE_LIMIT")
    if b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
        raise ValueError("GATEWAY_XML_ENTITY_FORBIDDEN")
    return bytes(data)


class Upnp:
    def __init__(self, journal, gateway, local):
        self.log, self.gateway, self.local = journal, gateway, local
        self.services = []

    async def discover(self):
        sock = new_socket(self.local, socket.SOCK_DGRAM)
        loop = asyncio.get_running_loop()
        locations = set()
        try:
            ipv6 = ":" in self.local
            interface = self.gateway.partition("%")[2]
            if ipv6:
                if not interface:
                    raise ValueError("UPNP_IPV6_DISCOVERY_INTERFACE_UNAVAILABLE")
                index = socket.if_nametoindex(interface)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, index)
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
                destination, header_host = ("ff02::c", 1900, 0, index), "[FF02::C]:1900"
            else:
                destination, header_host = ("239.255.255.250", 1900), "239.255.255.250:1900"
            for st in (
                "urn:schemas-upnp-org:device:InternetGatewayDevice:1",
                "urn:schemas-upnp-org:device:InternetGatewayDevice:2",
                "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
            ):
                request = (
                    f"M-SEARCH * HTTP/1.1\r\nHOST: {header_host}\r\n"
                    f'MAN: "ssdp:discover"\r\nMX: 1\r\nST: {st}\r\n\r\n'
                ).encode()
                await loop.sock_sendto(sock, request, destination)
            deadline = loop.time() + 2
            while loop.time() < deadline and len(locations) < 8:
                try:
                    data, source = await asyncio.wait_for(
                        loop.sock_recvfrom(sock, 8192), deadline - loop.time()
                    )
                except TimeoutError:
                    break
                if source[0] != self.gateway.split("%")[0] or not data.startswith(b"HTTP/1.1 200"):
                    continue
                for line in data.decode(errors="replace").splitlines():
                    key, sep, value = line.partition(":")
                    if sep and key.lower() == "location":
                        try:
                            locations.add(safe_control_url(value.strip(), self.gateway))
                        except ValueError:
                            continue
        finally:
            sock.close()
        connector = aiohttp.TCPConnector(local_addr=(self.local, 0))
        async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                         timeout=aiohttp.ClientTimeout(total=3)) as session:
            for location in locations:
                try:
                    async with session.get(location, allow_redirects=False) as response:
                        response.raise_for_status()
                        root = SafeET.fromstring(await bounded_response(response))
                    for service in root.iter():
                        if service.tag.split("}")[-1] != "service":
                            continue
                        fields = {child.tag.split("}")[-1]: child.text for child in service}
                        kind = fields.get("serviceType")
                        if kind in SERVICES and fields.get("controlURL"):
                            control = safe_control_url(urljoin(location, fields["controlURL"]), self.gateway)
                            if (kind, control) not in self.services:
                                self.services.append((kind, control))
                except Exception as exc:
                    self.log.event("upnp.discovery_rejected", str(exc), "WARNING", gateway=self.gateway)
        self.log.event("upnp.discovered", gateway=self.gateway, services=[s for s, _ in self.services])
        return self.services

    async def soap(self, service, action, fields):
        kind, url = service
        envelope = ET.Element(
            "{http://schemas.xmlsoap.org/soap/envelope/}Envelope",
            {"encodingStyle": "http://schemas.xmlsoap.org/soap/encoding/"},
        )
        body = ET.SubElement(envelope, "{http://schemas.xmlsoap.org/soap/envelope/}Body")
        act = ET.SubElement(body, "{" + kind + "}" + action)
        for key, value in fields.items():
            ET.SubElement(act, key).text = str(value)
        connector = aiohttp.TCPConnector(local_addr=(self.local, 0))
        async with aiohttp.ClientSession(connector=connector, trust_env=False,
                                         timeout=aiohttp.ClientTimeout(total=3)) as session:
            async with session.post(
                url,
                data=ET.tostring(envelope),
                allow_redirects=False,
                headers={"SOAPAction": f'"{kind}#{action}"', "Content-Type": "text/xml; charset=utf-8"},
            ) as response:
                raw = await bounded_response(response)
                root = SafeET.fromstring(raw)
                result = {node.tag.split("}")[-1]: node.text for node in root.iter() if len(node) == 0}
                if "errorCode" in result:
                    raise ValueError("UPNP_SOAP_" + str(result["errorCode"]))
                response.raise_for_status()
                return result

    async def map(self, internal, external, lifetime=LEASE_SECONDS, *, protocol=17, any_port=False):
        validate_mapping(internal, external, lifetime, deletion=False)
        if protocol not in (6, 17):
            raise ValueError("UPNP_PROTOCOL_INVALID")
        if not external and not any_port:
            raise ValueError("UPNP_EXTERNAL_PORT_REQUIRED")
        service = next((s for s in self.services if "WANIPv6FirewallControl" not in s[0]), None)
        if not service:
            raise ValueError("UPNP_IPV4_SERVICE_NOT_FOUND")
        if any_port and not service[0].endswith(":2"):
            service = next((s for s in self.services if s[0].endswith("WANIPConnection:2")), None)
            if not service:
                raise ValueError("UPNP_IGDV2_UNAVAILABLE")
        wire_protocol = "TCP" if protocol == 6 else "UDP"
        result = await self.soap(service, "GetExternalIPAddress", {})
        address = str(ipaddress.IPv4Address(result["NewExternalIPAddress"]))
        # Do not overwrite a mapping that may belong to another application.
        if not any_port:
            try:
                await self.soap(
                    service,
                    "GetSpecificPortMappingEntry",
                    {"NewRemoteHost": "", "NewExternalPort": external, "NewProtocol": wire_protocol},
                )
            except ValueError as exc:
                if str(exc) != "UPNP_SOAP_714":
                    raise
            else:
                raise ValueError("UPNP_PORT_ALREADY_MAPPED")
        fields = {
            "NewRemoteHost": "",
            "NewExternalPort": external,
            "NewProtocol": wire_protocol,
            "NewInternalPort": internal,
            "NewInternalClient": self.local,
            "NewEnabled": 1,
            "NewPortMappingDescription": "p2plab",
            "NewLeaseDuration": lifetime,
        }
        result = await self.soap(service, "AddAnyPortMapping" if any_port else "AddPortMapping", fields)
        if any_port:
            external = int(result["NewReservedPort"])
            endpoint(address, external)
            fields["NewExternalPort"] = external
        return service, fields, endpoint(address, external)

    async def pinhole(self, internal_address, internal_port, remote, lifetime=LEASE_SECONDS, *, protocol=17):
        validate_mapping(internal_port, remote[1], lifetime, deletion=False)
        if (
            ipaddress.ip_address(internal_address).version != 6
            or ipaddress.ip_address(remote[0]).version != 6
        ):
            raise ValueError("PINHOLE_REQUIRES_IPV6")
        service = next((s for s in self.services if "WANIPv6FirewallControl" in s[0]), None)
        if not service:
            raise ValueError("UPNP_IPV6_FIREWALL_SERVICE_NOT_FOUND")
        status = await self.soap(service, "GetFirewallStatus", {})
        if status.get("InboundPinholeAllowed") != "1":
            raise ValueError("UPNP_PINHOLE_NOT_ALLOWED")
        result = await self.soap(
            service,
            "AddPinhole",
            {
                "RemoteHost": remote[0],
                "RemotePort": remote[1],
                "InternalClient": internal_address,
                "InternalPort": internal_port,
                "Protocol": protocol,
                "LeaseTime": lifetime,
            },
        )
        uid = int(result["UniqueID"])
        if not 0 <= uid <= 65535:
            raise ValueError("UPNP_PINHOLE_ID_INVALID")
        return service, uid


@dataclass
class Lease:
    owner: object
    mechanism: str
    external: tuple[str, int]
    lifetime: int
    renew: object
    delete: object
    task: asyncio.Task | None = None
    released: bool = False

    def start(self):
        self.task = asyncio.create_task(self.watch(), name="lease:" + self.mechanism)
        self.owner.log.event(
            "gateway.lease_created",
            mechanism=self.mechanism,
            external=self.external,
            lifetime=self.lifetime,
            evidence="router-response-not-p2p-connectivity",
        )
        return self

    async def watch(self):
        try:
            while not self.released:
                await asyncio.sleep(max(10, self.lifetime / 2))
                result = await self.renew()
                if result.get("external", self.external) != self.external:
                    raise ValueError("MAPPING_ENDPOINT_CHANGED_REQUIRES_NEW_ATTEMPT")
                self.lifetime = result.get("lifetime", self.lifetime)
                self.owner.log.event(
                    "gateway.lease_renewed", mechanism=self.mechanism, lifetime=self.lifetime
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("gateway.lease_renewal_failed", exc, mechanism=self.mechanism)

    async def release(self):
        if self.released:
            return
        self.released = True
        if self.task:
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        try:
            await self.delete()
            self.owner.log.event("gateway.lease_deleted", mechanism=self.mechanism, external=self.external)
        except Exception as exc:
            self.owner.log.exception(
                "gateway.lease_delete_failed",
                exc,
                mechanism=self.mechanism,
                expires_within_seconds=self.lifetime,
            )


async def create_lease(owner, method, udp, remote=None):
    if not owner.gateway_enabled:
        raise ValueError("GATEWAY_DISABLED")
    original_method = method
    protocol = 6 if method.endswith("-tcp") else 17
    if protocol == 6:
        method = method[:-4]
    max_leases = owner.config.get("experiment", {}).get("max_active_leases", 128 if not owner.loopback else 8)
    if len([lease for lease in owner.leases if not lease.released]) >= max_leases:
        raise ValueError("ACTIVE_LEASE_LIMIT")
    route = next((r for r in owner.network.get("gateways", []) if r["local"] == udp.host), None)
    if method.startswith("pcp") and ":" in udp.host:
        route = next((r for r in owner.network.get("gateways6", []) if r["local"] == udp.host), None)
    if method == "pinhole":
        interface = next(
            (r["interface"] for r in owner.network.get("addresses", []) if r["address"] == udp.host), None
        )
        route = next((r for r in owner.network.get("gateways6", []) if r.get("interface") == interface), None) or next(
            (r for r in owner.network.get("gateways", []) if r.get("interface") == interface), None)
    if not route:
        raise ValueError("NO_TRUSTED_DEFAULT_GATEWAY_FOR_INTERFACE")
    gateway, local = route["gateway"], route["local"]
    address = ipaddress.ip_address(gateway)
    if address.version == 6:
        local = udp.host
        gateway += "%" + route["interface"]
    port = udp.candidates[0][1]
    if method.startswith("pcp"):
        nonce = secrets.token_bytes(12)
        preferred_port = port

        async def operation(lifetime):
            nonlocal preferred_port
            data = await gateway_datagram(
                gateway, local, pcp_request(udp.host, port, preferred_port, nonce, lifetime,
                    protocol=protocol, peer=remote if method == "pcp-peer" else None,
                    filter_remote=remote if method == "pcp-filter" else None,
                    prefer_failure=method == "pcp-prefer")
            )
            result = parse_pcp(data, nonce, port, deleting=lifetime == 0, protocol=protocol,
                               peer=remote if method == "pcp-peer" else None)
            if lifetime:
                preferred_port = result["external"][1]
            return result

        result = await operation(LEASE_SECONDS)
        lease = Lease(
            owner,
            method,
            result["external"],
            result["lifetime"],
            lambda: operation(LEASE_SECONDS),
            lambda: operation(0),
        )
    elif method == "natpmp":
        raw = await gateway_datagram(gateway, local, b"\0\0")
        if len(raw) != 12 or raw[:2] != b"\0\x80" or struct.unpack_from("!H", raw, 2)[0]:
            raise ValueError("NATPMP_EXTERNAL_ADDRESS_FAILED")
        address = str(ipaddress.IPv4Address(raw[8:12]))
        preferred_port = port

        async def operation(lifetime):
            nonlocal preferred_port
            raw = await gateway_datagram(gateway, local, natpmp_request(port, preferred_port, lifetime, protocol=protocol))
            result = parse_natpmp(raw, port, deleting=lifetime == 0, protocol=protocol)
            if lifetime:
                preferred_port = result["port"]
            return result

        result = await operation(LEASE_SECONDS)
        lease = Lease(
            owner,
            method,
            endpoint(address, result["port"]),
            result["lifetime"],
            lambda: operation(LEASE_SECONDS),
            lambda: operation(0),
        )
    else:
        upnp = Upnp(owner.log, gateway, local)
        await upnp.discover()
        if method in ("upnp", "upnp-any"):
            try:
                service, fields, external = await upnp.map(port, 0 if method == "upnp-any" else port,
                                                          protocol=protocol, any_port=method == "upnp-any")
            except ValueError as exc:
                if str(exc) != "UPNP_PORT_ALREADY_MAPPED":
                    raise
                service, fields, external = await upnp.map(port, secrets.randbelow(40000) + 20000, protocol=protocol)

            async def renew():
                current = await upnp.soap(
                    service,
                    "GetSpecificPortMappingEntry",
                    {k: fields[k] for k in ("NewRemoteHost", "NewExternalPort", "NewProtocol")},
                )
                if (
                    current.get("NewInternalClient") != local
                    or int(current.get("NewInternalPort", 0)) != port
                ):
                    raise ValueError("UPNP_MAPPING_NO_LONGER_OWNED")
                await upnp.soap(service, "AddPortMapping", fields)
                return {"lifetime": LEASE_SECONDS}

            async def delete():
                await upnp.soap(
                    service,
                    "DeletePortMapping",
                    {k: fields[k] for k in ("NewRemoteHost", "NewExternalPort", "NewProtocol")},
                )
        elif method == "pinhole":
            service, uid = await upnp.pinhole(udp.host, port, remote, protocol=protocol)
            owner.log.event("upnp.pinhole_control_source", internal_client=udp.host, control_source=local,
                            same_source=udp.host == local, protocol=protocol, attempt=udp.attempt)
            external = (udp.host, port)

            async def renew():
                await upnp.soap(service, "UpdatePinhole", {"UniqueID": uid, "NewLeaseTime": LEASE_SECONDS})
                return {"lifetime": LEASE_SECONDS}

            async def delete():
                await upnp.soap(service, "DeletePinhole", {"UniqueID": uid})
        else:
            raise ValueError("UNKNOWN_GATEWAY_MECHANISM")
        lease = Lease(owner, method, external, LEASE_SECONDS, renew, delete)
    lease.mechanism = original_method
    owner.leases.append(lease)
    return lease.start()
