import asyncio
import struct
import xml.etree.ElementTree as ET

import pytest
from aiohttp import web

import p2plab.gateway as gateway_module
from p2plab.gateway import Upnp, create_lease
from p2plab.udp import UdpAttempt


class FakeGateway(asyncio.DatagramProtocol):
    def __init__(self):
        self.requests = []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, source):
        self.requests.append(data)
        if data[0] == 2:
            lifetime = struct.unpack_from("!I", data, 4)[0]
            internal = struct.unpack_from("!H", data, 40)[0]
            response = struct.pack("!BBBBII12x", 2, 0x81, 0, 0, lifetime, 123)
            response += struct.pack(
                "!12sB3xHH16s",
                data[24:36],
                17,
                internal,
                54321,
                bytes(10) + b"\xff\xff" + bytes([203, 0, 113, 5]),
            )
        elif data == b"\0\0":
            response = struct.pack("!BBHI4s", 0, 128, 0, 123, bytes([203, 0, 113, 5]))
        else:
            internal, _, lifetime = struct.unpack_from("!HHI", data, 4)
            response = struct.pack("!BBHIHHI", 0, 129, 0, 123, internal, 54321, lifetime)
        self.transport.sendto(response, source)


@pytest.mark.parametrize("method", ["pcp", "natpmp"])
async def test_mock_gateway_create_renew_delete(peers, monkeypatch, method):
    a, _ = peers
    a.gateway_enabled = True
    a.network = {"gateways": [{"gateway": "127.0.0.1", "local": "127.0.0.1"}]}
    transport, responder = await asyncio.get_running_loop().create_datagram_endpoint(
        FakeGateway, local_addr=("127.0.0.1", 0)
    )
    monkeypatch.setattr(gateway_module, "PCP_PORT", transport.get_extra_info("sockname")[1])
    udp = UdpAttempt(a, {"attempt": "gateway-test"}, "127.0.0.1")
    try:
        await udp.open()
        lease = await create_lease(a, method, udp)
        assert lease.external == ("203.0.113.5", 54321)
        renewed = await lease.renew()
        assert renewed["lifetime"] == 120
        await lease.release()
        assert lease.released
        if method == "pcp":
            assert len({r[24:36] for r in responder.requests}) == 1
            assert struct.unpack_from("!H", responder.requests[1], 42)[0] == 54321
            assert struct.unpack_from("!I", responder.requests[-1], 4)[0] == 0
        else:
            assert struct.unpack_from("!H", responder.requests[2], 6)[0] == 54321
            assert struct.unpack_from("!I", responder.requests[-1], 8)[0] == 0
    finally:
        for lease in a.leases:
            await lease.release()
        await udp.close()
        transport.close()


async def test_real_soap_mock_router_and_ipv6_pinhole(peers):
    a, _ = peers
    calls = []

    async def soap(request):
        root = ET.fromstring(await request.read())
        action = next(iter(list(root)[0]))
        name = action.tag.split("}")[-1]
        fields = {child.tag: child.text or "" for child in action}
        calls.append((name, fields))
        results = {
            "GetExternalIPAddress": {"NewExternalIPAddress": "203.0.113.9"},
            "GetFirewallStatus": {"FirewallEnabled": "1", "InboundPinholeAllowed": "1"},
            "AddPinhole": {"UniqueID": "42"},
        }
        if name == "GetSpecificPortMappingEntry":
            return web.Response(
                status=500,
                text="<Envelope><Fault><errorCode>714</errorCode></Fault></Envelope>",
                content_type="text/xml",
            )
        result = results.get(name, {})
        text = (
            "<Envelope><Body>" + "".join(f"<{k}>{v}</{k}>" for k, v in result.items()) + "</Body></Envelope>"
        )
        return web.Response(text=text, content_type="text/xml")

    app = web.Application()
    app.router.add_post("/control", soap)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        upnp = Upnp(a.log, "127.0.0.1", "127.0.0.1")
        url = f"http://127.0.0.1:{port}/control"
        upnp.services = [
            ("urn:schemas-upnp-org:service:WANIPConnection:1", url),
            ("urn:schemas-upnp-org:service:WANIPv6FirewallControl:1", url),
        ]
        service, fields, external = await upnp.map(10000, 10001)
        assert external == ("203.0.113.9", 10001)
        assert fields["NewLeaseDuration"] == 120
        service, uid = await upnp.pinhole("2001:db8::1", 10000, ("2001:db8::2", 10001))
        assert uid == 42
        await upnp.soap(service, "UpdatePinhole", {"UniqueID": uid, "NewLeaseTime": 120})
        await upnp.soap(service, "DeletePinhole", {"UniqueID": uid})
        pinhole = next(fields for name, fields in calls if name == "AddPinhole")
        assert pinhole["Protocol"] == "17" and pinhole["RemoteHost"] == "2001:db8::2"
        assert "DeletePinhole" in [name for name, _ in calls]
    finally:
        await runner.cleanup()


async def test_soap_entities_are_rejected(peers):
    a, _ = peers

    async def bad(request):
        return web.Response(text='<!DOCTYPE a [<!ENTITY x SYSTEM "file:///etc/passwd">]><a>&x;</a>')

    app = web.Application()
    app.router.add_post("/", bad)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        upnp = Upnp(a.log, "127.0.0.1", "127.0.0.1")
        with pytest.raises(ValueError, match="ENTITY_FORBIDDEN"):
            await upnp.soap(
                ("urn:schemas-upnp-org:service:WANIPConnection:1", f"http://127.0.0.1:{port}/"),
                "GetExternalIPAddress",
                {},
            )
    finally:
        await runner.cleanup()


async def test_igdv2_tcp_any_port_and_ipv6_soap_source_binding(peers):
    a, _ = peers
    calls = []

    async def soap(request):
        root = ET.fromstring(await request.read())
        action = next(iter(list(root)[0]))
        name = action.tag.split("}")[-1]
        fields = {child.tag: child.text or "" for child in action}
        calls.append((name, fields, request.transport.get_extra_info("peername")[0]))
        answers = {"GetExternalIPAddress": {"NewExternalIPAddress": "203.0.113.7"},
                   "AddAnyPortMapping": {"NewReservedPort": "54322"},
                   "GetFirewallStatus": {"FirewallEnabled": "1", "InboundPinholeAllowed": "1"},
                   "AddPinhole": {"UniqueID": "43"}}
        result = answers.get(name, {})
        return web.Response(text="<Envelope><Body>" + "".join(f"<{k}>{v}</{k}>" for k, v in result.items())
                            + "</Body></Envelope>", content_type="text/xml")

    app = web.Application()
    app.router.add_post("/", soap)
    runner = web.AppRunner(app)
    await runner.setup()
    sites = [web.TCPSite(runner, host, 0) for host in ("127.0.0.1", "::1")]
    try:
        for site in sites:
            await site.start()
        v4 = Upnp(a.log, "127.0.0.1", "127.0.0.1")
        v4.services = [("urn:schemas-upnp-org:service:WANIPConnection:2",
                        f"http://127.0.0.1:{sites[0]._server.sockets[0].getsockname()[1]}/")]
        _, fields, external = await v4.map(12000, 12001, protocol=6, any_port=True)
        assert external == ("203.0.113.7", 54322) and fields["NewExternalPort"] == 54322
        action = next(row for row in calls if row[0] == "AddAnyPortMapping")
        assert action[1]["NewProtocol"] == "TCP" and action[2] == "127.0.0.1"
        v6 = Upnp(a.log, "::1", "::1")
        v6.services = [("urn:schemas-upnp-org:service:WANIPv6FirewallControl:1",
                        f"http://[::1]:{sites[1]._server.sockets[0].getsockname()[1]}/")]
        _, uid = await v6.pinhole("::1", 12000, ("::1", 12001), protocol=6)
        assert uid == 43
        action = next(row for row in calls if row[0] == "AddPinhole")
        assert action[1]["Protocol"] == "6" and action[1]["InternalClient"] == action[2] == "::1"
    finally:
        await runner.cleanup()
