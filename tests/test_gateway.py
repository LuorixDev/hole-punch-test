import asyncio
import socket
import struct
import xml.etree.ElementTree as ET
from types import SimpleNamespace

import pytest
from aiohttp import web

import p2plab.gateway as gateway_module
from p2plab.gateway import Upnp, create_lease
from p2plab.udp import UdpAttempt


@pytest.mark.parametrize("scope", [17, "17", "Ethernet"])
def test_interface_scope_names_and_numeric_indices(monkeypatch, scope):
    from p2plab.common import interface_index

    def resolve(name):
        assert name == "Ethernet"
        return 17

    monkeypatch.setattr(socket, "if_nametoindex", resolve)
    assert interface_index(scope) == 17


@pytest.mark.parametrize("scope", [0, "0", 0x100000000])
def test_interface_scope_rejects_invalid_numeric_indices(scope):
    from p2plab.common import interface_index

    with pytest.raises(ValueError, match="INVALID_INTERFACE_INDEX"):
        interface_index(scope)


async def test_gateway_scope_lookup_failure_allocates_no_socket(monkeypatch):
    allocated = []

    def missing(name):
        raise OSError("no interface with this name")

    monkeypatch.setattr(socket, "if_nametoindex", missing)
    monkeypatch.setattr(gateway_module, "new_socket", lambda *a, **kw: allocated.append(a))
    with pytest.raises(OSError, match="no interface"):
        await gateway_module.gateway_datagram("fe80::1%missing", "::1", b"test")
    assert not allocated


async def test_ipv6_gateway_numeric_scope_and_ssdp(peers, monkeypatch):
    a, _ = peers
    sent, options, closed = [], [], []
    sock = SimpleNamespace(setsockopt=lambda *args: options.append(args),
                           close=lambda: closed.append(True))
    monkeypatch.setattr(gateway_module, "new_socket", lambda *a, **kw: sock)

    def wrong_lookup(name):
        raise AssertionError("Numeric Windows scope must not resolve InterfaceAlias")

    monkeypatch.setattr(socket, "if_nametoindex", wrong_lookup)
    loop = asyncio.get_running_loop()

    async def send(sock, data, target):
        sent.append(target)

    async def receive(sock, size):
        return b"reply", ("fe80::1", 5351, 0, 17)

    monkeypatch.setattr(loop, "sock_sendto", send)
    monkeypatch.setattr(loop, "sock_recvfrom", receive)
    assert await gateway_module.gateway_datagram("fe80::1%17", "::1", b"test") == b"reply"
    assert sent == [("fe80::1", 5351, 0, 17)] and len(closed) == 1

    async def no_response(sock, size):
        raise TimeoutError

    monkeypatch.setattr(loop, "sock_recvfrom", no_response)
    assert await Upnp(a.log, "fe80::1%17", "::1").discover() == []
    assert sent[1:] == [("ff02::c", 1900, 0, 17)] * 3
    assert (socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, 17) in options
    assert len(closed) == 2


async def test_pcp_lease_uses_route_index_instead_of_windows_alias(peers, monkeypatch):
    a, _ = peers
    a.gateway_enabled = True
    a.network = {"gateways6": [{"gateway": "fe80::1", "local": "::1",
                               "interface": "以太网", "interface_index": 17}]}
    calls = []

    async def request(gateway, local, data, **kw):
        calls.append((gateway, local))
        return data

    def response(data, nonce, internal, *, deleting, **kw):
        return {"external": ("2001:db8::1", internal), "lifetime": 0 if deleting else 120}

    monkeypatch.setattr(gateway_module, "gateway_datagram", request)
    monkeypatch.setattr(gateway_module, "parse_pcp", response)
    udp = UdpAttempt(a, {"attempt": "gateway-index"}, "::1")
    try:
        await udp.open()
        lease = await create_lease(a, "pcp", udp)
        await lease.renew()
        await lease.release()
        assert calls == [("fe80::1%17", "::1")] * 3
    finally:
        await udp.close()
        for lease in a.leases:
            await lease.release()


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


async def test_malformed_soap_response_has_stable_diagnostic(peers):
    a, _ = peers

    async def malformed(request):
        return web.Response(text="<Envelope><x:Fault></Envelope>", content_type="text/xml")

    app = web.Application()
    app.router.add_post("/", malformed)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    try:
        upnp = Upnp(a.log, "127.0.0.1", "127.0.0.1")
        with pytest.raises(ValueError, match="UPNP_SOAP_INVALID_XML"):
            await upnp.soap(
                ("urn:schemas-upnp-org:service:WANIPConnection:1", f"http://127.0.0.1:{port}/"),
                "DeletePortMapping",
                {},
            )
        event = next(row for row in a.log.query() if row["event"] == "upnp.soap_invalid_response")
        assert event["fields"]["action"] == "DeletePortMapping"
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
