import asyncio
import ipaddress
import socket
import struct
import pytest
from aiohttp import web
from p2pchat.native.gateway import GatewayPolicy, PCP, NATPMP, UPnP
from p2pchat.native.stun import binding, parse_binding, COOKIE


class MockGateway(asyncio.DatagramProtocol):
    def __init__(self, mode, reject=False):
        self.mode, self.reject, self.requests = mode, reject, []

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        self.requests.append(data)
        if self.mode == "pcp":
            lifetime = struct.unpack("!I", data[4:8])[0]
            nonce, protocol, internal, external, _ = struct.unpack("!12sB3xHH16s", data[24:])
            reply = struct.pack("!BBBBII12x", 2, 129, 0, 2 if self.reject else 0, lifetime, 100)
            reply += struct.pack("!12sB3xHH16s", nonce, protocol, internal, external or 45678,
                                 ipaddress.IPv6Address("::ffff:198.51.100.7").packed)
        elif self.mode == "natpmp":
            if data == b"\x00\x00":
                reply = struct.pack("!BBHI4s", 0, 128, 0, 100, socket.inet_aton("198.51.100.7"))
            else:
                _, _, _, internal, external, lifetime = struct.unpack("!BBHHHI", data)
                reply = struct.pack("!BBHIHHI", 0, 129, 2 if self.reject else 0, 100, internal, external or 45678, lifetime)
        else:
            transaction = data[8:20]
            mapped = struct.pack("!BBH", 0, 1, addr[1] ^ (COOKIE >> 16))
            mapped += bytes(a ^ b for a, b in zip(socket.inet_aton(addr[0]), struct.pack("!I", COOKIE)))
            reply = struct.pack("!HHI12sHH", 0x101, 12, COOKIE, transaction, 0x20, 8) + mapped
        self.transport.sendto(reply, addr)


async def mock(mode, reject=False):
    transport, protocol = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: MockGateway(mode, reject), local_addr=("127.0.0.1", 0))
    return transport, protocol, GatewayPolicy("127.0.0.1", "127.0.0.1", enabled=True, mock_loopback=True,
                                             port=transport.get_extra_info("sockname")[1], timeout=.05)


async def external_mock_validator(lease):
    assert lease.external_address == "198.51.100.7"
    assert lease.external_port == 45678
    return True  # MOCK validator only, explicitly not external-router evidence


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,cls", [("pcp", PCP), ("natpmp", NATPMP)])
async def test_gateway_packets_lease_renew_delete(kind, cls):
    transport, protocol, policy = await mock(kind)
    gateway = cls(policy)
    try:
        lease = await gateway.map(12345, validator=external_mock_validator)
        assert lease.verified and lease.lifetime == 120
        await gateway.renew(lease, external_mock_validator, lifetime=240)
        assert lease.lifetime == 240
        assert await gateway.close() == []
        assert not lease.verified and not gateway.leases
        assert protocol.requests[-1][-4:] == b"\0"*4 if kind == "natpmp" else struct.unpack("!I", protocol.requests[-1][4:8])[0] == 0
    finally:
        transport.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind,cls", [("pcp", PCP), ("natpmp", NATPMP)])
async def test_gateway_rejection_and_missing_external_validation(kind, cls):
    transport, protocol, policy = await mock(kind)
    try:
        with pytest.raises(ValueError, match="EXTERNAL_VALIDATION_REQUIRED"):
            await cls(policy).map(12345)
        assert len(protocol.requests) >= 2  # missing validator triggers actual lease deletion
        protocol.reject = True
        with pytest.raises(ValueError, match="RESULT_2"):
            await cls(policy).map(12345, validator=external_mock_validator)
    finally:
        transport.close()


@pytest.mark.asyncio
async def test_optin_route_validation_and_timeout():
    with pytest.raises(PermissionError, match="OPT_IN"):
        await PCP(GatewayPolicy("127.0.0.1", "127.0.0.1")).map(12345)
    with pytest.raises(ValueError, match="CONTROL_URL"):
        UPnP(GatewayPolicy("127.0.0.1", "127.0.0.1"), "http://192.0.2.1/control", "urn:schemas-upnp-org:service:WANIPConnection:1")
    transport, _, policy = await mock("pcp")
    transport.close()
    with pytest.raises(TimeoutError, match="GATEWAY_TIMEOUT"):
        await PCP(policy).map(12345)


@pytest.mark.parametrize("platform", ["linux", "win32", "darwin"])
def test_gateway_platform_validation_fail_closed(monkeypatch, platform):
    import p2pchat.native.gateway as module
    monkeypatch.setattr(module.sys, "platform", platform)
    # No host route probing needed: deterministic empty Linux routing fixture.
    monkeypatch.setattr(module.Path, "read_text", lambda self: "Iface Destination Gateway Flags\n")
    with pytest.raises(PermissionError, match="GATEWAY_OPT_IN_REQUIRED"):
        GatewayPolicy("198.51.100.77", "127.0.0.1").validate()
    if platform == "linux":
        with pytest.raises(PermissionError, match="NOT_LOCAL_ROUTED_GATEWAY"):
            GatewayPolicy("198.51.100.77", "127.0.0.1", enabled=True).validate()
    else:
        with pytest.raises(NotImplementedError, match="LOCAL_GATEWAY_VALIDATION_UNAVAILABLE"):
            GatewayPolicy("198.51.100.77", "127.0.0.1", enabled=True).validate()
    # Authorized mock protocol testing remains allowed; not real route discovery.
    GatewayPolicy("::1", "::1", enabled=True, mock_loopback=True).validate()


@pytest.mark.asyncio
async def test_upnp_mapping_and_pinhole_mock():
    actions = []
    async def action(req):
        action = req.headers["SOAPAction"].strip('"').split("#")[1]
        body = await req.text()
        actions.append((action, body))
        values = {"GetExternalIPAddress": "<NewExternalIPAddress>198.51.100.7</NewExternalIPAddress>",
                  "GetFirewallStatus": "<InboundPinholeAllowed>1</InboundPinholeAllowed>",
                  "AddPinhole": "<UniqueID>42</UniqueID>"}.get(action, "")
        return web.Response(text=f'<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><Response>{values}</Response></s:Body></s:Envelope>')
    app = web.Application()
    app.router.add_post("/control", action)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    policy = GatewayPolicy("127.0.0.1", "127.0.0.1", enabled=True, mock_loopback=True)
    gateway = UPnP(policy, f"http://127.0.0.1:{port}/control", "urn:schemas-upnp-org:service:WANIPConnection:1")
    try:
        lease = await gateway.map(12345, 45678, validator=external_mock_validator)
        await gateway.renew(lease, external_mock_validator)
        await gateway.close()
        assert [a for a, _ in actions] == ["GetExternalIPAddress", "AddPortMapping", "AddPortMapping", "DeletePortMapping"]
        assert "<NewLeaseDuration>120</NewLeaseDuration>" in actions[1][1]
    finally:
        await runner.cleanup()

    # IPv6 firewall service on an IPv6-only mock gateway.
    app = web.Application()
    app.router.add_post("/control", action)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "::1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    policy = GatewayPolicy("::1", "::1", enabled=True, mock_loopback=True)
    gateway = UPnP(policy, f"http://[::1]:{port}/control", "urn:schemas-upnp-org:service:WANIPv6FirewallControl:1")
    async def valid_pinhole(lease):
        return lease.unique_id == "42"
    try:
        lease = await gateway.pinhole(12345, "::1", 45678, validator=valid_pinhole)
        await gateway.renew(lease, valid_pinhole)
        assert await gateway.close() == []
        assert [a for a, _ in actions][-4:] == ["GetFirewallStatus", "AddPinhole", "UpdatePinhole", "DeletePinhole"]
    finally:
        await runner.cleanup()


@pytest.mark.asyncio
async def test_stun_same_socket_mapping():
    transport, _, policy = await mock("stun")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    before = sock.getsockname()
    try:
        result = await binding(sock, (policy.gateway, policy.port))
        assert (result["address"], result["port"]) == before == sock.getsockname()
        assert result["observation"] == "mapped-address-only-not-nat-type"
    finally:
        sock.close()
        transport.close()
    with pytest.raises(ValueError, match="TRUNCATED"):
        parse_binding(b"bad", b"x"*12)
