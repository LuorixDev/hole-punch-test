import asyncio
import socket
import ssl
import uuid

import aiohttp
import pytest
from aiohttp import web

from p2plab.client import Client
from p2plab.common import Identity
from p2plab.journal import Journal
from p2plab.server import Hub
from p2plab.stun import StunServer
from p2plab.tcp import TcpAttempt
from tests.test_cli import local_certificate


async def start_hub(tmp_path, *, shared=False, ssl_context=None):
    journal = Journal(tmp_path / "central.db", role="server", console=False)
    hub = Hub(journal, admin_token="admin", tcp_observer_protocol="http" if shared else "raw",
              allow_loopback=True)
    runner = web.AppRunner(hub.app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0, ssl_context=ssl_context)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
        lambda: StunServer(journal, {}, ("127.0.0.1", port if shared else 0), None),
        local_addr=("127.0.0.1", port if shared else 0),
    )
    hub.stun_port = transport.get_extra_info("sockname")[1]
    tcp = None if shared else await asyncio.start_server(hub.observe_tcp, "127.0.0.1", 0)
    hub.tcp_port = port if shared else tcp.sockets[0].getsockname()[1]
    return hub, journal, runner, transport, tcp, f"{'wss' if ssl_context else 'ws'}://127.0.0.1:{port}/ws"


async def join(session, url, directory, room="test", client=None):
    identity = Identity(directory)
    client = client or str(uuid.uuid4())
    ws = await session.ws_connect(url)
    challenge = await ws.receive_json()
    proof = identity.sign(
        {
            "v": 1,
            "kind": "join",
            "nonce": challenge["nonce"],
            "room": room,
            "client": client,
            "public": identity.public,
            "name": "test",
            "certificate_fingerprint": identity.fingerprint,
        }
    )
    await ws.send_json(
        {
            "v": 1,
            "type": "join",
            "client": client,
            "room": room,
            "name": "test",
            "public": identity.public,
            "certificate": identity.cert_pem,
            "proof": proof,
        }
    )
    welcome = await ws.receive_json()
    identity.close()
    return ws, welcome


async def cleanup_hub(journal, runner, transport, tcp):
    if tcp:
        tcp.close()
        await tcp.wait_closed()
    transport.close()
    await runner.cleanup()
    journal.close()


@pytest.mark.parametrize("tls,hostname", [(False, "127.0.0.1"), (True, "127.0.0.1"), (True, "localhost")])
async def test_shared_http_observer_measures_actual_bound_socket_and_same_port_stun(tmp_path, tls, hostname):
    context, trusted = None, True
    cert, key = local_certificate(tmp_path) if tls else (None, None)
    if tls:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(cert, key)
        trusted = ssl.create_default_context(cafile=str(cert))
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path, shared=True, ssl_context=context)
    client = Client({"data_dir": str(tmp_path / "probe"), "server": url.replace("127.0.0.1", hostname),
                     **({"ca_file": str(cert)} if tls else {})}, "test", console=False)
    attempt = TcpAttempt(client, {"attempt": "shared-observer", "method": "tcp", "initiator": True}, "127.0.0.1")
    try:
        assert tcp is None and hub.stun_port == hub.tcp_port
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=trusted)) as session:
            ws, welcome = await join(session, url, tmp_path / "joined")
            assert welcome["tcp_observer_protocol"] == "http"
            client.tcp_observer, client.observation_token = ("127.0.0.1", hub.tcp_port), welcome["observation_token"]
            client.tcp_observer_protocol = "http"
            await attempt.prepare()
            assert attempt.observed == ["127.0.0.1", attempt.candidates[0][1]]
            assert attempt.sock.getsockname()[1] == attempt.candidates[0][1]
            observation = next(e for e in journal.query() if e["event"] == "tcp.observation")
            assert observation["fields"]["mapped"] == attempt.observed
            from p2plab.stun import HEADER, parse_response

            tid = b"shared-port!"
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.bind(("127.0.0.1", 0))
                probe.setblocking(False)
                loop = asyncio.get_running_loop()
                await loop.sock_sendto(probe, HEADER.pack(1, 0, 0x2112A442, tid), ("127.0.0.1", hub.stun_port))
                reply, source = await asyncio.wait_for(loop.sock_recvfrom(probe, 1024), 2)
                assert source == ("127.0.0.1", hub.tcp_port)
                assert parse_response(reply, tid)["mapped"] == probe.getsockname()
            await ws.close()
    finally:
        await attempt.close()
        await client.close()
        await cleanup_hub(journal, runner, transport, tcp)


async def test_shared_tls_observer_does_not_downgrade_on_untrusted_certificate(tmp_path):
    cert, key = local_certificate(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path, shared=True, ssl_context=context)
    client = Client({"data_dir": str(tmp_path / "probe"), "server": url}, "test", console=False)
    attempt = TcpAttempt(client, {"attempt": "bad-cert", "method": "tcp", "initiator": True}, "127.0.0.1")
    try:
        trusted = ssl.create_default_context(cafile=str(cert))
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=trusted)) as session:
            ws, welcome = await join(session, url, tmp_path / "joined")
            client.tcp_observer, client.observation_token = ("127.0.0.1", hub.tcp_port), welcome["observation_token"]
            client.tcp_observer_protocol = "http"
            await attempt.prepare()
            assert attempt.observed is None
            assert attempt.sock.getsockname()[1] == attempt.candidates[0][1]
            failures = [e for e in client.log.query() if e["event"] == "tcp.observer_failed"]
            assert len(failures) == 1 and "certificate" in failures[0]["message"].lower()
            assert not any(e["event"] == "tcp.observation" for e in journal.query())
            await ws.close()
    finally:
        await attempt.close()
        await client.close()
        await cleanup_hub(journal, runner, transport, tcp)


@pytest.mark.parametrize("kind,error", [
    ("redirect", "TCP_OBSERVER_UNEXPECTED_STATUS"),
    ("oversized", "TCP_OBSERVER_RESPONSE_LIMIT"),
    ("invalid-json", "Expecting value"),
    ("wrong-family", "TCP_OBSERVER_FAMILY_MISMATCH"),
])
async def test_shared_observer_rejects_bad_responses_and_rebinds_socket(tmp_path, kind, error):
    visits = []

    async def observe(request):
        visits.append(request.path)
        if kind == "redirect":
            return web.json_response({"mapped": ["127.0.0.1", 12345]}, status=302,
                                     headers={"Location": "/unexpected"})
        if kind == "oversized":
            return web.Response(body=b"x" * 4097)
        if kind == "wrong-family":
            return web.json_response({"mapped": ["::1", 12345]})
        return web.Response(body=b"invalid-json")

    app = web.Application()
    app.router.add_post("/tcp-observe", observe)
    app.router.add_get("/unexpected", observe)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    client = Client({"data_dir": str(tmp_path / "probe"), "server": f"ws://127.0.0.1:{port}/ws"},
                    "test", console=False)
    client.tcp_observer, client.observation_token, client.tcp_observer_protocol = ("127.0.0.1", port), "test", "http"
    attempt = TcpAttempt(client, {"attempt": "bad-response", "method": "tcp", "initiator": True}, "127.0.0.1")
    try:
        await attempt.prepare()
        assert visits == ["/tcp-observe"]
        assert len(attempt.candidates) == 1
        assert attempt.sock.getsockname()[1] == attempt.candidates[0][1]
        events = client.log.query()
        assert not any(e["event"] == "tcp.mapped" for e in events)
        assert any(e["event"] == "tcp.observer_failed" and error in e["message"] for e in events)
    finally:
        await attempt.close()
        await client.close()
        await runner.cleanup()


@pytest.mark.parametrize("reason", ["invalid-token", "expired", "wrong-source", "forwarded"])
async def test_shared_tcp_observer_rejects_invalid_identity_or_proxy(tmp_path, reason):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path, shared=True)
    try:
        async with aiohttp.ClientSession() as session:
            ws, welcome = await join(session, url, tmp_path / "joined")
            token = welcome["observation_token"]
            headers = {"Authorization": "Bearer " + token}
            if reason == "invalid-token":
                headers["Authorization"] = "Bearer invalid"
            elif reason == "expired":
                hub.observation_tokens[token] = (welcome["id"], -1)
            elif reason == "wrong-source":
                hub.peers[welcome["id"]]["source"] = "192.0.2.1"
            else:
                headers["X-Forwarded-For"] = "127.0.0.1"
            async with session.post(url.replace("ws://", "http://").replace("/ws", "/tcp-observe"),
                                    headers=headers) as response:
                assert response.status == 403
            assert not any(e["event"] == "tcp.observation" for e in journal.query())
            assert token not in str(journal.query())
            await ws.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


@pytest.mark.parametrize("source,forwarded,error", [
    ("192.168.1.88", False, "NON_GLOBAL_SOURCE"),
    ("100.71.69.142", False, "NON_GLOBAL_SOURCE"),
    ("8.8.8.8", True, "DISABLED_FOR_FORWARDED"),
])
def test_tcp_observer_does_not_certify_proxy_mapping(tmp_path, source, forwarded, error):
    journal = Journal(tmp_path / "proxy.db", role="server", console=False)
    hub = Hub(journal, admin_token="test", forwarded=forwarded)
    hub.peers["peer"] = {"source": source, "room": "test", "id": "peer"}
    hub.observation_tokens["token"] = ("peer", float("inf"))
    try:
        with pytest.raises(ValueError, match=error):
            hub.observed_mapping("token", (source, 12345))
        assert not any(r["event"] == "tcp.observation" for r in journal.query())
    finally:
        journal.close()


async def test_error_delivery_to_closing_websocket_does_not_escape_request_handler(tmp_path, monkeypatch, caplog):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    original = web.WebSocketResponse.send_json

    async def fail_dispatch(peer, body):
        raise aiohttp.ClientConnectionResetError("Cannot write to closing transport")

    async def send_json(ws, data, *args, **kwargs):
        if data.get("type") == "error":
            raise aiohttp.ClientConnectionResetError("Cannot write to closing transport")
        return await original(ws, data, *args, **kwargs)

    try:
        async with aiohttp.ClientSession() as session:
            ws, _ = await join(session, url, tmp_path / "closing")
            await ws.receive_json()
            monkeypatch.setattr(hub, "dispatch", fail_dispatch)
            monkeypatch.setattr(web.WebSocketResponse, "send_json", send_json)
            await ws.send_json({"v": 1, "type": "trigger"})
            closed = await asyncio.wait_for(ws.receive(), 3)
            assert closed.type == aiohttp.WSMsgType.CLOSE
            assert any(r["event"] == "signal.error_delivery_failed" for r in journal.query())
            assert not hub.peers
            assert "Error handling request" not in caplog.text
            await ws.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_two_person_rooms_no_relay_and_admin_export(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            a, wa = await join(session, url, tmp_path / "a")
            assert wa["type"] == "welcome"
            assert (await a.receive_json())["type"] == "waiting"
            b, wb = await join(session, url, tmp_path / "b")
            assert wb["type"] == "welcome"
            pa, pb = await asyncio.gather(a.receive_json(), b.receive_json())
            assert pa["pair"] == pb["pair"]
            c, error = await join(session, url, tmp_path / "c")
            assert error["code"] == "ROOM_FULL"
            await c.close()
            async with session.get(url.replace("ws://", "http://").replace("/ws", "/logs")) as response:
                assert response.status == 401
            async with session.get(
                url.replace("ws://", "http://").replace("/ws", "/logs"),
                headers={"Authorization": "Bearer admin"},
                params={"room": "test"},
            ) as response:
                assert response.status == 200
                assert any(e["event"] == "room.join" for e in (await response.json())["events"])
            await a.send_json(
                {
                    "v": 1,
                    "type": "signal",
                    "pair": pa["pair"],
                    "data": {"kind": "chat", "attempt": "x", "text": "must-not-relay"},
                }
            )
            assert (await a.receive_json())["code"] == "SIGNAL_ONLY_NO_APPLICATION_RELAY"
            await a.close()
            await b.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_identity_binding_prevents_client_id_takeover(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            client = str(uuid.uuid4())
            original, first = await join(session, url, tmp_path / "original", client=client)
            assert first["type"] == "welcome"
            impostor, denied = await join(session, url, tmp_path / "impostor", client=client)
            assert denied["code"] == "CLIENT_IDENTITY_CHANGED"
            assert not original.closed
            await impostor.close()
            await original.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_research_signal_shapes_and_retry_attempt_bookkeeping(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            a, _ = await join(session, url, tmp_path / "research-a")
            await a.receive_json()
            b, _ = await join(session, url, tmp_path / "research-b")
            pa, _ = await asyncio.gather(a.receive_json(), b.receive_json())
            signal = {"kind": "raw_meta", "attempt": "x", "meta": {"sequence": 12345}}
            await a.send_json({"v": 1, "type": "signal", "pair": pa["pair"], "data": signal})
            assert (await b.receive_json())["data"] == signal
            for peer in hub.rooms["test"]:
                peer["signals"]["previous-matrix"] = 100
            retry = {"kind": "phase", "attempt": "setup", "phase": "retry"}
            await a.send_json({"v": 1, "type": "signal", "pair": pa["pair"], "data": retry})
            assert (await b.receive_json())["data"] == retry
            assert all("previous-matrix" not in peer["signals"] for peer in hub.rooms["test"])
            await a.close()
            await b.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


@pytest.mark.parametrize("data,expected,follower", [
    ({"kind": "path_park", "attempt": "x", "request": None}, "PATH_PARK_SCHEMA", False),
    ({"kind": "path_park_ack", "attempt": "x", "request": "0" * 16, "allowed": 1}, "PATH_PARK_SCHEMA", False),
    ({"kind": "path_reopen_request", "attempt": "x", "request": "0" * 16, "mode": "chat"}, "PATH_REOPEN_SCHEMA", False),
    ({"kind": "path_reopen", "attempt": "x", "source": "old", "request": "0" * 16, "mode": "use"}, "ONLY_COORDINATOR_CAN_REOPEN", True),
    ({"kind": "path_reopen_reject", "attempt": "x", "request": "0" * 16, "reason": "text"}, "PATH_REOPEN_REJECT_SCHEMA", False),
    ({"kind": "raw_meta", "attempt": "x", "meta": {"sequence": 1, "text": "no"}}, "RAW_METADATA_SCHEMA", False),
    ({"kind": "raw_meta", "attempt": "x", "meta": {"sequence": True}}, "RAW_METADATA_RANGE", False),
    ({"kind": "plan_part", "attempt": "setup", "index": 0, "total": 65, "plan": []}, "PLAN_PART_SCHEMA", False),
    ({"kind": "phase", "attempt": "setup", "phase": "unexpected"}, "PHASE_SCHEMA", False),
    ({"kind": "phase", "attempt": "setup", "phase": "retry"}, "ONLY_COORDINATOR_CAN_RESTART_MATRIX", True),
])
async def test_research_invalid_signals_rejected_and_closed(tmp_path, data, expected, follower):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            a, _ = await join(session, url, tmp_path / "bad-a")
            await a.receive_json()
            b, _ = await join(session, url, tmp_path / "bad-b")
            pa, _ = await asyncio.gather(a.receive_json(), b.receive_json())
            sender = b if follower else a
            await sender.send_json({"v": 1, "type": "signal", "pair": pa["pair"], "data": data})
            assert (await sender.receive_json())["code"] == expected
            await a.close()
            await b.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_automatic_ipv6_callback_while_alone_and_central_logging(tmp_path, capsys):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    hub.allow_inbound = hub.allow_loopback = True
    client = Client(
        {
            "server": url,
            "loopback": True,
            "data_dir": str(tmp_path / "callback"),
            "experiment": {"diagnostics": False, "gateway": False, "stun": []},
        },
        "callback",
        console=True,
    )
    task = asyncio.create_task(client.signaling())
    upload = asyncio.create_task(client.uploader())
    try:
        await asyncio.wait_for(client.connected.wait(), 5)
        client.network = {"addresses": [{"address": "::1", "family": 6}]}
        client.network_ready.set()
        await asyncio.wait_for(client.inbound_task, 10)
        results = [record for record in client.log.query() if record["event"] == "ipv6.inbound_result"]
        assert len(results) == 1
        assert results[0]["fields"]["code"] == "REACHABLE"
        assert results[0]["fields"]["listener_received"] is True
        assert results[0]["fields"]["firewall_assessment"] == "HTTP_ALLOWED_FOR_THIS_PROBE"
        assert results[0]["fields"]["address"] == "::1"
        assert results[0]["fields"]["port"] >= 1024
        assert results[0]["fields"]["elapsed_ms"] >= 0
        assert client.pair is None
        assert client.manager is None
        async with asyncio.timeout(5):
            while client.log.pending():
                await asyncio.sleep(0.05)
        assert any(record["event"] == "ipv6.inbound" for record in journal.query(room="callback"))
        assert any(record["id"] == results[0]["id"] for record in journal.query(room="callback"))
        assert "IPv6 HTTP callback reached the client" in capsys.readouterr().out
    finally:
        await client.close()
        task.cancel()
        upload.cancel()
        await asyncio.gather(task, upload, return_exceptions=True)
        await cleanup_hub(journal, runner, transport, tcp)


async def test_full_client_pair_matrix_and_central_upload(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    options = {
        "timeout": 1,
        "profiles": ["fast"],
        "gateway": False,
        "diagnostics": False,
        "stun": [],
        "max_pairs": 1,
        "port_prediction": False,
    }
    clients = [
        Client(
            {
                "server": url,
                "data_dir": str(tmp_path / name),
                "name": name,
                "loopback": True,
                "experiment": options,
            },
            "matrix",
            console=False,
        )
        for name in ("a", "b")
    ]
    tasks = []
    try:
        for client in clients:
            tasks.extend(
                [
                    asyncio.create_task(client.signaling()),
                    asyncio.create_task(client.uploader()),
                    asyncio.create_task(client.collect_network()),
                ]
            )
        await asyncio.wait_for(asyncio.gather(*(c.paired.wait() for c in clients)), 10)
        while any(c.manager.task is None for c in clients):
            await asyncio.sleep(0.01)
        await asyncio.wait_for(asyncio.gather(*(c.manager.task for c in clients)), 90)
        assert all(len(c.manager.results) == len(c.manager.plan) for c in clients)
        assert all(any(r["data_path"] for r in c.manager.results) for c in clients)
        await clients[0].chat("integration chat")
        await clients[0].command("/ping")
        await clients[0].command("/speed 1")
        async with asyncio.timeout(10):
            while any(c.log.pending() for c in clients):
                await asyncio.sleep(0.05)
        events = journal.query(room="matrix")
        assert any(e["event"] == "chat.delivered" for e in events)
        assert any(e["event"] == "experiment.completed" for e in events)
        assert all(client.peer_network for client in clients)
        assert sum(e["event"] == "network.peer_status" for e in events) >= 2
        assert all("integration chat" not in str(e) for e in events)
        for client in clients:
            recorded = {e["fields"]["attempt"]: e["fields"]["state"] for e in events
                        if e["client"] == client.log.client and e["event"] == "experiment.result"}
            assert recorded == {r["attempt"]: r["state"] for r in client.manager.results}
    finally:
        for client in clients:
            await client.close()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await cleanup_hub(journal, runner, transport, tcp)
