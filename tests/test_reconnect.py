import asyncio
from types import SimpleNamespace

import aiohttp
import pytest

from p2plab.client import Client
from tests.test_server import cleanup_hub, join, start_hub


async def wait_for(predicate, timeout=5):
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.05)


async def test_disconnect_spools_and_reconnect_delivers_without_loss(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    client = Client(
        {
            "server": url,
            "data_dir": str(tmp_path / "client"),
            "logs": {"upload_interval": 0.1, "retry_interval": 0.2},
            "experiment": {"diagnostics": False, "gateway": False, "stun": []},
        },
        "reconnect",
        console=False,
    )
    signaling = asyncio.create_task(client.signaling())
    uploader = asyncio.create_task(client.uploader())
    try:
        await asyncio.wait_for(client.connected.wait(), 5)
        old_peer = client.peer_id
        online = client.log.event("test.before_disconnect")
        await wait_for(lambda: not client.log.pending())
        await client.ws.close()
        client.connected.clear()
        offline = [client.log.event("test.offline", index=i) for i in range(20)]
        await wait_for(lambda: client.connected.is_set() and client.peer_id != old_peer)
        await wait_for(lambda: not client.log.pending())
        records = journal.query(room="reconnect", limit=1000)
        ids = [record["id"] for record in records]
        for event in [online, *offline]:
            assert ids.count(event["id"]) == 1
        assert any(record["event"] == "signaling.offline" for record in records)
    finally:
        await client.close()
        signaling.cancel()
        uploader.cancel()
        await asyncio.gather(signaling, uploader, return_exceptions=True)
        await cleanup_hub(journal, runner, transport, tcp)


async def test_departed_pair_late_signal_does_not_disconnect_waiting_or_repaired_client(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            a, _ = await join(session, url, tmp_path / "a")
            await a.receive_json()
            b, _ = await join(session, url, tmp_path / "b")
            pa, _ = await asyncio.gather(a.receive_json(), b.receive_json())
            old = {"v": 1, "type": "signal", "pair": pa["pair"],
                   "data": {"kind": "ready", "attempt": "setup", "addresses": []}}
            await b.close()
            assert (await a.receive_json())["type"] == "peer_left"
            await a.send_json(old)
            await wait_for(lambda: any(r["event"] == "signal.stale_pair" for r in journal.query()))
            assert not a.closed and len(hub.peers) == 1
            c, _ = await join(session, url, tmp_path / "c")
            new, remote = await asyncio.gather(a.receive_json(), c.receive_json())
            assert new["pair"] != pa["pair"]
            await a.send_json(old)
            await a.send_json({**old, "pair": new["pair"]})
            received = await asyncio.wait_for(c.receive_json(), 3)
            assert received["pair"] == remote["pair"]
            assert not any(r["event"] == "signaling.error" for r in journal.query())
            await a.close()
            await c.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_peer_left_cancels_pending_pair_setup_and_stops_status_publication(peers, monkeypatch):
    client, peer = peers
    client.connected.set()
    client.paired.set()
    started = asyncio.Event()

    async def setup():
        started.set()
        await asyncio.Event().wait()

    async def never(*args):
        pytest.fail("A waiting client must not signal a departed pair")

    client.pair_task = client.spawn(setup(), "pair-setup")
    await started.wait()
    monkeypatch.setattr(client, "signal", never)
    await client.handle_control({"type": "peer_left", "peer": peer.peer_id})
    assert client.pair is None and not client.paired.is_set() and client.pair_task.cancelled()
    await client.publish_status()
    assert client.connected.is_set()


@pytest.mark.parametrize("forwarded,source", [(True, "8.8.8.8"), (False, "192.168.1.88")])
async def test_forwarded_welcome_keeps_external_observers_not_proxy_mapping(peers, forwarded, source):
    client, _ = peers
    client.loopback = False
    client.extra_observers = ["stun.cloudflare.com:3478"]
    await client.handle_control({"type": "welcome", "id": "new-session", "observation_token": "test",
                                 "observed_ipv4": source, "stun_port": 8443, "tcp_port": 8443,
                                 "tcp_observer_protocol": "http", "inbound_check": False,
                                 "inbound_ipv4_check": True,
                                 "observation_mode": "forwarded" if forwarded else "direct"})
    await asyncio.gather(client.inbound_task)
    assert client.observers == client.extra_observers and client.tcp_observer is None
    assert client.server_observed_ipv4 == source and not client.inbound_ipv4_supported
    assert client.pair is None


async def test_queued_old_pair_send_is_rejected_after_pair_changes(peers):
    client, _ = peers
    client.ws = SimpleNamespace(closed=False)
    old_pair = client.pair
    async with client.signal_lock:
        send = asyncio.create_task(client.send_control({"type": "signal", "pair": old_pair, "data": {}}))
        await asyncio.sleep(0)
        client.pair = None
    with pytest.raises(ConnectionError, match="SIGNALING_PAIR_CHANGED"):
        await send


async def test_peer_leaves_while_new_pair_setup_is_still_closing_old_managers(peers, monkeypatch):
    client, _ = peers
    started = asyncio.Event()

    async def setup(body):
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(client, "begin_pair", setup)
    await client.handle_control({"type": "paired", "peer": {"id": "new-peer"}})
    await started.wait()
    await client.handle_control({"type": "peer_left", "peer": "new-peer"})
    assert client.pair_task.cancelled() and client.pair is None and client.pending_pair_peer is None
