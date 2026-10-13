import asyncio

from p2plab.client import Client
from tests.test_server import cleanup_hub, start_hub


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
