import asyncio
import uuid

import pytest
import pytest_asyncio

from p2plab.client import Client


@pytest_asyncio.fixture(params=[False, True], ids=["normal-tasks", "eager-tasks"])
async def task_scheduling(request):
    loop = asyncio.get_running_loop()
    previous = loop.get_task_factory()
    loop.set_task_factory(asyncio.eager_task_factory if request.param else None)
    try:
        yield
    finally:
        loop.set_task_factory(previous)


@pytest.fixture
def peers(tmp_path):
    config = {
        "server": "ws://127.0.0.1:8443/ws",
        "experiment": {"timeout": 2, "gateway": False, "diagnostics": False, "stun": []},
        "loopback": True,
    }
    a = Client({**config, "data_dir": str(tmp_path / "a")}, "test", console=False)
    b = Client({**config, "data_dir": str(tmp_path / "b")}, "test", console=False)
    a.peer_id, b.peer_id = str(uuid.uuid4()), str(uuid.uuid4())
    a.pair = b.pair = str(uuid.uuid4())
    a.leader, b.leader = True, False
    for local, remote in ((a, b), (b, a)):
        local.peer = {
            "id": remote.peer_id,
            "name": "peer",
            "public": remote.identity.public,
            "certificate": remote.identity.cert_pem,
        }
    yield a, b
    for peer in (a, b):
        peer.identity.close()
        peer.log.close()
