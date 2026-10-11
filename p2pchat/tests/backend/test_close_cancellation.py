"""Failure injection owns real sockets; never claims mock P2P success."""
import asyncio
import socket
import uuid
import pytest
from p2pchat.peer import Peer
from p2pchat.tests.backend.cleanup import cleanup_peers


def leaves(error):
    if isinstance(error,BaseExceptionGroup):
        return [leaf for child in error.exceptions for leaf in leaves(child)]
    return [error]

class CancelledSocketOwner:
    sctp=None
    closed=False
    def __init__(self):
        self.socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        self.socket.bind(('127.0.0.1',0))
    async def close(self):
        # Deliberately model a resource close cancelled before socket release.
        raise asyncio.CancelledError()

@pytest.mark.asyncio
@pytest.mark.parametrize('resource',['rtc','ws'])
async def test_required_close_cancelled_is_failure_with_socket_still_open(tmp_path,resource):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    owner=CancelledSocketOwner();events=[]
    peer.event=lambda kind,data,path=None:events.append((kind,data))
    if resource=='ws':peer.ws=owner
    else:
        aid=str(uuid.uuid4())
        peer.paths[aid]={'pc':owner,'files':{},'acks':{},'tasks':set(),'attempt':aid,
            'connectionId':str(uuid.uuid4()),'closing':False,'hello':True,
            'low':asyncio.Event(),'benchmark_ready':asyncio.Event()}
    try:
        for _ in range(2):
            with pytest.raises(BaseExceptionGroup) as failure:await peer.close()
            assert any(isinstance(e,RuntimeError) and 'P2P_CLOSE_CANCELLED' in str(e) for e in leaves(failure.value))
        assert owner.socket.fileno()!=-1
        assert not any(data.get('state')=='closed' for _,data in events)
    finally:owner.socket.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('cancelled',['peer','runner'])
async def test_cancelled_cleanup_preserves_body_error(cancelled):
    class ClosingPeer:
        async def close(self):
            if cancelled=='peer':raise asyncio.CancelledError()
    class ClosingRunner:
        async def cleanup(self):
            if cancelled=='runner':raise asyncio.CancelledError()
    body=KeyError('original-body')
    with pytest.raises(BaseExceptionGroup) as failure:
        await cleanup_peers([ClosingPeer()],[],ClosingRunner(),body)
    assert body in leaves(failure.value)
    assert any(isinstance(e,RuntimeError) and 'TEST_CLEANUP_CANCELLED' in str(e) for e in leaves(failure.value))

@pytest.mark.asyncio
async def test_expected_worker_cancel_does_not_fail_cleanup(tmp_path):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    worker=peer.spawn(asyncio.Event().wait());await asyncio.sleep(0)
    await peer.close();assert worker.cancelled()
    class Runner:
        async def cleanup(self):pass
    run=asyncio.create_task(asyncio.Event().wait());await asyncio.sleep(0)
    await cleanup_peers([], [run], Runner())
    assert run.cancelled()
