"""Real sockets + controlled pending-write order; not Windows execution evidence."""
import asyncio
from asyncio.proactor_events import _ProactorDatagramTransport
import socket
import uuid
from types import SimpleNamespace
import pytest
from aioice.ice import StunProtocol
from p2pchat.backend.rtc_shutdown import abort_stalled_udp,assert_sockets_released,affected_runtime
from p2pchat.backend import rtc_shutdown
from p2pchat.peer import Peer
from p2pchat.tests.backend.cleanup import cleanup_peers

class Receiver:
    def data_received(self,data,component):pass

@pytest.mark.asyncio
async def test_proactor_pending_write_close_stall_then_public_abort():
    # Execute CPython's actual Proactor transport methods without a Windows IOCP
    # backend. Pending Future models one send completion; socket and callback real.
    loop=asyncio.get_running_loop();sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1',0));sock.connect(('127.0.0.1',9));protocol=StunProtocol(Receiver())
    class NoReaderTransport(_ProactorDatagramTransport):
        def _loop_reading(self,fut=None):pass
    transport=NoReaderTransport(loop,sock,protocol)
    await asyncio.sleep(0)
    pending=loop.create_future();transport._write_fut=pending
    close=asyncio.create_task(protocol.close());await asyncio.sleep(0)
    # Graceful close sees pending write; completion returns at _conn_lost guard.
    pending.set_result(None);transport._loop_writing(pending)
    done,_=await asyncio.wait({close},timeout=.01)
    assert not done and sock.fileno()!=-1
    helper=asyncio.create_task(abort_stalled_udp(close,[transport],grace=.01))
    await asyncio.wait_for(asyncio.shield(close),1);await helper
    assert sock.fileno()==-1
    assert_sockets_released([transport])
    assert not close.cancelled()

@pytest.mark.asyncio
async def test_abort_guard_does_not_touch_active_transport():
    class Active:
        def is_closing(self):return False
        def abort(self):raise AssertionError('active transport aborted')
    finish=asyncio.Event()
    task=asyncio.create_task(finish.wait());helper=asyncio.create_task(abort_stalled_udp(task,[Active()],.005))
    await asyncio.sleep(.02);finish.set();await task;await helper

@pytest.mark.asyncio
async def test_real_aioice_udp_close_releases_socket():
    loop=asyncio.get_running_loop();transport,protocol=await loop.create_datagram_endpoint(lambda:StunProtocol(Receiver()),local_addr=('127.0.0.1',0))
    sock=transport.get_extra_info('socket')
    await asyncio.wait_for(protocol.close(),1)
    assert sock.fileno()==-1

@pytest.mark.asyncio
async def test_peer_close_deadline_and_repeat_failure(tmp_path,capsys):
    class StuckPC:
        sctp=None
        def __init__(self):self.release=asyncio.Event()
        async def close(self):await self.release.wait()
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path);peer.CLOSE_TIMEOUT=.03
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    await path['pc'].close();pc=StuckPC();path['pc']=pc
    try:
        with pytest.raises(BaseExceptionGroup):await peer.close()
        with pytest.raises(BaseExceptionGroup):await peer.close()
        assert 'P2P_CLOSE_TIMEOUT' in capsys.readouterr().err
        assert not path['rtc_close_task'].cancelled()
    finally:
        pc.release.set();await asyncio.gather(path['rtc_close_task'],return_exceptions=True)

@pytest.mark.asyncio
async def test_original_body_error_and_cleanup_error_preserved():
    class BrokenPeer:
        async def close(self):raise RuntimeError('cleanup')
    class Runner:
        async def cleanup(self):pass
    body=KeyError('original')
    with pytest.raises(BaseExceptionGroup) as info:await cleanup_peers([BrokenPeer()],[],Runner(),body)
    assert body in info.value.exceptions
    assert any(isinstance(e,RuntimeError) for e in info.value.exceptions)

@pytest.mark.asyncio
async def test_benchmark_waits_for_event_and_fails_on_closed(tmp_path):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()));path['hello']=True
    waiter=asyncio.create_task(peer.wait_benchmark(path,.5));await asyncio.sleep(0)
    assert not waiter.done()
    path['benchmark']=SimpleNamespace(readyState='open');path['benchmark_ready'].set()
    assert await waiter is path['benchmark']
    await peer.close()
    with pytest.raises(RuntimeError):await peer.wait_benchmark(path)


def test_exact_runtime_guard(monkeypatch):
    monkeypatch.setattr(rtc_shutdown.sys,'platform','win32')
    monkeypatch.setattr(rtc_shutdown.sys,'version_info',(3,12,10))
    monkeypatch.setattr(rtc_shutdown,'version',lambda name:{'aiortc':'1.15.0','aioice':'0.10.2'}[name])
    assert affected_runtime()
    monkeypatch.setattr(rtc_shutdown.sys,'version_info',(3,12,11))
    assert not affected_runtime()
    monkeypatch.setattr(rtc_shutdown.sys,'version_info',(3,12,10))
    monkeypatch.setattr(rtc_shutdown,'version',lambda name:'future-version')
    assert not affected_runtime()

@pytest.mark.asyncio
async def test_concurrent_close_and_cancel_one_waiter_preserves_socket(tmp_path):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    a=asyncio.create_task(peer.close_path(path));b=asyncio.create_task(peer.close_path(path))
    await asyncio.sleep(0);a.cancel();await asyncio.gather(a,return_exceptions=True)
    await b
    assert path['rtc_close_task'].done() and not path['rtc_close_task'].cancelled()
    await peer.close()

@pytest.mark.asyncio
async def test_abort_failure_is_not_ignored(monkeypatch):
    gate=asyncio.Event()
    class Transport:
        def is_closing(self):return True
        def abort(self):raise OSError('controlled abort error')
    class PC:
        async def close(self):await gate.wait()
    monkeypatch.setattr(rtc_shutdown,'owned_udp_transports',lambda pc:[Transport()])
    try:
        with pytest.raises(OSError):await rtc_shutdown.close_rtc(PC())
    finally:
        gate.set();await asyncio.sleep(0)
