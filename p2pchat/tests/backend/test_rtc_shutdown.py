"""Real sockets + controlled pending-write order; not Windows execution evidence."""
import asyncio
from asyncio.proactor_events import _ProactorDatagramTransport
import socket
import time
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

def _flatten(exc):
    """展开嵌套 ExceptionGroup，取出叶子错误（用于断言具体原因码）。"""
    return [leaf for item in exc.exceptions for leaf in _flatten(item)] if isinstance(exc,BaseExceptionGroup) else [exc]


@pytest.mark.asyncio
async def test_peer_close_deadline_and_repeat_failure(tmp_path,capsys):
    """关闭时 RTC 排空未完成：**有界**（不超过 CLOSE_TIMEOUT+余量）返回/失败并带明确原因码。

    这就是 Windows 上 test_outage 报的那条路径：`P2P_CLOSE_TIMEOUT:path.workers_rtc`。
    """
    class StuckPC:
        sctp=None
        def __init__(self):self.release=asyncio.Event()
        async def close(self):await self.release.wait()
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path);peer.CLOSE_TIMEOUT=.03
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    await path['pc'].close();pc=StuckPC();path['pc']=pc
    try:
        started=time.monotonic()
        with pytest.raises(BaseExceptionGroup) as path_level:await peer.close_path(path)
        with pytest.raises(BaseExceptionGroup) as first:await peer.close()
        elapsed=time.monotonic()-started
        with pytest.raises(BaseExceptionGroup):await peer.close()      # 幂等：重复调用看到同一结果
        assert elapsed < 2*(peer.CLOSE_TIMEOUT+0.5), elapsed           # 有界，不是无限等待
        assert 'P2P_CLOSE_TIMEOUT:path.workers_rtc' in [str(leaf) for leaf in _flatten(path_level.value)]
        codes=[str(leaf) for leaf in _flatten(first.value)]
        assert 'P2P_CLOSE_TIMEOUT:path.workers_rtc' in codes           # 明确原因码（CI 报的相位）
        # 外层组一定是 peer 级相位；内层带具体路径相位（若路径更慢则退化为 peer 级超时叶）
        assert first.value.message=='P2P close failed: peer.workers_ws_paths'
        assert 'P2P_CLOSE_TIMEOUT' in capsys.readouterr().err
        assert path['closing'] is True
        assert not path['rtc_close_task'].cancelled()                  # 残余任务仍被持有，不当成功
    finally:
        pc.release.set()
        residual=path.get('rtc_close_task')
        if residual is not None:await asyncio.gather(residual,return_exceptions=True)


@pytest.mark.asyncio
async def test_traversal_structure_drift_never_breaks_close(monkeypatch,capsys):
    """库私有结构变了：遍历放弃规避（一行 stderr），但绝不能把关闭变成异常。"""
    monkeypatch.setattr(rtc_shutdown,'_TRAVERSAL_WARNED',False)
    _gate(monkeypatch,'win32',(3,12,14))
    assert rtc_shutdown.owned_udp_transports(SimpleNamespace(sctp=SimpleNamespace())) == []
    assert 'P2P_UDP_TRAVERSAL_UNAVAILABLE' in capsys.readouterr().err
    assert rtc_shutdown.owned_udp_transports(SimpleNamespace(sctp=None)) == []
    closed=asyncio.Event()
    async def close():closed.set()
    await rtc_shutdown.close_rtc(SimpleNamespace(close=close))
    assert closed.is_set()


def _drain_attempt(pending,state='direct',drain_timeout=0.2):
    from p2pchat.native.adapter import Attempt,Budget
    attempt=Attempt.__new__(Attempt)      # 不跑 __init__（需要 bridge）；只测排水等待本身
    attempt.state=state
    attempt.quic=object()
    attempt.adapter=SimpleNamespace(budget=Budget(drain_timeout=drain_timeout))
    async def pending_bytes():return pending
    attempt.quic_pending_bytes=pending_bytes
    return attempt


@pytest.mark.asyncio
async def test_drain_wait_bounded_and_short_circuited_by_close():
    """排水等待：排空即返回；对方不 ACK 到界报 BACKPRESSURE；关闭/失败立刻短路为 CLOSED；取消不被吞。"""
    assert await _drain_attempt(0).wait_for_quic_drain(1) is None          # 控制组：正常排空
    started=time.monotonic()
    with pytest.raises(ValueError) as backpressure:
        await _drain_attempt(10**9,drain_timeout=0.05).wait_for_quic_drain(1)
    assert str(backpressure.value)=='BACKPRESSURE'
    assert time.monotonic()-started<0.5                                    # 有界，不无限等
    for state in ('closed','failed','timeout','unsupported'):
        started=time.monotonic()
        with pytest.raises(ValueError) as closed:
            await _drain_attempt(10**9,state=state,drain_timeout=30).wait_for_quic_drain(1)
        assert str(closed.value)=='CLOSED'
        assert time.monotonic()-started<0.5                                # 不把 30s 预算等满
    task=asyncio.create_task(_drain_attempt(10**9,drain_timeout=30).wait_for_quic_drain(1))
    await asyncio.sleep(.03);task.cancel()
    with pytest.raises(asyncio.CancelledError):await task                  # 关闭取消发送任务：立即传播

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


def _gate(monkeypatch, platform, version_info, aiortc='1.15.0', aioice='0.10.2'):
    monkeypatch.setattr(rtc_shutdown.sys, 'platform', platform)
    monkeypatch.setattr(rtc_shutdown.sys, 'version_info', version_info)
    monkeypatch.setattr(rtc_shutdown, 'version',
                        lambda name, _a={'aiortc': aiortc, 'aioice': aioice}: _a[name])
    return rtc_shutdown.gate_reason()


@pytest.mark.parametrize('platform,version_info,aiortc,aioice,expected,reason_part', [
    ('win32', (3, 12, 10), '1.15.0', '0.10.2', True, 'Proactor'),      # 当时观察并适配的组合
    ('win32', (3, 12, 14), '1.15.0', '0.10.2', True, 'Proactor'),      # runner 实际解析到的补丁
    ('win32', (3, 12, 99), '1.15.0', '0.10.2', True, 'Proactor'),      # 更高的 3.12 补丁
    ('win32', (3, 12, 9), '1.15.0', '0.10.2', False, '3.12.9'),        # 低于验证下限
    ('win32', (3, 13, 0), '1.15.0', '0.10.2', False, 'not 3.12.x'),    # 未验证的次版本
    ('linux', (3, 12, 14), '1.15.0', '0.10.2', False, 'not win32'),    # 非 Windows 不启用
    ('darwin', (3, 12, 14), '1.15.0', '0.10.2', False, 'not win32'),
    ('win32', (3, 12, 14), '1.14.9', '0.10.2', False, 'aiortc'),       # 低于库下限
    ('win32', (3, 12, 14), '1.15.0', '0.10.1', False, 'aioice'),
    ('win32', (3, 12, 14), '1.16.0', '0.11.0', True, 'Proactor'),      # 更新的库沿用同一下限策略
    ('win32', (3, 12, 14), 'future-version', '0.10.2', False, 'aiortc'),  # 解析不出来=不启用
    ('win32', (3, 12, 14), '1.15.0', 'unknown', False, 'aioice'),
])
def test_runtime_gate_is_floor_based_and_fails_closed(monkeypatch, platform, version_info,
                                                      aiortc, aioice, expected, reason_part):
    """下限式门控：3.12.10 起的补丁与新库版本都启用；版本/平台不符或解析失败一律不启用。"""
    affected, reason = _gate(monkeypatch, platform, version_info, aiortc, aioice)
    assert affected is expected
    assert reason_part in reason
    assert affected_runtime() is expected


def test_runtime_note_names_platform_versions_gate_and_reason(monkeypatch, capsys):
    """CI 日志要能一眼看出门控为何开/关，且这行不得含载荷/密钥类字样。"""
    monkeypatch.setattr(rtc_shutdown, '_RUNTIME_LOGGED', False)
    affected, _ = _gate(monkeypatch, 'win32', (3, 12, 14), '1.15.0', '0.10.2')
    assert affected
    rtc_shutdown.log_runtime_once()
    rtc_shutdown.log_runtime_once()          # 只打一次
    line = capsys.readouterr().err
    assert line.count('P2P_RTC_SHUTDOWN') == 1
    for field in ('platform=win32', 'python=3.12.14', 'aiortc=1.15.0', 'aioice=0.10.2', 'gate=on', 'reason='):
        assert field in line, field
    for forbidden in ('secret', 'proof', 'sdp', 'candidate', 'password', 'token'):
        assert forbidden not in line.lower()
    monkeypatch.setattr(rtc_shutdown, '_RUNTIME_LOGGED', False)
    affected, _ = _gate(monkeypatch, 'linux', (3, 12, 14))
    assert not affected
    rtc_shutdown.log_runtime_once()
    assert 'gate=off reason=platform=linux is not win32' in capsys.readouterr().err


class _ProactorLookalike(asyncio.DatagramTransport):
    """只有 __module__/__name__ 长得像，类型不是 asyncio.proactor_events 的真类型。"""

    def __init__(self, closing=True):
        self._closing = closing
        self.aborted = False

    def is_closing(self):
        return self._closing

    def abort(self):
        self.aborted = True


_ProactorLookalike.__module__ = 'asyncio.proactor_events'
_ProactorLookalike.__name__ = '_ProactorDatagramTransport'
_ProactorLookalike.__qualname__ = '_ProactorDatagramTransport'


class _ForeignTransport(_ProactorLookalike):
    """同一个类层次，但来自别的模块：遍历必须拒绝。"""


_ForeignTransport.__module__ = 'some.other.module'
_ForeignTransport.__name__ = '_ProactorDatagramTransport'


def _fake_pc(*transports):
    """镜像 peer/pc 的私有结构 pc.sctp.transport.transport._connection._protocols[].transport。"""
    protocols = [SimpleNamespace(transport=transport) for transport in transports]
    connection = SimpleNamespace(_protocols=protocols)
    return SimpleNamespace(sctp=SimpleNamespace(
        transport=SimpleNamespace(transport=SimpleNamespace(_connection=connection))))


@pytest.mark.asyncio
async def test_gate_off_never_calls_abort_and_gate_on_takes_the_runner_version(monkeypatch):
    """门控 False：遍历为空、close 全程不 abort；门控 True（runner 的 win32 3.12.14）：只 abort is_closing 的自身 transport。"""
    stalled, active, foreign = _ProactorLookalike(closing=True), _ProactorLookalike(closing=False), _ForeignTransport(closing=True)
    pc = _fake_pc(stalled, active, foreign)
    closed = asyncio.Event()

    async def close():
        closed.set()

    _gate(monkeypatch, 'linux', (3, 12, 14))
    assert rtc_shutdown.owned_udp_transports(pc) == []
    await rtc_shutdown.close_rtc(SimpleNamespace(close=close))
    assert closed.is_set()
    assert not stalled.aborted and not active.aborted and not foreign.aborted

    _gate(monkeypatch, 'win32', (3, 12, 14))
    assert rtc_shutdown.owned_udp_transports(pc) == [stalled, active]   # 精确类型：外来同名类被拒
    blocked = asyncio.create_task(asyncio.Event().wait())
    helper = asyncio.create_task(rtc_shutdown.abort_stalled_udp(blocked, [stalled, active], grace=.01))
    await asyncio.sleep(.03)
    assert stalled.aborted and not active.aborted                      # 只动已经 is_closing 的
    helper.cancel();blocked.cancel()
    await asyncio.gather(helper, blocked, return_exceptions=True)
