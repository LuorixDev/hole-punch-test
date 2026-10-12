"""Narrow close-only workaround for CPython Proactor UDP drain stall.

Observed runner: CPython 3.12.10, aiortc 1.15.0, aioice 0.10.2. Never
manufacture connection_lost or mutate aioice's __closed Future. The public
DatagramTransport.abort() really cancels I/O/closes the socket and delivers the
normal protocol callback. A failed/unknown closure remains a failed shutdown.

门控腐烂（t34 记录，必须保留）：t22 曾把这段规避逻辑门控成**精确等式**
`win32 + Python==3.12.10 + aiortc==1.15.0 + aioice==0.10.2`。当 runner 的
`python-version: '3.12'` 解析出的补丁版本从 3.12.10 升到 3.12.14 之后，等式静默变成
False：规避逻辑不再运行，pc.close() 又卡在 CPython Proactor 的 pending-write 排空上，
表现为 Windows 上 test_outage 的 `P2P_CLOSE_TIMEOUT:path.workers_rtc`。这不是偶发，
而是"精确版本门控"随时间必然失效。现在改成**下限式**门控，并把每次关闭时的门控结论打到
stderr；下次补丁升级时，CI 日志里能一眼看出门控为何开/关。

为什么放宽仍然安全（与补丁号无关）：
- 卡点机制由**传输实现形状**决定，不由补丁号决定：`_ProactorDatagramTransport` 在有
  pending write 时遇到 conn_lost 直接 return，不再安排 connection_lost，aioice 的
  StunProtocol.close 因此等不到回调。3.12.10 之后的补丁仍走同一段代码。
- 遍历仍然只认 `sys.platform=='win32'` 与**精确类型**
  `asyncio.proactor_events._ProactorDatagramTransport`；类型不符一律不碰。
- 只对本 Peer 自己 data-only PC 拥有的 UDP transport 生效，且只对**已经 is_closing()**
  的调用公开 abort()；持续传输中的 transport 绝不 abort。
- 外层有界关闭不变：Peer/path 共享绝对截止（CLOSE_TIMEOUT）；这里只观察原始 pc.close()
  真正完成，超时仍然大声失败（P2P_CLOSE_TIMEOUT），残余任务继续被持有，不当成功。
- 库版本用下限：aiortc>=1.15.0、aioice>=0.10.2（当时实际观察并适配的组合），更高的版本
  沿用同一条公开 abort 路径。若将来 aioice 改变 StunProtocol.close 语义，本门控与
  tests/backend/test_rtc_shutdown.py 的断言必须重新验证——runtime 日志就是留给那时的证据。
"""
import asyncio
from importlib.metadata import version
import re
import sys

MIN_PYTHON = (3, 12, 10)
MIN_AIORTC = (1, 15, 0)
MIN_AIOICE = (0, 10, 2)
_RUNTIME_LOGGED = False
_TRAVERSAL_WARNED = False


def _version_tuple(text):
    """'1.15.0'/'2.0.0rc1' -> (1,15,0)/(2,0,0)；解析不出来返回 ()（宁可不启用）。"""
    parts = []
    for chunk in str(text).split('.')[:3]:
        digits = re.match(r'\d+', chunk)
        if digits is None:
            break
        parts.append(int(digits.group()))
    return tuple(parts)


def _version_of(name):
    try:
        return str(version(name))
    except Exception:  # 包元数据缺失：按不满足下限处理，绝不默认启用
        return 'unknown'


def _dotted(value):
    return '.'.join(str(part) for part in value)


def gate_reason():
    """返回 (是否启用规避逻辑, 人话原因)。

    原因里只有平台/版本/门控结论，没有载荷、密钥、地址或候选。
    """
    if sys.platform != 'win32':
        return False, 'platform=%s is not win32' % sys.platform
    python = '.'.join(str(part) for part in sys.version_info[:3])
    if sys.version_info[:2] != MIN_PYTHON[:2]:
        return False, 'python %s is not %d.%d.x' % (python, MIN_PYTHON[0], MIN_PYTHON[1])
    if sys.version_info[:3] < MIN_PYTHON:
        return False, 'python %s < %s' % (python, _dotted(MIN_PYTHON))
    aiortc, aioice = _version_of('aiortc'), _version_of('aioice')
    if _version_tuple(aiortc) < MIN_AIORTC:
        return False, 'aiortc %s < %s' % (aiortc, _dotted(MIN_AIORTC))
    if _version_tuple(aioice) < MIN_AIOICE:
        return False, 'aioice %s < %s' % (aioice, _dotted(MIN_AIOICE))
    return True, ('win32 python %s aiortc %s aioice %s: Proactor pending-write drain workaround '
                  '(mechanism is patch-independent; verified from %s)'
                  % (python, aiortc, aioice, _dotted(MIN_PYTHON)))


def affected_runtime():
    return gate_reason()[0]


def runtime_note():
    """一行门控证据：平台、Python 补丁版本、aiortc/aioice 版本、门控结果与原因。"""
    affected, reason = gate_reason()
    return ('P2P_RTC_SHUTDOWN platform=%s python=%s aiortc=%s aioice=%s gate=%s reason=%s'
            % (sys.platform,
               '.'.join(str(part) for part in sys.version_info[:3]),
               _version_of('aiortc'), _version_of('aioice'),
               'on' if affected else 'off', reason))


def log_runtime_once():
    """第一次关闭时把门控结论写进 stderr；之后不再重复。"""
    global _RUNTIME_LOGGED
    if _RUNTIME_LOGGED:
        return
    _RUNTIME_LOGGED = True
    print(runtime_note(), file=sys.stderr, flush=True)


def owned_udp_transports(pc):
    """Private read-only traversal, enabled for the verified mechanism.

    Our Peer creates data-only PCs. The traversal still demands the exact Proactor
    datagram transport type: a look-alike from another module is never touched.

    Best effort by construction: if the private structure drifts (library upgrade),
    this returns [] after one stderr note instead of turning a close into an
    exception. The peer-level deadline still bounds the close, so a stall stays a
    loud failure rather than a silent success.
    """
    global _TRAVERSAL_WARNED
    if not affected_runtime():return []
    try:
        if pc.sctp is None:return []
        connection=pc.sctp.transport.transport._connection
        protocols=tuple(connection._protocols)
    except Exception as exc:  # 私有结构变了：放弃规避，但绝不把关闭变成异常
        if not _TRAVERSAL_WARNED:
            _TRAVERSAL_WARNED=True
            print('P2P_UDP_TRAVERSAL_UNAVAILABLE reason=%s' % type(exc).__name__,file=sys.stderr,flush=True)
        return []
    result=[]
    for protocol in protocols:
        transport=protocol.transport
        if (type(transport).__module__=='asyncio.proactor_events'
                and type(transport).__name__=='_ProactorDatagramTransport'
                and isinstance(transport,asyncio.DatagramTransport)):
            result.append(transport)
    return result


async def abort_stalled_udp(close_task,transports,grace=.25):
    """Observe graceful close then abort only already-closing owned UDP sockets.

    Stop when close completes. This task is cancelled/joined by its owner. If
    aiortc reaches the UDP close later (SCTP drain first), continue observing.
    """
    aborted=set()
    while not close_task.done():
        done,_=await asyncio.wait({close_task},timeout=grace)
        if done:return
        for transport in transports:
            if transport not in aborted and transport.is_closing():
                print('P2P_UDP_CLOSE_ABORT runtime=cpython312-proactor',file=sys.stderr,flush=True)
                transport.abort()
                aborted.add(transport)


def assert_sockets_released(transports):
    for transport in transports:
        sock=transport.get_extra_info('socket')
        if sock is not None and sock.fileno()!=-1:
            raise RuntimeError('P2P_UDP_SOCKET_NOT_RELEASED')


async def close_rtc(pc):
    log_runtime_once()
    transports=owned_udp_transports(pc)
    close=asyncio.create_task(pc.close())
    # Shielding protects aiortc's shared completion Future, including concurrent
    # library-internal close callers. The Peer deadline observes without cancel.
    helper=asyncio.create_task(abort_stalled_udp(close,transports)) if transports else None
    close.add_done_callback(lambda t: None if t.cancelled() else t.exception())
    try:
        if helper:
            done,_=await asyncio.wait({close,helper},return_when=asyncio.FIRST_COMPLETED)
            if helper in done:helper.result()  # abort errors are shutdown errors
        await asyncio.shield(close)
        assert_sockets_released(transports)
    finally:
        if helper:
            helper.cancel()
            try:await helper
            except asyncio.CancelledError:pass
