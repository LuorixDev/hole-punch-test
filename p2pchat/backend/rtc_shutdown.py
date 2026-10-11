"""Narrow close-only workaround for CPython 3.12 Proactor UDP drain stall.

Observed runner: CPython 3.12.10, aiortc 1.15.0, aioice 0.10.2. Never
manufacture connection_lost or mutate aioice's __closed Future. The public
DatagramTransport.abort() really cancels I/O/closes the socket and delivers the
normal protocol callback. A failed/unknown closure remains a failed shutdown.
"""
import asyncio
from importlib.metadata import version
import sys


def affected_runtime():
    return (sys.platform == 'win32' and sys.version_info[:3] == (3,12,10)
            and version('aiortc') == '1.15.0' and version('aioice') == '0.10.2')


def owned_udp_transports(pc):
    """Private read-only traversal, enabled ONLY for the tested library versions.

    Our Peer creates data-only PCs. No traversal for other versions; their close
    still has the peer-level deadline and fails visibly if it cannot complete.
    """
    if not affected_runtime():return []
    if pc.sctp is None:return []
    connection=pc.sctp.transport.transport._connection
    result=[]
    for protocol in tuple(connection._protocols):
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
