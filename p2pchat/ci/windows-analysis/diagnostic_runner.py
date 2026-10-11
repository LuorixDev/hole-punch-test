"""Read-only pytest instrumentation: task await chains, stages, no locals/arguments.
Run under existing ci/watchdog.py; this entrypoint preserves pytest's exit status.
"""
import asyncio
import functools
import importlib.metadata
import json
from pathlib import Path
import sys
import threading
import time

ROOT=Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path: sys.path.insert(0,str(ROOT))
import pytest


def emit(stage,**data):
    print(json.dumps({'diag':'windows-peer','mono':round(time.monotonic(),3),'stage':stage,**data}),flush=True)


def chain(obj):
    result=[];seen=set()
    while obj is not None and id(obj) not in seen and len(result)<40:
        seen.add(id(obj))
        code=getattr(obj,'cr_code',None) or getattr(obj,'gi_code',None)
        frame=getattr(obj,'cr_frame',None) or getattr(obj,'gi_frame',None)
        if code:result.append({'file':Path(code.co_filename).name,'function':code.co_name,'line':frame.f_lineno if frame else code.co_firstlineno})
        obj=getattr(obj,'cr_await',None) or getattr(obj,'gi_yieldfrom',None)
    return result


def dump(loop,stage):
    if loop.is_closed():return
    tasks=[]
    for task in asyncio.all_tasks(loop):
        waiter=getattr(task,'_fut_waiter',None)
        tasks.append({'task':id(task),'done':task.done(),'cancelling':task.cancelling(), 'waiterType':type(waiter).__name__,'waiterTask':id(waiter) if isinstance(waiter,asyncio.Task) else None,'gatherChildren':[{'task':id(t),'done':t.done(),'cancelled':t.cancelled()} for t in getattr(waiter,'_children',())],'await':chain(task.get_coro())})
    emit(stage,tasks=tasks)


class DiagnosticPlugin:
    def __init__(self):self.stop=threading.Event();self.loops=set();self.originals=[];self.phase='init'
    def wrap(self,cls,name):
        original=getattr(cls,name)
        @functools.wraps(original)
        async def wrapped(obj,*args,**kwargs):
            loop=asyncio.get_running_loop();self.loops.add(loop)
            label=cls.__name__+'.'+name
            emit(label+'.start',object=id(obj),task=id(asyncio.current_task()))
            try:
                result=await original(obj,*args,**kwargs)
                emit(label+'.done',object=id(obj));return result
            except BaseException as exc:
                # Class only, no message/locals/credentials/content.
                emit(label+'.error',object=id(obj),error=type(exc).__name__)
                dump(loop,label+'.error.tasks');raise
        self.originals.append((cls,name,original));setattr(cls,name,wrapped)
    def pytest_sessionstart(self,session):
        from p2pchat.peer import Peer
        from aiortc import RTCPeerConnection
        from aiortc.rtcicetransport import RTCIceTransport
        from aioice.ice import Connection,StunProtocol
        from aiohttp import ClientWebSocketResponse,web
        emit('environment',python=sys.version.split()[0],platform=sys.platform,versions={x:importlib.metadata.version(x) for x in ('aiortc','aioice','aiohttp','pytest','pytest-asyncio')})
        for cls,names in [(Peer,['run','close','close_path','_close_path']),(RTCPeerConnection,['close']),(RTCIceTransport,['stop']),(Connection,['close']),(StunProtocol,['close']),(ClientWebSocketResponse,['close']),(web.AppRunner,['cleanup'])]:
            for name in names:self.wrap(cls,name)
        def ticker():
            while not self.stop.wait(10):
                emit('heartbeat',phase=self.phase)
                for loop in list(self.loops):
                    if not loop.is_closed():
                        try:loop.call_soon_threadsafe(dump,loop,'periodic.tasks')
                        except RuntimeError:pass
        self.thread=threading.Thread(target=ticker,daemon=True);self.thread.start()
    def pytest_runtest_logstart(self,nodeid,location):self.phase=nodeid;emit('test.start',nodeid=nodeid)
    def pytest_runtest_logreport(self,report):emit('test.report',nodeid=report.nodeid,when=report.when,outcome=report.outcome)
    def pytest_sessionfinish(self,session,exitstatus):
        self.stop.set();self.thread.join(1)
        for cls,name,original in reversed(self.originals):setattr(cls,name,original)
        emit('pytest.done',exitstatus=int(exitstatus))

if __name__=='__main__':
    # Normal pytest CLI return-code propagation; no timeout/success substitution.
    raise SystemExit(pytest.main(sys.argv[1:] or ['p2pchat/tests/backend/test_data_limits.py','-vv','-s'],plugins=[DiagnosticPlugin()]))
