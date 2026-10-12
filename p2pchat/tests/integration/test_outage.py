"""Real local sockets: one-sided roster loss then 60s two-sided control outage."""
import asyncio
import sys
from p2pchat.tests.backend.cleanup import cleanup_peers
import hashlib
import secrets
import time
import uuid
from aiohttp import web
import pytest
from p2pchat.server import make_app
from p2pchat.peer import Peer

def _leaves(exc):
    """展开嵌套 ExceptionGroup，取出叶子错误（用于断言具体原因码）。"""
    return [leaf for item in exc.exceptions for leaf in _leaves(item)] if isinstance(exc,BaseExceptionGroup) else [exc]


async def until(peer,predicate):
    async with asyncio.timeout(15):
        while True:
            _,m=await peer.received.get()
            if predicate(m):return m

@pytest.mark.asyncio
async def test_control_outage_keeps_authenticated_data_and_replays_logs(tmp_path):
    block={'value':False}
    @web.middleware
    async def gate(request,handler):
        if block['value'] and request.path=='/ws':raise web.HTTPServiceUnavailable()
        return await handler(request)
    app=make_app(tmp_path/'central');app.middlewares.append(gate)
    runner=web.AppRunner(app);await runner.setup();site=web.TCPSite(runner,'127.0.0.1',0);await site.start();port=site._server.sockets[0].getsockname()[1]
    secret=secrets.token_hex(32);a=Peer(f'ws://127.0.0.1:{port}/ws','离线🌏',secret,'a',tmp_path/'a',False);b=Peer(a.url,a.room,secret,'b',tmp_path/'b',True)
    tasks=[asyncio.create_task(p.run()) for p in (a,b)]
    try:
        await asyncio.wait_for(a.ready.wait(),20);p=next(p for p in a.paths.values() if p['hello']);old=a.id
        block['value']=True;await a.ws.close();await asyncio.sleep(.2)
        assert p['hello'] and not p['closing']
        await b.ws.close();start=time.monotonic()
        for i in range(7):
            mid=str(uuid.uuid4());a.send(p,{'kind':'text','id':mid,'text':'outage '+str(i)})
            assert (await until(a,lambda m:m.get('echoOf')==mid))['text']=='outage '+str(i)
            payload=secrets.token_bytes(1024);fid=await a.send_file(p,payload,'generated.bin','application/octet-stream')
            assert (await until(a,lambda m:m.get('kind')=='file' and m.get('echoOf')==fid))['sha256']==hashlib.sha256(payload).hexdigest()
            if i<6:await asyncio.sleep(10)
        assert time.monotonic()-start>=60 and a.store.pending() and b.store.pending()
        block['value']=False
        # 断网结束后，客户端可能刚好在退避里睡满一整轮才重连（Peer.RECONNECT_BACKOFF_MAX
        # 秒），之后还要握手、重新加入、回放积压。预算必须**从退避上限推导**，不能随手写：
        # Windows runner 上 40 秒不够（CI run 38222972337 就是卡在 40 秒那个预算上），
        # 所以这里取「退避上限 + 60 秒余量」，并在超时时打印可诊断的状态而不是只抛超时。
        budget=Peer.RECONNECT_BACKOFF_MAX+60
        started_recovery=time.monotonic()
        try:
            async with asyncio.timeout(budget):
                while a.id==old or not a.ws or not b.ws or a.store.pending() or b.store.pending():await asyncio.sleep(.2)
        except TimeoutError:
            raise AssertionError(
                '断网结束后 %ss 内没有恢复（预算=%ss=退避上限 %ss + 60s）：'
                'session 是否已换=%s（旧 %s / 新 %s）、a.ws=%s、b.ws=%s、'
                'a 积压=%s、b 积压=%s、实际等待=%.1fs'
                % (budget,budget,Peer.RECONNECT_BACKOFF_MAX,a.id!=old,old,a.id,
                   bool(a.ws),bool(b.ws),a.store.pending(),b.store.pending(),
                   time.monotonic()-started_recovery))
        assert p['closing'] and a.id!=old
        rows=app['store'].db.execute('SELECT scope,session,id,count(*) FROM diagnostics GROUP BY scope,session,id HAVING count(*)>1').fetchall();assert not rows
        await a.close();assert all(p['closing'] for p in a.paths.values())
    finally:
        await cleanup_peers((a,b),tasks,runner,sys.exception())


@pytest.mark.asyncio
async def test_stalled_rtc_close_is_bounded_and_names_the_phase(tmp_path,monkeypatch):
    """控制组：注入卡死的 pc.close()，等价于 Windows 上 CPython Proactor 排空卡住。

    证明两件事：(1) 在 Linux 上就能**确定性复现** CI 那条失败
    `P2P_CLOSE_TIMEOUT:path.workers_rtc`（不是偶发、也不是环境噪声）；
    (2) 关闭仍然**有界**结束并带明确原因码，残余任务继续被持有，绝不当作成功。
    """
    async def stalled(pc):
        await asyncio.sleep(3600)          # 排空永远不完成
    monkeypatch.setattr('p2pchat.peer.close_rtc',stalled)
    peer=Peer('ws://127.0.0.1:1/ws','bounded',secrets.token_hex(16),'bounded',tmp_path/'bounded',False)
    peer.CLOSE_TIMEOUT=.05
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    try:
        started=time.monotonic()
        with pytest.raises(BaseExceptionGroup) as info:await peer.close_path(path)
        elapsed=time.monotonic()-started
        assert info.value.message=='P2P close failed: path.workers_rtc'   # CI 报的那条组消息
        assert 'P2P_CLOSE_TIMEOUT:path.workers_rtc' in [str(leaf) for leaf in _leaves(info.value)]
        assert elapsed<2*peer.CLOSE_TIMEOUT+0.5,elapsed            # 有界：不无限等排水
        assert path['closing'] is True                            # 关闭状态已确立
        residual=path.get('rtc_close_task')
        assert residual is not None and not residual.done()       # 残余任务仍被持有，不当成功
    finally:
        residual=path.get('rtc_close_task')
        if residual is not None:
            residual.cancel();await asyncio.gather(residual,return_exceptions=True)
