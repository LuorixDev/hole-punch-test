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
        async with asyncio.timeout(40):
            while a.id==old or not a.ws or not b.ws or a.store.pending() or b.store.pending():await asyncio.sleep(.2)
        assert p['closing'] and a.id!=old
        rows=app['store'].db.execute('SELECT scope,session,id,count(*) FROM diagnostics GROUP BY scope,session,id HAVING count(*)>1').fetchall();assert not rows
        await a.close();assert all(p['closing'] for p in a.paths.values())
    finally:
        await cleanup_peers((a,b),tasks,runner,sys.exception())
