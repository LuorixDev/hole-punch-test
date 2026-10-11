import asyncio
import hashlib
import json
import uuid
import pytest
from p2pchat.peer import Peer,frame
from p2pchat.tests.backend.test_security import start

class Channel:
    """Unit-only sink; never used as proof of direct connectivity."""
    readyState='open';bufferedAmount=0
    def __init__(self):self.messages=[]
    def send(self,value):self.messages.append(json.loads(value))

@pytest.mark.asyncio
async def test_file_sequence_budget_and_pre_ack_failures(tmp_path):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    peer.id='local';path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()));path.update(hello=True,dc=Channel())
    async def control(m):await peer.receive(path,json.dumps({'v':1,**m}))
    def begin(fid,size=33554432):return {'kind':'file-start','id':fid,'name':'x','mime':'application/octet-stream','size':size,'sha256':hashlib.sha256(b'x').hexdigest(),'benchmark':False}
    try:
        await control(begin('a'));await control(begin('b'));await control(begin('c'))
        assert peer.reserved==67108864 and not path['dc'].messages[-1]['ok']
        with pytest.raises(ValueError):await peer.receive(path,frame('a',b'x',1))
        await peer.close_path(path);assert peer.reserved==0 and peer.active_receives==0
    finally:await peer.close()

@pytest.mark.asyncio
async def test_real_two_echo_bots_no_loop_and_benchmark(tmp_path):
    app,runner,url=await start(tmp_path/'hub')
    a=Peer(url,'echo','long-secret',log_dir=tmp_path/'a',echo=True);b=Peer(url,'echo','long-secret',log_dir=tmp_path/'b',echo=True)
    tasks=[asyncio.create_task(a.run()),asyncio.create_task(b.run())]
    try:
        await asyncio.wait_for(a.ready.wait(),30);path=next(p for p in a.paths.values() if p['hello']);mid=str(uuid.uuid4())
        a.send(path,{'kind':'text','id':mid,'text':'single echo'})
        async with asyncio.timeout(5):
            while True:
                _,m=await a.received.get()
                if m.get('echoOf')==mid:break
        await asyncio.sleep(.1)
        assert sum(1 for _,m in list(b.received._queue) if m.get('text')=='single echo')==1
        dc=path['benchmark'];future=asyncio.get_running_loop().create_future();fid=str(uuid.uuid4())
        @dc.on('message')
        def got(raw):
            if isinstance(raw,str):
                m=json.loads(raw)
                if m.get('kind')=='bench-ack' and not future.done():future.set_result(m)
        dc.send(json.dumps({'v':1,'kind':'bench-start','id':fid}))
        for seq in range(4):dc.send(frame(fid,b'x'*1000,seq))
        dc.send(json.dumps({'v':1,'kind':'bench-end','id':fid}))
        ack=await asyncio.wait_for(future,3);assert ack['bytes']==4000 and ack['elapsedMs']>0
    finally:
        await a.close();await b.close()
        for task in tasks:task.cancel()
        await asyncio.gather(*tasks,return_exceptions=True);await runner.cleanup()
