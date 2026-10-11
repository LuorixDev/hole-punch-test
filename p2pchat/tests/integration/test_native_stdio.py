"""Two real sidecar processes, JSON-lines bridge and QUIC payload integrity."""
import asyncio
import base64
import json
import secrets
import sys
import uuid
import pytest

class RPC:
    async def open(self):
        self.p=await asyncio.create_subprocess_exec(sys.executable,'-m','p2pchat.native.bridge',stdin=asyncio.subprocess.PIPE,stdout=asyncio.subprocess.PIPE,stderr=asyncio.subprocess.PIPE)
        self.seq=0;self.pending={};self.events=[];self.reader=asyncio.create_task(self.read());return self
    async def read(self):
        while line:=await self.p.stdout.readline():
            m=json.loads(line)
            if 'id' in m:
                future=self.pending.pop(m['id'],None)
                if future and not future.done():future.set_result(m)
            else:self.events.append(m)
    async def call(self,method,params):
        self.seq+=1;f=asyncio.get_running_loop().create_future();self.pending[self.seq]=f
        self.p.stdin.write((json.dumps({'v':1,'id':self.seq,'method':method,'params':params})+'\n').encode());await self.p.stdin.drain()
        m=await asyncio.wait_for(f,8);assert 'error' not in m,m;return m['result']
    async def close(self):
        self.p.stdin.close();await asyncio.wait_for(self.p.wait(),10);await self.reader

@pytest.mark.asyncio
async def test_two_real_stdio_quic_processes():
    a,b=await RPC().open(),await RPC().open();cid,aid=str(uuid.uuid4()),str(uuid.uuid4());secret=secrets.token_hex(32)
    try:
        assert a.p.pid!=b.p.pid
        for rpc,local,remote,role in [(a,'a','b','offerer'),(b,'b','a','answerer')]:
            await rpc.call('start',dict(connectionId=cid,attemptId=aid,peerId=remote,mechanism='quic',profile='direct',role=role,timeoutMs=5000,auth=dict(room='跨语言桥🌏',localPeerId=local,secret=secret)))
        async with asyncio.timeout(5):
            while not all(any(e.get('event')=='candidate' and 'nativeCandidate' in e['params'] for e in r.events) for r in (a,b)):await asyncio.sleep(.02)
        for target,source,sender in [(a,b,'b'),(b,a,'a')]:
            for e in source.events:
                if e.get('event')=='candidate':await target.call('signal',{**e['params'],'from':sender})
        async with asyncio.timeout(10):
            while True:
                states=await asyncio.gather(*(r.call('stats',{'attemptId':aid}) for r in (a,b)))
                assert not any(s['state'] in ('failed','timeout') for s in states),states
                if all(s['state']=='direct' for s in states):break
                await asyncio.sleep(.05)
        raw=secrets.token_bytes(32768)
        for lane in ('chat','benchmark'):
            await a.call('send',{'attemptId':aid,'lane':lane,'dataB64':base64.b64encode(raw).decode()})
            async with asyncio.timeout(5):
                while not any(e.get('event')=='data' and e['params']['lane']==lane for e in b.events):await asyncio.sleep(.02)
            event=next(e for e in b.events if e.get('event')=='data' and e['params']['lane']==lane)
            assert base64.b64decode(event['params']['dataB64'])==raw
    finally:await asyncio.gather(a.close(),b.close())
