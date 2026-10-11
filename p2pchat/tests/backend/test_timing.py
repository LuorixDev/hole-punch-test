"""Clock fault injection, not fabricated network performance evidence."""
import asyncio
import hashlib
import json
from types import SimpleNamespace
import uuid
import pytest
import p2pchat.peer as peer_module
from p2pchat.peer import Peer,frame,measured_elapsed

class Channel:
    readyState='open'
    bufferedAmount=0
    def __init__(self):self.handlers={};self.messages=[]
    def on(self,name,callback=None):
        def register(fn):self.handlers[name]=fn;return fn
        return register(callback) if callback else register
    def send(self,data):self.messages.append(json.loads(data))
    def close(self):self.readyState='closed'

def clocks(monkeypatch,samples):
    values=iter(samples)
    # Replace only peer's module reference, never asyncio's global time module.
    monkeypatch.setattr(peer_module,'time',SimpleNamespace(monotonic=lambda:1234.0,perf_counter_ns=lambda:next(values)))

@pytest.mark.asyncio
@pytest.mark.parametrize('delta',[123456,0,-1])
async def test_benchmark_uses_high_resolution_not_coarse_deadline_clock(tmp_path,monkeypatch,delta):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path,echo=False)
    dc=Channel();path={'hello':True,'benchmark_ready':asyncio.Event()};peer.paths['unit']=path
    peer.install_benchmark(path,dc)
    clocks(monkeypatch,[10**18,10**18+delta])
    receive=dc.handlers['message'];fid=str(uuid.uuid4())
    receive(json.dumps({'v':1,'kind':'bench-start','id':fid}))
    for seq in range(4):receive(frame(fid,b'x'*1000,seq))
    receive(json.dumps({'v':1,'kind':'bench-end','id':fid}))
    ack=dc.messages[-1]
    assert ack['kind']=='bench-ack' and ack['bytes']==4000
    if delta>0:
        assert ack['elapsedMs']==delta/1_000_000 and ack['elapsedMs']>0
        assert 'timingError' not in ack
    else:
        assert ack['elapsedMs'] is None and ack['timingError']=='TIMING_UNAVAILABLE'
        assert 'Infinity' not in json.dumps(ack)
    assert path['bench'] is None
    peer.paths.clear();await peer.close()

@pytest.mark.asyncio
@pytest.mark.parametrize('delta',[250000,0])
async def test_file_ack_uses_same_high_resolution_clock_and_preserves_integrity(tmp_path,monkeypatch,delta):
    peer=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path,echo=False)
    path=peer.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    path.update(hello=True,dc=Channel());fid=str(uuid.uuid4());payload=b'file bytes'
    clocks(monkeypatch,[10**18,10**18+delta])
    async def receive(m):await peer.receive(path,json.dumps({'v':1,**m}))
    try:
        await receive({'kind':'file-start','id':fid,'name':'test','mime':'application/octet-stream','size':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'benchmark':False})
        await peer.receive(path,frame(fid,payload,0))
        await receive({'kind':'file-end','id':fid})
        ack=path['dc'].messages[-1]
        assert ack['kind']=='file-ack' and ack['ok'] and ack['bytes']==len(payload)
        assert ack['sha256']==hashlib.sha256(payload).hexdigest()
        assert ack['elapsedMs']==(delta/1_000_000 if delta>0 else None)
        if delta==0:assert ack['timingError']=='TIMING_UNAVAILABLE'
    finally:await peer.close()
