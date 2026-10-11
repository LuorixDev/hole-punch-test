import asyncio
import hashlib
import json
import socket
import struct
import time
import uuid
from pathlib import Path
import pytest
from aiohttp import ClientSession,web
from p2pchat.server import make_app,Store,Stun,stun_binding,main
from p2pchat.backend.protocol import signal
from p2pchat.backend.telemetry import LocalQueue
from p2pchat.peer import Peer,frame

def join_message(room='r',session=None):return {'v':1,'type':'join','room':room,'secret':'abcdefgh','name':'n','clientSessionId':session or str(uuid.uuid4()),'capabilities':['webrtc','tcp']}

async def start(tmp_path,**kwargs):
    app=make_app(tmp_path,**kwargs);runner=web.AppRunner(app);await runner.setup();site=web.TCPSite(runner,'127.0.0.1',0);await site.start()
    return app,runner,f'http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}/ws'
async def connect(s,url,room='r',session=None):
    ws=await s.ws_connect(url);await ws.send_json(join_message(room,session));welcome=await ws.receive_json();assert welcome['type']=='welcome';await ws.receive_json();return ws,welcome['id']
async def receive_kind(ws,kind):
    async with asyncio.timeout(2):
        while True:
            m=await ws.receive_json()
            if m['type']==kind:return m

def sig(to,**extra):return {'v':1,'type':'signal','to':to,'connectionId':str(uuid.uuid4()),'attemptId':str(uuid.uuid4()),'mechanism':'webrtc','profile':'ice-v4',**extra}

@pytest.mark.asyncio
async def test_isolation_relay_schema_and_cleanup(tmp_path):
    app,runner,url=await start(tmp_path)
    try:
        async with ClientSession() as s:
            a,aid=await connect(s,url);b,bid=await connect(s,url,'other')
            await a.send_json(sig(bid,description={'type':'offer','sdp':'v=0\r\n'}))
            assert (await receive_kind(a,'error'))['code']=='PEER_UNAVAILABLE'
            await a.close();await b.close()
            c,cid=await connect(s,url);d,did=await connect(s,url)
            low,high=(c,did) if cid<did else (d,cid)
            await low.send_json(sig(high,description={'type':'offer','sdp':'v=0\r\na=candidate:1 1 UDP 123 127.0.0.1 1234 typ relay\r\n'}))
            assert (await receive_kind(low,'error'))['code']=='RELAY_FORBIDDEN'
            await c.close();await d.close()
            e,_=await connect(s,url)
            await e.send_json({'v':1,'type':'ping','ts':'secret body'})
            assert (await receive_kind(e,'error'))['code']=='SCHEMA_INVALID';await e.close()
        await asyncio.sleep(.05)
        assert not app['hub'].peers and not app['hub'].rooms and not app['hub'].room_keys and not app['hub'].attempts
    finally:await runner.cleanup()

@pytest.mark.asyncio
async def test_limits_binary_and_room_expiry(tmp_path):
    app,runner,url=await start(tmp_path,max_room=1,room_ttl=.3)
    try:
        async with ClientSession() as s:
            a,_=await connect(s,url)
            b=await s.ws_connect(url);await b.send_json(join_message())
            assert (await b.receive_json())['code']=='LIMIT_EXCEEDED';await b.close()
            assert (await receive_kind(a,'error'))['code']=='ROOM_EXPIRED';await a.close()
            c,_=await connect(s,url);await c.send_bytes(b'not signaling')
            assert (await receive_kind(c,'error'))['code']=='SCHEMA_INVALID';await c.close()
    finally:await runner.cleanup()

@pytest.mark.asyncio
async def test_identity_bound_persistent_ack_replay_and_conflict(tmp_path):
    local=LocalQueue(tmp_path/'local');e=local.emit('path.state',{'state':'probing','mechanism':'webrtc','family':4,'reason':None})
    session=local.session
    app,runner,url=await start(tmp_path/'central')
    try:
        async with ClientSession() as s:
            a,aid=await connect(s,url,session=session)
            batch={'v':1,'type':'telemetry','clientSessionId':session,'events':[e]}
            await a.send_json(batch);ack=await receive_kind(a,'telemetry_ack');assert ack['ids']==[e['id']]
            await a.close()
            b,bid=await connect(s,url,session=session);assert aid!=bid
            await b.send_json(batch);assert (await receive_kind(b,'telemetry_ack'))['ids']==[e['id']]
            batch['events'][0]={**e,'data':{'state':'failed'}}
            await b.send_json(batch);assert (await receive_kind(b,'error'))['code']=='EVENT_CONFLICT';await b.close()
            rows=app['store'].db.execute('SELECT peer,body FROM diagnostics WHERE session=?',(session,)).fetchall()
            assert len(rows)==1 and rows[0][0]==aid
        local.close();local=LocalQueue(tmp_path/'local');assert local.pending()[0]['id']==e['id']
        local.ack(str(uuid.uuid4()),[e['id']]);assert local.pending()
        local.ack(session,[e['id']]);assert not local.pending()
    finally:local.close();await runner.cleanup()

def test_telemetry_strict_whitelist_bounds_and_restart(tmp_path):
    q=LocalQueue(tmp_path/'q',max_events=3,max_bytes=64000)
    for _ in range(6):q.emit('path.stats',{'rttMs':1,'bytes':100,'text':'SECRET','sha256':'SECRET','name':'SECRET'})
    assert len(q.pending())==3 and q.dropped==3
    s=Store(tmp_path/'s',max_bytes=64000)
    e=q.pending()[0]
    for data in ({'text':'SECRET'},{'reason':'SECRET'},{'rttMs':float('nan')},{'endpointTag':'SECRET'}):
        with pytest.raises(ValueError):s.ingest('scope','bound',q.session,[{**e,'id':str(uuid.uuid4()),'data':data}])
    s.ingest('scope','bound',q.session,[e]);s.close();s=Store(tmp_path/'s',max_bytes=64000)
    assert s.ingest('scope','new-peer',q.session,[e])==[e['id']]
    for _ in range(100):s.event('scope','bound','path.stats',{'bytes':10})
    assert sum(p.stat().st_size for p in (tmp_path/'s').iterdir())<64000
    assert 'SECRET' not in (tmp_path/'q'/'server.jsonl').read_text()
    q.close();s.close()

def test_signal_ssrf_candidate_invalid_end_and_spoofing():
    for address in ('224.0.0.1','255.255.255.255','fe80::1','0.0.0.0'):
        m=sig('peer',nativeCandidate={'id':'a','family':6 if ':' in address else 4,'transport':'udp','address':address,'port':1234,'kind':'host','socketId':'x'})
        m.update(mechanism='udp-probe',profile='default')
        with pytest.raises(ValueError):signal(m)
    with pytest.raises(ValueError):signal(sig('peer',candidate=None))
    with pytest.raises(ValueError):signal(sig('peer',candidate=None,endOfCandidates=True,text='covert'))
    with pytest.raises(ValueError):make_app('/not-created',ice_servers=[{'urls':'turn:evil'}])

@pytest.mark.asyncio
@pytest.mark.parametrize('address,family',[('127.0.0.1',socket.AF_INET),('::1',socket.AF_INET6)])
async def test_real_udp_stun_and_abuse_rate(tmp_path,address,family):
    store=Store(tmp_path);loop=asyncio.get_running_loop()
    class ObservedStun(Stun):
        def __init__(self):
            super().__init__(store,clock=lambda:100.0)
            self.processed=0;self.batch_done=asyncio.Event();self.trace=[]
        def datagram_received(self,data,addr):
            start=time.perf_counter_ns()
            super().datagram_received(data,addr)
            self.trace.append({'arrivalNs':start,'callbackNs':time.perf_counter_ns()-start})
            self.processed+=1
            if self.processed==26:self.batch_done.set()
    transport,protocol=await loop.create_datagram_endpoint(ObservedStun,local_addr=(address,0),family=family)
    sock=socket.socket(family,socket.SOCK_DGRAM);sock.bind((address,0));sock.setblocking(False)
    try:
        remote=transport.get_extra_info('sockname');request=struct.pack('!HHI',1,0,0x2112A442)+b'123456789012'
        await loop.sock_sendto(sock,request,remote);response,_=await asyncio.wait_for(loop.sock_recvfrom(sock,1024),2)
        assert response==stun_binding(request,sock.getsockname())
        for _ in range(25):await loop.sock_sendto(sock,request,remote)
        # Await all arrival callbacks, not a guessed OS send duration. Only the
        # limiter clock is frozen; sockets, logging, loop and timeout are real.
        await asyncio.wait_for(protocol.batch_done.wait(),10)
        n=0
        while n<19:
            reply,_=await asyncio.wait_for(loop.sock_recvfrom(sock,1024),2)
            assert reply==stun_binding(request,sock.getsockname());n+=1
        assert n==19 and protocol.buckets[address]==26 and protocol.total==26
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(loop.sock_recvfrom(sock,1024),.05)
        (tmp_path/'stun-arrivals.json').write_text(json.dumps(protocol.trace))
        bad=struct.pack('!HHI',1,4,0x2112A442)+b'123456789012'+struct.pack('!HH',0x8022,100)
        assert stun_binding(bad,(address,1234)) is None
    finally:sock.close();transport.close();store.close()

@pytest.mark.asyncio
async def test_untrusted_hello_and_pre_auth_payload(tmp_path):
    p=Peer('ws://127.0.0.1:1/ws','r','abcdefgh',log_dir=tmp_path)
    p.id='local';path=p.new_path('remote','ice-v4',str(uuid.uuid4()),str(uuid.uuid4()))
    try:
        with pytest.raises(ValueError):await p.receive(path,json.dumps({'v':1,'kind':'text','id':'1','text':'not authenticated'}))
        with pytest.raises(ValueError):await p.receive(path,json.dumps({'v':1,'kind':'hello','peer':'remote','connectionId':path['connectionId'],'attemptId':path['attempt'],'nonce':'0'*64,'proof':'0'*64}))
        assert not path['hello'] and not p.ready.is_set()
    finally:await p.close()
