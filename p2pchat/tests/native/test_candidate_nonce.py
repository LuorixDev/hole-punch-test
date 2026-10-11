"""R5 local controlled sockets: complete captured proof replay and one-way loss.
No public networking; the translation shim models address rewriting, not a product relay.
"""
import asyncio
import json
import secrets
import uuid
import pytest
from p2pchat.native.adapter import NativeAdapter
from p2pchat.native.auth import Auth, packed
from .test_candidate_repair import Translation, endpoint
from .test_transport import params, wait_states

class Capture(asyncio.DatagramProtocol):
    def __init__(self,auth):self.auth=auth;self.frames=None;self.ready=asyncio.Event()
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,source):
        if self.frames is not None or not data.startswith(b'P2POBS1'):return
        frame=json.loads(data[7:])
        if frame.get('kind')!='hello':return
        ack=self.auth.receive(frame)
        self.frames=(b'P2POBS1'+packed(self.auth.frame()),b'P2POBS1'+packed(ack))
        self.ready.set()  # Capture only: do not return either proof to this tuple yet.

@pytest.mark.asyncio
@pytest.mark.parametrize('reverse',[False,True])
async def test_complete_captured_hello_ack_cannot_authenticate_another_tuple(reverse):
    a=NativeAdapter();cid,aid=str(uuid.uuid4()),str(uuid.uuid4());secret=secrets.token_hex(32)
    p=params('udp-probe','offerer',cid,aid);p['auth']['secret']=secret
    await a.start(p);attempt=a.attempts[aid];transports=[]
    try:
        capture=Capture(Auth('test',secret,cid,aid,'b','a'))
        original,_=await endpoint(capture);other,_=await endpoint(asyncio.DatagramProtocol());transports=[original,other]
        for transport in transports:
            await a.signal(dict(connectionId=cid,attemptId=aid,**{'from':'b'},nativeCandidate={**attempt.candidate,'port':transport.get_extra_info('sockname')[1]}))
        await asyncio.wait_for(capture.ready.wait(),1)
        first=original.get_extra_info('sockname');second=other.get_extra_info('sockname')
        assert attempt.candidate_auth[first].nonce!=attempt.candidate_auth[second].nonce
        observed=attempt.sock.getsockname();frames=capture.frames[::-1] if reverse else capture.frames
        # Replay exact captured wire bytes: no proof or nonce is regenerated.
        for frame in frames:other.sendto(frame,observed)
        await asyncio.sleep(.15)
        assert not attempt.selected and attempt.state=='probing'
        assert not attempt.candidate_auth[second].acked
        assert not attempt.candidate_auth[second].direct
        # Original challenged tuple still accepts its own valid exchange.
        for frame in capture.frames:original.sendto(frame,observed)
        async with asyncio.timeout(1):
            while attempt.state!='direct':await asyncio.sleep(.01)
        assert attempt.remote==first
    finally:
        await a.shutdown()
        for transport in transports:transport.close()

class OneWayTranslation(Translation):
    def __init__(self,drop):super().__init__();self.drop=drop;self.dropped=0
    def datagram_received(self,data,source):
        if self.drop and source==self.allowed_source:self.dropped+=1;return
        super().datagram_received(data,source)

@pytest.mark.asyncio
@pytest.mark.parametrize('mechanism',['udp-probe','quic'])
@pytest.mark.parametrize('drop_direction',[0,1])
async def test_one_way_translation_never_proves_bilateral_path(mechanism,drop_direction):
    a,b=NativeAdapter(),NativeAdapter();cid,aid=str(uuid.uuid4()),str(uuid.uuid4());events=[[],[]];transports=[]
    for i,adapter in enumerate((a,b)):adapter.subscribe(lambda k,e,i=i:events[i].append((k,e)))
    try:
        for i,adapter in enumerate((a,b)):
            p=params(mechanism,'offerer' if i==0 else 'answerer',cid,aid);p['timeoutMs']=600;await adapter.start(p)
        sockets=[x.attempts[aid].sock.getsockname() for x in (a,b)]
        shims=[OneWayTranslation(i==drop_direction) for i in range(2)]
        for shim in shims:
            t,_=await endpoint(shim);transports.append(t)
        shims[0].other,shims[0].target,shims[0].allowed_source=shims[1],sockets[0],sockets[1]
        shims[1].other,shims[1].target,shims[1].allowed_source=shims[0],sockets[1],sockets[0]
        for i,target in enumerate((a,b)):
            for kind,event in events[1-i]:
                if kind=='candidate' and 'description' in event:await target.signal({**event,'from':'b' if i==0 else 'a'})
            remote=(b,a)[i].attempts[aid].candidate
            await target.signal(dict(connectionId=cid,attemptId=aid,**{'from':'b' if i==0 else 'a'},nativeCandidate={**remote,'kind':'srflx','port':transports[1-i].get_extra_info('sockname')[1]}))
        assert await wait_states(a,b,aid,3)==['timeout','timeout']
        assert shims[drop_direction].dropped>0
        assert not any(k=='state' and e['state']=='direct' or k=='data' for es in events for k,e in es)
    finally:
        await a.shutdown();await b.shutdown()
        for transport in transports:transport.close()
