"""Independent authenticated WebRTC echo participant (never a signaling relay).

Run: python -m p2pchat.peer --secret-file /private/key. Files stay in bounded
memory. The selected ICE tuple is an aiortc-private observation, not packet proof.
"""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import re
import secrets
import struct
import time
import uuid
from aiohttp import ClientSession, ClientError, WSMsgType
from aiortc import RTCConfiguration, RTCIceServer, RTCPeerConnection, RTCSessionDescription
from aiortc.sdp import candidate_from_sdp
from p2pchat.server import PROFILES
from p2pchat.backend.telemetry import LocalQueue
from p2pchat.backend.rtc_shutdown import close_rtc

MAX_FILE=32*1024*1024

def allowed_candidate(line,profile):
    p=line.removeprefix('a=').split()
    if len(p)<8 or p[7]=='relay':return False
    try:version=ipaddress.ip_address(p[4]).version
    except ValueError:return profile=='ice-dual'
    return profile=='ice-dual' or version==(6 if profile=='ice-v6' else 4)
def filter_sdp(sdp,profile):return '\r\n'.join(line for line in sdp.splitlines() if not line.startswith('a=candidate:') or allowed_candidate(line,profile))+'\r\n'
def frame(identifier,data,sequence=0):
    b=identifier.encode()
    if not 1<=len(b)<=100 or len(data)>16384 or not 0<=sequence<=2**32-1:raise ValueError('SCHEMA_INVALID')
    return struct.pack('!H',len(b))+b+struct.pack('!I',sequence)+data

def unframe(data):
    if len(data)<7:raise ValueError('SCHEMA_INVALID')
    size=struct.unpack('!H',data[:2])[0]
    if not 1<=size<=100 or size+6>len(data) or len(data)-size-6>16384:raise ValueError('SCHEMA_INVALID')
    return data[2:2+size].decode(),struct.unpack('!I',data[2+size:6+size])[0],data[6+size:]

def proof(secret,room,cid,aid,sender,receiver,nonce,echo=None):
    parts=['p2pobs-v1' if echo is None else 'p2pobs-v1-ack',room,cid,aid,sender,receiver,nonce]
    if echo is not None:parts.append(echo)
    return hmac.new(secret.encode(),json.dumps(parts,ensure_ascii=False,separators=(',',':')).encode(),hashlib.sha256).hexdigest()

def identifier(value):
    if not isinstance(value,str) or not 1<=len(value.encode())<=100:raise ValueError('SCHEMA_INVALID')
    return value

class Peer:
    def __init__(self,url,room,secret,name='Server Echo',log_dir='peer-data',echo=True,origin=None):
        self.url,self.room,self.secret,self.name=url,room,secret,name;self.echo=echo;self.origin=origin
        self.store=LocalQueue(log_dir);self.ws=None;self.id=None;self.ice=[];self.paths={};self.early_candidates={};self.tasks=set()
        self.received=asyncio.Queue(maxsize=1024);self.ready=asyncio.Event();self.seen={};self.closed=False
        self.reserved=0;self.active_receives=0;self.echo_bytes=0;self.echo_count=0;self.sending=asyncio.Semaphore(4);self.peer_sending={};self.signal_queues={};self.signal_tasks={};self.upload_wake=asyncio.Event()
    def spawn(self,coroutine,path=None):
        task=asyncio.create_task(coroutine);self.tasks.add(task)
        if path is not None:path['tasks'].add(task)
        def done(t):
            self.tasks.discard(t)
            if path is not None:path['tasks'].discard(t)
            if not t.cancelled() and t.exception():self.event('task.error',{'error':'INTERNAL_ERROR'},path)
        task.add_done_callback(done);return task
    def event(self,kind,data,path=None):
        if self.closed:return
        self.store.emit(kind,data,path['connectionId'] if path else None,path['attempt'] if path else None);self.upload_wake.set()
    async def uploader(self):
        # One durable resend loop only. ACK deletes by session, never by transient peerId.
        while not self.closed:
            if self.ws and not self.ws.closed and self.id:
                events=self.store.pending()
                if events:
                    try:await self.ws.send_json({'v':1,'type':'telemetry','clientSessionId':self.store.session,'events':events})
                    except ConnectionError:pass
            await asyncio.sleep(1)
    def send(self,path,data):
        dc=path.get('dc')
        if not dc or dc.readyState!='open' or path.get('closing'):raise RuntimeError('CLOSED')
        if data.get('kind') not in {'hello','hello-ack'} and not path['hello']:raise ValueError('AUTH_FAILED')
        raw=json.dumps({'v':1,**data},ensure_ascii=False)
        if len(raw.encode())>65536:raise ValueError('LIMIT_EXCEEDED')
        if dc.bufferedAmount>524288:raise RuntimeError('LIMIT_EXCEEDED')
        dc.send(raw)
    async def drain(self,path,dc=None):
        dc=dc or path['dc']
        while dc.bufferedAmount>524288:
            path['low'].clear()
            if dc.readyState!='open' or path['closing']:raise RuntimeError('CLOSED')
            await asyncio.wait_for(path['low'].wait(),30)
    async def send_file(self,path,data,name,mime,echo_of=None):
        if len(data)>MAX_FILE or len(name)>255 or len(mime)>128:raise ValueError('LIMIT_EXCEEDED')
        async with self.sending,self.peer_sending.setdefault(path['peer'],asyncio.Semaphore(2)):
            fid=str(uuid.uuid4());digest=hashlib.sha256(data).hexdigest();loop=asyncio.get_running_loop()
            ready=loop.create_future();ack=loop.create_future();path['acks'][fid]={'ready':ready,'ack':ack,'size':len(data),'hash':digest}
            try:
                self.send(path,{'kind':'file-start','id':fid,'name':name,'mime':mime,'size':len(data),'sha256':digest,'echoOf':echo_of,'benchmark':False})
                response=await asyncio.wait_for(ready,60)
                if not response.get('ok'):raise ValueError('LIMIT_EXCEEDED')
                for seq,offset in enumerate(range(0,len(data),16384)):
                    await self.drain(path);path['dc'].send(frame(fid,data[offset:offset+16384],seq))
                await self.drain(path);self.send(path,{'kind':'file-end','id':fid})
                response=await asyncio.wait_for(ack,60)
                if not response.get('ok') or response.get('bytes')!=len(data) or response.get('sha256')!=digest:raise ValueError('INTEGRITY_FAILED')
                self.event('transfer.sent',{'bytes':len(data),'integrityOk':True},path)
                return fid
            finally:
                path['acks'].pop(fid,None)
                for future in (ready,ack):
                    if not future.done():future.cancel()
    def selected_pair(self,path):
        # aiortc does not expose browser getStats selectedCandidatePair. Observe the
        # actual nominated aioice pair, and report unavailable if version differs.
        try:
            connection=path['pc'].sctp.transport.transport._connection
            pairs=list(connection._nominated.values())
            if not pairs:return None
            pair=pairs[0]
            if pair.local_candidate.type=='relay' or pair.remote_candidate.type=='relay':return None
            return {'family':ipaddress.ip_address(pair.remote_addr[0]).version,'protocol':pair.local_candidate.transport,'candidateType':pair.local_candidate.type}
        except (AttributeError,ValueError,IndexError):return None
    def auth_send(self,path,kind,echo=None):
        m={'kind':kind,'peer':self.id,'connectionId':path['connectionId'],'attemptId':path['attempt'],'nonce':path['nonce']}
        if echo is not None:m['echoNonce']=echo
        m['proof']=proof(self.secret,self.room,path['connectionId'],path['attempt'],self.id,path['peer'],path['nonce'],echo)
        self.send(path,m)
    def install_channel(self,path,dc):
        if dc.label not in {'chat','benchmark'} or path.get(dc.label):dc.close();return
        path[dc.label]=dc
        if dc.label=='benchmark':
            self.install_benchmark(path,dc);return
        path['dc']=dc;dc.bufferedAmountLowThreshold=131072
        dc.on('bufferedamountlow',lambda:path['low'].set())
        def opened():
            if path['hello_sent']:return
            path['hello_sent']=True;self.event('datachannel.open',{},path);self.auth_send(path,'hello')
        dc.on('open',opened)
        dc.on('close',lambda:self.spawn(self.close_path(path)))
        queue=asyncio.Queue(maxsize=128)
        @dc.on('message')
        def enqueue(data):
            if len(data)>65536:dc.close();return
            try:queue.put_nowait(data)
            except asyncio.QueueFull:dc.close();self.event('receive.queue_overflow',{'reason':'LIMIT_EXCEEDED'},path)
        async def worker():
            while not path['closing']:
                data=await queue.get()
                try:await self.receive(path,data)
                except (ValueError,KeyError,TypeError,RuntimeError,UnicodeError):
                    self.event('receive.error',{'error':'SCHEMA_INVALID'},path);await self.close_path(path);return
        self.spawn(worker(),path)
        if dc.readyState=='open':opened()
    async def wait_benchmark(self,path,timeout=5):
        async with asyncio.timeout(timeout):
            await path['benchmark_ready'].wait()
        dc=path.get('benchmark')
        if path['closing'] or not path['hello'] or not dc or dc.readyState!='open':
            raise RuntimeError('BENCHMARK_CHANNEL_NOT_OPEN')
        return dc
    def install_benchmark(self,path,dc):
        def opened():path['benchmark_ready'].set()
        dc.on('open',opened)
        dc.on('close',lambda:path['benchmark_ready'].set())
        if dc.readyState=='open':opened()
        # Separate channel and bounded independent state; never echo benchmark bytes.
        path['bench']=None
        @dc.on('message')
        def receive(data):
            try:
                if not path['hello']:raise ValueError()
                if isinstance(data,bytes):
                    fid,seq,payload=unframe(data);b=path['bench']
                    if not b or fid!=b['id'] or seq!=b['seq'] or b['bytes']+len(payload)>MAX_FILE or time.monotonic()-b['start']>10:raise ValueError()
                    b['seq']+=1;b['bytes']+=len(payload)
                else:
                    if len(data)>65536:raise ValueError()
                    m=json.loads(data)
                    if m.get('v')!=1:raise ValueError()
                    if m['kind']=='bench-start':
                        if any(p.get('bench') for p in self.paths.values()):raise ValueError()
                        path['bench']={'id':identifier(m['id']),'seq':0,'bytes':0,'start':time.monotonic()}
                    elif m['kind']=='bench-end':
                        b=path['bench']
                        if not b or m['id']!=b['id'] or time.monotonic()-b['start']>10:raise ValueError()
                        dc.send(json.dumps({'v':1,'kind':'bench-ack','id':b['id'],'bytes':b['bytes'],'elapsedMs':(time.monotonic()-b['start'])*1000}));path['bench']=None
                    else:raise ValueError()
            except (ValueError,KeyError,TypeError):path['bench']=None;dc.close()
    def duplicate(self,peer,fid):
        now=time.monotonic()
        self.seen={k:v for k,v in self.seen.items() if now-v<600}
        key=(peer,fid)
        if key in self.seen:return True
        if len(self.seen)>=10000:self.seen.pop(next(iter(self.seen)))
        self.seen[key]=now;return False
    def release_file(self,path,fid):
        t=path['files'].pop(fid,None)
        if t:self.reserved-=t['size'];self.active_receives-=1
        return t
    async def receive(self,path,data):
        if isinstance(data,bytes):
            if not path['hello']:raise ValueError('AUTH_FAILED')
            fid,seq,payload=unframe(data);t=path['files'].get(fid)
            if t is None or seq!=t['seq'] or t['received']+len(payload)>t['size']:raise ValueError('SCHEMA_INVALID')
            t['seq']+=1;t['received']+=len(payload);t['data'].extend(payload);t['progress']=time.monotonic()
            if t['seq']%16==0 or time.monotonic()-t['last_ack']>.25:
                self.send(path,{'kind':'file-progress','id':fid,'nextSequence':t['seq'],'receivedBytes':t['received']});t['last_ack']=time.monotonic()
            return
        if len(data.encode())>65536:raise ValueError('LIMIT_EXCEEDED')
        m=json.loads(data)
        if not isinstance(m,dict) or m.get('v')!=1:raise ValueError('SCHEMA_INVALID')
        kind=m.get('kind')
        if kind in {'hello','hello-ack'}:
            if m.get('peer')!=path['peer'] or m.get('connectionId')!=path['connectionId'] or m.get('attemptId')!=path['attempt'] or not isinstance(m.get('nonce'),str) or not re.fullmatch('[0-9a-f]{64}',m['nonce']):raise ValueError('AUTH_FAILED')
            echo=m.get('echoNonce') if kind=='hello-ack' else None
            expected=proof(self.secret,self.room,path['connectionId'],path['attempt'],path['peer'],self.id,m['nonce'],echo)
            if not isinstance(m.get('proof'),str) or not hmac.compare_digest(expected,m['proof']):raise ValueError('AUTH_FAILED')
            if kind=='hello':
                if path['remote_nonce'] is not None:raise ValueError('AUTH_FAILED')
                path['remote_nonce']=m['nonce']
                if path.get('early_ack'):
                    if path['early_ack']!=m['nonce']:raise ValueError('AUTH_FAILED')
                    path['early_ack']=None;path['ack_received']=True
                self.auth_send(path,'hello-ack',m['nonce']);path['ack_sent']=True
            else:
                if path['ack_received'] or path.get('early_ack') or echo!=path['nonce']:raise ValueError('AUTH_FAILED')
                if path['remote_nonce'] is None:
                    path['early_ack']=m['nonce'];return
                if m['nonce']!=path['remote_nonce']:raise ValueError('AUTH_FAILED')
                path['ack_received']=True
            if path['ack_sent'] and path['ack_received']:
                pair=self.selected_pair(path)
                if not pair:raise ValueError('AUTH_FAILED')
                path['hello']=True;path['actual']=pair;self.ready.set();self.event('path.state',{'state':'direct','mechanism':'webrtc',**pair},path)
            return
        if not path['hello']:raise ValueError('AUTH_FAILED')
        if kind=='ping':self.send(path,{'kind':'pong','id':identifier(m.get('id'))})
        elif kind=='text':
            fid=identifier(m.get('id'))
            if not isinstance(m.get('text'),str) or len(m['text'].encode())>16384:raise ValueError('LIMIT_EXCEEDED')
            self.send(path,{'kind':'delivered','id':fid})
            if self.duplicate(path['peer'],fid):return
            self.deliver(path,m);self.event('chat.received',{'bytes':len(m['text'].encode()),'echo':bool(m.get('echoOf'))},path)
            if self.echo and not m.get('echoOf'):self.send(path,{'kind':'text','id':str(uuid.uuid4()),'text':m['text'],'echoOf':fid})
        elif kind=='file-start':
            fid=identifier(m.get('id'));size=m.get('size')
            valid=type(size) is int and 0<=size<=MAX_FILE and self.active_receives+self.echo_count<8 and self.reserved+self.echo_bytes+size<=64*1024*1024 and fid not in path['files'] and not m.get('benchmark')
            valid=valid and isinstance(m.get('name'),str) and len(m['name'])<=255 and isinstance(m.get('mime'),str) and len(m['mime'])<=128 and isinstance(m.get('sha256'),str) and bool(re.fullmatch('[0-9a-f]{64}',m['sha256'])) and (path['peer'],fid) not in self.seen
            if not valid:self.send(path,{'kind':'file-ready','id':fid,'ok':False,'reason':'LIMIT_EXCEEDED'});return
            now=time.monotonic();path['files'][fid]={**m,'data':bytearray(),'received':0,'seq':0,'started':now,'progress':now,'last_ack':now};self.reserved+=size;self.active_receives+=1
            self.send(path,{'kind':'file-ready','id':fid,'ok':True})
        elif kind=='file-end':
            fid=identifier(m.get('id'));t=self.release_file(path,fid)
            if t is None:raise ValueError('SCHEMA_INVALID')
            digest=hashlib.sha256(t['data']).hexdigest();ok=t['received']==t['size'] and digest==t['sha256']
            self.send(path,{'kind':'file-ack','id':fid,'ok':ok,'bytes':t['received'],'sha256':digest,'elapsedMs':(time.monotonic()-t['started'])*1000})
            self.event('transfer.received',{'bytes':t['received'],'integrityOk':ok},path)
            duplicate=self.duplicate(path['peer'],fid)
            if ok and not duplicate:
                self.deliver(path,{'kind':'file','id':fid,'bytes':t['received'],'ok':ok,'sha256':digest,'echoOf':t.get('echoOf')})
                if self.echo and not t.get('echoOf'):
                    self.echo_bytes+=t['size'];self.echo_count+=1
                    async def echo_file():
                        try:await self.send_file(path,t['data'],t['name'],t['mime'],fid)
                        finally:self.echo_bytes-=t['size'];self.echo_count-=1
                    self.spawn(echo_file(),path)
        elif kind in {'file-ready','file-ack'}:
            pending=path['acks'].get(m.get('id'))
            if pending:
                future=pending['ready' if kind=='file-ready' else 'ack']
                if not future.done():future.set_result(m)
            if kind=='file-ack':self.deliver(path,m)
        elif kind in {'file-progress','delivered','pong'}:self.deliver(path,m)
        else:raise ValueError('SCHEMA_INVALID')
    def deliver(self,path,m):
        if self.received.full():self.received.get_nowait()
        self.received.put_nowait((path['peer'],m))
    def new_path(self,peer,profile,attempt,cid):
        if len(self.paths)>=96:raise ValueError('LIMIT_EXCEEDED')
        pc=RTCPeerConnection(RTCConfiguration(iceServers=self.ice))
        path={'pc':pc,'peer':peer,'profile':profile,'attempt':attempt,'connectionId':cid,'files':{},'acks':{},'hello':False,'nonce':secrets.token_hex(32),'remote_nonce':None,'ack_sent':False,'ack_received':False,'hello_sent':False,'tasks':set(),'closing':False,'low':asyncio.Event(),'benchmark_ready':asyncio.Event(),'created':time.monotonic()}
        self.paths[attempt]=path
        @pc.on('connectionstatechange')
        async def changed():
            self.event('rtc.connection',{'state':pc.connectionState,'profile':profile},path)
            if pc.connectionState in {'failed','closed'}:self.spawn(self.close_path(path))
        @pc.on('datachannel')
        def channel(dc):self.install_channel(path,dc)
        return path
    def signal_frame(self,path,**payload):return {'v':1,'type':'signal','to':path['peer'],'mechanism':'webrtc','profile':path['profile'],'connectionId':path['connectionId'],'attemptId':path['attempt'],**payload}
    async def initiate(self,peer):
        cid=str(uuid.uuid4())
        async def one(profile):
            path=self.new_path(peer,profile,str(uuid.uuid4()),cid)
            self.install_channel(path,path['pc'].createDataChannel('chat',ordered=True))
            self.install_channel(path,path['pc'].createDataChannel('benchmark',ordered=True))
            try:
                async with asyncio.timeout(30):
                    await path['pc'].setLocalDescription(await path['pc'].createOffer())
                    await self.ws.send_json(self.signal_frame(path,description={'type':'offer','sdp':filter_sdp(path['pc'].localDescription.sdp,profile)}))
            except (TimeoutError,ConnectionError):await self.close_path(path)
        await asyncio.gather(*(one(p) for p in PROFILES))
    async def on_signal(self,m):
        if m['mechanism']!='webrtc':return
        attempt=m['attemptId'];path=self.paths.get(attempt)
        if path is None:
            if not m.get('description') or m['description']['type']!='offer':
                early=self.early_candidates.setdefault(attempt,{'at':time.monotonic(),'messages':[]})
                if len(early['messages'])>=64 or len(self.early_candidates)>96:raise ValueError('LIMIT_EXCEEDED')
                early['messages'].append(m);return
            path=self.new_path(m['from'],m['profile'],attempt,m['connectionId'])
        if m['from']!=path['peer'] or m['connectionId']!=path['connectionId'] or m['profile']!=path['profile']:raise ValueError('AUTH_FAILED')
        if path['closing']:return
        if m.get('description'):
            desc=m['description'];await path['pc'].setRemoteDescription(RTCSessionDescription(sdp=filter_sdp(desc['sdp'],path['profile']),type=desc['type']))
            for early in self.early_candidates.pop(attempt,{}).get('messages',[]):await self.on_signal(early)
            if desc['type']=='offer':
                await path['pc'].setLocalDescription(await path['pc'].createAnswer())
                await self.ws.send_json(self.signal_frame(path,description={'type':'answer','sdp':filter_sdp(path['pc'].localDescription.sdp,path['profile'])}))
        elif 'candidate' in m:
            if m['candidate'] is None:await path['pc'].addIceCandidate(None);return
            c=m['candidate'];raw=c['candidate']
            if not allowed_candidate(raw,path['profile']):return
            parsed=candidate_from_sdp(raw.removeprefix('candidate:'));parsed.sdpMid=c.get('sdpMid');parsed.sdpMLineIndex=c.get('sdpMLineIndex');await path['pc'].addIceCandidate(parsed)
    def enqueue_signal(self,m):
        aid=m['attemptId']
        if aid not in self.signal_queues:
            if len(self.signal_queues)>=96:raise ValueError('LIMIT_EXCEEDED')
            queue=asyncio.Queue(maxsize=66);self.signal_queues[aid]=queue
            async def worker():
                try:
                    while True:
                        msg=await asyncio.wait_for(queue.get(),35)
                        async with asyncio.timeout(30):await self.on_signal(msg)
                except (TimeoutError,ValueError):
                    path=self.paths.get(aid)
                    if path and not path['hello']:await self.close_path(path)
                finally:self.signal_queues.pop(aid,None);self.signal_tasks.pop(aid,None)
            self.signal_tasks[aid]=self.spawn(worker())
        self.signal_queues[aid].put_nowait(m)
    async def watchdog(self):
        while not self.closed:
            await asyncio.sleep(1);now=time.monotonic()
            for aid,early in list(self.early_candidates.items()):
                if now-early['at']>10:self.early_candidates.pop(aid,None)
            for path in list(self.paths.values()):
                if not path['hello'] and now-path['created']>30:await self.close_path(path)
                for fid,t in list(path['files'].items()):
                    if now-t['progress']>30:self.release_file(path,fid)
                if path.get('bench') and now-path['bench']['start']>10:path['bench']=None
    async def run(self):
        from urllib.parse import urlparse
        parsed=urlparse(self.url)
        try:local=ipaddress.ip_address(parsed.hostname).is_loopback
        except ValueError:local=parsed.hostname=='localhost'
        if parsed.scheme not in {'wss','https'} and not local:raise ValueError('remote signaling requires WSS')
        self.spawn(self.uploader());self.spawn(self.watchdog())
        backoff=1
        while not self.closed:
            try:
                async with ClientSession() as session:
                    self.ws=await session.ws_connect(self.url,heartbeat=20,max_msg_size=131072,origin=self.origin)
                    await self.ws.send_json({'v':1,'type':'join','room':self.room,'name':self.name,'secret':self.secret,'clientSessionId':self.store.session,'capabilities':['webrtc']})
                    known=set();backoff=1
                    async for msg in self.ws:
                        if msg.type!=WSMsgType.TEXT:continue
                        m=json.loads(msg.data)
                        if m['type']=='welcome':
                            for old in list(self.paths.values()):await self.close_path(old)
                            self.paths.clear();self.early_candidates.clear()
                            self.id=m['id'];self.ice=[RTCIceServer(urls=s['urls']) for s in m.get('iceServers',[]) if all(u.startswith('stun:') for u in ([s['urls']] if isinstance(s['urls'],str) else s['urls']))];self.event('session.joined',{'echo':self.echo})
                        elif m['type']=='roster':
                            ids={p['id'] for p in m['peers'] if p['id']!=self.id and 'webrtc' in p.get('capabilities',[])}
                            for peer in ids-known:
                                if self.id<peer:self.spawn(self.initiate(peer))
                            for path in list(self.paths.values()):
                                if path['peer'] not in ids and not path['hello']:await self.close_path(path)
                            known=ids
                        elif m['type']=='signal':self.enqueue_signal(m)
                        elif m['type']=='telemetry_ack':self.store.ack(m.get('clientSessionId'),m.get('ids',[]))
                        elif m['type']=='error':self.event('server.error',{'reason':m.get('code')});raise ValueError('server rejected session')
            except (ClientError,ConnectionError,OSError,asyncio.TimeoutError):pass
            finally:
                # Signaling loss is not user leave: authenticated data paths keep
                # their identity until a new welcome explicitly replaces session.
                self.ws=None
            if not self.closed:await asyncio.sleep(backoff);backoff=min(30,backoff*2)
    CLOSE_TIMEOUT = 5.0

    @staticmethod
    def _consume_close_result(task):
        # Retrieving an exception is not declaring success: errors are re-raised
        # by the owning close operation and timeout residuals are reported.
        if not task.cancelled():
            task.exception()

    async def _close_wait(self, tasks, deadline, phase, *, required):
        tasks = set(tasks)
        required = set(required)
        if not required <= tasks:
            raise ValueError('REQUIRED_CLOSE_TASK_NOT_TRACKED')
        if not tasks:
            return
        remaining = max(0.0, deadline - asyncio.get_running_loop().time())
        done, pending = await asyncio.wait(tasks, timeout=remaining)
        errors = []
        for task in done:
            if task.cancelled():
                if task in required:
                    errors.append(RuntimeError('P2P_CLOSE_CANCELLED:' + phase))
            elif task.exception() is not None:
                errors.append(task.exception())
        if pending:
            import sys
            # Enumerated phase/count only; never repr(task), locals, URL or SDP.
            print('P2P_CLOSE_TIMEOUT phase=%s pending=%d' % (phase, len(pending)),
                  file=sys.stderr, flush=True)
            errors.append(TimeoutError('P2P_CLOSE_TIMEOUT:' + phase))
        if errors:
            raise BaseExceptionGroup('P2P close failed: ' + phase, errors)

    async def close_path(self, path):
        if 'cleanup_task' not in path:
            path['cleanup_deadline'] = min(asyncio.get_running_loop().time() + self.CLOSE_TIMEOUT, getattr(self, '_shutdown_deadline', float('inf')))
            path['cleanup_task'] = asyncio.create_task(self._close_path(path))
            path['cleanup_task'].add_done_callback(self._consume_close_result)
        # Callers must not cancel the shared cleanup or aiortc's shared close
        # Future. _close_path itself observes an absolute deadline.
        if asyncio.current_task() is not path['cleanup_task']:
            await asyncio.shield(path['cleanup_task'])

    async def _close_path(self, path):
        path['closing'] = True
        path['hello'] = False
        path['low'].set()
        path['benchmark_ready'].set()
        for fid in list(path['files']):
            self.release_file(path, fid)
        for pending in path['acks'].values():
            for name in ('ready', 'ack'):
                if not pending[name].done():
                    pending[name].cancel()
        current = asyncio.current_task()
        tasks = {t for t in path['tasks'] if t is not current}
        signaling = self.signal_tasks.get(path['attempt'])
        if signaling and signaling is not current:
            tasks.add(signaling)
        for task in tasks:
            task.cancel()
        # Start transport shutdown before waiting for cancelled workers. A worker
        # blocked on I/O must not prevent the operation which releases its I/O.
        path['rtc_close_task'] = asyncio.create_task(close_rtc(path['pc']))
        path['rtc_close_task'].add_done_callback(self._consume_close_result)
        tasks.add(path['rtc_close_task'])
        await self._close_wait(tasks, path['cleanup_deadline'], 'path.workers_rtc', required={path['rtc_close_task']})
        self.event('path.state', {'state':'closed','reason':'CLOSED'}, path)

    async def close(self):
        # Idempotence includes failure: concurrent/repeated callers see the same
        # result rather than returning early because `closed` was already set.
        if not hasattr(self, '_shutdown_task'):
            self.closed = True
            self._shutdown_deadline = asyncio.get_running_loop().time() + self.CLOSE_TIMEOUT
            self._shutdown_task = asyncio.create_task(self._shutdown())
            self._shutdown_task.add_done_callback(self._consume_close_result)
        await asyncio.shield(self._shutdown_task)

    async def _shutdown(self):
        tasks = set(self.tasks)
        required = set()
        for task in tasks:
            task.cancel()
        # Close BOTH control and data I/O without serially waiting on WS first.
        # All child operations share the peer-level deadline.
        if self.ws and not self.ws.closed:
            self._ws_close_task = asyncio.create_task(self.ws.close())
            self._ws_close_task.add_done_callback(self._consume_close_result)
            tasks.add(self._ws_close_task)
            required.add(self._ws_close_task)
        for path in list(self.paths.values()):
            closer = asyncio.create_task(self.close_path(path))
            closer.add_done_callback(self._consume_close_result)
            tasks.add(closer)
            required.add(closer)
        try:
            await self._close_wait(tasks, self._shutdown_deadline, 'peer.workers_ws_paths', required=required)
        finally:
            self.secret = ''
            self.store.close()


async def main(args):
    peer=Peer(args.server,args.room,Path(args.secret_file).read_text().strip(),args.name,args.logs,echo=True,origin=args.origin)
    try:await peer.run()
    finally:await peer.close()
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--server',default='ws://127.0.0.1:8088/ws');p.add_argument('--room',default='lab');p.add_argument('--secret-file',required=True);p.add_argument('--name',default='Server Echo');p.add_argument('--origin',help='Exact operator-approved WSS Origin; not an identity credential');p.add_argument('--logs',default=str(Path(__file__).parent/'data'/'echo'))
    asyncio.run(main(p.parse_args()))
