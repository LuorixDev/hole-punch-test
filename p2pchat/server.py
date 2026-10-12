"""IPv4/IPv6 signaling + STUN. No application relay route; echo is a separate peer.

Two equivalent signaling transports share one App/Store/room/auth code path:
WebSocket (`/ws`) and HTTP POST + SSE (`/signal/join`, `/signal`, `/signal/events`).
Neither transport relays chat/file/voice data; both reject TURN.
"""
from __future__ import annotations
import argparse
import asyncio
import collections
import hashlib
import hmac
import ipaddress
import json
import logging
import re
import secrets
import socket
import ssl
import struct
import time
from pathlib import Path
from aiohttp import web, WSMsgType
from p2pchat.backend.telemetry import Store, room_directory
from p2pchat.backend.protocol import MECHANISMS, PROFILES, ProtocolError, check, fields, join, signal, string, uid

BASE=Path(__file__).resolve().parent
LOG=logging.getLogger('p2pchat')
SENSITIVE={'password','token','secret','key','authorization','sdp','body','content','payload','ice_pwd','credential','proof','nonce','candidate','text','name','mime','sha256'}
def redact(value,depth=0):
    if depth>6:return '[depth-limit]'
    if isinstance(value,dict): return {str(k)[:80]:'[redacted]' if str(k).lower() in SENSITIVE else redact(v,depth+1) for k,v in list(value.items())[:50]}
    if isinstance(value,list):return [redact(v,depth+1) for v in value[:50]]
    if isinstance(value,str):return value[:2048]
    return value if value is None or isinstance(value,(bool,int,float)) else '[redacted]'
def candidate_meta(sdp):
    out=[]
    for line in sdp.splitlines():
        if line.startswith('a=candidate:'):
            p=line[2:].split()
            if len(p)>=8:out.append({'protocol':p[2].lower(),'address':p[4],'port':p[5],'type':p[7]})
    return out[:64]

# Shared transport limits. The WS values are unchanged (max_msg_size=131072, 80 msg/s,
# 2 telemetry/s); the HTTP/SSE limits are the equivalents plus explicit bounds.
MESSAGE_BYTES=131072
LIMIT_EXCEEDED='LIMIT_EXCEEDED'
RATE_WINDOW=1.0
RATE_MESSAGES=80
RATE_TELEMETRY=2
WS_CLOSE_SHUTDOWN=1001
ERROR_CODES={'AUTH_FAILED','SCHEMA_INVALID','LIMIT_EXCEEDED','RELAY_FORBIDDEN','PEER_UNAVAILABLE','EVENT_CONFLICT','UNSUPPORTED_VERSION','ROOM_EXPIRED','ATTEMPT_CONFLICT','TIMEOUT'}
HTTP_STATUS={'SCHEMA_INVALID':400,'AUTH_FAILED':401,'RELAY_FORBIDDEN':403,'LIMIT_EXCEEDED':429,
             'ROOM_EXPIRED':410,'PEER_UNAVAILABLE':404,'ATTEMPT_CONFLICT':409,'TIMEOUT':408,
             'UNSUPPORTED_VERSION':400,'EVENT_CONFLICT':409}
def error_code(exc):return str(exc) if str(exc) in ERROR_CODES else 'SCHEMA_INVALID'

# ---------------------------------------------------------------------------
# 加入证明（join proof v2）：信令链路上不再传输可复用的房间密钥
# ---------------------------------------------------------------------------
# 客户端：join_key = HKDF-SHA256(secret, salt=room, info=JOIN_KEY_INFO)
#         proof    = HMAC-SHA256(join_key, room \0 nonce \0 clientSessionId)
# 服务器：只保存/比较 join_key（派生值），永远拿不到也不能还原原始 secret；
#         nonce 由服务器下发、一次性、有时效。
JOIN_KEY_INFO=b'p2pchat/join-key/v2'
JOIN_PROOF_ALGO='hkdf-sha256-hmac-v2'
JOIN_VERSION=2
LEGACY_JOIN_VERSION=1
LEGACY_JOIN_HINT='JOIN_PROOF_V2_REQUIRED'
LEGACY_JOIN_DETAIL=('服务器已要求 v2 加入证明：旧协议会把房间密钥明文交给服务器，'
                    '因此只在服务器本机来源上兼容；请把客户端升级到 v2（或由操作者显式开启 --allow-legacy-join）。')
HEX64=re.compile('[0-9a-f]{64}')
HEX48=re.compile('[0-9a-f]{48}')
def join_proof(join_key,room,nonce,client_session_id):
    """HMAC-SHA256(join_key, room \0 nonce \0 clientSessionId) 的 hex（与 peer.py / core.js 一致）。"""
    message=(room+'\0'+nonce+'\0'+client_session_id).encode()
    return hmac.new(join_key,message,hashlib.sha256).hexdigest()
def is_loopback_source(source):
    if source in (None,''):return False
    try:return ipaddress.ip_address(str(source).split('%')[0]).is_loopback
    except ValueError:return False

class JoinError(ProtocolError):
    """带人话提示的拒绝（错误码仍用既有集合，例如 UNSUPPORTED_VERSION）。"""
    def __init__(self,code,hint=None,detail=None):
        super().__init__(code);self.hint=hint;self.detail=detail
def error_payload(code,exc=None):
    payload={'v':1,'type':'error','code':code}
    hint=getattr(exc,'hint',None) if exc is not None else None
    detail=getattr(exc,'detail',None) if exc is not None else None
    if hint:payload['hint']=hint
    if detail:payload['detail']=detail
    return payload
def welcome_payload(pid,config):
    """One welcome shape for both transports (semantics must not fork)."""
    return {'v':1,'type':'welcome','id':pid,'strictP2P':True,'iceServers':config.get('iceServers',[]),
            'profiles':PROFILES,'limits':{'room':12,'messageBytes':MESSAGE_BYTES,'fileBytes':33554432}}
def sse_frame(payload):
    """One SSE data frame; UTF-8 JSON so the browser EventSource can parse it as-is."""
    return b'data: '+json.dumps(payload,ensure_ascii=False).encode()+b'\n\n'

class WsLink:
    """Downstream channel for one WebSocket peer (unchanged behavior, just wrapped)."""
    transport='ws'
    def __init__(self,ws):self.ws=ws
    @property
    def closed(self):return self.ws.closed
    async def send(self,payload):
        if self.ws.closed:return False
        await self.ws.send_json(payload);return True
    def close(self,reason=None):self.reason=reason

class SseLink:
    """Bounded downstream channel for one HTTP/SSE peer.

    Unread frames live in a deque with an explicit cap. Overflow is never silent:
    the link records LIMIT_EXCEEDED as its close reason, wakes the stream so the
    client receives one final error frame, and the hub then tears the session down.
    """
    transport='http'
    KEEPALIVE=20.0
    POLL=1.0
    def __init__(self,limit=64,on_overflow=None):
        self.queue=collections.deque();self.limit=limit;self.on_overflow=on_overflow
        self.closed=False;self.close_reason=None;self.reason_sent=False
        self.wake=asyncio.Event()
    def send_nowait(self,payload):
        if self.closed:return False
        if len(self.queue)>=self.limit:
            self.close(LIMIT_EXCEEDED)  # explicit reason, delivered as the final SSE frame
            if self.on_overflow:self.on_overflow()
            return False
        self.queue.append(payload);self.wake.set();return True
    async def send(self,payload):
        """WsLink.send 的等价接口；入队失败返回 False（绝不静默丢弃）。"""
        return self.send_nowait(payload)
    def close(self,reason=None):
        if self.closed:return
        self.closed=True;self.close_reason=reason;self.wake.set()
    async def stream(self,should_stop=None):
        """Yield ready-to-write SSE frames until closed/overflowed or the peer goes away."""
        idle=0
        while True:
            while self.queue:
                yield sse_frame(self.queue.popleft());idle=0
            if self.closed:
                if self.close_reason and not self.reason_sent:
                    self.reason_sent=True
                    yield sse_frame({'v':1,'type':'error','code':self.close_reason})
                return
            self.wake.clear()
            if self.closed:continue
            try:
                await asyncio.wait_for(self.wake.wait(),self.POLL)
            except asyncio.TimeoutError:
                idle+=1
                # 客户端断开时不会有人写失败来叫醒我们，所以这里轮询传输层状态。
                if should_stop is not None and should_stop():return
                if idle*self.POLL>=self.KEEPALIVE:
                    idle=0;yield b': keepalive\n\n'

class Session:
    """Transport-agnostic room member: same join/auth/room limits and same dispatch."""
    def __init__(self,hub,pid,room,scope,client_session,name,capabilities,link,transport,source=None):
        self.hub,self.pid,self.room,self.scope=hub,pid,room,scope
        self.client_session,self.name,self.capabilities=client_session,name,capabilities
        self.link,self.transport,self.source=link,transport,source
        self.joined=False;self.closed=False;self.streaming=False
        self.event_token=None;self.created=time.monotonic()
        self.window=time.monotonic();self.count=0;self.telemetry=0
    def rate_tick(self):
        """Same window semantics as the WS loop: 80 messages/s, 2 telemetry/s per session."""
        now=time.monotonic()
        if now-self.window>=RATE_WINDOW:self.count=0;self.telemetry=0;self.window=now
        self.count+=1;check(self.count<=RATE_MESSAGES,'LIMIT_EXCEEDED')
    async def send(self,payload):
        return await self.link.send(payload)

class Hub:
    def __init__(self,store,config):
        self.store,self.config=store,config
        self.peers={};self.rooms={};self.room_keys={};self.room_started={};self.attempts={};self.connections={};self.sockets=set()
        # HTTP/SSE bookkeeping (separate caps; the WS path is unchanged).
        self.http_sessions={};self.http_source_counts={};self.http_source_windows={}
        self.join_nonces={};self.join_source_windows={}
        self.tasks=set()
        self.salt=bytes.fromhex(store.salt)
    def digest(self,room,secret):return hmac.new(self.salt,(room+'\0'+secret).encode(),hashlib.sha256).digest()
    def origin_allowed(self,request):
        """Exact allowlist for every transport; no-Origin only via explicit operator switch."""
        allowed=self.config.get('origins',[])
        if not allowed:return True
        origin=request.headers.get('Origin')
        if origin is not None:return origin in allowed
        return bool(self.config.get('allowNoOrigin',False))
    async def roster(self,room):
        peers=[{'id':p,'name':self.peers[p]['name'],'capabilities':self.peers[p]['capabilities']} for p in self.rooms.get(room,set()) if p in self.peers]
        await asyncio.gather(*(self.peers[p]['link'].send({'v':1,'type':'roster','peers':peers}) for p in list(self.rooms.get(room,set())) if p in self.peers and not self.peers[p]['link'].closed),return_exceptions=True)
    def bind_signal(self,pid,data):
        target=self.peers.get(data['to']);source=self.peers[pid]
        check(target is not None and target['room']==source['room'],'PEER_UNAVAILABLE')
        signal(data)
        aid=data['attemptId'];cid=data['connectionId'];pair=tuple(sorted((pid,data['to'])))
        check(pid!=data['to'])
        existing=self.connections.get(cid)
        check(existing is None or existing==pair,'ATTEMPT_CONFLICT')
        # Native candidates / early ICE may precede offer, but only the lower ID announces a new connection.
        if existing is None:
            check(pid==pair[0],'ATTEMPT_CONFLICT');self.connections[cid]=pair
        binding=(cid,pair,data['mechanism'],data['profile'])
        a=self.attempts.get(aid)
        if a is None:
            check(pid==pair[0],'ATTEMPT_CONFLICT')
            check(sum(pid in v['binding'][1] for v in self.attempts.values())<96,'LIMIT_EXCEEDED')
            a=self.attempts[aid]={'binding':binding,'created':time.monotonic(),'counts':{},'offer':False,'answer':False,'closed':False}
        check(a['binding']==binding and not a['closed'],'ATTEMPT_CONFLICT')
        if not a['offer'] and data['mechanism']=='webrtc':check(time.monotonic()-a['created']<=10,'TIMEOUT')
        if 'description' in data:
            kind=data['description']['type']
            if kind=='offer': check(pid==pair[0] and not a['offer'],'ATTEMPT_CONFLICT');a['offer']=True
            else:check(pid==pair[1] and a['offer'] and not a['answer'],'ATTEMPT_CONFLICT');a['answer']=True
        if 'candidate' in data or 'nativeCandidate' in data:
            a['counts'][pid]=a['counts'].get(pid,0)+1;check(a['counts'][pid]<=64,'LIMIT_EXCEEDED')
        if 'retry' in data:
            previous=self.attempts.get(data['retry']['previousAttemptId'])
            check(previous is not None and previous['binding'][0:2]==binding[0:2] and previous is not a,'ATTEMPT_CONFLICT')
            previous['closed']=True
        return target
    NAT_SAMPLES_MAX=64
    NAT_SAMPLES_PER_ATTEMPT=8
    def bind_samples(self,pid,data):
        """nat-samples: whitelisted signaling metadata, strict schema, forward only.

        The frame carries HMAC-protected NAT port-allocation samples for the attempt.
        The server validates shape/bounds and relays it unchanged: it holds no room
        key, cannot read the samples' proof, and never carries chat content.
        """
        target=self.peers.get(data['to']);source=self.peers.get(pid)
        check(target is not None and target['room']==source['room'],'PEER_UNAVAILABLE')
        fields(data,{'v','type','to','connectionId','attemptId','mechanism','profile','nonce','proof','samples'})
        check(data['v']==1,'UNSUPPORTED_VERSION');check(data['type']=='nat-samples','SCHEMA_INVALID')
        check(pid!=data['to'])
        uid(data['connectionId']);uid(data['attemptId']);string(data['to'],100)
        check(data['mechanism'] in {'udp-probe','quic'},'SCHEMA_INVALID')
        string(data['profile'],48)
        check(isinstance(data['nonce'],str) and bool(HEX48.fullmatch(data['nonce'])),'SCHEMA_INVALID')
        check(isinstance(data['proof'],str) and bool(HEX64.fullmatch(data['proof'])),'SCHEMA_INVALID')
        samples=data['samples']
        check(isinstance(samples,list) and 1<=len(samples)<=self.NAT_SAMPLES_MAX,'LIMIT_EXCEEDED')
        for item in samples:
            check(isinstance(item,dict) and set(item)=={'sequence','localPort','destination','mappedPort'},'SCHEMA_INVALID')
            check(type(item['sequence']) is int and 0<=item['sequence']<=4095,'SCHEMA_INVALID')
            for key in ('localPort','mappedPort'):
                check(type(item[key]) is int and 1<=item[key]<=65535,'SCHEMA_INVALID')
            destination=item['destination']
            check(isinstance(destination,list) and len(destination)==2,'SCHEMA_INVALID')
            check(type(destination[1]) is int and 1<=destination[1]<=65535,'SCHEMA_INVALID')
            try: address=ipaddress.ip_address(destination[0])
            except ValueError: raise ProtocolError('SCHEMA_INVALID') from None
            check(not (address.is_multicast or address.is_unspecified or address.is_link_local or str(address)=='255.255.255.255'),'SCHEMA_INVALID')
        pair=tuple(sorted((pid,data['to'])))
        a=self.attempts.get(data['attemptId'])
        check(a is not None and not a['closed'] and a['binding'][0]==data['connectionId'] and a['binding'][1]==pair
              and a['binding'][2]==data['mechanism'],'ATTEMPT_CONFLICT')
        key='samples:'+pid
        a['counts'][key]=a['counts'].get(key,0)+1
        check(a['counts'][key]<=self.NAT_SAMPLES_PER_ATTEMPT,'LIMIT_EXCEEDED')
        return target
    # ---- 加入证明 v2 -------------------------------------------------
    def issue_join_nonce(self,room,client_session,source=None):
        """下发一次性 nonce；每次下发都顺手清理过期项，并限制未决 nonce 总数。"""
        ttl=self.config.get('join_nonce_ttl',30);now=time.monotonic()
        if source is not None:
            limit=self.config.get('max_join_challenges_per_source',30)
            window,count=self.join_source_windows.get(source,(now,0))
            if now-window>=RATE_WINDOW:window,count=now,0
            count+=1
            check(count<=limit,'LIMIT_EXCEEDED')
            self.join_source_windows[source]=(window,count)
        for nonce,item in list(self.join_nonces.items()):
            if now-item['created']>ttl:self.join_nonces.pop(nonce,None)
        check(len(self.join_nonces)<self.config.get('max_join_nonces',1024),'LIMIT_EXCEEDED')
        nonce=secrets.token_hex(24)
        self.join_nonces[nonce]={'room':room,'session':client_session,'created':now}
        return nonce,int(ttl*1000)
    def consume_join_nonce(self,nonce,room,client_session):
        """取走 nonce：一次性（重放必然失败）+ 有时效 + 绑定房间与会话。"""
        item=self.join_nonces.pop(nonce,None)
        check(item is not None,'AUTH_FAILED')
        check(time.monotonic()-item['created']<=self.config.get('join_nonce_ttl',30),'AUTH_FAILED')
        check(item['room']==room and item['session']==client_session,'AUTH_FAILED')
    def validate_join_v2(self,data):
        fields(data,{'v','type','joinVersion','room','name','clientSessionId','capabilities','nonce','proof'},{'verifier'})
        check(data['v']==1,'UNSUPPORTED_VERSION');check(data['type']=='join','SCHEMA_INVALID')
        check(data['joinVersion']==JOIN_VERSION,'UNSUPPORTED_VERSION')
        for key,lo,hi in [('room',1,64),('name',1,48)]:string(data[key],hi,lo)
        uid(data['clientSessionId'])
        caps=data['capabilities']
        check(isinstance(caps,list) and len(caps)<=8 and all(x in MECHANISMS for x in caps),'SCHEMA_INVALID')
        check(isinstance(data['nonce'],str) and bool(HEX48.fullmatch(data['nonce'])),'SCHEMA_INVALID')
        check(isinstance(data['proof'],str) and bool(HEX64.fullmatch(data['proof'])),'SCHEMA_INVALID')
        if 'verifier' in data:
            check(isinstance(data['verifier'],str) and bool(HEX64.fullmatch(data['verifier'])),'SCHEMA_INVALID')
    def legacy_join_allowed(self,source):
        """旧协议(明文 secret)只在显式许可或服务器本机来源上兼容，默认远端一律拒绝。"""
        explicit=self.config.get('allowLegacyJoin')
        if explicit is True:return True
        if explicit is False:return False
        return is_loopback_source(source)
    def join_v2(self,data,source=None):
        """校验 v2 加入：nonce 一次性 + HMAC 证明；服务器只保存/比较派生值。"""
        self.validate_join_v2(data)
        room=data['room'];client_session=data['clientSessionId']
        self.consume_join_nonce(data['nonce'],room,client_session)
        stored=self.room_keys.get(room)
        if stored is None:
            check('verifier' in data,'AUTH_FAILED')
            key_bytes=bytes.fromhex(data['verifier'])
        else:
            check(stored.get('version')==JOIN_VERSION,'AUTH_FAILED')
            key_bytes=stored['digest']
        check(hmac.compare_digest(join_proof(key_bytes,room,data['nonce'],client_session),data['proof']),'AUTH_FAILED')
        if stored is None:self.room_keys[room]={'version':JOIN_VERSION,'digest':key_bytes}
        scope=hmac.new(self.salt,b'v2\0'+room.encode()+b'\0'+key_bytes,hashlib.sha256).hexdigest()
        return room,scope
    def join_legacy(self,data,source=None):
        """旧协议：含明文 secret；只在允许的来源上接受，并且每次都醒目记录。"""
        if not self.legacy_join_allowed(source):
            raise JoinError('UNSUPPORTED_VERSION',LEGACY_JOIN_HINT,LEGACY_JOIN_DETAIL)
        join(data)
        room=data['room'];digest=self.digest(room,data['secret'])
        stored=self.room_keys.get(room)
        check(stored is None or (stored.get('version')==LEGACY_JOIN_VERSION and hmac.compare_digest(digest,stored['digest'])),'AUTH_FAILED')
        if stored is None:self.room_keys[room]={'version':LEGACY_JOIN_VERSION,'digest':digest}
        LOG.warning('legacy v1 join accepted from %s (room key sent in clear on the wire); '
                    'migrate this client to joinVersion=2',source)
        return room,digest.hex()
    async def open_session(self,pid,data,link,transport,source=None,event_token=None):
        """Join schema + room key + room cap + bookkeeping; identical for both transports."""
        version=JOIN_VERSION if isinstance(data,dict) and data.get('joinVersion')==JOIN_VERSION else LEGACY_JOIN_VERSION
        if version==JOIN_VERSION:
            room,scope=self.join_v2(data,source)
        else:
            room,scope=self.join_legacy(data,source)
        check(len(self.rooms.get(room,()))<self.config.get('max_room',12),'LIMIT_EXCEEDED')
        session=Session(self,pid,room,scope,data['clientSessionId'],data['name'],data['capabilities'],link,transport,source)
        session.event_token=event_token
        self.rooms.setdefault(room,set()).add(pid);self.room_started.setdefault(room,time.monotonic())
        self.peers[pid]={'link':link,'room':room,'name':data['name'],'capabilities':data['capabilities'],'session':data['clientSessionId'],'transport':transport}
        session.joined=True
        if transport=='http' and source is not None:
            self.http_source_counts[source]=self.http_source_counts.get(source,0)+1
        self.store.event(scope,pid,'session.joined',{})
        return session
    async def close_session(self,session):
        """Idempotent teardown; mirrors the WS finally-block ordering exactly."""
        if session is None or session.closed:return
        session.closed=True
        self.peers.pop(session.pid,None)
        for aid,a in list(self.attempts.items()):
            if session.pid in a['binding'][1]:self.attempts.pop(aid,None)
        for cid,pair in list(self.connections.items()):
            if session.pid in pair:self.connections.pop(cid,None)
        if session.event_token:self.http_sessions.pop(session.event_token,None)
        if session.transport=='http' and session.source is not None:
            remaining=self.http_source_counts.get(session.source,0)-1
            if remaining>0:self.http_source_counts[session.source]=remaining
            else:self.http_source_counts.pop(session.source,None)
        if session.link is not None:session.link.close()
        if session.joined:
            room=session.room
            self.rooms[room].discard(session.pid)
            if not self.rooms[room]:self.rooms.pop(room,None);self.room_keys.pop(room,None);self.room_started.pop(room,None)
            self.store.event(session.scope,session.pid,'session.left',{});await self.roster(room)
    async def dispatch(self,session,data):
        """The single message dispatcher both transports use (WS code path unchanged)."""
        check(isinstance(data,dict));check(data.get('v')==1,'UNSUPPORTED_VERSION')
        kind=data.get('type')
        if kind=='signal':
            target=self.bind_signal(session.pid,data)
            self.store.event(session.scope,session.pid,'signal.sdp' if 'description' in data else 'signal.candidate',{'mechanism':data['mechanism']},connection_id=data['connectionId'],attempt_id=data['attemptId'])
            await target['link'].send({**data,'from':session.pid})
            return []
        if kind=='nat-samples':
            target=self.bind_samples(session.pid,data)
            self.store.event(session.scope,session.pid,'signal.nat-samples',
                             {'mechanism':data['mechanism'],'samples':len(data['samples'])},
                             connection_id=data['connectionId'],attempt_id=data['attemptId'])
            await target['link'].send({**data,'from':session.pid})
            return []
        if kind=='telemetry':
            fields(data,{'v','type','clientSessionId','events'})
            check(data['clientSessionId']==self.peers[session.pid]['session'],'AUTH_FAILED')
            session.telemetry+=1;check(session.telemetry<=RATE_TELEMETRY,'LIMIT_EXCEEDED')
            ids=self.store.ingest(session.scope,session.pid,data['clientSessionId'],data['events'])
            return [{'v':1,'type':'telemetry_ack','clientSessionId':data['clientSessionId'],'ids':ids}]
        if kind=='ping':
            fields(data,{'v','type'},{'ts'})
            check('ts' not in data or type(data['ts']) in (int,float))
            return [{'v':1,'type':'pong','ts':data.get('ts')}]
        raise ValueError('SCHEMA_INVALID')
    async def websocket(self,request):
        if len(self.sockets)>=self.config.get('max_peers',256):raise web.HTTPServiceUnavailable()
        if not self.origin_allowed(request):raise web.HTTPForbidden()
        ws=web.WebSocketResponse(heartbeat=20,max_msg_size=MESSAGE_BYTES)
        self.sockets.add(ws)
        pid=secrets.token_hex(12);session=None
        try:
            await ws.prepare(request)
            source=self.http_source(request)
            msg=await asyncio.wait_for(ws.receive(),15)
            check(msg.type==WSMsgType.TEXT)
            first=json.loads(msg.data)
            if isinstance(first,dict) and first.get('type')=='join_challenge':
                fields(first,{'v','type','room','clientSessionId'})
                check(first['v']==1,'UNSUPPORTED_VERSION')
                string(first['room'],64);uid(first['clientSessionId'])
                nonce,expires=self.issue_join_nonce(first['room'],first['clientSessionId'],source)
                await ws.send_json({'v':1,'type':'join_challenge','nonce':nonce,'expiresInMs':expires,
                                    'proof':JOIN_PROOF_ALGO,'roomEstablished':first['room'] in self.room_keys})
                msg=await asyncio.wait_for(ws.receive(),15)
                check(msg.type==WSMsgType.TEXT)
                first=json.loads(msg.data)
            session=await self.open_session(pid,first,WsLink(ws),'ws',source)
            await ws.send_json(welcome_payload(pid,self.config))
            await self.roster(session.room)
            started=self.room_started[session.room]
            while not ws.closed:
                remaining=self.config.get('room_ttl',3600)-(time.monotonic()-started)
                if remaining<=0:raise ValueError('ROOM_EXPIRED')
                try:msg=await asyncio.wait_for(ws.receive(),remaining)
                except asyncio.TimeoutError:raise ValueError('ROOM_EXPIRED') from None
                if msg.type in {WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR}:break
                check(msg.type==WSMsgType.TEXT)
                session.rate_tick()
                for payload in await self.dispatch(session,json.loads(msg.data)):await ws.send_json(payload)
        except (ValueError,TypeError,AttributeError,KeyError,asyncio.TimeoutError) as exc:
            code=error_code(exc);scope=session.scope if session else ''
            self.store.event(scope,pid,'session.error',{'reason':code})
            if ws.prepared and not ws.closed:await ws.send_json(error_payload(code,exc))
        except (ConnectionError,RuntimeError): pass
        finally:
            self.sockets.discard(ws)
            await self.close_session(session)
            if ws.prepared:await ws.close()
        return ws
    # ------------------------------------------------------------------
    # HTTP + SSE transport (equivalent signaling; no relay, same bounds)
    # ------------------------------------------------------------------
    def http_session(self,request):
        token=request.headers.get('X-P2P-Token') or request.query.get('token') or ''
        session=self.http_sessions.get(token)
        check(session is not None and session.transport=='http' and not session.closed,'AUTH_FAILED')
        return session
    def http_source(self,request):return request.remote or 'unknown'
    def http_source_rate(self,source):
        """Per-source POST rate cap so one origin cannot monopolise the process."""
        limit=self.config.get('max_http_messages_per_source',240)
        now=time.monotonic();window,count=self.http_source_windows.get(source,(now,0))
        if now-window>=RATE_WINDOW:window,count=now,0
        count+=1
        check(count<=limit,'LIMIT_EXCEEDED')
        self.http_source_windows[source]=(window,count)
    def spawn(self,coro):
        task=asyncio.ensure_future(coro);self.tasks.add(task)
        task.add_done_callback(self.tasks.discard);return task
    def source_cap(self,request):
        limit=self.config.get('max_http_sse_per_source',4)
        check(self.http_source_counts.get(self.http_source(request),0)<limit,'LIMIT_EXCEEDED')
    def session_cap(self):
        check(len(self.http_sessions)<self.config.get('max_http_sse',128),'LIMIT_EXCEEDED')
    def register_http_session(self,session,token):
        session.event_token=token;self.http_sessions[token]=session
    async def overflow_session(self,session):
        """未读缓冲/慢消费者超限：先记原因再断开——绝不静默丢弃，也不无界增长。"""
        self.store.event(session.scope,session.pid,'session.error',{'reason':LIMIT_EXCEEDED})
        await self.close_session(session)
    async def prune_http_sessions(self):
        """Bound the token map: drop closed sessions and never-streamed ones past their TTL."""
        ttl=self.config.get('http_session_ttl',120);now=time.monotonic()
        for session in list(self.http_sessions.values()):
            if session.closed or (not session.streaming and now-session.created>ttl):
                await self.close_session(session)
    def close_streams(self):
        """Called on app shutdown: end SSE streams so handlers can finish."""
        for session in list(self.http_sessions.values()):session.link.close()
    async def read_json(self,request):
        """Bounded body read: no unbounded buffering, oversize is an explicit error."""
        length=request.content_length
        if length is not None and length>MESSAGE_BYTES:raise ValueError('LIMIT_EXCEEDED')
        try:raw=await request.read()
        except web.HTTPRequestEntityTooLarge:raise ValueError('LIMIT_EXCEEDED') from None
        if len(raw)>MESSAGE_BYTES:raise ValueError('LIMIT_EXCEEDED')
        try:data=json.loads(raw)
        except (ValueError,UnicodeDecodeError):raise ValueError('SCHEMA_INVALID') from None
        check(isinstance(data,dict))
        return data
    def http_error(self,code,status=None,exc=None):
        return web.json_response(error_payload(code,exc),status=status or HTTP_STATUS.get(code,400))
    def origin_error(self):
        """Origin 不匹配：HTTP 通道统一回 JSON 错误体（WS 握手仍是裸 403，行为不变）。"""
        return self.http_error('AUTH_FAILED',403)
    async def http_join_challenge(self,request):
        """下发一次性 nonce：v2 客户端用它构造加入证明。"""
        try:
            if not self.origin_allowed(request):return self.origin_error()
            data=await self.read_json(request)
            fields(data,{'v','type','room','clientSessionId'})
            check(data['v']==1,'UNSUPPORTED_VERSION');check(data['type']=='join_challenge','SCHEMA_INVALID')
            string(data['room'],64);uid(data['clientSessionId'])
            nonce,expires=self.issue_join_nonce(data['room'],data['clientSessionId'],self.http_source(request))
            return web.json_response({'v':1,'type':'join_challenge','nonce':nonce,'expiresInMs':expires,
                                      'proof':JOIN_PROOF_ALGO,'roomEstablished':data['room'] in self.room_keys})
        except (ProtocolError,ValueError) as exc:
            return self.http_error(error_code(exc),None,exc)
    async def http_join(self,request):
        pid=secrets.token_hex(12);session=None
        try:
            if not self.origin_allowed(request):return self.origin_error()
            await self.prune_http_sessions()
            self.source_cap(request);self.session_cap()
            data=await self.read_json(request)
            link=SseLink(self.config.get('max_http_queue',64))
            session=await self.open_session(pid,data,link,'http',self.http_source(request))
            token=secrets.token_urlsafe(24)
            self.register_http_session(session,token)
            link.on_overflow=lambda:self.spawn(self.overflow_session(session))
            payload=welcome_payload(pid,self.config)
            payload.update({'transport':'http','eventToken':token,'eventsPath':'/signal/events'})
            # 与 WS 相同顺序：欢迎之后立刻广播花名册；新 peer 的那一份留在队列里，等 SSE 连上再下发。
            await self.roster(session.room)
            return web.json_response(payload)
        except (ProtocolError,ValueError) as exc:
            code=error_code(exc);scope=session.scope if session else ''
            self.store.event(scope,pid,'session.error',{'reason':code})
            await self.close_session(session)
            # 房间密钥不匹配是"拒绝加入"（403）；无 token/伪造 token 才是 401。
            return self.http_error(code,403 if code=='AUTH_FAILED' else None,exc)
    async def http_post(self,request):
        session=None
        try:
            if not self.origin_allowed(request):return self.origin_error()
            session=self.http_session(request)
            self.http_source_rate(self.http_source(request))
            session.rate_tick()
            data=await self.read_json(request)
            for payload in await self.dispatch(session,data):await session.send(payload)
            return web.json_response({'v':1,'type':'accepted'},status=202)
        except (ProtocolError,ValueError) as exc:
            code=error_code(exc);status=413 if (code=='LIMIT_EXCEEDED' and (request.content_length or 0)>MESSAGE_BYTES) else None
            if session is not None:
                self.store.event(session.scope,session.pid,'session.error',{'reason':code})
                await session.send(error_payload(code,exc))
                await self.close_session(session)
            return self.http_error(code,status,exc)
    async def http_events(self,request):
        session=None;attached=False
        try:
            if not self.origin_allowed(request):return self.origin_error()
            await self.prune_http_sessions()
            session=self.http_session(request)
            if session.streaming:return self.http_error(LIMIT_EXCEEDED,409)
            session.streaming=True;attached=True
            response=web.StreamResponse(status=200,headers={'Content-Type':'text/event-stream',
                'Cache-Control':'no-cache','X-Accel-Buffering':'no'})
            await response.prepare(request)
            try:
                await response.write(b'retry: 3000\n\n')
                async for frame in session.link.stream(should_stop=lambda:request.transport is None or request.transport.is_closing()):
                    await response.write(frame)
            except (ConnectionResetError,asyncio.CancelledError):pass
            except RuntimeError:pass
            return response
        except (ProtocolError,ValueError) as exc:
            return self.http_error(error_code(exc),401 if session is None else None,exc)
        except web.HTTPException:
            raise
        finally:
            if session is not None and attached:
                session.streaming=False
                await self.close_session(session)

def stun_binding(data,addr):
    if not 20<=len(data)<=1024:return None
    kind,length,magic=struct.unpack('!HHI',data[:8])
    if kind!=1 or magic!=0x2112A442 or length!=len(data)-20 or length%4:return None
    offset=20
    while offset<len(data):
        if offset+4>len(data):return None
        typ,size=struct.unpack('!HH',data[offset:offset+4]);offset+=4
        if offset+size>len(data):return None
        # No credentials/allocations; unsupported comprehension-required attributes are rejected.
        if typ<0x8000 and typ not in {0x0006,0x0008}:return None
        if typ==0x0008:return None  # authenticated STUN not offered
        offset+=(size+3)&~3
        if offset>len(data):return None
    tx=data[8:20]
    try:ip=ipaddress.ip_address(addr[0])
    except ValueError:return None
    mask=struct.pack('!I',magic)+tx
    value=struct.pack('!BBH',0,1 if ip.version==4 else 2,addr[1]^(magic>>16))+bytes(a^b for a,b in zip(ip.packed,mask))
    attr=struct.pack('!HH',0x0020,len(value))+value
    return struct.pack('!HHI',0x0101,len(attr),magic)+tx+attr

class Stun(asyncio.DatagramProtocol):
    def __init__(self,store,*,clock=None):
        # Injection is for deterministic rate-window tests; production always
        # uses monotonic arrival-callback time, not sender/OS scheduling time.
        self.clock=clock if clock is not None else time.monotonic
        self.store=store;self.buckets={};self.window=self.clock();self.total=0
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,addr):
        now=self.clock()
        if now-self.window>=1:self.window=now;self.total=0;self.buckets={}
        self.total+=1
        if self.total>1000:return
        self.buckets[addr[0]]=self.buckets.get(addr[0],0)+1
        if self.buckets[addr[0]]>20:return
        reply=stun_binding(data,addr)
        if reply:
            self.transport.sendto(reply,addr)
            self.store.event('','stun','stun.binding',{'family':ipaddress.ip_address(addr[0]).version,'requestBytes':len(data),'responseBytes':len(reply)})

def data_directory(base,room=None):
    """服务端数据目录：房间名走**共享**的房间目录规则（ASCII 安全、不碰撞、旧目录优先）。

    * 给了 `--room`（一台机器/一个数据目录只服务一个房间的部署）：`base/<可读片段>-<哈希>`。
      房间名不再原样进路径，所以 POSIX + 非 UTF-8 文件系统编码（LC_ALL=C 的容器/CI）下也能建目录；
      旧版本已经按原名建过 `base/<房间名>` 且里面有数据时沿用旧目录，不会丢历史。
    * 没给房间（默认，多房间部署）：就是 `base` 本身——与旧行为完全一致，
      绝不会把一个 Store 按房间拆成多个。
    """
    return room_directory(base,room) if room else Path(base)

def make_app(data_dir,ice_servers=None,origins=None,**limits):
    for server in ice_servers or []:
        check(set(server)=={'urls'})
        urls=server['urls'] if isinstance(server['urls'],list) else [server['urls']]
        check(all(isinstance(u,str) and u.startswith('stun:') and len(u)<512 for u in urls),'RELAY_FORBIDDEN')
    store=Store(data_dir);hub=Hub(store,{'iceServers':ice_servers or [],'origins':origins or [],**limits})
    app=web.Application(client_max_size=131072);app['hub']=hub;app['store']=store
    app.router.add_get('/ws',hub.websocket)
    # Equivalent HTTP signaling: POST up, SSE down. Same app/Store/rooms/auth.
    app.router.add_post('/signal/join/challenge',hub.http_join_challenge)
    app.router.add_post('/signal/join',hub.http_join)
    app.router.add_post('/signal',hub.http_post)
    app.router.add_get('/signal/events',hub.http_events)
    async def health(request):return web.json_response({'ok':True,'mode':'strict-p2p','peers':len(hub.peers),'role':'signaling-stun'})
    async def index(request):return web.FileResponse(BASE/'web'/'index.html')
    app.router.add_get('/health',health);app.router.add_get('/',index);app.router.add_static('/assets/',BASE/'web')
    async def shutdown(app):
        hub.close_streams()  # end SSE streams so their handlers can return
        await asyncio.gather(*(ws.close(code=WS_CLOSE_SHUTDOWN) for ws in list(hub.sockets)),return_exceptions=True)
    async def cleanup(app):store.close()
    app.on_shutdown.append(shutdown);app.on_cleanup.append(cleanup);return app

def requested_hosts(raw):
    """--host is repeatable (like --stun-host); a plain string still means one host."""
    if isinstance(raw,str):return [raw] if raw else ['127.0.0.1']
    hosts=[str(h) for h in raw or () if str(h)]
    return hosts or ['127.0.0.1']
def is_loopback_host(host):
    try:return ipaddress.ip_address(host).is_loopback
    except ValueError:return host=='localhost'
def bound_addresses(site):
    """Actual bound (host,port) pairs of a site; [] if aiohttp internals ever change."""
    try:return [(str(sock.getsockname()[0]),sock.getsockname()[1]) for sock in site._server.sockets]
    except (AttributeError,TypeError):return []
def format_bound(address,port):
    text=str(address)
    return '%s:%s'%('['+text+']' if ':' in text else text,port)
async def serve(app,hosts,port,ssl_context=None,stun_hosts=None,stun_port=3478):
    """One site per --host sharing one AppRunner/Store: real dual stack, no cross-process lock.

    asyncio forces IPV6_V6ONLY on every listening socket, so one site is always
    single-family; dual stack means two explicit V6ONLY sites on the same port.
    Each family still gets its own STUN socket (STUN code sets V6ONLY itself).
    """
    runner=web.AppRunner(app);await runner.setup();transports=[]
    try:
        for host in hosts:
            site=web.TCPSite(runner,host,port,ssl_context=ssl_context)
            await site.start()
            bound=bound_addresses(site) or [(host,port)]
            for address,actual_port in bound:
                family='IPv6' if ':' in str(address) else 'IPv4'
                LOG.info('signaling listening on %s (%s, requested --host %s); every site shares one Store/data dir',format_bound(address,actual_port),family,host)
        for host in stun_hosts or ['127.0.0.1','::1']:
            family=socket.AF_INET6 if ':' in host else socket.AF_INET
            sock=socket.socket(family,socket.SOCK_DGRAM)
            if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((host,stun_port));sock.setblocking(False)
            t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Stun(app['store']),sock=sock);transports.append(t)
        await asyncio.Event().wait()
    finally:
        for t in transports:t.close()
        await runner.cleanup()

def public_bind_error(hosts,cert,origin,allow_plaintext):
    """非回环绑定的硬性要求；返回人话错误或 None。默认要求 TLS，只有显式开关才放开明文。"""
    if all(is_loopback_host(host) for host in hosts):return None
    if not origin:return 'public signaling requires --origin allowlist'
    if not cert and not allow_plaintext:
        return ('public signaling requires TLS and --origin allowlist '
                '(use --allow-plaintext only if you explicitly accept an unencrypted link)')
    return None
PLAINTEXT_WARNING=('警告：--allow-plaintext 已启用，信令未加密，链路可被观察/干扰；房间密钥不再在链路上传输。'
                   '任何能看到这条链路的人都可以观察或干扰信令，请只在你有意为之的隔离网络里这样用。')
async def main(args):
    hosts=requested_hosts(args.host)
    loopback=all(is_loopback_host(host) for host in hosts)
    if bool(args.cert)!=bool(args.key):raise ValueError('both --cert and --key required')
    if getattr(args,'allow_legacy_join',False) and getattr(args,'deny_legacy_join',False):
        raise ValueError('choose either --allow-legacy-join or --deny-legacy-join, not both')
    problem=public_bind_error(hosts,args.cert,args.origin,bool(getattr(args,'allow_plaintext',False)))
    if problem:raise ValueError(problem)
    if not loopback and not args.cert:
        LOG.warning('%s',PLAINTEXT_WARNING)
    if getattr(args,'allow_no_origin',False) and not loopback:
        LOG.warning('--allow-no-origin is ON for a non-loopback bind: clients that send no Origin header '
                    'will be accepted on both transports. Only use this for operators who explicitly trust the network path.')
    if getattr(args,'deny_legacy_join',False):
        LOG.warning('--deny-legacy-join is ON: the legacy join (room key on the wire) is refused from every source, '
                    'including this machine. Old clients must be updated to joinVersion=2.')
    if getattr(args,'allow_legacy_join',False):
        LOG.warning('--allow-legacy-join is ON: clients that still put the room key in the join message will be accepted '
                    'from any source. That key is reusable for end-to-end pairing; only enable it to migrate old clients.')
    context=None
    if args.cert:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(args.cert,args.key)
    data_dir=data_directory(args.data,args.room)
    LOG.info('data directory: %s (--room %s)',data_dir,args.room or '<shared across rooms>')
    app=make_app(str(data_dir),[{'urls':args.stun_url}] if args.stun_url else [],args.origin,
                 allowNoOrigin=bool(getattr(args,'allow_no_origin',False)),
                 allowLegacyJoin=(True if getattr(args,'allow_legacy_join',False)
                                  else False if getattr(args,'deny_legacy_join',False) else None))
    await serve(app,hosts,args.port,context,args.stun_host,args.stun_port)

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',action='append',help='Repeat for real IPv4+IPv6 (--host 0.0.0.0 --host ::); defaults to 127.0.0.1')
    p.add_argument('--port',type=int,default=8088)
    p.add_argument('--stun-host',action='append',help='Repeat for IPv4 and IPv6; defaults to both loopbacks')
    p.add_argument('--stun-port',type=int,default=3478);p.add_argument('--stun-url')
    p.add_argument('--data',default=str(BASE/'data'));p.add_argument('--cert');p.add_argument('--key');p.add_argument('--origin',action='append',default=[])
    p.add_argument('--room',help='Single-room deployment: --data becomes the base and this room gets an ASCII-safe, '
                                 'collision-free subdirectory (same rule as the desktop client; a legacy --data/<room> '
                                 'directory with data in it is reused). Omit it to keep one shared data directory for all rooms.')
    p.add_argument('--allow-plaintext',action='store_true',
                   help='Explicitly allow a NON-loopback plaintext listener. Off by default (non-loopback still requires '
                        '--cert/--key). Plaintext means the link can be observed or tampered with; the room key is no longer '
                        'sent on the wire, but TLS is still strongly recommended.')
    p.add_argument('--allow-legacy-join',action='store_true',
                   help='TEMPORARY migration escape hatch: also accept the legacy join that sends the room key itself, from any '
                        'source. Off by default (legacy joins are only accepted from loopback sources).')
    p.add_argument('--deny-legacy-join',action='store_true',
                   help='Refuse the legacy join (room key on the wire) from every source, including this machine. Use it when '
                        'a local reverse proxy makes remote clients look like loopback, or to be strict everywhere.')
    p.add_argument('--allow-no-origin',action='store_true',
                   help='Explicitly allow clients that send no Origin header (non-browser clients). '
                        'Off by default: without it, a configured --origin allowlist rejects missing Origin on both transports.')
    logging.basicConfig(level=logging.INFO);asyncio.run(main(p.parse_args()))
