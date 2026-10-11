"""IPv4/IPv6 signaling + STUN. No application relay route; echo is a separate peer."""
from __future__ import annotations
import argparse
import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import struct
import time
from pathlib import Path
from aiohttp import web, WSMsgType
from p2pchat.backend.telemetry import Store
from p2pchat.backend.protocol import PROFILES, check, fields, join, signal

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

class Hub:
    def __init__(self,store,config):
        self.store,self.config=store,config
        self.peers={};self.rooms={};self.room_keys={};self.room_started={};self.attempts={};self.connections={};self.sockets=set()
        self.salt=bytes.fromhex(store.salt)
    def digest(self,room,secret):return hmac.new(self.salt,(room+'\0'+secret).encode(),hashlib.sha256).digest()
    async def roster(self,room):
        peers=[{'id':p,'name':self.peers[p]['name'],'capabilities':self.peers[p]['capabilities']} for p in self.rooms.get(room,set()) if p in self.peers]
        await asyncio.gather(*(self.peers[p]['ws'].send_json({'v':1,'type':'roster','peers':peers}) for p in list(self.rooms.get(room,set())) if p in self.peers and not self.peers[p]['ws'].closed),return_exceptions=True)
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
    async def websocket(self,request):
        if len(self.sockets)>=self.config.get('max_peers',256):raise web.HTTPServiceUnavailable()
        allowed=self.config.get('origins',[])
        if allowed and request.headers.get('Origin') not in allowed:raise web.HTTPForbidden()
        ws=web.WebSocketResponse(heartbeat=20,max_msg_size=131072)
        self.sockets.add(ws)
        pid=secrets.token_hex(12);room=None;scope='';joined=False
        try:
            await ws.prepare(request)
            msg=await asyncio.wait_for(ws.receive(),15)
            check(msg.type==WSMsgType.TEXT)
            data=json.loads(msg.data);join(data)
            room=data['room'];digest=self.digest(room,data['secret']);scope=digest.hex()
            check(room not in self.room_keys or hmac.compare_digest(digest,self.room_keys[room]),'AUTH_FAILED')
            check(len(self.rooms.get(room,()))<self.config.get('max_room',12),'LIMIT_EXCEEDED')
            self.room_keys.setdefault(room,digest);self.rooms.setdefault(room,set()).add(pid);self.room_started.setdefault(room,time.monotonic())
            self.peers[pid]={'ws':ws,'room':room,'name':data['name'],'capabilities':data['capabilities'],'session':data['clientSessionId']};joined=True
            self.store.event(scope,pid,'session.joined',{})
            await ws.send_json({'v':1,'type':'welcome','id':pid,'strictP2P':True,'iceServers':self.config.get('iceServers',[]),'profiles':PROFILES,'limits':{'room':12,'messageBytes':131072,'fileBytes':33554432}})
            await self.roster(room)
            started=self.room_started[room];window=time.monotonic();count=telemetry=0
            while not ws.closed:
                remaining=self.config.get('room_ttl',3600)-(time.monotonic()-started)
                if remaining<=0:raise ValueError('ROOM_EXPIRED')
                try:msg=await asyncio.wait_for(ws.receive(),remaining)
                except asyncio.TimeoutError:raise ValueError('ROOM_EXPIRED') from None
                if msg.type in {WSMsgType.CLOSE,WSMsgType.CLOSED,WSMsgType.ERROR}:break
                check(msg.type==WSMsgType.TEXT)
                now=time.monotonic()
                if now-window>=1:count=telemetry=0;window=now
                count+=1;check(count<=80,'LIMIT_EXCEEDED')
                data=json.loads(msg.data);check(isinstance(data,dict));check(data.get('v')==1,'UNSUPPORTED_VERSION')
                kind=data.get('type')
                if kind=='signal':
                    target=self.bind_signal(pid,data)
                    self.store.event(scope,pid,'signal.sdp' if 'description' in data else 'signal.candidate',{'mechanism':data['mechanism']},connection_id=data['connectionId'],attempt_id=data['attemptId'])
                    await target['ws'].send_json({**data,'from':pid})
                elif kind=='telemetry':
                    fields(data,{'v','type','clientSessionId','events'})
                    check(data['clientSessionId']==self.peers[pid]['session'],'AUTH_FAILED')
                    telemetry+=1;check(telemetry<=2,'LIMIT_EXCEEDED')
                    ids=self.store.ingest(scope,pid,data['clientSessionId'],data['events'])
                    await ws.send_json({'v':1,'type':'telemetry_ack','clientSessionId':data['clientSessionId'],'ids':ids})
                elif kind=='ping':
                    fields(data,{'v','type'},{'ts'})
                    check('ts' not in data or type(data['ts']) in (int,float))
                    await ws.send_json({'v':1,'type':'pong','ts':data.get('ts')})
                else:raise ValueError('SCHEMA_INVALID')
        except (ValueError,TypeError,AttributeError,KeyError,asyncio.TimeoutError) as exc:
            code=str(exc) if str(exc) in {'AUTH_FAILED','SCHEMA_INVALID','LIMIT_EXCEEDED','RELAY_FORBIDDEN','PEER_UNAVAILABLE','EVENT_CONFLICT','UNSUPPORTED_VERSION','ROOM_EXPIRED','ATTEMPT_CONFLICT','TIMEOUT'} else 'SCHEMA_INVALID'
            self.store.event(scope,pid,'session.error',{'reason':code})
            if ws.prepared and not ws.closed:await ws.send_json({'v':1,'type':'error','code':code})
        except (ConnectionError,RuntimeError): pass
        finally:
            self.sockets.discard(ws);self.peers.pop(pid,None)
            for aid,a in list(self.attempts.items()):
                if pid in a['binding'][1]:self.attempts.pop(aid,None)
            for cid,pair in list(self.connections.items()):
                if pid in pair:self.connections.pop(cid,None)
            if joined:
                self.rooms[room].discard(pid)
                if not self.rooms[room]:self.rooms.pop(room,None);self.room_keys.pop(room,None);self.room_started.pop(room,None)
                self.store.event(scope,pid,'session.left',{});await self.roster(room)
            if ws.prepared:await ws.close()
        return ws

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
    def __init__(self,store):self.store=store;self.buckets={};self.window=time.monotonic();self.total=0
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,addr):
        now=time.monotonic()
        if now-self.window>=1:self.window=now;self.total=0;self.buckets={}
        self.total+=1
        if self.total>1000:return
        self.buckets[addr[0]]=self.buckets.get(addr[0],0)+1
        if self.buckets[addr[0]]>20:return
        reply=stun_binding(data,addr)
        if reply:
            self.transport.sendto(reply,addr)
            self.store.event('','stun','stun.binding',{'family':ipaddress.ip_address(addr[0]).version,'requestBytes':len(data),'responseBytes':len(reply)})

def make_app(data_dir,ice_servers=None,origins=None,**limits):
    for server in ice_servers or []:
        check(set(server)=={'urls'})
        urls=server['urls'] if isinstance(server['urls'],list) else [server['urls']]
        check(all(isinstance(u,str) and u.startswith('stun:') and len(u)<512 for u in urls),'RELAY_FORBIDDEN')
    store=Store(data_dir);hub=Hub(store,{'iceServers':ice_servers or [],'origins':origins or [],**limits})
    app=web.Application(client_max_size=131072);app['hub']=hub;app['store']=store
    app.router.add_get('/ws',hub.websocket)
    async def health(request):return web.json_response({'ok':True,'mode':'strict-p2p','peers':len(hub.peers),'role':'signaling-stun'})
    async def index(request):return web.FileResponse(BASE/'web'/'index.html')
    app.router.add_get('/health',health);app.router.add_get('/',index);app.router.add_static('/assets/',BASE/'web')
    async def shutdown(app):await asyncio.gather(*(ws.close(code=1001) for ws in list(hub.sockets)),return_exceptions=True)
    async def cleanup(app):store.close()
    app.on_shutdown.append(shutdown);app.on_cleanup.append(cleanup);return app

async def main(args):
    try:local=ipaddress.ip_address(args.host).is_loopback
    except ValueError:local=args.host=='localhost'
    if bool(args.cert)!=bool(args.key):raise ValueError('both --cert and --key required')
    if not local and (not args.cert or not args.origin):raise ValueError('public signaling requires TLS and --origin allowlist')
    context=None
    if args.cert:
        context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.minimum_version=ssl.TLSVersion.TLSv1_2;context.load_cert_chain(args.cert,args.key)
    app=make_app(args.data,[{'urls':args.stun_url}] if args.stun_url else [],args.origin)
    runner=web.AppRunner(app);await runner.setup();transports=[]
    try:
        await web.TCPSite(runner,args.host,args.port,ssl_context=context).start()
        for host in args.stun_host or ['127.0.0.1','::1']:
            family=socket.AF_INET6 if ':' in host else socket.AF_INET
            sock=socket.socket(family,socket.SOCK_DGRAM)
            if family==socket.AF_INET6:sock.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            sock.bind((host,args.stun_port));sock.setblocking(False)
            t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Stun(app['store']),sock=sock);transports.append(t)
        await asyncio.Event().wait()
    finally:
        for t in transports:t.close()
        await runner.cleanup()

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--host',default='127.0.0.1');p.add_argument('--port',type=int,default=8088)
    p.add_argument('--stun-host',action='append',help='Repeat for IPv4 and IPv6; defaults to both loopbacks')
    p.add_argument('--stun-port',type=int,default=3478);p.add_argument('--stun-url')
    p.add_argument('--data',default=str(BASE/'data'));p.add_argument('--cert');p.add_argument('--key');p.add_argument('--origin',action='append',default=[])
    logging.basicConfig(level=logging.INFO);asyncio.run(main(p.parse_args()))
