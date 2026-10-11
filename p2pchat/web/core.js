/* Shared pure protocol helpers. CommonJS export is for node:test only. */
(function(root){
'use strict';
const enc=new TextEncoder(),dec=new TextDecoder('utf-8',{fatal:true});
const LIMIT={file:32*1024*1024,reserved:64*1024*1024,chunk:16384,high:524288,low:131072};
const uuid=()=>crypto.randomUUID();
function family(address){return typeof address==='string'?(address.includes(':')?6:/^(\d{1,3}\.){3}\d{1,3}$/.test(address)?4:null):null;}
function candidateInfo(c){const a=c.trim().split(/\s+/);return {family:family(a[4]),protocol:a[2]?.toLowerCase(),type:a[a.indexOf('typ')+1]};}
function permitted(c,profile){const m=candidateInfo(c);return m.type!=='relay'&&(profile==='ice-dual'||m.family===null||m.family===(profile==='ice-v6'?6:4));}
function filterSdp(sdp,profile){return sdp.split(/\r?\n/).filter(l=>!l.startsWith('a=candidate:')||permitted(l.slice(2),profile)).join('\r\n');}
function encodeFrame(id,sequence,payload){const n=enc.encode(id),b=new Uint8Array(payload);if(!n.length||n.length>100||!Number.isInteger(sequence)||sequence<0||sequence>0xffffffff||b.length>LIMIT.chunk)throw Error('INVALID_CHUNK');const out=new Uint8Array(6+n.length+b.length),v=new DataView(out.buffer);v.setUint16(0,n.length);out.set(n,2);v.setUint32(2+n.length,sequence);out.set(b,6+n.length);return out;}
function decodeFrame(data){const b=new Uint8Array(data),v=new DataView(b.buffer,b.byteOffset,b.byteLength);if(b.length<7)throw Error('INVALID_CHUNK');const n=v.getUint16(0);if(!n||n>100||b.length<6+n||b.length-6-n>LIMIT.chunk)throw Error('INVALID_CHUNK');return {id:dec.decode(b.subarray(2,2+n)),sequence:v.getUint32(2+n),payload:b.subarray(6+n)};}
const hex=b=>[...new Uint8Array(b)].map(x=>x.toString(16).padStart(2,'0')).join('');
const sha=async b=>hex(await crypto.subtle.digest('SHA-256',b));
async function proof(secret,fields){const key=await crypto.subtle.importKey('raw',enc.encode(secret),{name:'HMAC',hash:'SHA-256'},false,['sign']);return hex(await crypto.subtle.sign('HMAC',key,enc.encode(JSON.stringify(fields))));}
function equal(a,b){if(typeof a!=='string'||typeof b!=='string'||a.length!==b.length)return false;let d=0;for(let i=0;i<a.length;i++)d|=a.charCodeAt(i)^b.charCodeAt(i);return d===0;}
/* 加入证明 v2：链路上不再出现房间密钥本身。
   joinKey = HKDF-SHA256(secret, salt=room, info='p2pchat/join-key/v2')
   proof   = HMAC-SHA256(joinKey, room \0 nonce \0 clientSessionId)
   服务器只保存/比较 joinKey（派生值），拿不到也还原不出原始 secret。
   这里没有回退到明文密钥的分支：服务器说 nonce 不可用就明确失败。 */
const JOIN={version:2,info:enc.encode('p2pchat/join-key/v2'),proof:'hkdf-sha256-hmac-v2'};
async function joinKeyBytes(secret,room){
 const material=await crypto.subtle.importKey('raw',enc.encode(secret),'HKDF',false,['deriveBits']);
 return crypto.subtle.deriveBits({name:'HKDF',hash:'SHA-256',salt:enc.encode(room),info:JOIN.info},material,256);
}
async function joinKey(secret,room){return hex(await joinKeyBytes(secret,room));}
async function joinProof(joinKeyHex,room,nonce,clientSessionId){
 const key=await crypto.subtle.importKey('raw',new Uint8Array((joinKeyHex.match(/../g)||[]).map(x=>parseInt(x,16))),{name:'HMAC',hash:'SHA-256'},false,['sign']);
 return hex(await crypto.subtle.sign('HMAC',key,enc.encode(`${room}\u0000${nonce}\u0000${clientSessionId}`)));
}
const joinChallengeMessage=(room,clientSessionId)=>({v:1,type:'join_challenge',room,clientSessionId});
async function joinMessage({room,secret,name,clientSessionId,capabilities,nonce,roomEstablished=false}){
 const key=await joinKey(secret,room);
 const message={v:1,type:'join',joinVersion:JOIN.version,room,name,clientSessionId,capabilities,
  nonce,proof:await joinProof(key,room,nonce,clientSessionId)};
 if(!roomEstablished)message.verifier=key;   // 只有房间里还没有密钥时才需要交派生值
 return message;
}
class Handshake{
 constructor(config){Object.assign(this,config);this.nonce=hex(crypto.getRandomValues(new Uint8Array(32)));this.remoteNonce=null;this.gotAck=false;this.sentAck=false;}
 fields(ack,sender,receiver,nonce,echo){const a=[ack?'p2pobs-v1-ack':'p2pobs-v1',this.room,this.connectionId,this.attemptId,sender,receiver,nonce];if(ack)a.push(echo);return a;}
 async hello(){return {v:1,kind:'hello',peer:this.localPeerId,connectionId:this.connectionId,attemptId:this.attemptId,nonce:this.nonce,proof:await proof(this.secret,this.fields(false,this.localPeerId,this.peerId,this.nonce))};}
 async receive(m){if(m.v!==1||m.peer!==this.peerId||m.connectionId!==this.connectionId||m.attemptId!==this.attemptId||!/^[a-f0-9]{64}$/.test(m.nonce))throw Error('AUTH_FAILED');const ack=m.kind==='hello-ack';if(!ack&&m.kind!=='hello')throw Error('AUTH_FAILED');if(!equal(m.proof,await proof(this.secret,this.fields(ack,this.peerId,this.localPeerId,m.nonce,m.echoNonce))))throw Error('AUTH_FAILED');if(ack){if(m.echoNonce!==this.nonce||this.gotAck||this.earlyAck)throw Error('AUTH_REPLAY');if(!this.remoteNonce){this.earlyAck=m.nonce;return null;}if(m.nonce!==this.remoteNonce)throw Error('AUTH_REPLAY');this.gotAck=true;return null;}if(this.remoteNonce)throw Error('AUTH_REPLAY');this.remoteNonce=m.nonce;if(this.earlyAck){if(this.earlyAck!==m.nonce)throw Error('AUTH_FAILED');this.earlyAck=null;this.gotAck=true;}this.sentAck=true;return {v:1,kind:'hello-ack',peer:this.localPeerId,connectionId:this.connectionId,attemptId:this.attemptId,nonce:this.nonce,echoNonce:m.nonce,proof:await proof(this.secret,this.fields(true,this.localPeerId,this.peerId,this.nonce,m.nonce))};}
 get complete(){return !!this.remoteNonce&&this.sentAck&&this.gotAck;}
 clear(){this.secret='';}
}
class Receiver{
 constructor(){this.items=new Map();this.reserved=0;}
 start(key,m,now=performance.now()){const budget=m.size+1024+256*Math.ceil(m.size/LIMIT.chunk);if(this.items.has(key)||this.items.size>=8||!Number.isInteger(m.size)||m.size<0||m.size>LIMIT.file||this.reserved+budget>LIMIT.reserved||typeof m.id!=='string'||!m.id.length||enc.encode(m.id).length>100||typeof m.name!=='string'||m.name.length>255||typeof m.mime!=='string'||m.mime.length>128||!/^[a-f0-9]{64}$/.test(m.sha256)||m.benchmark!==false)throw Error('TRANSFER_LIMIT');this.items.set(key,{id:m.id,name:m.name,mime:m.mime,size:m.size,sha256:m.sha256,echoOf:typeof m.echoOf==='string'?m.echoOf.slice(0,100):null,budget,parts:[],bytes:0,nextSequence:0,maxChunks:Math.ceil(m.size/LIMIT.chunk),started:now,updated:now});this.reserved+=budget;}
 chunk(key,c,now=performance.now()){const t=this.items.get(key);if(!t||c.sequence!==t.nextSequence||!c.payload.length||t.nextSequence>=t.maxChunks||c.payload.length!==Math.min(LIMIT.chunk,t.size-t.bytes))throw Error('INVALID_SEQUENCE');t.parts.push(c.payload.slice());t.bytes+=c.payload.length;t.nextSequence++;t.updated=now;return t;}
 take(key){const t=this.items.get(key);if(t){this.items.delete(key);this.reserved-=t.budget;}return t;}
 expire(now=performance.now()){for(const [k,t]of this.items)if(now-t.updated>30000)this.take(k);}
}
class Dedup{constructor(){this.entries=new Map();}has(key,now=Date.now()){for(const [k,t]of this.entries)if(now-t>600000)this.entries.delete(k);if(this.entries.has(key))return true;this.entries.set(key,now);while(this.entries.size>10000)this.entries.delete(this.entries.keys().next().value);return false;}}
function b64encode(bytes){let s='';for(const b of bytes)s+=String.fromCharCode(b);return btoa(s);}
function b64decode(s){if(typeof s!=='string'||s.length>90000)throw Error('INVALID_FRAME');return Uint8Array.from(atob(s),c=>c.charCodeAt(0));}
class NativeAdapter{
 constructor(bridge,onEvent){this.bridge=bridge;this.attempts=new Map();this.unsubscribe=bridge?.onEvent(e=>{const p=e.params||e,a=this.attempts.get(p.attemptId);if(!a||a.connectionId!==p.connectionId)return;const event=e.event||e.type;if(event==='data'){if(a.state!=='direct'||!a.canMessage)return;onEvent({event,...p,data:b64decode(p.dataB64)});}else{if(event==='state')a.state=p.state;onEvent({event,...p});}});}
 async capabilities(){return this.bridge?this.bridge.invoke('capabilities',{}):{v:1,methods:[{mechanism:'native',status:'unsupported',canMessage:false,reason:'NATIVE_BRIDGE_UNAVAILABLE'}]};}
 async start(p,canMessage){this.attempts.set(p.attemptId,{...p,canMessage,state:'gathering'});try{return await this.bridge.invoke('start',p);}catch(e){this.attempts.delete(p.attemptId);throw e;}}
 signal(p){return this.bridge.invoke('signal',p);}
 async send({attemptId,lane,data}){const p=this.attempts.get(attemptId);if(p?.state!=='direct'||!p.canMessage)throw Error('NOT_DIRECT');if(data.length>65536)throw Error('FRAME_LIMIT');const params={attemptId,lane,dataB64:b64encode(data)},deadline=performance.now()+(lane==='benchmark'?2000:10000);for(;;){if(this.attempts.get(attemptId)!==p||p.state!=='direct')throw Error('NOT_DIRECT');try{return await this.bridge.invoke('send',params);}catch(e){if(e.message!=='BACKPRESSURE')throw e;if(performance.now()>=deadline)throw Error('BACKPRESSURE_TIMEOUT');await new Promise((resolve,reject)=>{p.backpressureWaits||=new Set();const cancel=()=>{clearTimeout(timer);p.backpressureWaits.delete(cancel);reject(Error('NOT_DIRECT'));};const timer=setTimeout(()=>{p.backpressureWaits.delete(cancel);resolve();},20);p.backpressureWaits.add(cancel);});}}}
 stats(p){return this.bridge.invoke('stats',p);}
 async close(p){const old=this.attempts.get(p.attemptId);for(const cancel of old?.backpressureWaits||[])cancel();this.attempts.delete(p.attemptId);return this.bridge?.invoke('close',p);}
 destroy(){this.unsubscribe?.();}
}
const api={enc,dec,LIMIT,uuid,family,candidateInfo,permitted,filterSdp,encodeFrame,decodeFrame,sha,JOIN,joinKey,joinProof,joinChallengeMessage,joinMessage,Handshake,Receiver,Dedup,NativeAdapter};root.P2PCore=api;if(typeof module!=='undefined')module.exports=api;
})(globalThis);
