(function(root){
'use strict';
const EVENTS=new Set(['path.state','probe.ack','transfer.complete','client.error','client.boot']);
const STATES=new Set(['unsupported','gathering','probing','authenticating','direct','failed','timeout','closed']);
const METHODS=new Set(['webrtc','udp-probe','quic','tcp','tcp-simopen','upnp','pcp','natpmp']);
const REASONS=new Set(['AUTH_FAILED','SCHEMA_INVALID','LIMIT_EXCEEDED','RELAY_FORBIDDEN','PEER_UNAVAILABLE','EVENT_CONFLICT','UNSUPPORTED_VERSION','TIMEOUT','CLOSED','INTEGRITY_FAILED','UNSUPPORTED','INTERNAL_ERROR','ROOM_EXPIRED','ATTEMPT_CONFLICT','ENDPOINT_UNOBSERVABLE']);
function sanitize(event,data){if(!EVENTS.has(event))throw Error('UNKNOWN_LOG_EVENT');const out={};for(const [key,value]of Object.entries(data||{})){if(key==='state'&&STATES.has(value)||key==='mechanism'&&METHODS.has(value)||key==='family'&&[4,6,null].includes(value)||key==='reason'&&(REASONS.has(value)||value===null))out[key]=value;else if(['bytes','txBytes','rxBytes','rttMs','goodput','elapsedMs','queuedBytes'].includes(key)&&(value===null||typeof value==='number'&&Number.isFinite(value)&&value>=0))out[key]=value;else if(['integrityOk','ok','echo','canMessage'].includes(key)&&typeof value==='boolean')out[key]=value;}return out;}
function prune(records,now=Date.now(),maxBytes=20*1024*1024){let kept=records.filter(e=>now-e.tsWallMs<=7*86400000),bytes=kept.reduce((n,e)=>n+JSON.stringify(e).length*2,0),pending=kept.filter(e=>!e.acked).length,dropped=records.length-kept.length;while(kept.length&&(bytes>maxBytes||pending>2000)){const e=kept.shift();bytes-=JSON.stringify(e).length*2;if(!e.acked)pending--;dropped++;}return {records:kept,dropped};}
class Diagnostics{
 constructor(onChange){this.records=[];this.seq=0;this.session=crypto.randomUUID();this.onChange=onChange;this.error=null;this.dropped=0;this.chain=Promise.resolve();this.ready=this.open();}
 async open(){try{this.db=await new Promise((resolve,reject)=>{const q=indexedDB.open('p2pobs-diagnostics-v1',1);q.onupgradeneeded=()=>q.result.createObjectStore('state');q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});const saved=await new Promise((resolve,reject)=>{const q=this.db.transaction('state').objectStore('state').get('journal');q.onsuccess=()=>resolve(q.result);q.onerror=()=>reject(q.error);});if(saved){this.session=saved.session;this.seq=saved.seq;this.records=saved.records;this.dropped=saved.dropped||0;}this.trim();this.onChange?.(this);}catch{this.error='本地 IndexedDB 不可用：日志仅内存，刷新会丢失';this.onChange?.(this);}}
 trim(){const r=prune(this.records);this.records=r.records;this.dropped+=r.dropped;}
 persist(){this.trim();this.onChange?.(this);this.chain=this.chain.then(()=>{if(!this.db)return;const snapshot={session:this.session,seq:this.seq,records:this.records,dropped:this.dropped};return new Promise((resolve,reject)=>{const t=this.db.transaction('state','readwrite');t.objectStore('state').put(snapshot,'journal');t.oncomplete=resolve;t.onerror=()=>reject(t.error);t.onabort=()=>reject(t.error);});}).catch(()=>{this.error='本地日志写入失败：检查存储配额';this.onChange?.(this);});return this.chain;}
 add(event,data={},path={}){const e={v:1,id:crypto.randomUUID(),clientSessionId:this.session,seq:++this.seq,tsWallMs:Date.now(),monoMs:performance.now(),connectionId:path.connectionId||null,attemptId:path.attemptId||null,event,data:sanitize(event,data),acked:false};this.records.push(e);this.persist();return e;}
 batch(){return this.records.filter(e=>!e.acked).slice(0,30).map(({acked,...e})=>e);}
 ack(m){if(m.clientSessionId!==this.session||!Array.isArray(m.ids))return;const ids=new Set(m.ids);for(const e of this.records)if(ids.has(e.id))e.acked=true;this.persist();}
 export(){return this.records.map(({acked,...e})=>({...e,data:sanitize(e.event,e.data)}));}
}
root.P2PDiagnostics={Diagnostics,sanitize,prune};if(typeof module!=='undefined')module.exports=root.P2PDiagnostics;
})(globalThis);
