'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict');if(!global.crypto)global.crypto=require('node:crypto').webcrypto;const C=require('../../web/core.js'),Transfers=require('../../web/transfer.js');
const path={attemptId:'attempt',peerId:'peer',mechanism:'webrtc'};
test('transfer MOCK unit: ready gate, sequence chunks, integrity ACK on same attempt',async()=>{let a,b;const messages=[],statuses=[];a=new Transfers({send:async(p,lane,data)=>b.receive(p,lane,data),message:(...m)=>messages.push(m),status:s=>statuses.push(s),log(){}});b=new Transfers({send:async(p,lane,data)=>a.receive(p,lane,data),message:(...m)=>messages.push(m),status(){},log(){}});try{const blob=new Blob(['payload'],{type:'text/plain'});await a.file(path,blob);assert.equal(messages.length,2);assert.match(statuses.at(-1),/ACK goodput/);assert.equal(b.receiver.reserved,0);assert.equal(a.waiters.size,0);}finally{a.destroy();b.destroy();}});
test('transfer MOCK unit: text delivered state and duplicate ACK no redisplay',async()=>{const messages=[],frames=[];const t=new Transfers({send:async(p,lane,data)=>frames.push(JSON.parse(C.dec.decode(data))),message:(...m)=>messages.push(m),status(){},log(){}});try{const m=C.enc.encode(JSON.stringify({v:1,kind:'text',id:'text1',text:'<img src=x onerror=alert(1)>'}));await t.receive(path,'chat',m);await t.receive(path,'chat',m);assert.equal(messages.length,1);assert.equal(frames.length,2);assert.equal(frames[0].kind,'delivered');const done=t.wait(path,'x','file-ack');t.settle({...path,attemptId:'other'},{kind:'file-ack',id:'x'});assert.equal(t.waiters.size,1);t.close(path.attemptId);await assert.rejects(done,/PATH_CLOSED/);}finally{t.destroy();}});
test('transfer MOCK unit: rejects hash mismatch without displaying payload',async()=>{const frames=[],messages=[];const t=new Transfers({send:async(p,lane,data)=>frames.push(JSON.parse(C.dec.decode(data))),message:m=>messages.push(m),status(){},log(){}});try{await t.receive(path,'chat',C.enc.encode(JSON.stringify({v:1,kind:'file-start',id:'x',name:'x',mime:'text/plain',size:1,sha256:'0'.repeat(64),benchmark:false})));await t.receive(path,'chat',C.encodeFrame('x',0,new Uint8Array([1])));await t.receive(path,'chat',C.enc.encode(JSON.stringify({v:1,kind:'file-end',id:'x'})));assert.equal(frames.at(-1).ok,false);assert.equal(messages.length,0);assert.equal(t.receiver.reserved,0);}finally{t.destroy();}});
test('transfer MOCK unit: benchmark is separate lane and capped; stop sends ACK',async()=>{let a,b;const statuses=[];a=new Transfers({send:async(p,lane,data)=>{assert.equal(lane,'benchmark');await b.receive(p,lane,data);if(data[0]!==123)a.stop();},message(){},status:s=>statuses.push(s),log(){}});b=new Transfers({send:async(p,lane,data)=>a.receive(p,lane,data),message(){},status(){},log(){}});try{await a.bench(path);assert.match(statuses.at(-1),/已停止/);assert.match(statuses.at(-1),/16384 B/);assert.equal(a.benchmark,null);assert.equal(b.benches.size,0);await assert.rejects(a.bench({...path,mechanism:'tcp'}),/NO_ISOLATED_LANE/);}finally{a.destroy();b.destroy();}});

const vm=require('node:vm'),fs=require('node:fs');
function measuredTransfers(samples){
 const context={P2PCore:C,performance:{now:()=>samples.shift()},setInterval,clearInterval,setTimeout,clearTimeout,Blob};context.globalThis=context;
 vm.runInNewContext(fs.readFileSync(require.resolve('../../web/transfer.js'),'utf8'),context);
 return context.P2PTransfers;
}
for(const lane of ['file','bench'])for(const duration of [0.25,0,-1,NaN,Infinity])test(`timing MOCK ${lane}: local duration ${duration}, remote null does not corrupt delivery`,async()=>{
 const T=measuredTransfers(lane==='file'?[0,duration,duration]:[0,0,duration,duration]);
 const statuses=[],logs=[],messages=[];let header,t;
 t=new T({send:async(p,lane,data)=>{
  if(data[0]!==123){if(lane==='benchmark')t.stop();return;}
  const m=JSON.parse(C.dec.decode(data));
  if(m.kind==='file-start'){header=m;t.settle(p,{kind:'file-ready',id:m.id,ok:true});}
  if(m.kind==='file-end')t.settle(p,{kind:'file-ack',id:m.id,ok:true,bytes:header.size,sha256:header.sha256,elapsedMs:null,timingError:'TIMING_UNAVAILABLE'});
  if(m.kind==='bench-end')t.settle(p,{kind:'bench-ack',id:m.id,bytes:C.LIMIT.chunk,elapsedMs:null,timingError:'TIMING_UNAVAILABLE'});
 },message:(...m)=>messages.push(m),status:s=>statuses.push(s),log:(...m)=>logs.push(m)});
 try{
  if(lane==='file')await t.file(path,new Blob(['payload']));else await t.bench(path);
  const status=statuses.at(-1);assert.match(status,/对端接收耗时未知/);assert.doesNotMatch(status,/Infinity|NaN/);
  if(duration>0&&Number.isFinite(duration)){
   const bytes=lane==='file'?7:C.LIMIT.chunk;
   assert.ok(status.includes((bytes*8/duration/1000).toFixed(2)+' Mbps'));
   assert.equal(logs.at(-1)[1].elapsedMs,duration);
  }else{
   assert.match(status,/goodput 不可计算/);assert.doesNotMatch(status,/Mbps/);
   assert.equal(logs.at(-1)[1].elapsedMs,null);
   if(lane==='bench')assert.equal(logs.at(-1)[1].goodput,null);
  }
  if(lane==='file'){assert.equal(logs.at(-1)[1].integrityOk,true);assert.equal(messages.length,1);}
 }finally{t.destroy();}
});
