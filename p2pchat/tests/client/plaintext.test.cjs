'use strict';
/* 明文 ws:// 的放行（显式确认）、如实风险文案与持续提示。
   只跑真实 web/ 脚本（core/diagnostics/rtc/transfer/ux/app）在 vm 沙箱里的行为，并读 index.html；
   不连接任何服务器、不发任何网络请求：这里的“连接”全部是桩 WebSocket。 */
const {test}=require('node:test'),assert=require('node:assert/strict'),vm=require('node:vm'),fs=require('node:fs'),path=require('node:path');
const web=name=>path.join(__dirname,'../../web',name);
const IDS=['log-count','logs','transfer-status','peers','peer-count','chat-title','paths','active-path','messages','mesh','capabilities','server','join','room','name','secret','leave','discover','send','message','file','speed','stop-speed','record','export','status','upload-logs','central-status','step-label','open-settings','close-settings','settings-panel','screen-connect','screen-attempt','screen-chat','connection-error','attempt-summary','attempt-error','attempt-methods','attempt-settings','remaining','availability','benchmark-result','allow-plaintext','plaintext-banner'];

function harness(){
 const make=()=>({textContent:'',value:'',checked:false,disabled:false,hidden:false,children:[],append(...e){this.children.push(...e);},replaceChildren(...e){this.children=e;},querySelector(){return null;},querySelectorAll(){return [];}});
 const elements=Object.fromEntries(IDS.map(id=>[id,make()]));
 elements['plaintext-banner'].hidden=true;   // 与 index.html 一致：默认不显示明文提示
 const timers=new Map();let timerId=0;const sockets=[];
 class Socket{static OPEN=1;constructor(url){this.url=url;this.readyState=0;this.sentAll=[];sockets.push(this);}send(s){this.sent=JSON.parse(s);this.sentAll.push(this.sent);}close(){this.readyState=3;}}
 const sandbox={console,TextEncoder,TextDecoder,crypto:require('node:crypto').webcrypto,performance,URL,Blob,Uint8Array,DataView,Map,Set,Date,JSON,Promise,WebSocket:Socket,location:{protocol:'https:',host:'example.test'},document:{getElementById:id=>elements[id],createElement:make,createTextNode:text=>({textContent:text})},setTimeout:(fn,ms)=>{timers.set(++timerId,{fn,ms});return timerId;},clearTimeout(id){timers.delete(id);},setInterval:()=>1,clearInterval(){},btoa,atob};
 sandbox.window=sandbox;sandbox.addEventListener=()=>{};sandbox.RTCPeerConnection=function(){};
 const ctx=vm.createContext(sandbox);
 for(const file of ['core.js','diagnostics.js','rtc.js','transfer.js','ux.js','app.js'])vm.runInContext(fs.readFileSync(web(file),'utf8'),ctx,{filename:file});
 return {elements,sockets,timers};
}
async function attempt(h,{server,consent=false}){h.elements['allow-plaintext'].checked=consent;h.elements.server.value=server;h.elements.room.value='lab';h.elements.name.value='me';h.elements.secret.value='secret123456';await h.elements.join.onclick();}
async function tick(times=3){for(let i=0;i<times;i++)await new Promise(resolve=>setImmediate(resolve));}
async function open(h,index=0){const socket=h.sockets[index];socket.readyState=1;socket.onopen();return socket.sent;}
async function answerChallenge(h,index=0,extra={}){
 const socket=h.sockets[index];
 socket.onmessage({data:JSON.stringify(Object.assign({v:1,type:'join_challenge',nonce:'ab'.repeat(24),expiresInMs:30000,proof:'hkdf-sha256-hmac-v2',roomEstablished:false},extra))});
 for(let i=0;i<500&&socket.sent.type!=='join';i++)await new Promise(resolve=>setImmediate(resolve));
 return socket.sent;
}

test('本机回环 ws:// 默认放行，且加入报文里没有房间密钥',async()=>{
 const h=harness();
 await attempt(h,{server:'ws://127.0.0.1:8765/ws',consent:false});
 assert.equal(h.sockets.length,1,'loopback ws 不应被拦');
 assert.equal(h.elements['connection-error'].textContent,'');
 assert.equal(h.sockets[0].url,'ws://127.0.0.1:8765/ws');
 const challenge=await open(h);
 assert.equal(challenge.v,1);
 assert.equal(challenge.type,'join_challenge');
 const join=await answerChallenge(h);
 assert.equal(join.v,1);
 assert.equal(join.type,'join');
 assert.equal(join.joinVersion,2);
 assert.equal('secret' in join,false);
 assert.ok(!JSON.stringify(join).includes('secret123456'),'加入报文里不能出现房间密钥');
});

test('整个 127.0.0.0/8 与本机名都算回环，默认放行',async()=>{
 for(const server of ['ws://127.0.0.2:8765/ws','ws://localhost:8765/ws','ws://[::1]:8765/ws','ws://[0:0:0:0:0:0:0:1]:8765/ws']){
  const h=harness();
  await attempt(h,{server,consent:false});
  assert.equal(h.sockets.length,1,`${server} 是本机回环，不该被拦`);
  assert.equal(h.elements['connection-error'].textContent,'');
 }
 for(const server of ['ws://[fe80::1]:8765/ws','ws://192.168.1.50:8765/ws','ws://example.test/ws']){
  const h=harness();
  await attempt(h,{server,consent:false});
  assert.equal(h.sockets.length,0,`${server} 不是回环，未确认时必须被拦`);
  assert.match(h.elements['connection-error'].textContent,/没有加密/);
 }
});

test('非回环 ws:// 未确认时被拒绝，且不建立任何连接',async()=>{
 const h=harness();
 await attempt(h,{server:'ws://192.168.1.50:8765/ws',consent:false});
 assert.equal(h.sockets.length,0,'未确认时必须拒绝');
 assert.match(h.elements['connection-error'].textContent,/没有加密/);
 assert.match(h.elements['connection-error'].textContent,/wss:\/\//);
 assert.equal(h.elements['plaintext-banner'].hidden,true);
});

test('非回环 ws:// 明确确认后放行，确认只用一次并给出如实风险文案',async()=>{
 const h=harness();
 await attempt(h,{server:'ws://192.168.1.50:8765/ws',consent:true});
 assert.equal(h.sockets.length,1,'确认后应放行本次会话');
 assert.equal(h.sockets[0].url,'ws://192.168.1.50:8765/ws');
 assert.equal(h.elements['allow-plaintext'].checked,false,'确认不能留在界面上变成「以后总是允许」');
 const banner=h.elements['plaintext-banner'];
 assert.equal(banner.hidden,false);
 assert.match(banner.textContent,/未加密/);
 assert.match(banner.textContent,/观察/);
 assert.match(banner.textContent,/篡改/);
 assert.match(banner.textContent,/切断/);
 assert.match(banner.textContent,/局域网|VPN/);
 assert.match(banner.textContent,/密钥不上链路/);
 assert.ok(!/明文[^。]{0,6}安全|安全[^。]{0,6}明文/.test(banner.textContent),'不能把明文说成安全');
 await open(h);
 const join=await answerChallenge(h);
 assert.equal('secret' in join,false);
 // 断开后提示消失；再连另一个非回环明文地址必须重新确认
 h.elements.leave.onclick();
 assert.equal(banner.hidden,true);
 await attempt(h,{server:'ws://10.0.0.9:8765/ws',consent:false});
 assert.equal(h.sockets.length,1,'前一次的确认不能顺延到下一个服务器');
});

test('wss:// 始终放行、不显示明文提示、不做任何静默降级',async()=>{
 const h=harness();
 await attempt(h,{server:'wss://example.test/ws',consent:true});
 assert.equal(h.sockets.length,1);
 assert.equal(h.sockets[0].url,'wss://example.test/ws','TLS 路径不得被改写');
 assert.equal(h.elements['allow-plaintext'].checked,false);
 assert.equal(h.elements['plaintext-banner'].hidden,true);
 assert.equal((await open(h)).type,'join_challenge');
 assert.equal((await answerChallenge(h)).joinVersion,2);
});

test('明文提示在会话期间持续可见，断开后消失',async()=>{
 const h=harness();
 await attempt(h,{server:'ws://192.168.1.50:8765/ws',consent:true});
 await open(h);
 await answerChallenge(h);
 assert.equal(h.elements['plaintext-banner'].hidden,false);
 h.sockets[0].onmessage({data:JSON.stringify({v:1,type:'welcome',id:'me-1',strictP2P:true,iceServers:[{urls:'stun:example.test:3478'}]})});
 for(let i=0;i<50&&h.elements['screen-attempt'].hidden!==false;i++)await tick(1);
 assert.equal(h.elements['screen-attempt'].hidden,false,'应进入第 2 屏');
 assert.equal(h.elements['plaintext-banner'].hidden,false,'进入后续屏幕后提示仍然可见');
 assert.match(h.elements['plaintext-banner'].textContent,/密钥不上链路/);
 h.elements.leave.onclick();
 assert.equal(h.elements['plaintext-banner'].hidden,true);
});

test('index.html：确认控件默认未勾选、明文提示条在屏幕之外，且不把 ws:// 说成推荐',()=>{
 const html=fs.readFileSync(web('index.html'),'utf8');
 assert.match(html,/<input type="checkbox" id="allow-plaintext">/);
 assert.ok(!/id="allow-plaintext"[^>]*checked/.test(html),'确认框默认必须是未勾选');
 assert.match(html,/id="plaintext-banner"[^>]*hidden/);
 assert.ok(html.indexOf('id="plaintext-banner"')<html.indexOf('id="screen-connect"'),'提示条必须在三个屏幕之外，切换屏幕也看得见');
 assert.match(html,/默认请用加密的/);
 assert.match(html,/不作为推荐方式/);
 assert.match(html,/房间密钥不上链路/);
 assert.match(html,/观察/);
 assert.match(html,/篡改/);
 assert.match(html,/切断/);
 assert.match(html,/局域网|VPN/);
 assert.ok(!/推荐使用[^。]{0,8}ws:\/\//.test(html),'不得把 ws:// 描述成推荐方式');
});

test('明文确认不入 storage、不存在 trust-all/跳过证书校验，也不放宽无中继不变量',()=>{
 const files=['app.js','core.js','index.html','rtc.js','transfer.js','ux.js','diagnostics.js'];
 const text=files.map(name=>fs.readFileSync(web(name),'utf8')).join('\n');
 const app=fs.readFileSync(web('app.js'),'utf8');
 assert.ok(!/localStorage|sessionStorage/.test(text),'明文确认不得持久化到浏览器存储');
 for(const pattern of [/trust[ _-]?all/i,/rejectUnauthorized/i,/insecure/i,/跳过证书/,/忽略证书/,/NODE_TLS_REJECT_UNAUTHORIZED/,/certificate[ _-]?check/i])
  assert.ok(!pattern.test(text),`不得出现跳过 TLS 校验的写法：${pattern}`);
 assert.match(app,/if\(m\.strictP2P!==true\)throw Error\('RELAY_FORBIDDEN'\)/,'无中继不变量（strictP2P）必须保留');
 assert.match(app,/control\(C\.joinChallengeMessage\(auth\.room,diagnostics\.session\)\)/,'加入必须先取一次性 nonce');
});
