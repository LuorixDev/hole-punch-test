/* 三屏流程与人话方式说明的验收测试。
   这里只读文件、只调用展示层（web/ux.js），不启动网络、不连接服务器、不部署任何东西。 */
'use strict';
const {test}=require('node:test'),assert=require('node:assert/strict'),fs=require('node:fs'),path=require('node:path');
const UX=require('../../web/ux.js');
const web=name=>path.join(__dirname,'../../web',name);
const norm=value=>String(value).replace(/\*\*/g,'').replace(/[\u200b-\u200d\ufeff]/g,'').trim();
const BANNED=['TURN','中继','服务端转发','服务器代传','服务器转发'];
const NEGATED=/没有|不是|不会|并非|禁止|不经过|不通过/;
const ctx=extra=>Object.assign({joined:true,hasPeers:true,stunServers:['stun:example.test:3478'],platform:'web'},extra);
const caps=[
 {mechanism:'udp-probe',status:'available',canMessage:false,reason:'PROBE_ONLY',limits:{independentBenchmark:false}},
 {mechanism:'quic',status:'available',canMessage:true,reason:'EXPERIMENTAL_PLATFORM_UNVERIFIED',limits:{independentBenchmark:true}},
 {mechanism:'tcp',status:'available',canMessage:true,reason:'EXPERIMENTAL_PLATFORM_UNVERIFIED',limits:{independentBenchmark:false}},
 {mechanism:'tcp-simopen',status:'available',canMessage:true,reason:'EXPERIMENTAL_PLATFORM_UNVERIFIED',limits:{independentBenchmark:false}},
 {mechanism:'upnp',status:'unsupported',canMessage:false,reason:'OPT_IN_GATEWAY_API_ONLY'},
 {mechanism:'pcp',status:'unsupported',canMessage:false,reason:'OPT_IN_GATEWAY_API_ONLY'},
 {mechanism:'natpmp',status:'unsupported',canMessage:false,reason:'OPT_IN_GATEWAY_API_ONLY'}];
const paths=[
 {peerId:'b',mechanism:'webrtc',profile:'ice-dual',attemptId:'a1',state:'direct',canMessage:true,rttMs:12.4,gathering:'complete'},
 {peerId:'b',mechanism:'webrtc',profile:'ice-v6',attemptId:'a2',state:'direct',canMessage:false},
 {peerId:'b',mechanism:'webrtc',profile:'ice-v4',attemptId:'a3',state:'failed',failureCode:'ICE_FAILED'},
 {peerId:'b',mechanism:'udp-probe',profile:'direct',attemptId:'a4',state:'direct',canMessage:false},
 {peerId:'b',mechanism:'quic',profile:'direct',attemptId:'a5',state:'gathering'}];
const rowOf=(rows,id)=>rows.find(r=>r.id===id);

test('三屏状态机：连接服务器 → 逐条尝试 → 聊天，断开回到第一屏',()=>{
 assert.equal(UX.screen('connect',{joined:false,paths:[]}),'connect');
 assert.equal(UX.screen('connect',{joined:true,connecting:false,paths:[]}),'attempt');
 assert.equal(UX.screen('attempt',{joined:true,paths:[{state:'direct',canMessage:true}]}),'chat');
 assert.equal(UX.screen('chat',{joined:true,paths:[{state:'failed'}]}),'chat');
 assert.equal(UX.screen('chat',{joined:false,paths:[]}),'connect');
 assert.equal(UX.screen('attempt',{joined:true,paths:[{state:'direct',canMessage:false}]}),'attempt');
});

test('第2屏：固定顺序、人话名称、四种说明、状态与实测延迟',()=>{
 const rows=UX.rows(paths,caps,'b',true,ctx());
 assert.deepEqual(rows.map(r=>r.order),[1,2,3,4,5,6,7,8,9]);
 assert.deepEqual(rows.map(r=>r.id),['ice-dual','ice-v6','ice-v4','udp-probe','quic','tcp','tcp-simopen','observation','gateway']);
 for(const row of rows){
  assert.ok(row.title&&row.explain&&row.worksWhen&&row.commonFailure,`${row.id} 必须有名称/一句话说明/什么网络可行/失败最常见原因`);
  for(const code of ['ice-','tcp-simopen','udp-probe','stun-observation','observation','gateway','natpmp'])
   assert.ok(!row.title.toLowerCase().includes(code),`标题不能是内部代号：${row.title}`);
  assert.ok(['等待中','尝试中','已打通','已观测','不可用','不支持'].includes(row.state),`${row.id} 状态词不在约定集合内：${row.state}`);
 }
 const dual=rowOf(rows,'ice-dual');
 assert.equal(dual.state,'已打通');
 assert.equal(dual.latencyMs,12.4);
 assert.equal(dual.availability,'可用');
 const v6=rowOf(rows,'ice-v6');
 assert.equal(v6.state,'不可用');
 assert.notEqual(v6.state,'已打通');
 const v4=rowOf(rows,'ice-v4');
 assert.equal(v4.state,'不可用');
 assert.match(v4.detail,/直连/);
 assert.ok(!v4.detail.includes('ICE_FAILED'),'失败原因要用人的话，不能只抛内部代号');
 const probe=rowOf(rows,'udp-probe');
 assert.equal(probe.state,'已观测');
 assert.equal(probe.chatCapable,false);
 assert.ok(probe.badges.join(' ').includes('仅探测，不传内容'));
 assert.equal(probe.latencyMs,null);
 assert.equal(rowOf(rows,'quic').state,'尝试中');
 const tcp=rowOf(rows,'tcp');
 assert.equal(tcp.state,'等待中');
 assert.equal(tcp.availability,'可用');
 assert.equal(tcp.latencyMs,null);
 assert.equal(rowOf(rows,'observation').state,'已观测');
});

test('文案唯一来源：ux.js 的九条与 docs/METHODS-PLAIN.md 表格逐字一致',()=>{
 const doc=fs.readFileSync(path.join(__dirname,'../../docs/METHODS-PLAIN.md'),'utf8');
 const table=doc.split('\n').map(line=>/^\|\s*(\d+)\s*\|\s*\*\*(.+?)\*\*\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|\s*([^|]+?)\s*\|/.exec(line)).filter(Boolean);
 assert.equal(table.length,9,'METHODS-PLAIN.md 必须列出九种方式');
 table.forEach((match,index)=>{
  const [,order,name,what,works,failure]=match;
  assert.equal(UX.methods[index].order,Number(order));
  assert.equal(UX.methods[index].title,norm(name));
  assert.equal(UX.methods[index].explain,norm(what));
  assert.equal(UX.methods[index].worksWhen,norm(works));
  assert.equal(UX.methods[index].commonFailure,norm(failure));
 });
});

test('界面不提供中继/TURN/服务器转发选项，也不暗示失败会改走服务器',()=>{
 const html=fs.readFileSync(web('index.html'),'utf8');
 const rows=UX.rows(paths,caps,'b',true,ctx());
 for(const row of rows){
  const text=[row.title,row.explain,row.worksWhen,row.commonFailure,row.detail,...row.badges].join('。');
  for(const sentence of text.split(/[。；;]/))for(const word of BANNED)
   if(sentence.includes(word))assert.match(sentence,NEGATED,`这一句把「${word}」说成了可用选项：${sentence}`);
 }
 for(const sentence of html.replace(/<[^>]*>/g,' ').split(/[。；;]/))for(const word of BANNED)
  if(sentence.includes(word))assert.match(sentence,NEGATED,`index.html 这一句把「${word}」说成了可用选项：${sentence}`);
 assert.ok(rowOf(rows,'udp-probe').badges.join(' ').includes('仅探测，不传内容'));
 assert.ok(rowOf(rows,'observation').badges.join(' ').includes('不是中继'));
 assert.ok(html.includes('安卓显示为「不支持」'));
 const android=rowOf(UX.rows(paths,caps,'b',true,ctx({platform:'android'})),'gateway');
 assert.equal(android.state,'不支持');
 assert.match(android.detail,/安卓/);
 const webOnly=UX.rows([], [], 'b', true, ctx({stunServers:[]}));
 for(const id of ['udp-probe','quic','tcp','tcp-simopen'])
  assert.equal(rowOf(webOnly,id).state,'不支持',`网页版没有桌面组件，${id} 应显示不支持`);
 assert.equal(rowOf(webOnly,'observation').state,'不支持');
 assert.equal(rowOf(webOnly,'gateway').state,'不支持');
});

test('并行尝试：第一条可聊天连接就进聊天，其余方式仍在后台继续尝试',()=>{
 const rows=UX.rows(paths,caps,'b',true,ctx());
 assert.equal(UX.screen('attempt',{joined:true,paths}),'chat');
 assert.equal(rowOf(rows,'ice-dual').state,'已打通');
 assert.equal(rowOf(rows,'quic').state,'尝试中');
 assert.ok(UX.summary(rows).remaining.some(r=>r.id==='quic'),'还没成功的方式要继续留在「剩余方式」里');
});

test('设置面板数据：剩余方式/可用性/延迟如实反映，未测得不用零代替',()=>{
 const rows=UX.rows(paths,caps,'b',true,ctx());
 const summary=UX.summary(rows);
 assert.ok(summary.remaining.length>0);
 assert.ok(summary.remaining.every(r=>['等待中','尝试中'].includes(r.state)));
 assert.deepEqual(new Set(summary.availability.map(a=>a.availability)),new Set(['可用','不可用','不支持']));
 assert.deepEqual(summary.latency,[{id:'ice-dual',title:'双栈直连',latencyMs:12.4}]);
 assert.deepEqual(summary.chatReady.map(r=>r.id),['ice-dual']);
 assert.ok(rows.every(r=>r.latencyMs===null||Number.isFinite(r.latencyMs)));
});

test('页面装配：三屏结构齐全、ux.js 先于 app.js、app.js 用到的 id 都存在',()=>{
 const html=fs.readFileSync(web('index.html'),'utf8'),app=fs.readFileSync(web('app.js'),'utf8');
 for(const id of ['screen-connect','screen-attempt','screen-chat'])assert.ok(html.includes(`id="${id}"`),`缺少 ${id}`);
 assert.match(html,/id="upload-logs"[^>]*checked/);
 assert.ok(html.indexOf('ux.js')<html.indexOf('app.js'),'ux.js 必须在 app.js 之前加载');
 const used=[...app.matchAll(/\$\('([a-z0-9-]+)'\)/g)].map(m=>m[1]);
 assert.ok(used.length>10);
 for(const id of new Set(used))assert.ok(html.includes(`id="${id}"`),`app.js 用到 ${id}，index.html 里没有`);
 for(const word of UX.STATE_HELP.map(help=>help.state))assert.ok(html.includes(word),`index.html 缺少状态词 ${word}`);
 assert.ok(html.includes('已观测')&&html.includes('它不能传消息'),'index.html 必须说明「已观测」不是聊天成功');
 for(const word of ['剩余方式','可用性','测速'])assert.ok(html.includes(word),`index.html 设置面板缺少 ${word}`);
});

test('UX-FLOW.md 记录三屏状态机与状态语义',()=>{
 const doc=fs.readFileSync(path.join(__dirname,'../../docs/UX-FLOW.md'),'utf8');
 for(const anchor of ['第 1 屏','第 2 屏','第 3 屏','已观测','并行','METHODS-PLAIN.md'])
  assert.ok(doc.includes(anchor),`UX-FLOW.md 缺少 ${anchor}`);
});
