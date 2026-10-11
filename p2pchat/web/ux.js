/* 展示层：界面文案与状态判定。只读地描述连接，不启动、不认证、不关闭任何连接。
   文案唯一来源：p2pchat/docs/METHODS-PLAIN.md —— 下面 methods 的名称与三段说明逐字对应那份文档的表格，
   改文案必须先改文档。状态词（等待中/尝试中/已打通/已观测/不可用/不支持）同样来自那文档的「状态用词」表。 */
(function(root){
'use strict';
const STATUS={WAITING:'等待中',TRYING:'尝试中',DIRECT:'已打通',OBSERVED:'已观测',UNAVAILABLE:'不可用',UNSUPPORTED:'不支持'};
const AVAILABILITY={[STATUS.DIRECT]:'可用',[STATUS.OBSERVED]:'可用',[STATUS.TRYING]:'可用',[STATUS.WAITING]:'可用',[STATUS.UNAVAILABLE]:'不可用',[STATUS.UNSUPPORTED]:'不支持'};
const SLUG={[STATUS.WAITING]:'waiting',[STATUS.TRYING]:'trying',[STATUS.DIRECT]:'direct',[STATUS.OBSERVED]:'observed',[STATUS.UNAVAILABLE]:'unavailable',[STATUS.UNSUPPORTED]:'unsupported'};
const methods=[
 {order:1,id:'ice-dual',profile:'ice-dual',chatCapable:true,title:'双栈直连',explain:'同时用 IPv6 和 IPv4 两种地址去找对方，谁先通就用谁',worksWhen:'双方都有可用公网地址（大多数家宽）',commonFailure:'两边 NAT 都严格、或运营商拦截 UDP',badges:['这一条和下面两条是同一套网页直连（WebRTC）的三种地址选择，不是三个独立协议']},
 {order:2,id:'ice-v6',profile:'ice-v6',chatCapable:true,title:'IPv6 直连',explain:'只用 IPv6 地址直连',worksWhen:'两台设备都有可用公网 IPv6，且入站防火墙放行',commonFailure:'一方没有 IPv6；或路由器/防火墙挡了入站',badges:[]},
 {order:3,id:'ice-v4',profile:'ice-v4',chatCapable:true,title:'IPv4 直连',explain:'只用 IPv4 地址直连',worksWhen:'至少一方有公网 IPv4，或双方 NAT 容易打洞',commonFailure:'双方都在大内网/CGNAT 后面',badges:[]},
 {order:4,id:'udp-probe',mechanisms:['udp-probe'],chatCapable:false,title:'UDP 探测',explain:'互相发加密小包，确认「这个地址端口能不能直达」',worksWhen:'只要能出去 UDP 就能探测',commonFailure:'UDP 被运营商限制',badges:['仅探测，不传内容：这条通了也不能用来聊天']},
 {order:5,id:'quic',mechanisms:['quic'],chatCapable:true,title:'QUIC 加密直连',explain:'用同一个 UDP 端口建立一条加密通道来传数据',worksWhen:'双方 UDP 可达',commonFailure:'UDP 被挡；或中间设备干扰',badges:[]},
 {order:6,id:'tcp',mechanisms:['tcp'],chatCapable:true,title:'TCP 加密直连',explain:'用 TCP 建立一条互相验证身份的加密连接',worksWhen:'UDP 被限制但 TCP 能出去的网络',commonFailure:'一方无法被动接受连接',badges:[]},
 {order:7,id:'tcp-simopen',mechanisms:['tcp-simopen'],chatCapable:true,title:'TCP 同时打开',explain:'双方同时主动向对方发起连接，谁都不当"服务器"',worksWhen:'只允许主动外连、不允许被动监听的网络',commonFailure:'双方时序错开，或中间设备重置连接',badges:[]},
 {order:8,id:'observation',mechanisms:['observation'],chatCapable:false,title:'STUN 映射观测',explain:'问外网「我在你眼里是什么地址和端口」，用来判断能不能直连',worksWhen:'所有能上网的环境',commonFailure:'服务器不可达；对称 NAT 下观测结果无用',badges:['只观察地址、不转发任何数据：它不是中继，看见地址也不等于能聊天']},
 {order:9,id:'gateway',mechanisms:['upnp','pcp','natpmp','gateway'],chatCapable:true,title:'路由器放行（UPnP / PCP / NAT-PMP / IPv6 放行）',explain:'向你自己家的路由器申请开一个端口',worksWhen:'路由器支持该协议且已开启',commonFailure:'路由器关闭了这类功能；运营商光猫拦截',badges:['默认关闭，必须你明确同意才会尝试','只有桌面 Python 版支持，安卓显示为「不支持」']}
];
const reasons={AUTH_FAILED:'双方身份校验未通过，请确认房间密码相同。',INTEGRITY_FAILED:'收到的文件校验不一致，已拒绝交付，请重新发送。',RELAY_FORBIDDEN:'发现了被禁止的转发路径，已拒绝使用。',SIGNAL_OFFLINE:'与服务器的连接已断开，正在等待恢复；已有直连可继续使用。',SIGNAL_SOCKET_ERROR:'无法连接服务器，请检查地址、网络和服务器证书。',PEER_UNAVAILABLE:'对方当前不在线，请等待对方重新加入。',NO_PEER:'房间里还没有其他人，请让对方加入同一房间。',NO_DIRECT_PATH:'还没有可聊天的直连，请等待连接成功或重新尝试。',NATIVE_BRIDGE_UNAVAILABLE:'此客户端没有可用的桌面网络组件（浏览器和安卓默认没有，桌面 Python 版才有）。',UNSUPPORTED:'此设备不支持这种方式。',OPT_IN_GATEWAY_API_ONLY:'需要在桌面 Python 侧显式开启；此界面不会自动修改路由器。',PROBE_ONLY:'这种方式只能探测连通性，不能用来传消息。',EXPERIMENTAL_PLATFORM_UNVERIFIED:'这个平台还没有经过真机验证，可能失败；不会把模拟结果当成成功。',ATTEMPT_TIMEOUT:'在等待时间内没有收到对方确认，可能被路由器或防火墙阻断。',TIMEOUT:'等待对方响应超时，请检查网络后重试。',ICE_FAILED:'浏览器没找到能互通的地址（没有可用的直连路径），请检查双方网络和防火墙。',PROBE_TIMEOUT:'对方已一段时间没有回应，连接可能已断开。',PEER_LOST:'与对方的连接中断了。',CHANNEL_CLOSED:'发送通道已关闭，请重新连接。',CHANNEL_ERROR:'发送通道出错，已停止使用这条连接。',START_FAILED:'这次连接未能启动，请检查本机网络组件后重试。',FAMILY_MISMATCH:'实际地址类型与所选方式不符，已拒绝把它算作成功。',LIMIT_EXCEEDED:'已达到本机或对方的安全限额，请稍后再试。',BENCH_UNSUPPORTED_NO_ISOLATED_LANE:'这条连接没有独立测速通道，因此不能测速。',BENCH_BUSY:'已有测速正在进行，请先停止或等待结束。',ACK_TIMEOUT:'没有按时收到接收确认；未报告发送成功。',REMOTE_RETRY_BUDGET_OR_NO_RESPONSE:'对方没有在 12 秒内建立新连接，可能已用完自动重试次数。',RETRY_REPLACED:'对方已开始新的连接尝试。',SESSION_RECONNECTED_OR_CLOSED:'会话已重新建立或关闭，旧连接已回收。',SUPERSEDED:'已由新的连接尝试替代。',RETRY_REQUESTED:'正在等待对方重新连接。',CLOSED:'连接已关闭。',INTERNAL_ERROR:'操作未能完成，请重试；详细记录可在设置中导出。',SCHEMA_INVALID:'对方发送的连接信息格式不符合要求，已拒绝。',UNSUPPORTED_VERSION:'双方软件版本不兼容，请使用相同版本。',SAVE_FAILED:'保存失败，请检查存储权限后重试。',EXPORT_FAILED:'诊断记录导出失败，请检查保存权限。',RECORDING_LIMIT:'录音已达到大小限制，请缩短录音。',RECORDING_FAILED:'录音失败，请检查麦克风权限后重试。',FILE_LIMIT_32_MIB:'文件太大，请选择不超过 32 MiB 的文件。',TEXT_LIMIT:'文字太长，请分成几条发送。',SEND_BUSY:'同时发送的文件过多，请等待当前文件发送完毕。',PEER_LEFT:'对方已离开房间。'};
const STATE_HELP=[
 {state:STATUS.WAITING,meaning:'还没轮到它，或正在排队。'},
 {state:STATUS.TRYING,meaning:'正在探测，通常几秒内出结果。'},
 {state:STATUS.DIRECT,meaning:'这条路径成功了，可以用来聊天。'},
 {state:STATUS.OBSERVED,meaning:'只用于探测或观测的方式成功了；它不能传消息，所以不叫「已打通」。'},
 {state:STATUS.UNAVAILABLE,meaning:'试过但失败了；点开这一条可以看到人话原因。'},
 {state:STATUS.UNSUPPORTED,meaning:'当前平台或当前配置用不了（例如安卓上的路由器放行）。'}];
const copy={
 probeNotice:'UDP 探测只确认能不能直连，不传聊天内容；它成功也不代表可以聊天。',
 stunNotice:'STUN 只观察地址，不转发任何数据 —— 它不是中继，本产品也没有中继、没有 TURN。',
 relayNotice:'整个产品没有任何中继、TURN 或服务器代传选项：直连不成功就是明确失败，不会偷偷改走服务器。',
 androidNotice:'路由器放行默认关闭，必须你明确同意才会尝试；只有桌面 Python 版支持，安卓显示为「不支持」。',
 parallelNotice:'列表按固定顺序展示，实际是并行尝试：第一条能聊天的连接成功就自动进入聊天，其余方式继续在后台尝试，失败不会被当成成功。',
 benchmarkNotice:'这是应用层速度，不是线路带宽。'
};
function reason(code){if(!code)return '';const key=String(code).split(' ')[0];return reasons[key]||(/[^\x00-\x7f]/.test(String(code))?String(code):'这次尝试未完成；请检查双方网络后重试。');}
function methodFor(p){if(!p)return null;return methods.find(m=>m.profile?p.mechanism==='webrtc'&&m.profile===p.profile:(m.mechanisms||[]).includes(p.mechanism))||null;}
function labelFor(idOrMechanism){const m=methods.find(x=>x.id===idOrMechanism||(x.mechanisms||[]).includes(idOrMechanism));return m?m.title:'桌面网络组件';}
function canBench(p){return !!p&&p.state==='direct'&&p.canMessage&&(p.mechanism==='webrtc'||p.limits?.independentBenchmark===true);}
function pathState(p,chatCapable){
 if(p.state==='direct'){
  if(p.canMessage)return {state:STATUS.DIRECT,detail:'双方已经完成安全校验，可以直接传消息。'};
  if(chatCapable)return {state:STATUS.UNAVAILABLE,detail:'连接虽然建立，但没有完成「可以传消息」的校验，所以不算打通。'};
  return {state:STATUS.OBSERVED,detail:'探测成功：这个地址端口能直达；但它只能探测，不传内容。'};
 }
 if(['gathering','probing','authenticating','connecting','negotiating','starting'].includes(p.state))return {state:STATUS.TRYING,detail:'正在探测，通常几秒内出结果。'};
 if(p.state==='unsupported')return {state:STATUS.UNSUPPORTED,detail:reason(p.failureCode)||'当前设备/配置用不了这种方式。'};
 if(['failed','timeout','closed','interrupted'].includes(p.state))return {state:STATUS.UNAVAILABLE,detail:reason(p.failureCode)||'试过但没有成功。'};
 return {state:STATUS.WAITING,detail:'排队等待中。'};
}
function rows(paths,caps,peerId,webRTC,ctx){
 const list=Array.isArray(paths)?paths:[...paths.values()];
 const capList=Array.isArray(caps)?caps:[];
 const context=ctx||{};
 const joined=context.joined===true,hasPeers=context.hasPeers===true;
 const platform=context.platform||'web',stunCount=(context.stunServers||[]).length;
 const capOf=mechanism=>capList.find(c=>c.mechanism===mechanism);
 const nativeReady=mechanism=>{const cap=capOf(mechanism);return !!cap&&['available','supported','experimental','ready'].includes(cap.status);};
 return methods.map(m=>{
  const mine=list.filter(p=>p.peerId===peerId&&(m.profile?p.mechanism==='webrtc'&&p.profile===m.profile:(m.mechanisms||[]).includes(p.mechanism)));
  const path=mine.find(p=>p.state==='direct'&&p.canMessage)||mine.find(p=>p.state==='direct')||mine.at(-1)||null;
  const row={order:m.order,id:m.id,title:m.title,explain:m.explain,worksWhen:m.worksWhen,commonFailure:m.commonFailure,badges:m.badges.slice(),chatCapable:!!m.chatCapable,path,state:STATUS.WAITING,detail:'',latencyMs:null,availabilityNote:''};
  const whenIdle=()=>joined?(hasPeers?'本机支持，正在排队等待开始尝试。':'服务器已连接，等待对方加入同一房间。'):'连接服务器后开始。';
  let fromPath=null;
  if(m.id==='observation'){
   if(!joined){row.state=STATUS.WAITING;row.detail='连接服务器后，随直连尝试一起观测；只观察地址，不传消息。';}
   else if(!stunCount){row.state=STATUS.UNSUPPORTED;row.detail='这个服务器没有给出 STUN 观测地址，看不到本机的外部地址形态；这只影响观测，不影响直连尝试。';}
   else if(list.some(p=>p.peerId===peerId&&p.mechanism==='webrtc'&&(p.gathering==='complete'||p.tuple))){
    row.state=STATUS.OBSERVED;row.detail='已经看到本机在外网眼中的地址形态。它不转发任何数据，也不是聊天路径。';
   }else{row.state=STATUS.TRYING;row.detail=hasPeers?'正在随浏览器收集地址进行观测，只观察出口、不传消息。':'还没开始收集地址；对方加入后随直连尝试一起观测。';}
  }else if(m.id==='gateway'){
   if(platform==='android'){row.state=STATUS.UNSUPPORTED;row.detail='安卓版不支持路由器放行；需要时请改用桌面 Python 版。';}
   else if(!(m.mechanisms||[]).some(nativeReady)){row.state=STATUS.UNSUPPORTED;const cap=(m.mechanisms||[]).map(capOf).find(Boolean);row.detail=`${reason(cap?.reason||'OPT_IN_GATEWAY_API_ONLY')}（默认关闭，只会在桌面 Python 版里经你明确同意后尝试；这个界面不会自动修改路由器）`;}
   else if(path){fromPath=pathState(path,row.chatCapable);}
   else{row.state=STATUS.WAITING;row.detail='需要在桌面版里明确同意后才会尝试；默认关闭。';}
  }else if(m.profile){
   if(!webRTC){row.state=STATUS.UNSUPPORTED;row.detail='这个浏览器或设备没有网页直连（WebRTC）能力。';}
   else if(path){fromPath=pathState(path,row.chatCapable);}
   else{row.detail=whenIdle();}
  }else{
   const ready=(m.mechanisms||[]).some(nativeReady);
   if(!ready){row.state=STATUS.UNSUPPORTED;const cap=(m.mechanisms||[]).map(capOf).find(Boolean);row.detail=`${reason(cap?.reason||'NATIVE_BRIDGE_UNAVAILABLE')}`;}
   else if(path){fromPath=pathState(path,row.chatCapable);}
   else{row.detail=whenIdle();}
  }
  if(fromPath){row.state=fromPath.state;row.detail=fromPath.detail;}
  if(path&&Number.isFinite(path.rttMs))row.latencyMs=path.rttMs;
  row.availability=AVAILABILITY[row.state];row.slug=SLUG[row.state];
  if(row.state===STATUS.TRYING)row.availabilityNote='（正在尝试，尚无结果）';
  else if(row.state===STATUS.WAITING&&joined)row.availabilityNote='（还没出结果）';
  return row;
 });
}
function screen(current,options){
 const o=options||{},list=(o.paths||[]).slice();
 if(list.some(p=>p.state==='direct'&&p.canMessage))return 'chat';
 if(!o.joined)return 'connect';
 if(current==='chat')return 'chat';
 return 'attempt';
}
function summary(rowsList){
 const rows=rowsList||[];
 return {
  remaining:rows.filter(r=>[STATUS.WAITING,STATUS.TRYING].includes(r.state)).map(r=>({id:r.id,title:r.title,state:r.state})),
  availability:rows.map(r=>({id:r.id,title:r.title,availability:r.availability,note:r.availabilityNote})),
  latency:rows.filter(r=>r.latencyMs!==null).map(r=>({id:r.id,title:r.title,latencyMs:r.latencyMs})),
  chatReady:rows.filter(r=>r.state===STATUS.DIRECT&&r.path?.canMessage).map(r=>({id:r.id,title:r.title,latencyMs:r.latencyMs}))
 };
}
root.P2PUX={STATUS,STATE_HELP,copy,methods,reasons,reason,labelFor,methodFor,canBench,rows,screen,summary,availabilityOf:state=>AVAILABILITY[state]};
if(typeof module!=='undefined')module.exports=root.P2PUX;
})(globalThis);
