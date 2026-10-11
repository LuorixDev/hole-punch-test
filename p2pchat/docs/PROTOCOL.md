# P2P Observatory 协作契约 v1

状态：**目标契约，不是实现完成声明**。基线于 2026-10-11 阅读；能力证据见 [CAPABILITIES](CAPABILITIES.md)，验收见 [ACCEPTANCE](ACCEPTANCE.md)。规范词“必须”是实现门槛；运行时不能执行须明确限制，但任务约定的实现缺失必须上报 captain，不能以 `unsupported`、mock、同机或接口存在代替通过。

勘误（t10）：仅校正 t2/t3 目录所有权、实验能力验收语义和已授权的中央诊断收集边界；既定 v1 消息与 adapter/native bridge 接口不变。

勘误（t16）：§2 的 join 改为**加入证明 v2**（§2.1），新增迁移矩阵（§2.2）与 `--allow-plaintext`（§2.3）；控制面其余帧、数据面 v1 hello/ACK、adapter/native bridge 接口与既有语义不变。变更文件与 sha256 见 §7。

## 1. 范围、所有权与安全边界

测试型聊天室，最多 12 人的小房间 mesh；各对端独立直连，不做好友/社交系统、离线消息服务、实时音视频或语音识别。录音是录制结束后的文件。控制面只做认证、发现、候选交换、诊断；STUN 只返回地址。Python Echo 是有明确 peerId 的真正接收终端，不是转发节点。TURN、HTTP/WebSocket 聊天/文件中继永久禁用；TLS/WSS 443 不是 TCP 打洞或数据回退路径。

默认 HTTP、STUN 和任何本地桥接只监听 loopback。用户已要求本产品将脱敏、白名单内的诊断元数据自动汇集到所配置中心，该功能已获授权，不需逐批另行确认。原始抓包、聊天正文采集或外部上传、研究数据外传、公网部署和网关映射不在此诊断授权内，分别需要相应授权；即使获其他授权，聊天正文也不得进入本产品日志或控制面。不能把 GitHub 上传授权视为部署或上传聊天/研究数据授权。公网控制面必须 TLS 和 origin allowlist。发现无直连则明确失败，绝不降级成服务器转发。

| Owner | 唯一写入区域 | 对外接口/责任 |
|---|---|---|
| server-engineer（t2） | `p2pchat/server.py`, `p2pchat/peer.py`, `p2pchat/tests/backend/`, `p2pchat/requirements.txt`, `p2pchat/tests/test_core.py` | v1 控制面、双栈 STUN、中心持久化、WebRTC echo、Python 数据帧及既有测试/依赖维护 |
| transport-engineer（t3） | `p2pchat/native/`, `p2pchat/tests/native/` | Python 原生传输、JSON-lines sidecar 入口、UDP/QUIC/TCP/映射的实际能力及负例 |
| client-engineer | `p2pchat/web/`, `p2pchat/tests/client/` | WebRTC adapter、共同 UI、数据消息、浏览器持久化、消费 native bridge |
| platform-engineer | `p2pchat/desktop/`, `p2pchat/android/`, `p2pchat/tools/`, `p2pchat/package*.json`, `p2pchat/capacitor.config.json`, `.github/workflows/` | Electron preload/main 安全桥接与 sidecar 生命周期、Capacitor 权限/封装、构建依赖与流水线 |
| architect（后续集成任务） | `p2pchat/docs/`；集成阶段才处理跨模块兼容 | 文档、接口冻结、明确冲突与协商；不并行改他人文件 |
| verifier/reviewer | 独立证据与审查，新增测试须先协调路径 | 不修改产品来让验证通过 |

`p2pchat/requirements.txt` 与 `p2pchat/tests/test_core.py` 当前明确由 server-engineer（t2）维护；其它成员需要依赖或基线测试变更时通知该 owner，不直接竞争写入。根 README 由 captain/集成者协调。`dist-web` 是 platform 的生成目录，不手改；`outputs/`、研究证据、秘密、聊天内容不进入源码上传。

## 2. 身份和认证

- `v:1` 必填于新协议。`clientSessionId` 为本地随机 UUID，会话日志队列跨重连保持不变；`peerId` 由中心为本次加入随机生成。显示名不是身份。
- `join` **v2**（默认，t16 起）：不再发送房间密钥。房间 ID ≤64、名称 ≤48、secret 8–256 字符（UI 推荐随机 ≥128 bit）。加入前先向服务器要一次性 nonce，再提交 HMAC 证明；服务器只保存/比较**派生值**，拿不到也还原不出原始 secret。详见 §2.1。
- `welcome {v,type,id,strictP2P:true,iceServers,profiles,limits}`；`roster {v,type,peers:[{id,name,capabilities}]}`。服务器覆盖 `from`，不接受客户端自报来源；只向同房间在线目标转发。
- `connectionId` 是一对 peer 的逻辑连接 UUID，由 peerId 字典序较小者生成并通过首个 offer 宣告。所有并行机制同一 connectionId；每机制/策略/重试各自新 `attemptId` UUID。尝试必须绑定 `(connectionId,attemptId,from,to,mechanism,profile)`，不得中途更换；两个发起者冲突时以字典序较小者为主并明确拒绝另一个 attempt。
- 新数据通道首先交换 `hello {v,kind,peer,connectionId,attemptId,nonce,proof}`。`proof` 是 HMAC-SHA256：UTF-8 JSON 紧凑数组 `["p2pobs-v1",room,connectionId,attemptId,senderPeerId,receiverPeerId,nonce]`，key 为 UTF-8 房间 secret，nonce 为新 32 字节随机数的 hex，proof为64小写hex。紧凑JSON不转义非ASCII、无空格，所有字段均字符串。返回 `hello-ack {v,kind,peer,connectionId,attemptId,nonce,echoNonce,proof}`：nonce为发送方自己的hello nonce，echoNonce为收到的对方hello nonce；proof覆盖数组 `["p2pobs-v1-ack",room,connectionId,attemptId,senderPeerId,receiverPeerId,nonce,echoNonce]`。收/发双方 proof、nonce、attempt 一致且双向 ACK 后才允许应用消息；每 attempt 的 nonce 只接受一次。常量时间比较，禁止把 proof/key/nonce 原文写日志。
- 这提供“知道房间共享密钥且来自已信任 WSS 信令所指对端”的配对，不提供恶意同房间成员之间的独立身份认证；共享密钥成员可冒充。**服务器不再接触原始房间密钥**（t16 起，见 §2.1）：它只保存由 secret 派生的加入验证值，无法用它伪造数据面配对证明。UI 不得宣称独立公钥身份或零信任服务器。WebRTC SDP DTLS 指纹必须由已认证信令绑定；QUIC/TCP TLS 指纹也须绑定同一 attempt，禁止无条件忽略证书。
- 路径 `direct` 判定：身份握手完成、双向挑战应答完成、实际端点非 relay；WebRTC 还要检查 selected pair。仅 ICE connected、socket connected、hello 字符串、探测包收到或中心可达都不算验证通过。

### 2.1 加入证明 v2：信令链路不再传输房间密钥（t16）

**问题**：旧 `join` 把房间 secret 原文交给服务器（`{"type":"join","secret":"..."}`）。该 secret 同时是端到端配对 HMAC 的密钥，所以（a）服务器本身能看到用户密钥，（b）任何明文/无 TLS 链路（HTTP 或 WS）上的观察者都能拿到**可复用**凭据。

**现在**：客户端用由 secret 派生的密钥，对服务器下发的随机数做 HMAC 证明。

```
客户端                                                        服务器
  |-- {v:1,type:"join_challenge",room,clientSessionId} ------>|  生成一次性 nonce(48 hex, TTL 30s)
  |<- {v:1,type:"join_challenge",nonce,expiresInMs, ----------|  绑定 room+clientSessionId
  |    proof:"hkdf-sha256-hmac-v2",roomEstablished:<bool>}    |
  |
  |  joinKey = HKDF-SHA256(ikm=secret, salt=room, info="p2pchat/join-key/v2")   (=32B hex)
  |  proof   = HMAC-SHA256(key=joinKey, msg=UTF8(room \0 nonce \0 clientSessionId))
  |
  |-- {v:1,type:"join",joinVersion:2,room,name,clientSessionId,capabilities,
  |    nonce,proof, verifier:joinKey(仅当 roomEstablished=false)} --------->| 常量时间比较校验 proof
  |<- welcome / error{AUTH_FAILED|UNSUPPORTED_VERSION|SCHEMA_INVALID|LIMIT_EXCEEDED} -------|
```

约束与不变量：

* **链路上没有房间密钥**：只有 HKDF 派生值（`verifier`，且只在房间还没有密钥时出现一次）与 nonce 绑定的证明。派生值不是数据面密钥，也无法反推 secret；拿到它最多能加入该房间的**信令**，不能伪造端到端配对证明。
* **服务器不接收、不存储原始 secret**：内存里只保留 `HMAC(salt, 'v2' \0 room \0 joinKey)` 形式的房间校验值与 `roomVerifierScope`；数据目录（`server.jsonl`、`events.sqlite3`）里既没有 secret，也没有 `verifier`/joinKey 原文（有测试断言）。
* **nonce 一次性且有时效**：取用即作废（重放同一 nonce 必然 `AUTH_FAILED`）；默认 30 秒过期；绑定 `(room, clientSessionId)`，换房间或换会话都失败；未决 nonce 总量与每来源下发速率都有上限。
* **校验失败语义不变**：仍是 `AUTH_FAILED`；缺字段/格式不对是 `SCHEMA_INVALID`。
* **HTTP/SSE 通道**同样先 `POST /signal/join/challenge` 取 nonce，再 `POST /signal/join` 提交证明；两条通道共用同一套校验代码。

**房间密钥只能在同一种协议内建立**：v1 房间（旧协议建立）与 v2 房间不能混用，跨协议加入一律 `AUTH_FAILED`（两者校验值含义不同，混用等于静默降级）。房间空掉时密钥随之释放（与既有行为一致）。

### 2.2 迁移与兼容矩阵（旧客户端 / 旧服务器）

| 客户端 | 新服务器（t16，v2 默认） | 旧服务器（只认 v1） |
|---|---|---|
| 新客户端：`peer.py`、`web/core.js` 的 `joinMessage()`（v2） | 正常加入 | `join_challenge` 不被识别 → 明确失败，**不会**退回明文密钥 |
| 旧客户端：仍发 `{"type":"join","secret":...}`（t16 时 `web/app.js` 与 `python_desktop` 尚未接线） | **本机来源（loopback）**：接受并记 WARNING；**其他来源**：`UNSUPPORTED_VERSION` + `hint:"JOIN_PROOF_V2_REQUIRED"` + 人话 `detail`；操作者可用 `--allow-legacy-join` 显式放开（临时逃生门，默认关） | 正常加入（旧行为） |

* **没有静默降级路径**：客户端只在拿到服务器 nonce 后才构造 v2 加入；nonce 缺失/不合法就报错，不会改用 v1 的明文密钥。
* **待接线**：`web/app.js` 的 `connect()` 与桌面端（`python_desktop`，后续任务）仍需改为「先 `joinChallengeMessage()` 再 `joinMessage()`」；`core.js` 已导出 `JOIN`/`joinKey`/`joinProof`/`joinChallengeMessage`/`joinMessage` 供接线。接线前这些客户端只能从服务器本机来源加入。
* **反向代理的坑**：旧协议兼容只看“来源是不是本机”——如果服务器前面有同机反向代理，远端旧客户端会看起来像 loopback。此时请用 `--deny-legacy-join`（对所有来源一律拒绝旧协议，含本机），不要让兼容判定替你决定。
* **回滚**：回到旧行为需要旧客户端 + 服务器侧 `--allow-legacy-join`；不推荐长期这样跑。

### 2.3 明文监听开关（`--allow-plaintext`）

* 默认行为不变：只要有非回环 `--host`，就必须同时提供 `--cert/--key` 与 `--origin`，否则拒绝启动。
* 只有操作者显式加 `--allow-plaintext` 才允许非回环明文监听；启动时必须打印醒目警告：

  > 警告：--allow-plaintext 已启用，信令未加密，链路可被观察/干扰；房间密钥不再在链路上传输。任何能看到这条链路的人都可以观察或干扰信令，请只在你有意为之的隔离网络里这样用。

* `--allow-plaintext` 不能替代 `--origin`（allowlist 仍必须配置），也不与 STUN/网关相关开关合并——它是独立开关，默认关闭，不存在隐式放开。
* 即使开了明文，房间密钥仍不上链路（§2.1 的不变量与链路上是否加密无关）。

## 3. 控制面帧

WS 文本 JSON ≤128 KiB；SDP ≤64 KiB；候选 ≤2 KiB、每 attempt ≤64；未知 type、未知顶层字段、跨房间、重放旧 attempt、relay 一律拒绝且记录枚举原因（不回显原文）。连接每秒最多80帧；房间12、中心总 peer256。二进制 WS 拒绝。SDP/ICE 是必要控制资料，不作为日志原文保存。

```json
{"v":1,"type":"signal","to":"peer-id","connectionId":"uuid","attemptId":"uuid","mechanism":"webrtc","profile":"ice-v6","description":{"type":"offer","sdp":"..."}}
```

- 一个 `signal` 必须恰有一种负载：`description`、`candidate`、`nativeCandidate`、`retry`。服务端转发时加可信 `from`，保留其他契约字段。
- `description {type:offer|answer,sdp}`；trickle `candidate {candidate,sdpMid,sdpMLineIndex}`；`candidate:null,endOfCandidates:true` 表示结束，不能与 description 混用。offer 前到达候选暂存 ≤64、10秒，超出丢弃并报原因；answer 只能用于对应未完成 offer。
- `mechanism` 枚举 `webrtc|udp-probe|quic|tcp|tcp-simopen|upnp|pcp|natpmp`。`ice-v6|ice-v4|ice-dual` 是 **同一 WebRTC 协议的候选地址族策略**，并非三个独立打洞算法；mDNS 隐藏地址为 unknown，不因 profile 名称断言实际 IPv6。
- `nativeCandidate {id,family:4|6,transport:udp|quic|tcp,address,port,kind:host|srflx|mapped,socketId,certificateFingerprint?}`。tuple 中 family/address/port/transport 均需验证；socketId 是进程内不透明 token，不是可由 UI 任意指定的 fd。仅配对的候选可被探测，不允许桥接任意网络扫描；拒绝 multicast/broadcast、port0、未协商的 link-local scope。`kind:relay` 禁止。
- `retry {previousAttemptId,reason}` 宣告新 attempt；网络切换、ICE restart、主动重试均生成新 attemptId，旧任务显式标为 superseded。只对失败 attempt 有界退避（1/2/4秒，最多3次），第一条成功不会取消其他尝试。可用机制并发启动，启动失败不阻止其他机制，所有 terminal reason 可见。
- `ping/pong` 仅信令存活；其 RTT 不可作为 P2P RTT。
- `error {v,type,code,connectionId?,attemptId?}` 使用稳定错误码（如 `AUTH_FAILED`, `RELAY_FORBIDDEN`, `LIMIT_EXCEEDED`, `UNSUPPORTED_VERSION`），不得带任意正文。
- 基线 v0 使用 `attempt`、无 v/connectionId；兼容层如保留必须显式标 `legacy-unverified`，不能通过 v1 认证门槛。四模块新开发以 v1 字段为准；迁移可接受 `attempt` 别名但不能悄悄丢失 connectionId。

## 4. 统一 adapter 与 native bridge（冻结边界）

共同 UI 使用异步 adapter，WebRTC 由 client 实现，native 由 transport + platform 实现：

```text
capabilities() -> {v:1, methods:[{mechanism,status,canMessage,reason,limits}]}
start({connectionId,attemptId,peerId,mechanism,profile,role,timeoutMs,auth:{room,localPeerId,secret}}) -> {attemptId}
signal({connectionId,attemptId,from,description?|candidate?|nativeCandidate?}) -> void
send({attemptId,lane:"chat"|"benchmark",data:Uint8Array}) -> {queuedBytes}
stats({attemptId}) -> PathStats
close({attemptId,reason}) -> void
subscribe(handler) -> unsubscribe
```

`auth` 仅经受控本地IPC/stdio传入adapter内存，用于本次握手，禁止持久化/日志/stdout事件/控制面signal传播，close时释放；不允许native start自行读取用户任意文件。WebRTC adapter与native adapter均负责握手并仅向UI交付已认证应用帧，UI不额外伪造auth-success。事件是 `candidate|state|data|diagnostic`，均带 connectionId/attemptId；`data` 只通过本地桥/直连送 UI，绝不送中心。PathStats 含 state、mechanism、actual family/protocol/candidate types、可观测 tuple、rttMs、tx/rxBytes、goodput、observability 与 failureCode；unknown 数值用 null，不用 0 冒充。state：`unsupported,gathering,probing,authenticating,direct,failed,timeout,closed`。

### 可执行桥接所有者与测试

1. transport-engineer 提供 `python -m p2pchat.native.bridge`，标准输入输出逐行 JSON RPC：请求 `{v:1,id,method,params}`；响应 `{v:1,id,result}` 或 `{v:1,id,error:{code,message}}`；事件 `{v:1,event,params}`。方法名与上述 adapter 一致（subscribe 是本地订阅事件，无远端 RPC）；stdout 仅协议，诊断写 stderr 且脱敏。二进制 send/data 以 `dataB64` 表示，单帧解码上限64 KiB，RPC行上限128 KiB。必须提供可在 subprocess 测试的 `capabilities` 和 unsupported 行为。
2. platform-engineer 提供 renderer `window.p2pNative`：`invoke(method,params):Promise`、`onEvent(callback):unsubscribe`；Electron preload contextBridge 固定 allowlist，main 启动一个受控 sidecar，stdio 转发，禁止 renderer 执行命令或选择可执行文件。配置只由 main 读取用户确认的 Python 路径；无 Python/依赖时能力 unavailable，UI 仍可 WebRTC，不伪造 native 成功。IPC 只接受应用本地 frame，远端页面无法访问。
3. client-engineer 实现 bridge wrapper，把 dataB64 变 Uint8Array；启动前查询 capabilities，仅 `canMessage:true` 且 `direct` 的路径可选为聊天路径。桥不存在/返回 unsupported 时展示原生功能不可用，不隐藏或打绿勾。fixture 只供单元测试并标 mock，不能用于发布能力证明。
4. Android Capacitor 默认仅 WebRTC；不把宿主 Linux Python 当 Android 原生能力。platform 如实现 Capacitor 插件同样暴露 `window.p2pNative` facade，否则显式 unavailable。Android Kotlin 原生协议属于后续单独范围，当前不能承诺 Python sidecar 移植。
5. bridge 测试：transport 验 stdio ID/顺序/无效输入/退出清理；platform 验 IPC 来源/allowlist/超时/sidecar崩溃；client 验事件归属和 unsupported UI；集成验一次真实端到端 native 数据往返，否则该机制仅实验。

UDP 精确 tuple 双向探测本身 `canMessage:false`，必须用 HMAC+nonce、单调计时、有界重试拒绝伪造/单向假阳性；不把明文裸 UDP 当安全可靠聊天。QUIC 必须复用同一已探测 UDP socket/映射及认证的证书；若库做不到必须 `unsupported_same_socket`，新 socket QUIC 直连不得冒称保持打洞映射。TCP 直连和 simultaneous open 分开报告；后者必须有真正同 tuple bind/connect 证据，普通监听连接不是 simultaneous open。映射机制只是候选来源，UI 记录 mapping + 实际承载，不能将映射成功等同数据成功。

## 5. 数据面、分块与限额

所有应用帧仅在认证后的可靠有序数据通道上。JSON control ≤64 KiB，text UTF-8 ≤16 KiB；data lane chat/benchmark 必须独立队列（WebRTC 独立 DataChannel、QUIC 独立 stream；TCP 无可靠隔离时测速禁用或明确 busy，不能阻塞聊天）。transport send 必须背压，不能无限缓存。

- 文本 `{v:1,kind:"text",id,text,echoOf?}`，接收验证后 `delivered {id}`；发送态 queued/sent/delivered 分开。去重以 `(remotePeerId,id)`，TTL10分钟、最多10000项，重复包重新 ACK 不重复显示。
- `file-start {v:1,kind,id,name,mime,size,sha256,echoOf?,benchmark:false}`；文件/图片/录音共用协议。name ≤255，仅展示不直接拼路径；mime ≤128 不可信，不能执行 HTML/SVG。size 整数0..32MiB；sha256 为64小写hex。
- 二进制 v1 块：`u16be id字节数 | UTF8 id | u32be sequence | payload`；id≤100字节，payload≤16384字节，sequence从0递增。接收必须拒绝跳号、重号、未知ID、越界，不把 v0 缺失序号帧解释为 v1。
- `file-ready {id,ok,reason?}` 后才发块；每16块或250ms发 `file-progress {id,nextSequence,receivedBytes}`，仅显示进度，不等于完成。`file-end {id}` 后校验实际大小和 SHA-256，`file-ack {id,ok,bytes,sha256,elapsedMs}`。发送方检查 ACK 归属 attempt、ID、大小、hash 才报告成功。块内重传不是当前保证；断路取消并用新ID重发，不能 silently resume。
- 单进程最多8个活动接收、所有活动接收预留总额64MiB（不能8×32MiB不受控）；发送并发每peer2、全局4。超过限额先拒绝。buffer高水位512KiB、低水位128KiB；等待不能忙循环且关闭可立即中断。file-ready/最终ack超时60秒、无进展30秒，取消释放接收缓存、计时器、对象 URL 和 ACK map。
- benchmark 专用 `bench-start/chunk/end/ack`，上限每轮32MiB；时长不再用固定硬窗口，改为**进度型空闲窗口**：空闲 20 秒即超时，发起方可协商 `drainMs`（≤60 秒，窗口取 max(20, drain+5)），另设 300 秒硬顶兜底；桌面端当前宣告 drainMs=10000，因此 12–15 秒的长轮次也能正常拿到 bench-ack。失败必须发 `bench-error{code}` 与 `task.error` 诊断事件、不得静默关通道；对端沉默仍报 ACK_TIMEOUT 且不伪造速率。默认一条测速任务；不能沿用 file 的免 hash 标记绕过文件完整性。统计有效接收 ACK bytes / 单调 elapsed，注明 application goodput，不冒充线路带宽。probe RTT 用本地单调 nonce 往返，不用两个设备墙钟相减。发现与测速分别按钮，默认聊天可用才自动选首路，但不取消其余发现；切换路径不能把正在传文件移到另一个 attempt。
- Echo 只在自己的 direct channel 上回复来源 peer，不向房间广播、不替 A 转发 B。echoOf 缺失且 payload 完整验证才回声一次，回复新 id+原 id 为 echoOf；带 echoOf 的帧不再回声，benchmark/hello/ACK 不回声。至少两只 echo bot 相连也不能形成循环。

## 6. 可关联诊断与持久化

事件白名单模式（任意 `data` 对象不是契约），本地和中心共享以下 envelope：

```json
{"v":1,"id":"uuid","clientSessionId":"uuid","seq":1,"tsWallMs":1791699000000,"monoMs":100.5,"connectionId":"uuid-or-null","attemptId":"uuid-or-null","event":"path.state","data":{"state":"probing","mechanism":"webrtc","family":6,"reason":null}}
```

`tsWallMs` 仅关联，`monoMs` 仅同一进程排序/耗时；服务端添加 `receivedAtMs`、可信 peerId。每类 data 只接收必要字段：状态/枚举失败码/计数/时长/消息随机ID/协议类型/地址族/候选类型。地址默认按本地日志 salt HMAC 得到 endpointTag，端口仅必要时保留；原始地址仅本地显式诊断授权，导出再次脱敏。房间/名字、SDP、candidate原文、ICE密码、token、密钥、proof、正文、完整文件、base64、文件名与 MIME任意字符串禁止中心日志。文件 SHA-256 只留本地完整性显示，中心默认仅 integrityOk（低熵内容 hash 也可泄漏）。UA 不上传完整字符串。禁止通过 telemetry 夹带正文、借中心回放作消息通道；服务端不得把遥测转发给 peer。

`telemetry {v:1,type,clientSessionId,events:[...]}`：≤30事件/批，每事件≤2KiB，≤2批/秒；`telemetry_ack {v:1,type,clientSessionId,ids:[...]}` 只在已持久化后 ACK。中心去重键 `(roomVerifierScope,clientSessionId,id)`，不依赖会改变的 peerId；同key不同内容拒绝 `EVENT_CONFLICT`，不可静默覆盖。只删除匹配 session 的已 ACK 本地待传事件。断线/重启从持久队列补传，退避1..30秒；不能无限 spawn 上传任务。

浏览器 IndexedDB；Python/sidecar SQLite；Electron用应用私有数据目录；Android使用 WebView持久化（清理/卸载会丢失，UI注明）。本地日志总额20MiB/7天，待传上限2000条；中心默认100MiB/7天并有数据库/WAL与JSONL轮转策略。超额淘汰最旧诊断并记录 droppedCount，不删除聊天内容因为日志从不存聊天。时间/磁盘/批量计数都有测试；日志自身故障不能造成消息改走服务器。用户本地导出是单独操作，不等于允许向GitHub等外部目的地上传；不影响已获授权的本产品脱敏诊断自动集中收集。

可观测性：WebRTC 只声称 getStats 暴露的 selected pair/字节/RTT；浏览器通常看不到 IP头、TCP flags、原始 STUN事务/重传包、真实外网线路 MTU，字段使用 `null` + `unavailableReason`。aiortc 缺 selected-pair API 时不得编造。pcap 如额外获授权仅本地保存、人工脱敏、不进 GitHub；未抓到的包不补造。

## 7. 本次变更（t16）：加入证明 v2 与显式明文开关

| 文件 | 说明 | sha256 |
|---|---|---|
| `p2pchat/server.py` | 新增 join_challenge + v2 加入校验（HKDF 派生值 + nonce HMAC、一次性/有时效/绑定房间与会话）、房间密钥按协议版本区分、旧协议来源策略（本机兼容 / `--allow-legacy-join` / `--deny-legacy-join`）、`--allow-plaintext` 与醒目警告、错误帧新增 `hint`/`detail` | `16e2d88c05089330cec03ebaf1a8824aa526a5a9c688846c78ccc8f153383204` |
| `p2pchat/peer.py` | Python peer 改用 v2 加入（`derive_join_key`/`join_proof`/`join_v2`），不再发送房间密钥 | `f7ab45c0626f7260b33c80eff2ca334421e0f951fc54a26e0f67729355b2f74c` |
| `p2pchat/web/core.js` | 导出 `JOIN`/`joinKey`/`joinProof`/`joinChallengeMessage`/`joinMessage`（WebCrypto HKDF+HMAC，与 Python 实现同值，有 node 测试交叉核对） | `602b9f5230746cf5f9d9d30c37d67e4b1761dec9981fd4d722c8f8fae960733a` |
| `p2pchat/tests/backend/test_join_proof.py` | 19 项：正例/错密钥/重放/过期/缺失/伪造/绑定/服务器不含原始密钥/旧协议策略/无静默降级/明文开关 | `4ddfca7970e1facb424758d3ff7021865b174b5976cfaea67ea73f385801e8a1` |
| `p2pchat/tests/client/joinproof.test.cjs` | 5 项：派生值与独立 HKDF 实现一致、报文不含 secret、无 nonce 时不构造证明 | `65f7a7e014ec7eef7f2678792b4911f81d8a9137d7c394968fd43e0dc4397cba` |
| `p2pchat/docs/PROTOCOL.md` | 本文档（§2 加入报文、§2.1/2.2/2.3 安全与迁移说明、本节） | 见交付报告（自引用会使哈希失效） |

复现命令：

```bash
.venv/bin/python -m pytest p2pchat/tests/backend/test_join_proof.py -q   # 19 passed
.venv/bin/python -m pytest p2pchat/tests/backend -q                      # 183 passed
node --test p2pchat/tests/client                                         # 47 passed
```

尚未接线的客户端：`web/app.js`（`connect()` 仍发旧 join）与 `python_desktop`（后续任务）。接线前它们只能从服务器本机来源加入——这是有意的明确失败，不是静默降级。
