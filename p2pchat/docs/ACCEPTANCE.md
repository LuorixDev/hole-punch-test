# 验收计划与证据边界

目标契约见 [PROTOCOL](PROTOCOL.md)，基线/平台现状见 [CAPABILITIES](CAPABILITIES.md)。本文件定义通过条件，**不表示这些测试已运行**。目前唯一重跑证据为 `test_core.py` 四项通过（同机同进程），不能代替下列验收。

## 1. 分层报告，禁止混淆

每条结果记录 caseId、git commit、平台/版本、测试命令、开始时间、拓扑、实际输出/退出码、PASS/FAIL/NOT_RUN/UNSUPPORTED、限制。源码可交付不等于全平台验证；实现存在但没有设备/权限时写NOT_RUN与原因；平台确实不支持时写UNSUPPORTED及限制证据；尚未实现单列实现缺口，不能借NOT_RUN/UNSUPPORTED掩盖。桌面/Python 已约定的真实 socket 实现要求不因此豁免，无法完成须向 captain 上报并讨论，不得以 unavailable 占位完成 t3。

| 层级 | 环境 | 可证明 | 不可证明 |
|---|---|---|---|
| L0 | 单元/fixture/mock | 编解码、状态机、负例 | 真实网络、封装可用 |
| L1 | 同机独立OS进程（hub、A、B/echo） | 真实socket/进程隔离、应用互通 | 家宽穿透、平台实机 |
| L2 | 独立netns/容器，双NAT或v6 stateful隔离 | 可控防火墙/NAT条件下可复现行为 | 真实路由器/运营商或手机 |
| L3 | 两个独立设备与两条真实网络 | 此设备/网络组合现场互通 | 任意网络必通 |
| B | Linux/Windows/Android产物构建 | 可重复编译、包内容 | 启动、权限、网络、实机通过 |

需要root/netns/抓包、公网部署、真实网关变更而未获得授权时，不自行提权或修改真实网络；在隔离拓扑或明确NOT_RUN后继续源码交付。基础依赖安装授权不能替代这些授权。

## 2. 控制面与严格P2P

| ID | 动作/故障 | 通过条件 |
|---|---|---|
| SIG-01 | 不带v、未知v、未知type/字段、binary WS、超长SDP/候选/速率 | 明确拒绝/有界错误；不能进入数据转发 |
| AUTH-01 | 错room key、跨房间target、自报from、错peerId/attempt/connectionId | 认证/绑定失败；无数据渲染，无错误内容日志 |
| AUTH-02 | hello错HMAC/key、nonce重放、ACK错nonce、只单向验证、旧attempt信号注入 | 不进入direct；失败原因可见；不能用open/connected冒充认证 |
| RELAY-01 | turn/turns配置、SDP/trickle relay candidate、selected-pair relay注入 | 每层拒绝，关闭不安全路径，不能静默接受 |
| SIG-02 | offer前ICE、重复answer、旧retry、不同from使用相同attempt | 有界缓存、拒绝混淆；合法乱序能成功 |
| DATA-01 | A↔B已认证后断开hub进程或阻断WS端口，继续文本/文件60秒 | 真实数据继续，ACK/hash匹配；不能被roster leave无条件关闭；状态显示信令离线 |
| DATA-02 | 阻断A↔B而保持hub/STUN可达 | 数据失败，服务器不代发；可从数据字节数与负例确认无假阳性 |
| LEAK-01 | telemetry含text/content/base64/嵌套任意键/SDP/secret；未知字段注入 | schema拒绝或字段移除，中心无正文、文件、名字/secret；不向peer广播遥测 |

DATA-01 的断信令不等于用户主动“离开并关闭全部路径”，两者必须区分。运行L1时三个独立子进程，记录PID及连接角色；不使用同一事件循环两个Peer冒称独立进程。

## 3. 网络机制与可控拓扑

- **NET-v4**：A在NAT-A后、B在NAT-B后，STUN/信令在第三命名空间；防火墙不允许默认外部直入。分别测endpoint-independent mapping/filter、address/port dependent filtering、对称映射、UDP blocked。记录预设规则与实际tuple；失败是有效观测，不能要求每类NAT必成功。IPv4 LAN/public host另测，不能混为穿透。
- **NET-v6**：A/B不同v6子网，各自stateful firewall默认丢未建立入站；允许出站，验证双向探测/ICE后路径；另测完全入站禁用与单向丢包。明确不是“有IPv6便无需打洞/防火墙问题”。
- **STUN-01**：UDP v4/v6真实socket，transaction/地址/port XOR解码一致；畸形/超长/错magic、响应源不符、transaction不符被拒绝；资源限额/反射率受控。函数编码测试仅L0。
- **UDP-01**：双端对信令约定的精确tuple，HMAC+随机nonce双向挑战ACK，错源、错key、旧包、只单向收包都不能direct；限制包率、重试时长及尝试数。probe-only不能选为聊天路径。
- **QUIC-01**：观察同socket的local port/socketId、STUN mapped tuple及QUIC握手，验证消息ACK与证书指纹；重建socket的普通QUIC不能通过“同socket”项。
- **TCP-01**：普通直连与simultaneous open分开case；后者须双端主动绑定同tuple并发connect（必要时授权抓包验证SYN轨迹），不能仅凭接口名通过。
- **MAP-01**：UPnP IGD v4、UPnP v6 pinhole、PCP、NAT-PMP分别验证；默认无发现/映射副作用，显式opt-in后创建、租期续租、失败、过期/退出删除；只删除本session持有映射。模拟网关仅L0，不等于真实路由器兼容。

所有路径记录 mechanism 和实际候选类型/地址族；`ice-v6/v4/dual` 是WebRTC策略而非三协议。selected pair不可见时标unknown/limited，不编造抓包、prflx或端口。第三方STUN与中心不可达的失败亦要显示。

## 4. 并行、测速、消息与回声

| ID | 测试 | 通过条件 |
|---|---|---|
| PAR-01 | 所有可用机制注入不同延迟，一路很快成功、另一路稍后成功 | 同时启动；首路成功不取消其余；所有attempt最终状态可见 |
| PAR-02 | 不支持native、无v6、一个adapter抛异常 | 明确unsupported/failure；其它可用路径继续，不用无功能占位成功 |
| BENCH-01 | 不测速只发现，再点独立测速；测速中发送文本/取消测速 | 无自动大流量；chat与benchmark独立lane/队列；文本仍可ACK；取消不关闭聊天 |
| BENCH-02 | 注入延迟/丢包/错误ACK/重放ACK、0字节及超时 | 使用有效接收ACK bytes和本机单调elapsed；测速不混入文件/聊天统计；错误ACK不报告吞吐成功 |
| FILE-01 | 0B、1B、16KiB边界、32MiB、超32MiB、图片/录音/普通二进制 | size/hash双端匹配才delivered；超限在分配大内存前拒绝 |
| FILE-02 | 重号/跳号块、未知transfer、越界、错hash、duplicate start、ACK归属错误 | 拒绝/失败并释放资源，无下载成功提示，无跨attempt混淆 |
| FILE-03 | 中途断路、等待ready/ACK超时、切换活动路径 | 超时清理；文件不静默换route；新尝试新ID，全局64MiB预留上限有效 |
| ECHO-01 | A→echo文本/图片/文件/录音；echo与另一echo连接 | 回到原peer/同direct数据路，内容与hash一致；新id+echoOf，一次而已 |
| ECHO-02 | 明确发送带echoOf帧、重复原帧、benchmark/ACK帧 | 观察至少两倍最大回复等待窗口并计数：无二次回声，无循环放大，不跨peer转发 |
| TEXT-01 | Unicode边界、超16KiB、重复ID、不同peer相同ID | UTF-8字节限额，去重带peer作用域，重传ACK且不重复渲染 |

测速结果写明应用层goodput、方向、bytes、elapsed、是否与其它数据竞争；不把信令ping或两个设备墙钟差当P2P RTT。WebRTC共享底层拥塞可能影响聊天，UI需注明，独立lane不等于物理链路独占。

## 5. 日志、资源与恶意输入

1. 用户已授权本产品脱敏诊断元数据自动集中收集，验收应实际验证该功能，不以“未获日志上传授权”跳过。原始pcap、聊天正文、外部目的地上传或研究证据外传不属于该授权；聊天正文始终不得进入日志。日志事件带稳定id/clientSessionId/seq、connectionId/attemptId和Wall/mono时间。跨客户端可关联，中心 receivedAt 不是客户端真实发生时刻；重启mono时间重置不跨session相减。
2. 断线生成事件→退出重启→重连补传→ACK丢失重复上传。中心去重同一事件只一条；换peerId仍去重；ACK仅在持久化成功后；同ID不同内容拒绝。
3. 超过本地20MiB/2000 pending/7天和中心100MiB/7天，SQLite/WAL/JSONL均受控；淘汰计数可见。磁盘满/权限拒绝时错误可见、重试有界、不丢进程控制、不将聊天改走服务器。
4. 日志正文扫描已知测试secret/文本/文件样本/base64/SDP/原始IP；不能仅验证几个敏感key。自由错误字符串也要清洗，不能回显恶意输入。sha256默认不进中心。
5. 恶意候选、未知RPC、128KiB超长桥接、异常base64、ACK flood、候选数>64、反复重试、并发32MiB文件，验证任务/队列/内存/FD/CPU有界；关闭后无悬挂socket/tasks/objectURL。
6. 对packet字段无观测能力返回null+unavailableReason，测试禁止构造虚假的IP头、flags/sequence/MTU/重传信息用于UI绿灯。

## 6. 平台、桥接与移动生命周期

- transport stdio 与 Electron IPC独立合约测试；native无依赖/不可执行/崩溃/协议版本错时fallback仅为WebRTC候选能力，不是消息中继；界面显示原因。
- 检查Electron contextIsolation、sandbox、nodeIntegration false、IPC来源白名单、外链阻断、路径/命令不可由renderer控制。应用本地页面才可请求麦克风；非录音时不采集。
- Linux实际启动、最小窗口、文件选择/拖放（若提供）、录音权限与播放/下载测试。Windows Actions构建与Windows实机分开标记。Android APK构建与真机安装分开；SDK缺失则NOT_RUN，不宣称APK已测。
- Android拒绝/撤销麦克风权限、60秒录音上限、锁屏/后台/系统回收、Wi-Fi↔蜂窝切换、IPv4↔IPv6变化：后台不保证保持socket，必须显示暂停/断开并在恢复生成新attempt；旧ACK不污染新session。录音结束/取消立即停止track。
- 无真实Android/Windows设备、真实公网两端或已授权网关时，**明确未验证**；可继续可复现源码/构建交付，但最终报告不得用“全平台均可用/全部穿透成功”。

## 7. 发布门槛与证据保管

核心发布必须：无relay/无日志正文通道、可复现L1独立进程认证直连文本+文件+echo、严格负例通过、现有四项回归、接口/schema同步、资源上限与日志补传测试。发现安全阻断项则修复后重新验证，不以“实验”豁免泄漏或身份绕过。高级机制尚未实现必须在能力表列实现缺口且不在UI冒充可用路径；若属于已约定的桌面/Python实现范围，须完成真实实现或上报 captain 讨论范围调整，不能仅以unsupported完成验收。Android当前原生范围缺口与平台确实不支持须分别说明，不能泛化为其它平台豁免。

Windows/Android构建或L2/L3条件不足不阻止源码交付，但发行状态必须限制为相应已验证层级。每个产物记录构建commit、命令、工具链、校验值与是否启动测试。依赖漏洞审计记录风险与处理，不盲目升级破坏锁文件。

GitHub仅审核后的源码/配置/测试与无敏感数据的构建产物；不传运行data/log/pcap/证书/room secret/聊天数据/研究证据。自动产物、日志export和公网deploy权限分开；默认部署loopback，绝不因CI成功自动部署公网或打开网关。证据目录与发布清单由集成任务另定，当前需求任务不写outputs。
