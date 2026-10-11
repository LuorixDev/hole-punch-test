# 平台与机制支持矩阵

这是 **2026-10-11 原型基线 + 本轮目标边界**，不是发布已完成清单。实现完成后必须附独立验证证据更新状态。共同契约见 [PROTOCOL](PROTOCOL.md)，测试等级见 [ACCEPTANCE](ACCEPTANCE.md)。

## Round 2 更新

R1–R4实现修复详见 [REPAIR-ROUND2](REPAIR-ROUND2.md)：有界块对象/空块拒绝；native多可信候选同socket调度、受控STUN桌面授权入口；真实QUIC应用bench bytes/ACK；移动pause/resume/切网实现及模拟回归。仍不声称Android/Windows实机或真实家宽验证。旧t6哈希已被新SOURCE-MANIFEST替代，不能以旧审查结果当修复后证据。

## t6 历史集成状态

2026-10-11：四模块已实现并在Linux进行局部真实集成；完整证据和运行方法见 [INTEGRATION](INTEGRATION.md)。下方P/E矩阵保留为t1历史快照，不应读作当前尚无实现。

| 方法 | Linux浏览器 | Linux桌面/Python native | Windows | Android |
|---|---|---|---|---|
| WebRTC IPv4 host / DataChannel | 真实Chromium↔独立Python echo通过（本机） | Python独立进程通过；Electron包启动证据单列 | 源码+构建配置，实机NOT_RUN | 源码+Capacitor工程，编译/实机NOT_RUN |
| WebRTC IPv6 host | 实际无成功v6路径，超时可见 | STUN/原生v6 socket测试通过，不替代WebRTC v6 | NOT_RUN | NOT_RUN |
| STUN srflx | 配置实现；真实NAT NOT_RUN | 双栈STUN socket测试通过，公网NAT NOT_RUN | NOT_RUN | NOT_RUN |
| prflx/triggered ICE | 引擎能力，具体路径未证实 | 同左 | NOT_RUN | NOT_RUN |
| UDP精确tuple探测 | 无原生API | 真双向认证socket测试v4/v6通过，probe不可聊天 | 源码未实机 | 未实现原生 |
| QUIC同socket | 无原生API | 实现；双Python stdio+JS桥真实双lane完整性通过 | 源码未实机 | 未实现原生 |
| TCP直连 | 无原生API | mutual TLS socket测试v4/v6通过 | 源码未实机 | 未实现原生 |
| TCP simultaneous open | 无原生API | 真bind/connect实现，t3双netns正例；同机可明确失败 | 源码未实机 | 未实现原生 |
| UPnP IGD / IPv6 pinhole / PCP / NAT-PMP | 无原生API | Python显式opt-in API实现/模拟网关测试；真实网关NOT_RUN；桥/UI授权入口未实现 | 源码未实机 | 未实现原生 |

重要限制：网关映射桥返回 `OPT_IN_GATEWAY_API_ONLY`，入口是 [gateway.py](../native/gateway.py) 的显式 opt-in API，而不是客户端可点即用；不得把模拟网关成功当真实路由器兼容。Python Echo只广告WebRTC，原生QUIC/TCP互通需两端native客户端，不宣称所有机制支持Python Echo。Electron默认原生绑定loopback，可通过“原生网络绑定”菜单经确认选择本机接口；跨主机原生/家宽证据仍NOT_RUN。Windows/Android麦克风、移动后台、网络切换和真实NAT全部NOT_RUN，不能被Linux浏览器结果替代。

本轮修复早到ACK、信令离线直连保留、503重连异常、自动集中诊断默认开启与明确暂停/丢弃提示、高ID有界重试终态。v1消息字段未变。浏览器已实际录音发送并获得回声/完整性ACK，播放进度可见；音源硬件身份/人声质量未验证，媒体原件不进入仓库。

## 状态含义（t1基线）

- **P/U**：源码路径存在（prototype），目标平台/网络未经验证；不是“可用保证”。
- **P/L**：有原型且本机测试覆盖部分功能（local），绝不是公网、真实 NAT 或平台实机通过。
- **E/U**：本轮实验目标在原型基线尚未实现、未验证；不是允许用 unsupported 占位完成任务。交付时必须分别记录实现状态与测试状态。
- **N/U**：本轮不提供原生能力（浏览器API限制或Android当前明确范围缺口）；运行时返回 unsupported，而非永久不可实现，也不表示所有平台的同一机制都可免做。
- **engine/U**：ICE引擎可能支持，不由应用单独实现或保证；必须以实际候选/抓包证据确认。

## 每个平台逐项矩阵（基线）

| 机制/路径 | Linux浏览器 | Linux Electron | Windows Electron | Android Capacitor | Python Linux peer | 实现/测试限制 |
|---|---|---|---|---|---|---|
| IPv6 host | P/U | P/U | P/U | P/U | P/L | ICE候选过滤存在；本机测试未强制v6路径成功，stateful防火墙/公网未验 |
| IPv4 LAN/public host | P/U | P/U | P/U | P/U | P/L | 本地两Peer存在可用通道，未证明独立LAN主机/公网host |
| STUN srflx | P/U | P/U | P/U | P/U | P/U | 浏览器/aiortc STUN配置和Python Binding编码存在；函数级v4/v6编码通过，不等于网络穿透通过 |
| prflx / triggered ICE checks | engine/U | engine/U | engine/U | engine/U | engine/U | 引擎内ICE机制；非独立协议；浏览器不暴露时记不可观测 |
| WebRTC DataChannel (DTLS/SCTP) | P/U | P/U | P/U | P/U | P/L | Python同进程实例文本/文件回声通过；其余平台无实机互通证据 |
| 原生UDP精确tuple双向探测 | N/U | E/U | E/U | N/U | E/U | Python sidecar为桌面实验目标，浏览器无任意UDP socket；probe不是安全可靠聊天 |
| QUIC同UDP socket接续 | N/U | E/U | E/U | N/U | E/U | 必须证明探测/STUN/QUIC复用socket；aioquic已安装不等于实现 |
| TCP直连 | N/U | E/U | E/U | N/U | E/U | 真实端点listener/connect及身份验证；Windows防火墙待验证 |
| TCP simultaneous open | N/U | E/U | E/U | N/U | E/U | OS/NAT依赖；必须实际同tuple双端active-open，普通TCP直连不得冒充 |
| UPnP IGD IPv4映射 | N/U | E/U | E/U | N/U | E/U | 用户明确opt-in，路由器兼容/授权/到期清理未验；不是打洞算法 |
| UPnP IPv6 firewall pinhole | N/U | E/U | E/U | N/U | E/U | 与IPv4端口映射分开；服务支持受限，不能用IGD成功推断 |
| PCP | N/U | E/U | E/U | N/U | E/U | 需要网关支持，映射生命周期/nonce/撤销测试；非STUN变种 |
| NAT-PMP | N/U | E/U | E/U | N/U | E/U | 主要IPv4，网关支持受限；不同于PCP，拒绝猜测路由器支持 |
| TURN / 信令聊天中继 | 禁用 | 禁用 | 禁用 | 禁用 | 禁用 | 配置、候选、选中pair、服务端消息类型各层拒绝 |

E/U 不承诺每个真实网络都能成功，但不降低 t3 的真实 socket 实现要求。桌面/Python 已约定方法必须真实实现并提供对应测试；无法完成须向 captain 上报具体阻断与拟议范围调整，未获明确调整不能仅返回 unavailable/unsupported 就完成任务。交付状态必须区分：**平台确实不支持**（说明API/OS限制，运行时unsupported）、**实现存在但环境不能测**（NOT_RUN并列缺少设备/授权/拓扑条件）、**尚未实现**（实现缺口，不能冒充前两者）。Android 原生仍是当前显式范围缺口，不能当作桌面方法的豁免。普通公网 QUIC 直连若实现，可单列实验项，不能冒称已完成“同 socket 打洞”。网关映射是另一种机制；成功只证明产生候选，仍需双向P2P握手。

## 平台交付策略

- **Linux**：优先可复现 Python server/echo/native CLI + 浏览器；Electron 封装走同一 web。Python 3.12 .venv 已存在，aiohttp/aiortc/aioquic/pytest 已可导入并运行基线。
- **Windows**：Electron便携包是构建目标，原生功能需兼容Python sidecar/可分发运行时。若未打包runtime则明确安装Python依赖及路径配置，不能交付“原生已内置”假象。Actions 构建成功≠Windows桌面启动、麦克风、网络/防火墙实测。
- **Android**：Capacitor WebView + WebRTC 是务实目标，录音权限和HTTPS要求明确；Python sidecar不适用，native机制默认unsupported。Java25已知，Android SDK待确认；根据Android Gradle Plugin实际需求选CI JDK，不能假设Java25兼容。存在Flutter目录不代表项目已移植Flutter，不在本轮混入第二套UI。
- **浏览器**：受限于WebRTC/MediaRecorder/IndexedDB/安全上下文权限；没有原生UDP/TCP/网关API。IPv6 mDNS候选或stats隐去地址显示unknown，不按profile命名推断。
- npm install已完成，报告10个漏洞（8 moderate、2 high）；Electron postinstall此前未执行。platform-engineer必须验证Electron可执行文件、锁版本与审计影响，不可把node_modules存在当构建通过。此计数为输入快照，最终需重新审计并记录。
- GitHub 私有仓库 `LuorixDev/hole-punch-test` 与 Actions Windows 等构建获授权；只上传审核后的源码/构建配置，不上传 `.venv`、依赖目录、秘密、data、日志、pcap、研究证据或聊天数据。capture/upload/deploy 三种权限独立；此处外部上传限制不影响用户已要求并授权的本产品脱敏诊断元数据自动汇集到所配置中心，原始pcap、聊天正文与研究证据不属于该授权。

## 已读取原型与真实基线

已完整阅读 [server.py](../server.py)、[peer.py](../peer.py)、[app.js](../web/app.js)、[package.json](../package.json)、[desktop/main.cjs](../desktop/main.cjs)、[capacitor.config.json](../capacitor.config.json)、[test_core.py](../tests/test_core.py)。

本次运行（退出0）：

```sh
.venv/bin/python -m pytest p2pchat/tests/test_core.py -v
# 4 passed, 10 warnings in 1.26s
```

1. STUN v4/v6 XOR-MAPPED-ADDRESS函数编码、坏报文长度拒绝。
2. 敏感key脱敏、二进制frame往返及SDP族/relay过滤。
3. loopback信令拒绝错房间key与chat消息；日志不含该测试聊天正文。
4. 同一Python进程中的两个真实aiortc对象，三个profile尝试存在、至少一路文本和文件回声/ACK/hash成功。不是两个独立进程，不是独立设备，不是隔离NAT，不是三个协议全部通。

警告：aiohttp NotAppKeyWarning 2项及bare handler deprecation 8项；未使测试失败，但不应忽略维护整改。

### 尚未完成，后续实现不得沿用过强声明

- v0无版本、connectionId；hello仅比较peer字段和strictP2P标志，无双向密钥证明；部分接收逻辑未以认证态为门槛。必须按v1修正。
- 浏览器首次发起按profile循环await，非完整并发调度；既有路径数量不证明三路成功。重试、早到ICE缓存/限额、信令离线后的roster清理行为要验。
- 浏览器日志仅内存，Python客户端没有持久pending/ACK补传；中心以临时peerId拼事件id，不保证跨重连去重；SQLite/JSONL无轮转限额；允许任意遥测嵌套字段，仅敏感词redact不足以防日志承载正文。
- 日志目前含原始IP/candidate/name/remote字段；脱敏与事件白名单尚不满足v1；底层抓包细节不可观测不能补造。
- 文件已有32MiB限制、16KiB块、最终hash ACK与高水位等待；没有块sequence/ready/progress、全局总内存预留、完整超时释放。测速复用文件与聊天通道，未隔离。
- 文本/文件echoOf防循环原型存在，但现有用例末尾发送echoOf后未严格计数证明无回复；需要真正负例。
- Electron只有安全窗口与麦克风提示，无preload/native桥；Capacitor仅配置，未确认Android项目/SDK与APK。原生UDP/QUIC/TCP/映射均无原型实现证据。

## 永久限制与声明规则

不承诺对称NAT、CGNAT、UDP阻断、IPv6有状态防火墙或任意网络都能成功；IPv6地址存在不表示入站允许。所有可用路径并行尝试且首路成功不取消其它尝试，但用户取消/退出/资源上限可结束，并必须注明原因。无成功路线时只报告失败/建议检查网络，不自动启用TURN。默认绑定loopback；任何公网部署与网关变更需另行用户确认。
