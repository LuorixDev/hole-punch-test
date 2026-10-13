# P2P 打洞方法、项目与实现缺口调查

调查日期：2026-10-13。范围：本项目实际代码，以及公开标准、作者论文、项目官方文档和源码。

本文是调查与代码审阅，不是新方法的完成报告。未安装或实测这些外部项目，也未把它们的成功率当成本项目的成功率。分支链接会变化；实现时应固定版本或提交。

## 结论

当前是覆盖常见机制的实验工具，不是“所有打洞方法已实现”。增加同一 socket 的发送频率和重试次数，不等于增加独立机制；换 QUIC、KCP 或 uTP 也不自动改变 NAT 的放行规则。

最有工程价值的补充方向是：正确的过滤探测、端口预测成功后转为真实聊天通道、RTT 同步、有限随机端口碰撞、TCP 监听与主动连接组合，以及网关 TCP 放行。IPv6 优先补真实 CPE 兼容性和长时间地址/状态变化，而非只增加 IPv4 端口猜测。

## 本轮已经修改

- `--allow-inbound-check` 启用 HTTP 回连后，未填写 `--inbound-prefix` 即允许任意全局 IPv6，朋友不再需要先提供前缀。
- 填写 `--inbound-prefix` 仍可选择限制范围；它现在是可选限制，而不是必须参数。
- 保留网卡地址有效期、地址范围、会话签名、一次性回显等正确性校验。回连开关仍默认关闭。
- 服务端启动日志记录 `inbound_ipv6_policy` 和实际前缀。已有启动命令若仍带前缀参数，仍然会限制，需去掉该参数。
- 验证：相关测试 33 项通过；全套 199 项通过、0 失败；报告在 `data/verification/junit-inbound-unrestricted.xml`。

## 当前代码覆盖

| 当前功能 | 实际实现边界 |
| --- | --- |
| IPv4 / IPv6 UDP | 双向认证探针；三个发送节奏；接收认证过的实际来源可发现 peer-reflexive 端点。裸 UDP 探针不承载聊天。 |
| QUIC | 复用已经打通的 UDP socket；两种报文上限、两个角色、方向性尺寸测试及大包失败后的 1200 回退。 |
| TCP 直连 | 双向角色尝试；IPv4 使用 TCP 观察器，不借用 UDP STUN 映射；TLS 数据通道。 |
| TCP 同时打开 | 真实双方 `connect()`，多个固定错峰；不含同端口 listener + 多 connect 竞争组合。 |
| WebRTC | aiortc / aioice 的 UDP ICE，双栈及单地址族，角色交换；不是 ICE-TCP。 |
| IPv4 端口预测 | 同 socket、不同目的观察，要求固定步长绝对值 1–8；仅外推最多四个端口，且成功目前只算探针，不转为聊天。 |
| IPv4 网关 | UPnP、PCP MAP、NAT-PMP 的 UDP 租约；UPnP 已有冲突时换随机外部端口尝试。 |
| IPv6 网关 | PCP UDP MAP、UPnP IPv6 AddPinhole；并非系统管理员直接修改防火墙。 |
| 地址选择 | 真实网卡、稳定/临时 IPv6、有效期与 DAD 状态；没有实现跨地址族 NAT64 候选。 |
| 全部方案调度 | 成功后继续已选矩阵；上限 200 项、有限地址对，超预算会记录省略，不是全参数穷举。 |

代码位置：`p2plab/experiments.py`、`udp.py`、`tcp.py`、`rtc.py`、`gateway.py`、`network.py`。

## 必须先纠正的准确性问题

### 过滤探测受到自身流量污染

`UdpAttempt.observe()` 在取得 OTHER-ADDRESS 后，先向备用 IP/端口发送普通 Binding，再发送 CHANGE-REQUEST 检查备用地址回包。普通 Binding 已经可能在 NAT 上打开了对应过滤状态。

只读复现：模拟端点无关映射、地址和端口相关过滤；仅放行本 socket 已联系过的源 IP/端口。实际调用序列为：

```text
主 IP:3478 -> 主 IP:3478 -> 备用 IP:3478 -> 备用 IP:3479 -> 主 IP:3478 CHANGE=6
真实模拟过滤：address-and-port-dependent
当前输出：endpoint-independent-observed
```

这不是“对称 NAT 一定不能穿透”的问题，而是诊断证据不正确。RFC 5780 第 4.4、4.5 节明确指出过滤测试依赖此前的 NAT 状态。应先执行未被污染的过滤测试，或使用独立的新探测 socket；处理多个观察器时也要检查此前联系过的目的地址，无法排除污染就报证据不足。[S01]

本轮没有改动这个算法，按用户要求先报告发现的问题。已经通过的旧测试不能排除这个缺陷。

### 端口预测成功并不提供聊天室链路

当前 `prediction` 与 `udp` 走同一“只认证探针”的分支，结束后关闭 socket。因此未来即使预测真正在某种 NAT 上有效，也不能直接用其聊天或测速。应在同一获胜 socket 上继续建立 QUIC 等经过认证的数据通道；不能关掉再换端口。[本地：`Experiments.execute()`]

### 网关覆盖还缺少 TCP 与部分 CPE 约束

PCP、NAT-PMP、UPnP 和 IPv6 pinhole 当前使用 UDP 协议号 17，没有 TCP 映射/开孔。UPnP SOAP 请求也没有显式绑定目标 pinhole 对应的 IPv6 源地址；某些网关会检查控制请求源地址是否与 InternalClient 一致。需要按网关协议规范和真实 CPE 单独验证，不能把模拟 SOAP 成功当作兼容性通过。[S07][S08][S09]

## 独立机制和参数变体清单

实施后注（2026-10-13）：下表是调研时的历史状态；当前实施与真实验证边界见 `EXPERIMENT-COVERAGE.md`，不要把下表中的“缺失”继续当作当前状态，也不要把后续模拟测试视为真实公网验收。

下表“缺失”表示当前代码没有该专门策略，不代表外部方法在任意网络一定成功。“建议”是针对本项目的工程判断。

| 方法或变体 | 通俗解释 | 当前状态 / 建议 | 原始依据 |
| --- | --- | --- | --- |
| 标准双向 UDP 打洞 | 双方从同一数据端口往对方发包，建立 NAT/防火墙回包状态。 | 已有；IPv6 同样需要考虑状态防火墙。 | S02、S03 |
| peer-reflexive 候选 | 对端从不同于信令预测的端口回包时，经认证接受实际来源。 | 已有基础能力；不是一个新 NAT 类型。 | 本地 `udp.py`；S03 |
| 随机端口单侧碰撞 | 难 NAT 一侧开多个本地 socket，另一侧探测随机目标端口，增加碰中映射的机会。 | 缺失；优先补，一难一易最值得测。 | S03、S04、S05 |
| 双难 NAT 碰撞 | 两侧目的相关映射同时变化，尝试源/目的端口组合。 | 缺失；不可套用单侧碰撞的概率，成本更高。 | S03、S05 |
| 分段或轮次端口搜索 | 把目标端口空间分段，在多个轮次中渐进尝试并保留获胜 socket。 | 缺失；属于碰撞策略参数维度。 | S05 |
| 更宽预测窗口 | 对固定增减步长、局部端口范围及外部并发导致的偏移做有限尝试。 | 仅很窄的四端口预测；需先建立数据通道。 | S04、S05、S14 |
| 多公网 IP 候选 | NAT/CGNAT 对不同目的可能使用不同公网 IP，不能只猜端口。 | 当前观察地址可进入候选，但预测要求单公网 IP；缺专门策略。 | S03、S05 |
| 低 TTL / Hop Limit 预热 | 包先经过本端网关建立状态，但尽量不抵达尚未准备好的对端；随后恢复正常 TTL 再连接。 | 缺失；IPv4 TTL 与 IPv6 Hop Limit 分开测，不是万能放行。 | S04、S12 |
| 秒级错峰、角色重排 | 让一端先开状态，另一端晚一些发送；不同于多发几次。 | UDP 仅固定 0.35 秒错峰；TCP 也只有有限固定错峰，缺更长组合。 | S04 |
| RTT/2 同步 | 在控制通道测往返时间，再协调两个端点大致同时发 SYN/UDP。 | 缺专门同步协议；优先补 TCP 时序。 | S06 |
| TCP listener + connect 竞争 | 同本地端口同时接受入站，并对多个内外网候选主动连接，保留任一获胜连接。 | 缺失；与现有纯同时 `connect()` 分开编号，不能冒充同一方案。 | S02 |
| TCP 连接反转 | 谁能被直接访问就由另一端主动连接，无需两边都映射。 | 普通 TCP 已有角色交换；网关 TCP 尚缺。 | S14 |
| ICE-TCP | 标准化 active / passive / simultaneous-open TCP 候选与连通检查。 | 缺失；aiortc 的 UDP ICE 不能算这项。 | S10、S11 |
| UPnP IGDv2 AddAnyPortMapping | 请求网关选择可用外部端口，而不是只请求某个具体端口。 | 缺失；当前 AddPortMapping 随机换端口不是同一动作。 | S08 |
| TCP 网关映射与 IPv6 TCP pinhole | UDP 被限制时，尝试允许 TCP 入站，再建立 TLS 聊天。 | 缺失；值得优先补。 | S07、S08 |
| PCP PEER / FILTER 等 | 用对端相关映射或过滤选项控制连接状态；区别于基础 MAP。 | 缺失；设备是否实现应独立记录。 | S07 |
| 多层 NAT / 同 CGNAT hairpin | 同一上游 NAT 的两端通过公网映射回到内网，或者选择可直接到达的内网候选。 | 已有 host 候选和公网候选；缺明确拓扑实验与 hairpin 归因。 | S02、S13 |
| 主动 LAN 发现 | 本地组播/广播寻找可直接通信的端点，避开公网 NAT 路径。 | 未实现主动发现；现有信令交换 host 地址可做部分 LAN 直连。 | S02；用户参考文档 |
| NAT64 / DNS64 / 464XLAT | 只有 IPv6 的端通过转换访问 IPv4 对端，需要合成候选和不同地址族匹配。 | 缺失；当前候选要求双方同族。IPv4 信令也需可用 IPv4/CLAT 路径。 | S03、S15 |
| IPv6 映射观察 / NAT66 | 少数 IPv6 路径仍可能改变地址；不能把本机 IPv6 一律当外部看到的地址。 | 原生 UDP 对 IPv6 跳过 STUN；没有专门观察和候选策略。 | 本地 `udp.py`；S07 的部署范围 |
| 保活、自适应重打洞、连接迁移 | 已建立的状态超时、切网或地址轮换后，保持或恢复真实数据通道。 | 有一般链路保活/关闭逻辑；不等同于完整切网迁移策略。 | S16、S17 |
| uTP 与 BitTorrent BEP 55 | 已连接的公共节点传递 rendezvous/connect 信息，端点直接建立 uTP。 | 未实现；可借鉴协调方式，协议不是新的 NAT 放行条件。 | S18 |
| pwnat 的 ICMP 关联技巧 | 借 NAT 对 ICMP 错误中引用报文的关联处理发现对端，再做 UDP 通信。 | 未实现；只建议作为单独历史/特定设备实验，不能保证现代 CPE 兼容。 | S19 |
| STUNT / NATBlaster | 历史 TCP 穿透研究中的低 TTL、连接反转或原始 TCP 报文处理。 | 未实现；部分变体需要特殊权限或非普通 socket，不作为默认客户端方案。 | S12 |

## 库与项目

这些是可学习或可接入的实现，不是建议全部作为运行依赖。纯 Python 控制和 TUI 可以保留；原生库可作为可选传输后端，是否提高本项目吞吐需要另行测量。

| 项目 | 适合研究的部分 | 接入边界 | 依据 |
| --- | --- | --- | --- |
| frp XTCP | NAT 行为分类后的 TTL、角色、延迟、预测范围和随机端口组合。 | 主要参考 `pkg/nathole/analysis.go`；XTCP 与转发型 STCP 不混淆。 | S04 |
| EasyTier | 多 socket、可预测/随机 NAT 策略、TCP 穿透。 | 当前源码已迁到 `easytier-core/src/connectivity/hole_punch/`；整套 VPN 有中继，不能默认拿它冒充严格 P2P。 | S05 |
| Tailscale | NAT 行为、候选路径、随机碰撞、NAT64 等解释。 | 博文的策略讨论不等于每个技巧都是当前生产客户端的实现；不要照搬成功率。 | S03 |
| libp2p DCUtR | RTT 测量、Connect/Sync、TCP/QUIC 打洞同步。 | 完整协议先依赖 relay 连接；本项目只借鉴控制层同步，用现有 WS，不加数据中继。规范成功后取消剩余尝试，本项目应保留继续全测要求。 | S06 |
| libp2p punchr | 按尝试收集真实打洞证据与失败阶段。 | 测量工具，不是可直接替换的 Python 聊天库。 | S20 |
| Hyperswarm / HyperDHT | DHT 寻址、打洞协调、加密端到端流。 | Node.js 生态，DHT 不是新的 NAT 放行机制；可独立对照测试。 | S21 |
| P2PD | Python 多网卡、TCP 正向/反向连接、端口规律和同步。 | 作者文档值得研究；未在本项目验收，不据其描述承诺成功或推荐无条件替换。 | S14 |
| RakNet / SLikeNet | 游戏联机的同步、局域网/公网顺序、预测重试。 | NatPunchthroughClient/Server 插件；老文档“IPv6 不需打洞”的表述不能忽略状态防火墙。 | S22、S16 |
| aioice / aiortc | asyncio 的 UDP ICE、WebRTC 数据通道。 | 当前已使用；不能算支持 ICE-TCP，也不是端口爆破引擎。 | S23 |
| libnice | 原生 ICE、ICE-TCP、可选 UPnP。 | GLib/C 库；需明确编译能力和候选类型。 | S11 |
| libjuice | 轻量 UDP ICE。 | C 库，不提供 ICE-TCP；仅负责连通性，不等同于完整加密聊天协议。 | S24 |
| libdatachannel | 原生 WebRTC DataChannel 和可选 ICE 后端。 | C/C++；可选 libjuice 或 libnice；用 Python FFI/独立进程还需额外适配。 | S25 |
| Pion ICE | Go ICE 实现及 TCP mux 等。 | 可作独立辅助进程/对照客户端，不直接塞进 Python import。 | S26 |
| MiniUPnP / miniupnpc | UPnP IGD、AddAnyPortMapping、IPv6 pinhole。 | 优先用成熟实现核对自有报文与真实设备行为。 | S08 |
| libpcpnatpmp | PCP / NAT-PMP 客户端。 | 原生库，可比较租约和协议行为；不能替代公网连通认证。 | S09 |
| Natter / NATMap | 在适合的 NAT 行为下发现并维持可入站映射。 | 官方定位为 full-cone；不是任意对称 NAT 的解法。 | S27、S28 |
| Nebula | lighthouse 通知后的打洞、punchy 保活与响应。 | VPN 项目，有独立 relay 功能；需只统计真正直连路径。 | S17 |
| GameNetworkingSockets | 游戏数据传输、P2P signaling 和 ICE 集成。 | C++；构建配置与提供的信令后端决定功能，不能默认认为 Python 即插即用。 | S29 |
| pwnat | ICMP 关联技巧的具体历史实现。 | 作为研究对象，不据 README 推断今天的普适兼容性。 | S19 |

## 参数组合应怎样补

下面是建议的试验设计，不是已完成配置：

- 分离“机制”和“参数”：例如 `UDP-BIRTHDAY`、`TCP-CONNECT-LISTEN`、`TCP-RTT-SYNC`，每个再带网卡、地址族、端口数、TTL、延迟和轮次。
- 有限梯度：随机碰撞可从 16/64/256 本地 socket、分段目标端口和多轮次研究开始。这些只是初始实验档位，不是有效概率保证；两难 NAT 独立设计。
- 同步不只加固定 sleep：记录控制 RTT、抖动、双方准备完成、实际发送单调时刻；不假设两台机器墙上时钟同步。
- 每条成功链路保留原 socket、实际获胜远端和认证结果。QUIC 升级不可另开 UDP 端口；端口预测、碰撞与网关路径都要有真正聊天室验收。
- 低 TTL 预热与正常数据阶段分开，恢复 TTL 后才作最终认证；记录无 TTL 变体供比较。
- 双端网关角色：都不申请、只有 A、只有 B、双方申请；UDP/TCP、请求端口与网关选端口分别统计。
- 地址维度包括稳定/临时 IPv6、多网卡、跨运营商前缀变化；不能用一个 `max_pairs` 小预算宣称全组合已试。
- 当前 24 个候选、32 个候选挑战、200 项矩阵等约束无法原样承载 socket 阵列。扩展时同步设计候选表示、任务取消、资源回收和日志吞吐。
- 测试分层：纯报文/模拟网关；命名空间 NAT 与防火墙；真实 CPE；真实跨运营商。每层记录已运行、失败、证据不足、未运行，不能用增加测试数量替代公网证据。

## 建议实施顺序

1. 纠正 NAT 过滤顺序，新增污染状态的回归测试；把预测成功升级为真实数据链路。
2. 加 RTT 同步与 TCP listener/connect 组合，保留独立结果，测试第一包丢弃/RST/延迟等场景。
3. 加有限随机碰撞、分轮端口策略和更宽预测；先一难一易，再研究两难，不承诺必通。
4. 加网关 TCP、AddAnyPortMapping、IPv6 pinhole 的来源绑定与真实 CPE 验收。
5. 再扩 ICE-TCP、NAT64/纯 IPv6 接入、切网恢复，以及低 TTL 和 ICMP/原始 TCP 的独立实验。

这份优先级是本项目的判断，不是文献给出的通用最优顺序。本轮没有接入上述外部库，也没有声称所有新增机制完成。

## 原始来源

- S01：[RFC 5780，尤其 4.4/4.5 节：过滤状态和测试顺序](https://www.rfc-editor.org/rfc/rfc5780.html)
- S02：[Bryan Ford 等，Peer-to-Peer Communication Across NATs；同端口 TCP listen/connect](https://bford.info/pub/net/p2pnat/)
- S03：[Tailscale 作者文章，How NAT traversal works；生日碰撞、NAT64 与路径选择](https://tailscale.com/blog/how-nat-traversal-works)
- S04：[frp nathole 策略源码](https://github.com/fatedier/frp/blob/dev/pkg/nathole/analysis.go)；[XTCP 官方说明](https://gofrp.org/en/docs/features/xtcp/)
- S05：[EasyTier 当前 socket 阵列](https://github.com/EasyTier/EasyTier/blob/main/easytier-core/src/connectivity/hole_punch/udp/socket_array.rs)、[UDP 客户端策略](https://github.com/EasyTier/EasyTier/blob/main/easytier-core/src/connectivity/hole_punch/udp/client.rs)、[TCP 穿透](https://github.com/EasyTier/EasyTier/blob/main/easytier-core/src/connectivity/hole_punch/tcp.rs)、[项目说明](https://github.com/EasyTier/EasyTier)
- S06：[libp2p DCUtR 原始协议，Connect/Sync 和 RTT/2](https://github.com/libp2p/specs/blob/master/relay/DCUtR.md)
- S07：[RFC 6887，PCP MAP/PEER 与选项、IPv4/IPv6/CGN/NAT64 部署](https://www.rfc-editor.org/rfc/rfc6887.html)
- S08：[MiniUPnP 官方项目](https://github.com/miniupnp/miniupnp)；[AddAnyPortMapping / AddPinhole 实例](https://github.com/miniupnp/miniupnp/blob/master/miniupnpc/src/upnpc.c)；[IPv6 pinhole 控制请求源地址限制问题](https://github.com/miniupnp/miniupnp/issues/731)
- S09：[libpcpnatpmp，PCP/NAT-PMP 客户端库](https://github.com/libpcpnatpmp/libpcpnatpmp)
- S10：[RFC 6544，ICE-TCP active/passive/simultaneous-open 候选](https://www.rfc-editor.org/rfc/rfc6544.html)
- S11：[libnice 官方镜像，ICE-TCP 与可选 gupnp-igd](https://github.com/libnice/libnice)
- S12：[Guha / Francis，Characterization and Measurement of TCP Traversal through NATs and Firewalls；STUNT/NATBlaster 等历史研究](https://www.usenix.org/legacy/event/imc05/tech/full_papers/guha/guha_html/index.html)
- S13：[RFC 5128，多层 NAT 与 hairpinning](https://www.rfc-editor.org/rfc/rfc5128.html)
- S14：[P2PD 连接方法](https://p2pd.readthedocs.io/en/latest/p2p/connect.html)；[端口规律/预测](https://p2pd.readthedocs.io/en/latest/articles/nat_classification.html)
- S15：[RFC 7050，IPv6 前缀发现与 NAT64 合成](https://www.rfc-editor.org/rfc/rfc7050.html)
- S16：[RFC 6092，住宅 IPv6 CPE 状态过滤](https://www.rfc-editor.org/rfc/rfc6092.html)
- S17：[Nebula punchy 官方文档](https://nebula.defined.net/docs/config/punchy/)；[NAT traversal 说明](https://nebula.defined.net/docs/guides/nat-traversal/)
- S18：[BitTorrent BEP 55，IPv4/IPv6 rendezvous/connect 与 uTP](https://www.bittorrent.org/beps/bep_0055.html)
- S19：[pwnat 作者项目与 ICMP 机制说明](https://github.com/samyk/pwnat)
- S20：[libp2p punchr 测量工具](https://github.com/libp2p/punchr)；[2026 年 DCUtR/IPFS 大规模测量论文，结果仅适用于其条件与样本](https://arxiv.org/abs/2604.12484)
- S21：[HyperDHT，Hyperswarm 的打洞与 Noise 流基础](https://github.com/holepunchto/hyperdht)
- S22：[SLikeNet / RakNet NatPunchthrough 官方算法文档](https://github.com/SLikeSoft/SLikeNet/blob/master/Help/RakNet/documentation/natpunchthrough.html)
- S23：[aioice 作者项目，UDP ICE](https://github.com/aiortc/aioice)
- S24：[libjuice 作者项目，UDP ICE](https://github.com/paullouisageneau/libjuice)
- S25：[libdatachannel 作者项目与后端说明](https://github.com/paullouisageneau/libdatachannel)
- S26：[Pion ICE 作者项目](https://github.com/pion/ice)；[TCP mux 选项](https://github.com/pion/ice/blob/main/agent_options.go)
- S27：[Natter 作者项目，full-cone 定位](https://github.com/MikeWang000000/Natter)
- S28：[NATMap 作者项目，full-cone 定位](https://github.com/heiher/natmap)
- S29：[GameNetworkingSockets 官方 P2P 接入说明](https://github.com/ValveSoftware/GameNetworkingSockets/blob/master/README_P2P.md)
