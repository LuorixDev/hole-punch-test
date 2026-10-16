# P2P 实验实施与验收边界

更新：2026-10-13。这里记录实际代码边界，不把文献、探针、模拟设备或库名称当成真实公网成功证明。

## 已实施机制

| 类别 | 实现与参数 | 已有验证 | 真实网络待测 |
| --- | --- | --- | --- |
| UDP / QUIC | IPv4/IPv6，peer-reflexive，三发送档，两角色，1200/1400 MTU 证据与避让 | 本地认证、聊天、文件、双向测速；隔离 IPv6 CPE、1280 MTU、静态阻断 | 各运营商/实际 CPE |
| 同步与时序 | 控制信道三次 RTT/2，TTL/Hop Limit 1/2/3，0.5/2/5 秒错峰 | 普通/立即调度任务；TTL 设置先于 SYN，之后恢复 | 非对称延迟、实际 CPE 状态寿命 |
| TCP 同时打开 | 仅 bind/connect，无监听兜底 | 内核套接字及失败路径，明确区分普通 TCP | 多 OS/CPE；不保证内核/网关支持 |
| TCP 监听竞争 | 同端口 listen/connect，多候选；区分内核同时打开并协商 TLS 角色，双方选择同一条认证连接 | IPv4/IPv6，零延迟及错峰，聊天、文件 | 同端口复用的跨平台差异 |
| STUNT #2 | 低 TTL SYN 预热，撤销并同端口重新监听/连接，角色互换 | IPv4/IPv6 TLS 聊天 | NAT 是否保留取消后的状态 |
| 预测与端口搜索 | 多公网 IP、固定步长宽窗；16/64/256 socket；单侧/双侧、四轮分段，约 200 次主动探针/秒上限 | 获胜 nonce 协商、原 socket QUIC、资源清理；有限参数生成 | 真实目的相关映射、随机映射、多层 CGNAT |
| LAN 发现 | 配对身份签名广播/IPv6 链路组播，再验证 QUIC | 实际 IPv4 广播与聊天、签名拒绝 | IPv6 组播网卡、跨无线隔离、广播限制 |
| Hairpin | 自 socket 向本机候选/外部映射签名回环 | 仅探针证据，绝不作为对端聊天成功 | 真正 NAT/CGNAT 回环，不能由 loopback 推断 |
| 网关 | UPnP、NAT-PMP、PCP、IPv6 pinhole；UDP/TCP；A/B/双方；IGDv2 自动端口；PEER/FILTER/PREFER_FAILURE | 报文、模拟租约续删、真实 HTTP SOAP 源绑定、TCP AddAny/Pinhole | CPE 协议实现、权限、IPv6 SOAP 源约束 |
| 原生 ICE | libnice 的 TCP 或 UDP/PseudoTCP；明确禁用 TURN/UPnP，选定候选后再验证 TLS | IPv4、IPv6、双栈本地通道、聊天、文件；库实际候选日志 | ICE-TCP 各候选支持和 CPE 兼容性 |
| 原生 uTP | 固定上游 libutp v2，保守 UDP payload 1200，TLS 加密可靠流 | IPv4/IPv6、聊天、文件、双向测速、普通/立即调度 | LEDBAT/MTU/真实 WAN 吞吐；未承诺千兆 |
| NAT64 | 两个 RFC 7050 答案验证前缀，六种 RFC 6052 长度；跨族候选、转换后映射、原 socket QUIC | 六长度单元测试；隔离命名空间 UDP 转换后的真实 QUIC、聊天和文件 | 真正 NAT64/DNS64 网关；464XLAT 由系统提供 |
| ICMP 关联 | 向自有观察服务器 Echo；对端 Time Exceeded 引用报文；再用认证 UDP/QUIC | 隔离命名空间实际原始报文与聊天 | NAT ID 重写/ICMP 关联兼容性；不是原版 pwnat 的第三方固定地址 |
| NATBlaster | 捕获本机低 TTL SYN 序列号，交换后注入无源地址冒充的 SYNACK，让内核完成 TCP，再 TLS | 隔离命名空间丢弃裸 SYN、保留注入 SYNACK，实际内核连接与聊天 | RAW 权限、路径跳数、NAT 序列号改写及 SYNACK 过滤 |
| 恢复与日志 | 地址变化/全通道失效请求协调端重试；保留活跃通道；旧结果/省略项持续落盘并上传 | 矩阵替换不破坏已有 QUIC；重连日志持久化；分块计划 | 真正拔插/换运营商；不是无缝 QUIC 迁移 |

## 配置与边界

- 非 loopback 默认 `comprehensive = true`；基础最多 200 项，完整最多 1024 项。每种方案成功后仍执行后续入选项。
- 地址配对仍受 `max_addresses`、`max_pairs` 和矩阵预算约束。日志记录省略参数，不声称无限穷举。
- 一端诊断/启动公网测速可能较慢，配对准备最多等待 420 秒；每项对端结果等待 130 秒，覆盖其最大 110 秒执行预算，避免过早跨入后续阶段。对端退出信令后停止待执行矩阵，已有 P2P 通道继续保留。
- 先完成无网关改动的基线，再执行全部主动网关申请。已成功的出站连接可能改变后续同拓扑状态，真实测量须结合时间顺序解释。
- `raw_probes = false` 默认记录未启用。启用后没有 `CAP_NET_RAW` 仍记录权限不可用，客户端不会修改宿主机权限或防火墙。
- 原生 ICE 需 libnice；uTP 运行 `tools/install_libutp.py`，或设 `P2PLAB_LIBUTP`。构建来源、固定提交和产物 SHA-256 记录在 `data/native/libutp-build.json`。
- Windows Actions 使用 UCRT64 编译同一固定源码，打包 DLL 依赖；源码及冻结客户端验收均覆盖 IPv4/IPv6 的 uTP、ICE-TCP、原生 ICE 聊天/文件/双向测速。结果属于回环功能验证，不是高 RTT 广域网吞吐保证。
- 收集/协调和日志通过 IPv4 服务器；聊天、附件、ping、P2P 测速始终直达对端，不经该服务器转发。
- 网关租约、ICMP 回包、签名 UDP 探针、可靠通道和应用 pong 是不同证据。没有辅助机制证据的直连，不标为该机制已生效。
- 原生流和 Python QUIC 的性能各不相同。既有千兆实验不代表新增 uTP/PseudoTCP 也达到同样速度；需单独实测。
- QUIC 已合并发送调度、复用截止定时器、使用 Linux timerfd 并调整已认证 socket 的缓冲区。双端吞吐诊断区分疑似实现限制、疑似方案/网络限制、正常与未确定；低速和 NAT/防火墙方案名称本身不是瓶颈证据。仍不宣称 aioquic 千兆无性能墙。实测见 `PERFORMANCE-AUDIT-2026-10-13.md`。

## 未冒充实现的内容

STUNT #1 的观察服务器冒充任意源地址、BitTorrent BEP 55 协议互操作、DHT 公共节点发现、全部 VPN 产品后端、所有传输的无缝连接迁移未包含在本矩阵。前者受服务器 RAW 权限和上游反源地址伪造限制；其余不是独立的 NAT 放行机制。已研究的项目用于提取机制，并不代表逐一安装或实现其完整协议栈。

## 验证入口

本轮最终结果：全量 **293 passed / 3 skipped**，Ruff 通过。主进程跳过的三项 ICMP、NATBlaster、跨族转换测试由隔离子进程实际执行，**3 passed / 0 skipped**。报告分别是 `data/verification/junit-comprehensive-full.xml` 与 `data/verification/junit-raw-netns.xml`。双端各一个 IPv4/IPv6 地址、三种发送档的示例生成 40 个策略编号、249 项尝试，预算内无省略；这些编号包含协议/网关变体，不是 40 种独立 NAT 原理。

```bash
.venv/bin/ruff check p2plab tests tools
.venv/bin/pytest -q --junitxml=data/verification/junit-comprehensive-full.xml
unshare -Urn .venv/bin/python tests/research_netns.py "$(readlink /proc/self/ns/net)"
```

最后一个入口强制检查隔离网络命名空间，只修改该隔离环境中的 loopback、synthetic IPv6 地址和 nftables。`tests/test_netns.py` 自动执行它；常规主进程中三项隔离专用测试跳过，在子进程中真正运行，见 `data/verification/junit-raw-netns.xml`。

测量协议和历史调研保留在 `NAT-TRAVERSAL-SURVEY-2026-10-13.md`。测试报告应与实际代码版本一起保存，不将此前的 231 项报告当作本次新实现已经验收。
