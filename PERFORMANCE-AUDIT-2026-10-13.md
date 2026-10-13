# QUIC 优化与速度瓶颈审计（2026-10-13）

## 结论与范围

当前 Python/aioquic 接收侧存在单核实现瓶颈，不能把所有 QUIC 的低速归因于公网网络，也不能宣称它已在千兆以内消除了实现上限。此次优化减少了应用发送/定时调度开销和内核 UDP 接收丢包，但没有替换 aioquic 为原生 QUIC 引擎。

实验在同一 Linux 主机上运行两个独立 Python 3.12 进程，aioquic 1.5.0；确认字节经过原有加密、身份验证及应用接收确认。虚拟链路使用一次性 user/network namespaces、veth 和 netem，无外网出口，不修改宿主机网络、防火墙或 sysctl。它们不是两台真实电脑或真实运营商线路。双方向顺序测试，下面速率均为应用层 Mbps，不是线路速率。

## 实测

初始对照：1200 字节 QUIC、每方向 32 MiB、两轮，原实现 221.0–251.8 Mbps；第一阶段合并调度/精确定时后 359.5–389.5 Mbps。原始数据分别位于 `data/verification/quic-before` 和 `data/verification/quic-after-timer`。后者样本低于一秒，只作为初步对照，不用于瓶颈判定。更长样本只对优化后的实现采集，不能把不同大小的测试混为严格 A/B。

最终长样本及隔离实验：

| 环境 | 每方向大小 / 轮数 | 上下行结果 Mbps | 双端 CPU 证据 | 判断 |
|---|---|---|---|---|
| 本地 IPv4，1200 字节 | 128 MiB / 2 | 398.8–416.1 | 接收端约 96–100% 单核 | 实现限制（疑似） |
| 本地 IPv4，1400 字节 | 128 MiB / 2 | 457.9–488.9 | 接收端约 96–100% 单核 | 实现限制（疑似） |
| 本地 IPv6，1200 字节 | 128 MiB / 1 | 410.2 / 406.4 | 接收端约 99% / 97% 单核 | 实现限制（疑似） |
| veth 1000 Mbps，无附加延迟 | 128 MiB / 1 | 406.9 / 409.5 | 接收端约 99% / 98% 单核 | 实现限制（疑似） |
| veth 1000 Mbps，附加 RTT 50 ms | 128 MiB / 1 | 341.7 / 44.7 | 一方向有接收缓冲错误；另一方向负载低 | 两方向未确定 |
| veth 50 Mbps，附加 RTT 20 ms | 64 MiB / 1 | 46.5 / 43.8 | 事件循环约 12–18% 单核 | 上行正常（≥90%），下行未确定 |
| veth 1000 Mbps，附加 RTT 50 ms，每方向丢包 0.1% | 32 MiB / 1 | 8.6 / 7.2 | 双端约 5–6% 单核；至少 28 / 32 次拥塞恢复 | 方案/网络限制（疑似） |
| TCP/TLS 对照，1000 Mbps，附加 RTT 50 ms | 512 MiB / 1 | 840.8 / 851.7 | 双端约 5–9% 单核 | 未确定，不冒充已跑满千兆 |

最终数据目录为 `data/verification/quic-tuned-local-1200`、`quic-tuned-local-1400`、`quic-tuned-ipv6`、`quic-tuned-gigabit`、`quic-tuned-gigabit-rtt50`、`quic-tuned-50mbps`、`quic-tuned-loss` 和 `tcp-reference-gigabit-rtt50`。每个目录都有 `summary.json`、各进程 JSON 报告和诊断 SQLite；隔离实验另有 `topology.json`。

在增加 socket 缓冲前，长样本 asyncio 与 timerfd 都已约 400 Mbps，说明合并调度后接收侧的单核成本成为主要限制，**不能把收益全归于 timerfd**。增加缓冲后本机记录不再出现 UDP 缓冲错误，但高 RTT 的一个方向仍有错误且双方向差异明显，不能声称该参数组合解决了所有高 RTT 性能问题。1400 字节降低每字节的报文处理次数，但仅可用于通过既有 MTU 证据的路径，不能为了速度绕过尺寸黑洞检测。

## 修改

- 合并同一轮事件循环内的发送请求，每累计约 256 KiB 让出执行，避免每个应用块立即刷新。保留 16 MiB 未确认窗口与约每 256 KiB 的接收确认。
- 复用 QUIC 截止定时器，避免相同截止时间反复取消/重建；Linux timerfd 无忙等待、无额外线程，其他平台或失败时回退 asyncio。关闭、取消及回退均清理句柄/文件描述符。
- 仅已认证的打洞 socket 升级后申请 4 MiB 收发缓冲，内核实际返回值进入日志。本机实际各为 8 MiB，这是 Linux 返回值的记账方式，不表示修改了系统上限。
- 避免每个 QUIC StreamDataReceived 都构造一个不会使用的空 bytearray。
- 双端每 50 ms 收集有限运行时样本，不启用逐包 qlog。定时延误扣除包生成已经耗掉的 deadline 时间，避免把生成开销误报为定时精度问题。
- 新增链路表“速度瓶颈 ↑ / ↓”及中文详情；两个方向的判断、依据和双端采样进入原有持续中心日志链路。

## 判断边界

CPU 指标是事件循环线程的单核占用，不是整机平均 CPU，也不是精确剥离后的 Python 解释器成本。加密、系统调用、日志和其他事件循环任务都可能包含其中。接近单核满载只标为疑似实现限制，尚未通过替换原生后端完成因果证明。

低 CPU 不自动代表网络限制。网络类判定还需多次拥塞恢复、窗口利用率与 `cwnd/RTT` 约束证据；丢包/RTT 对当前 Reno 实现的约束不意味着改为另一种合规控制算法、原生引擎或其他传输也不能更快。打洞方案通常只是建链方式，不能给 IPv6 入站打洞、IPv4 NAT 或 UPnP 按名字赋一个固有带宽上限。

命名空间 UDP 错误不是单 socket 计数，只能辅助诊断；单凭该计数会显示未确定。双端采样不足、短样本、旧对端、同期打洞/附件流量也显示未确定。正常要求有效双端参考及达到其 90%；低于参考或超过参考都不会自动判定物理瓶颈。

aioquic 的窗口/RTT/拥塞时间采用带版本保护的只读内部适配，绝不修改拥塞和 pacing 状态。内部字段变化时缺失相应证据，聊天/测速继续，判断降为未确定。

## 复现

```bash
.venv/bin/python tools/performance_lab.py --transport quic --size 128 --runs 2 --data data/repeat-quic
.venv/bin/python tools/performance_lab.py --transport quic --size 128 --runs 2 --quic-datagram-size 1400 --data data/repeat-quic-1400
.venv/bin/python tools/performance_lab.py --transport quic --size 128 --runs 2 --quic-timer asyncio --data data/repeat-quic-asyncio
.venv/bin/python tools/performance_netns.py --transport quic --size 128 --runs 1 --delay-ms 0 --rate-mbps 1000 --data data/repeat-quic-gigabit
.venv/bin/python tools/performance_netns.py --transport quic --size 32 --runs 1 --delay-ms 25 --rate-mbps 1000 --loss-percent 0.1 --data data/repeat-quic-loss
```

实验工具还允许显式对照 `--quic-cc reno|cubic`；生产默认仍为 Reno，不把未充分验证的算法切换默认为普遍提速。不要同时运行多组性能测试，否则共享 CPU 会污染对照。

## 回归验证

完整测试 306 通过、3 个隔离环境专用测试在普通进程中跳过；这些专用测试另外由命名空间子进程实际执行，3 通过、0 跳过。Ruff 全库检查通过。结果在 `data/verification/junit-quic-optimization.xml` 和 `data/verification/junit-raw-netns.xml`。

回归覆盖双端采样、旧对端/短样本/并行流量的保守判断、发送/接收端 CPU 与循环延迟、命名空间 UDP 计数歧义、拥塞证据、定时器取消/重设/失败回退、IPv4/IPv6 实际 QUIC、MTU/故障、聊天与附件，以及 60×24、80×24、112×34、160×48 的 TUI。TUI 原始截图保存在 `data/verification/quic-tui`。
