# QUIC 性能复测（2026-10-14）

## 目的与方法

复核 50 ms RTT、1000 Mbps 的隔离 veth 链路上 QUIC 双向吞吐不对称问题，并区分方向顺序、拥塞算法、TCP 对照及 Python 事件循环负载。每个 benchmark 由两个独立 Python 进程运行；TCP 与 QUIC 用同一 netns harness，网络命名空间与宿主机隔离。此结果不是公网、物理网卡或真实运营商线路测试。

新增 `--direction-order forward-first|reverse-first`，默认行为不变。它只改变隔离性能工具的测速顺序，可用于检验先后次序，不改变产品配置。

## 结果

应用层 Mbps，每轮每方向 64 MiB，运行两轮：

| 配置 | 方向顺序及吞吐 | 关键证据 |
|---|---|---|
| QUIC Reno | 正向先：282.8、31.8、342.0、73.1 | 低吞吐的第二发送端 `cwnd/RTT` 中位估算约 34–79 Mbps，在途占用约 100%；该方向事件循环约 11–28% 单核，P95 延迟约 1.5 ms，无该轮 UDP buffer error。 |
| QUIC Reno | 反向先：294.5、31.8、372.5、73.2 | 调换先测方向后，首个方向仍约 294–372 Mbps，另一发送端首次发送仍约 32 Mbps，第二次提升至约 73 Mbps；顺序效应跟随“发送端是否已建立拥塞窗口”，不跟随 IPv4 方向。 |
| QUIC Cubic | 正向先：299.7、46.0、363.5、259.5 | 反方向后续轮次改善，但冷方向首轮仍慢；没有稳定、可概括到公网的优势，不应据此替换生产默认 Reno。 |
| TCP/TLS | 正向先：364.8、376.8、593.6、562.6 | CPU 约 3–8% 单核，双向相对接近；后两样本小于 1 秒，不能作为稳态值。 |

Reno 复测数据：`data/verification/quic-repeat-rtt50-clean-20261014/summary.json` 与 `data/verification/quic-reversefirst-rtt50-20261014/summary.json`。Cubic：`data/verification/quic-cubic-rtt50-20261014/summary.json`。TCP 对照：`data/verification/tcp-repeat-rtt50-20261014/summary.json`。另一次与回归测试重叠的基准被视为污染样本，不纳入以上结论。

隔离网卡 UDP 计数在部分 QUIC 首轮出现接收缓冲溢出（最高约 2,075）；该计数是网络命名空间级而非单 socket 归因，单独不能证明具体丢包来自哪条连接。相同慢方向有的轮次没有此错误，因此它不足以解释方向差异。

## 判断

- “测速完全失败”不是当前隔离样本表现：全部列出的传输完成并确认了 64 MiB。较短时间或冷方向测试会得到显著偏低的 QUIC 平均值，不能当作已稳定的链路上限。
- 高 RTT 未被代码修复。netem 配置基线 RTT 为 50 ms；活跃传输观测到约 50–94 ms，部分增加与传输期间排队一致。远端 LibreSpeed 节点此前约 166–239 ms 的 RTT 是到该测速节点的路径延迟，不能由 P2P 客户端直接消除。
- 已复现 QUIC 每个独立发送端的拥塞窗口冷启动/爬升差异；冷方向的低速匹配当时的 `cwnd/RTT` 估算并处于满在途，但目前没有充分证据把根因进一步归到 Python CPU、丢包或单一 aioquic 缺陷。单核占用很低，不支持把该慢方向称为 Python 性能墙。
- 后续增加只读 QUIC 流控额度采样后，32 MiB/50 ms Reno 冷方向的剩余额度最小仍约 8.3 MiB，blocked 样本为 0；因此不支持应用/QUIC 流控额度耗尽。瓶颈更符合发送拥塞窗口限制，同时部分 pacing 定时存在调度延误。
- 同样 32 MiB/50 ms 的单轮 Cubic 对照中，冷方向首次约 135.6 Mbps，Reno 对照约 22.7 Mbps，显示 Cubic 可能更快爬升；但同轮首发送端约 238 Mbps且有命名空间级 UDP 缓冲计数，所以不足以得出稳定 A/B 结论。生产默认保持 Reno，后续需交错顺序、多轮重复并记录 socket 粒度丢包证据。
- 本机全双向结果也未达到 1000 Mbps。TCP 对照同样没有稳定跑满 1 Gbps，说明该受限 veth/主机测试不能充当真实千兆能力证明。
- 未更改生产 QUIC 拥塞算法、初始窗口、缓冲或测速语义；仅扩展隔离基准以支持顺序对照。贸然调整这些参数可能掩盖冷启动、放大缓冲排队或加剧丢包。

## 验证

- 全量测试：525 passed、4 skipped（隔离专用用例在普通 pytest 进程中跳过）。
- Ruff 全库检查与 `git diff --check` 通过。
- `performance_lab.py` 与 `performance_netns.py` 的 `--help` 均确认显示方向顺序选项；两种顺序都已完成实际 QUIC 双进程复测。

后续若要宣称“已解决”，需要针对冷发送端的 QUIC ACK、流控更新和拥塞窗口演进做逐阶段追踪，并至少以稳定长样本和独立原生 QUIC 实现作对照；公网高 RTT 还需在实际两端空闲、路径固定的条件下重复测量。

## 原生 C uTP 与构建复核

项目已经带有可选的 libutp C 后端，并不需要另写 C 扩展。本轮把 `utp` 加入隔离性能工具，用同一 TLS/Path 测速协议实际对照。首次 64 MiB 压测在 TLS 适配层的 128 块队列触发 `NATIVE_RECEIVE_QUEUE_LIMIT`；队列从固定小块数改为最多 4096 块且总缓冲最多 4 MiB，同时记录溢出大小。性能控制器也改为任一 worker 非零退出就终止另一个 worker 并收集双方输出，避免一端异常时挂等。

| libutp socket 缓冲 | RTT | 每方向 / 吞吐 | UDP 缓冲错误 |
|---|---:|---:|---|
| 默认系统值 | 0 ms | 32 MiB / 98.4、101.1 Mbps | 有少量命名空间级接收错误 |
| 每方向申请 4 MiB（本机实际 8 MiB） | 0 ms | 32 MiB / 161.7、163.9 Mbps | 0 |
| 默认系统值 | 50 ms | 64 MiB / 约 22–24 Mbps | 个别样本出现接收错误 |
| 每方向申请 4 MiB（本机实际 8 MiB） | 50 ms | 32 MiB / 29.2、29.5 Mbps | 0 |

排队字节上限和 socket 缓冲均是每连接有界设置，不改全局 sysctl。调整缓冲后 64 MiB 两方向均可完成且不再发生 TLS 队列断链；50 ms RTT 下 uTP 仍只有约 29 Mbps，远低于本次 TCP/QUIC 对照。该后端以延迟导向拥塞策略为目标，不能据这些样本得出它适合作为交互型 QUIC 的替代，也不能推断它在所有网络都如此。

性能工具新增 `--transport utp`；方向顺序选项仍可独立使用。uTP 复测产物位于 `data/verification/utp-rtt50-64m-20261014/summary.json`、`data/verification/utp-buffered-rtt0-32m-20261014/summary.json`、`data/verification/utp-buffered-rtt50-32m-20261014/summary.json`。

原生 C/平台边界：Linux CI 会构建 libutp，Linux PyInstaller client 包含 `data/native/libutp.so` 和许可证；Windows release workflow 不构建或打包 libutp，Windows 上仍应把它视为可选实验后端，不能切成默认。Python 侧的有界队列与测速工具变更是跨平台代码，但本轮只在 Linux x64 完成冻结构建和运行测试。

Linux client/server 单文件在 `/tmp` 独立目录用 PyInstaller 成功构建，未覆盖仓库已有 release 产物；client 包检查确认包含 libutp 与许可证。第一次 frozen smoke 发现测试在矩阵尚未完成时就发测速指令，与客户端“矩阵运行期间拒绝测速”的约定冲突；smoke 已调整为等待两端 `experiment.completed` 后再执行聊天、ping、测速和文件传输。第二次 loopback frozen smoke 全流程通过：双向测速、文件传输、共享 TCP/UDP 端口、中心日志均通过，后台错误为 0。此项仍是 loopback 构建冒烟，不是公网或跨平台性能验证。

QUIC 流控只读采样与 Reno/Cubic 32 MiB 对照产物分别位于 `data/verification/quic-flow-control-rtt50-20261014/summary.json` 和 `data/verification/quic-cubic-flow-rtt50-20261014/summary.json`。采样仅收集额度和 blocked 状态，不修改 aioquic 流控/拥塞内部状态。
