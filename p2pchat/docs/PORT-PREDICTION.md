# 对称 NAT 端口预测打洞

状态：**本地实现与受控端点测试已完成；真实家宽对称 NAT = NOT_RUN**（需用户在真实网络运行）。

实现：`p2pchat/native/port_prediction.py`　测试：`p2pchat/tests/native/test_port_prediction.py`　依赖：`p2pchat/native/nat_behavior.py`（t10，不改动）

## 0. 先说清楚能力边界（必须照抄进界面文案）

> 对称 NAT 下端口预测的命中概率有限，失败是正常结果，不能把它当成普遍可用的直连手段。
> 优先顺序：**1) 优先 IPv6 直连**（家宽多有 IPv6，一般不受 NAT 端口分配影响）；**2) 其次在自家路由器/网关上显式放行**（UPnP/PCP/NAT-PMP 授权映射）；**3) 最后才用端口预测**，并且必须双方同时向对方发包。

本功能不做中继、不做 TURN，也不把预测成功说成"稳定可用"。

## 1. 什么时候才会预测

只有 t10 的多观测点分类结果是**地址+端口相关（对称型）**时才进入预测：

- 其它映射行为（端点无关 / 地址相关 / 无法判定）→ 直接返回 `NOT_SYMMETRIC_MAPPING_BEHAVIOR`，**一个包都不发**；
- 生效范围仅限本机与该对端之间，不扫描任何第三方主机。

预测的是**对端**下一次新建映射时会拿到的对外端口（对端把映射建向本机地址时使用），因此：

- 采样来自对端自己的观测（t10 采集的端口分配序列）——由对端经既有信令/诊断通道共享；本机自己的采样只用于了解本机；
- 对端必须**同时**向本机的候选地址发包，否则端口上不会存在可回包的映射。

## 2. 端口分配规律与预测

从"新建映射的顺序"看对外端口序列（观测样本，不是猜测）：

| 规律 | 观测特征 | 是否预测 |
|---|---|---|
| **递增** | 每次新建映射对外端口 +固定小步长（同一步长） | 是：沿序列外推下一个 |
| **分块** | 每个目的地一组连续端口，组基址按固定块大小推进 | 是：预测下一组的块内偏移 |
| **哈希** | 无顺序，且端口在不同映射间重复或压缩在一个很窄的窗口内 | 否：无法外推 |
| **随机** | 无顺序，且端口分散在很大的范围内 | 否：无法外推 |

- 样本不足（默认 <4 个不同映射）→ `INSUFFICIENT_ALLOCATION_SAMPLES`，**不预测**；
- 规律冲突（例如递增序列中途出现大跳变）→ 归入"不可外推"，**不预测**；
- 哈希与随机都不可外推，两者的区分只是**形状**（重复/窄窗口 vs 大范围分散），都与成功率无关，文档与界面不得暗示"识别出哈希就能预测"。

## 3. 严格有界（全部是硬上限，不是建议值）

| 限制 | 默认 | 作用 |
|---|---|---|
| 预测候选数 `max_candidates` | 8 | 最多只猜测这么多个对外端口 |
| 预测窗口 `max_span` | 32 | 预测端口与最后一个观测端口的最大偏差；超窗直接拒绝（`PREDICTION_WINDOW_EXCEEDED`），不可能变成端口段扫描 |
| 每候选探测次数 `probes_per_candidate` | 2 | 不无限重试，失败即终态 |
| 发包间隔 `min_interval` | 40 ms | 约 ≤25 包/秒 |
| 单候选等待 `per_candidate_timeout` | 0.4 s | 有界等待 |
| 总时长 `total_timeout` | 6 s | 到点即终态（`DEADLINE_REACHED`） |
| 并发 | 固定 1 | 单 socket 顺序探测，没有并发突发 |
| 目标地址 | 仅已信令地址 | 只允许探测**已经过信令交换**的对端地址，端口才可能被预测；其它地址一律 `UNSIGNALED_TARGET_ADDRESS` 拒绝 |

命名探测前缀 `P2POBS1` + 认证帧；总发包数 ≤ `max_candidates × probes_per_candidate`（默认 ≤16）。命中即停（不再试探其余预测端口）。

## 4. 安全边界不变

- **不放宽既有候选校验**：本模块不修改 `validate_candidate`；预测端口最终仍要按 §5 走同一套校验/信令。特别地，**预测端口不会伪装成 STUN 观测候选写进候选清单**：`kind` 只能是既有的 `host/srflx/mapped`，新增 `kind=predicted` 仍被拒绝（有测试断言）。
- **不修改配对 HMAC 与候选独立 nonce 语义**：探测帧就是 `p2pchat/native/auth.py` 的同一个 `Auth`（`P2POBS1`+`packed(frame)`），每个预测候选一个独立 nonce，重试沿用该候选自己的 nonce。
- **不引入中继**：本模块只发包/收包做认证探测，不转发任何数据。

## 5. 认证探测流程

1. 建立/复用一个 UDP socket（显式绑定本机地址，不枚举网卡）；
2. 对每个预测候选 (对端地址, 预测端口)：发 `P2POBS1`+hello（HMAC）；
3. 只接受**来自该候选地址端口**且能通过 `Auth.receive` 的回包；来源不符、非 `P2POBS1`、JSON 畸形、证明不符（伪造）一律丢弃并记 `REPLIES_REJECTED`，绝不当作命中；
4. 命中即停，终态 `hit`；无回包 → `no_response`（`NO_AUTHENTICATED_REPLY`）；到总时长 → `DEADLINE_REACHED`；
5. 命中只表示"该预测端口上存在通过同一 HMAC 认证的对端映射"。命中后该路径以 `predicted-port` 标注（`stats().remoteCandidateType`），**不是** STUN 观测到的候选，也不伪装成 `srflx`；证书 pinning 仍用信令阶段拿到的指纹。

## 5.1 接入真实连接流程（t21）

上面 §5 描述的是库自身的探测。t21 把它接进了真实尝试（`p2pchat/native/adapter.py`），现在有生产调用点：

1. **只有 t10 判定为地址+端口相关（对称型）才会启用**。尝试启动后先在用户显式配置的观测点上采样；结论不是对称型（含"无法判定"）→ 状态 `not-symmetric`，**零额外探测包**，`prediction.observedMapping` 如实记录观测到的映射行为。
2. **双向样本交换**：本端把观测到的端口分配序列（只含序号、本地端口、观测点地址端口、对外端口；**不含**自己的公网映射地址）用房间密钥 HMAC 签名（域分隔串 `p2pobs-v1-samples`）后作为信令消息 `{"type":"nat-samples"}` 发出；对端回传同样签名。nonce 一次性（每个尝试有界保存 ≤64 个），重复即 `SAMPLES_REPLAY`；证明不符即 `SAMPLES_PROOF_MISMATCH`；形状/长度/地址非法即 `INVALID_SAMPLES`/`SAMPLES_LIMIT`。密钥永远不上信令链路。
3. **服务端只做白名单校验与转发**：`nat-samples` 在 `p2pchat/server.py::Hub.bind_samples` 里逐字段校验（v/type/to/connectionId/attemptId/mechanism/profile/nonce/proof/samples；未知字段、>64 条、非法/组播/链路本地/未指定地址、非法端口一律拒绝），要求该尝试已存在且绑定匹配（否则 `ATTEMPT_CONFLICT`），每尝试每个 peer 限 8 条（`LIMIT_EXCEEDED`）。服务端**没有房间密钥**，看不到样本内容，也不存储样本，只转发；`signal` 消息的 schema 依旧封闭，样本不能塞进普通信号帧（有测试）。
4. **同时探测**：两端都用**自己尝试的同一个 UDP socket**（也就是信令过的本地候选）向**已信令的对端地址** + 预测端口发 `P2POBS1` hello。因此对端看到的来源就是它已经认识的候选，回包才能落在它的映射上；每目标最多 `PREDICTION_PROBE_BUDGET = 2` 次，沿用 §3 的候选数/窗口/速率/总时长上限，绝不扫描第三方地址或大范围端口。
5. **预测目标不是候选**：预测端口只进 `predicted_targets`，地址必须等于已信令对端地址，且仍用同一套 `validate_candidate` 规则校验（把信令候选的元数据配上预测端口）；`kind=predicted` 仍被拒绝。命中后才把该路径标为 `predicted-port`。
6. **默认关闭 + 显式同意**：`NativeAdapter(prediction={"enabled": True, "points": [...]})` 才启用；桌面端在设置面板「需要你单独同意的三件事」里由用户点按同意后调用 `engine.prediction_enable(consent=True)`，`prediction_disable()` 可随时关闭。`capabilities()['prediction']` 如实报告 `disabled` / `unavailable(OBSERVATION_POINTS_REQUIRED)` / `available`。
7. **终态明确**：`hit` / `no-hit`（`NO_AUTHENTICATED_REPLY`、`REPLIES_REJECTED`、`DEADLINE_REACHED`、`SEND_FAILED`）/ `unpredictable`（`ALLOCATION_NOT_EXTRAPOLABLE`…）/ `not-symmetric` / `not-applicable`（IPv6）/ `timeout`（`PEER_SAMPLES_TIMEOUT`）/ `unavailable`，都有界、无无限重试。

## 6. 为什么失败很常见（如实解释）

- 对端 NAT 是**随机或哈希**分配 → 根本不该预测（本工具会明确说"不可外推"）；
- 对端在建向本机的映射之前/之后端口序列已经前移（有其它程序也在建映射）→ 预测落空；
- 双方时序不齐（本机发包时对端的映射还没建立）；
- 运营商 CGNAT 的端口分配窗口随时会变。

因此界面必须显示"预测命中概率有限、失败属正常结果"，并且把 IPv6 直连与网关放行排在它前面。

## 7. 本地可复现命令与哈希

```text
.venv/bin/python -m pytest p2pchat/tests/native/test_port_prediction.py -q
22 passed                                  # t18 库本身

.venv/bin/python -m pytest p2pchat/tests/native/test_prediction_integration.py \
    p2pchat/tests/backend/test_prediction_signal.py -q
15 passed in 1.70s    exit 0               # t21 接入（含样本交换/同时探测/命中与负例）

.venv/bin/python -m pytest p2pchat/tests -q
450 passed in 2:06    exit 0
```

t21 变更文件 sha256（engine.py/ui.py 与 t26 并发共用，哈希为本次运行时刻）：

```text
70fac9dc36be17f6b1e99500b77c75671bd198bfcca78508369c86a65c3b4285  p2pchat/native/adapter.py
09c9678497f1b307394ef29dc34467eafe353c0540fff0674a9f2289a1128cfa  p2pchat/server.py
553caa755fce17bac5ea254142cb7403317050b2d866a329db1e1e4eba64e579  p2pchat/peer.py
f0c860a7edca7090cfbf3797fc04af46b043732a0b8e89d151df75b05f03f79e  p2pchat/python_desktop/engine.py
5161440630c57844c63c72ff82f90ca6fccbdb3aa55d19ccf37fdf23cd5e0e10  p2pchat/python_desktop/ui.py
32222ed0811a85a09c0b7c5dd38984ba69c003a05ccb55b09f7814d8fd701bfb  p2pchat/python_desktop/native_session.py
a98c4ef18d73c3c0bffbfe2d2a51f4d224355b68aa6af11aaac15df6b0efc95e  p2pchat/python_desktop/signal_session.py
a7e1e8b6c9202e44af278c6ea54d583c9f8c598b3baabd4d08db58e26f67ef44  p2pchat/tests/native/test_prediction_integration.py
a4bddf9b02f7306afdf62b2e1cb390007d655976fca7a3a8c27898c7bfbe79d0  p2pchat/tests/backend/test_prediction_signal.py
0508db7a57bae53e9240f24c898c7f5d368de2d9bbcc97e31ea5a0a7ed68a714  p2pchat/tests/backend/test_benchmark_ack.py
```

测试用受控 loopback 端点：脚本化 STUN 观测点构造四种端口分配规律（递增/分块/哈希/随机）与 APDM 分类，脚本化对端构造命中、伪造证明、畸形响应、静默（黑洞）等场景；负例覆盖样本不足、规律冲突、对端地址未信令、候选超限、越窗、总超时。**这些都不是真实家宽对称 NAT 证据**：真实家宽对称 NAT 仍为 **NOT_RUN**，需要用户在自己的网络上用 t10 的 CLI（见 [NAT-BEHAVIOR](NAT-BEHAVIOR.md) 第 6 节）先得到分类，再结合实际打洞观察，才能给出真实成功率。
