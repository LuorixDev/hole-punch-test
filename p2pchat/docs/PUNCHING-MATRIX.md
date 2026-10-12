# P2P 穿透技术全量对照矩阵（可审计）

本文回答用户的问题：**「打洞方式集成了吗？咋感觉不全面」**——把当前仓库里**真实存在**的每一条穿透路径、它落在哪个端、能不能传消息、以及证据等级，逐条摊开。

这是一份**对代码取证的说明**，不是功能承诺。判定原则只有一条：

> 表格里的每一行，都必须能在源码里指出**实际启动这条路径的位置**；指不出来的一律写进第 8 节「缺口台账」，并标注 PENDING / NOT_RUN。**没有实现的功能不写成已实现，同机与受控模拟不写成真实家宽证据。**

- 首版写入：2026-10-11；本轮修订：2026-10-12（本机 Asia/Shanghai）
- 桌面版版本号（`python_desktop/version.py` 的 `VERSION`）：`0.2.0`
- 首版取证时的源树封存值（**历史**）：`430471c693a875b09f57154222d31a1ad8d57e2b46ce1516e889d3b3b9807c58`（140 文件，对应 `docs/FREEZE.json` revision `t34-windows-stun-ipv6-platform-reviewed`）
- 本轮修订时的 HEAD：`b56f507`（"Move the desktop to Python, stop sending the room secret, and fix Windows preflight"）

> **这份矩阵会随着代码变动过期。** 任何人改动 `peer.py`、`native/`、`python_desktop/`、`web/` 之后，必须按第 9 节的核对命令重跑，并更新本文件末尾的「取证记录」；不要沿用旧表说新树。
>
> **当前树的冻结状态（必须如实读）**：首版记录的冻结不一致**已由 t22 修正**——`tools/freeze.py` 的 `SOURCE_DIRS` 现在包含 `python_desktop`（不再有已删除的 `desktop`），`ROOT_FILES` 不再引用 `electron-builder.yml`，并新增 `REMOVED_WITH_ELECTRON_SHELL` + `assert_shell_removed()` 把「Electron 壳必须保持删除」变成断言；`tools/artifact-manifest.py` 同样改成缺失即跳过 + 同一断言（stale 引用已清）。但**本文件不是冻结值**：`docs/SOURCE-MANIFEST.json` / `docs/FREEZE.json` 的重新生成排在桌面 Qt 迁移（t24）落地、整套回归恢复全绿之后，届时以那两份文件为唯一当前清单。在那之前，本文的行号与结论属于**取证快照**，请按第 9 节自行复核。

---

## 1. 先说清楚：什么叫「一种打洞方式」

历史上出现「感觉不全面」的模糊，根因是**把不同层次的东西混在一张列表里数**。本文先把口径定死，再填表。

| 口径 | 定义 | 例子 |
|---|---|---|
| **方式条目（用户能看到的 9 条）** | `docs/METHODS-PLAIN.md` 表格里的 1–9 行，界面上逐条显示状态与实测延迟 | 「双栈直连」「UDP 探测」「路由器放行」 |
| **底层机制（mechanism）** | 真正干活的传输实现，由 `native/adapter.py` 的 `METHODS`、`python_desktop/engine.py` 的 `WEBRTC_PROFILES` 与 `observation` 枚举 | `ice-dual`、`udp-probe`、`quic`、`tcp`、`tcp-simopen` |
| **候选来源** | 地址从哪里来，不等于传输方式 | host 候选、STUN srflx 候选、网关申请到的映射候选 |
| **信令 / 观测服务** | 帮助双方交换地址或看自己的出口，**不转发任何聊天数据** | 信令 WebSocket、STUN Binding 服务 |

**三条计数红线（违反即视为把没实现的写成实现了）：**

1. **三种 ICE 配置不是一个独立协议。** `ice-dual` / `ice-v6` / `ice-v4` 是同一套 WebRTC 上的三种地址族过滤（`peer.py:51-57` 的 `allowed_candidate`/`filter_sdp`），页面文案必须这样讲，`web/ux.js` 第 1 条徽标与 `docs/UX-FLOW.md` 已经这么写。
2. **观测不是分类，探测不是传输。** STUN 映射观测只回答「外网看我是什么地址端口」；`native/stun.py:145` 明确标注 `mapped-address-only-not-nat-type`。UDP 探测是 `probe-only`，成功也只显示「已观测」。
3. **网关放行是「候选来源」，不是传输成功证明。** `native/gateway.py` 的映射在独立对端外部校验成功前一律视为未验证（该文件 docstring 原文）。

---

## 2. 证据等级（本文出现的每个等级都必须能落到证据上）

| 等级 | 含义 | 能证明什么 / 不能证明什么 |
|---|---|---|
| **L0** | 纯单元测试、mock、JVM/无浏览器模拟 | 只能证明接口与算法；**不能**证明任何真实网络行为 |
| **L1** | 本机真实进程/真实 socket/真实浏览器，含多进程与隔离 netns | 证明实现真的能跑起来并互通；**不能**证明跨 NAT/家宽/实机 |
| **L2** | 受控拓扑（独立 netns + 路由器 + stateful 防火墙 + netem 延迟丢包） | 证明在**被构造**的网络条件下工作；**不是**真实运营商网络 |
| **L3** | 真实设备/真实浏览器 + 真实操作系统（本机或 CI runner） | 证明该平台可运行；仍不等于用户家庭网络 |
| **L4** | 真实家宽、真实 CGNAT、真实路由器网关、真实手机 | 唯一能支持「用户家里能不能打通」的等级 |
| **NOT_RUN / PENDING** | 条件不具备或尚未执行 | 必须如实保留，不许用其他等级的绿灯顶替 |

`CAPABILITIES.md` 的行话翻译：**实现 ≠ 构建 ≠ 实机互通**；本机/隔离 namespace 测试 ≠ 真实家宽。

---

## 3. 当前平台盘点（谁在跑什么）

| 端 | 形态 | 代码入口 | 能启动的底层机制 | 备注 |
|---|---|---|---|---|
| **网页版（保留）** | 浏览器 WebRTC，无任意 UDP/TCP API | `web/index.html` + `web/app.js` / `web/rtc.js` | 仅 WebRTC 三 profile | 无 UDP/QUIC/TCP/网关能力，界面必须显示「不支持」 |
| **桌面版** | 纯 Python + Qt(PySide6) + PyInstaller，Electron 已删 | `python_desktop/app.py`、`python_desktop/engine.py`、`python_desktop/qt_ui.py`（Tk 版 `ui.py` 已按用户要求移除，原因见 `docs/DESKTOP-PYTHON.md`） | WebRTC 三 profile + `udp-probe` / `quic` / `tcp` / `tcp-simopen` + STUN 观测 + 网关放行（默认关闭）+ 局域网发现（默认关闭）+ 对称 NAT 端口预测（默认关闭） | 进程内直接复用 `peer.py` 与 `native/adapter.py`，不再需要 stdio bridge/asar。**Qt 迁移已完成并经独立复审 pass（t43→t44→t45，基准 HEAD `e60ba0d`）；其后的提交不在该审范围内** |
| **安卓版（当前可交付）** | Capacitor WebView 壳 | `android/`（页面资源来自 `web/`） | 仅 WebView 自带的 WebRTC | 无原生网络适配器（见 `PLATFORMS.md` 的「User-facing platform behavior」） |
| **安卓原生（第一阶段已落地）** | Kotlin + WebRTC Android SDK，无 WebView 承载 | `android-native/app/src/main/java/dev/p2pobservatory/nativeprobe/`（11 个 `.kt`，t46） | 仅 WebRTC（STUN-only ICE 配置）+ v2 加入证明 + 数据通道/限额对齐 | **本机编译 NOT_RUN（无 SDK/JDK21）、真机运行 NOT_RUN**；Capacitor APK 保留至原生对等经实机验证；见 `docs/ANDROID-NATIVE.md` |
| **服务端（信令+STUN+日志中心）** | 单进程 Python，可多 `--host` 双栈 | `server.py`、`backend/protocol.py`、`backend/telemetry.py` | 信令 WebSocket、STUN Binding、中心日志收集 | **不转发聊天**，不是中继（见第 6.8 条） |

---

## 4. 主矩阵：一条一行，能否传消息写清楚

「能否传消息」= 成功后能不能用来聊文本/图片/文件/语音。**只有 `能` 的才允许在界面显示「已打通」。**

### 4.1 用户可见的 9 条方式

| # | 界面名称 | 底层实现（真实代码位置） | 能传消息 | 网页版 | 桌面 Python 版 | 安卓 | 最高已有证据 |
|---|---|---|---|---|---|---|---|
| 1 | 双栈直连 | `ice-dual`：`peer.py:51-57`，`python_desktop/engine.py:46` | 能 | 实现/可用 | 实现/可用 | WebView 实现 | L1–L2（浏览器与 Python 双端真 socket；v6 受控拓扑） |
| 2 | IPv6 直连 | `ice-v6`：同上（只放行 v6 候选） | 能 | 实现，本机实测为超时 | 实现 | WebView 实现 | L1 负例充分；真实 v6 家宽正向 NOT_RUN |
| 3 | IPv4 直连 | `ice-v4`：同上（只放行 v4 候选） | 能 | 实现，L1 有成功 | 实现，L1 有成功 | WebView 实现 | L1（本机 LAN 跨进程/跨浏览器） |
| 4 | UDP 探测 | `udp-probe`：`native/adapter.py:43,605,621` | **不能**（probe-only） | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（v4/v6 真 socket、候选独立 nonce、单向丢包负例） |
| 5 | QUIC 加密直连 | `quic`：`native/adapter.py` + `aioquic`，同 UDP socket | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（双向 64 KiB、stateful IPv6、40 ms/5% loss 受控） |
| 6 | TCP 加密直连 | `tcp`：`native/adapter.py` mutual TLS；TCP 无独立测速道 | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1（v4/v6 socket 完整性） |
| 7 | TCP 同时打开 | `tcp-simopen`：真双端 `bind`+`connect` | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（双 netns 正例；零延迟可失败） |
| 8 | STUN 映射观测 | `python_desktop/engine.py` 的 `observe():1067` / `_stun_binding():1118`；协议实现 `native/stun.py` | **不能**（观测） | 不单独上报该行结果（随 WebRTC gathering 展示） | 实现 | 同网页 | L1（本机真实 UDP Binding）；真实 NAT 出口观测 NOT_RUN |
| 9 | 路由器放行（自动开一个端口） | 候选来源 + 显式动作：`native/gateway.py` 的 `UPnP`/`PCP`/`NATPMP`；生产入口 `native/adapter.py` 的 `gateway_capability():396`、`gateway_map():426`、`gateway_pinhole():462`、`gateway_renew():479`、`gateway_release():491` | **不能**（只开端口；`METHODS-PLAIN.md` 第 9 条列「否，它只开端口」） | 无 API → 不支持 | **已接线但默认关闭**：需显式同意，见 4.2 | 不支持 | L0/L1（受控回环 mock 协议测试 + 本机 Linux 平台能力核对可读出默认网关）；真实路由器映射 **L4 = NOT_RUN** |

> 界面文案的唯一来源 `docs/METHODS-PLAIN.md` 现在带第 6 列「能否传消息」：1–3、5–7 为「是」，4 与 8 为「否，只能探测/观测」，**第 9 条为「否，它只开端口」**。矩阵与它必须逐字一致；`p2pchat/tests/desktop/test_methods_copy.py` 会直接解析该表格核对。

### 4.2 桌面版「路由器放行」现在接到哪一步（t14 已接线，仍默认关闭）

按调用链从用户点击到真实路由器（`file:line` 为 2026-10-12 取证快照，重跑请以第 9 节为准）：

1. **目录项**：`python_desktop/methods.py:114-123` 第 9 条 `gateway` 带 `opt_in: True`，标题「路由器放行（自动开一个端口）」，与 `docs/METHODS-PLAIN.md` 第 9 行一致。
2. **能力报告不再恒报不支持**：`native/adapter.py:50` 的 `gateway_platform_capability()` 只在 Linux 且能只读核对 `/proc/net/route` 时返回 `available`，并能读出默认网关（`default_gateway_v4():64`）；其它平台返回 `unsupported` + `PLATFORM_VALIDATION_UNAVAILABLE`（Windows/macOS **fail-closed**，不猜不认识的转发规则）。`NativeAdapter.gateway_capability():396` 再叠加 `consentRequired: true`、`mockLoopbackAllowed: false`、`maxMappings: 8`、`maxLifetimeSeconds: 7200`。
3. **桌面端消费真实能力**：`python_desktop/engine.py` 的 `GATEWAY_MECHANISMS:53`、`gateway_capability():302`、`gateway_capability_line():799`、`availability_for():744`。本机 Linux 实测：`status=available`、`gateway=10.8.1.254`、`consentRequired=True`、`consented=False` → 界面第 9 行可用性=**可用**、状态=等待中、说明「需要操作者单独显式授权」、`canMessage=false`（与设置面板那句不再矛盾）。
4. **显式同意才动路由器**：`engine.gateway_consent_text():305` 给人话解释 → `engine.gateway_consent():317` → `engine.gateway_open_port():322` → `NativeAdapter.gateway_map():426`。**没有 `consent=True` 时不创建任何 socket**（直接 `PermissionError`）；启动、连接、导入 STUN 配置都不会产生映射。映射只有在独立对端外部验证通过后才算「已建立」。
5. **可撤销、有界**：`engine.gateway_close_port():338` → `gateway_renew():479` / `gateway_release():491` / `gateway_release_all():506`；租期与映射数都有上限。
6. **界面入口**：桌面设置面板的「让路由器开一个端口 / 撤销已开的端口 / 技术详情」；`python_desktop/gateway_optin.py` 保存同意状态、人话文案与审计记录。

**结论（如实）**：协议层 + 适配器 + 桌面端 + 界面**已经接线**；默认关闭、必须显式同意、只有平台可核对时（本机 Linux 实测可核对，默认网关 10.8.1.254）才报「可用」，其它平台报「不支持」并给平台原因。**但它仍然不是聊天路径**：它只申请端口映射，`canMessage=false`。**真实路由器上的映射成功与设备兼容性 = L4 NOT_RUN**——本仓库只在受控回环 mock 上测过协议，并用能力接口读出过本机网关，**从未向真实路由器发起过映射，也从未改动宿主路由/防火墙**。

> 一处已知的注释残留（不影响行为，out-of-scope 未改）：`python_desktop/version.py:10-12` 的顶部注释仍写「Gateway methods … deliberately absent … reports them unsupported」，而同一文件的 `_gateway_capability_line()` 已经改成按平台如实报告。注释与实现不一致，需在下一轮清理。

### 4.3 底层机制逐个核对（含「这条到底是谁在用」）

| mechanism | 是否真能启动 | 启动点 | 候选来源 | canMessage | benchmark 通道 |
|---|---|---|---|---|---|
| `ice-dual` / `ice-v6` / `ice-v4` | 是 | `peer.py:380-391` `initiate()`；桌面 `python_desktop/engine.py:1555` `_ensure_webrtc()` | WebRTC host/srflx/prflx（引擎内部） | 是 | 是（`peer.py:228` `install_benchmark()` 的独立 `benchmark` DataChannel） |
| `udp-probe` | 是 | `native/adapter.py:605-660` | 配对信令里的 host 候选 | 否 | 无（`native/adapter.py:1235-1241` 拒绝） |
| `quic` | 是 | 同上（`udp=True` 分支，`native/adapter.py:621`） | host，IPv4 且有显式 STUN 时追加 srflx（`native/adapter.py:645-652`） | 是 | 是（`native/adapter.py:296` 的 `capabilities()` 里 `independentBenchmark: m=="quic"`） |
| `tcp` | 是 | 同上（`SOCK_STREAM`，answerer 侧 `listen`） | host 候选，**严格单一 tuple**（`native/adapter.py:684-685` 变更即要求新尝试） | 是 | 否（无独立 lane） |
| `tcp-simopen` | 是 | 同上 + 真同时 `connect` | host 候选 | 是 | 否 |
| `upnp` / `pcp` / `natpmp` | 是（Linux 可核对 + 显式同意时；其它平台 fail-closed） | `adapter.py` 的 `gateway_map():426`（唯一生产入口，需 `consent=True`；`validate_candidate():157` 仍拒绝 `predicted` kind）；桌面 `engine.gateway_open_port():322` | 路由器申请的映射候选（外部对端验证通过才算建立） | **否**（只开端口） | 无 |
| `port-prediction`（对称 NAT 端口预测） | 是（默认关闭；仅 t10 判定「地址+端口相关」时） | `adapter.py` 的 `prediction_capability():309` / `prediction_signal():363` / `prediction_clock():859`；桌面 `engine.prediction_enable():876` | 双向样本交换（`nat-samples`，房间密钥 HMAC，不带自己的公网映射） | 是（命中后走既有认证路径） | 无（独立 lane 仍仅 quic） |

### 4.4 相邻但**不属于**打洞方式的东西（防止再次被混数）

| 名称 | 它是什么 | 为什么不算一种「打洞方式」 |
|---|---|---|
| 信令 WebSocket（`server.py`） | 房间、roster、转发 offer/answer/candidate 与 native 信令帧 | 只交换控制信息，**不转发聊天数据**；断掉后已建立的直连仍可用（`peer.py:478-482`） |
| STUN Binding 服务（服务端 `--stun-*`） | 让客户端看自己的映射地址，或作为 WebRTC 的 `iceServers` | 只观察，不是传输，也不是 NAT 分类 |
| 中心日志收集（`backend/telemetry.py`） | 客户端事件去重、ACK、补传 | 与连通性无关的诊断通道 |
| 测速（benchmark） | 在已直连的独立 lane 上测应用层吞吐 | 是「已连上以后」的测量，不是连接方式 |

---

## 5. 平台 × 机制细表（`U` = 实现但该平台/网络未验证）

| mechanism / 候选来源 | Linux 浏览器 | Linux Python 桌面 | Windows 桌面 | 安卓 WebView | 安卓原生 Kotlin | 真实家宽/网关 |
|---|---|---|---|---|---|---|
| WebRTC host v4 | L1 成功 | L1 成功 | **U**（CI 结果见第 6 节） | U | 未实现 | NOT_RUN |
| WebRTC host v6 | L1 超时（负例） | 实现，未据此声明成功 | **U** | U | 未实现 | NOT_RUN |
| STUN srflx（WebRTC） | 配置实现，真实 NAT **U** | 双栈 STUN 服务已实现 | **U** | U | 未实现 | NOT_RUN |
| prflx / triggered ICE | 引擎能力，轨迹未证实 | 引擎能力/U | U | U | 未实现 | NOT_RUN |
| UDP 精确 tuple 双向探测 | 无 API → 不支持 | L1–L2 通过 | **U** | 不支持 | 未实现 | NOT_RUN |
| QUIC 同 UDP socket | 无 API → 不支持 | L1–L2 通过 | **U** | 不支持 | 未实现 | NOT_RUN |
| TCP 直连（mutual TLS） | 无 API → 不支持 | L1 通过 | **U** | 不支持 | 未实现 | NOT_RUN |
| TCP simultaneous open | 无 API → 不支持 | L1–L2 通过 | **U** | 不支持 | 未实现 | NOT_RUN |
| UPnP IGD IPv4 映射 | 无 API → 不支持 | **已接线**；Linux 平台可核对时报「可用，需显式同意」（4.2） | 未接线到实机 → 报 `unsupported`；无实机 | 不支持 | 未实现 | NOT_RUN |
| UPnP IPv6 firewall pinhole | 无 API → 不支持 | 同上（`gateway_pinhole():462`） | 同上 | 不支持 | 未实现 | NOT_RUN |
| PCP MAP / NAT-PMP | 无 API → 不支持 | 同上（`gateway_renew/release`） | 同上 | 不支持 | 未实现 | NOT_RUN |
| 局域网直连发现（无需打洞） | 无组播 API → 不支持 | **已实现**（L1：测试用受限回环组播 + **真实第二个 OS 进程**互相发现并直连；默认关闭，需同意） | 未验证 | 不支持 | 未实现 | 真实双设备同 Wi-Fi = **L4 NOT_RUN** |
| NAT 行为分类（多 STUN 观测） | 无 API → 不支持 | **已实现**（L1：受控多 STUN 应答端点，映射/过滤行为分类；观测不足明确「无法判定」） | 未验证 | 不支持 | 未实现 | 真实家宽 NAT = **L4 NOT_RUN** |
| 对称 NAT 端口预测 | 无 API → 不支持 | **已实现**（L1：受控端点 + 接入连接流程；**默认关闭**，仅分类为「地址+端口相关」时启用） | 未验证 | 不支持 | 未实现 | 真实对称 NAT = **L4 NOT_RUN**（命中率有限，失败是正常结果） |
| TURN / 信令数据中继 | **永久禁用** | **永久禁用** | **永久禁用** | **永久禁用** | **永久禁用** | 不适用 |

平台标注的原始依据：`docs/CAPABILITIES.md:25-49`、`PLATFORMS.md` 的「User-facing platform behavior」一节、`android-native/FEASIBILITY.md`。本表与它们不冲突；冲突时以**代码取证**为准并同步修文档。

---

## 6. 证据台账（哪条结论来自哪次运行）

| 标识 | 范围 | 已观察结论 | 限制 |
|---|---|---|---|
| `verification/VERIFICATION-FINAL.md`（t7/t19） | 冻结树 135 文件版 | 本机 Linux L0/L1 + 隔离 L2 通过：72 Python、34 Node、4 真实 native 集成；四进程 echo、真停信令 63 秒、浏览器真实 UI | 真实家宽/安卓/Windows 实机 NOT_RUN；Windows CI 当时失败 |
| `docs/FREEZE.json`（t34，**历史**） | 上一轮冻结值（不是当前） | 97 Python passed（8 AppKey 警告，81.21 s，无 skip）；48 Node passed；Linux 重建 + sandbox smoke 通过 | 该清单不含 Python 桌面 Qt 迁移后的树；当前树的清单在 t24 落地后重新生成 |
| `docs/EVIDENCE-INDEX.md` | 可公开摘要 | 历史 CI `78a2050` / run 38132637106：Linux/Android success；Windows 70 passed / 6 failed / 1 skipped，无 EXE | 旧 commit 结果不继承；当前 Windows PENDING |
| `p2pchat/review/ROUND1.md`、`p2pchat/review/ROUND2.md`、`p2pchat/review/ROUND3.md` 与 `review/*/T*.md` | 独立审查（私有区，不随 GitHub 发布） | 候选 nonce、证书 pinning、STUN 窗口、native 平台修复独立复核通过 | 都是 Linux；不构成 Windows/实机证明 |
| `docs/NAT-BEHAVIOR.md`（t10） | 多观测点 NAT 映射/过滤分类 | 受控多 STUN 应答端点下分类正确；观测不足明确「无法判定」而不是猜；只访问用户显式配置的观测点 | 真实家宽 NAT 行为 = **NOT_RUN**（须用户在真实网络运行） |
| `docs/LAN-DISCOVERY.md`（t12） | 同网段组播发现 + 直接连接 | 真实 UDP 组播 socket（测试用受限模式 `restricted_local=True`）+ **真正独立的第二个 OS 进程**互相发现并完成 UDP 直连（`state=direct`，无信令、无打洞、无中继）；伪造 HMAC / 过期 nonce / 跨房间 / 洪泛四条负例被拒 | 真实双设备同 Wi-Fi = **NOT_RUN**；Windows/macOS/Android 未执行；生产模式拒绝回环 |
| `docs/PORT-PREDICTION.md`（t18）+ t21 接线 | 对称 NAT 端口预测 | 受控端点命中/未命中用例；接入连接流程（**默认关闭**，仅分类为「地址+端口相关」时启用）；双向样本经房间密钥 HMAC + 一次性 nonce，不带自己的公网映射 | 真实对称 NAT = **NOT_RUN**；命中率有限，失败是正常结果，不得写成「稳定可用」 |
| `docs/GATEWAY-OPTIN.md`（t14） | 网关放行接线到产品 | 能力按平台如实报告（Linux 可只读核对、其它平台 fail-closed）+ 默认关闭 + 显式同意门槛 + 受控回环 mock 协议测试；本机 Linux 读出默认网关 10.8.1.254 | 真实路由器映射 = **NOT_RUN**；本仓库从未改动宿主路由/防火墙 |
| `p2pchat/review/ux-desktop/REVIEW-ROUND3.md`（t27） | 第三轮独立审查 | verdict=pass：暂停文案单点、网关可用性与面板一致、STUN 四态、矩阵未被改动；实跑 450 Python / 67 desktop（含真实 Tk）/ 55 Node / 6 platform | **基准是 Tk 版 + 数据层**；Qt 迁移（t24）新增文件不在该结论覆盖范围内，须另行复审 |
| `p2pchat/tests/desktop/test_methods_copy.py`（2026-10-12 复跑） | 文案与目录一致性 | **21 passed**：`METHODS-PLAIN.md` 补齐第 6 列「能否传消息」后，本文首版记录的 3 项失败已消失 | 只证明文案一致，不证明任何网络行为 |

**必须保留的 NOT_RUN 清单**（任何汇总文档都不许把它们写成已完成）：

- 真实家宽 / 双 NAT / CGNAT / 运营商 UDP 封锁下的打洞成功；
- 真实路由器（UPnP / PCP / NAT-PMP / IPv6 pinhole）放行，及相关网关设备兼容性；
- Windows 桌面 GUI/打包/防火墙实机（CI runner 结果 ≠ 用户机器）；
- macOS 打包与运行；
- 安卓真机安装、WebView 或原生互通、录音、后台/切网/Doze；
- 真实麦克风录音（历史采集不冒充本轮实测）；
- 磁盘写满、断电、七天长跑下的日志限额行为。

---

## 7. 状态词与界面显示规则（防止「把失败说成成功」）

界面状态词只有六个，来源 `docs/METHODS-PLAIN.md:33-44`：**等待中 / 尝试中 / 已打通 / 已观测 / 不可用 / 不支持**。

| 状态 | 只允许在什么条件下出现 |
|---|---|
| 已打通 | 该路径 `state==='direct'` **且** `canMessage===true` |
| 已观测 | 仅 `probe_only` 的方式（UDP 探测、STUN 映射观测）拿到了结果，同行必须标「仅探测，不传内容」 |
| 不可用 | 试过但失败，或连接建立但未通过「可传消息」校验（`web/ux.js` 的 `pathState`） |
| 不支持 | 平台/配置用不了：浏览器与安卓无原生适配器、网关放行在不可核对的平台（Windows/macOS）fail-closed、服务器没给 STUN 地址、无 WebRTC |

任何「还没试过」或「没测到」的路径，延迟与可用性一律显示**尚未测得 / 还没出结果**，不许用 0、1 ms 或绿灯占位。

---

## 8. 缺口台账（用户觉得「不全面」的那些，逐条给状态与核实方式）

**核实方式统一为：命令能跑出结果 = 已实现；命令无输出 = 仍是缺口。**（全部在工作目录 `/home/Luorix/DATA/Project/ipv6打洞` 下执行，只读。）

| id | 缺口 | 当前状态 | 责任人 | 核实命令（有输出=已落地） | 若已落地，最高能拿到的证据 |
|---|---|---|---|---|---|
| G1 | **局域网直连发现（同网段无需打洞）** | **已落地（t12）**：`native/lan_discovery.py` + `python_desktop/lan_client.py`；默认关闭、需同意、生产模式拒绝回环 | traversal-engineer | `ls p2pchat/native/lan_discovery.py` | **L1**（测试受限回环组播 + 真实第二个 OS 进程直连）；真实双设备同 Wi-Fi = **L4 NOT_RUN** |
| G2 | **NAT 行为分类（多 STUN 观测）** | **已落地（t10）**：`native/nat_behavior.py`；只访问用户显式配置的观测点 | transport-engineer | `ls p2pchat/native/nat_behavior.py` | **L1**（受控多 STUN 应答端点）；真实家宽 = **L4 NOT_RUN** |
| G3 | **对称 NAT 端口预测** | **已落地（t18）+ 已接入连接流程（t21）**：`native/port_prediction.py`；默认关闭，仅对称型启用 | transport-engineer / traversal-engineer | `ls p2pchat/native/port_prediction.py` | **L1**（受控端点）；真实对称 NAT = **L4 NOT_RUN**；命中率有限，失败是正常结果 |
| G4 | **网关放行接线到产品** | **已落地（t14）**：适配器 `gateway_capability/map/pinhole/renew/release` + 桌面 `gateway_open_port/close_port` + 设置面板入口；默认关闭 + 显式同意 | platform-engineer | `grep -rn "gateway_map\|gateway_open_port" p2pchat/native/adapter.py p2pchat/python_desktop/` | **L0/L1**（受控回环 mock + 平台能力核对，读出默认网关）；真实路由器 = **L4 NOT_RUN** |
| G5 | **安卓原生 Kotlin** | **第一阶段已落地（t46）**：业务逻辑全在 Kotlin（11 个 `.kt`），协议按 `peer.py`/`core.js` 对齐并有 JVM 单测；Capacitor 版保留 | platform-engineer | `find p2pchat/android-native -name '*.kt' \| wc -l` | **构建与真机运行 NOT_RUN**：本机无 SDK/JDK21，CI 只跑 JVM 单测与 AAR 校验；真机 DataChannel 需用户实测 |
| G6 | **Windows 桌面实机** | **PENDING**（新版 Python+Qt 桌面的 Windows CI 结果待 captain 推送后确认；历史成功记录属于**已删除的 Electron 版**，不可继承） | captain / platform-engineer | `.github/workflows/build.yml` 的 Windows job 结论 | CI runner ≠ 用户机器；GUI/防火墙实机 NOT_RUN |
| G7 | **macOS 打包** | **未验证** | platform-engineer | `ls p2pchat/tools/build-desktop-macos.sh` | 脚本存在不等于产物可用 |
| G8 | **TURN / 中继** | **永久禁用（不是缺口）** | — | `grep -rn "turn:" p2pchat/web p2pchat/native p2pchat/peer.py p2pchat/server.py` | 应无 `turn:` 配置；出现即回归 |
| G9 | **桌面 GUI 的 Qt(PySide6) 迁移** | **已落地并经独立复审 pass（t43 needs_revision → t44 修复+重建产物 → t45 pass，基准 HEAD `e60ba0d`）**；迁移中间态曾让整套回归无法收集，现已修好且可收集 | desktop-engineer | `ls p2pchat/python_desktop/qt_ui.py; .venv/bin/python -m pytest p2pchat/tests -q` | 桌面证据从「只对 Tk 基线成立」升级为**对 Qt 版 `e60ba0d` 成立**；**之后的提交（t49/t53/t62/t61）不在该审范围内**，冻结前仍需复核 |
| G10 | **网页客户端只支持 WebSocket 信令** | **服务端已实现、客户端未接入**：HTTP/SSE（t15）无客户端使用 | client-engineer | `grep -rn "EventSource\|/events" p2pchat/web/` | 服务端能力已实现不等于产品可用；当前网页端只走 WS |

**不确定性声明（必须这么读）**：G1–G4 的状态取自 **2026-10-12 的源树取证**，并各自给出**最高证据等级**（最高只到 L1/L2，真实网络一律 NOT_RUN）。G5 已从「未实现」升级为「第一阶段已落地、构建与真机 NOT_RUN」，G9 已从「进行中」升级为「已复审 pass（基准 `e60ba0d`）」——**升级只对证据覆盖到的那次基准成立**。G6（Windows 桌面实机）、G7（macOS）、G10（网页端只走 WS）仍是**当前真实缺口**，任何汇总文档不得把它们写成已完成。新增或删除一条用户可见方式时，必须同时更新 `docs/METHODS-PLAIN.md`（界面文案唯一来源）、`web/ux.js`、`python_desktop/methods.py` 与本文矩阵——四者不同步即视为文档回归。

---

## 9. 复核方法（任何人 3 条命令内可重跑）

<!-- MATRIX-COMPARE-ANCHOR: 本节命令的机器可读版本；改动本文件时保留此注释块，便于将来做成脚本。 -->

```sh
cd /home/Luorix/DATA/Project/ipv6打洞

# 1) 9 条方式条目 + 底层机制是否与本文一致
sed -n '34,140p' p2pchat/python_desktop/methods.py | grep -c '"title"'   # 期望 9
grep -n '^METHODS' p2pchat/native/adapter.py                             # 7 项机制
grep -n 'PROFILES' p2pchat/backend/protocol.py                           # 3 个 ICE profile
grep -n '^## 状态用词' p2pchat/docs/METHODS-PLAIN.md                     # 本文第 7 节引用的位置

# 2) 缺口台账逐条核对（G1–G4 已落地；G5/G9/G10 应仍有输出）
ls p2pchat/native/lan_discovery.py p2pchat/native/nat_behavior.py p2pchat/native/port_prediction.py
ls p2pchat/python_desktop/qt_ui.py; ls p2pchat/python_desktop/ui.py     # Qt 在、Tk 不在
find p2pchat/android-native -name '*.kt' | wc -l                        # 期望 0（G5 仍未实现）
grep -rn "gateway_map\|gateway_open_port" p2pchat/native/adapter.py p2pchat/python_desktop/
grep -rn "EventSource\|/events" p2pchat/web/ || echo NO_SSE_CLIENT       # G10：客户端仍未接入 HTTP/SSE
.venv/bin/python -m pytest p2pchat/tests -q                             # 全量回归；必须能收集且全绿才算可冻结

# 3) 红线自检：不得出现 TURN/中继 配置，不得把三 profile 说成三种协议
grep -rn "turn:" p2pchat/web p2pchat/native p2pchat/peer.py p2pchat/server.py || echo NO_TURN
grep -rni "三种独立协议\|三个独立协议" p2pchat/docs p2pchat/web || echo NO_PROTOCOL_CONFUSION
```

判定：
- 命令 1 的计数变了（方式条目 ≠ 9，或 `METHODS` 数量变了）→ 必须先改 `METHODS-PLAIN.md` 与两端文案，再回来更新本表；
- 命令 2 中 G1–G4 的核实命令若**查不到**了 → 那是回归，不是「整理」；G5/G9/G10 若查得到落地证据 → 按第 8 节的「若已落地」列处理并**升格**（不许直接把实现写成通过）；
- **全量回归必须能收集且全绿** 才允许把本文当作冻结依据；收集阶段报错（例如 `ImportError: cannot import name 'ui'`）时，任何「已冻结/已通过」的写法都是假话；
- 命令 3 出现任何命中 → 视为边界回归，报 captain，不自行放宽。

**2026-10-12 实际跑分（照抄，便于将来对比）**：

```sh
sed -n '34,140p' p2pchat/python_desktop/methods.py | grep -c '"title"'   # 9
grep -n '^METHODS' p2pchat/native/adapter.py         # 43:METHODS = ("udp-probe","quic","tcp","tcp-simopen","upnp","pcp","natpmp")
grep -n 'PROFILES' p2pchat/backend/protocol.py       # 3 个 ICE profile
ls p2pchat/native/lan_discovery.py p2pchat/native/nat_behavior.py p2pchat/native/port_prediction.py   # 三个都存在（G1/G2/G3 已落地）
ls p2pchat/python_desktop/qt_ui.py; ls p2pchat/python_desktop/ui.py   # qt_ui.py 在；ui.py: No such file（G9 已落地并复审 pass）
find p2pchat/android-native -name '*.kt' | wc -l     # 11（G5 第一阶段已落地；构建/真机仍 NOT_RUN）
grep -rn "EventSource\|/events" p2pchat/web/         # NO_SSE_CLIENT（G10 仍是缺口）
grep -c "turn:" p2pchat/web/* p2pchat/native/*.py p2pchat/peer.py p2pchat/server.py 2>/dev/null | paste -sd' '   # 每个文件计数 0
.venv/bin/python -m pytest p2pchat/tests/desktop/test_methods_copy.py -q   # 21 passed
.venv/bin/python -m pytest p2pchat/tests -q   # 冻结 HEAD a5e5aaa：692 passed / 0 fail / 0 skip（144.20 秒）
```

注意第 3 节命令的退出码：`grep` 无命中时退出码是 1（这正是「没有中继」的期望结果）。做脚本判断时写成 `if grep -rn "turn:" ...; then echo REGRESSION; else echo NO_TURN; fi`，**不要**把非零退出当成命令失败。

另有一处**正常差异**需记住：`web/ux.js` 的 `methods` 比本文 4.1 多第 10 个条目（`title:'桌面网络组件'`，用于承载原生信令成员，不属于九条方式）。这是设计使然，不是矩阵缺项。

---

## 10. 给未来改动的四条硬规则

1. **先改文案源，再改代码**：`docs/METHODS-PLAIN.md` 是界面文案唯一来源；新增/删除一条方式，必须同时改 `web/ux.js`、`python_desktop/methods.py`、本文矩阵。
2. **证据等级不可跳级**：本机/受控模拟只能升到 L1/L2；写「可用」「已打通」之前先问「这是 L4 吗」，不是 L4 就写 NOT_RUN。
3. **缺口必须留在台账里**：删掉第 8 节的一行，等于声称它已实现；只有「代码已落地 + 证据已取得」才允许移出，并把证据标识写进第 6 节。
4. **不中继是产品的定义，不是配置项**：任何「连不上就自动走服务器」的改动都是产品级违规，不是功能补全。

---

## 11. 取证记录

<!-- EVIDENCE-LOG: 只追加，不重写历史行。每行=日期 | 取证者 | treeSha256/HEAD | 结论摘要。 -->

| 日期 | 取证者 | 依据（treeSha256 / HEAD） | 结论摘要 |
|---|---|---|---|
| 2026-10-11 | architect（t11） | `430471c6…07c58` / `36e7e32` | 用户可见 9 条；桌面可启动机制 4 项 native + 3 ICE profile + 观测；网关协议层已实现但**未接线**；局域网发现与 NAT 分类为 PENDING；安卓原生零 Kotlin；真实家宽/网关/实机全部 NOT_RUN |
| 2026-10-12 | architect（t13 文档轮，冻结延后） | HEAD `b56f507`（**未冻结**：清单在 Qt 迁移 t24 落地后重新生成） | 第 9 条改为「路由器放行（自动开一个端口）」并**已接线但默认关闭**（需显式同意；Linux 可核对时「可用」，其它平台 fail-closed）；G1 局域网发现 / G2 NAT 行为分类 / G3 端口预测 / G4 网关接线 **均已落地，最高证据只到 L1**；新增缺口 G9（Qt 迁移进行中、未复审）与 G10（网页端只有 WS，无 HTTP/SSE 接入）；`test_methods_copy.py` 由 3 failed 变为 **21 passed**；整套回归在收集阶段被 t24 中间态阻断，因此**本轮不生成冻结清单** |
| 2026-10-12（当晚） | architect（t13 文档轮 2，冻结仍延后） | HEAD `4ccbf59`（**仍未冻结**：captain 要求等「代码冻结」） | **G5 升级**：安卓原生 Kotlin 第一阶段已落地（t46，11 个 `.kt`，`docs/ANDROID-NATIVE.md`），构建与真机仍 NOT_RUN；**G9 升级**：Qt 迁移经 t43 needs_revision → t44 修复重建 → **t45 verdict=pass（基准 `e60ba0d`）**，收集层恢复（690 tests collected），其后的提交不在该审范围内；修正 Qt 证据表中「qt-5/qt-6 来自最终构建」「连接后截图未产出」等过期表述；本轮仍**只做文档、不生成清单** |
| 2026-10-12（终检） | architect（t13 最终冻结） | **HEAD `d07ed36c`（已冻结）**：`docs/SOURCE-MANIFEST.json` **231 文件** + `--verify` 绿；产物记录仍绑 `4ccbf59`（已复审） | 冻结清单生成 + `--verify` 绿；回归 **693 pytest passed + 62 node passed**（0 fail/0 skip）；**产物身份分层**：记录里是 `4ccbf59` 那次被 t45 复审的产物（exe `412b7d8f…`、整包 `9b54cc6c…`），本机 `dist/` 已删除，记录仍绑 `4ccbf59` 的已复审产物；G1–G5/G9 状态见第 8 节，G6/G7/G10 仍为缺口；**覆盖缺口已关闭**：`freeze.py` 现包含 `android-native`（清单里 23 个文件）并收录 `.spec`（`tools/desktop.spec` 已在清单内）；`android/` 57 个文件 |

> 更新规则：每次改动产品代码后，复制上一行、改日期与依据、只写**本次实际核对过**的内容；不要重写历史行。

### （历史）2026-10-11 记录的两条失败 —— 已于 2026-10-12 复跑确认修复

**结论更新（2026-10-12）**：`.venv/bin/python -m pytest p2pchat/tests/desktop/test_methods_copy.py -q` → **21 passed**。`docs/METHODS-PLAIN.md` 已补齐第 6 列「能否传消息」、第 9 条标题也已与 `python_desktop/methods.py` 统一，下面记录的 3 项失败全部消失。保留下面的原始取证（只作历史，勿据它判断当前状态）。

写本文时按第 9 节命令运行拷贝一致性测试，看到 3 项失败。为免下游把它误记成「矩阵文档写坏了」，此处保留**可复现的取证**：

```sh
.venv/bin/python -m pytest p2pchat/tests/desktop/test_methods_copy.py -q
# → 3 failed, 7 passed, 1 skipped
#   test_document_is_the_catalogue                  : doc_rows() == [] 期望 [1..9]
#   test_documented_order_is_the_attempt_order      : methods.py 顺序 == 文档顺序，右值为 []
#   test_no_internal_codenames_are_visible_to_users : 标题「路由器放行（UPnP / …）」命中禁用词 "upnp"
```

根因与归属（静态可判定，未修改任何产品文件）：

1. `docs/METHODS-PLAIN.md` 第 12–13 行的表头与分隔行**只有 5 列**（其他 5 列表格也一样），而测试的表格解析器要求 `len(cells) >= 6`（`tests/desktop/test_methods_copy.py:34`）。因此 `doc_rows()` 返回空列表，前两项失败是同一个根因。**该文件与 HEAD 逐字节相同**（`git diff HEAD -- p2pchat/docs/METHODS-PLAIN.md` 无输出，`git cat-file -e HEAD:…` 存在），即早于本次取证就失败。归属：client-engineer。
2. 第 3 项来自 `python_desktop/methods.py` 里第 9 条标题使用中文「路由器放行…」而非 METHODS-PLAIN.md 的英文缩写标题（`UPnP`）。`python_desktop/methods.py` 在 HEAD 中**不存在**（新文件，本组在途），与本文无关。归属：desktop-engineer。
3. 本文 `PUNCHING-MATRIX.md` 是新增文件，**不在旧清单 `docs/SOURCE-MANIFEST.json` 的 140 项里**；因此它不可能造成上述任何失败。

**当时的结论**：这是真实产品回归（文档表格结构 + 文案标题不符合既有测试契约），按分工不自行修改；已上报 captain 决定修法与重跑范围。**该回归已由对应 owner 修好，本轮复跑 21 passed（见本节顶部）。**
