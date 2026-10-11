# P2P 穿透技术全量对照矩阵（可审计）

本文回答用户的问题：**「打洞方式集成了吗？咋感觉不全面」**——把当前仓库里**真实存在**的每一条穿透路径、它落在哪个端、能不能传消息、以及证据等级，逐条摊开。

这是一份**对代码取证的说明**，不是功能承诺。判定原则只有一条：

> 表格里的每一行，都必须能在源码里指出**实际启动这条路径的位置**；指不出来的一律写进第 8 节「缺口台账」，并标注 PENDING / NOT_RUN。**没有实现的功能不写成已实现，同机与受控模拟不写成真实家宽证据。**

- 写入日期：2026-10-11（本机 Asia/Shanghai）
- 桌面版版本号（`python_desktop/version.py` 的 `VERSION`）：`0.2.0`
- 取证时的源树封存值：`docs/SOURCE-MANIFEST.json` 的 `treeSha256` = `430471c693a875b09f57154222d31a1ad8d57e2b46ce1516e889d3b3b9807c58`（140 文件，对应 `docs/FREEZE.json` revision `t34-windows-stun-ipv6-platform-reviewed`）
- 取证时的 HEAD：`36e7e32`（"Add three-screen client flow, plain-language method guide and dual-stack signaling"）

> **这份矩阵会随着代码变动过期。** 有效期绑在上面的 `treeSha256`。任何人改动 `peer.py`、`native/`、`python_desktop/`、`web/` 之后，必须按第 9 节的核对命令重跑，并更新本文件末尾的「取证记录」；不要沿用旧表说新树。

> **一处已知的冻结不一致（取证时实测）**：`p2pchat/tools/freeze.py --verify` 当前**失败**（`AssertionError: SOURCE_FREEZE_CHANGED`）。旧清单 140 项、当前源树 151 项：新增 15（含本文件与在途的 `python_desktop/` 相关文档/测试/工具）、删除 4（`p2pchat/desktop/bridge.cjs`、`p2pchat/desktop/main.cjs`、`p2pchat/desktop/preload.cjs`、`p2pchat/electron-builder.yml` —— 这 4 个路径在旧清单里存在、在磁盘上已被删除，Electron 壳已移除）、内容变更 11（`README.md`、`native/adapter.py`、`native/gateway.py`、`native/stun.py`、`package.json`、`server.py`、`tests/client/app.test.cjs`、`tests/native/test_windows_endpoints.py`、`web/{app.js,index.html,style.css}`）。另外 `freeze.py:9` 的 `SOURCE_DIRS` **不包含 `python_desktop`**，桌面版主体代码目前**根本不进源树清单**。这两条属于冻结流程问题，已上报 captain，本文不改清单。

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

1. **三种 ICE 配置不是一个独立协议。** `ice-dual` / `ice-v6` / `ice-v4` 是同一套 WebRTC 上的三种地址族过滤（`peer.py:39-45` 的 `allowed_candidate`/`filter_sdp`），页面文案必须这样讲，`web/ux.js` 第 1 条徽标与 `docs/UX-FLOW.md` 已经这么写。
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
| **桌面版（本组改版中）** | 纯 Python + Tkinter + PyInstaller，Electron 已删 | `python_desktop/app.py`、`python_desktop/engine.py`、`python_desktop/ui.py` | WebRTC 三 profile + `udp-probe` / `quic` / `tcp` / `tcp-simopen` + STUN 观测 | 进程内直接复用 `peer.py` 与 `native/adapter.py`，不再需要 stdio bridge/asar |
| **安卓版（当前可交付）** | Capacitor WebView 壳 | `android/`（页面资源来自 `web/`） | 仅 WebView 自带的 WebRTC | 无原生网络适配器，见 `PLATFORMS.md:33` |
| **安卓原生（目标形态）** | Kotlin + WebRTC Android SDK | `android-native/` | **零 Kotlin 源码**，只有 Gradle 骨架与 `android-native/app/src/main/AndroidManifest.xml` | `android-native/FEASIBILITY.md`：manifest 指向不存在的 `.MainActivity`；可行性=可行，功能对等=未开始 |
| **服务端（信令+STUN+日志中心）** | 单进程 Python，可多 `--host` 双栈 | `server.py`、`backend/protocol.py`、`backend/telemetry.py` | 信令 WebSocket、STUN Binding、中心日志收集 | **不转发聊天**，不是中继（见第 6.8 条） |

---

## 4. 主矩阵：一条一行，能否传消息写清楚

「能否传消息」= 成功后能不能用来聊文本/图片/文件/语音。**只有 `能` 的才允许在界面显示「已打通」。**

### 4.1 用户可见的 9 条方式

| # | 界面名称 | 底层实现（真实代码位置） | 能传消息 | 网页版 | 桌面 Python 版 | 安卓 | 最高已有证据 |
|---|---|---|---|---|---|---|---|
| 1 | 双栈直连 | `ice-dual`：`peer.py:39-45`，`python_desktop/engine.py:42` | 能 | 实现/可用 | 实现/可用 | WebView 实现 | L1–L2（浏览器与 Python 双端真 socket；v6 受控拓扑） |
| 2 | IPv6 直连 | `ice-v6`：同上（只放行 v6 候选） | 能 | 实现，本机实测为超时 | 实现 | WebView 实现 | L1 负例充分；真实 v6 家宽正向 NOT_RUN |
| 3 | IPv4 直连 | `ice-v4`：同上（只放行 v4 候选） | 能 | 实现，L1 有成功 | 实现，L1 有成功 | WebView 实现 | L1（本机 LAN 跨进程/跨浏览器） |
| 4 | UDP 探测 | `udp-probe`：`native/adapter.py:37,233,241,330` | **不能**（probe-only） | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（v4/v6 真 socket、候选独立 nonce、单向丢包负例） |
| 5 | QUIC 加密直连 | `quic`：`native/adapter.py` + `aioquic`，同 UDP socket | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（双向 64 KiB、stateful IPv6、40 ms/5% loss 受控） |
| 6 | TCP 加密直连 | `tcp`：`native/adapter.py` mutual TLS；TCP 无独立测速道 | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1（v4/v6 socket 完整性） |
| 7 | TCP 同时打开 | `tcp-simopen`：真双端 `bind`+`connect` | 能 | 无 API → 不支持 | 实现 | 无适配器 → 不支持 | L1–L2（双 netns 正例；零延迟可失败） |
| 8 | STUN 映射观测 | `python_desktop/engine.py:639-732` 的 `observe()` / `_stun_binding()`；协议实现 `native/stun.py` | **不能**（观测） | 不单独上报该行结果（随 WebRTC gathering 展示） | 实现 | 同网页 | L1（本机真实 UDP Binding）；真实 NAT 出口观测 NOT_RUN |
| 9 | 路由器放行（UPnP / PCP / NAT-PMP / IPv6 放行） | `native/gateway.py` 的 `UPnP`/`PCP`/`NATPMP`（协议编解码级实现） | 潜在能，**当前不可达** | 无 API → 不支持 | **不接线**：适配器固定报不支持，见 4.2 | 不支持 | L0（回环 mock 协议测试）；真实网关 NOT_RUN |

### 4.2 桌面版「路由器放行」到底是停在哪一步（最容易被问的一条）

按调用链从用户点击到真实路由器：

1. `python_desktop/methods.py:34-110` 第 9 条 `gateway` 带 `opt_in: True`；`engine.py:427-430` 与 `engine.py:581-585` 在没有显式授权时直接把状态写成 `unsupported` + `OPT_IN_GATEWAY_API_ONLY`。
2. 即使被授权，`engine.py:600-605` 只从 `NativeAdapter.capabilities()` 里找对应机制；而 `native/adapter.py:106-113` 对 `upnp`/`pcp`/`natpmp` **恒定返回 `status="unsupported"`**。
3. `native/adapter.py:232-235` 的 `Attempt.start()` 对不在 `{udp-probe, quic, tcp, tcp-simopen}` 里的机制直接 `transition("unsupported")`。
4. `native/gateway.py` 里的 `GatewayPolicy`/`PCP`/`NATPMP`/`UPnP` **没有任何生产调用点**：全仓库只有 `p2pchat/tests/native/test_gateway.py` 与 `p2pchat/tests/native/test_candidate_repair.py` 引用它。
5. `python_desktop/version.py:9-14` 明确写：网关机制**刻意不在** `NATIVE_MECHANISMS` 里，"reports them unsupported unless an operator opts in out of band"；`capability_lines()` 直接输出「路由器放行……：不支持」。

**结论（如实）**：UPnP / PCP / NAT-PMP / IPv6 pinhole 的**协议编解码、租期、续租、删除、fail-closed 授权校验已实现并只在回环 mock 上测过（L0）**，但**从产品界面到适配器这条线没有接通**，也没有任何真实网关证据（L4 = NOT_RUN）。因此当前用户在任何端都**无法**让产品去改自己的路由器。

### 4.3 底层机制逐个核对（含「这条到底是谁在用」）

| mechanism | 是否真能启动 | 启动点 | 候选来源 | canMessage | benchmark 通道 |
|---|---|---|---|---|---|
| `ice-dual` / `ice-v6` / `ice-v4` | 是 | `peer.py:305-316` `initiate()`；桌面 `engine.py:1045-1062` `_ensure_webrtc` | WebRTC host/srflx/prflx（引擎内部） | 是 | 是（`peer.py:175-202` 独立 `benchmark` DataChannel） |
| `udp-probe` | 是 | `adapter.py:232-271` | 配对信令里的 host 候选 | 否 | 无（`adapter.py:637-644` 拒绝） |
| `quic` | 是 | 同上（`udp=True` 分支，`adapter.py:241`） | host，IPv4 且有显式 STUN 时追加 srflx（`adapter.py:262-270`） | 是 | 是（`capabilities` 里 `independentBenchmark: m=="quic"`） |
| `tcp` | 是 | 同上（`SOCK_STREAM`，answerer 侧 `listen`） | host 候选，**严格单一 tuple**（`adapter.py:304-305` 变更即要求新尝试） | 是 | 否（无独立 lane） |
| `tcp-simopen` | 是 | 同上 + 真同时 `connect` | host 候选 | 是 | 否 |
| `upnp` / `pcp` / `natpmp` | **否（当前不可达）** | 无（见 4.2） | — | — | — |

### 4.4 相邻但**不属于**打洞方式的东西（防止再次被混数）

| 名称 | 它是什么 | 为什么不算一种「打洞方式」 |
|---|---|---|
| 信令 WebSocket（`server.py`） | 房间、roster、转发 offer/answer/candidate 与 native 信令帧 | 只交换控制信息，**不转发聊天数据**；断掉后已建立的直连仍可用（`peer.py:397-401`） |
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
| UPnP IGD IPv4 映射 | 无 API → 不支持 | 协议实现；**未接线**（4.2） | 未接线 | 不支持 | 未实现 | NOT_RUN |
| UPnP IPv6 firewall pinhole | 无 API → 不支持 | 同上 | 未接线 | 不支持 | 未实现 | NOT_RUN |
| PCP MAP / NAT-PMP | 无 API → 不支持 | 同上 | 未接线 | 不支持 | 未实现 | NOT_RUN |
| 局域网直连发现（无需打洞） | 无组播 API | **未实现（PENDING，见第 8 节）** | 未实现 | 不支持 | 未实现 | NOT_RUN |
| NAT 行为分类 / 端口预测 | 无 API | **未实现（PENDING）** | 未实现 | 不支持 | 未实现 | NOT_RUN |
| TURN / 信令数据中继 | **永久禁用** | **永久禁用** | **永久禁用** | **永久禁用** | **永久禁用** | 不适用 |

平台标注的原始依据：`docs/CAPABILITIES.md:27-42`、`PLATFORMS.md:33`、`android-native/FEASIBILITY.md`。本表与它们不冲突；冲突时以**代码取证**为准并同步修文档。

---

## 6. 证据台账（哪条结论来自哪次运行）

| 标识 | 范围 | 已观察结论 | 限制 |
|---|---|---|---|
| `verification/VERIFICATION-FINAL.md`（t7/t19） | 冻结树 135 文件版 | 本机 Linux L0/L1 + 隔离 L2 通过：72 Python、34 Node、4 真实 native 集成；四进程 echo、真停信令 63 秒、浏览器真实 UI | 真实家宽/安卓/Windows 实机 NOT_RUN；Windows CI 当时失败 |
| `docs/FREEZE.json`（t34） | 当前冻结值 | 97 Python passed（8 AppKey 警告，81.21 s，无 skip）；48 Node passed；Linux 重建 + sandbox smoke 通过 | 同机 Linux；Windows 待 captain 新推送 |
| `docs/EVIDENCE-INDEX.md` | 可公开摘要 | 历史 CI `78a2050` / run 38132637106：Linux/Android success；Windows 70 passed / 6 failed / 1 skipped，无 EXE | 旧 commit 结果不继承；当前 Windows PENDING |
| `p2pchat/review/ROUND1.md`、`p2pchat/review/ROUND2.md`、`p2pchat/review/ROUND3.md` 与 `review/*/T*.md` | 独立审查（私有区，不随 GitHub 发布） | 候选 nonce、证书 pinning、STUN 窗口、native 平台修复独立复核通过 | 都是 Linux；不构成 Windows/实机证明 |
| 本文 4.2 的网关结论 | 代码静态取证 | `p2pchat/native/gateway.py` 无生产调用点；适配器恒报 unsupported | 结论是「不可达」这一负向事实，不需要运行即可判定 |

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

界面状态词只有六个，来源 `docs/METHODS-PLAIN.md:30-41`：**等待中 / 尝试中 / 已打通 / 已观测 / 不可用 / 不支持**。

| 状态 | 只允许在什么条件下出现 |
|---|---|
| 已打通 | 该路径 `state==='direct'` **且** `canMessage===true` |
| 已观测 | 仅 `probe_only` 的方式（UDP 探测、STUN 映射观测）拿到了结果，同行必须标「仅探测，不传内容」 |
| 不可用 | 试过但失败，或连接建立但未通过「可传消息」校验（`web/ux.js` 的 `pathState`） |
| 不支持 | 平台/配置用不了：浏览器与安卓无原生适配器、安卓不支持路由器放行、服务器没给 STUN 地址、无 WebRTC |

任何「还没试过」或「没测到」的路径，延迟与可用性一律显示**尚未测得 / 还没出结果**，不许用 0、1 ms 或绿灯占位。

---

## 8. 缺口台账（用户觉得「不全面」的那些，逐条给状态与核实方式）

**核实方式统一为：命令能跑出结果 = 已实现；命令无输出 = 仍是缺口。**（全部在工作目录 `/home/Luorix/DATA/Project/ipv6打洞` 下执行，只读。）

| id | 缺口 | 当前状态 | 责任人 | 核实命令（有输出=已落地） | 若已落地，最高能拿到的证据 |
|---|---|---|---|---|---|
| G1 | **局域网直连发现（同网段无需打洞）** | **PENDING**（任务 t12 in_progress；`native/lan_discovery.py` 不存在） | traversal-engineer | `ls p2pchat/native/lan_discovery.py` | 至多 L1（本机受限组播/回环）；真实双设备同 Wi-Fi = L4 NOT_RUN |
| G2 | **NAT 行为分类（多 STUN 观测）** | **PENDING**（任务 t10 claimed；`native/nat_behavior.py` 不存在） | transport-engineer | `ls p2pchat/native/nat_behavior.py` | 至多 L0/L1（受控 STUN 应答端点）；真实家宽 = L4 NOT_RUN |
| G3 | **对称 NAT 端口预测打洞** | **未实现**（无对应模块；G2 是它的前置） | 未指派 | `grep -rn "port.predict\|对称" p2pchat/native/` | 同上；且对称 NAT 不能承诺成功 |
| G4 | **网关放行接线到产品** | **未接线**（协议层已实现，见 4.2） | 未指派 | `grep -rn "from .gateway\|import gateway" p2pchat/native/adapter.py p2pchat/python_desktop/` | 至多 L1；真实路由器 = L4 NOT_RUN |
| G5 | **安卓原生 Kotlin** | **未实现**（只有 Gradle 骨架） | platform-engineer | `find p2pchat/android-native -name '*.kt'` | 本机无 SDK/JDK 21：APK 构建与模拟器 DataChannel 均 NOT_RUN |
| G6 | **Windows 桌面（PyInstaller）实机** | **PENDING** | platform-engineer / captain | `.github/workflows/` 的 Windows job 结论 | CI runner ≠ 用户机器；GUI/防火墙实机 NOT_RUN |
| G7 | **macOS 打包** | **未验证** | platform-engineer | `ls p2pchat/tools/build-desktop-macos.sh` | 脚本存在不等于产物可用 |
| G8 | **TURN / 中继** | **永久禁用（不是缺口）** | — | `grep -rn "turn:" p2pchat/web/ p2pchat/native/ p2pchat/peer.py` | 应无 `turn:` 服务器配置；出现即回归 |

**不确定性声明（必须这么读）**：G1/G2 的落地状态取自**取证时刻**的源树，两条任务当时处于 in_progress/claimed；本文不预判它们的结果，也不把它们计入当前能力。**若将来它们合并，本文 4.1 的第 9 条之后需要新增第 10/11 条**，并且必须同时更新 `docs/METHODS-PLAIN.md`（界面文案唯一来源）、`web/ux.js`、`python_desktop/methods.py` 与本文矩阵——四者不同步即视为文档回归。

---

## 9. 复核方法（任何人 3 条命令内可重跑）

<!-- MATRIX-COMPARE-ANCHOR: 本节命令的机器可读版本；改动本文件时保留此注释块，便于将来做成脚本。 -->

```sh
cd /home/Luorix/DATA/Project/ipv6打洞

# 1) 9 条方式条目 + 底层机制是否与本文一致
sed -n '34,110p' p2pchat/python_desktop/methods.py            # 9 条 human title
grep -n '^METHODS' p2pchat/native/adapter.py                  # native 7 项
grep -n 'PROFILES' p2pchat/backend/protocol.py               # 3 个 ICE profile

# 2) 缺口台账是否仍然成立（无输出=仍是缺口）
ls p2pchat/native/lan_discovery.py p2pchat/native/nat_behavior.py 2>&1
find p2pchat/android-native -name '*.kt'
grep -rn "gateway" p2pchat/native/adapter.py p2pchat/python_desktop/engine.py

# 3) 红线自检：不得出现 TURN/中继 配置，不得把三 profile 说成三种协议
grep -rn "turn:" p2pchat/web p2pchat/native p2pchat/peer.py p2pchat/server.py || echo NO_TURN
grep -rni "三种独立协议\|三个独立协议" p2pchat/docs p2pchat/web || echo NO_PROTOCOL_CONFUSION
```

判定：
- 命令 1 的计数变了（方式条目 ≠ 9，或 `METHODS` 数量变了）→ 必须先改 `METHODS-PLAIN.md` 与两端文案，再回来更新本表；
- 命令 2 出现新文件 → 用第 8 节的「若已落地」列处理，补证据并**升格**（不许直接把实现写成通过）；
- 命令 3 出现任何命中 → 视为边界回归，报 captain，不自行放宽。

**写本文时的实际跑分（照抄，便于将来对比）**：

```sh
sed -n '34,110p' p2pchat/python_desktop/methods.py   # 9 条 title，与本文 4.1 逐字一致
grep -n '^METHODS' p2pchat/native/adapter.py         # 37:METHODS = ("udp-probe","quic","tcp","tcp-simopen","upnp","pcp","natpmp")
grep -n 'PROFILES' p2pchat/backend/protocol.py       # 7:PROFILES=('ice-v6','ice-v4','ice-dual')
ls p2pchat/native/lan_discovery.py p2pchat/native/nat_behavior.py 2>&1   # 两条 No such file（G1/G2 仍成立）
find p2pchat/android-native -name '*.kt' | wc -l     # 0（G5 仍成立）
grep -rn "gateway" p2pchat/native/adapter.py p2pchat/python_desktop/engine.py   # 只有 adapter.py:3 注释 + 4.2 描述的 fail-closed 分支
grep -c "turn:" p2pchat/web/* p2pchat/native/*.py p2pchat/peer.py p2pchat/server.py 2>/dev/null | paste -sd' '  # 每个文件计数 0
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

> 更新规则：每次改动产品代码后，复制上一行、改日期与依据、只写**本次实际核对过**的内容；不要重写历史行。

### 取证时观察到的两条现存失败（不是本文件引入的）

写本文时按第 9 节命令运行拷贝一致性测试，看到 3 项失败。为免下游把它误记成「矩阵文档写坏了」，此处保留**可复现的取证**：

```sh
.venv/bin/python -m pytest p2pchat/tests/desktop/test_methods_copy.py -q
# → 3 failed, 7 passed, 1 skipped
#   test_document_is_the_catalogue                  : doc_rows() == [] 期望 [1..9]
#   test_documented_order_is_the_attempt_order      : methods.py 顺序 == 文档顺序，右值为 []
#   test_no_internal_codenames_are_visible_to_users : 标题「路由器放行（UPnP / …）」命中禁用词 "upnp"
```

根因与归属（静态可判定，未修改任何产品文件）：

1. `docs/METHODS-PLAIN.md` 第 12–13 行的表头与分隔行**只有 5 列**（其他 5 列表格也一样），而测试的表格解析器要求 `len(cells) >= 6`（`tests/desktop/test_methods_copy.py:29`）。因此 `doc_rows()` 返回空列表，前两项失败是同一个根因。**该文件与 HEAD 逐字节相同**（`git diff HEAD -- p2pchat/docs/METHODS-PLAIN.md` 无输出，`git cat-file -e HEAD:…` 存在），即早于本次取证就失败。归属：client-engineer。
2. 第 3 项来自 `python_desktop/methods.py` 里第 9 条标题使用中文「路由器放行…」而非 METHODS-PLAIN.md 的英文缩写标题（`UPnP`）。`python_desktop/methods.py` 在 HEAD 中**不存在**（新文件，本组在途），与本文无关。归属：desktop-engineer。
3. 本文 `PUNCHING-MATRIX.md` 是新增文件，**不在旧清单 `docs/SOURCE-MANIFEST.json` 的 140 项里**；因此它不可能造成上述任何失败。

**结论**：这是真实产品回归（文档表格结构 + 文案标题不符合既有测试契约），按分工不自行修改；已上报 captain 决定修法与重跑范围。
