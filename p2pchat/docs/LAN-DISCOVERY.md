# 局域网直连发现（同一 Wi-Fi 下不用打洞）

日期：2026-10-11。范围：本机 Linux 上的真实 UDP 组播 socket（回环受限模式）+ 一个真正独立的第二个进程；**不含**真实双设备同 Wi-Fi 的证据，也不含 Windows/macOS/Android 实机。

## 人话说明（界面文案来源）

同一个 Wi-Fi / 同一个网段里的两台设备本来就能互相发数据包，根本不需要打洞、也不需要信令服务器牵线。这个功能就是**在局域网里喊一嗓子**：谁跟我在同一个房间、同一个网段，就回个话，把「我监听哪个端口」告诉对方，然后两边直接连。喊话用的是组播（只在本网段内传播，路由器不会转发出去），每句话都带一个用房间密钥算出来的签名，所以同网段的其他设备即使听到了，也听不懂、也插不进来。

界面上的名称建议：**「同一网络直连（不用打洞）」**；
一句话解释：「你和对方在同一个 Wi-Fi 下，直接连就行，不需要打洞、也不经过服务器。」
浏览器版必须显示「**不支持**」并给出原因（浏览器没有 UDP/组播接口），不能假装可用。

## 交换了什么（最小信息）

组播报文只有一个 JSON 帧，字段固定七个：

```
{"v":1,"scope":<房间作用域标签>,"nonce":<一次性随机数>,"ts":<时间戳>,
 "port":<对方直连监听端口>,"identity":<身份指纹>,"mac":<认证标签>}
```

| 字段 | 含义 | 为什么可以发 |
|---|---|---|
| `scope` | 房间作用域标签 = `HMAC(房间密钥派生的LAN密钥, "p2pobs-lan-scope-v1:" + 房间名)` 的前 32 个十六进制字符 | 是派生标签，**房间名原文和房间密钥都不发** |
| `nonce` | 每次喊话新生成的 32 字节随机数 | 用于拒绝重放，不是秘密 |
| `ts` | 发送时的墙上时钟（秒） | 只用于新鲜度窗口（默认 ±120 秒） |
| `port` | 对方希望我们直连过去的 UDP 端口 | 连接必需；不是秘密 |
| `identity` | 身份指纹 = 本进程临时公钥 DER 的 SHA-256 | 只发公钥指纹，私钥永不出进程 |
| `mac` | 对以上所有字段（含 `scope`）的 HMAC-SHA256，密钥是从房间密钥域分离派生的 LAN 密钥 | 不可伪造；**没有任何字段可被替换** |

**地址不发**：对方地址一律取「收到数据包的源地址」，报文里写什么地址都不采信。
**不发的内容**：房间密钥、房间名原文、证书（PEM）、聊天/图片/文件/录音内容、文件名、任何用户数据。诊断与事件里同样没有这些内容（`stats()` 只有派生标签与计数器）。

## 拒绝规则（都在产生候选之前）

1. **伪造/未认证**：MAC 不匹配 → `mac`。
2. **跨房间**：作用域标签不匹配 → `scope`；同名房间但密钥不同，标签不同，且伪造标签仍需密钥算 MAC。
3. **过期**：`|now - ts| > 120s` → `stale`。
4. **重放**：同一身份 + 同一 nonce 第二次出现 → `replay`（有界缓存，最多 256 条）。
5. **自己**：本机组播回环 → `selfAnnounce`，绝不当成对端。
6. **洪泛**：超速报文在任何 HMAC 计算之前就被丢弃 → `rateLimited`。
7. **候选不合法**：源地址/端口没通过既有 `validate_candidate` → `invalidCandidate`。

## 有界与可关闭

| 边界 | 值 | 说明 |
|---|---|---|
| 发送速率 | 4 条/秒 | `MAX_SEND_PER_SECOND`，实际默认每 2 秒喊一次（带抖动） |
| 响应速率 | 4 条/秒，且每个来源 2 秒内最多 1 条 | 只在**学到新对端或对端地址端口变化**时才响应；响应只发到固定的链路本地组播组，**不会**发到任意单播源地址，因此不能被当成反射放大器，也不会形成来回响应风暴 |
| 入站处理 | 64 条/秒（全局）+ 每来源 16 条/秒 | 超限先丢，不进入解析与 HMAC |
| 跟踪来源 | 64 个（LRU 淘汰） | 表长有上限，攻击者换源地址不能撑爆内存 |
| 对端数量 | 32 个（最久未见淘汰，TTL 90 秒） | `MAX_PEERS`，候选数量同上限 |
| nonce 缓存 | 256 条 | 有界先进先出 |
| 报文大小 | 512 字节 | 超大直接 `malformed` |
| 计数器 | 整数饱和（上限 2^20） | 只有计数器，不存报文正文 |

**明确关闭**：`await LanDiscovery.close()` 会取消两个后台任务、关闭 socket、清空派生密钥（`self.key = b""`）与临时私钥、清空对端/nonce/限速表；关闭后再收到有效报文不会复活服务。`LanPolicy(enabled=False)` 时 `start()` 直接 `PermissionError("LAN_DISCOVERY_DISABLED")`（**默认即关闭**，必须显式打开）。

## 浏览器（无 UDP/组播接口）

`lan_capability(runtime="browser")` 与运行时检测会返回：

```json
{"mechanism":"lan-direct","status":"unsupported","reason":"NO_UDP_MULTICAST_API","canMessage":false}
```

服务层同样拒绝启动：`await LanDiscovery(policy, runtime="browser").start()` 抛 `NotImplementedError("NO_UDP_MULTICAST_API")`，`stats()["status"] == "unsupported"`，不会创建 socket、不会返回任何候选。缺少 IP 组播常量的运行环境（如 Pyodide）走同一条路径。

## 不破坏既有身份与作用域边界

- 发现出来的端点被包装成候选前，**必须**通过既有 `p2pchat.native.adapter.validate_candidate`：未指定地址（`0.0.0.0`）、组播地址、`255.255.255.255`、链路本地（`169.254.0.0/16`、`fe80::/10`）、带接口 scope 的地址、非法端口都会抛错。测试同时用信令侧 schema（`p2pchat.backend.protocol.signal` 的 `nativeCandidate` 校验）再验证一遍，确认两层规则都没放宽。
- 本模块**不改** `server.py`、`peer.py`、`backend/protocol.py`，也没有新增/修改任何信令作用域规则。
- 不做中继：收到别人的报文只用于本地判断，绝不转发；响应是**自己**生成的一条新报文，发到固定的组播组。
- 不访问第三方：只发到 `239.0.0.0/8` 里选定的组播组（默认 `239.255.42.99`，TTL=1，路由器不转发），不做任何互联网探测或未知地址扫描。
- 不改宿主网络配置：只 `join` 组播组，不写路由、不改防火墙。

## 已知限制（不绕过）

1. **只支持 IPv4 组播发现**。IPv6 链路上的对端只会以链路本地源地址（`fe80::/10`）出现，而候选 schema 明确拒绝链路本地地址、也不协商 IPv6 接口 scope；因此本任务把 IPv6 局域网发现列为**不支持**（`LAN_IPV6_LINK_LOCAL_UNUSABLE`），而不是放宽规则或猜 scope。
2. **真实双设备同 Wi-Fi 的发现与连接 = NOT_RUN**。测试里的回环组播（`restricted_local=True`，测试专用模式）只能证明协议与实现是对的，**不能**当成家宽/局域网证据。生产模式下 `restricted_local` 必须为 `False` 且接口不能是回环地址，否则 `validate()` 直接拒绝（`LOOPBACK_REQUIRES_RESTRICTED_LOCAL` / `RESTRICTED_LOCAL_MUST_BE_LOOPBACK`）。
3. **Windows / macOS / Android 实机 = NOT_RUN**。源码与边界检查已就位，但未在这些平台执行；`IP_MULTICAST_*` 常量缺失时能力接口会报 `unsupported`。
4. **证书描述交换仍走原有的点对点控制面**。局域网发现只负责给出「地址 + 端口」，QUIC/TCP 通道需要的证书描述仍由原有本地 `signal()` 交换（没有服务器、没有中继）；「局域网内完全无服务器的证书交换」不在本任务范围。
5. **MAC 只覆盖报文内容，地址一律不采信报文**，所以同网段攻击者把一条**尚在新鲜度窗口内、且比原发送者先到**的合法报文从别的源地址抢先塞进来，可以在 120 秒内为那个身份伪造出一个错误端点。随后真正建连时仍要过房间密钥握手（证书通道还要比对固定指纹），因此**无法冒充聊天内容**，最多浪费一次尝试。要绑定源地址就必须采信发送方自报地址，本任务有意拒绝这种信任模型。

## 集成方式

```python
from p2pchat.native.lan_discovery import LanDiscovery, LanPolicy, lan_capability

capability = lan_capability()                     # 界面第 2 屏直接显示可用/不支持
discovery = LanDiscovery(LanPolicy(
    room=room, secret=room_secret, peer_id=my_peer_id,
    listen_port=my_adapter_candidate_port,        # 本端适配器实际绑定的端口
    interface="192.168.1.23",                     # 显式指定本机局域网接口地址
    enabled=True, restricted_local=False))        # 生产默认关闭，需用户明确打开
status = await discovery.start()                  # 只用组播，不连信令服务器
peer = (await wait_for_peers(discovery))[0]       # 有界快照，含地址/端口/身份指纹
candidate = peer.candidate()                       # 已通过既有候选校验
await adapter.signal({... "nativeCandidate": candidate})   # 本地调用，不是服务器
```

- `peers()` 返回有界快照（最多 32 个，最久未见先淘汰，读取时顺带清理过期项）。
- `candidates()` 直接给出可喂给本机适配器的候选。
- `subscribe(handler)` 只会在对端**新增或地址端口变化**时发 `lan-peer` 事件，并只在启动/关闭/不支持时发 `lan-status`；事件里没有密钥与用户内容。
- `stats()` 给出计数器、边界值和 `observability.evidence = REAL_LAN_REQUIRES_TWO_DEVICES_NOT_RUN`。

建议在界面「尝试打洞」那一屏把这一项排在**最前面**：同一 Wi-Fi 下先试它，成功就不必打洞；失败再按 [METHODS-PLAIN](METHODS-PLAIN.md) 的顺序继续。它与打洞方式并列，但**不是**打洞，也不要把它说成独立的 ICE 变体。

## 可复现命令与结果

```
.venv/bin/python -m pytest p2pchat/tests/native/test_lan_discovery.py -q   → 18 passed
.venv/bin/python -m pytest p2pchat/tests/native -q                          → 115 passed
.venv/bin/python -m pytest p2pchat/tests/native -q --ignore=p2pchat/tests/native/test_nat_behavior.py  → 92 passed
```

本机（Linux，Python 3.12.14，`.venv`）实际观察：本任务文件 18/18 通过，连续重复 3 次结果一致；native 全量 115 条全部通过（= 既有 74 条 + 本任务 18 条 + 并行任务 t10 当时新增的 23 条；`--ignore` 并行文件后为 92 条），**没有新增 skip，也没有弱化任何既有断言**。执行期间 t10 的文件曾处于编辑中间态并失败 1 条（`test_nat_behavior.py::test_classify_filtering_edges`），t10 完成后重跑已全绿——该失败与本任务三个文件无关，且未被我掩盖或跳过。t10 仍在追加测试，因此全量条数会随后续变更上升，本任务自身的 18 条与既有 74 条不随之改变。
其中 `test_cross_process_multicast_discovery_and_direct_connection` 真的起了**第二个 OS 进程**：父进程与子进程各自只从组播报文里学到对方的地址与端口，然后各自调用本机适配器完成 UDP 直连（`state == "direct"`，双方一致），全程没有信令服务器、没有打洞、没有中继；子进程退出码 0。
`test_discovered_candidate_carries_a_message_lane` 用发现出来的候选把 QUIC 通道打通并双向传输 4 KiB 校验一致（证书描述来自本进程本地事件总线，没有服务器）。

## 桌面端接线（t14：让本页能力在纯 Python 桌面端真正可用）

协议层（`native/lan_discovery.py`）一直是默认 `enabled=False`、生产拒绝回环；
本任务补的是**桌面端的生产调用点**，不改协议层。

| 层 | 生产调用点 |
| --- | --- |
| 桌面控制器 | `python_desktop/lan_client.py::LanDirect`（能力文案、同意、审计、候选校验） |
| 引擎 | `python_desktop/engine.py::lan_enable()` / `lan_disable()` / `lan_capability()` / `lan_diagnostics()` |
| 界面 | 设置面板：“开启同网段直连发现 / 关闭同网段直连发现”，默认关闭 |

规则（与协议层一致，没有放宽）：

* **默认关闭**：不连接、不启动、不导入 STUN 都不会开始组播；开启要单独点一次并在确认框里点“是”
  （确认框文案见 `LanDirect.consent_text()`，人话说明“只在本网段、用房间密码派生密钥签名、随时可关”）；
* **需要一条真实在听的端口**：广告的端口必须来自已经绑定的原生尝试（UDP/QUIC）。
  还没有可用路径时会明确提示“先在第二条屏幕等到有可用路径”，不会编造一个端口；
* **接口必须是真实网卡地址**：`primary_ipv4()` 只用 UDP connect（不发包）取默认出口地址，
  拿不到就报 `NO_LAN_INTERFACE`；回环只在显式 `restricted_local=True`（测试模式）下允许，
  且这种候选会被标记 `testOnly: true`，**绝不当成局域网证据**；
* **候选不放宽**：`LanDirect.accept_candidate()` 先调用与信令路径同一个 `validate_candidate()`，
  再额外拒绝生产路径上的回环地址；伪造字段/非法端口/组播地址一律拒绝；
* **审计**（`{"kind": "lan-direct", "action": ...}`，不含密钥）：`enable-requested` / `enabled` /
  `enable-denied`（未同意、平台不支持、没有网卡）/ `enable-failed` / `status`（来自 `lan-status`）/
  `peer-found` / `peer-rejected`（含具体原因）/ `disabled`（带之前发现的设备数）。

测试（`p2pchat/tests/desktop/test_lan_wiring.py`）：

* 默认关闭 + 未同意时**连发现实例都不创建**（工厂记录器证明）；
* 生产路径拒绝回环接口与回环候选，非法候选一律 `INVALID_CANDIDATE`；
* **受控组播“发现→直连”一次**：两个本机实例（`restricted_local=True`）互相发现，
  然后把数据真正发到发现到的候选端口并由对端监听端口收到，最后关闭并断言不再运行。

**未验证**：真实同网段设备之间的发现与直连（需要用户环境；本机只有回环测试模式），
以及 Windows/macOS 上的表现。

## 变更文件与 sha256

| 文件 | 行数 | sha256 |
|---|---|---|
| `p2pchat/native/lan_discovery.py` | 618 | `2590faeb227e61603c82e6975a9d39ae377bb76a3dd1a9487732232873749689` |
| `p2pchat/tests/native/test_lan_discovery.py` | 570 | `471f0a1522efe7f886a9516012a3f50990df48d54d620adaa8518f674acba58e` |

（本文件自身的 sha256 属自引用，不列入。）
