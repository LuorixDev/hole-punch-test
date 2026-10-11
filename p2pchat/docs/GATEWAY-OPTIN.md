# 让路由器开一个端口（桌面端，默认关闭 + 单独同意）

界面上的按钮叫 **“让路由器开一个端口”**，不叫 UPnP/PCP/NAT-PMP。协议名只出现在
“技术详情”里。本文说明它到底会做什么、什么情况下不会做、以及哪些结论还没验证过。

## 一、为什么需要这份接线（t11 的发现）

`p2pchat/native/gateway.py` 里协议层早就实现了（PCP / NAT-PMP / UPnP IGD / IPv6 pinhole），
但**没有任何生产调用点**，适配器对这三个机制恒报 `unsupported`，界面到适配器也没接线——
也就是“有实现、不可用”。本任务补上的是**调用点**与**如实的能力报告**：

| 层 | 生产调用点 |
| --- | --- |
| 协议层（不改） | `native/gateway.py`：`PCP` / `NATPMP` / `UPnP`（`map` / `renew` / `release` / `pinhole` / `verify`） |
| 适配器（本任务） | `native/adapter.py`：`gateway_capability()`、`gateway_map()`、`gateway_renew()`、`gateway_release()`、`gateway_pinhole()`；`capabilities()` 按平台如实报告 |
| 桌面端（本任务） | `python_desktop/gateway_optin.py`：同意状态、人话文案、审计；`python_desktop/engine.py`：`gateway_open_port()` / `gateway_close_port()` / `gateway_consent()` |
| 界面（本任务） | 设置面板里的“让路由器开一个端口 / 撤销已开的端口 / 技术详情” |

## 二、默认关闭 + 单独同意（这是硬约束）

- 启动应用、导入 STUN 配置、连接服务器：**都不会**创建任何映射，也不会有任何探测；
- 只有你在设置面板点“让路由器开一个端口”，并在弹出的确认框（人话解释）上点“是”，
  才会尝试一次；
- 代码级保证：`NativeAdapter.gateway_map()` 在没有 `consent=True` 时**不创建任何 socket**，
  直接 `GATEWAY_OPT_IN_REQUIRED`；测试用替换过的 socket 模块记录器证明了“零 socket 创建”
  （`tests/desktop/test_gateway_optin.py`）；
- 同意不会被记住到下一次启动：每次运行都要重新点。

## 三、平台能力（如实报告，不假装）

`NativeAdapter.gateway_capability()` 与 `capabilities()` 的 `upnp` / `pcp` / `natpmp` 三项：

| 平台 | 状态 | 原因代号 | 说明 |
| --- | --- | --- | --- |
| Linux（有 `/proc/net/route`） | `available` | `EXPLICIT_OPT_IN_REQUIRED` | 能只读核对“这个地址确实是我本机的默认网关”；仍需显式同意 |
| Linux（无路由表） | `unsupported` | `NO_LOCAL_ROUTING_TABLE` | 无法确认网关，拒绝操作 |
| Linux（没有默认网关） | `unsupported` | `NO_DEFAULT_GATEWAY` | 例如不在家庭/办公室网络里 |
| Windows / macOS | `unsupported` | `PLATFORM_VALIDATION_UNAVAILABLE` | 没有我们认识的“本机路由证据”来源，**明确报不可用**，不静默降级、也不猜一个地址去发请求 |

三种机制**永远** `canMessage: false`：它是“让路由器开一个口”的动作，不是一条数据通道。
试图把它当成数据通道（`attempt.mechanism` 取 `pcp`/`natpmp`/`upnp`）会被明确拒绝，并给出
`GATEWAY_MAPPING_IS_NOT_A_DATA_PATH`（可用时）或平台原因——不再笼统地说“unsupported”。

## 四、一次尝试会做什么

1. 只读解析 `/proc/net/route` 得到默认网关（没有任何写操作）；
2. 依次尝试 **PCP → NAT-PMP → UPnP IGD**：
   - PCP / NAT-PMP：向网关的标准端口（默认 5351）发一个请求，等待有界超时；
   - UPnP：先做一次有界 SSDP 搜索（标准组播地址 `239.255.255.250:1900`，只接受**网关自己地址**上的控制 URL），
     再走 SOAP `AddPortMapping`；
3. 映射必须经过**外部对端验证**才算建立（`gateway.Gateway.verify`）：没有验证者时，
   协议层会撤销这次映射并报 `EXTERNAL_VALIDATION_REQUIRED`——我们不把“路由器答应了”当成“打通了”；
4. 上限：单次租约 ≤ 7200 秒（且 ≥30 秒），最多 8 条映射；`renew` 续租、`release` 删除都走同一套协议层；
5. 关闭应用时会主动撤销本次运行创建的映射，撤销失败会记进 `engine.errors`（`GATEWAY_RELEASE_FAILED:*`）。

## 五、审计与日志

每条记录都是 `{"kind": "gateway", "action": ..., ...}`，不含任何密钥/私钥/房间密码，
并且会同时进入诊断事件流（`diagnostic`，`code = GATEWAY:<action>`）：

| action | 何时 |
| --- | --- |
| `consent-granted` / `consent-revoked` | 用户点同意/取消 |
| `mapping-requested` | 已同意，开始尝试（带端口、时长、协议范围） |
| `mapping-established` / `mapping-unverified` | 映射建立（外部验证通过/未通过） |
| `mapping-denied` | 没有同意、平台不可用、没有适配器 |
| `mapping-failed` | 协议层失败（带代号 + 人话解释） |
| `renew-requested` / `renew-ok` / `renew-denied` | 续租 |
| `release-ok` / `release-skipped` | 撤销 |

人话解释表在 `python_desktop/gateway_optin.py::PLAIN_FAILURES`，例如
`GATEWAY_TIMEOUT` → “路由器没有回应（可能关掉了 UPnP/PCP/NAT-PMP，或路由器不认这个请求）”。

## 六、测试与证据（哪些是真跑的）

`tests/desktop/test_gateway_optin.py`：

- **未授权零请求**：`GatewayOptIn.map_port()` 在未同意时抛 `PermissionError`，
  受控 mock 适配器的调用列表为空；真实 `NativeAdapter` 在替换 socket 记录器的情况下
  连一次 `socket()` 都没有发生；
- **授权后受控 mock 全生命周期**：`map → renew → close` 依次调用适配器，审计动作齐全，
  并且断言审计里不出现 `secret`/`privatekey`/`password`；
- **非 Linux 不可用**：`gateway_platform_capability("win32"/"darwin")` 报
  `PLATFORM_VALIDATION_UNAVAILABLE`；把适配器看到的平台改掉后，`gateway_map(consent=True)` 抛
  `NotImplementedError`，`capabilities()` 的三项如实变成 `unsupported`；
- **失败用人话记录**：`GATEWAY_TIMEOUT` 会被记成带“路由器”字样的解释，而不是裸代号。

`tests/desktop/test_engine.py::test_gateway_methods_report_real_capability_but_never_message`
保留原有意图（网关机制不能传内容），并把“恒报 unsupported”的旧断言改成“按平台如实报告 + 显式同意”。

## 七、没有验证的部分（不要当成已通过）

- **真实路由器：NOT_RUN。** 本机没有真实 UPnP/PCP/NAT-PMP 路由器可测；受控 mock 只证明接线与协议实现，
  **不是**家宽/NAT 证据。真实能否放行，必须在你家的路由器上实测。
- **Windows / macOS：NOT_RUN**，只保证“如实报不可用”这条路径。
- **外部对端验证**：协议层要求外部验证者；桌面端目前把“未验证”如实标出来，不会显示成成功。
- 不改宿主防火墙、不改路由配置、不做端口扫描——这些边界没有变。
