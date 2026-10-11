# tests/platform —— 平台边界测试（怎么跑、覆盖什么）

## 怎么跑（必须用 glob 形式）

```bash
# 仓库根目录
node --test p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/client/*.test.cjs

# 或 p2pchat/ 目录内（CI 用的就是这一行，见 .github/workflows/build.yml 的 Platform and client gates）
node --test tests/platform/*.test.cjs tests/client/*.test.cjs
```

**不要**写成 `node --test p2pchat/tests/platform`（目录形式）。在 Node v24.20.0 上实测
`dir`、`dir/`、以及目录形式都会以 `Error: Cannot find module '<目录>'` 失败——那是命令形式
问题，不是测试失败。只有 glob 形式（由 shell 展开，或给 node 传带 `*` 的模式）可用。
带引号的 `node --test "p2pchat/tests/platform/*.test.cjs"` 也可以：node 自己展开该模式。

## 覆盖什么

| 文件 | 覆盖 |
| --- | --- |
| `bridge.test.cjs` | ① Electron 桌面壳与其 Node 桥**保持删除**（`desktop/*.cjs`、`electron-builder.yml`、package.json 里的 electron/asar），同时确认网页与 Capacitor 入口仍在；② Android 平台门面（`platform/mobile.js` 的 capabilities/unsupported/SAF 保存，测试内是显式的假 Capacitor 桥）；③ 安卓明文策略不变量（`androidScheme: http` + `allowMixedContent: false` + network security config 生效 + `usesCleartextTraffic="false"` + 只信任系统 CA + 无 debug-overrides + 页面来源精确匹配两个 loopback 来源） |
| `stun_config.test.cjs` | STUN 端点策略：**真的执行** `python -m p2pchat.native.bridge`，验证"显式的一对数值 IPv4 地址+端口才接受、默认关闭、拒绝 DNS/URL/多播/未指定/链路本地/广播/IPv6/越界端口/半配置"，以及 CLI 与 Python 桌面都不存在中继（turn:/relay）入口。找不到带原生依赖的解释器时显式 `skip` 并写明原因，不假装通过 |

## Electron 退役后删掉的用例（附去向）

`p2pchat/desktop/*.cjs`（Electron 主进程/preload/stdio sidecar 桥）已随"桌面改为纯 Python"删除，
下面这些用例的被测对象**不存在了**，因此按"随组件一起移除"处理，**没有**用 mock/空实现顶替：

| 已删除的用例 | 原被测对象 | 现在由谁守 |
| --- | --- | --- |
| `reject unknown commands and oversized/bad payloads` | `desktop/bridge.cjs` 的 `validateRequest` | 组件已删除；等价约束是"不得再有 renderer/IPC 桥"，见 `tests/desktop/test_electron_removed.py` |
| `IPC requires same contents AND exact main frame URL` | `isTrustedSender`（Electron webContents IPC） | 同上（Python 桌面无 IPC 层） |
| `sidecar request correlates result / timeout / crash` | `Sidecar`（stdio sidecar 生命周期） | 桌面改为进程内调用 `p2pchat.native.*`，见 `tests/desktop/test_engine.py` |
| `malformed/overlong stdout kill sidecar` | sidecar stdout 协议 | 同上 |
| `validateStunConfig` / `sidecarArgs`（STUN 变固定 argv、≤1024B 选择器、renderer 无 configureStun RPC） | Electron 主进程菜单 + `desktop/main.cjs` | 由本目录 `stun_config.test.cjs` 改写为等价断言：同样的负数清单（DNS/URL/多播/未指定/链路本地/广播/端口越界）打到**真实**的原生 CLI 上 |

结论：平台门里没有任何"删掉断言就绿"的用例；删掉的是被测对象已不存在的用例，且每条都有承接者。
