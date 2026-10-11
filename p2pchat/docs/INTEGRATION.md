# t6 跨模块集成与冻结记录

日期：2026-10-11，范围仅本机Linux与已交接模块证据。此文件不含密钥、原始IP、媒体、截图或日志原件，不是家宽穿透证明。当前支持矩阵见 [CAPABILITIES](CAPABILITIES.md)，协议字段仍为 [PROTOCOL v1](PROTOCOL.md)。

## 修复

- WebCrypto/Python对相同UTF-8紧凑JSON字段生成HMAC；有效ACK先于hello时仅保存一个nonce，待匹配hello后才能认证，重复/错nonce仍拒绝。
- 信令中断不等于Leave：浏览器和Python保存已认证direct通道；另一端收到roster缺失时保留旧peerId直连并提示离线身份。新welcome替换session，关闭旧资源并生成新attempt；不会按同名节点继承旧身份/ACK。
- Python重连HTTP503曾退出整个echo，现捕获aiohttp ClientError继续有界退避；显式Leave/close仍回收所有数据资源。
- 中央脱敏诊断默认自动开启（点击连接确认中心），可暂停；暂停、待ACK、本地淘汰、持久化错误显示“中心记录不完整”。ACK使上传退避恢复到1秒。
- 高peerId重试最多等待12秒，远端预算耗尽/未响应、信令离线、对端缺失都有明确终态和操作指引；不增加自动重试次数。
- Native事件tuple/observability适配UI；网关映射仅Python授权API、WebRTC-only Echo、loopback原生绑定限制在界面中直接说明。

## 实际可见证据（Agent Window，不使用其它浏览器后端）

| ID | 真实观测 | 限定 |
|---|---|---|
| UI-XLANG | Chromium↔独立Python echo，Unicode房间/运行时随机Unicode密钥；文字echo成功 | loopback控制面，本机实际WebRTC，不是公网 |
| UI-ORDER | 测试专用Python echo真实发送early ACK与SDP前trickle；页面计数4 early ICE/2 early ACK，重连后累计8/4；正常认证与回声成功 | 有意调序fixture，不伪造网络状态或成功事件 |
| UI-PAR | ice-v4与ice-dual均direct；ice-v6仍尝试随后有界timeout/retry；chat/benchmark两个真实DataChannel | Chromium隐藏本地地址，actual family显示unknown，不按profile猜测 |
| UI-FILE | 生成合法PNG109B、合法WAV8044B、随机文件65000B，双端SHA-256匹配后echo与下载/播放控件可见 | 生成WAV不是麦克风采集 |
| UI-BENCH | 独立benchmark接收ACK33554432B，与文字聊天同时成功；页面goodput约112–123Mbps | 仅当次应用goodput，不是线路带宽 |
| UI-ONE-OFFLINE | 仅浏览器WS断开，另一端收到roster变化；62.8615秒内7轮文字+2048B文件ACK/回声持续；18待传诊断重连后归零 | 新peerId；原身份不能被新roster同名节点替换 |
| UI-BOTH-OFFLINE | 两端WS断开并拒绝重连61.963秒，7轮文字+文件持续；18待传诊断归零，新peerId | 恢复后按新session重建数据通道，PythonSQLite也经回归验证归零 |
| UI-RECORD | 用户界面点击录音→结束发送，实际getUserMedia/MediaRecorder产出566865B WebM，完整性ACK及echo；点击回声播放后进度35.46秒 | 未注入假麦克风；不声明硬件音源身份/人声质量；不代表Windows/Android实机 |
| UI-RETRY | 真实高peerId浏览器关闭旧路径，Python发起端不重试；12秒后页面PASS并显示REMOTE_RETRY_BUDGET_OR_NO_RESPONSE与操作指引 | 耗尽/无响应同一有界终态；信令重连/对端消失另有确定性UI单测 |
| UI-PAUSE | 取消自动汇集后实际显示“中心记录不完整：已暂停自动汇集” | 队列淘汰提示另有确定性单元测试 |

测试运行中发现的两次失败已修复后重测：双端断线遇503导致Python退出；新增stdio测试初版只转发证书而漏了独立nativeCandidate（修正测试为完整真实信令，未降低产品断言）。

## 可复现入口

```sh
.venv/bin/python -m pytest p2pchat/tests -q
node --test p2pchat/tests/client/*.test.cjs p2pchat/tests/platform/*.test.cjs
node --test p2pchat/tests/integration/native_bridge.test.cjs
npm --prefix p2pchat run sync:web
# 仅本机手动Agent Window fixture，生产server不注册这些测试route：
.venv/bin/python -m p2pchat.tests.integration.browser_lab --port 8098
# 打开 http://127.0.0.1:8098/integration，点击连接，再点测试按钮。
```

[integration tests](../tests/integration/) 包含双真实stdio进程QUIC、JS NativeAdapter→platform Sidecar→Python真实双lane、JS/Python Unicode HMAC及早ACK、真实socket控制面中断≥60秒与SQLite补传；浏览器手动fixture和调序echo可供独立复测。fixture随机密钥只在本地运行目录生成、权限0600，媒体仅运行时生成或内存录制；生产入口不提供测试操作。

基线已有t2独立server/echo/client进程、t3 v4/v6 native及双netns simultaneous-open、t5带sandbox Linux启动证据。最终回归/构建输出摘要写入 [FREEZE](FREEZE.json)，源码逐文件SHA-256与上传allowlist为 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)。Python精确版本记录 [requirements-lock](../requirements-lock.txt)，npm使用 [package-lock](../package-lock.json)；不把锁定版本等同无漏洞，t5审计为0 high/8 moderate（构建链sprintf-js）。

## 最终回归与构建结果

- Python全套：45 passed，8项aiohttp AppKey建议警告，73.21秒，退出0。
- client/platform Node：27 passed；真实native bridge额外1 passed，均退出0。
- `sync:web` 和最终 `dist:linux`（PyInstaller + Electron44.7.0）退出0；最终包带sandbox执行 `--platform-smoke` 打印 `P2P_PLATFORM_LOCAL_RENDERER_LOADED`，退出0。仅Fontconfig缓存版本警告。
- 录音已经结束（所有track停止），最后执行明确Leave并关闭Agent Window；测试fixture任务已停止。媒体未另存/上传。

## 发布边界

- 本轮Linux包在最终产品源码停止修改后重建，核对随包native source-manifest；旧t5包不代表最终版本。
- Windows/Android构建/麦克风/实机/后台切网：NOT_RUN，交由已授权Actions及后续设备测试。Android本机Java25/缺SDK未解除，不接受SDK许可来假装可编译。
- 浏览器IPv6直连、真实双家宽/CGNAT/对称NAT、真实路由器映射：NOT_RUN/未成功，不从同机证据推断。
- 原生网关API、simultaneous-open在具体网络失败是可见结果，不回退TURN；Echo是终端不是relay。
- 仓库allowlist仅源码/构建配置/测试/脱敏结果摘要；排除data、日志、媒体、pcap、screenshots、密钥、node_modules、构建缓存/包与研究证据。Actions工作流在t6范围外，由captain另审；不push/release/deploy。
