# 可发布的脱敏证据索引与Windows平台修复整合

本文件是GitHub可读的结论摘要。完整review/verification报告、原始运行日志、随机房间key、媒体与抓包只在本地私有证据区，**不上传、不为修复断链扩大allowlist**。此处只记版本、测试范围与结论，不包含秘密或个人地址。当前精确源树和产物值见 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)、[FREEZE](FREEZE.json)；**每条打洞方式到底实现到什么程度、证据到哪一级（L0–L4）、还剩哪些缺口，见 [打洞方式全量对照矩阵](PUNCHING-MATRIX.md)**——那是最不容易被误读的一份。

## 本轮（p2p-delivery-v2）公开结论

- **桌面端换了实现**：删除 Electron 桌面壳，改为纯 Python + Qt(PySide6) + PyInstaller，进程内复用 `peer.py` 与 `native/adapter.py`（不再有 stdio sidecar / asar / 渲染层桥）。Tkinter 壳被 Qt 替换的原因是这个 Tk 运行时不链接 Xft、字体 families 只有 `('fixed',)`、中文测量宽度为 0（界面会显示空白）。**Qt 迁移（t24）在写入本行时仍在收尾、尚未独立复审**；Tk 基线的测试与审查结论只对该基线成立。
- **新增能力（都默认关闭、需显式同意）**：NAT 行为分类（多 STUN 观测）、局域网直连发现（同网段不用打洞）、对称 NAT 端口预测，以及「路由器放行」的真实接线。每项的**最高证据只到 L1/L2**（本机真实套接字、隔离 netns、受控应答端点）；**真实家宽/双 NAT/CGNAT、真实路由器映射、各类实机一律 NOT_RUN**。
- **本地实跑（Tk 基线，独立复审复跑）**：450 Python passed、`tests/desktop` 67 passed / 0 skipped（含真实 Tk 面板）、55 Node client、6 platform；`--self-test`（源码与打包产物）真实握手通过，独立通道测速两次拿到对端确认（65.52 / 53.58 Mbps，**应用层 goodput，不是线路带宽**）。
- **本轮暂不出冻结清单的原因（如实）**：写入本行时整套回归在**收集阶段**中止（`ImportError: cannot import name 'ui' from 'p2pchat.python_desktop'`）——Qt 迁移已删除 Tk 的 `ui.py`，而 `tests/desktop/test_ui.py` 尚未跟着改。冻结清单必须建立在一棵稳定且全绿的树上，因此重新生成排在迁移完成之后。细节见矩阵第 8 节 G9 与第 11 节。
- **仍属缺口（不得写成已完成）**：安卓原生 Kotlin（零源码，仅可行性）、Windows/macOS 桌面实机与打包、网页端只走 WS 信令（服务端 HTTP/SSE 无客户端接入）、真实麦克风采集、磁盘满/断电/七天长跑。

## 最新Windows实际结果，不混淆历史失败

> **先读这句**：下面这一节是**已删除的 Electron 桌面版与更早轮次**的 CI 记录，用来保留失败留痕与分工；它**不代表本轮 Python/Qt 桌面的状态**。本轮 Windows 结果仍是 PENDING（待 captain 推送）。历史成功包与成功 EXE 都不可继承到新桌面。

`78a20506972d24605bdb9557378c3ce47c92a818` / [run38132637106](https://github.com/LuorixDev/hole-punch-test/actions/runs/38132637106)：**原双echo/计时诊断2 passed；完整Python suite70 passed、6 failed、1 skipped。** Linux job114449949454与Android job114449949242成功（各76 passed/1 skipped/8warnings，skip为Linux netns条件非native v6）；Windows job114449949400未完成测试门，未取得成功EXE。其定向诊断2 passed/4.42秒，watchdog6.141秒exit0；全套154.33秒。当前失败不是旧关闭挂起或elapsedMs=0。

六失败分工：

- t30：IPv4和IPv6真实STUN限流测试各1项，原测试假定26包都在同一秒固定窗口；实际批量可能跨窗口。生产20/IP与1000全局固定窗口预算不改，只允许测试注入clock；保留真实UDP/Store，等待全部26回调后精确19剩余回复；另跑默认monotonic跨1秒真实Binding。
- t31：IPv6 UDP probe、QUIC、TCP三项，修正合法IPv6展开/压缩/%0表示的exact endpoint规范化；仍精确port/family并拒绝非零scope，保持独立nonce/证书/same-socket。旧日志缺原始sockaddr，**不能认定表示差异已证明是Windows全部失败的唯一原因**，需新runner确认。
- t31：网关验证1项，生产真实route验证本来Linux-only；Windows/macOS明确fail-closed为LOCAL_GATEWAY_VALIDATION_UNAVAILABLE。测试分平台断言而非整组skip，mock授权生命周期不代表真实网关。

历史分别保留：61b400e收到4000B但elapsed0、关闭正常exit1；a1c6e7e关闭诊断90秒exit124。新修复由t32/t33独立Linux审查pass，**Windows post-repair仍PENDING**，captain负责新commit与完整CI门。

## 私有证据的公开摘要

| 本地证据标识（非下载链接） | 适用版本/范围 | 已观察结论与限制 |
|---|---|---|
| t15 VERIFICATION-R2 / t19 ROUND3 | 8687adf历史129文件 | 58 Python、34 Node、4真实native集成；独立进程/浏览器/60秒控制中断、v6隔离stateful及延迟丢包通过；非家宽/实机 |
| t26 Windows T26 | 关闭修复 | 独立33项通过，required closer取消必须失败；不是Windows IOCP通过 |
| t28 Timing T28 | 短时计时修复 | 独立25 Python+17 Node，高分辨率整数差与未知耗时；原4000B正耗时断言保留 |
| t32 STUN-Windows T32 | 本轮STUN窗口修复 | 独立17项通过；真实v4/v6、生产默认clock、限额/端口变化/畸形预算与白名单；受控60ms反例不是Windows SQLite实测 |
| t33 Native-Windows T33 | 本轮native平台修复 | 独立53项无skip通过；实际IPv6格式变化后QUIC/TCP双向64KiB、nonce重放/证书/错误port拒绝、网关三平台fail-closed；Windows runner尚未执行 |

本轮t34不改任何产品或测试，只核对审查目标字节、执行完整Python及Node/native应用回归、重建Linux并重新冻结。实际回归：**97 Python passed，8 AppKey建议警告，81.21秒，无skip；48 Node passed（客户端/平台/真实native应用管线），无skip**。sync:web与完整Linux构建退出0；没有为平台差异跳过失败节点。Linux netns成功保留其平台专属意义，Windows缺该能力的skip不是其他IPv6测试的豁免。

## 可公开访问的复现入口

- 应用回归：[tests](../tests/)，包含真实socket和显式标注MOCK的单元测试，二者不能互换。
- 运行/部署：[README](../README.md)；能力边界：[CAPABILITIES](CAPABILITIES.md)；**逐条打洞方式状态与缺口：[PUNCHING-MATRIX](PUNCHING-MATRIX.md)**；桌面端实现与打包：[DESKTOP-PYTHON](DESKTOP-PYTHON.md)；版本历史与上传规则：[DELIVERY](DELIVERY.md)。
- 修复摘要：[REPAIR-ROUND2](REPAIR-ROUND2.md)、[REPAIR-ROUND3](REPAIR-ROUND3.md)、[WINDOWS-INTEGRATION](WINDOWS-INTEGRATION.md)、[TIMING-INTEGRATION](TIMING-INTEGRATION.md)。这些历史文档中“当前”仅指该任务当时，以本索引与最新FREEZE为最新状态。

发布链接检查以明确uploadAllowlist/已跟踪文件为准，不因本地磁盘存在私有报告就保留GitHub无效链接。review/verification、ci分析日志与patch、任何run/key/media不加入清单。当前三平台CI仍待captain新推送；不声称Windows或真实手机/家宽/网关已经完成。
