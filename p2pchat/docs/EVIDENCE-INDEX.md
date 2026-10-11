# 可发布的脱敏证据索引与Windows平台修复整合

本文件是GitHub可读的结论摘要。完整review/verification报告、原始运行日志、随机房间key、媒体与抓包只在本地私有证据区，**不上传、不为修复断链扩大allowlist**。此处只记版本、测试范围与结论，不包含秘密或个人地址。当前精确源树和产物值见 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)、[FREEZE](FREEZE.json)。

## 最新Windows实际结果，不混淆历史失败

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
- 运行/部署：[README](../README.md)；能力边界：[CAPABILITIES](CAPABILITIES.md)；版本历史与上传规则：[DELIVERY](DELIVERY.md)。
- 修复摘要：[REPAIR-ROUND2](REPAIR-ROUND2.md)、[REPAIR-ROUND3](REPAIR-ROUND3.md)、[WINDOWS-INTEGRATION](WINDOWS-INTEGRATION.md)、[TIMING-INTEGRATION](TIMING-INTEGRATION.md)。这些历史文档中“当前”仅指该任务当时，以本索引与最新FREEZE为最新状态。

发布链接检查以明确uploadAllowlist/已跟踪文件为准，不因本地磁盘存在私有报告就保留GitHub无效链接。review/verification、ci分析日志与patch、任何run/key/media不加入清单。当前三平台CI仍待captain新推送；不声称Windows或真实手机/家宽/网关已经完成。
