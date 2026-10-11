# 交付清单、版本证据与GitHub隐私边界

## 交付结论

**已完成：声明实验范围的本地源码实现、R1–R5修复、独立复验/审查，以及同版Linux本地包。未完成：最终同版三平台Actions终态、Windows成功包、Android/Windows实机和真实家宽/网关验证。** 不把整个用户目标写成“全平台全方法可用”。安装/运行见 [README](../README.md)，逐平台机制见 [CAPABILITIES](CAPABILITIES.md)。

## 版本与CI状态

**当前：高分辨率计时修复待当前commit CI确认，Windows尚未完成。** t29整合t27+t28已审性能测量与JS未知时间显示修复，重新sync/Linux构建及完整 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)/[FREEZE](FREEZE.json)。最新源码/产物SHA以这两个文件为唯一当前清单，当前commit/run尚待captain推送，不继承旧包。最近61b400e Linux/Android成功，Windows4000B收到但elapsedMs=0导致原正耗时断言失败，关闭正常、约4.937秒exit1；**与此前90/600秒关闭挂起不同**。详见 [TIMING-INTEGRATION](TIMING-INTEGRATION.md)。

变化包含新增 [rtc_shutdown.py](../backend/rtc_shutdown.py)、Peer幂等有界关闭、required closer取消失败传播及相关测试；范围与Linux证据见 [WINDOWS-INTEGRATION](WINDOWS-INTEGRATION.md)。新Windows runner必须完成原双echo90秒诊断、完整测试和portable打包门。下面的8687adf数值与哈希表只保留作**历史t15已验证快照**，不是当前版本标识。

历史代码验证基线（不是Git commit）：

```text
sourceTreeSha256 = 8687adf15b114380747308b43d78df29dd0634bc006a3e4d16215abeb4062388
sourceFileCount = 129
sourceManifestSha256 = 1173efbab49cfb3156d1d5df3bbaa2e5c003ec0a5759082186671251f13ac52e
Linux packageTreeSha256 = b0c9f7aae146f8ee852a30f2fcf7ebe25e4f16e55748dd9fd046a63ac49e9227
```

**文档provenance：t9曾是8687adf后的docs-only overlay；t24现将该overlay与已审关闭修复一起重新冻结。** 旧t15/t19报告只属于旧树并原样保留，新manifest包含当前README/CAPABILITIES/DELIVERY及新增backend/测试，不再要求当前整树匹配旧129文件哈希。产品修复由t22/t25完成，t24只整理文档/来源、检查审查目标hash和重建，未修改产品以迎合验证。

| 版本/来源 | Linux | Android | Windows | 可作何种证据 |
|---|---|---|---|---|
| t29当前计时修复（hash见FREEZE） | 新本地包重建/sandbox检查；新CI待推 | 新CI待推，实机NOT_RUN | 计时修复待当前commit CI确认，无成功包 | t27 Linux77项+t28独立25 Python/17 Node；非Windows成功声明 |
| 历史61b400e关闭修复 | success | success，无实机 | 4000B ACK已到、elapsedMs=0断言失败；约4.937秒exit1，关闭正常，未打包 | 不把本轮测试失败混为旧挂起/超时124 |
| 历史8687adf→`a1c6e7e724390440d6422e4bb0b06804c9ba16a7` / run`38124339483` | success | success，无实机 | 90秒diagnostic exit124，未打包 | 挂起链已定位到aioice StunProtocol.close，不作为新关闭修复结果 |
| `855c19ceed67d6ae23cbf52c61131dd6d637ea8d`，run `38122604055` | success | success/debug构建 | failed，watchdog600秒exit124，未打包 | 旧commit诊断包，不可继承到8687adf |
| `ec2969a`，run `38121429541` | success | success | 长挂后取消 | 取消不是通过，也非已定位根因 |
| `eb9316b`，run `38121009114` | 构建门失败 | 构建门失败 | 构建门失败 | Python版本/工作目录历史失败 |

最新已知远端历史commit是`61b400e98ff955120e42caafe05284fcb940b11f` / run`38129731771`，其关闭修复已正常退出但计时断言失败，不包含本轮高分辨率计时修复。更早a1c6e7e/run38124339483的90秒超时保留为独立历史。新commit、run及对应产物SHA/下载链接：**PENDING，由captain追加**。t11/t21的workflow/诊断入口不能给未成功的Windows产品背书；不上传windows-analysis中的proposal patch或源码快照，不跳过失败测试门。历史run链接：

- [61b400e历史构建（计时断言失败，关闭正常）](https://github.com/LuorixDev/hole-punch-test/actions/runs/38129731771)
- [a1c6e7e历史构建（Windows诊断超时）](https://github.com/LuorixDev/hole-punch-test/actions/runs/38124339483)
- [855c19c诊断构建](https://github.com/LuorixDev/hole-punch-test/actions/runs/38122604055)
- [ec2969a历史构建](https://github.com/LuorixDev/hole-punch-test/actions/runs/38121429541)
- [首轮失败](https://github.com/LuorixDev/hole-punch-test/actions/runs/38121009114)
- [项目Actions入口](https://github.com/LuorixDev/hole-punch-test/actions)

链接需私有仓库权限。选包必须核对**source commit + job success + artifact manifest SHA**；不能下载任意最新旧包然后宣称修复已包含。

## 历史8687adf产物与锁文件SHA-256（当前见FREEZE）

| 文件/范围 | SHA-256 |
|---|---|
| Linux完整目录树（109文件） | `b0c9f7aae146f8ee852a30f2fcf7ebe25e4f16e55748dd9fd046a63ac49e9227` |
| launcher | `10a14d05c6ff4f94075cfb3eeb6ed6571be33ebcc08cbd675b5ce9ff84706564` |
| app.asar | `352275b49b9097ac027a0b4fb251beed77cf67b093909bead3dfd23216dde59b` |
| native sidecar | `c27f1cf3bee14f48549c8cfc24953f1c582663d886f708a3b310e8296bb9e3f6` |
| [package-lock](../package-lock.json) | `6beed4f9163d5bcc775c1dd8429caf6b405b71909a8643ba23720a20f64dbef0` |
| [requirements-lock](../requirements-lock.txt) | `e8a8f0a6b1dbf627b99353c4e42aeb2add5859bfa0594d0c0959e295bf75c9bd` |

完整目录树hash算法为按相对路径排序的逐文件SHA map紧凑JSON再SHA256，不是tar/zip哈希；未来打包压缩包必须另记其SHA。保留整个Linux目录，不能只传launcher。上述本机glibc2.44包不保证较旧发行版；Actions Ubuntu包需要自己的工具链及artifact哈希。

## 独立验证与审查依据

本地报告 [VERIFICATION-R2](../verification/VERIFICATION-R2.md)（t15）在验证前后逐文件核对129源码、两个冻结文件与5 artifact/lock，前后相同；[ROUND3](../review/ROUND3.md)（t19）独立审查pass。上传这些报告须另做脱敏/链接裁剪，不上传其引用的run树；本文件摘要可直接用于交付。

- **58 Python、34客户端/平台Node、4真实native应用集成**通过；另独立23资源边界、移动track与旧ACK检查。
- 四独立进程server/echo/A/B，文字/合法PNG/WAV/随机文件SHA与回声；杀server后63.316秒继续数据传输，恢复后pending归零。
- Agent Window真实浏览器↔独立echo：Unicode HMAC，early ICE/ACK，PNG109B/WAV8044B/随机文件65000B逐SHA通过；32MiB benchmark ACK约117.246Mbps并发chat。是当次应用goodput，不是线路带宽。
- 双端WS关闭并503拒重连61.703秒，7轮消息/文件持续；19待上传→0，新peerId无旧身份复用。
- native host黑洞后late srflx可控UDP转换、同fd/socket/port、双向64KiB；真实QUIC业务capability→Transfers benchmark ACK通过。转换shim不是内核双NAT/真实CPE成功。
- 隔离IPv6 stateful拓扑及每端40ms/注入5%loss双向64KiB SHA通过；不是真实线路5%测量，不是家宽证明。
- R1块对象/空块、R2候选绑定/STUN、R3测速能力、R4移动生命周期模拟、R5完整proof跨tuple重放/单向丢包负例均覆盖。
- 有限负载62份SQLite/JSONL已知测试key/正文/SDP凭据/PEM标记零命中，去重与补传通过；磁盘满/断电/真实七天长跑NOT_RUN。
- 最终独立本轮只生成合法WAV，未重测真实麦克风；t6历史实际浏览器录音证据单列，不当Windows/Android或最终独立采集证据。

历史不抹除：t7旧`fd54a6…`验证failed；t8要求R1–R4，t13对`bfac700…`发现R5；这些受影响项经t18修复、t19与t15复验，不拿中间版本冒充最终通过。旧IPv4 SNAT观测/预期timeout仍不是穿透成功。产品变化后需新hash；本轮关闭修复已在Linux全套72项及独立33项复验，t24不重复旧浏览器实验，不把旧实验自动升级为新Windows原生结果。

## GitHub上传allowlist

目标：[LuorixDev/hole-punch-test](https://github.com/LuorixDev/hole-punch-test)，**private**；分支`build/p2p-observatory`。captain唯一负责审核stage、commit、push、Actions监看。本任务不运行Git写操作、不发布Release、不部署公网。

1. 从被验 [SOURCE-MANIFEST](SOURCE-MANIFEST.json) 的`uploadAllowlist`逐文件开始，检查差异；仅允许应用源码、测试源码、锁文件、构建配置、文档。新增本文件；明确包含Android构建所引用的`proguard-rules.pro`。不要用`git add .`。
2. 额外按文件审核Actions workflow和安全ignore规则；本轮完整冻结JSON作为版本元数据加上；ci诊断runner仅按manifest独立CI允许项审核，不放行整个ci/windows-analysis。
3. review/verification **目录不整体allowlist**。若需要报告，只单独批准已人工脱敏的Markdown摘要；脚本另审，禁止其run/output/basetemp/日志树。默认用本交付摘要满足外部引用，保留完整报告本地。
4. 产物只经私有Actions artifacts保留，按commit附SHA；不把构建目录当源码上传，不自动创建公开或私有Release。

**无条件排除**（即使仓库private）：`.venv`、`node_modules`、`outputs`、`data`、`logs`、SQLite/JSONL运行记录、room.key、token/PEM/私钥、个人公网/私有地址列表、录音/照片/聊天正文、pcap、浏览器截图、review/verification的`run*`/`pytest-temp*`/恢复副本、`dist-web`、`releases`、`platform/build`、`platform/work`、Android生成assets/build/.gradle/local.properties、安装缓存/SDK/下载ZIP。Android模板图标等构建静态资源可以逐文件allowlist，不能据此放行真实媒体。

不上传签名密钥、环境凭据或SDK许可状态。诊断中心白名单元数据自动汇集已获用户要求，不等于原始抓包/聊天数据外传授权；GitHub源码上传也不等于公网部署/网关变更授权。

## captain待追加的最终交付行

| 字段 | 待填写条件 |
|---|---|
| 最终代码commit / docs-only commit | 实际推送完整SHA，说明产品相对8687adf有无变化 |
| Actions run / job URL | 同commit实际结论，不用dispatch成功替代构建成功 |
| Linux artifact + SHA + toolchain | 对应当前commit；区分本机包与runner包 |
| Android APK + SHA + debug signing | 构建成功也标实机NOT_RUN；不提供私钥 |
| Windows portable + SHA | 只有测试门及打包真成功才填；当前失败/待诊断 |
| 安装/跨网络现场结果 | 尚无设备/授权则NOT_RUN，不自造通过 |

最终云端构建未完成不抹掉本地源码交付价值，也不把用户完整目标提前标完成。
