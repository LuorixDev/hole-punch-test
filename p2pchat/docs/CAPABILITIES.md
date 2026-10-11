# 最终能力矩阵与限制

**t34最新：STUN窗口、native IPv6规范化与网关平台分支修复待新commit Windows CI。** 78a2050原双echo/计时2pass，完整70pass6fail1skip；不是旧关闭挂起/elapsed0。六失败与t30/t31及t32/t33审查对应见 [公开脱敏索引](EVIDENCE-INDEX.md)。本轮native字节已变，不能沿用下文历史“native未变”作为当前断言。最新hash见FREEZE。

**当前状态：高分辨率计时修复已审，Windows待当前commit CI确认。** 61b400e的Linux/Android成功，Windows收到4000B但elapsedMs=0导致断言失败；关闭正常完成、约4.937秒exit1，不是旧挂起。t27改perf_counter_ns测量及JS未知计时提示，t28独立25 Python+17 Node通过；本轮按新前端字节重建Linux，详见 [TIMING-INTEGRATION](TIMING-INTEGRATION.md)。下面关闭修复描述为此前t24边界，仍保留但不能覆盖本轮计时变更。 最新完整源码和Linux包哈希见 [SOURCE-MANIFEST](SOURCE-MANIFEST.json)、[FREEZE](FREEZE.json)，已合并t22+t25关闭修复及交付文档。该补丁仅精确win32/Python3.12.10/aiortc1.15.0/aioice0.10.2的本Peer Proactor UDP；Linux模拟/全套72项与 T26（本地私有证据，不随GitHub交付） 独立33项通过，不表示Windows IOCP已通过。

下表L1/L2证据来自历史基线`8687adf15b114380747308b43d78df29dd0634bc006a3e4d16215abeb4062388`的 VERIFICATION-R2（本地私有证据，不随GitHub交付） 与 ROUND3（本地私有证据，不随GitHub交付）；77个旧安全域文件及native字节未变，但Python Peer关闭逻辑已变，不能把旧全套报告直接套新整树。[旧a1c6e7e run38124339483](https://github.com/LuorixDev/hole-punch-test/actions/runs/38124339483)已Linux/Android成功、Windows90秒exit124未打包。当前新版需同commit重跑原双echo诊断+全套测试+打包，详见 [WINDOWS-INTEGRATION](WINDOWS-INTEGRATION.md)。

## 1. 平台分层状态

`实现`不等于`构建`，`构建`不等于`实机互通`，本机/隔离namespace测试不等于真实家宽。NOT_RUN=条件不具备；“未实现”是功能缺口，两者不可互换。

| 平台 | 实现 | 当前基线构建 | 当前基线本地运行/测试 | 平台实机/现场 |
|---|---|---|---|---|
| Linux Chromium | WebRTC聊天/文件/录音/诊断 | Web静态资源已同步 | 真实浏览器↔独立Python echo、文件SHA、独立benchmark、断信令补传通过 | 本机有证据；两条家宽NOT_RUN |
| Linux Electron x64 | 共享UI+安全IPC+内置Python sidecar | 本地最终包已重建 | sandbox启动、sidecar来源hash；JS业务→platform桥→双Python native测试通过 | Electron完整GUI跨设备/网关NOT_RUN；本机glibc2.44包不保证旧Linux |
| Python Linux | 双栈信令/STUN、中心日志、WebRTC Echo、native API | 源码与本地sidecar构建 | 独立进程、v4/v6 socket、隔离v6 stateful/延迟丢包、候选负例通过 | 真实双NAT/公网/CPE兼容NOT_RUN |
| Windows Electron | 同源封装/sidecar配置 | **计时修复待当前commit CI确认，无成功包**；61b400e关闭正常但elapsed0失败，旧版另有90/600秒超时 | 未运行当前版Windows | GUI/文件/麦克风/防火墙实机NOT_RUN |
| Android Capacitor | 共享WebRTC UI、SAF保存、音频权限、pause/resume/切网回调 | 关闭修复同版待CI；旧commit debug APK成功不继承 | lifecycle/旧ACK/track回收仅源码+模拟 | 真机安装、WebView互通、录音、后台/切网NOT_RUN |

新关闭修复各平台运行结论/产物链接由captain推送新commit后按实际终态补充，目前Windows修复不预判成功；上述a1c6e7e仅旧版历史。旧`855c19ceed67d6ae23cbf52c61131dd6d637ea8d` / run`38122604055`：Linux、Android成功；Windows watchdog600秒exit124，未打包。详情见 [交付版本表](DELIVERY.md#版本与ci状态)。

## 2. 所有约定机制逐平台状态

缩写：**L1**=本机真实进程/socket/浏览器；**L2**=隔离netns/可控拓扑；**U**=实现但该平台/网络未验证；**无API/未实现**=明确不可用，不以绿灯占位。

| 方法 | Linux浏览器 | Linux桌面/Python native | Windows桌面 | Android | 限制/证据 |
|---|---|---|---|---|---|
| IPv6 host（WebRTC） | 实现，本次v6策略超时 | Python实现，未据此声明WebRTC v6成功 | U | WebView实现/U | native v6通过不能替代WebRTC v6；隐藏地址族unknown |
| IPv4 LAN/public host | WebRTC L1 host成功 | Python WebRTC/native L1成功 | U | U | LAN跨设备/public host现场NOT_RUN |
| STUN srflx | WebRTC STUN配置实现，真实NAT U | 双栈STUN服务；native IPv4受控STUN同socket测试通过 | 源码U | WebRTC引擎/U | STUN观察映射不是NAT分类；桌面配置需明确授权 |
| prflx / triggered ICE | 引擎能力，具体prflx轨迹未证实 | aiortc引擎能力/U | 引擎能力/U | WebView引擎能力/U | 不是独立协议；不可观测不编造 |
| WebRTC DataChannel DTLS/SCTP | 真实L1文字/文件/echo/benchmark通过 | Python独立进程L1通过 | U | U | 三profile是同协议地址族策略，不是三算法 |
| UDP精确tuple双向探测 | 浏览器无任意UDP API | v4/v6真socket；每candidate随机challenge；错source/key/完整proof重放与单向丢包负例通过 | 源码U | 原生未实现 | probe-only，canMessage=false |
| QUIC同UDP socket | 浏览器无API | 探测/候选保持fd/port；host黑洞→srflx可控转换+双向64KiB；业务benchmark ACK L1；v6 stateful和40ms/5%loss L2通过 | 源码U | 原生未实现 | 转换shim不是内核双NAT/CPE成功；独立stream共享拥塞 |
| TCP直连 | 浏览器无API | mutual TLS、v4/v6 socket完整性通过 | 源码U | 原生未实现 | 不支持独立benchmark；不得回退控制面443传正文 |
| TCP simultaneous open | 浏览器无API | 真双端bind/connect；t3双netns正例；零延迟可失败 | 源码U | 原生未实现 | 不是普通listener/connect；OS/NAT依赖，现场U |
| UPnP IGD IPv4映射 | 无API | Python opt-in API实现+受控服务测试 | 源码；网关验证受限 | 未实现 | 桌面桥没有映射授权入口，OPT_IN_GATEWAY_API_ONLY |
| UPnP IPv6 firewall pinhole | 无API | Python API+受控IPv6服务测试 | 源码U | 未实现 | 不能由IPv4映射成功推断；link-local scope受限 |
| PCP MAP | 无API | 编码/nonce/lease/续租删除API+受控服务测试 | 源码U | 未实现 | 真实网关NOT_RUN |
| NAT-PMP | 无API | IPv4协议/API+受控服务测试 | 源码U | 未实现 | 协议本身无密码学认证，须可信本地网关与外部验证 |
| TURN / 信令数据中继 | 永久禁用 | 永久禁用 | 永久禁用 | 永久禁用 | 配置、候选、实际pair、控制面schema均拒绝 |

网关映射是不同机制/候选来源，不是STUN变种或传输成功证明。调用 [gateway.py](../native/gateway.py) 需显式opt-in、可信路由网关、外部peer验证、有限lease/续租/close；本产品没有替用户操作真实路由器。Python Echo只支持WebRTC，native QUIC/TCP应连另一个native客户端，不把“无法向Echo使用native”隐藏成所有机制均已回声。

## 3. 传输与诊断

- 文本UTF-8≤16KiB；文件/图片/录音≤32MiB；16KiB非尾块，严格sequence/最终SHA256 ACK；空文件仅start/end。预算≤64MiB且计对象开销、块数有界，超限明确失败。
- 录音是完成后的文件，非实时通话。t6历史Linux浏览器实际录音566865B并回声播放；**t15最终独立复验只生成合法WAV，真实麦克风未重测**，不覆盖Windows/Android麦克风。
- Android暂停停止已登记及迟到stream，关闭旧path/ACK；resume/切网合并且有界重建。没有后台服务、wake-lock或系统回收保证；真实锁屏/Doze仍NOT_RUN。
- WebRTC与QUIC允许独立lane手动测速；TCP禁用。goodput来自实际接收ACK与单调时间，不是线路带宽；共享链路/拥塞仍可能影响聊天。
- 日志IndexedDB/SQLite持久化、session/connection/attempt关联、中心ACK去重补传、白名单脱敏、限额。自动汇集当前确认中心已获授权；暂停/淘汰显示“中心记录不完整”。磁盘满/断电/真实7天长跑未验。
- 底层包头、STUN重传/TCP flags/MTU等API不暴露字段返回null/unknown；Python selected pair是明确声明的aiortc私有只读观察。

## 4. 信任与交付边界

共享房间密钥不防恶意同房间成员冒充；TLS/WSS必须验证证书且精确Origin，不支持trust-all。默认所有服务/原生绑定loopback；公网部署和网关修改另需操作者确认。对称NAT、CGNAT、UDP封锁、IPv6防火墙或任意网络均不保证成功。

依赖标准：STUN Binding、ICE/DTLS/SCTP、QUIC/TLS1.3、TCP、UPnP/PCP/NAT-PMP分别按实际实现列出；标准名称不等于互操作认证。旧t7失败基线fd54a6与round2的bfac700缺陷均保留，不能作为最终通过依据；最终t15与t19覆盖R1–R5。t24已将关闭修复与交付文档重新纳入完整manifest，不暗改原t15/t19记录；未来代码变更仍须新hash复验。
