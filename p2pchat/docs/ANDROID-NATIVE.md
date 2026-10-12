# 安卓原生客户端（第一阶段：与 WebView 版功能对等）

任务 `t46`（platform-engineer）。用户要求：**安卓不要 WebView，用原生完整实现一个**。
本文件记录：代码结构、与桌面/网页端的协议对齐点、无中继硬约束、证据分层与已知缺口。

## 1. 一句话状态

| 层面 | 状态 |
| --- | --- |
| 原生 Kotlin 源码 | **已写**：10 个源文件（业务逻辑全在 Kotlin，无 WebView 承载） |
| 协议对齐（v2 加入证明 / 数据通道 kind / 帧格式 / 限额） | **已按 `peer.py`、`web/core.js` 逐字对齐**，并有静态断言 + 独立向量交叉验证 |
| 无中继（只收 STUN、拒绝 `turn:`、丢 `relay` 候选、失败不改走服务器） | **静态 + 运行时双闸**，`turn:` 出现即失败 |
| 本机编译 | **NOT_RUN（做不到，如实标注）**：本机无 Android SDK，JDK 25 让 Kotlin 2.1.20 直接失败（见 §7） |
| CI 构建 + APK sha256 | **待 CI 的 `android-native` job 跑第一次**（本任务不在 runner 上跑） |
| 真机运行时 DataChannel | **NOT_RUN**：需要用户在真机安装后验证；**不能拿「构建成功」冒充「可用」** |
| Capacitor APK | **保留不动**（`p2pchat/android/`），移除由 captain 决定 |

## 2. 代码结构（`app/src/main/java/dev/p2pobservatory/nativeprobe/`）

| 文件 | 职责 |
| --- | --- |
| `Protocol.kt` | 与 `core.js` 逐字对齐的纯函数：帧编解码（u16 idLen + id + u32 seq + payload，16 KiB/帧）、`LIMIT`、地址族与候选过滤（`typ relay` 一律丢）、STUN 白名单、握手 HMAC 输入（等价 `JSON.stringify`） |
| `JoinProof.kt` | v2 加入证明：HKDF-SHA256(secret, salt=room, info=`p2pchat/join-key/v2`) + HMAC-SHA256(joinKey, `room\0nonce\0clientSessionId`)；**自检向量**在启动时校验 |
| `SignalingClient.kt` | OkHttp WebSocket：`join_challenge` → `join`(v2) → `welcome`（必须 `strictP2P=true`，`iceServers` 只接受 `stun:`/`stuns:`）→ `roster`/`signal`；遥测上报 `{type:'telemetry',...}`，按 `telemetry_ack` 清批次 |
| `RtcSession.kt` | 一条路径 = 一个 profile：`RTCConfiguration` 只用服务器下发的 STUN；双向 SDP 过滤；`chat` 与 `benchmark` 两条独立 DataChannel；数据通道握手、文本、文件分块与背压、独立通道测速 |
| `PathRunner.kt` | 九条方式的顺序与状态机：三条 WebRTC 档位真连；不支持的如实标「不支持」；STUN 观测成功只标「已观测」 |
| `MethodCatalog.kt` | 界面文案（**逐字来自 `docs/METHODS-PLAIN.md`**）、状态词表、可用性词表、「—」未测得语义、技术详情（内部代号只在这里出现） |
| `Telemetry.kt` | 事件结构与 `backend/telemetry.py` 同源：白名单/枚举/数值键、脱敏、内存 400 条 + 本地 `diagnostics.jsonl` 2 MiB 上限、丢弃计数 `diagnostic.dropped` |
| `Media.kt` | 录音语音消息：`MediaRecorder` → `.m4a` 文件（60 s / 4 MiB 上限），**录完走文件传输**，不做实时通话、不做 STT |
| `Background.kt` | 前台服务 + 通知（锁屏/后台保持连接）；局域网发现：组 `239.255.42.99`、端口 `41420`、多播锁、`lan_key = HMAC(joinKey,"p2pobs-lan-key-v1")`、`scope`/`mac` 与 Python 端同域分隔 |
| `MainActivity.kt` | 三屏原生界面（连接 → 逐条尝试 → 聊天 + 右上角设置）、运行时权限、遥测上传循环 |

工具与构建：`tools/verify_native_client.py`（27 条静态断言）、`tools/probe_join_vectors.py`（独立 HKDF/HMAC 复核向量）、
`gradle/libs.versions.toml`（版本目录）、`app/proguard-rules.pro`（R8 规则）、`app/src/test/.../ProtocolTest.kt`（JVM 单元测试）。

## 3. 协议对齐（加不进房间就等于没做）

- 加入：`{v:1,type:'join',joinVersion:2,room,name,clientSessionId,capabilities,nonce,proof[,verifier]}`；
  `proof = HMAC-SHA256(HKDF-SHA256(secret, salt=room, info='p2pchat/join-key/v2'), room\0nonce\0clientSessionId)`。
  **房间密钥不上链路**；`verifier` 只在房间还没建立密钥时发送（仍然是派生值）。收到非 48 位 hex nonce 就明确失败，绝不回退明文。
- 数据通道控制消息 kind 与 `peer.py` 一致：`hello/hello-ack/ping/pong/text/delivered/file-start/file-ready/file-progress/file-end/bench-start/bench-end/bench-ack/bench-error`；
  二进制分块用 `encodeFrame(id,sequence,payload)`（16 KiB、id ≤ 100 字节）。
- 限额：文件 ≤ 32 MiB、背压高/低水位 512 KiB / 128 KiB、文本 ≤ 16 KiB。
- 握手用**房间密钥** HMAC（与 `core.js Handshake` 一致），未通过握手前的任何消息都不处理。

## 4. 无中继硬约束（四道闸）

1. `Protocol.stunUrls()` 只接受 `stun:`/`stuns:`，遇到 `turn:`/`turns:` 抛 `RELAY_FORBIDDEN`；
2. `RtcSession.assertNoRelay()` 在构造 `RTCConfiguration` 前再断言一次；
3. 本端与对端候选都过 `Protocol.permitted()`：`typ relay` 一律丢弃（三档 profile 都不例外）；
4. 没有任何「失败就改走服务器」的分支：直连失败 = `不可用`，聊天内容从不上行到服务器。

## 5. 文案与诚实状态语义

- 九条方式的「界面名称 / 它到底是什么 / 什么网络下可行 / 失败最常见的原因」与 `docs/METHODS-PLAIN.md` **逐字一致**（静态断言逐条比对）。
- 内部代号（`ice-v6`、`tcp-simopen`、`stun` …）只出现在每行的「技术详情」里。
- 状态词表固定：等待中 / 尝试中 / 已打通 / 已观测 / 不可用 / 不支持；只有能聊天且真的打通的路径才显示「已打通」，
  UDP 探测与 STUN 映射观测成功时显示「已观测」并标注「仅探测，不传内容」。
- 未测得显示 **「—」**，绝不显示 0；探测/观测往返与聊天延迟分开存放、分开标注。
- 本阶段如实标注的能力边界：三条 WebRTC 档位真做；**UDP 探测 / QUIC / TCP / TCP 同时打开 / 路由器放行在原生安卓上显示「不支持」**
  （没有对应的原生通道实现，不假装有）；QUIC 尤其如此（安卓没有可用的标准 QUIC API）。

## 6. 权限与后台

申请且仅申请：`INTERNET`、`ACCESS_NETWORK_STATE`、`RECORD_AUDIO`、`FOREGROUND_SERVICE`、`FOREGROUND_SERVICE_DATA_SYNC`、
`POST_NOTIFICATIONS`、`ACCESS_WIFI_STATE`、`CHANGE_WIFI_MULTICAST_STATE`（静态断言比对，多一个就失败）。
前台服务 `KeepAliveService` 带常驻通知（用户可见）；录音是运行时权限，拒绝时只有语音消息不可用；局域网发现用 `MulticastLock`。
**不做保活欺骗**（没有自启/唤醒锁滥用/隐藏前台服务的花样）。

## 7. 构建（本机做不到，只有 CI 能做）

```bash
# 本机（Linux 开发机，无 Android SDK，JDK 25）——如实记录失败原文
bash p2pchat/android-native/gradlew -p p2pchat/android-native --version
bash p2pchat/android-native/gradlew -p p2pchat/android-native --no-daemon -Pandroid.builder.sdkDownload=false assembleRtcDebug

# runner（预装 android-36 / build-tools 36.0.0 / JDK 21）由 android-native job 执行同一条 assembleRtcDebug
```

- 版本目录 `gradle/libs.versions.toml`：AGP 8.13.0、Kotlin 2.1.20、`io.github.webrtc-sdk:android:150.7871.01`、OkHttp 4.12.0。
- `abiFilters` 只留 `arm64-v8a` / `x86_64`（16 KB 页合规，t5 实测；32 位 ABI 的 PT_LOAD 对齐不达标）。
- `release` 开 R8（`isMinifyEnabled` + `proguard-rules.pro` 保留 WebRTC/OkHttp/协议类），debug 不混淆；不签名、不发布。

## 8. 证据分层（不得互相冒充）

| 层 | 内容 | 当前状态 |
| --- | --- | --- |
| L1 静态 | `tools/verify_native_client.py` 27/27 通过；`tools/probe_join_vectors.py` 独立复核加入证明向量 | **已跑，通过（本机）** |
| L2 构建 | CI `android-native` job 真编译 + APK sha256（`p2pchat/releases/android-native-apk.sha256`）+ artifact 名里的 commit | **待 CI**（本机 NOT_RUN） |
| L3 运行时 | 真机安装后能加入房间、打通 DataChannel、发文本/图片/文件/录音 | **NOT_RUN**：需要用户真机验证 |
| L4 真实家宽 | 端到端穿透证据 | **不在本任务范围**，也不允许用模拟结果替代 |

## 9. 已知缺口（下一步，按 captain 的顺序推进）

1. **CI 第一次构建**是最重要的下一步：编译错误只能由 runner 暴露（本机 JDK/SDK 限制）。
   `sourceCommit` 目前只体现在 artifact 名 `p2p-observatory-android-native-<commit>`；
   若要把它写进 sha256 同一行，需要改 `.github/workflows/build.yml`（**t46 out of scope**，需另派）。
2. JVM 单元测试 `ProtocolTest.kt` 尚未在 CI 上执行（job 只跑 `assembleRtcDebug`）；补好环境后可用
   `./gradlew :app:testRtcDebugUnitTest` 跑（覆盖加入证明向量、帧编解码、地址族过滤、`turn:` 拒绝）。
3. 局域网发现：组播参数与算法域分隔与 Python 端一致，但**没有做过与桌面端的字节级互通实测**，
   界面不声称「局域网发现已工作」；真机 + 桌面同网段时才能确认（NOT_RUN）。
4. 第 4/5/6/7/9 条方式（UDP 探测 / QUIC / TCP / TCP 同时打开 / 路由器放行）在原生安卓上仍是「不支持」，
   要做到与桌面端完全对等需要原生 UDP/QUIC/TCP 适配器（另派任务，且必须保持无中继）。
5. 回退路径：在原生功能对等完成并通过真机验证前，**Capacitor APK 构建保留**（`p2pchat/android/` 未被本任务改动）。
