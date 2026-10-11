# 安卓原生 WebRTC 可行性验证与缺口清单（t5）

任务：`t5`，attempt `9155691c-0ffc-4cab-966d-96f48760a4c8`（platform-engineer）
日期：2026-10-11　范围：只回答"原生 Kotlin + WebRTC SDK 是否可行"和"还缺什么"，不做功能重写。
本机环境：Linux x86_64，无 Android SDK，JDK 仅 25.0.4.1，`/dev/kvm` 存在但无 emulator/系统镜像。

---

## 1. 结论（TL;DR）

| 问题 | 结论 | 依据 |
| --- | --- | --- |
| 依赖是否可用 | **可行** | `io.github.webrtc-sdk:android:150.7871.01` 在 Maven Central 可解析；curl 直下 + 分块重组 + Gradle 解析三次得到同一 sha256 |
| 官方坐标是否可用 | **不可用（已死）** | `org.webrtc:google-webrtc:1.0.32006` 在 Maven Central 与 Google Maven 均 404，Gradle 报 `Could not resolve all files for configuration ':official'` |
| 需要的 API 是否齐全 | **可行** | 18/18 关键类存在（DataChannel / ICE / STUN 配置 / 网络变化 / 音频），JNI 导出 224 个 `Java_org_webrtc_*` 符号 |
| 无中继是否可强制 | **可行** | `RTCConfiguration.iceServers` 由我们构造，只放 STUN 即无 relay；SDK 不提供任何默认 TURN |
| 目标 ABI 是否满足 Android 15+ 16 KB 页要求 | **可行** | arm64-v8a / x86_64 的 PT_LOAD `p_align=0x4000`；armeabi-v7a / x86 只有 `0x1000`，必须继续用 abiFilters 排除 |
| 本机能否编出 APK | **不能（NOT_RUN）** | 本机无 Android SDK；且仅有 JDK 25，Kotlin 2.1.20 直接抛 `IllegalArgumentException: 25.0.4.1` |
| 模拟器 DataChannel 运行证据 | **NOT_RUN** | 无 Android SDK / emulator / 系统镜像；下载镜像需接受许可 → 按边界不下载、不交互 |
| 原生功能是否已对等 | **完全没有** | `app/src/main/` 下只有 AndroidManifest.xml，零 Kotlin 源码、零 res，Manifest 指向不存在的 `.MainActivity` |

**一句话**：技术路线可行、依赖真实可获取、许可证与体积可控；但当前脚手架**只有构建骨架没有一行代码**，且在功能对等（文本/图片/文件/录音）完成前**必须保留**现有 Capacitor APK 构建（`p2pchat/android/`，本任务未改动）。

---

## 2. 可复现证据

### 2.1 坐标与产物身份（三次独立获取，同一个 sha256）

```bash
# a) Maven Central 元数据：latest = release = 150.7871.01
curl -sS https://repo1.maven.org/maven2/io/github/webrtc-sdk/android/maven-metadata.xml

# b) 仓库自报校验（HEAD，2026-10-11）
curl -sSI https://repo1.maven.org/maven2/io/github/webrtc-sdk/android/150.7871.01/android-150.7871.01.aar
#   content-length: 49147033
#   x-checksum-sha1:  b9ae2a17fa38f16ce071f029cf8684fb9166a1c7
#   x-checksum-md5:   c3cd7ed857f7ba00cafadfb65def64e9
#   注意：.sha1 / .sha256 / .md5 边车文件均 HTTP 404 —— 该坐标不发布校验文件

# c) 分 6 段 Range 重组完整产物（单连接会在 ~34–40 MB 被掐断）
#    组装结果 49147033 字节
sha1sum   /tmp/webrtc-full.aar   # b9ae2a17fa38f16ce071f029cf8684fb9166a1c7
sha256sum /tmp/webrtc-full.aar   # 0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0
cmp /tmp/webrtc-full.aar p2pchat/android-native/evidence/webrtc-inspect.aar   # IDENTICAL

# d) 用 Gradle 解析同一坐标（不带 Android 插件，无需 SDK）
gradle -q probe   # COMMUNITY_OK android-150.7871.01.aar bytes=49147033 sha256=0a1627b1...9b0
```

结论：仓库内 `evidence/webrtc-inspect.aar` 与 Maven Central 实际服务的产物**逐字节相同**（sha1 与仓库自报值一致，sha256 三次一致）。

### 2.2 产物身份（记录值）

| 项 | 值 |
| --- | --- |
| 坐标 | `io.github.webrtc-sdk:android:150.7871.01`（Maven Central） |
| 大小 | 49,147,033 字节 |
| sha256 | `0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0` |
| sha1 | `b9ae2a17fa38f16ce071f029cf8684fb9166a1c7` |
| md5 | `c3cd7ed857f7ba00cafadfb65def64e9` |
| 许可证（POM） | The 3-Clause BSD License |
| POM `<dependencies>` | **无**（AAR 自包含，但见缺口 G4） |

### 2.3 本机工具链实况

```bash
java -version            # openjdk 25.0.4.1（/usr/lib/jvm 下只有 java-25-openjdk；AS 自带 jbr 也是 25.0.3）
echo $ANDROID_HOME       # 未设置；ANDROID_SDK_ROOT 未设置
which sdkmanager adb emulator avdmanager   # 全部不存在；~/Android/Sdk、/opt/android-sdk 不存在
test -e /dev/kvm         # 存在；/proc/cpuinfo 有 vmx/svm 20 条
./gradlew --version      # Gradle 8.14.3（wrapper 分发已在 ~/.gradle 缓存内，离线可用）
```

```bash
# 本机构建尝试（真实输出，10 秒内失败）
p2pchat/android-native$ ./gradlew --no-daemon assembleRtcDebug
# FAILURE: Build failed with an exception.
# * What went wrong: 25.0.4.1
# * Exception is:
#   java.lang.IllegalArgumentException: 25.0.4.1
#     at org.jetbrains.kotlin.com.intellij.util.lang.JavaVersion.parse(JavaVersion.java:307)
#     at org.jetbrains.kotlin.cli.jvm.modules.JavaVersionUtilsKt.isAtLeastJava9(javaVersionUtils.kt:11)
# BUILD FAILED in 10s
```

即：本机连配置阶段都过不去（Kotlin 2.1.20 的版本解析器读不了 `25.0.4.1` 这种四段版本号），更不用说需要 `platforms/android-36` 与 `build-tools/36.0.0`。**本任务不产出 APK，也不产出任何 APK/运行 sha256。**

### 2.4 AAR 内容事实（离线探针，可复跑）

工具：`p2pchat/android-native/tools/probe_webrtc_aar.py`（纯标准库，自带 ELF 解析，不依赖 SDK/模拟器/JVM）

```bash
python3 p2pchat/android-native/tools/probe_webrtc_aar.py --remote \
        --json p2pchat/android-native/evidence/probe-webrtc-aar.json
# verdict: PASS（--remote 时同时核对 Maven Central 的 x-checksum-sha1）
```

| ABI | .so 大小 | PT_LOAD p_align | 16 KB 页就绪 | sha256（libjingle_peerconnection_so.so） |
| --- | --- | --- | --- | --- |
| arm64-v8a | 12,287,312 | 0x4000 | 是 | `7b299113fcd743de7dc5559686b21fc2681b2c8598347d8dc0743d2e004995ca` |
| x86_64 | 16,166,352 | 0x4000 | 是 | `0717afcc43da0c1aabd904f9ef0653efc8f3d37b5750f39a123697e7910b623a` |
| armeabi-v7a | 6,809,404 | 0x1000 | 否 | `762f3d5e1c4c69c3f02f2383540f40e1142cb631e9d99e86bdb1602f4c277559` |
| x86 | 12,818,648 | 0x1000 | 否 | `80e7b1b7e07bb5a53841a8cacabf942a6f3eb8ee9759a1731741dd912f367f19` |

- `classes.jar`：1,063,812 字节，sha256 `2789e444c63f5b9b5f9f1ba227d12fbc03dfe617d6b83c0192b426730b3d8989`，字节码 major 61（Java 17，与应用 `sourceCompatibility 17` 一致）。
- AAR 内 `AndroidManifest.xml`：`package="org.webrtc"`，`minSdkVersion=21`、`targetSdkVersion=23` → 与 `minSdk 26` 无冲突。
- AAR 只有 6 个条目：Manifest、classes.jar、4 个 ABI 的 .so；**没有** ProGuard/consumer-rules、没有 assets、没有 R.txt。
- 动态依赖：`libEGL.so libdl.so libm.so liblog.so libc.so`（**不需要** `libc++_shared.so`，因此不存在 AAR 漏带 C++ 运行时的 UnsatisfiedLinkError 风险）。
- 构建指纹：`ELF 64-bit LSB ... for Android 23, built by NDK r30-beta1 (14904198), stripped`；arm64 导出 224 个 `Java_org_webrtc_*` JNI 符号。

### 2.5 关键 API 存在性（javap 实测，18/18）

- 会话/数据：`PeerConnectionFactory.initialize(InitializationOptions)`、`PeerConnectionFactory$Builder.createPeerConnectionFactory()`、`PeerConnection.createDataChannel(String, DataChannel$Init)`、`DataChannel.send(Buffer)`、`DataChannel$Observer`、`DataChannel.state()/label()/id()`。
- ICE/STUN：`PeerConnection$IceServer$Builder`（setUsername/setPassword/setTlsCertPolicy）、`RTCConfiguration.iceServers` / `iceTransportsType` / `continualGatheringPolicy` / `candidateNetworkPolicy` / `stunCandidateKeepaliveIntervalMs` / `disableIPv6OnWifi` / `maxIPv6Networks`、`addIceCandidate(IceCandidate, AddIceObserver)`、`setConfiguration`、`setLocalDescription/SdpObserver`。
- 诊断关联：`PeerConnection$Observer.onSelectedCandidatePairChanged(CandidatePairChangeEvent)`、`onIceCandidateError(IceCandidateErrorEvent)`、`getStats(RTCStatsCollectorCallback)`。
- 网络变化（原生可用性关键）：`NetworkMonitor`、`NetworkChangeDetector`、`PeerConnectionFactory$Options.networkIgnoreMask` / `disableNetworkMonitor`。
- 语音消息：`org.webrtc.audio.JavaAudioDeviceModule` + `Builder`（含 `AudioRecordStartErrorCallback` / `SamplesReadyCallback`）。
- 以上只证明"类与方法在产物里"，**不证明**任何运行行为。

### 2.6 相关坐标可得性（HEAD 实测）

| 坐标 | 来源 | HTTP |
| --- | --- | --- |
| `com.android.tools.build:gradle:8.13.0` | Google Maven | 200 |
| `org.jetbrains.kotlin:kotlin-gradle-plugin:2.1.20` | Maven Central | 200 |
| `androidx.test:runner:1.6.2` | Google Maven | 200 |
| `androidx.test.ext:junit:1.2.1` | Google Maven | 200 |
| `androidx.annotation:annotation:1.10.0` / `1.11.0` | Google Maven | 200 |
| `org.webrtc:google-webrtc:1.0.32006` | Maven Central | **404** |
| `org.webrtc:google-webrtc`（metadata） | Google Maven | **404** |

---

## 3. 缺口清单（按严重度）

| ID | 严重度 | 缺口 | 必须怎么修 |
| --- | --- | --- | --- |
| G1 | blocker（本机） | 本机无 Android SDK：无 `ANDROID_HOME`、无 `sdkmanager/adb/emulator`、无 `platforms/android-36`、无 `build-tools/36.0.0`。下载 SDK 需接受许可 → 边界禁止，故本机无法出 APK | 只在 CI（runner 预装 SDK）或用户装有 SDK 的机器上构建；本机保持 NOT_RUN，禁止用 JVM/Robolectric 结果替代 |
| G2 | blocker（本机） | 本机仅 JDK 25.0.4.1；Kotlin 2.1.20 抛 `IllegalArgumentException: 25.0.4.1`，AGP 8.13 官方支持区间为 JDK 17–21 | 构建环境固定 JDK 17 或 21（现有 CI 用 temurin 21.0.10 合适）；不要用系统 java 25 |
| G3 | blocker（功能） | `p2pchat/android-native/app/src/main/` 只有 `AndroidManifest.xml`：零 Kotlin 源码、零 `res/`，Manifest 声明 `.MainActivity`（`dev.p2pobservatory.nativeprobe.MainActivity`）**不存在** → 即使构建成功，安装后启动即崩 | 先实现最小可运行 Activity + 真实 DataChannel 双端互通路径，再谈对等；在拿到真实运行证据前不得声称"原生可用" |
| G4 | medium | AAR 的 POM **不声明任何依赖**，但 classes.jar 中 93 个类、103 处引用 `androidx/annotation` | 应用侧显式加 `androidx.annotation:annotation:1.11.0`（Google Maven 200）；不要依赖"恰好能编过" |
| G5 | medium | AAR **不带** consumer ProGuard/R8 规则（探针 `consumer_proguard_rules: []`） | debug 不受影响；一旦 release 开 `minifyEnabled`，必须自加 `-keep class org.webrtc.** { *; }` 等规则（JNI 通过类名查找），并在真机装 release 包验证 |
| G6 | medium | 体积：AAR 49 MB / 4 ABI；按当前 `abiFilters = arm64-v8a + x86_64`，`useLegacyPackaging=false` 时 .so 不压缩进 APK ≈ 28.5 MB 原生库 + 1.06 MB classes | 面向用户出 arm64-v8a 单 ABI（或 ABI split）；x86_64 仅留给模拟器；把预期体积写进发布说明，避免"原生包突然 30 MB"被当成回归 |
| G7 | medium | 16 KB 页：armeabi-v7a / x86 是 `p_align=0x1000`，**不满足** Android 15+ 16 KB 设备与 targetSdk≥35 要求 | 保持只打包 arm64-v8a / x86_64；探针已把该检查固化为可回归门（`--abis` 默认读 `app/build.gradle.kts` 的 abiFilters） |
| G8 | medium | 供应链：镜像不发布 `.sha1/.sha256` 边车文件（404），只有 `x-checksum-*` 头；产物由第三方用 `NDK r30-beta1`（beta 工具链）打包，非 Google 官方构建 | 锁版本；用本报告 sha256 或探针 `--remote` 做校验；需要更强校验就落 `gradle/verification-metadata.xml`（sha256 固定），并禁止自动升级版本 |
| G9 | high（证据） | 原生运行证据 = **NOT_RUN**：本机无 SDK/emulator/系统镜像（`/dev/kvm` 存在但无镜像可用），下载镜像即接受许可 → 不做 | 首选用户真机装 APK 实测（最有价值）；CI 只在"预装系统镜像 + emulator + KVM"三者同时成立时跑模拟器 DataChannel，否则打印探针结果并标 NOT_RUN |
| G10 | high（流程） | `.github/workflows/build.yml` 现有 `android` job 构建的是 Capacitor APK，**没有** android-native job | 由 t6 增补独立的 `android-native` job（见 §4）；在原生功能对等前**不得**删除现有 Capacitor APK 构建 |
| G11 | medium（协议） | 原生侧若照抄示例代码容易引入 `iceTransportsType=RELAY` 或加 TURN 服务器条目 | 明确：`iceServers` 只放 STUN（本项目自己的 STUN/信令），禁止 TURN/中继；`RELAY` 策略值属 ICE 配置变体，**不是**独立协议，UI 与文档都不得那样表述 |
| G12 | medium | 可用性能力（原生相对 WebView 的最大卖点）尚未实现：网络切换自动重建、IPv6 双栈候选、丢包统计 | 用 `NetworkMonitor/NetworkChangeDetector` + `PeerConnectionFactory$Options.networkIgnoreMask` + `stunCandidateKeepaliveIntervalMs` 实现，并必须在真机/真实家宽上验证（同机、模拟器结果不算穿透证据） |
| G13 | medium | Manifest 缺权限与前台服务声明：录音语音消息需要 `RECORD_AUDIO`（+ 运行时申请），长连接后台保活需要前台服务类型；当前只有 `INTERNET` | 加 `RECORD_AUDIO`、按需 `POST_NOTIFICATIONS`、`foregroundServiceType="dataSync|microphone"` 等，并做 Android 14+ 前台服务合规检查 |
| G14 | low | `gradle.properties` 里 `android.builder.sdkDownload=false` 与现有 CI 的 SDK 断言必须配套 | CI 先断言 `$ANDROID_HOME/platforms/android-36` 与 `build-tools/36.0.0` 存在（沿用现有 Capacitor job 的写法），再做原生构建；失败就失败，不偷偷下载 |
| G15 | low | `evidence/`（含 49 MB AAR）被 `.gitignore` 忽略；根 `build.gradle.kts` 的 `probeWebRtcCoordinates` 任务在**没有 SDK** 的机器上跑不起来（配置 `:app` 需要 AGP+SDK），恰好是最需要它的场景 | 保留探针但写明前置条件；需要无 SDK 的坐标校验就用 `tools/probe_webrtc_aar.py --remote`（本报告已实测）或独立小工程解析 |

补充观察（非阻塞，供审查）：
- 根 `build.gradle.kts` 里 `officialWebRtc` 负向探针失败被吞掉（只对 `alternative` 抛错），这是有意设计，但读代码的人容易误以为官方坐标可用；建议在注释里直接写明"官方坐标 404，仅作负向记录"。
- AAR 内 4 个 ABI 里 2 个（armeabi-v7a/x86）不满足 16 KB 页；若将来需求要覆盖 32 位设备，必须换版本或换镜像。

---

## 4. 给 t6（CI 矩阵）的结论与建议

结论：**可以新增 android-native 构建 job**，但必须满足三个前置并保持现有 Capacitor job 不动。

建议 job（草案，**未在本机验证过**——本机无 SDK，第一次 CI 运行才是第一份真实证据）：

```yaml
  android-native:
    runs-on: ubuntu-24.04
    timeout-minutes: 40
    steps:
      - uses: actions/checkout@v5
      - uses: actions/setup-java@v5
        with: { distribution: temurin, java-version: '21' }   # 不用系统 JDK 25（见 G2）
      - name: Assert runner SDK present (no license acceptance, no download)
        run: |
          test -n "$ANDROID_HOME"
          test -d "$ANDROID_HOME/platforms/android-36"
          test -d "$ANDROID_HOME/build-tools/36.0.0"
      - name: Environment probes (read-only, honest NOT_RUN source)
        run: |
          sdkmanager --list_installed || true
          ls /usr/local/lib/android/sdk/system-images 2>/dev/null || echo NO_PREINSTALLED_SYSTEM_IMAGES
          test -e /dev/kvm && echo KVM_PRESENT || echo KVM_ABSENT
          emulator -accel-check || true
      - name: Dependency + artifact probe (no mock, content-level only)
        run: python3 p2pchat/android-native/tools/probe_webrtc_aar.py --remote --json p2pchat/releases/android-native-aar.json
      - name: Build native spike APK
        working-directory: p2pchat/android-native
        run: ./gradlew --no-daemon -Pandroid.builder.sdkDownload=false assembleRtcDebug
      - name: Record artifact sha256
        run: sha256sum p2pchat/android-native/app/build/outputs/apk/rtc/debug/*.apk | tee p2pchat/releases/android-native-apk.sha256
```

模拟器 DataChannel 验证：**只有在"预装系统镜像 + emulator + KVM"三者同时成立时**才跑；否则打印上述探针输出并明确标 `NOT_RUN`。禁止 Robolectric/JVM/mock 结果顶替（G9）。

---

## 5. 明确未做的事 / 未验证边界

- 未改 `p2pchat/android/`（Capacitor 工程）任何文件；未删除任何现有可交付构建。
- 未改 `.github/workflows/`（属 t6 inScope），§4 只是建议草案。
- 未下载 Android SDK / 系统镜像，未接受任何许可，未 `git`/推送/发布。
- 未写 Kotlin 代码，未产出 APK，因此**没有**任何 APK sha256 或原生运行证据。
- 依赖坐标、AAR 内容、16 KB 对齐、androidx 引用、坐标可得性均为本机实测；CI runner 上 `platforms/android-36`、`build-tools/36.0.0`、系统镜像与 KVM 的实际状态**未在本机验证**（PENDING）。
- 体积估算为按 .so 大小与 `useLegacyPackaging=false` 推导的**估算值**，非实测 APK 大小。
