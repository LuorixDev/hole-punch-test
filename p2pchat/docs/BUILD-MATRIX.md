# CI 构建矩阵（GitHub Actions）

工作流文件：`.github/workflows/build.yml`。触发方式：`workflow_dispatch` 或推送到 `build/p2p-observatory` 分支。
权限只有 `contents: read`；**不发布 Release、不部署、不签名、不做许可交互接受**；产物一律是私有 artifact，保留 14 天。

## 一、两个 job

| job id | 名称 | runner | 超时 | 作用 |
| --- | --- | --- | --- | --- |
| `build` | `Clients (${{ matrix.target }})` | 矩阵 `ubuntu-24.04` / `windows-2022` / `ubuntu-24.04` | 40 min | 质量门 + 按平台构建桌面客户端（linux/windows）+ 保留的 Capacitor 安卓 APK（android） |
| `android-native` | `Android native spike (WebRTC AAR)` | `ubuntu-24.04` | 40 min | 原生 Kotlin spike 的依赖校验与 APK 构建（不替代上面的 Capacitor APK） |

`build` 的矩阵目标：`linux`（Linux 桌面）、`windows`（Windows 桌面）、`android`（Capacitor APK）。
`fail-fast: false`：一个平台失败不会取消其它平台；**失败如实保留，不跳过、不掩盖**。

## 二、每个平台的步骤（`build` job）

所有平台都跑（质量门，均保持不变）：

1. `actions/checkout@v5`；
2. `actions/setup-node@v6`（24.20.0，npm 缓存指向 `p2pchat/package-lock.json`）；
3. `actions/setup-python@v6`（3.12，pip 缓存指向 `requirements.txt` / `platform/build-requirements.txt` / `platform/constraints.txt`）；
4. `Install locked npm dependencies (no unreviewed lifecycle scripts)`：`npm ci --ignore-scripts`；
5. `Python dependencies and bundler`：按锁定约束安装运行时与打包依赖；
6. `Platform and client gates`：`node --test tests/platform/*.test.cjs tests/client/*.test.cjs`（**必须用 glob 形式**，目录形式在 Node 24 下会 `Cannot find module`，见 `p2pchat/tests/platform/README.md`）+ `npm audit --omit=dev --audit-level=moderate` + `npm audit --audit-level=high`；
7. `Python gates (repository root, bounded diagnostic runner)`：`unittest discover -s p2pchat/ci`、**Windows 上的有界诊断**（`ci/watchdog.py` 包裹 `windows-analysis/diagnostic_runner.py`）、`ci/watchdog.py --timeout 600` 包裹的 `pytest p2pchat/tests` 全量套件。三个日志分别落到 `p2pchat/releases/`。

桌面平台（`linux` / `windows`）额外：

8. `Build desktop client with PyInstaller (one-folder bundle)`：
   `python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec`（依赖 spec 里的 `pyinstaller==6.20.0` 与 `platform/constraints.txt`）→ 日志 `p2pchat/releases/desktop-build.log`；
9. `Run the packaged desktop self-test (headless, real handshake)`：运行**打包产物**的 `--self-test`（Linux `dist/p2p-desktop/p2p-desktop`、Windows `dist/p2p-desktop/p2p-desktop.exe`），做一次真实握手（服务端 + 回声 + 客户端同进程）→ 日志 `p2pchat/releases/desktop-selftest.log`；
10. `Package desktop bundle (explicit name; no installer, no signing)`：`tar -czf releases/p2p-desktop-<target>-x64.tar.gz -C .. dist/p2p-desktop`。

安卓平台（`android`）额外（**保留不动**，直到原生 Kotlin 功能对等）：

11. `actions/setup-java@v5`（temurin `21.0.10`）；
12. `Build Capacitor Android APK using preinstalled runner SDK (no license acceptance)`：断言 runner 预装 `platforms/android-36` 与 `build-tools/36.0.0`，`npm run android:sync`，`bash android/gradlew -p android --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug`，APK 复制进 `p2pchat/releases/`。
    **不执行 `sdkmanager --licenses`，不下载 SDK 组件**——只用 runner 预装件，缺了就失败。

所有平台最后两步：

13. `Record artifact sha256 and dependency audit (no release, no deploy)`（`if: always()`）：写 `npm-audit.json`，并对 `p2pchat/releases/` 下所有产物生成 `SHA256SUMS.txt`；
14. `Upload private build output and failure evidence (no release)`（`if: always()`）：`actions/upload-artifact@v6`，`retention-days: 14`，`if-no-files-found: error`。

## 三、android-native job 的步骤

1. `actions/checkout@v5`；
2. `actions/setup-java@v5`（temurin `21.0.10`；**不要用 runner 的系统 JDK**，原因见下）；
3. `actions/setup-python@v6`（3.12，只给产物校验脚本用，脚本是纯标准库）；
4. `Assert the runner SDK is present (no download, no license acceptance)`：先把 `ANDROID_HOME` / `android-36` / `build-tools 36.0.0` 的存在性写进 `android-native-probes.log`，再断言；缺失即失败，**不下载、不接受许可**；
5. `Read-only environment probes (system image, emulator, KVM)`：`sdkmanager --list_installed`、`$ANDROID_HOME/system-images` 列表、`command -v emulator`、`test -e /dev/kvm`、`emulator -accel-check`（全部只读，追加进同一个日志）；
6. `Build the native spike APK (preinstalled SDK, no license acceptance)`：
   `bash p2pchat/android-native/gradlew -p p2pchat/android-native --no-daemon --console=plain -Pandroid.builder.sdkDownload=false assembleRtcDebug` → 日志 `android-native-build.log`；
7. `Verify the resolved WebRTC artifact contents and record APK sha256`（`if: always()`）：从 Gradle 缓存里找到 `io.github.webrtc-sdk:android:150.7871.01` 的 AAR，跑 `p2pchat/android-native/tools/probe_webrtc_aar.py <aar> --abis arm64-v8a,x86_64 --json …`（真实内容校验：sha256、ABI、16 KB 页对齐、必需类），写 `webrtc-aar-probe.json/log`；再对 `app/build/outputs/apk/rtc/debug/*.apk` 记 sha256 到 `android-native-apk.sha256`（没产出则如实写 `NO_APK_PRODUCED`）；
8. `Data channel runtime verification status (never fabricated)`：写 `android-native-emulator-status.txt`，明确 `DATA_CHANNEL_RUNTIME_TEST: NOT_RUN` 及原因；
9. `Upload private android-native evidence (no release)`：`retention-days: 14`。

## 四、产物路径与命名

| 平台 | 产物 | 路径 | sha256 记录 |
| --- | --- | --- | --- |
| Linux 桌面 | `p2p-desktop-linux-x64.tar.gz`（解包得 `dist/p2p-desktop/`，入口 `p2p-desktop`） | `p2pchat/releases/` | `p2pchat/releases/SHA256SUMS.txt` |
| Windows 桌面 | `p2p-desktop-windows-x64.tar.gz`（入口 `p2p-desktop.exe`） | `p2pchat/releases/` | 同上 |
| 安卓（Capacitor，保留） | `app-debug.apk`（生产名 `p2p-observatory-android-<sha>` artifact） | `p2pchat/releases/` | 同上 |
| 安卓原生 spike | `app-rtc-debug.apk` + 探测/构建日志 + AAR 探针 json | `p2pchat/releases/`、`p2pchat/android-native/**/build/` | `p2pchat/releases/android-native-apk.sha256` |

artifact 名称：`p2p-observatory-<target>-<commit sha>` 与 `p2p-observatory-android-native-<commit sha>`，均保留 14 天。

> 关于 `p2pchat/tools/artifact-manifest.py`：该工具仍会对已删除的 `electron-builder.yml` 取 sha256 并抛 `FileNotFoundError`（实测 exit 1，见本任务报告），而 `p2pchat/tools/` 不在本任务范围，因此工作流**暂时不再调用它**，改用工作流内的 `sha256sum` 生成 `SHA256SUMS.txt`（记录范围反而更全：含 apk/tar.gz/日志/json）。修复该工具（以及同样引用已删文件的 `p2pchat/tools/freeze.py`）需要单独派单。

## 五、诚实标注（未验证的东西不会被写成通过）

- **本机（Linux 开发机）没有 Android SDK**，`android-native` job 的所有步骤在本地都是 **NOT_RUN**：Java/Gradle 只验证到 `gradlew --version` 与 `assembleRtcDebug` 因缺 SDK/JDK 25 而失败（可行性报告 G1/G2）。**这个 job 的第一次 CI 运行才是它的第一份真实证据**，本地没有、也不会有它的结果。
- **构建成功 ≠ 应用可用**：`p2pchat/android-native` 目前只有构建脚手架与 AndroidManifest，没有 Kotlin 源码也没有 instrumentation 用例（可行性报告 G3）。所以模拟器 DataChannel 验证是 `NOT_RUN`（原因写在 `android-native-emulator-status.txt`）：没有可执行的用例，且按边界不下载系统镜像、不接受许可。
- **Windows 桌面未验证**：spec 头注释与 `docs/DESKTOP-PYTHON.md` 都标注了 Windows/macOS 未实测；`build (windows)` 第一次运行的结果就是结论，**失败就留失败**。
- **Linux 桌面已实测**：`p2p-desktop --self-test` 在打包产物上跑通（本机 25.8 秒，真实握手，双栈直连 + IPv4 直连，退出码 0），打包命令与 `tar` 打包命令也按工作流里的原样验证过。
- CI 只证明「能构建、能跑自检」；**不代表家宽/NAT 穿透成功**，也不代表真机安装/录音/锁屏行为（那些需要用户实机）。

## 六、本地复现（与工作流同样的命令）

```bash
# 质量门
node --test p2pchat/tests/platform/*.test.cjs p2pchat/tests/client/*.test.cjs
.venv/bin/python -m unittest discover -s p2pchat/ci -p 'test_*.py'
.venv/bin/python -m pytest p2pchat/tests -q

# 桌面（Linux 已实测；Windows 用 Windows 上的 python 执行同一条命令）
.venv/bin/python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec
./dist/p2p-desktop/p2p-desktop --self-test
tar -czf /tmp/p2p-desktop-linux-x64.tar.gz -C . dist/p2p-desktop

# 安卓原生 spike（需要已授权的 SDK 36 / build-tools 36.0.0 + JDK 21）
bash p2pchat/android-native/gradlew -p p2pchat/android-native --no-daemon \
  -Pandroid.builder.sdkDownload=false assembleRtcDebug
python p2pchat/android-native/tools/probe_webrtc_aar.py "$AAR" --abis arm64-v8a,x86_64 --remote
```

## 七、本任务范围外的遗留（需 captain 另派）

- `p2pchat/tools/artifact-manifest.py:23`、`p2pchat/tools/freeze.py:8,17` 仍引用已删除的 `electron-builder.yml` / `platform/native_entry.py`。
- `p2pchat/package-lock.json` 仍是旧锁文件：根条目里还写着 `electron` / `electron-builder`，全文 40 个条目提到 electron/asar（实测）。`npm ci` 的同步检查通过（exit 0），所以 CI 不会因此红，但每个 job 仍会装这些死包，`npm-audit.json` 也会带上它们的 advisory（当前 `--omit=dev --audit-level=moderate` 与 `--audit-level=high` 都是 exit 0，门没有被削弱）。清理方式（需要单独的 npm/依赖任务）：删掉锁里这两个包后 `npm install --package-lock-only --ignore-scripts`，再用 `grep -c "node_modules/electron" package-lock.json` 复核为 0。
- `p2pchat/README.md` 的「Linux Electron / Windows Electron」两行与 `p2pchat/PLATFORMS.md` 的 Electron 表述需要归属人同步。
- 旧的 sidecar 构建产物（`p2pchat/platform/work/p2p-native/warn-*.txt`）已不再上传：CI 不再运行那条 sidecar 构建链；`p2pchat/tools/build-native.cjs` 是否保留由 `tools/` 归属人决定。
