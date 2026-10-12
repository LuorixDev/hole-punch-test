# CI 构建矩阵（GitHub Actions）

工作流文件：`.github/workflows/build.yml`。触发方式：`workflow_dispatch` 或推送到 `build/p2p-observatory` 分支。
权限只有 `contents: read`；**不发布 Release、不部署、不签名、不做许可交互接受**；产物一律是私有 artifact，保留 14 天。

## 一、两个 job

| job id | 名称 | runner | 超时 | 作用 |
| --- | --- | --- | --- | --- |
| `build` | `Clients (${{ matrix.target }})` | 矩阵 `ubuntu-24.04` / `windows-2022` / `ubuntu-24.04` | 40 min | 质量门 + 编码防线 + 按平台构建桌面客户端（linux/windows）+ 保留的 Capacitor 安卓 APK（android） |
| `android-native` | `Android native spike (WebRTC AAR)` | `ubuntu-24.04` | 40 min | 原生 Kotlin spike 的依赖校验与 APK 构建（不替代上面的 Capacitor APK） |

`build` 的矩阵目标：`linux`（Linux 桌面）、`windows`（Windows 桌面）、`android`（Capacitor APK）。
`fail-fast: false`：一个平台失败不会取消其它平台；**失败如实保留，不跳过、不掩盖**。
工作流里 **没有任何 `continue-on-error`**（实测 `grep -c continue-on-error` = 0），新增的编码门也没有 `|| true`、没有 deselect。

## 二、每个平台的步骤（`build` job）

所有平台都跑（质量门，均保持不变）：

1. `actions/checkout@v5`；
2. `actions/setup-node@v6`（24.20.0，npm 缓存指向 `p2pchat/package-lock.json`）；
3. `actions/setup-python@v6`（3.12，pip 缓存指向 `requirements.txt` / `platform/build-requirements.txt` / `platform/constraints.txt`）；
4. `Install locked npm dependencies (no unreviewed lifecycle scripts)`：`npm ci --ignore-scripts`；
5. `Python dependencies and bundler`：按锁定约束安装运行时与打包依赖；
6. `Platform and client gates`：`node --test tests/platform/*.test.cjs tests/client/*.test.cjs`（**必须用 glob 形式**，目录形式在 Node 24 下会 `Cannot find module`，见 `p2pchat/tests/platform/README.md`）+ `npm audit --omit=dev --audit-level=moderate` + `npm audit --audit-level=high`；
7. `Python gates (repository root, bounded diagnostic runner)`：`unittest discover -s p2pchat/ci`、**Windows 上的有界诊断**（`ci/watchdog.py` 包裹 `windows-analysis/diagnostic_runner.py`）、`ci/watchdog.py --timeout 600` 包裹的 `pytest p2pchat/tests` 全量套件。三个日志分别落到 `p2pchat/releases/`。

桌面平台与 Windows 目标（`linux` / `windows`，即 `matrix.target != 'android'`）额外：

8. `Python encoding gate (implicit encoding fails here, not on the next Windows run)`：`PYTHONWARNDEFAULTENCODING=1` + `-X warn_default_encoding` + `-W error::EncodingWarning` 跑 `p2pchat/tests/backend`（`ci/watchdog.py --timeout 600` 包裹）→ 日志 `p2pchat/releases/encoding-gate.log`。详见第三节；
9. `Non-UTF-8 default encoding scan (LC_ALL=C, ASCII-only paths)`（仅 `linux`）：`LC_ALL=C PYTHONCOERCECLOCALE=0 PYTHONUTF8=0` + 同上钳制，从 `/tmp` 下的 ASCII 符号链接路径跑 `p2pchat/tests`（唯一排除 `tests/desktop/test_engine.py`，理由见 3.5）→ 日志 `p2pchat/releases/non-utf8-encoding-scan.log`。详见第三节。

桌面平台（`linux` / `windows`）额外：

10. `Build desktop client with PyInstaller (one-folder bundle)`：
    `python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec`（依赖 spec 里的 `pyinstaller==6.20.0` 与 `platform/constraints.txt`）→ 日志 `p2pchat/releases/desktop-build.log`；
11. `Run the packaged desktop self-test (headless, real handshake)`：运行**打包产物**的 `--self-test`（Linux `dist/p2p-desktop/p2p-desktop`、Windows `dist/p2p-desktop/p2p-desktop.exe`），做一次真实握手（服务端 + 回声 + 客户端同进程）→ 日志 `p2pchat/releases/desktop-selftest.log`；
12. `Package desktop bundle (explicit name; no installer, no signing)`：`tar -czf releases/p2p-desktop-<target>-x64.tar.gz -C .. dist/p2p-desktop`。

安卓平台（`android`）额外（**保留不动**，直到原生 Kotlin 功能对等）：

13. `actions/setup-java@v5`（temurin `21.0.10`）；
14. `Build Capacitor Android APK using preinstalled runner SDK (no license acceptance)`：断言 runner 预装 `platforms/android-36` 与 `build-tools/36.0.0`，`npm run android:sync`，`bash android/gradlew -p android --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug`，APK 复制进 `p2pchat/releases/`。
    **不执行 `sdkmanager --licenses`，不下载 SDK 组件**——只用 runner 预装件，缺了就失败。

所有平台最后两步：

15. `Record artifact sha256 and dependency audit (no release, no deploy)`（`if: always()`）：写 `npm-audit.json`，并对 `p2pchat/releases/` 下所有产物生成 `SHA256SUMS.txt`；
16. `Upload private build output and failure evidence (no release)`（`if: always()`）：`actions/upload-artifact@v6`，`retention-days: 14`，`if-no-files-found: error`。新增的两个编码日志（`*.log`）随既有 `p2pchat/releases/*.log` 一起上传，失败证据不会丢。

## 三、编码防线（t32 建门，t35 扩到全域）

背景：t29/t30 清掉 backend 域 18 处隐式编码依赖，但那条命令只活在成员终端里；t32 把它固化成 CI 两步；
t35 清掉 4 处根因（6 个写法）后，把两步的扫描范围从 `p2pchat/tests/backend` 扩到整套 `p2pchat/tests`。
两步在 `build` job 里（`linux`/`windows` 都跑；`android` 目标不跑 Python 测试，故排除）。

### 3.1 步骤 8：EncodingWarning 当错误（全域 482 条）

```bash
PYTHONWARNDEFAULTENCODING=1 python -u p2pchat/ci/watchdog.py --timeout 600 -- \
  python -u -X warn_default_encoding -W error::EncodingWarning \
  -m pytest p2pchat/tests -q -o faulthandler_timeout=60 | tee -a p2pchat/releases/encoding-gate.log
```

- 任何未指定 `encoding` 的 `open()` / `Path.read_text()` / `Path.write_text()` / 文本模式 `subprocess` 都会抛 `EncodingWarning` → 直接失败（`-W error::EncodingWarning` 把它变成异常）；
- 日志第一段如实记录 runner 的 `sys.getdefaultencoding()` / `locale.getpreferredencoding(False)` / `sys.getfilesystemencoding()`；
  Windows 上额外打印 `WINDOWS_DEFAULT_CODE_PAGE` 与 `EFFECTIVE_NON_UTF8_DEFAULT`（cp1252 时是 `YES`），
  于是"Windows 默认码页天然覆盖 cp1252"这件事有日志可查，而不是口头声明；
- `set -o pipefail` 保证 `tee` 不吞退出码；没有 `continue-on-error`、没有 `|| true`、没有 deselect/`-k`。

### 3.2 步骤 9：非 UTF-8 默认编码扫描（仅 linux；全域减去 1 个结构性不兼容文件）

```bash
PREFIX="$(python -c 'import sys; print(sys.prefix)')"
ln -sfn "$GITHUB_WORKSPACE" /tmp/enc-scan/repo
ln -sfn "$PREFIX" /tmp/enc-scan/pyprefix
cd /tmp/enc-scan/repo
LC_ALL=C PYTHONCOERCECLOCALE=0 PYTHONUTF8=0 PYTHONWARNDEFAULTENCODING=1 \
  /tmp/enc-scan/pyprefix/bin/python -u p2pchat/ci/watchdog.py --timeout 600 -- \
  /tmp/enc-scan/pyprefix/bin/python -u -X warn_default_encoding -W error::EncodingWarning \
  -m pytest p2pchat/tests -q --ignore=p2pchat/tests/desktop/test_engine.py \
  -o faulthandler_timeout=60 | tee -a p2pchat/releases/non-utf8-encoding-scan.log
```

**为什么必须先建 ASCII 符号链接再 `cd` 进去（本机实测，不是推测）**：

| 做法 | 结果 |
| --- | --- |
| 直接从真实仓库路径（本机目录名含中文）跑 `LC_ALL=C … -m pytest p2pchat/tests/backend` | **14 个 collection error**：`UnicodeEncodeError: 'utf-8' codec can't encode characters in position 30-35: surrogates not allowed` |
| 同上，只 `import multidict` | 同一个 `surrogates not allowed`（定位到 `_multidict` C 扩展导入那一行） |
| 用 `/tmp/enc-scan/{repo,pyprefix}` 两个 ASCII 符号链接进入后跑同一命令 | **231 passed**（日志里 `default=utf-8 preferred=ANSI_X3.4-1968 fs=ascii`） |

根因是**与被测代码无关的环境噪声**：`LC_ALL=C` 让文件系统编码变成 ascii，而解释器前缀 / site-packages 的路径里含非 ASCII 字符，
C 扩展导入时需要把它按 UTF-8 编码 → `surrogates not allowed`。符号链接让 `sys.executable` / `sys.prefix` 变成纯 ASCII。
注意：即使从符号链接进入，`os.getcwd()` 仍会解析成真实（含中文）路径——这一步治的是"解释器/包路径"，不是 cwd；
GitHub runner 的路径本来就是 ASCII，符号链接是让**同一条命令在路径含非 ASCII 的开发机上也能跑**。

**本机复现的两个额外条件（实测）**：

1. 在**路径含非 ASCII 的开发机**上，符号链接还不够：`p2pchat/tests/desktop/test_ui.py` 的 5 条 Qt 用例
   （`QApplication` 初始化）会因为 cwd 仍是中文路径而 `UnicodeEncodeError: ... surrogates not allowed`（ERROR）。
   要完整复现 CI（runner 的 workspace 本来就是 ASCII），需要**真实的 ASCII 副本**，例如：
   `mkdir -p /tmp/enc-ascii && tar -cf - --exclude=node_modules --exclude=.git --exclude=dist . | (cd /tmp/enc-ascii && mkdir -p repo && cd repo && tar -xf -) && mkdir -p /tmp/enc-ascii/repo/p2pchat/releases`
   （实测：ASCII 副本下 Qt 用例正常，只剩 3.5 里那 4 条结构性失败）。
2. 步骤 9 在 `cd` 之前 `mkdir -p p2pchat/releases`，`cd` 之后把日志写回同一个目录 —— 所以**副本里必须先有 `p2pchat/releases/`**，否则 `tee` 会报 `No such file or directory`（本机实测踩过一次）。

### 3.3 实测证据（本机 Linux，Python 3.12.14；两步命令从 `build.yml` 原样提取执行）

成功（t35 最终状态）：

| 步骤 | 实测输出 | 退出码 | 耗时 |
| --- | --- | --- | --- |
| 8 EncodingWarning 当错误（全域 482 条） | `482 passed, 53 warnings` / `WATCHDOG_FINISHED exitCode=0`；日志 `default=utf-8 preferred=UTF-8 fs=utf-8`；**EncodingWarning 出现 0 次** | 0 | 123 s |
| 9 C locale 扫描（469 条） | `469 passed, 49 warnings` / `WATCHDOG_FINISHED exitCode=0`；日志 `preferred=ANSI_X3.4-1968 fs=ascii` | 0 | 112 s |

失败一次（负例）：把 `p2pchat/tests/test_core.py:58` 临时改回不带 `encoding` 的 `read_text()`，用步骤 8 的命令原样跑：
`EncodingWarning: 'encoding' argument not specified` → `1 failed, 481 passed`，`WATCHDOG_FINISHED exitCode=1`（整体 exit=1）；
随后撤销、`grep` 确认恢复成 `read_text(encoding='utf-8')`，再跑一次全绿。
（t32 时的另一个负例仍然有效：C locale 下不带 `encoding` 读含中文的文件 → `UnicodeDecodeError: 'ascii' codec can't decode byte 0xe8 ...`。）

### 3.4 时间代价

| 步骤 | 本机实测 | 对比 t32（只跑 backend） |
| --- | --- | --- |
| 8 EncodingWarning 当错误（482 条） | 123 s | +101 s |
| 9 C locale 扫描（469 条） | 112 s | +90 s |
| 合计 | **+235 s / job（约 3.9 min）** | t32 时为 +44 s |

两步各自 `timeout-minutes: 12`；job 总超时仍是 40 min。

### 3.5 覆盖面与一处结构性边界（不掩盖）

- **步骤 8 覆盖整套 `p2pchat/tests`**（本机 482 条全集，EncodingWarning 0 次）。t32 报告里的 4 个根因（共 6 个写法）
  都在 t35 修好，统一只加显式编码、不改行为：
  `p2pchat/native/adapter.py:69`（产品代码，读 `/proc/net/route`，仍保留原来的 `try/except OSError → return None` 降级）、
  `p2pchat/tests/test_core.py:58` 与 `:98`、`p2pchat/tests/native/test_security.py:102` 与 `:116`（`subprocess.run(..., text=True)` 补 `encoding="utf-8"`）、
  `p2pchat/tests/integration/test_cross_language.py:15`（同上）。
- **步骤 9 覆盖 469 条**，唯一排除 `p2pchat/tests/desktop/test_engine.py`（13 条，其中 4 条触发）：
  `test_real_webrtc_handshake_text_and_file`、`test_no_direct_path_is_reported_not_faked`、
  `test_gateway_methods_report_real_capability_but_never_message`、`test_udp_probe_reports_probe_only`
  用**中文标签**拼出数据目录（如 `lab.config("网关回声")`），在 `LC_ALL=C`（`fs=ascii`）下
  `p2pchat/backend/telemetry.py:67` 的 `directory.mkdir(parents=True, exist_ok=True)` 必然
  `UnicodeEncodeError: 'ascii' codec can't encode characters ...` —— 这是「ASCII 文件系统无法创建这个文件名」的
  结构性限制，**不是**被测代码的隐式编码缺陷（这 4 条在步骤 8 的全域门里是绿的）。
  归属：`p2pchat/tests/desktop/`；修法二选一：把那几条的标签/目录名改成 ASCII，或显式声明需要 UTF-8 文件系统。
  修好后删掉步骤 9 的 `--ignore=...` 即可覆盖 482 条全集（命令其余部分不动）。
- 既有 `Python gates` 步骤里的 Windows 全量 `pytest p2pchat/tests`（不带钳制）仍在 cp1252 默认码页下运行，
  属于"整套的非 UTF-8 运行时覆盖"；t32/t35 都没有改动它、也没有削弱它。
- 易混淆点：`p2pchat/server.py:630` 在 C locale 日志里出现的那一行是 aiohttp 的 `NotAppKeyWarning`（`web.Application(...)`），
  **不是**隐式编码问题。

## 四、android-native job 的步骤

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

## 五、产物路径与命名

| 平台 | 产物 | 路径 | sha256 记录 |
| --- | --- | --- | --- |
| Linux 桌面 | `p2p-desktop-linux-x64.tar.gz`（解包得 `dist/p2p-desktop/`，入口 `p2p-desktop`） | `p2pchat/releases/` | `p2pchat/releases/SHA256SUMS.txt` |
| Windows 桌面 | `p2p-desktop-windows-x64.tar.gz`（入口 `p2p-desktop.exe`） | `p2pchat/releases/` | 同上 |
| 安卓（Capacitor，保留） | `app-debug.apk`（生产名 `p2p-observatory-android-<sha>` artifact） | `p2pchat/releases/` | 同上 |
| 安卓原生 spike | `app-rtc-debug.apk` + 探测/构建日志 + AAR 探针 json | `p2pchat/releases/`、`p2pchat/android-native/**/build/` | `p2pchat/releases/android-native-apk.sha256` |
| 编码门证据（新增） | `encoding-gate.log`、`non-utf8-encoding-scan.log` | `p2pchat/releases/` | 同上（随 `*.log` 上传） |

artifact 名称：`p2p-observatory-<target>-<commit sha>` 与 `p2p-observatory-android-native-<commit sha>`，均保留 14 天。

> 关于 `p2pchat/tools/artifact-manifest.py`：该工具仍会对已删除的 `electron-builder.yml` 取 sha256 并抛 `FileNotFoundError`（实测 exit 1，见本任务报告），而 `p2pchat/tools/` 不在本任务范围，因此工作流**暂时不再调用它**，改用工作流内的 `sha256sum` 生成 `SHA256SUMS.txt`（记录范围反而更全：含 apk/tar.gz/日志/json）。修复该工具（以及同样引用已删文件的 `p2pchat/tools/freeze.py`）需要单独派单。

## 六、诚实标注（未验证的东西不会被写成通过）

- **编码门的 runner 侧结论只能在 runner 上确认**：本机（Linux 开发机）只证明命令能跑通、能失败、以及本机路径含非 ASCII 时符号链接/ASCII 副本方案有效；
  `windows-2022` 上 `WINDOWS_DEFAULT_CODE_PAGE` 实际打印什么、`LC_ALL=C` 在 runner 上的行为、两步在 runner 上的耗时，
  以及**步骤 8 在 Windows 上跑全域（482 条，含那 4 条中文标签用例）是否全绿**，都要看第一次 CI 的 artifact 日志（本任务不在 runner 上跑过）。
- **本机（Linux 开发机）没有 Android SDK**，`android-native` job 的所有步骤在本地都是 **NOT_RUN**：Java/Gradle 只验证到 `gradlew --version` 与 `assembleRtcDebug` 因缺 SDK/JDK 25 而失败（可行性报告 G1/G2）。**这个 job 的第一次 CI 运行才是它的第一份真实证据**，本地没有、也不会有它的结果。
- **构建成功 ≠ 应用可用**：`p2pchat/android-native` 目前只有构建脚手架与 AndroidManifest，没有 Kotlin 源码也没有 instrumentation 用例（可行性报告 G3）。所以模拟器 DataChannel 验证是 `NOT_RUN`（原因写在 `android-native-emulator-status.txt`）：没有可执行的用例，且按边界不下载系统镜像、不接受许可。
- **Windows 桌面未验证**：spec 头注释与 `docs/DESKTOP-PYTHON.md` 都标注了 Windows/macOS 未实测；`build (windows)` 第一次运行的结果就是结论，**失败就留失败**。
- **Linux 桌面已实测**：`p2p-desktop --self-test` 在打包产物上跑通（本机 25.8 秒，真实握手，双栈直连 + IPv4 直连，退出码 0），打包命令与 `tar` 打包命令也按工作流里的原样验证过。
- CI 只证明「能构建、能跑自检」；**不代表家宽/NAT 穿透成功**，也不代表真机安装/录音/锁屏行为（那些需要用户实机）。

## 七、本地复现（与工作流同样的命令）

```bash
# 质量门
node --test p2pchat/tests/platform/*.test.cjs p2pchat/tests/client/*.test.cjs
.venv/bin/python -m unittest discover -s p2pchat/ci -p 'test_*.py'
.venv/bin/python -m pytest p2pchat/tests -q

# 编码防线（t32 建门 / t35 扩到全域；与工作流第 8、9 步同一条命令）
PYTHONWARNDEFAULTENCODING=1 .venv/bin/python -u p2pchat/ci/watchdog.py --timeout 600 -- \
  .venv/bin/python -u -X warn_default_encoding -W error::EncodingWarning \
  -m pytest p2pchat/tests -q -o faulthandler_timeout=60

# C locale 扫描：本机路径含中文时，符号链接只解决解释器/包路径；
# 若要连 Qt 桌面用例一起跑（等价 CI 的 ASCII workspace），改用 3.2 里的 ASCII 真实副本再执行下面这段。
PREFIX="$(.venv/bin/python -c 'import sys; print(sys.prefix)')"
mkdir -p /tmp/enc-scan && ln -sfn "$PWD" /tmp/enc-scan/repo && ln -sfn "$PREFIX" /tmp/enc-scan/pyprefix
cd /tmp/enc-scan/repo
LC_ALL=C PYTHONCOERCECLOCALE=0 PYTHONUTF8=0 PYTHONWARNDEFAULTENCODING=1 \
  /tmp/enc-scan/pyprefix/bin/python -u p2pchat/ci/watchdog.py --timeout 600 -- \
  /tmp/enc-scan/pyprefix/bin/python -u -X warn_default_encoding -W error::EncodingWarning \
  -m pytest p2pchat/tests -q --ignore=p2pchat/tests/desktop/test_engine.py -o faulthandler_timeout=60

# 桌面（Linux 已实测；Windows 用 Windows 上的 python 执行同一条命令）
.venv/bin/python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec
./dist/p2p-desktop/p2p-desktop --self-test
tar -czf /tmp/p2p-desktop-linux-x64.tar.gz -C . dist/p2p-desktop

# 安卓原生 spike（需要已授权的 SDK 36 / build-tools 36.0.0 + JDK 21）
bash p2pchat/android-native/gradlew -p p2pchat/android-native --no-daemon \
  -Pandroid.builder.sdkDownload=false assembleRtcDebug
python p2pchat/android-native/tools/probe_webrtc_aar.py "$AAR" --abis arm64-v8a,x86_64 --remote
```

> 本机用 `.venv/bin/python`；CI 里没有 venv，用的是 `actions/setup-python` 装好的 `python`，
> 因此工作流里的 `PREFIX` 取 `sys.prefix`（runner 上本来就是 ASCII 路径），逻辑与本机一致。

## 八、本任务范围外的遗留（需 captain 另派）

- 编码门的唯一结构性边界：`p2pchat/tests/desktop/test_engine.py` 的 4 条用例用中文标签拼数据目录，在 `fs=ascii` 下无法创建文件名（见 3.5）。
  归属人把它改成 ASCII 标签后，删掉步骤 9 的 `--ignore=...` 即可覆盖 482 条全集。步骤 8（EncodingWarning 门）没有这个排除，跑的是全集。
- `p2pchat/tools/artifact-manifest.py:23`、`p2pchat/tools/freeze.py:8,17` 仍引用已删除的 `electron-builder.yml` / `platform/native_entry.py`。
- `p2pchat/package-lock.json` 仍是旧锁文件：根条目里还写着 `electron` / `electron-builder`，全文 40 个条目提到 electron/asar（实测）。`npm ci` 的同步检查通过（exit 0），所以 CI 不会因此红，但每个 job 仍会装这些死包，`npm-audit.json` 也会带上它们的 advisory（当前 `--omit=dev --audit-level=moderate` 与 `--audit-level=high` 都是 exit 0，门没有被削弱）。清理方式（需要单独的 npm/依赖任务）：删掉锁里这两个包后 `npm install --package-lock-only --ignore-scripts`，再用 `grep -c "node_modules/electron" package-lock.json` 复核为 0。
- `p2pchat/README.md` 的「Linux Electron / Windows Electron」两行与 `p2pchat/PLATFORMS.md` 的 Electron 表述需要归属人同步。
- 旧的 sidecar 构建产物（`p2pchat/platform/work/p2p-native/warn-*.txt`）已不再上传：CI 不再运行那条 sidecar 构建链；`p2pchat/tools/build-native.cjs` 是否保留由 `tools/` 归属人决定。
