# Client platform evidence and build instructions

## Current integration status (t24, 2026-10-11)

**Windows修复待当前commit CI确认 / Windows close fix awaits CI on the new commit.** Current complete source and rebuilt Linux artifact hashes are in [SOURCE-MANIFEST](docs/SOURCE-MANIFEST.json) and [FREEZE](docs/FREEZE.json). This integrates t22+t25 reviewed by [T26](review/windows/T26.md), plus the delivery documentation; it is not the old 8687adf snapshot. Linux implementation tests (72) and independent close-focused review tests (33) passed. The narrow workaround only applies to win32/CPython3.12.10/aiortc1.15.0/aioice0.10.2 and owned Proactor UDP transports; Linux simulated coverage is **not** Windows IOCP validation.

Historical a1c6e7e/run38124339483 built Linux/Android, but Windows diagnostic timed out at90s (exit124), before packaging; the await chain reached aioice StunProtocol.close. New Windows gates must run the original two-echo diagnostic, all tests, and native packaging without skipping failure. Current commit/run are pending captain push. Android/Windows interactive device, microphone, home NAT and real gateways remain NOT_RUN. See [integration delta](docs/WINDOWS-INTEGRATION.md).

## Earlier platform implementation evidence (not current CI certification)

| Platform | Source | Local build | Launch / hardware |
|---|---|---|---|
| Linux x64 | Electron + fixed PyInstaller stdio sidecar | `npm run dist:linux` passed, unpacked directory ~346 MiB | Local renderer smoke passed with sandbox enabled. Not a home-NAT/cross-device result; file picker/microphone UX not hardware-validated |
| Windows x64 | Same Electron source; portable EXE config; native sidecar built on Windows runner | Configured only until Actions completes | No Windows device tested |
| Android API24+ | Capacitor8 project, SAF save plugin, audio permission | Local Gradle downloaded/verified, build blocked: only Java25 available, Gradle8.14.3 reports unsupported class major69; Android SDK/adb absent | No APK locally verified; no Android device tested |

Actions status is deliberately **not** claimed here before a real run. The workflow only uploads private run artifacts (14-day retention), never signs, releases or deploys. Captain handles repository publication/trigger. Dispatch or `build/p2p-observatory` push triggers independent Linux/Windows/Android jobs with fail-fast disabled. A failed native build fails that desktop job; Windows never receives a Linux executable.

## User-facing platform behavior

The shared UI provides server address, room/shared-secret settings, text/image/file/recording messages and sanitized diagnostic export. Desktop file selection uses Chromium's user-mediated file picker. Desktop saves open an OS save dialog. Android uses WebView file selection and `ACTION_CREATE_DOCUMENT` for attachment/NDJSON saves, with no broad storage access. Saves are limited to32MiB and one pending native save. Recording is completed audio-file messaging, not a call; microphone permission is requested on demand and limited to app-local audio capture. Revocation/denial is not silently bypassed.

Android loads local assets from `https://localhost`; cleartext traffic and mixed content are disabled, no trust-all certificate hook exists. Use a valid HTTPS/WSS signaling certificate. Default WebView TLS errors remain rejected. External navigation is blocked. Desktop loads the exact packaged file, blocks navigation/new windows/webviews, uses `sandbox:true`, `contextIsolation:true`, `nodeIntegration:false`, web security enabled. Its WSS Origin is `null`, so operators must explicitly configure `--origin null` if enabling desktop clients; this value is **not authentication**. Android origin allowlist is exactly `https://localhost`. Room secret/HMAC remains independently required. Never use wildcard origins.

Android has **no Python/native networking adapter**: UDP-probe, QUIC, TCP, TCP simultaneous-open, UPnP, PCP and NAT-PMP each report `unsupported / ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED`; no mock-success path. WebRTC availability depends on Android System WebView and real device tests. No foreground service, wake-lock, background execution or battery-optimization exemption is implemented. Screen-off/Doze/process death may terminate signaling/transfers; no background delivery promise. Native pause/resume/network signals now stop tracked recording streams and clear old paths/ACKs; resume/network changes debounce and rebuild new attempts with a bounded budget. Users manually reconnect when that budget is exhausted; this source/mock coverage is not physical Android lifecycle proof. WebView IndexedDB persists locally but uninstall/clear-data removes diagnostics.

## Restricted desktop bridge

`window.p2pNative.invoke` allowlists capabilities/start/signal/send/stats/close, and `onEvent` carries `{v,event,params}`. IPC checks exact entry URL + mainFrame identity + webContents identity. No renderer-selected executable, arbitrary file read, shell, localhost listener or command argument exists. Packaged executable runs as fixed `resources/native/p2p-native[.exe]`, JSON-lines over private inherited pipes; binary payload max64KiB, line max128KiB, bounded64 pending RPCs and512KiB stdin backpressure,15s request timeout. Crashes fail pending requests and tracked attempts. Raw stderr never reaches renderer/log upload. Missing native runtime yields explicit unsupported capabilities; WebRTC still works. Native implementation validates pair/candidate/auth boundaries; bridge is not independent proof of that transport's security or cross-NAT capability.

Native sockets default to loopback. The **native network binding** menu enumerates only real local interfaces (excluding scoped/link-local IPv6), asks confirmation, closes old sidecar, and binds the selected local IP. It cannot accept remote arbitrary bind/exec inputs. Network changes require restart/reselection. The inherited process environment is not controllable by renderer. Sidecar diagnostics/events go to the common client's bounded redacted logging; stdout carries protocol only and is not persisted wholesale. First successful path does not trigger cancellation of other paths.

## Reproducible build recipe

Node24.20.0, exact npm lockfile; Python3.12; PyInstaller6.20.0; pinned build requirements and runtime constraints. Run from repository root:

```sh
python -m pip install -r p2pchat/requirements.txt -r p2pchat/platform/build-requirements.txt -c p2pchat/platform/constraints.txt
npm --prefix p2pchat ci --ignore-scripts
node p2pchat/node_modules/electron/install.js
node --test p2pchat/tests/platform/*.test.cjs
npm --prefix p2pchat run dist:linux  # or dist:windows on Windows
```

Local script finds repository `.venv/bin/python`, otherwise `python`; a build-time `PYTHON` environment variable may select the build interpreter but is not exposed to app/IPC. The native build records source SHA256 **before** packaging and fails if native source changes mid-build. A final integration source freeze must rebuild sidecar/UI. `tools/artifact-manifest.py` records source/lockfile hashes, commit, Python dependencies and artifact SHA256. This is source/toolchain reproducibility, not a claim of byte-identical unsigned EXE/APK output (timestamps/toolchain variation remain). Local Linux glibc2.44 build is not guaranteed to run on older distributions; CI Ubuntu24.04 builds are the supported baseline. Archive the whole linux-unpacked directory, not just its launcher.

Android: Java21.0.10 + Gradle8.14.3 (distribution SHA256 pinned) + AGP8.13.0 + SDK/platform36 + build-tools36.0.0, Capacitor8.5.3. CI checks runner preinstalled SDK packages and disables SDK auto-download. It does not run `sdkmanager --licenses`. Local Gradle download/cache used ~489MiB; no Android SDK downloaded, no additional SDK license accepted, no QEMU/VM installed. An operator with SDK rights can provide licensed SDK and Java21 then run:

```sh
npm --prefix p2pchat run android:sync
cd p2pchat/android
./gradlew --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug
```

Debug APK is deliberately unsigned-for-distribution (Android debug key only), not production Play release. The Android project, not its generated build/assets/cache/local.properties, is committed. `dist-web` is generated from all shared web modules plus mobile facade. Root ignore rules exclude secrets, research outputs, databases, dependencies and build caches.

## Dependency audit and remaining risk

Original Electron38.8.6/builder install:10 findings (8moderate/2high). Explicitly reviewed upgrade to Electron44.7.0, builder26.15.3, Capacitor8.5.3; targeted `xcode -> uuid11.1.1` override preserves CJS APIs. No `npm audit fix --force` used. Current committed `platform/npm-audit.json`:8moderate,0high/critical. Production `npm audit --omit=dev`:0. Audit is dependency evidence, not product security certification.

Remaining GHSA-hp3w-g68c-fv3c: `sprintf-js<=1.1.3` unbounded-precision DoS via builder -> app-builder-lib -> @electron/get -> global-agent -> roarr. npm reports8 affected package nodes from this single chain. Registry latest sprintf-js is1.1.3, no patched release. This is build-time tooling, not shipped app runtime; untrusted logging format input on a build machine remains a risk. npm's suggested builder26.5.0 downgrade was not blindly applied. CI rejects high/critical across all dependencies and any production moderate+. Review audit periodically, build only trusted commits and avoid untrusted proxy/log formatting inputs.

`npm ci --ignore-scripts` intentionally avoids electron-winstaller's script (Squirrel target unused: Windows portable builder path). Electron's download script **is required**; explicitly running `node node_modules/electron/install.js` restored the runtime and Linux build/launch passed. Each CI desktop runner runs this explicit script; Android does not need Electron binary. Dependencies are not vendored into Git.
