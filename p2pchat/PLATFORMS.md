# Client platform evidence and build instructions

## Current state (2026-10-12)

**The desktop client is pure Python + PySide6 (Qt) + PyInstaller; the Electron desktop shell has been deleted.** The three ICE profiles are one WebRTC implementation with three address-family filters, not three protocols. The browser client is preserved; the Android client remains a Capacitor WebView app; and the Android **native Kotlin client is now a phase-1 implementation** (`android-native/`, Kotlin sources with no WebView hosting, protocol-aligned with `peer.py`/`core.js`, JVM unit tests in CI) whose **local build and on-device run remain NOT_RUN**. Per-method status, evidence levels and open gaps: [PUNCHING-MATRIX](docs/PUNCHING-MATRIX.md). Public evidence boundaries: [EVIDENCE-INDEX](docs/EVIDENCE-INDEX.md). Current frozen hashes: [SOURCE-MANIFEST](docs/SOURCE-MANIFEST.json) (**231 files**, verified) and [FREEZE](docs/FREEZE.json) — generated at the final freeze on HEAD `d07ed36c` (authoritative `treeSha256` lives only in those two files, which are excluded from the manifest itself; documents intentionally do not copy it). **Artifact identity is layered, read carefully:** `python_desktop/evidence/desktop-build.json` still binds the artifact built at `4ccbf59`, which is the one independently reviewed (t45) — exe `412b7d8f…`, bundle `9b54cc6c…`; the local `dist/` has been deleted, so no unreviewed local bundle sits beside the reviewed record; that artifact can be re-checked with the private artifact of CI run `4ccbf59`. **Coverage closed at this freeze:** `tools/freeze.py` now covers `android-native/**` (23 files) and collects `.spec` files, so `tools/desktop.spec` (the packaging input) is inside the manifest; `android/` (the Capacitor project) contributes 57 files. Windows CI for the new desktop failed exactly one different test in each of three consecutive runs; both causes are fixed and the final run is pending.

### Ownership map

| Surface | Source | Runtime today | Evidence ceiling reached |
|---|---|---|---|
| Desktop (Linux) | `python_desktop/` (`app.py`, `engine.py`, `qt_ui.py`), packaged by `tools/desktop.spec` | Pure Python + Qt(PySide6), one-folder PyInstaller bundle | **L1/L3 (this host)**: real in-process handshake (server + echo + client), packaged bundle launched. Not a home-NAT/cross-NAT result |
| Desktop (Windows / macOS) | same source and same spec | never executed there | **NOT_RUN** — no installer, no device, no CI green for this round yet |
| Browser | `web/` (loaded by `server.py`) | WebRTC only; WS signalling client | **L1/L3**: real browser ↔ independent Python echo, real files/SHA, isolated benchmark lane |
| Android (shipping) | `android/` (Capacitor 8.5.3, assets from `web/`) | WebView | source/mock only; **device install = NOT_RUN** |
| Android native (phase 1) | `android-native/app/src/main/java/dev/p2pobservatory/nativeprobe/` (Kotlin, no WebView hosting) — see [ANDROID-NATIVE](docs/ANDROID-NATIVE.md) | Kotlin + WebRTC Android SDK; STUN-only ICE config | **JVM unit tests in CI only**; local build **NOT_RUN** (no Android SDK / JDK 21 here), on-device run **NOT_RUN** |
| Signalling / STUN / log centre | `server.py`, `backend/` | one process, one `--host` per listening site (V6ONLY), so `--host 0.0.0.0 --host ::` is real dual-stack in one process | **L1/L2**: real sockets, isolated netns topologies; real home broadband NOT_RUN |

### Why the GUI toolkit changed (Tk → Qt)

The first pure-Python desktop shell used Tkinter. On this host that Tk runtime is **not linked against Xft**, `tkinter.font.families()` returns only `('fixed',)`, and measuring Chinese text yields width 0 — the three-screen UI rendered Chinese as blanks. Qt(PySide6) has proper font handling, so the shell was replaced. The Tk module (`python_desktop/ui.py`) is deleted; `tools/desktop.spec` now collects Qt platform plugins and **excludes** `tkinter`. The migration (t24) has since been **independently reviewed and passed** (t43 needs_revision → t44 repair + artifact rebuild → **t45 pass at HEAD `e60ba0d`**); commits after that baseline (network check, reachability verdict dispatch, Windows console UTF-8) are **not** covered by that review.

## What each client can actually start

| Capability | Desktop (Python) | Browser | Android WebView | Android native |
|---|---|---|---|---|
| WebRTC (3 ICE profiles) | yes | yes | yes (System WebView) | yes, phase 1 (JVM tests only; device NOT_RUN) |
| UDP probe / QUIC / TCP / TCP simultaneous-open | yes (in-process `native/adapter.py`) | no API → unsupported | no adapter → unsupported | not implemented (phase 1 is WebRTC-only) |
| STUN mapping observation | yes | via WebRTC gathering only | same as browser | yes (STUN-only ICE config; no TURN) |
| Gateway mapping (UPnP / PCP / NAT-PMP / IPv6 pinhole) | **wired, default OFF, explicit consent only**; reported "available" only where the platform can be verified read-only (Linux) | no API → unsupported | unsupported | not implemented |
| LAN direct discovery (same subnet, no hole punching) | implemented, default OFF, consent required | no multicast API → unsupported | unsupported | not implemented |
| Symmetric-NAT port prediction | implemented, default OFF, only when classified symmetric | no API → unsupported | unsupported | not implemented |

No client has TURN, relay, or server-side message forwarding. A failed direct path is reported as failed.

## User-facing platform behavior

The shared UI covers: server address, room / shared secret, text / image / file / recorded-audio messages, a per-method attempt screen in plain language, and sanitized diagnostic export. Recording is completed-audio-file messaging, not a call; the microphone is requested on demand and never silently bypassed. Saves are bounded to 32 MiB. Desktop file selection uses Qt's own dialogs; Android uses WebView file selection plus `ACTION_CREATE_DOCUMENT` for attachment/NDJSON saves with no broad storage access.

### Android cleartext and origin (corrected)

The Capacitor config uses `server.androidScheme: "http"`, so the WebView loads its own assets from **`http://localhost`** — still a secure context, so recording works. Because the *signalling host* is typed by the user at runtime (a bare home IP or DDNS name) and Android blocks cleartext by default since API 28, the APK ships an explicit `res/xml/network_security_config.xml` that permits cleartext for user-entered signalling targets. `allowMixedContent` stays `false`; there is no trust-all certificate hook, and WebView TLS errors are still rejected. The signalling origin allowlist for Android is therefore exactly **`http://localhost`** (if you switch `androidScheme` back to `https`, use `https://localhost` instead). Origin is not authentication: the room secret and the data-plane HMAC are independently required. Never use wildcard origins. Details and trade-offs: [ANDROID-CLEARTEXT](docs/ANDROID-CLEARTEXT.md).

The desktop client is pure Python and makes its own sockets: it passes an explicit `Origin` (or none) to the signalling connection, and refuses non-loopback `ws://` unless the operator confirms plaintext for that session — with a persistent unencrypted-session warning and no trust-all fallback. See [DESKTOP-PYTHON](docs/DESKTOP-PYTHON.md).

**Known product gap:** the browser client still allows `ws://` only to loopback, so pointing a phone or browser at your own plaintext signalling address is refused by the client even though the Android build can carry cleartext. Fixing that is a client change, not a platform limitation.

Android has **no Python/native networking adapter**: UDP-probe, QUIC, TCP, TCP simultaneous-open, gateway mapping, LAN discovery and port prediction each report `unsupported` with a real reason (`ANDROID_NATIVE_ADAPTER_NOT_IMPLEMENTED` or platform validation), and there is no mock-success path. No foreground service, wake-lock, background execution or battery-optimization exemption exists; screen-off/Doze/process death may end signalling or transfers, and there is no background-delivery promise. Pause/resume/network changes stop tracked recording streams and rebuild attempts within a bounded budget; a real device lifecycle test remains NOT_RUN.

## Reproducible build recipe

Python 3.12 (repo `.venv`), Node 24.20.0 with the exact npm lockfile, PyInstaller 6.20.0 pinned in `platform/build-requirements.txt`. From the repository root:

```sh
.venv/bin/python -m pip install -r p2pchat/requirements.txt -r p2pchat/platform/build-requirements.txt -c p2pchat/platform/constraints.txt
npm --prefix p2pchat ci --ignore-scripts
node --test p2pchat/tests/platform/*.test.cjs p2pchat/tests/client/*.test.cjs
npm --prefix p2pchat run test:platform

# Desktop bundle (Linux verified locally; Windows/macOS use the same spec, unverified)
.venv/bin/python -m PyInstaller --noconfirm --clean p2pchat/tools/desktop.spec
dist/p2p-desktop/p2p-desktop --capabilities
dist/p2p-desktop/p2p-desktop --self-test      # headless; real handshake inside one process
```

There is no `node node_modules/electron/install.js` step any more: Electron and electron-builder are gone from `package.json` and the lockfile, and `tools/build-native.cjs` is **deprecated** (kept only to build the standalone native CLI for native↔native experiments; no CI step calls it). `tools/freeze.py` asserts the removed shell files stay absent, and `tools/artifact-manifest.py` skips missing optional root files instead of crashing. Both have been verified to run on this tree.

`tools/artifact-manifest.py` records source/lockfile hashes, commit, Python dependencies and artifact SHA256. This is source/toolchain reproducibility, not a claim of byte-identical unsigned bundles (timestamps/toolchain variation remain). The local Linux build (glibc 2.44) is not guaranteed on older distributions; CI Ubuntu 24.04 builds are the supported baseline.

Android (Capacitor): Java 21.0.10 + Gradle 8.14.3 (pinned distribution SHA256) + AGP 8.13.0 + SDK/platform 36 + build-tools 36.0.0. CI asserts the runner's preinstalled SDK and disables SDK auto-download; it never runs `sdkmanager --licenses`. Locally no Android SDK was available, so no APK was verified here:

```sh
npm --prefix p2pchat run android:sync
cd p2pchat/android && ./gradlew --no-daemon -Pandroid.builder.sdkDownload=false assembleDebug
```

The debug APK is deliberately unsigned-for-distribution (Android debug key only), not a Play release. The Android project — not its generated assets/build/cache/`local.properties` — is committed. `dist-web/` is generated from the shared web modules plus the mobile facade. Root ignore rules exclude secrets, research output, databases, dependencies and build caches.

## CI matrix (private artifacts only)

`.github/workflows/build.yml` defines two jobs, both with private, 14-day-retention artifacts and **no release, signing, deploy or license acceptance**:

1. **Clients (matrix: linux / windows / android)** — Node 24.20.0 + Python 3.12; `npm ci --ignore-scripts`; client and platform gates (`node --test` + two `npm audit` levels); watchdog-bounded Python gates (`unittest` for `p2pchat/ci`, the bounded Windows diagnostic, then the full `pytest` suite under a 600 s watchdog); on desktop targets `PyInstaller` plus the packaged `--self-test`; on android the Capacitor APK build against the preinstalled SDK; then tar + `SHA256SUMS.txt` + per-run `npm audit --json`, uploaded as `p2p-observatory-<target>-<sha>`.
2. **Android native (phase 1)** — Java 21, SDK presence assertion, read-only environment probes, **native Kotlin/JVM unit tests (a failure fails the job)**, `assembleRtcDebug` with the APK sha256 recorded together with `sourceCommit`, WebRTC AAR verification (sha256 / ABI / 16 KB page alignment / required classes), and an explicit `DATA_CHANNEL_RUNTIME_TEST: NOT_RUN` line with its reason; uploaded as `p2p-observatory-android-native-<sha>`.

Windows results for the **new Python/Qt desktop** are PENDING a captain push; the historical Windows success/`EXE` records belong to the deleted Electron packaging and must not be inherited. A failed native build fails only its own job; Windows never receives a Linux executable.

## Dependency audit and remaining risk

Electron and electron-builder were removed, so the npm tree is now `@capacitor/*` (plus the pinned `xcode -> uuid 11.1.1` override). The committed `platform/npm-audit.json` is a **pre-removal Electron-era snapshot** and must not be quoted as the current audit result; CI regenerates `npm audit --json` per run into the private artifact, rejects high/critical everywhere and any production moderate. **Owner action pending: regenerate or retire that committed snapshot.**

## What is still NOT_RUN

- Real home broadband / double NAT / CGNAT / carrier UDP blocking, on any client;
- Real router mapping (UPnP / PCP / NAT-PMP / IPv6 pinhole) and gateway-device compatibility;
- Windows desktop packaging/GUI/firewall on a real machine, and macOS packaging/notarization;
- Android device install, WebView or native interop, recording, background/network-change/Doze behavior;
- Real microphone capture (earlier browser capture is not re-measured here);
- Disk-full, power-loss and seven-day log-retention behaviour.
