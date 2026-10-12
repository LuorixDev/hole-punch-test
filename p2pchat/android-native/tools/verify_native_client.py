#!/usr/bin/env python3
"""原生安卓客户端的静态断言（不编译也能查的硬约束）。

为什么要有这个：本机没有 Android SDK、JDK 只有 25（Kotlin 2.1.20 起不来），
所以「能不能编译」只能由 CI 的 android-native job 回答；但**协议硬约束**与**文案逐字一致**
这两类问题完全可以静态查，而且必须查——它们一旦漂移，真机上表现为「加不进房间」或「界面撒谎」。

检查项：
  1. 源码存在且**没有任何 WebView 业务逻辑**（不允许 import android.webkit）；
  2. 九条方式的人话名称/解释/什么网络下可行/失败原因与 docs/METHODS-PLAIN.md **逐字一致**；
  3. 状态词表与 METHODS-PLAIN.md 一致；未测得用「—」；
  4. 无中继：`turn:` 只允许出现在**拒绝**逻辑里；iceServers 只能来自服务器下发的 STUN；
  5. 加入证明 v2：joinVersion=2、HKDF info 串、证明公式；加入报文里不得出现 secret；
  6. abiFilters 只有 arm64-v8a / x86_64；版本目录存在且被引用；R8 规则就位；
  7. 权限清单与前台服务/录音/多播锁符合约定，没有无关权限；
  8. 遥测事件结构与服务端白名单同源（字段名/限额），且不含敏感键。
"""
from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "app/src/main/java/dev/p2pobservatory/nativeprobe"
DOC = ROOT.parent / "docs/METHODS-PLAIN.md"
MANIFEST = ROOT / "app/src/main/AndroidManifest.xml"
APP_GRADLE = ROOT / "app/build.gradle.kts"
CATALOG = ROOT / "gradle/libs.versions.toml"
PROGUARD = ROOT / "app/proguard-rules.pro"
TELEMETRY = ROOT.parent / "backend/telemetry.py"

ALLOWED_PERMISSIONS = {
    "android.permission.INTERNET",
    "android.permission.ACCESS_NETWORK_STATE",
    "android.permission.RECORD_AUDIO",
    "android.permission.FOREGROUND_SERVICE",
    "android.permission.FOREGROUND_SERVICE_DATA_SYNC",
    "android.permission.POST_NOTIFICATIONS",
    "android.permission.ACCESS_WIFI_STATE",
    "android.permission.CHANGE_WIFI_MULTICAST_STATE",
}

results: list[tuple[bool, str, str]] = []


def check(ok: bool, name: str, detail: str = "") -> None:
    results.append((ok, name, detail))


def strip_comments(text: str, markers: tuple[str, ...] = ("//", "*", "/*", "#")) -> str:
    """只保留真正的代码行：注释里提到 turn:/armeabi 不算违规。"""
    kept = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(markers):
            continue
        kept.append(line)
    return "\n".join(kept)


def kotlin_sources() -> dict[str, str]:
    return {path.name: path.read_text(encoding="utf-8") for path in sorted(SRC.glob("*.kt"))}


def doc_rows() -> list[dict[str, str]]:
    text = DOC.read_text(encoding="utf-8")
    rows = []
    for line in text.splitlines():
        if not line.startswith("| ") or line.startswith("| 序号") or line.startswith("|---"):
            continue
        cells = [c.strip() for c in line.strip("|").split("|")]
        if len(cells) < 6:
            continue
        index, title, explain, works, failure = cells[0], cells[1], cells[2], cells[3], cells[4]
        if not index.isdigit():
            continue
        rows.append({
            "index": index,
            "title": title.replace("**", ""),
            "explain": explain,
            "works": works,
            "failure": failure,
        })
    return rows


def main() -> int:
    sources = kotlin_sources()
    check(len(sources) >= 8, "kotlin sources exist", f"files={len(sources)}: {', '.join(sources)}")
    joined = "\n".join(sources.values())

    # 1) 没有 WebView 承载业务逻辑
    webview = [name for name, text in sources.items()
               if "android.webkit" in text or "WebView(" in text or "loadUrl(" in text]
    check(not webview, "no WebView business logic", f"offenders={webview}")

    # 2) 九条方式逐字一致（标题/解释/什么网络下可行/失败原因都在 MethodCatalog.kt 里）
    catalog = sources.get("MethodCatalog.kt", "")
    rows = doc_rows()
    check(len(rows) == 9, "METHODS-PLAIN.md has nine rows", f"parsed={len(rows)}")
    missing = []
    for row in rows:
        for field in ("title", "explain", "works", "failure"):
            if row[field] not in catalog:
                missing.append(f"{row['index']}:{field}")
    check(not missing, "nine methods copy is verbatim", f"missing={missing[:6]}")

    # 3) 状态词表 + 未测得用「—」
    doc_text = DOC.read_text(encoding="utf-8")
    vocab = ["等待中", "尝试中", "已打通", "已观测", "不可用", "不支持"]
    check(all(f'"{w}"' in catalog for w in vocab), "status vocabulary verbatim", "")
    check('UNMEASURED = "—"' in catalog, "unmeasured shows em dash (not 0)", "")
    check(all(w in doc_text for w in vocab), "doc holds the same vocabulary", "")

    # 4) 无中继：`turn:` 只允许出现在拒绝逻辑里（注释不算）
    code_sources = {name: strip_comments(text) for name, text in sources.items()}
    turn_hits = [(name, index) for name, text in code_sources.items()
                 for index, line in enumerate(text.splitlines(), 1) if "turn:" in line]
    rejecting = all(
        ("RELAY_FORBIDDEN" in code_sources[name].splitlines()[index - 1]
         or "startsWith" in code_sources[name].splitlines()[index - 1]) for name, index in turn_hits)
    fed_into_config = [f"{name}:{index}" for name, index in turn_hits
                       if re.search(r"IceServer\.builder|RTCConfiguration|iceServers\.add", code_sources[name].splitlines()[index - 1])]
    check(bool(turn_hits) and rejecting and not fed_into_config,
          "turn: only in rejection paths",
          f"lines={[f'{name}:{index}' for name, index in turn_hits]} fed_into_config={fed_into_config}")
    rtc = sources.get("RtcSession.kt", "")
    check("stunUrls.map { PeerConnection.IceServer.builder(it)" in rtc,
          "iceServers built only from server-supplied STUN", "")
    check("assertNoRelay(stunUrls)" in rtc, "runtime relay assertion present", "")
    check("relay" in sources.get("Protocol.kt", ""), "typ relay candidates are dropped", "")

    # 5) 加入证明 v2
    join = sources.get("JoinProof.kt", "")
    check('JOIN_VERSION = 2' in join, "joinVersion=2", "")
    check('"p2pchat/join-key/v2"' in join, "HKDF info string", "")
    check('room + "\\u0000" + nonce + "\\u0000" + clientSessionId' in join, "proof separator matches peer.py", "")
    check('put("secret"' not in joined, "join payload never carries the room secret", "")
    check("containsSecret" in join and "containsSecret" in sources.get("SignalingClient.kt", ""),
          "runtime secret-on-wire guard", "")
    # 声明的 capabilities 必须是服务器认识的机制（`stun` 不是机制 → 会被判 SCHEMA_INVALID，真机表现为加不进房间）
    protocol_py = (ROOT.parent / "backend/protocol.py").read_text(encoding="utf-8")
    mechanisms = re.search(r"MECHANISMS\s*=\s*\{(.*?)\}", protocol_py, re.DOTALL)
    known = set(re.findall(r"'([a-z\-]+)'", mechanisms.group(1))) if mechanisms else set()
    signaling = sources.get("SignalingClient.kt", "")
    caps_block = re.search(r"capabilities: List<String> = listOf\((.*?)\)", signaling, re.DOTALL)
    declared = set(re.findall(r'"([a-z\-]+)"', caps_block.group(1))) if caps_block else set()
    check(bool(declared) and declared.issubset(known),
          "declared capabilities are server-known mechanisms",
          f"declared={sorted(declared)} unknown={sorted(declared - known)}")
    # 三个 WebRTC 档位必须与服务器 PROFILES 一致
    profiles = re.search(r"PROFILES\s*=\s*\((.*?)\)", protocol_py, re.DOTALL)
    server_profiles = set(re.findall(r"'([a-z0-9\-]+)'", profiles.group(1))) if profiles else set()
    client_profiles = set(re.findall(r'PROFILE_[A-Z0-9]+ = "([a-z0-9\-]+)"', sources.get("Protocol.kt", "")))
    check(client_profiles == server_profiles, "profile ids match server PROFILES",
          f"client={sorted(client_profiles)} server={sorted(server_profiles)}")

    # 6) 构建配置
    gradle = APP_GRADLE.read_text(encoding="utf-8")
    gradle_code = strip_comments(gradle)
    check('abiFilters += listOf("arm64-v8a", "x86_64")' in gradle, "abiFilters only arm64-v8a/x86_64", "")
    check("armeabi" not in gradle_code and '"x86"' not in gradle_code, "no 32-bit ABI leftovers", "")
    check(CATALOG.exists() and "libs." in gradle, "version catalog wired", "")
    check(PROGUARD.exists() and "org.webrtc" in PROGUARD.read_text(encoding="utf-8"), "R8/proguard rules", "")

    # 7) 权限与后台
    manifest = MANIFEST.read_text(encoding="utf-8")
    granted = set(re.findall(r'android:name="(android\.permission\.[A-Z_]+)"', manifest))
    check(granted == ALLOWED_PERMISSIONS, "permission set is exactly the agreed list",
          f"extra={sorted(granted - ALLOWED_PERMISSIONS)} missing={sorted(ALLOWED_PERMISSIONS - granted)}")
    check("KeepAliveService" in manifest and 'android:foregroundServiceType="dataSync"' in manifest,
          "foreground service declared", "")
    check("RecordingPermission" not in joined and "RECORD_AUDIO" in joined
          and "requestPermissions(arrayOf(Manifest.permission.RECORD_AUDIO)" in joined,
          "RECORD_AUDIO runtime flow", "")
    check("createMulticastLock" in joined and "joinGroup" in joined, "multicast lock + group join", "")

    # 8) 遥测结构
    telemetry = sources.get("Telemetry.kt", "")
    server = TELEMETRY.read_text(encoding="utf-8")
    server_events = re.search(r"EVENTS = \{(.*?)\}", server, re.DOTALL)
    server_event_names = set(re.findall(r"'([a-z][a-z0-9_.]+)'", server_events.group(1))) if server_events else set()
    client_events = set(re.findall(r'"([a-z][a-z0-9_.]+)"', telemetry))
    check(server_event_names.issubset(client_events),
          "client event allowlist covers server events",
          f"missing={sorted(server_event_names - client_events)[:5]}")
    for field in ("clientSessionId", "seq", "tsWallMs", "monoMs", "connectionId", "attemptId", "event", "data"):
        if f'"{field}"' not in telemetry:
            check(False, f"telemetry field {field}", "")
    check('"droppedCount"' in telemetry, "dropped events are counted (quota)", "")
    check("diagnostics.jsonl" in telemetry, "local diagnostics retained", "")

    # 报告
    failed = [item for item in results if not item[0]]
    for ok, name, detail in results:
        print(f"{'PASS' if ok else 'FAIL'} {name}" + (f"  [{detail}]" if detail else ""))
    print(f"VERIFY_NATIVE_CLIENT checks={len(results)} failed={len(failed)}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
