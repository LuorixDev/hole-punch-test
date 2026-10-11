"""The Electron desktop shell is gone and its absence is checkable.

The workspace contract for this change: ``p2pchat/desktop/`` and
``p2pchat/electron-builder.yml`` are removed, ``package.json`` no longer depends
on electron/electron-builder, and nothing under ``p2pchat/python_desktop`` may
reference an asar bundle, a stdio sidecar or a Node bridge.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT


def test_electron_shell_files_are_removed() -> None:
    assert not (PACKAGE / "desktop").exists(), "p2pchat/desktop/ 仍然存在"
    assert not (PACKAGE / "electron-builder.yml").exists(), "electron-builder.yml 仍然存在"
    assert not (PACKAGE / "desktop" / "main.cjs").exists()
    assert not (PACKAGE / "desktop" / "preload.cjs").exists()
    assert not (PACKAGE / "desktop" / "bridge.cjs").exists()


def test_package_json_has_no_electron_dependency() -> None:
    manifest = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
    blob = json.dumps(manifest, ensure_ascii=False)
    assert "electron" not in blob, "package.json 仍然提到 electron"
    assert "electron-builder" not in blob
    assert "asar" not in blob
    for section in ("dependencies", "devDependencies", "scripts"):
        for name in manifest.get(section, {}):
            assert "electron" not in name
    # The web and Capacitor projects must keep working.
    assert manifest["scripts"]["sync:web"] == "node tools/sync-web.cjs"
    assert manifest["scripts"]["android:sync"] == "npm run sync:web && cap sync android"
    assert "@capacitor/core" in manifest["dependencies"]
    assert "@capacitor/android" in manifest["dependencies"]
    assert "@capacitor/cli" in manifest["devDependencies"]


def test_desktop_package_has_no_node_bridge_or_asar_reference() -> None:
    """No Node/Electron glue: no asar, no .cjs bridge, no child-process sidecar."""
    offenders = []
    for path in sorted((PACKAGE / "python_desktop").glob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        for needle in (".cjs", "bridge.cjs", "preload.cjs", "main.cjs", "node_modules", "contextbridge", "ipcmain", "electron."):
            if needle in text:
                offenders.append(f"{path.name}: {needle}")
        for line in text.splitlines():
            if re.search(r"\basar\b", line) and "no asar" not in line:
                offenders.append(f"{path.name}: {line.strip()}")
    assert not offenders, f"桌面 Python 包仍引用 Electron/Node 桥接：{offenders}"
    # Recording spawns a local audio front end, never a transport sidecar.
    audio = (PACKAGE / "python_desktop" / "audio.py").read_text(encoding="utf-8")
    assert "create_subprocess_exec" in audio


def test_desktop_reuses_the_python_transports() -> None:
    engine = (PACKAGE / "python_desktop" / "engine.py").read_text(encoding="utf-8")
    assert "from p2pchat.peer import Peer, frame as peer_frame" in engine
    assert "from p2pchat.native.adapter import" in engine
    native = (PACKAGE / "python_desktop" / "native_session.py").read_text(encoding="utf-8")
    assert "from p2pchat.native.adapter import MAX_FRAME, NativeAdapter" in native
    # Strictly no relay: the only mentions allowed are the negatives.
    for path in sorted((PACKAGE / "python_desktop").glob("*.py")):
        text = path.read_text(encoding="utf-8").lower()
        assert "turn:" not in text, f"{path.name} 提到了 TURN 服务器"
        for line in text.splitlines():
            if "relay" in line:
                # "relay_forbidden" is the reused transport's own rejection code
                # for a banned forwarding path, not an offered feature.
                allowed = ("no relay", "no-relay", "不转发", "没有中继", "relay_forbidden")
                assert any(token in line for token in allowed), f"{path.name}: {line.strip()}"


def test_spec_and_docs_exist_and_state_verification_status() -> None:
    spec = (PACKAGE / "tools" / "desktop.spec").read_text(encoding="utf-8")
    assert "PyInstaller" in spec
    assert "collect_submodules('aiortc')" in spec
    assert "collect_submodules('aioquic')" in spec
    assert "collect_submodules('p2pchat')" in spec
    # The frozen entry point delegates to the same CLI and is generated, not kept.
    assert "p2pchat.python_desktop.app import main" in spec
    assert "desktop-entry.py" in spec
    # Only a real source tree ever enters the bundle.
    assert "'node_modules'" in spec and "'releases'" in spec
    docs = (PACKAGE / "docs" / "DESKTOP-PYTHON.md").read_text(encoding="utf-8")
    assert "未验证" in docs and "Windows" in docs
    assert "desktop.spec" in docs


def test_capacitor_web_assets_are_untouched() -> None:
    """The retained web client still builds its assets for Capacitor."""
    for name in ("web/index.html", "web/app.js", "web/ux.js", "platform/mobile.js", "capacitor.config.json"):
        assert (PACKAGE / name).exists(), f"{name} 不见了"
    config = json.loads((PACKAGE / "capacitor.config.json").read_text(encoding="utf-8"))
    assert config["webDir"] == "dist-web"
    assert config["android"]["allowMixedContent"] is False

def test_lockfile_has_no_electron_or_electron_builder() -> None:
    """package-lock.json must not reinstall the removed shell.

    Regenerated with ``npm install --package-lock-only --ignore-scripts``; a lock
    that still declared electron/electron-builder would make ``npm ci`` install
    the dead shell again and silently rot the audit tree.
    """
    lock_path = PACKAGE / "package-lock.json"
    raw = lock_path.read_text(encoding="utf-8")
    assert "node_modules/electron" not in raw, "锁文件仍在安装 node_modules/electron*"
    assert "electron-builder" not in raw, "锁文件仍然声明 electron-builder"
    assert "asar" not in raw, "锁文件仍然声明 asar"
    lock = json.loads(raw)
    packages = lock.get("packages", {})
    offenders = [name for name in packages if "electron" in name or "asar" in name]
    assert not offenders, f"锁文件 packages 里仍有 {offenders}"
    # The lock must still describe the web/Capacitor dependencies.
    assert any(name.startswith("node_modules/@capacitor/core") for name in packages)
    assert any(name.startswith("node_modules/@capacitor/cli") for name in packages)
    # Every declared dependency is represented in the lock.
    manifest = json.loads((PACKAGE / "package.json").read_text(encoding="utf-8"))
    for section in ("dependencies", "devDependencies"):
        for name in manifest.get(section, {}):
            assert f"node_modules/{name}" in packages, f"{name} 不在锁文件里"
