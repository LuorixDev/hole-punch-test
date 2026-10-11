"""Create reproducibility manifest without copying secrets or local research state.

Run: ``python p2pchat/tools/artifact-manifest.py``

The Electron desktop shell was deleted, so this tool must never require its
files: the removed shell entries are asserted *absent* instead, and the desktop
source directory is ``python_desktop/``. A missing optional root file is skipped
rather than crashing (the previous version exited 1 on the deleted
``electron-builder.yml``).
"""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "releases"
OUT.mkdir(exist_ok=True)

# Source trees that define the shipped clients. ``python_desktop`` replaces the
# deleted Electron ``desktop/`` shell.
SOURCE_DIRS = ("native", "python_desktop", "platform", "web")
# Root-level files worth hashing; anything absent is skipped, never required.
ROOT_SOURCE_FILES = ("package-lock.json", "requirements.txt", "tools/desktop.spec")
# Deleted with the Electron shell: assert absence instead of requiring it.
REMOVED_WITH_ELECTRON_SHELL = ("desktop/main.cjs", "desktop/preload.cjs", "desktop/bridge.cjs", "electron-builder.yml")


def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def assert_shell_removed():
    present = [name for name in REMOVED_WITH_ELECTRON_SHELL if (ROOT / name).exists()]
    if present:
        raise SystemExit("ELECTRON_SHELL_REAPPEARED: " + ", ".join(present))


assert_shell_removed()

sources = {}
for directory in SOURCE_DIRS:
    tree = ROOT / directory
    if not tree.is_dir():
        continue
    for path in tree.rglob("*"):
        if path.is_file() and path.suffix in (".py", ".js", ".cjs", ".html", ".css", ".txt") and not any(x in path.parts for x in ("build", "work", "__pycache__")):
            sources[path.relative_to(ROOT).as_posix()] = digest(path)
for name in ROOT_SOURCE_FILES:
    path = ROOT / name
    if path.is_file():
        sources[name] = digest(path)

artifacts = {p.name: digest(p) for p in OUT.iterdir() if p.is_file() and p.suffix in (".apk", ".exe", ".gz")}
manifest = {"sourceCommit": os.environ.get("GITHUB_SHA", "local-uncommitted"), "python": platform.python_version(), "system": platform.system(),
            "sourceDirs": list(SOURCE_DIRS), "removedWithElectronShell": list(REMOVED_WITH_ELECTRON_SHELL),
            "sourceSha256": sources, "artifactSha256": artifacts,
            "pythonDependencies": subprocess.check_output([__import__('sys').executable, "-m", "pip", "freeze"], text=True).splitlines()}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
print(f"ARTIFACT_MANIFEST_CREATED {OUT / 'manifest.json'} sources={len(sources)} artifacts={len(artifacts)}")
