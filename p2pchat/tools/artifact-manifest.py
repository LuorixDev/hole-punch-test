"""Create reproducibility manifest without copying secrets or local research state."""
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "releases"
OUT.mkdir(exist_ok=True)
def digest(path):
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()
sources = {}
for directory in ("native", "desktop", "platform", "web"):
    for path in (ROOT / directory).rglob("*"):
        if path.is_file() and path.suffix in (".py", ".js", ".cjs", ".html", ".css", ".txt") and not any(x in path.parts for x in ("build", "work", "__pycache__")):
            sources[path.relative_to(ROOT).as_posix()] = digest(path)
for name in ("package-lock.json", "requirements.txt", "electron-builder.yml"):
    sources[name] = digest(ROOT / name)
artifacts = {p.name: digest(p) for p in OUT.iterdir() if p.is_file() and p.suffix in (".apk", ".exe", ".gz")}
manifest = {"sourceCommit": os.environ.get("GITHUB_SHA", "local-uncommitted"), "python": platform.python_version(), "system": platform.system(), "sourceSha256": sources, "artifactSha256": artifacts,
            "pythonDependencies": subprocess.check_output([__import__('sys').executable, "-m", "pip", "freeze"], text=True).splitlines()}
(OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf8")
