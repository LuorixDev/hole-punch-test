"""Build record for the packaged desktop client.

The record binds a PyInstaller bundle to the sources that produced it, so a
package or a screenshot can be traced to one revision instead of being trusted.
It is committed next to the desktop evidence, and the recipe it uses is written
in ``docs/DESKTOP-PYTHON.md`` so anyone can recompute it without this script:

    sourceTree = sha256 over every ``p2pchat/**`` file whose suffix is one of
                 .py, .spec, .md, .txt, excluding these directories anywhere in
                 the path: node_modules, releases, review, verification, ci,
                 dist-web, evidence.
    bundle     = sha256 over every file in dist/p2p-desktop (same line format)
    line       = <path relative to the root, POSIX separators> + two spaces + sha256
    digest     = sha256 of the lines joined by "\\n" with no trailing newline

The exclusions matter: a leftover ``node_modules`` from the removed Electron
shell used to leak hundreds of .md/.txt files into the source tree hash, so the
recorded digest changed with the state of a gitignored directory and could not
be recomputed. Only real sources are hashed now.

Usage::

    .venv/bin/python p2pchat/tools/desktop_build_record.py            # write/refresh
    .venv/bin/python p2pchat/tools/desktop_build_record.py --verify   # check only
    .venv/bin/python p2pchat/tools/desktop_build_record.py --recipe   # print the recipe
"""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGE = ROOT / "p2pchat"
DEFAULT_BUNDLE = ROOT / "dist" / "p2p-desktop"
DEFAULT_RECORD = PACKAGE / "python_desktop" / "evidence" / "desktop-build.json"
SOURCE_SUFFIXES = {".py", ".spec", ".md", ".txt"}
EXCLUDED_DIRS = ("node_modules", "releases", "review", "verification", "ci", "dist-web", "evidence")
RECIPE = (
    "sourceTree = sha256 of '<rel>  <sha256>' lines joined by \\n (no trailing newline) over "
    "p2pchat/** files with suffix in .py/.spec/.md/.txt, excluding paths containing any of: "
    + ", ".join(EXCLUDED_DIRS)
    + ". bundle = same line format over every file in dist/p2p-desktop."
)


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_digest(pairs: list[tuple[str, str]]) -> str:
    payload = "\n".join(f"{rel}  {sha}" for rel, sha in pairs).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def _excluded(rel: str) -> bool:
    parts = rel.split("/")
    return any(part in EXCLUDED_DIRS for part in parts[:-1]) or (parts and parts[0] in EXCLUDED_DIRS)


def source_entries() -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for path in PACKAGE.rglob("*"):
        if not path.is_file() or path.suffix not in SOURCE_SUFFIXES:
            continue
        rel = path.relative_to(ROOT).as_posix()
        if _excluded(rel.removeprefix("p2pchat/")):
            continue
        entries.append((rel, file_sha256(path)))
    # Sort by the relative path as a string: sorting ``Path`` objects compares the
    # parts, which orders "a-b" and "a/b" differently and made the digest
    # impossible to reproduce with a plain sort of the printed paths.
    entries.sort()
    return entries


def bundle_entries(bundle: Path) -> list[tuple[str, str]]:
    entries = [
        (path.relative_to(bundle).as_posix(), file_sha256(path))
        for path in bundle.rglob("*")
        if path.is_file()
    ]
    entries.sort()
    return entries


def git(*args: str) -> str:
    result = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, encoding="utf-8")
    return result.stdout.strip()


def desktop_sources() -> dict[str, str]:
    wanted: list[Path] = []
    wanted += [p for p in sorted((PACKAGE / "python_desktop").rglob("*.py"))]
    wanted += [PACKAGE / "tools" / "desktop.spec", PACKAGE / "tools" / "desktop_build_record.py"]
    return {p.relative_to(ROOT).as_posix(): file_sha256(p) for p in wanted if p.is_file()}


def build_record(bundle: Path, previous: dict) -> dict:
    sources = source_entries()
    artifacts = bundle_entries(bundle)
    artifact_index = dict(artifacts)
    exe = "p2p-desktop"
    record = dict(previous)
    record.update(
        {
            "recordVersion": 1,
            "generatedAtUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "sourceCommit": git("rev-parse", "HEAD"),
            "worktreeDirtyAtBuild": bool(git("status", "--porcelain", "--", "p2pchat").strip()),
            "sourceTree": tree_digest(sources),
            "sourceFiles": len(sources),
            "sourceTreeExcludes": list(EXCLUDED_DIRS),
            "recipe": RECIPE,
            "artifact": {
                "bundle": bundle.relative_to(ROOT).as_posix() if bundle.is_relative_to(ROOT) else str(bundle),
                "exe": exe,
                "exeSha256": artifact_index.get(exe, ""),
                "exeBytes": (bundle / exe).stat().st_size if (bundle / exe).is_file() else 0,
                "treeSha256": tree_digest(artifacts),
                "treeFiles": len(artifacts),
                "treeBytes": sum((bundle / rel).stat().st_size for rel, _ in artifacts),
            },
            "desktopSources": desktop_sources(),
        }
    )
    return record


def verify(record: dict, rebuilt: dict) -> list[str]:
    problems: list[str] = []
    for key in ("sourceTree", "sourceFiles"):
        if record.get(key) != rebuilt.get(key):
            problems.append(f"{key}: record={record.get(key)!r} recomputed={rebuilt.get(key)!r}")
    for key in ("exeSha256", "treeSha256", "treeFiles", "treeBytes"):
        if record.get("artifact", {}).get(key) != rebuilt.get("artifact", {}).get(key):
            problems.append(
                f"artifact.{key}: record={record.get('artifact', {}).get(key)!r} "
                f"recomputed={rebuilt.get('artifact', {}).get(key)!r}"
            )
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write or verify the desktop build record.")
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE, help="packaged one-folder bundle")
    parser.add_argument("--out", type=Path, default=DEFAULT_RECORD, help="record file to write")
    parser.add_argument("--verify", action="store_true", help="recompute and compare against the record; no write")
    parser.add_argument("--recipe", action="store_true", help="print the hash recipe and exit")
    args = parser.parse_args(argv)

    if args.recipe:
        print(RECIPE)
        return 0

    if not args.bundle.is_dir():
        print(f"bundle not found: {args.bundle}", file=sys.stderr)
        return 2

    previous: dict = {}
    if args.out.is_file():
        try:
            previous = json.loads(args.out.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"existing record unreadable ({exc}); writing a fresh one", file=sys.stderr)

    rebuilt = build_record(args.bundle, previous)

    if args.verify:
        problems = verify(previous, rebuilt)
        if problems:
            print("BUILD RECORD MISMATCH:", file=sys.stderr)
            for problem in problems:
                print(f"  {problem}", file=sys.stderr)
            return 1
        print("BUILD RECORD VERIFIED")
        print(f"  sourceTree {rebuilt['sourceTree']} ({rebuilt['sourceFiles']} files)")
        print(f"  bundle     {rebuilt['artifact']['treeSha256']} ({rebuilt['artifact']['treeFiles']} files)")
        return 0

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(rebuilt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {args.out.relative_to(ROOT)}")
    print(f"  exe        {rebuilt['artifact']['exeSha256']} ({rebuilt['artifact']['exeBytes']} bytes)")
    print(f"  bundle     {rebuilt['artifact']['treeSha256']} ({rebuilt['artifact']['treeFiles']} files)")
    print(f"  sourceTree {rebuilt['sourceTree']} ({rebuilt['sourceFiles']} files)")
    print(f"  commit     {rebuilt['sourceCommit']} dirty={rebuilt['worktreeDirtyAtBuild']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
