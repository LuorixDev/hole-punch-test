#!/usr/bin/env python3
"""把 APK 的身份写进**一份**记录：sha256 + sourceCommit + 源文件树哈希。

为什么：只把 commit 放在 artifact 名字里，产物与源码版本就绑不住（t43 复审抓到的同类问题）。
这个工具让 `p2pchat/releases/android-native-apk.sha256` 同时回答三个问题：

  * 这个 APK 的 sha256 是多少（第一行仍是 `sha256sum` 兼容格式）；
  * 它由哪个 commit 构建（`sourceCommit=`）；
  * 该 commit 下 `p2pchat/android-native/` 的源文件树哈希（`sourceTree=` + `sourceFiles=`），
    即使 APK 被重新打包/挪走，也能用源文件哈希核对"证据是不是来自被审版本"。

记录样例（有 APK）：

    6e4c3a0d…9f2b  app-rtc-debug.apk
    sourceCommit=21651b59b08c42aea0c54754a6056c2d21651b59
    sourceTree=sha256:8c1f…ab7d
    sourceFiles=47
    apkSha256=6e4c3a0d…9f2b
    apkName=app-rtc-debug.apk
    repo=p2pchat/android-native
    generatedAtUtc=2026-10-12T04:10:11Z
    recordVersion=1

没有产出 APK 时（第一行保持原来的 `NO_APK_PRODUCED` 语义，便于 grep）：

    NO_APK_PRODUCED
    reason=no apk matched …
    sourceCommit=…
    sourceTree=sha256:…
    sourceFiles=47
    apkSha256=-
    apkName=-
    repo=p2pchat/android-native
    generatedAtUtc=…
    recordVersion=1

用途：
    python3 p2pchat/android-native/tools/apk_identity.py \\
        --apk p2pchat/android-native/app/build/outputs/apk/rtc/debug \\
        --commit "$GITHUB_SHA" --source-root p2pchat/android-native \\
        --out p2pchat/releases/android-native-apk.sha256
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import sys
from pathlib import Path

SKIP_DIRS = {"build", ".gradle", ".git", "__pycache__", ".idea", "releases"}
SKIP_FILES = {"local.properties", ".DS_Store"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def find_apk(target: str) -> Path | None:
    if not target:
        return None
    candidate = Path(target)
    if candidate.is_dir():
        apks = sorted(candidate.rglob("*.apk"), key=lambda path: path.stat().st_mtime, reverse=True)
        return apks[0] if apks else None
    if candidate.is_file():
        return candidate
    parent = candidate.parent
    if parent.is_dir():
        apks = sorted(parent.glob(candidate.name), key=lambda path: path.stat().st_mtime, reverse=True)
        return apks[0] if apks else None
    return None


def source_tree_hash(root: Path) -> tuple[str, int, list[str]]:
    """按路径排序后对 (相对路径, 文件 sha256) 再次哈希：源文件树指纹。"""
    if not root.is_dir():
        return "", 0, []
    entries: list[tuple[str, str]] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        if path.name in SKIP_FILES:
            continue
        entries.append((path.relative_to(root).as_posix(), sha256_file(path)))
    if not entries:
        return "", 0, []
    accumulator = hashlib.sha256()
    for relative, digest in entries:
        accumulator.update(f"{relative}\0{digest}\n".encode())
    return accumulator.hexdigest(), len(entries), [relative for relative, _ in entries]


def main() -> int:
    parser = argparse.ArgumentParser(description="APK identity record (sha256 + sourceCommit + source tree hash)")
    parser.add_argument("--apk", default="", help="APK 文件、目录或 glob；为空/找不到时记录 NO_APK_PRODUCED")
    parser.add_argument("--commit", default="unknown", help="sourceCommit（CI 里传 $GITHUB_SHA）")
    parser.add_argument("--source-root", default="p2pchat/android-native")
    parser.add_argument("--out", default="", help="记录写到这个文件（同时打到 stdout）")
    args = parser.parse_args()

    root = Path(args.source_root)
    tree_hash, file_count, files = source_tree_hash(root)
    apk = find_apk(args.apk)
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    lines: list[str] = []
    if apk is not None:
        digest = sha256_file(apk)
        lines.append(f"{digest}  {apk.name}")
        apk_fields = (digest, apk.name)
    else:
        lines.append("NO_APK_PRODUCED")
        lines.append(f"reason=no apk matched {args.apk or '<empty>'}")
        apk_fields = ("-", "-")

    lines.append(f"sourceCommit={args.commit}")
    lines.append(f"sourceTree=sha256:{tree_hash or '-'}")
    lines.append(f"sourceFiles={file_count}")
    lines.append(f"apkSha256={apk_fields[0]}")
    lines.append(f"apkName={apk_fields[1]}")
    lines.append(f"repo={root.as_posix()}")
    lines.append(f"generatedAtUtc={timestamp}")
    lines.append("recordVersion=1")

    record = "\n".join(lines) + "\n"
    print(record, end="")
    if args.out:
        out_path = Path(args.out)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(record, encoding="utf-8")
        print(f"RECORD_WRITTEN {out_path} files={file_count} apk={apk_fields[1]}", file=sys.stderr)
    # 记录本身永远不失败 job：构建失败由构建步骤负责，这里只如实记录。
    return 0


if __name__ == "__main__":
    sys.exit(main())
