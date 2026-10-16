"""Build pinned upstream libutp locally, without installing system packages."""
import hashlib
import io
import json
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REVISION = "2b364cbb0650bdab64a5de2abb4518f9f228ec44"
SHA256 = "6643eee9bad3452768ff9647fd753f438fcf77e4722ceaf9ca99c810016f28fd"
URL = f"https://codeload.github.com/bittorrent/libutp/tar.gz/{REVISION}"


def main():
    root = Path(__file__).resolve().parents[1] / "data/native"
    root.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("LIBUTP_SOURCE_HASH_MISMATCH")
    with tempfile.TemporaryDirectory() as directory:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            archive.extractall(directory, filter="data")
        source = Path(directory) / f"libutp-{REVISION}"
        filename = "libutp.dll" if sys.platform == "win32" else "libutp.so"
        if sys.platform == "win32":
            sources = ["utp_" + name + ".cpp" for name in
                       ("internal", "utils", "hash", "callbacks", "api", "packedsockaddr")]
            subprocess.run(["g++", "-shared", "-O3", "-DWIN32", "-fno-exceptions", "-fno-rtti",
                            "-fpermissive", "-static-libgcc", "-static-libstdc++",
                            "-Wl,--export-all-symbols", "-o", filename, *sources, "-lws2_32"],
                           cwd=source, timeout=120, check=True)
        else:
            subprocess.run(["make", "-j2", "libutp.so"], cwd=source, timeout=120, check=True)
        shutil.copyfile(source / filename, root / filename)
        for name in ("LICENSE", "LICENSE.md"):
            if (source / name).exists():
                shutil.copyfile(source / name, root / "libutp.LICENSE")
    evidence = {"project": "bittorrent/libutp", "revision": REVISION, "source": URL,
                "archive_sha256": hashlib.sha256(data).hexdigest(),
                "platform": sys.platform,
                "library_sha256": hashlib.sha256((root / filename).read_bytes()).hexdigest()}
    (root / "libutp-build.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(root / filename)


if __name__ == "__main__":
    main()
