"""Build pinned upstream libutp locally, without installing system packages."""
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

REVISION = "2b364cbb0650bdab64a5de2abb4518f9f228ec44"
URL = f"https://codeload.github.com/bittorrent/libutp/tar.gz/{REVISION}"


def main():
    root = Path(__file__).resolve().parents[1] / "data/native"
    root.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=30) as response:
        data = response.read(16 * 1024 * 1024)
    with tempfile.TemporaryDirectory() as directory:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            archive.extractall(directory, filter="data")
        source = Path(directory) / f"libutp-{REVISION}"
        subprocess.run(["make", "-j2", "libutp.so"], cwd=source, timeout=120, check=True)
        shutil.copyfile(source / "libutp.so", root / "libutp.so")
        for name in ("LICENSE", "LICENSE.md"):
            if (source / name).exists():
                shutil.copyfile(source / name, root / "libutp.LICENSE")
    evidence = {"project": "bittorrent/libutp", "revision": REVISION, "source": URL,
                "archive_sha256": hashlib.sha256(data).hexdigest(),
                "library_sha256": hashlib.sha256((root / "libutp.so").read_bytes()).hexdigest()}
    (root / "libutp-build.json").write_text(json.dumps(evidence, indent=2) + "\n")
    print(root / "libutp.so")


if __name__ == "__main__":
    main()
