"""Build the tested, checksum-pinned libnice without changing system libraries."""

import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.request
from pathlib import Path

VERSION = "0.1.22"
REVISION = "ae3eb16fd7d1237353bf64e899c612b8a63bca8a"
SHA256 = "55ee4553f2e324be88cd95a5335095ea1658512157370d90c21580d9606b59ac"
URL = f"https://codeload.github.com/libnice/libnice/tar.gz/{REVISION}"


def main():
    if sys.platform != "linux":
        raise SystemExit("This libnice build recipe requires Linux")
    root = Path(__file__).resolve().parents[1]
    prefix = root / ".tools/libnice"
    prefix.mkdir(parents=True, exist_ok=True)
    with urllib.request.urlopen(URL, timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != SHA256:
        raise SystemExit("LIBNICE_SOURCE_HASH_MISMATCH")
    (root / f".tools/libnice-source-{VERSION}.tar.gz").write_bytes(raw)
    with tempfile.TemporaryDirectory() as temporary:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            archive.extractall(temporary, filter="data")
        source = Path(temporary) / f"libnice-{REVISION}"
        build = Path(temporary) / "build"
        subprocess.run([
            "meson", "setup", str(build), str(source), "--prefix", str(prefix), "--libdir", "lib",
            "-Dgupnp=disabled", "-Dgstreamer=disabled", "-Dexamples=disabled", "-Dtests=disabled",
            "-Dgtk_doc=disabled", "-Dintrospection=disabled",
        ], check=True, timeout=120)
        subprocess.run(["meson", "compile", "-C", str(build), "-j", "2"], check=True, timeout=180)
        subprocess.run(["meson", "install", "-C", str(build)], check=True, timeout=60)
        for name in ("COPYING", "COPYING.LGPL", "COPYING.MPL"):
            shutil.copyfile(source / name, prefix / name)
    print("Installed tested libnice", VERSION, "in", prefix)


if __name__ == "__main__":
    main()
