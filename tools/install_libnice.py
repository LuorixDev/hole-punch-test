"""Build the tested, checksum-pinned libnice without changing system libraries."""

import hashlib
import io
import json
import os
import re
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


def bundle_windows_dependencies(prefix):
    """Copy only the transitive PE imports, never depend on the build machine PATH."""
    compiler = Path(shutil.which("gcc") or "")
    if not compiler.is_file():
        raise RuntimeError("WINDOWS_NATIVE_BUILD_REQUIRES_MSYS2_UCRT64")
    directory = compiler.resolve().parent
    destination = prefix / "bin"
    pending = list(destination.glob("*.dll"))
    utp = prefix.parents[1] / "data/native/libutp.dll"
    if utp.is_file():
        pending.append(utp)
    seen = set()
    system = Path(os.environ["SystemRoot"]) / "System32"
    packages = set()
    while pending:
        path = pending.pop()
        if path.name.lower() in seen:
            continue
        seen.add(path.name.lower())
        imports = subprocess.run(["objdump", "-p", str(path)], capture_output=True,
                                 text=True, check=True, timeout=30).stdout
        for name in re.findall(r"DLL Name:\s*(\S+)", imports):
            if name.lower().startswith(("api-ms-", "ext-ms-")) or (system / name).is_file():
                continue
            source = directory / name
            target = destination / name
            if not target.is_file():
                if not source.is_file():
                    raise RuntimeError("MISSING_NATIVE_DLL_DEPENDENCY:" + name)
                shutil.copy2(source, target)
                posix_path = subprocess.run(["cygpath", "-u", str(source)], check=True, text=True,
                                            capture_output=True, timeout=30).stdout.strip()
                package = subprocess.run(["pacman", "-Qqo", posix_path], check=True,
                                         text=True, capture_output=True, timeout=30).stdout.strip()
                packages.add(package)
            pending.append(target)
    licenses = prefix / "dependency-licenses"
    records = []
    for package in sorted(packages):
        info = subprocess.run(["pacman", "-Qi", package], check=True, text=True,
                              capture_output=True, timeout=30).stdout
        records.append({"package": package, "metadata": info})
    license_root = directory.parent / "share/licenses"
    if license_root.is_dir():
        shutil.copytree(license_root, licenses, dirs_exist_ok=True)
    inventory = {"packages": records, "dlls": [
        {"file": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in sorted(destination.glob("*.dll"))]}
    (prefix / "windows-dependencies.json").write_text(json.dumps(inventory, indent=2) + "\n")


def main():
    if sys.platform not in ("linux", "win32"):
        raise SystemExit("This libnice build recipe requires Linux or Windows UCRT64")
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
    if sys.platform == "win32":
        bundle_windows_dependencies(prefix)
    print("Installed tested libnice", VERSION, "in", prefix)


if __name__ == "__main__":
    main()
