"""Build target-native one-file executables and their redistribution notices."""

import argparse
import hashlib
import importlib.metadata as metadata
import json
import platform
import shutil
import subprocess
import sys
import sysconfig
import tarfile
import tempfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def collect_licenses(destination):
    destination.mkdir(parents=True, exist_ok=True)
    packages = [line.split("==", 1)[0] for line in (ROOT / "requirements.lock").read_text().splitlines()
                if line and not line[0].isspace() and not line.startswith("#")]
    inventory = []
    for name in [*packages, "pyinstaller", "pyinstaller-hooks-contrib"]:
        distribution = metadata.distribution(name)
        files = []
        for file in distribution.files or []:
            if not any(word in str(file).lower() for word in ("license", "copying", "notice")):
                continue
            source = Path(distribution.locate_file(file))
            if not source.is_file():
                continue
            target = destination / name / Path(*[part for part in file.parts if part != ".."])
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            files.append(target.relative_to(destination).as_posix())
        inventory.append({
            "name": name, "version": distribution.version,
            "license": distribution.metadata.get("License-Expression") or distribution.metadata.get("License"),
            "project_urls": distribution.metadata.get_all("Project-URL", []), "license_files": files,
        })
    python_license = next((path for path in (
        Path(sysconfig.get_path("stdlib")) / "LICENSE.txt", Path(sys.base_prefix) / "LICENSE.txt",
        Path(sys.base_prefix) / "licenses/LICENSE.cpython.txt",
    ) if path.is_file()), None)
    if python_license is None:
        raise RuntimeError("Cannot redistribute Python without its original LICENSE.txt")
    shutil.copyfile(python_license, destination / "PYTHON-LICENSE.txt")
    for source in (ROOT / "LICENSE", ROOT / "THIRD-PARTY-NOTICES.md",
                   ROOT / ".tools/LIBRESPEED-LICENSE", ROOT / "data/native/libutp.LICENSE"):
        if source.is_file():
            shutil.copyfile(source, destination / source.name)
    for source in (ROOT / ".tools/libnice").glob("COPYING*"):
        shutil.copyfile(source, destination / ("libnice-" + source.name))
    native_licenses = ROOT / ".tools/libnice/dependency-licenses"
    if native_licenses.is_dir():
        shutil.copytree(native_licenses, destination / "native-windows", dirs_exist_ok=True)
    if sys.platform == "linux":
        for name in ("libnice10", "libglib2.0-0", "libglib2.0-0t64"):
            copyright = Path("/usr/share/doc") / name / "copyright"
            if copyright.is_file():
                shutil.copyfile(copyright, destination / (name + "-copyright.txt"))
    (destination / "dependencies.json").write_text(json.dumps(inventory, indent=2) + "\n", encoding="utf-8")
    return inventory


def collect_sources(output, licenses):
    import av

    version = av.ffmpeg_version_info
    if not version or any(char not in "0123456789." for char in version):
        raise RuntimeError("Unsupported FFmpeg version string for corresponding source")
    archives = [
        (f"FFmpeg-source-{version}.tar.xz", f"https://ffmpeg.org/releases/ffmpeg-{version}.tar.xz"),
        ("LibreSpeed-source-1.0.14.tar.gz", "https://codeload.github.com/librespeed/speedtest-cli/tar.gz/refs/tags/v1.0.14"),
    ]
    records = []
    nice_source = ROOT / ".tools/libnice-source-0.1.22.tar.gz"
    if nice_source.is_file():
        source_copy = output / "libnice-source-0.1.22.tar.gz"
        shutil.copyfile(nice_source, source_copy)
        records.append({"file": source_copy.name, "url": "https://github.com/libnice/libnice/tree/0.1.22",
                        "sha256": sha256(source_copy)})
    for name, url in archives:
        path = output / name
        if not path.is_file():
            with urllib.request.urlopen(url, timeout=60) as response, path.open("wb") as stream:
                shutil.copyfileobj(response, stream)
        records.append({"file": name, "url": url, "sha256": sha256(path)})
    with tarfile.open(output / archives[0][0], "r:xz") as archive:
        for name in ("LICENSE.md", "COPYING.GPLv2", "COPYING.GPLv3", "COPYING.LGPLv2.1", "COPYING.LGPLv3"):
            entry = archive.getmember(f"ffmpeg-{version}/{name}")
            if not entry.isfile() or entry.size > 128 * 1024:
                raise RuntimeError("Invalid FFmpeg license archive entry")
            with archive.extractfile(entry) as stream:
                (licenses / ("FFmpeg-" + name)).write_bytes(stream.read())
    record = {"version": version, "library_versions": av.library_versions, "sources": records}
    (licenses / "native-sources.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    return record


def write_checksums(directory, name="SHA256SUMS.txt"):
    rows = [f"{sha256(path)}  {path.name}" for path in sorted(directory.iterdir())
            if path.is_file() and not path.name.startswith("SHA256SUMS")]
    (directory / name).write_text("\n".join(rows) + "\n", encoding="ascii")


def run(*args):
    subprocess.run([str(arg) for arg in args], cwd=ROOT, check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--skip-build", action="store_true")
    parser.add_argument("--skip-speedtest-install", action="store_true")
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12) or platform.machine().lower() not in ("amd64", "x86_64"):
        raise SystemExit("Release builds require native x64 Python 3.12")
    target = {"win32": "windows-x64", "linux": "linux-x64"}.get(sys.platform)
    if not target:
        raise SystemExit("Release builds support Windows x64 and Linux x64")
    if not args.skip_speedtest_install:
        run(sys.executable, ROOT / "tools/install_librespeed.py")
    output = ROOT / "dist/release"
    output.mkdir(parents=True, exist_ok=True)
    licenses = ROOT / ".tools/licenses"
    inventory = collect_licenses(licenses)
    native_sources = collect_sources(output, licenses)
    if not args.skip_build:
        for name in ("client", "server"):
            run(sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", ROOT / f"packaging/{name}.spec")
    extension = ".exe" if sys.platform == "win32" else ""
    binaries = {}
    from PyInstaller.archive.readers import CArchiveReader

    for role in ("Client", "Server"):
        source = ROOT / "dist" / f"P2PLab-{role}{extension}"
        archive = CArchiveReader(str(source))
        if not archive.toc or not any("THIRD-PARTY-NOTICES" in name for name in archive.toc):
            raise RuntimeError("One-file bundle is missing redistribution notices")
        if role == "Client" and not any("librespeed-cli" in name for name in archive.toc):
            raise RuntimeError("Client bundle is missing LibreSpeed")
        if role == "Client":
            required = ("libutp.dll", "libnice-10.dll", "libglib-2.0-0.dll", "libgobject-2.0-0.dll") if extension else (
                "libutp.so", "libnice.so.10")
            for name in required:
                if not any(Path(entry.replace("\\", "/")).name == name for entry in archive.toc):
                    raise RuntimeError("Client bundle is missing native library: " + name)
        run(source, "--help")
        destination = output / f"P2PLab-{role}-{target}{extension}"
        shutil.copy2(source, destination)
        binaries[role.lower()] = destination
    with zipfile.ZipFile(output / f"THIRD-PARTY-LICENSES-{target}.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(licenses.rglob("*")):
            if path.is_file():
                archive.write(path, path.relative_to(licenses).as_posix())
    (ROOT / "build").mkdir(exist_ok=True)
    smoke = Path(tempfile.mkdtemp(prefix=f"frozen-smoke-{target}-", dir=ROOT / "build"))
    run(sys.executable, ROOT / "tools/smoke_frozen.py", "--client", binaries["client"],
        "--server", binaries["server"], "--output", smoke)
    native_report = smoke / "native-report.json"
    run(binaries["client"], "--native-self-test", native_report)
    revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True,
                              capture_output=True, check=False).stdout.strip() or "uncommitted-local-build"
    record = {"git_revision": revision, "platform": platform.platform(), "python": sys.version,
              "target": target, "format": "pyinstaller-onefile", "dependencies": inventory,
              "native_sources": native_sources,
              "native_smoke": json.loads(native_report.read_text(encoding="utf-8")),
              "smoke": json.loads((smoke / "report.json").read_text()),
              "binaries": {role: {"name": path.name, "sha256": sha256(path), "bytes": path.stat().st_size}
                           for role, path in binaries.items()}}
    (output / f"build-record-{target}.json").write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
    write_checksums(output, f"SHA256SUMS-{target}.txt")
    print("Release assets:", output)


if __name__ == "__main__":
    main()
