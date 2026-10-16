"""Install a checksum-pinned LibreSpeed CLI into this project, without root."""

import hashlib
import io
import platform
import tarfile
import urllib.request
import zipfile
from pathlib import Path

VERSION = "1.0.14"
HASHES = {
    ("Linux", "x86_64"): ("linux_amd64", "89800767ac14085c78a20847ebea23340f6c14a78de0a15c2ac7db8b565c961f"),
    ("Linux", "aarch64"): ("linux_arm64", "75e51a2494d03cb35a92ddbf862b40571a25a1526f3cf3dfa8b1d5d7bc622bd9"),
    ("Windows", "AMD64"): ("windows_amd64", "324f9bc16f3b9bb6bfa6af89bad1e3e5183ae8c91464b3cb3fc2db8df1d6b503"),
    ("Windows", "x86_64"): ("windows_amd64", "324f9bc16f3b9bb6bfa6af89bad1e3e5183ae8c91464b3cb3fc2db8df1d6b503"),
    ("Darwin", "arm64"): ("darwin_arm64", "2c19acf8cf751341ca4edcf6ce5ca460c1091646e68fcea885d941ce3542af7d"),
    ("Darwin", "x86_64"): ("darwin_amd64", "1daa058118e8fc788d985734110f7a51f6d8d37c641be4782d0276cd21458eb8"),
}


def install_archive(raw, directory, *, windows=False):
    directory.mkdir(exist_ok=True)
    binary = "librespeed-cli.exe" if windows else "librespeed-cli"
    if windows:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            for name in (binary, "LICENSE"):
                entry = archive.getinfo(name)
                if entry.is_dir() or entry.file_size > 32 * 1024 * 1024:
                    raise ValueError("LIBRESPEED_ARCHIVE_INVALID")
                destination = directory / (name if name == binary else "LIBRESPEED-LICENSE")
                destination.write_bytes(archive.read(entry))
    else:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:gz") as archive:
            for name in (binary, "LICENSE"):
                entry = archive.getmember(name)
                if not entry.isfile() or entry.size > 32 * 1024 * 1024:
                    raise ValueError("LIBRESPEED_ARCHIVE_INVALID")
                destination = directory / (name if name == binary else "LIBRESPEED-LICENSE")
                with archive.extractfile(entry) as stream:
                    destination.write_bytes(stream.read())
        (directory / binary).chmod(0o755)
    return directory / binary


def archive_url(asset):
    """Release URL of `asset`; only the Windows build is published as a zip, not a tarball."""
    base = f"https://github.com/librespeed/speedtest-cli/releases/download/v{VERSION}/"
    suffix = "zip" if asset.startswith("windows_") else "tar.gz"
    return base + f"librespeed-cli_{VERSION}_{asset}.{suffix}"


def main():
    asset, digest = HASHES.get((platform.system(), platform.machine()), (None, None))
    if not asset:
        raise SystemExit("Install librespeed-cli using your platform package manager instead")
    windows = asset.startswith("windows_")
    url = archive_url(asset)
    with urllib.request.urlopen(url, timeout=30) as response:
        raw = response.read(16 * 1024 * 1024 + 1)
    if len(raw) > 16 * 1024 * 1024 or hashlib.sha256(raw).hexdigest() != digest:
        raise SystemExit("LIBRESPEED_DOWNLOAD_HASH_MISMATCH")
    directory = Path(__file__).resolve().parents[1] / ".tools"
    binary = install_archive(raw, directory, windows=windows)
    print("Installed", binary, "version", VERSION)


if __name__ == "__main__":
    main()
