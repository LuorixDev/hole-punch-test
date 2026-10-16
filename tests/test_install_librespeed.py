"""The checksum-pinned LibreSpeed CLI download must cover macOS, which has no project package."""

import io
import re
import tarfile

from tools.install_librespeed import HASHES, VERSION, archive_url, install_archive

MACOS_ARCHITECTURES = {("Darwin", "arm64"): "darwin_arm64", ("Darwin", "x86_64"): "darwin_amd64"}


def test_hash_pins_cover_both_macos_architectures():
    """Without these, `python tools/install_librespeed.py` tells macOS users to go elsewhere."""
    for key, asset in MACOS_ARCHITECTURES.items():
        assert HASHES[key][0] == asset


def test_every_pinned_digest_is_a_sha256():
    for asset, digest in HASHES.values():
        assert re.fullmatch(r"[0-9a-f]{64}", digest), (asset, digest)


def test_darwin_assets_download_as_tarballs():
    """Only the Windows release is published as a zip; macOS ships a tar.gz like Linux."""
    assert archive_url("darwin_arm64") == (
        f"https://github.com/librespeed/speedtest-cli/releases/download/v{VERSION}/"
        f"librespeed-cli_{VERSION}_darwin_arm64.tar.gz"
    )
    assert archive_url("windows_amd64").endswith(".zip")


def test_install_archive_extracts_a_darwin_tarball(tmp_path):
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as archive:
        for name in ("librespeed-cli", "LICENSE"):
            payload = b"#!/bin/sh\n"
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    binary = install_archive(raw.getvalue(), tmp_path / "tools")
    assert binary.name == "librespeed-cli"
    assert binary.read_bytes() == b"#!/bin/sh\n"
    assert (tmp_path / "tools" / "LIBRESPEED-LICENSE").read_bytes() == b"#!/bin/sh\n"
    assert binary.stat().st_mode & 0o111, "the downloaded CLI must end up executable"
