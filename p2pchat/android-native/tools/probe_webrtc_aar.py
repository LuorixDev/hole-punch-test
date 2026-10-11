#!/usr/bin/env python3
"""Offline content verifier for the WebRTC Android AAR used by the native spike.

This tool answers *artifact* questions only. It deliberately does no Android
build, no emulator run and no JVM mock: it inspects the AAR bytes and reports
facts that can be re-derived by anyone with the same file.

Checks
------
1. archive identity          sha256 / sha1 / size, optionally compared with a
                             recorded expectation and (with --remote) with the
                             checksum Maven Central itself serves for the
                             coordinate.
2. shipped ABIs              which jni/<abi>/libjingle_peerconnection_so.so exist
                             and how large they are.
3. 16 KB page readiness      every PT_LOAD segment's p_align, per ABI. Android 15+
                             (targetSdk >= 35) on 16 KB-page devices needs
                             0x4000-aligned load segments. Only the ABIs the app
                             actually packages (--abis, default: the abiFilters in
                             app/build.gradle.kts) can fail the verdict; the other
                             ABIs are still reported.
4. dynamic dependencies      DT_NEEDED entries; a missing on-device library here
                             would be an UnsatisfiedLinkError at runtime.
5. Java API surface          the org.webrtc classes the client needs (DataChannel,
                             ICE/STUN configuration, network monitoring, audio).
6. consumer rules            whether the AAR ships ProGuard/R8 rules of its own.

Exit codes: 0 = all checks passed, 1 = at least one check failed,
2 = usage/IO error. NOT a substitute for a device or emulator run.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import urllib.error
import urllib.request
import zipfile

# ---------------------------------------------------------------- expectations

COORDINATE = "io.github.webrtc-sdk:android:150.7871.01"
MAVEN_BASE = "https://repo1.maven.org/maven2/io/github/webrtc-sdk/android/150.7871.01"
AAR_NAME = "android-150.7871.01.aar"

# Recorded for the coordinate above. sha1 is the value Maven Central itself
# serves in the `x-checksum-sha1` response header; sha256 is the digest of the
# byte-identical local copy (same sha1 + same Content-Length 49147033).
EXPECTED = {
    "size": 49147033,
    "sha1": "b9ae2a17fa38f16ce071f029cf8684fb9166a1c7",
    "sha256": "0a1627b1a48c2bc17d9a40d62fc47bd45166f44a311e95917f147c402de379b0",
}

REQUIRED_CLASSES = [
    "org/webrtc/PeerConnectionFactory.class",
    "org/webrtc/PeerConnectionFactory$Builder.class",
    "org/webrtc/PeerConnection.class",
    "org/webrtc/PeerConnection$RTCConfiguration.class",
    "org/webrtc/PeerConnection$IceServer.class",
    "org/webrtc/PeerConnection$IceServer$Builder.class",
    "org/webrtc/PeerConnection$Observer.class",
    "org/webrtc/DataChannel.class",
    "org/webrtc/DataChannel$Init.class",
    "org/webrtc/DataChannel$Observer.class",
    "org/webrtc/DataChannel$Buffer.class",
    "org/webrtc/IceCandidate.class",
    "org/webrtc/SessionDescription.class",
    "org/webrtc/SdpObserver.class",
    "org/webrtc/NetworkMonitor.class",
    "org/webrtc/NetworkChangeDetector.class",
    "org/webrtc/audio/JavaAudioDeviceModule.class",
    "org/webrtc/audio/JavaAudioDeviceModule$Builder.class",
]

ELF_MAGIC = b"\x7fELF"
PT_LOAD = 1
PT_DYNAMIC = 2
DT_NEEDED = 1
DT_STRTAB = 5


def sha(path: str, algo: str, chunk: int = 1 << 20) -> str:
    h = hashlib.new(algo)
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(chunk), b""):
            h.update(block)
    return h.hexdigest()


# ------------------------------------------------------------------ ELF reader


class Elf:
    """Minimal ELF reader: program headers and DT_NEEDED, no external tools."""

    def __init__(self, data: bytes):
        self.d = data
        if data[:4] != ELF_MAGIC:
            raise ValueError("not an ELF file")
        self.is64 = data[4] == 2
        endian = "<" if data[5] == 1 else ">"
        self.e = endian
        if self.is64:
            (self.e_phoff,) = struct.unpack_from(endian + "Q", data, 0x20)
            (self.e_phentsize,) = struct.unpack_from(endian + "H", data, 0x36)
            (self.e_phnum,) = struct.unpack_from(endian + "H", data, 0x38)
        else:
            (self.e_phoff,) = struct.unpack_from(endian + "I", data, 0x1C)
            (self.e_phentsize,) = struct.unpack_from(endian + "H", data, 0x2A)
            (self.e_phnum,) = struct.unpack_from(endian + "H", data, 0x2C)

    def program_headers(self):
        out = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            if self.is64:
                p_type, p_flags, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = (
                    struct.unpack_from(self.e + "IIQQQQQQ", self.d, off)
                )
            else:
                p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = (
                    struct.unpack_from(self.e + "IIIIIIII", self.d, off)
                )
            out.append(
                {
                    "type": p_type,
                    "flags": p_flags,
                    "offset": p_offset,
                    "vaddr": p_vaddr,
                    "filesz": p_filesz,
                    "memsz": p_memsz,
                    "align": p_align,
                }
            )
        return out

    def _vaddr_to_offset(self, vaddr: int):
        for ph in self.program_headers():
            if ph["type"] == PT_LOAD and ph["vaddr"] <= vaddr < ph["vaddr"] + ph["filesz"]:
                return ph["offset"] + (vaddr - ph["vaddr"])
        return None

    def needed(self):
        dyn = next((p for p in self.program_headers() if p["type"] == PT_DYNAMIC), None)
        if dyn is None:
            return []
        entsize = 16 if self.is64 else 8
        strtab_vaddr = None
        needed_offsets = []
        for i in range(dyn["filesz"] // entsize):
            off = dyn["offset"] + i * entsize
            if self.is64:
                tag, val = struct.unpack_from(self.e + "qQ", self.d, off)
            else:
                tag, val = struct.unpack_from(self.e + "iI", self.d, off)
            if tag == 0:
                break
            if tag == DT_NEEDED:
                needed_offsets.append(val)
            elif tag == DT_STRTAB:
                strtab_vaddr = val
        if strtab_vaddr is None:
            return []
        base = self._vaddr_to_offset(strtab_vaddr)
        if base is None:
            return []
        names = []
        for rel in needed_offsets:
            end = self.d.index(b"\x00", base + rel)
            names.append(self.d[base + rel : end].decode("utf-8", "replace"))
        return names

    def abi(self) -> str:
        machine = struct.unpack_from(self.e + "H", self.d, 0x12)[0]
        if machine == 183:
            return "aarch64"
        if machine == 62:
            return "x86-64"
        if machine == 40:
            return "arm"
        if machine == 3:
            return "i386"
        return f"machine-{machine}"


# ------------------------------------------------------------------- checks


def check_archive(path: str, remote: bool, result: dict) -> None:
    size = os.path.getsize(path)
    digests = {"sha256": sha(path, "sha256"), "sha1": sha(path, "sha1")}
    arch = {
        "path": path,
        "size": size,
        "sha256": digests["sha256"],
        "sha1": digests["sha1"],
        "expected": EXPECTED,
        "expect_recorded_for": COORDINATE,
    }
    problems = []
    if size != EXPECTED["size"]:
        problems.append(f"size {size} != expected {EXPECTED['size']}")
    if digests["sha1"] != EXPECTED["sha1"]:
        problems.append("sha1 differs from the checksum Maven Central serves")
    if digests["sha256"] != EXPECTED["sha256"]:
        problems.append("sha256 differs from the recorded value")
    arch["local_match"] = not problems
    arch["problems"] = problems

    if remote:
        probe = {"url": f"{MAVEN_BASE}/{AAR_NAME}", "checks": {}}
        for header in ("x-checksum-sha1", "x-checksum-md5", "content-length"):
            try:
                req = urllib.request.Request(f"{MAVEN_BASE}/{AAR_NAME}", method="HEAD")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    probe["http_status"] = resp.status
                    probe["checks"][header] = resp.headers.get(header)
            except (urllib.error.URLError, OSError) as exc:  # pragma: no cover - network
                probe["error"] = f"{type(exc).__name__}: {exc}"
                break
        remote_sha1 = probe["checks"].get("x-checksum-sha1")
        probe["sha1_matches_local"] = remote_sha1 == digests["sha1"] if remote_sha1 else None
        arch["remote"] = probe
        if probe.get("sha1_matches_local") is False:
            arch["problems"].append("remote sha1 differs from local file")
            arch["local_match"] = False
    result["archive"] = arch


def check_abis(zf: zipfile.ZipFile, result: dict, build_abis: list) -> None:
    so_names = sorted(
        n for n in zf.namelist() if n.startswith("jni/") and n.endswith(".so")
    )
    abis = []
    for name in so_names:
        abi = name.split("/")[1]
        data = zf.read(name)
        entry = {"abi": abi, "name": os.path.basename(name), "size": len(data)}
        try:
            elf = Elf(data)
            loads = [p for p in elf.program_headers() if p["type"] == PT_LOAD]
            aligns = sorted({hex(p["align"]) for p in loads})
            entry.update(
                {
                    "elf_abi": elf.abi(),
                    "load_align": aligns,
                    "all_loads_16k": bool(loads) and all(p["align"] >= 0x4000 for p in loads),
                    "needed": elf.needed(),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
        except (ValueError, struct.error) as exc:
            entry["error"] = f"{type(exc).__name__}: {exc}"
        abis.append(entry)
    result["abis"] = abis
    result["checks"]["abis_16kb_ready"] = [a["abi"] for a in abis if a.get("all_loads_16k")]
    result["checks"]["16kb_not_ready_all_abis"] = [
        a["abi"] for a in abis if not a.get("all_loads_16k")
    ]
    # Only the ABIs the app packages matter for the shipping APK.
    result["checks"]["build_abis"] = build_abis
    result["checks"]["16kb_missing_in_build_abis"] = [
        a["abi"] for a in abis if a["abi"] in build_abis and not a.get("all_loads_16k")
    ]

    unexpected = sorted(
        {
            lib
            for a in abis
            for lib in a.get("needed", [])
            if lib not in {"libEGL.so", "libGLESv2.so", "libdl.so", "libm.so", "liblog.so", "libc.so", "libandroid.so", "libjnigraphics.so"}
        }
    )
    result["checks"]["needed_outside_platform"] = unexpected


def check_java(zf: zipfile.ZipFile, result: dict) -> None:
    with zf.open("classes.jar") as fh:
        cj = fh.read()
    result["classes_jar"] = {
        "size": len(cj),
        "sha256": hashlib.sha256(cj).hexdigest(),
    }
    import io

    with zipfile.ZipFile(io.BytesIO(cj)) as inner:
        names = set(inner.namelist())
        present = [c for c in REQUIRED_CLASSES if c in names]
        missing = [c for c in REQUIRED_CLASSES if c not in names]
        result["classes_jar"]["required_present"] = len(present)
        result["classes_jar"]["required_total"] = len(REQUIRED_CLASSES)
        result["checks"]["missing_classes"] = missing
        raw = inner.read("org/webrtc/DataChannel.class") if "org/webrtc/DataChannel.class" in names else b""
    if len(raw) > 8:
        major = struct.unpack_from(">H", raw, 6)[0]
        result["classes_jar"]["bytecode_major"] = major
        result["classes_jar"]["bytecode_java"] = major - 44

    extras = [n for n in zf.namelist() if n.startswith("proguard") or "consumer-rules" in n]
    result["checks"]["consumer_proguard_rules"] = extras


def default_build_abis() -> list:
    """Read ndk.abiFilters out of app/build.gradle.kts so the default cannot drift."""
    here = os.path.dirname(os.path.abspath(__file__))
    gradle = os.path.normpath(os.path.join(here, "..", "app", "build.gradle.kts"))
    try:
        with open(gradle, encoding="utf-8") as fh:
            text = fh.read()
    except OSError:
        return []
    match = re.search(r"abiFilters[^\n]*?listOf\(([^)]*)\)", text)
    if not match:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "aar",
        nargs="?",
        default=None,
        help="path to the WebRTC AAR (default: evidence/webrtc-inspect.aar next to this tool)",
    )
    ap.add_argument("--remote", action="store_true", help="also ask Maven Central for its checksum")
    ap.add_argument(
        "--abis",
        default=None,
        help="comma separated ABIs the APK packages (default: ndk.abiFilters from app/build.gradle.kts)",
    )
    ap.add_argument("--json", metavar="PATH", help="write the full report as JSON here")
    args = ap.parse_args()

    build_abis = (
        [a.strip() for a in args.abis.split(",") if a.strip()]
        if args.abis
        else default_build_abis()
    )

    path = args.aar
    if path is None:
        here = os.path.dirname(os.path.abspath(__file__))
        path = os.path.join(here, "..", "evidence", "webrtc-inspect.aar")
        path = os.path.normpath(path)
    if not os.path.isfile(path):
        print(f"ERROR: AAR not found: {path}", file=sys.stderr)
        return 2

    result: dict = {"tool": "probe_webrtc_aar", "coordinate": COORDINATE, "checks": {}}
    check_archive(path, args.remote, result)
    with zipfile.ZipFile(path) as zf:
        result["aar_entries"] = sorted(zf.namelist())
        check_abis(zf, result, build_abis)
        check_java(zf, result)

    checks = result["checks"]
    failed = (
        not result["archive"]["local_match"]
        or bool(checks["missing_classes"])
        or bool(checks["16kb_missing_in_build_abis"])
        or bool(checks["needed_outside_platform"])
    )
    result["verdict"] = "FAIL" if failed else "PASS"
    result["scope_note"] = (
        "content-level verification only: no APK build, no emulator, no device run"
    )
    text = json.dumps(result, indent=2, ensure_ascii=False, sort_keys=True)
    print(text)
    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
