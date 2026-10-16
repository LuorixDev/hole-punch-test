"""macOS raw-probe backend: BPF capture in place of Linux's AF_PACKET.

macOS has no AF_PACKET, so the capture half of the raw probes needs /dev/bpf. These tests cover the
platform selection, the record/link-layer parsing, and (on a Darwin host) a real capture.
"""

import asyncio
import socket
import struct
import sys

import pytest

from p2plab.raw_probes import (
    DARWIN_BPF_HEADER_LENGTH,
    bpf_frames,
    open_capture,
    raw_capture_backend,
    require_raw,
    strip_link_header,
)

PROBE = b"P2PLAB-BPF-PROBE"
DARWIN_DLT_NULL = 0
DARWIN_DLT_EN10MB = 1


class FakeOwner:
    def __init__(self, raw_probes):
        self.config = {"experiment": {"raw_probes": raw_probes}}


@pytest.mark.parametrize(
    ("system", "expected"),
    [
        ("linux", "af-packet"),
        ("linux2", "af-packet"),
        ("darwin", "bpf"),
        ("win32", None),
        ("freebsd13", None),
    ],
)
def test_raw_capture_backend_maps_each_platform(system, expected):
    assert raw_capture_backend(system) == expected


def bpf_record(frame):
    """Lay out one record the way the kernel does: timeval32 stamp, then caplen/datalen/hdrlen."""
    header = struct.pack("=IIIIH2x", 0, 0, len(frame), len(frame), DARWIN_BPF_HEADER_LENGTH)
    return header + frame + bytes(-len(frame) % 4)


def test_bpf_frames_walks_word_aligned_records():
    first, second, third = b"\x01\x02\x03", b"\x04\x05" * 3, b"\x06"
    buffer = bpf_record(first) + bpf_record(second) + bpf_record(third)
    assert list(bpf_frames(buffer)) == [first, second, third]


def test_bpf_frames_stops_at_a_truncated_tail():
    buffer = bpf_record(b"abcd") + b"\x00" * 8
    assert list(bpf_frames(buffer)) == [b"abcd"]


def test_strip_link_header_handles_null_and_ethernet():
    ip = b"\x45" + bytes(19) + b"payload"
    assert strip_link_header(struct.pack("=I", 2) + ip, DARWIN_DLT_NULL) == ip
    ethernet = bytes(12) + struct.pack("!H", 0x0800) + ip
    assert strip_link_header(ethernet, DARWIN_DLT_EN10MB) == ip


def test_strip_link_header_handles_vlan_tagged_ethernet():
    ip = b"\x45" + bytes(19)
    tagged = bytes(12) + struct.pack("!HHH", 0x8100, 1, 0x0800) + ip
    assert strip_link_header(tagged, DARWIN_DLT_EN10MB) == ip


def test_require_raw_rejects_when_the_experiment_is_off():
    with pytest.raises(ValueError, match="RAW_EXPERIMENT_DISABLED"):
        require_raw(FakeOwner(False))


def test_require_raw_rejects_platforms_without_a_capture_backend(monkeypatch):
    monkeypatch.setattr("p2plab.raw_probes.raw_capture_backend", lambda system=None: None)
    with pytest.raises(ValueError, match="RAW_BACKEND_UNAVAILABLE_ON_THIS_PLATFORM"):
        require_raw(FakeOwner(True))


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS BPF admission")
def test_darwin_is_admitted_and_fails_on_privilege_not_on_platform():
    require_raw(FakeOwner(True))  # macOS has a backend, so the platform check must not fire


@pytest.mark.skipif(sys.platform != "darwin", reason="BPF is macOS-only")
async def test_darwin_bpf_capture_recovers_a_real_datagram():
    """The whole point of the backend: read a real packet off the wire via /dev/bpf."""
    try:
        capture = open_capture(asyncio.get_running_loop(), "127.0.0.1")
    except (PermissionError, ValueError) as exc:
        pytest.skip(f"BPF unavailable on this host: {type(exc).__name__}: {exc}")
    try:
        sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sender.bind(("127.0.0.1", 0))
        sender.sendto(PROBE, ("127.0.0.1", 45999))
        sender.close()
        await asyncio.wait_for(await_probe_payload(capture), 5)
    finally:
        capture.close()


async def await_probe_payload(capture):
    while True:
        packet = await capture.recv()
        if len(packet) < 20 or packet[0] >> 4 != 4 or packet[9] != 17:
            continue
        header = (packet[0] & 15) * 4
        _, _, length = struct.unpack_from("!HHH", packet, header)
        if packet[header + 8 : header + length] == PROBE:
            return
