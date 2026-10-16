from __future__ import annotations

import asyncio
import ipaddress
import os
import secrets
import socket
import struct
import sys
import time

import psutil

from .common import sockaddr
from .research import Synchronizer
from .tcp import TcpAttempt
from .udp import UdpAttempt


def checksum(data):
    data += bytes(len(data) % 2)
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return ~total & 65535


def ipv4_packet(source, destination, protocol, payload, ttl=64):
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, ttl, protocol, 0,
                         socket.inet_aton(source), socket.inet_aton(destination))
    header = header[:10] + struct.pack("!H", checksum(header)) + header[12:]
    return header + payload


def icmp_echo(identifier, sequence=1):
    frame = struct.pack("!BBHHH", 8, 0, 0, identifier, sequence)
    return frame[:2] + struct.pack("!H", checksum(frame)) + frame[4:]


def icmp_error(quoted):
    frame = bytes([11, 0]) + bytes(6) + quoted
    return frame[:2] + struct.pack("!H", checksum(frame)) + frame[4:]


def synack(source, target, sequence, acknowledgement):
    src, sport = source
    dst, dport = target
    tcp = struct.pack("!HHIIBBHHH", sport, dport, sequence, acknowledgement, 0x50, 0x12, 65535, 0, 0)
    pseudo = socket.inet_aton(src) + socket.inet_aton(dst) + struct.pack("!BBH", 0, 6, len(tcp))
    tcp = tcp[:16] + struct.pack("!H", checksum(pseudo + tcp)) + tcp[18:]
    return ipv4_packet(src, dst, 6, tcp)


# macOS has no AF_PACKET, so capture comes from /dev/bpf. BPF_TIMEVAL is timeval32 under LP64,
# which makes struct bpf_hdr 18 bytes and word-aligns bh_hdrlen up to 20.
DARWIN_BPF_HEADER_LENGTH = 20
DARWIN_BPF_ALIGNMENT = 4
DARWIN_BPF_BUFFER_BYTES = 512 * 1024
DARWIN_BPF_DEVICE_LIMIT = 256
DARWIN_DLT_NULL = 0
DARWIN_DLT_EN10MB = 1
DARWIN_VLAN_TYPES = (0x8100, 0x88A8)
IOC_OUT, IOC_IN, IOC_INOUT = 1, 2, 3


def darwin_ioctl(direction, number, length):
    """Darwin _IO* request encoding: direction(2) | size(14) | group 'B'(8) | number(8)."""
    return (direction << 30) | (length << 16) | (ord("B") << 8) | number


def raw_capture_backend(system=None):
    """Name this platform's packet-capture backend, or None when it has none."""
    system = sys.platform if system is None else system
    if system.startswith("linux"):
        return "af-packet"
    if system == "darwin":
        return "bpf"
    return None


def bpf_frames(buffer):
    """Yield each captured frame from one BPF read, honouring bh_hdrlen and BPF_WORDALIGN."""
    offset = 0
    while offset + DARWIN_BPF_HEADER_LENGTH <= len(buffer):
        captured = struct.unpack_from("=I", buffer, offset + 8)[0]
        header = struct.unpack_from("=H", buffer, offset + 16)[0]
        if header < DARWIN_BPF_HEADER_LENGTH or offset + header + captured > len(buffer):
            return
        yield buffer[offset + header : offset + header + captured]
        offset = (offset + header + captured + DARWIN_BPF_ALIGNMENT - 1) & ~(DARWIN_BPF_ALIGNMENT - 1)


def strip_link_header(frame, link_type):
    """Return the IP packet inside a captured frame; AF_PACKET yields this already, BPF does not."""
    if link_type == DARWIN_DLT_NULL:
        return frame[4:]
    if link_type == DARWIN_DLT_EN10MB:
        offset = 12
        ethertype = struct.unpack_from("!H", frame, offset)[0]
        while ethertype in DARWIN_VLAN_TYPES and offset + 6 <= len(frame):
            offset += 4
            ethertype = struct.unpack_from("!H", frame, offset)[0]
        return frame[offset + 2 :]
    return frame


def interface_for(address):
    """Name the local interface holding `address`, or None when it cannot be resolved."""
    for name, entries in psutil.net_if_addrs().items():
        for entry in entries:
            if entry.address == address:
                return name
    return None


class AfPacketCapture:
    """Linux capture: AF_PACKET in SOCK_DGRAM mode already reports the network-layer packet."""

    def __init__(self, loop, sock):
        self.loop, self.sock = loop, sock

    async def recv(self):
        return await self.loop.sock_recv(self.sock, 65536)

    def close(self):
        self.sock.close()


class DarwinBpfCapture:
    """macOS capture through /dev/bpf; needs root or membership of the access_bpf group."""

    def __init__(self, loop, fd, link_type, buffer_length, interface):
        self.loop, self.fd, self.link_type = loop, fd, link_type
        self.buffer_length, self.interface = buffer_length, interface
        self.pending = []
        self.readable = asyncio.Event()
        loop.add_reader(fd, self.readable.set)

    def close(self):
        if self.fd is not None:
            self.loop.remove_reader(self.fd)
            os.close(self.fd)
            self.fd = None

    def drain(self):
        """Read everything the kernel queued and keep the link-stripped IP packets."""
        while self.fd is not None:
            try:
                buffer = os.read(self.fd, self.buffer_length)
            except BlockingIOError:
                return
            if not buffer:
                return
            for frame in bpf_frames(buffer):
                packet = strip_link_header(frame, self.link_type)
                if packet:
                    self.pending.append(packet)
            if len(buffer) < self.buffer_length:
                return

    async def recv(self):
        while not self.pending:
            self.readable.clear()
            self.drain()
            if self.pending:
                break
            await self.readable.wait()
        return self.pending.pop(0)


def attach_darwin_bpf(loop, fd, interface):
    """Configure one BPF device for `interface` and hand back a reader for it."""
    import fcntl

    fcntl.ioctl(fd, darwin_ioctl(IOC_INOUT, 102, 4), struct.pack("=I", DARWIN_BPF_BUFFER_BYTES))
    fcntl.ioctl(fd, darwin_ioctl(IOC_IN, 108, 32), struct.pack("=16s16s", interface.encode()[:16], b""))
    fcntl.ioctl(fd, darwin_ioctl(IOC_IN, 112, 4), struct.pack("=I", 1))
    link_type = struct.unpack("=I", fcntl.ioctl(fd, darwin_ioctl(IOC_OUT, 106, 4), struct.pack("=I", 0)))[0]
    length = struct.unpack("=I", fcntl.ioctl(fd, darwin_ioctl(IOC_OUT, 102, 4), struct.pack("=I", 0)))[0]
    os.set_blocking(fd, False)
    return DarwinBpfCapture(loop, fd, link_type, length, interface)


def open_darwin_bpf(loop, address):
    """Attach a BPF reader to the interface holding `address`."""
    interface = interface_for(address)
    if interface is None:
        raise ValueError("RAW_BPF_INTERFACE_UNRESOLVED")
    failure = None
    for index in range(DARWIN_BPF_DEVICE_LIMIT):
        try:
            fd = os.open(f"/dev/bpf{index}", os.O_RDWR)
        except PermissionError:
            raise
        except OSError as exc:
            failure = exc
            break
        try:
            return attach_darwin_bpf(loop, fd, interface)
        except OSError as exc:
            failure = exc
            os.close(fd)
    raise failure if failure is not None else OSError("DARWIN_BPF_DEVICE_EXHAUSTED")


def open_capture(loop, address):
    """Open the capture source for the interface holding `address`, or explain why not."""
    backend = raw_capture_backend()
    if backend == "af-packet":
        family = getattr(socket, "AF_PACKET", None)
        if family is None:
            raise ValueError("RAW_BACKEND_UNAVAILABLE_ON_THIS_PLATFORM")
        sock = socket.socket(family, socket.SOCK_DGRAM, socket.htons(0x0800))
        sock.setblocking(False)
        return AfPacketCapture(loop, sock)
    if backend == "bpf":
        return open_darwin_bpf(loop, address)
    raise ValueError("RAW_BACKEND_UNAVAILABLE_ON_THIS_PLATFORM")


def require_raw(owner):
    if not owner.config.get("experiment", {}).get("raw_probes", False):
        raise ValueError("RAW_EXPERIMENT_DISABLED;SET_experiment.raw_probes=true")
    if raw_capture_backend() is None:
        raise ValueError("RAW_BACKEND_UNAVAILABLE_ON_THIS_PLATFORM")


class IcmpAttempt(UdpAttempt):
    def __init__(self, owner, spec, host):
        require_raw(owner)
        super().__init__(owner, spec, host)
        self.raw = None
        self.metadata = None
        self.metadata_ready = asyncio.Event()
        self.sync = Synchronizer(owner, self.attempt)
        self.association_evidence = None

    async def handle(self, data):
        if data["kind"] == "sync":
            await self.sync.handle(data)
        elif data["kind"] == "raw_meta":
            meta = data["meta"]
            if set(meta) != {"observer", "identifier", "public"} or type(meta["identifier"]) is not int or not 0 <= meta["identifier"] <= 65535:
                raise ValueError("ICMP_METADATA_SCHEMA")
            if any(ipaddress.ip_address(meta[key]).version != 4 for key in ("observer", "public")):
                raise ValueError("ICMP_METADATA_FAMILY")
            self.metadata = meta
            self.metadata_ready.set()

    async def warmup(self):
        try:
            self.raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.raw.bind((self.host, 0))
            self.raw.setblocking(False)
        except PermissionError as exc:
            raise ValueError("RAW_PERMISSION_UNAVAILABLE_CAP_NET_RAW") from exc
        observer = self.owner.tcp_observer[0] if self.owner.tcp_observer else None
        public = next((ip for ip, _ in self.candidates if ipaddress.ip_address(ip).is_global), None)
        if self.owner.loopback:
            observer, public = self.host, self.host
        if not observer or not public:
            raise ValueError("ICMP_PUBLIC_MAPPING_UNAVAILABLE")
        identifier = secrets.randbelow(65536)
        self.raw.sendto(icmp_echo(identifier), (observer, 0))
        await self.owner.signal({"kind": "raw_meta", "attempt": self.attempt,
                                 "meta": {"observer": observer, "identifier": identifier, "public": public}})
        await asyncio.wait_for(self.metadata_ready.wait(), self.owner.timeout)
        await self.sync.synchronize(self.owner.timeout)
        meta = self.metadata
        quoted = ipv4_packet(meta["public"], meta["observer"], 1, icmp_echo(meta["identifier"]))
        loop = asyncio.get_running_loop()
        received, started = False, time.monotonic()
        for _ in range(3):
            self.raw.sendto(icmp_error(quoted), (meta["public"], 0))
            try:
                async with asyncio.timeout(0.5):
                    while True:
                        packet, source = await loop.sock_recvfrom(self.raw, 4096)
                        offset = (packet[0] & 15) * 4
                        if len(packet) < offset + 36 or packet[offset] != 11 or source[0] != meta["public"]:
                            continue
                        inner = packet[offset + 8:]
                        ihl = (inner[0] & 15) * 4
                        if len(inner) >= ihl + 8 and inner[9] == 1 and inner[16:20] == socket.inet_aton(observer):
                            received = inner[ihl] == 8 and struct.unpack_from("!H", inner, ihl + 4)[0] == identifier
                            if received:
                                break
            except TimeoutError:
                pass
            if received:
                break
        self.association_evidence = {"received": received, "observer": observer,
            "evidence": "quoted-echo-error-only;ICMP-ID-rewriting-may-prevent-match;no-causality-claim"}
        self.owner.log.event("raw.icmp_association", attempt=self.attempt, received=received,
            elapsed_ms=(time.monotonic() - started) * 1000, observer=observer,
            evidence="quoted-echo-error-only;ICMP-ID-rewriting-may-prevent-match;no-causality-claim")
        self.raw.close()
        self.raw = None

    async def close(self):
        if self.raw:
            self.raw.close()
            self.raw = None
        await super().close()


class NatBlasterAttempt(TcpAttempt):
    def __init__(self, owner, spec, host):
        require_raw(owner)
        super().__init__(owner, spec, host)
        self.raw = self.capture = None
        self.remote_sequence = None
        self.sequence_ready = asyncio.Event()
        self.sync = Synchronizer(owner, self.attempt)

    async def handle(self, data):
        if data["kind"] == "sync":
            await self.sync.handle(data)
        elif data["kind"] == "raw_meta":
            meta = data["meta"]
            if set(meta) != {"sequence"} or type(meta["sequence"]) is not int or not 0 <= meta["sequence"] < 2**32:
                raise ValueError("NATBLASTER_SEQUENCE_SCHEMA")
            self.remote_sequence = meta["sequence"]
            self.sequence_ready.set()

    async def connect(self):
        await asyncio.wait_for(self.candidates_ready.wait(), self.owner.timeout)
        target = min(self.remote_candidates, key=lambda ep: not ipaddress.ip_address(ep[0]).is_global)
        local = tuple(self.candidates[0])
        loop = asyncio.get_running_loop()
        connecting = None
        original_ttl = self.sock.getsockopt(socket.IPPROTO_IP, socket.IP_TTL)
        try:
            try:
                self.raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
                self.raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                self.capture = open_capture(loop, self.host)
            except PermissionError as exc:
                raise ValueError("RAW_PERMISSION_UNAVAILABLE_CAP_NET_RAW") from exc
            await self.sync.synchronize(self.owner.timeout)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, self.spec.get("ttl", 1))
            connecting = asyncio.create_task(loop.sock_connect(self.sock, sockaddr(target)))
            async with asyncio.timeout(self.owner.timeout):
                while True:
                    packet = await self.capture.recv()
                    offset = (packet[0] & 15) * 4
                    if (len(packet) < offset + 20 or packet[9] != 6 or packet[12:16] != socket.inet_aton(self.host)
                            or packet[16:20] != socket.inet_aton(target[0])):
                        continue
                    sport, dport, sequence = struct.unpack_from("!HHI", packet, offset)
                    if sport == local[1] and dport == target[1] and packet[offset + 13] & 0x12 == 0x02:
                        break
            await self.owner.signal({"kind": "raw_meta", "attempt": self.attempt, "meta": {"sequence": sequence}})
            await asyncio.wait_for(self.sequence_ready.wait(), self.owner.timeout)
            acknowledgement = (self.remote_sequence + 1) & 0xFFFFFFFF
            crafted = synack(local, target, sequence, acknowledgement)
            for _ in range(3):
                self.raw.sendto(crafted, (target[0], 0))
                await asyncio.sleep(0.1)
                if connecting.done():
                    break
            await asyncio.wait_for(connecting, self.owner.timeout)
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl)
            self.owner.log.event("raw.natblaster_handshake", attempt=self.attempt, local=local, target=target,
                sequence=sequence, acknowledgement=acknowledgement, crafted_synack=True,
                evidence="kernel-connect-completed;raw-SYNACK-injected;not-proof-of-causality")
            if not self.spec["initiator"]:
                reader, writer = await self.accept_connected_socket(self.sock)
            else:
                reader, writer = await asyncio.open_connection(sock=self.sock,
                    ssl=self.owner.identity.context(self.owner.peer["certificate"], server=False),
                    server_hostname="p2p-peer", ssl_handshake_timeout=5, limit=128 * 1024)
            self.sock = None
            await self.establish(reader, writer)
            await self.path.wait_ready(self.owner.timeout)
            return self.path
        finally:
            if connecting:
                connecting.cancel()
                await asyncio.gather(connecting, return_exceptions=True)
            for resource in (self.raw, self.capture):
                if resource:
                    resource.close()
            self.raw = self.capture = None
            if self.sock:
                self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, original_ttl)

    async def close(self):
        for resource in (self.raw, self.capture):
            if resource:
                resource.close()
        self.raw = self.capture = None
        await super().close()
