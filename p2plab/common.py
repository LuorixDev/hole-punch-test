from __future__ import annotations

import asyncio
import base64
import datetime as dt
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import NameOID

VERSION = 1
MAX_FRAME = 64 * 1024
BENCH_BINARY_FLAG = 1 << 31
FILE_BINARY_FLAG = 1 << 30
BINARY_FLAGS = BENCH_BINARY_FLAG | FILE_BINARY_FLAG
BENCH_HEADER = struct.Struct("!8sI")
BENCH_CHUNK = 60 * 1024
MAX_TEXT = 16 * 1024
ALPN = "p2plab/1"


def packed(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def endpoint(address: str, port: int, *, public: bool = False) -> tuple[str, int]:
    ip = ipaddress.ip_address(address)
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("INVALID_PORT")
    if ip.is_unspecified or ip.is_multicast or ip.is_link_local or "%" in address:
        raise ValueError("INVALID_ADDRESS_SCOPE")
    if str(ip) == "255.255.255.255" or (public and not ip.is_global):
        raise ValueError("NON_PUBLIC_ADDRESS")
    return ip.compressed, port


def sockaddr(ep: tuple[str, int]) -> tuple:
    return (*ep, 0, 0) if ":" in ep[0] else ep


def family(host: str) -> int:
    return socket.AF_INET6 if ":" in host else socket.AF_INET


def interface_index(interface: str | int) -> int:
    # Windows InterfaceAlias is not necessarily a Winsock interface name.
    if type(interface) is int or isinstance(interface, str) and interface.isascii() and interface.isdecimal():
        index = int(interface)
    else:
        index = socket.if_nametoindex(interface)
    if not 1 <= index <= 0xFFFFFFFF:
        raise ValueError("INVALID_INTERFACE_INDEX")
    return index


def new_socket(host: str, kind: int, port: int = 0, *, reuse_port=False, reuse_address=False) -> socket.socket:
    sock = socket.socket(family(host), kind)
    try:
        if sock.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        if kind == socket.SOCK_STREAM or reuse_address:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port:
            if not hasattr(socket, "SO_REUSEPORT"):
                raise ValueError("SO_REUSEPORT_UNAVAILABLE")
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        sock.setblocking(False)
        sock.bind(sockaddr((host, port)))
        return sock
    except BaseException:
        sock.close()
        raise


class Identity:
    def __init__(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock_file = (directory / "device.lock").open("a+b")
        if os.name == "posix":
            import fcntl

            try:
                fcntl.flock(self.lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                self.lock_file.close()
                raise ValueError("CLIENT_DATA_DIRECTORY_ALREADY_IN_USE;USE_A_DIFFERENT_--data") from None
        elif os.name == "nt":
            import msvcrt

            # Windows denies reads of another process's locked byte; size queries are safe.
            if not os.fstat(self.lock_file.fileno()).st_size:
                self.lock_file.write(b"\0")
                self.lock_file.flush()
            self.lock_file.seek(0)
            try:
                msvcrt.locking(self.lock_file.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError:
                self.lock_file.close()
                raise ValueError("CLIENT_DATA_DIRECTORY_ALREADY_IN_USE;USE_A_DIFFERENT_--data") from None
        signing_file = directory / "device.key"
        if signing_file.exists():
            self.signing = ed25519.Ed25519PrivateKey.from_private_bytes(signing_file.read_bytes())
        else:
            self.signing = ed25519.Ed25519PrivateKey.generate()
            with signing_file.open("xb") as f:
                signing_file.chmod(0o600)
                f.write(self.signing.private_bytes_raw())
        self.public = b64(self.signing.public_key().public_bytes_raw())
        self.tls_key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p2p-peer")])
        now = dt.datetime.now(dt.timezone.utc)
        self.certificate = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(self.tls_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=2))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("p2p-peer")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(self.tls_key, hashes.SHA256())
        )
        self.cert_pem = self.certificate.public_bytes(serialization.Encoding.PEM).decode()
        self.fingerprint = self.certificate.fingerprint(hashes.SHA256()).hex()
        suffix = secrets.token_hex(8)
        self.cert_file = directory / f"tls-{suffix}.crt"
        self.key_file = directory / f"tls-{suffix}.key"
        for path, data in (
            (self.cert_file, self.cert_pem.encode()),
            (
                self.key_file,
                self.tls_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption(),
                ),
            ),
        ):
            with path.open("xb") as f:
                path.chmod(0o600)
                f.write(data)

    def sign(self, body: dict) -> dict:
        body = dict(body)
        body["signature"] = b64(self.signing.sign(packed(body)))
        return body

    @staticmethod
    def verify(body: dict, public: str) -> dict:
        if not isinstance(body, dict):
            raise ValueError("INVALID_SIGNED_FRAME")
        copy = dict(body)
        signature = unb64(copy.pop("signature"))
        ed25519.Ed25519PublicKey.from_public_bytes(unb64(public)).verify(signature, packed(copy))
        return copy

    def context(self, peer_cert: str, *, server: bool) -> ssl.SSLContext:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.load_cert_chain(self.cert_file, self.key_file)
        ctx.load_verify_locations(cadata=peer_cert)
        ctx.verify_mode = ssl.CERT_REQUIRED
        if not server:
            ctx.check_hostname = True
        return ctx

    def close(self):
        self.key_file.unlink(missing_ok=True)
        self.cert_file.unlink(missing_ok=True)
        self.lock_file.close()


def encode_frame(body: dict) -> bytes:
    if body.get("kind") in ("bench_chunk", "file_chunk") and isinstance(body.get("data"), bytes):
        bid = bytes.fromhex(body["id"])
        seq = body["seq"]
        if len(bid) != 8 or isinstance(seq, bool) or not isinstance(seq, int) or not 0 <= seq < 2**32:
            raise ValueError("BENCH_BINARY_HEADER")
        raw = body["data"]
        if not 1 <= len(raw) <= BENCH_CHUNK:
            raise ValueError("BENCH_CHUNK_LIMIT")
        data = BENCH_HEADER.pack(bid, seq) + raw
        flag = FILE_BINARY_FLAG if body["kind"] == "file_chunk" else BENCH_BINARY_FLAG
        return struct.pack("!I", flag | len(data)) + data
    data = packed(body)
    if len(data) > MAX_FRAME:
        raise ValueError("FRAME_LIMIT")
    return struct.pack("!I", len(data)) + data


def decode_frame(data, binary=False, *, attachment=False):
    if binary:
        if not BENCH_HEADER.size < len(data) <= BENCH_HEADER.size + BENCH_CHUNK:
            raise ValueError("BENCH_BINARY_FRAME_LIMIT")
        bid, seq = BENCH_HEADER.unpack_from(data)
        return {
            "kind": "file_chunk" if attachment else "bench_chunk",
            "id": bid.hex(),
            "seq": seq,
            "data": bytes(data[BENCH_HEADER.size :]),
        }
    body = json.loads(data)
    if not isinstance(body, dict):
        raise ValueError("INVALID_FRAME")
    return body


def extract_frames(buffer: bytearray) -> list[dict]:
    frames = []
    while len(buffer) >= 4:
        header = struct.unpack_from("!I", buffer)[0]
        flags = header & BINARY_FLAGS
        if flags == BINARY_FLAGS:
            raise ValueError("INVALID_BINARY_FLAGS")
        size = header & ~BINARY_FLAGS
        if not 1 <= size <= MAX_FRAME:
            raise ValueError("FRAME_LIMIT")
        if len(buffer) < size + 4:
            break
        body = decode_frame(buffer[4 : 4 + size], bool(flags), attachment=bool(flags & FILE_BINARY_FLAG))
        frames.append(body)
        del buffer[: 4 + size]
    if len(buffer) > MAX_FRAME + 4:
        raise ValueError("FRAME_BUFFER_LIMIT")
    return frames


async def read_frame(reader: asyncio.StreamReader) -> dict:
    header = struct.unpack("!I", await reader.readexactly(4))[0]
    flags = header & BINARY_FLAGS
    if flags == BINARY_FLAGS:
        raise ValueError("INVALID_BINARY_FLAGS")
    size = header & ~BINARY_FLAGS
    if not 1 <= size <= MAX_FRAME:
        raise ValueError("FRAME_LIMIT")
    return decode_frame(await reader.readexactly(size), bool(flags), attachment=bool(flags & FILE_BINARY_FLAG))
