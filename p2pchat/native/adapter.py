"""Async direct-only transport adapter; all remote endpoints come from paired signaling.

No discovery, TURN, fallback relaying, automatic gateway changes or traffic benchmarks.
The caller MUST authenticate signaling before calling signal(). UDP is a probe only.
"""
import asyncio
import base64
import datetime
import hashlib
import ipaddress
import json
import os
import secrets
import socket
import ssl
import struct
import tempfile
import time
import uuid
from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import HandshakeCompleted, StreamDataReceived, ConnectionTerminated
from aioquic.quic.packet import pull_quic_header
from .auth import Auth, packed

MAX_FRAME = 65536
MAX_WIRE = 100000
TERMINAL = {"closed", "failed", "timeout", "unsupported"}
METHODS = ("udp-probe", "quic", "tcp", "tcp-simopen", "upnp", "pcp", "natpmp")


def certificate():
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "p2p-peer")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("p2p-peer")]), False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .sign(key, hashes.SHA256()))
    return key, cert


def validate_candidate(c):
    if not isinstance(c, dict) or set(c) - {"id", "family", "transport", "address", "port", "kind", "socketId", "certificateFingerprint"}:
        raise ValueError("INVALID_CANDIDATE")
    address = ipaddress.ip_address(c["address"])
    if (address.version != c["family"] or address.is_multicast or address.is_unspecified or address.is_link_local
            or str(address) == "255.255.255.255" or not isinstance(c["port"], int)
            or isinstance(c["port"], bool) or not 1 <= c["port"] <= 65535
            or c["kind"] not in {"host", "srflx", "mapped"}
            or c["transport"] not in {"udp", "quic", "tcp"}):
        raise ValueError("INVALID_CANDIDATE")
    return str(address), c["port"]


@dataclass
class Budget:
    attempts: int = 16
    candidates: int = 64
    queued_bytes: int = 512 * 1024


class MutualQuicConnection(QuicConnection):
    """aioquic 1.x lacks public server-side client-cert request configuration.

    Require client proof-of-possession then pin its exact signaling certificate
    on HandshakeCompleted. Private API use is tested against installed aioquic.
    """
    def _initialize(self, peer_cid):
        super()._initialize(peer_cid)
        if not self.configuration.is_client:
            self.tls._request_client_certificate = True


class NativeAdapter:
    def __init__(self, bind_host="127.0.0.1", budget=None, stun_server=None):
        self.bind_host = bind_host
        self.stun_server = stun_server  # explicit trusted configuration, never IPC-specified arbitrary scans
        self.budget = budget or Budget()
        self.attempts = {}
        self.handlers = []
        self.seen = set()

    def subscribe(self, handler):
        self.handlers.append(handler)
        return lambda: self.handlers.remove(handler) if handler in self.handlers else None

    def emit(self, event, params):
        for handler in tuple(self.handlers):
            try:
                handler(event, params)
            except Exception:
                pass  # consumer exceptions must not kill sockets or leak payloads

    async def capabilities(self):
        return {"v": 1, "methods": [
            {"mechanism": m, "status": "available" if m not in {"upnp", "pcp", "natpmp"} else "unsupported",
             "canMessage": m in {"quic", "tcp", "tcp-simopen"},
             "reason": "OPT_IN_GATEWAY_API_ONLY" if m in {"upnp", "pcp", "natpmp"} else
                       ("PROBE_ONLY" if m == "udp-probe" else "EXPERIMENTAL_PLATFORM_UNVERIFIED"),
             "limits": {"maxFrameBytes": MAX_FRAME, "benchmark": m == "quic", "independentBenchmark": m == "quic", "maxAttempts": self.budget.attempts}}
            for m in METHODS]}

    async def start(self, params):
        if len(self.attempts) >= self.budget.attempts:
            raise ValueError("RESOURCE_LIMIT")
        for field in ("connectionId", "attemptId"):
            uuid.UUID(params[field])
        if params["attemptId"] in self.seen:
            raise ValueError("ATTEMPT_REPLAY")
        if len(self.seen) >= 4096:
            raise ValueError("SESSION_ATTEMPT_LIMIT")
        a = params["auth"]
        if not (8 <= len(a["secret"]) <= 256 and 1 <= len(a["room"]) <= 64 and
                a["localPeerId"] != params["peerId"] and params["role"] in {"offerer", "answerer"}):
            raise ValueError("INVALID_AUTH")
        attempt = Attempt(self, params)
        self.attempts[attempt.id] = attempt
        self.seen.add(attempt.id)
        await attempt.start()
        return {"attemptId": attempt.id}

    async def signal(self, params):
        attempt = self.attempts[params["attemptId"]]
        if params["connectionId"] != attempt.connection or params["from"] != attempt.peer:
            raise ValueError("SIGNAL_IDENTITY_MISMATCH")
        await attempt.signal(params)

    async def send(self, params):
        return await self.attempts[params["attemptId"]].send(params["lane"], params["data"])

    async def stats(self, params):
        return self.attempts[params["attemptId"]].stats()

    async def close(self, params):
        attempt = self.attempts.pop(params["attemptId"], None)
        if attempt:
            await attempt.close(params.get("reason", "USER_CLOSED"))
        return {}

    async def network_changed(self):
        """Close old tuples; caller negotiates fresh attemptId/candidates, never reuses identity."""
        for attempt in list(self.attempts.values()):
            await attempt.close("NETWORK_CHANGED")
        self.attempts.clear()

    async def shutdown(self):
        for aid in list(self.attempts):
            await self.close({"attemptId": aid})


class Attempt:
    def __init__(self, adapter, p):
        self.adapter = adapter
        self.id, self.connection, self.peer = p["attemptId"], p["connectionId"], p["peerId"]
        self.mechanism, self.role = p["mechanism"], p["role"]
        self.profile = p.get("profile", "direct")
        self.timeout = min(30, max(.2, p.get("timeoutMs", 10000) / 1000))
        auth = p["auth"]
        self.auth = Auth(auth["room"], auth["secret"], self.connection, self.id, auth["localPeerId"], self.peer)
        self.state, self.failure = "gathering", None
        self.sock = self.writer = self.server = self.quic = None
        self.tasks = set()
        self.remote = self.remote_candidate = self.remote_pem = self.remote_cert = None
        self.candidate = None
        self.signal_ready = asyncio.Event()
        self.stream_buffers = {}
        self.tx = self.rx = 0
        self.rtt = None
        self.start_time = time.monotonic()
        self.direct_time = None
        self.last_receive = time.monotonic()
        self.pings = {}
        self.send_lock = asyncio.Lock()
        self.transport_ready = False
        self.probe_start = None
        self.quic_started = False
        self._temp = None
        self.key = self.cert = None
        self.candidate_count = 0
        self.remote_candidates = {}  # authenticated signaling tuples only; <=64
        self.candidate_auth = {}  # proof state isolated per exact source tuple
        self.remote_socket_id = None
        self.selected = False
        self.probe_cursor = 0
        self.probe_schedule = {}
        self.queued = 0
        self.rx_window, self.rx_packets = time.monotonic(), 0

    def event(self, event, **kwargs):
        self.adapter.emit(event, {"connectionId": self.connection, "attemptId": self.id, **kwargs})

    def transition(self, state, reason=None):
        self.state, self.failure = state, reason
        self.event("state", **self.stats())

    def spawn(self, coro):
        task = asyncio.create_task(coro)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)
        return task

    def stats(self):
        return {"state": self.state, "mechanism": self.mechanism, "profile": self.profile,
                "family": self.candidate["family"] if self.candidate else None,
                "protocol": self.candidate["transport"] if self.candidate else None,
                "localCandidateType": self.candidate["kind"] if self.candidate else None,
                "remoteCandidateType": self.remote_candidate["kind"] if self.remote_candidate else None,
                "localTuple": [self.candidate["address"], self.candidate["port"]] if self.candidate else None,
                "remoteTuple": list(self.remote) if self.remote else None,
                "rttMs": self.rtt, "txBytes": self.tx, "rxBytes": self.rx,
                "goodput": None, "failureCode": self.failure,
                "observability": {"scope": "native-local-socket", "goodput": "MEASURE_WITH_EXPLICIT_BENCHMARK_ACK"}}

    async def start(self):
        if self.mechanism not in {"udp-probe", "quic", "tcp", "tcp-simopen"}:
            self.transition("unsupported", "OPT_IN_GATEWAY_API_ONLY" if self.mechanism in METHODS else "UNSUPPORTED_METHOD")
            return
        try:
            address = ipaddress.ip_address(self.adapter.bind_host)
            if address.is_unspecified or address.is_multicast or address.is_link_local:
                raise ValueError("EXPLICIT_BIND_REQUIRED")
            family = socket.AF_INET if address.version == 4 else socket.AF_INET6
            udp = self.mechanism in {"udp-probe", "quic"}
            self.sock = socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM)
            if family == socket.AF_INET6:
                self.sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            if not udp:
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.sock.setblocking(False)
            self.sock.bind((str(address), 0))
            self.candidate = {"id": str(uuid.uuid4()), "family": address.version,
                              "transport": "quic" if self.mechanism == "quic" else "udp" if udp else "tcp",
                              "address": str(address), "port": self.sock.getsockname()[1], "kind": "host",
                              "socketId": secrets.token_hex(16)}
            if self.mechanism != "udp-probe":
                self.key, self.cert = certificate()
                self.candidate["certificateFingerprint"] = self.cert.fingerprint(hashes.SHA256()).hex()
                self.event("candidate", description={"type": "offer" if self.role == "offerer" else "answer",
                                                     "sdp": self.cert.public_bytes(serialization.Encoding.PEM).decode()})
            if self.mechanism == "tcp" and self.role == "answerer":
                self.sock.listen(4)
            self.transition("gathering")
            self.event("candidate", nativeCandidate=self.candidate)
            if udp and address.version == 4 and self.adapter.stun_server:
                from .stun import binding
                try:
                    mapped = await binding(self.sock, self.adapter.stun_server)
                    self.event("candidate", nativeCandidate={**self.candidate,
                        "id": str(uuid.uuid4()), "kind": "srflx",
                        "address": mapped["address"], "port": mapped["port"]})
                except (OSError, TimeoutError):
                    self.event("diagnostic", code="STUN_MAPPING_UNAVAILABLE")
            self.spawn(self.run())
        except (OSError, ValueError):
            await self.fail("BIND_UNAVAILABLE")

    async def signal(self, p):
        if self.state in TERMINAL:
            raise ValueError("ATTEMPT_TERMINAL")
        if "description" in p:
            pem = p["description"]["sdp"]
            if len(pem) > 8192 or self.mechanism == "udp-probe":
                raise ValueError("INVALID_CERTIFICATE")
            cert = x509.load_pem_x509_certificate(pem.encode())
            if self.remote_pem is not None and self.remote_pem != pem:
                raise ValueError("CERTIFICATE_CHANGED")
            if any(c.get("certificateFingerprint") != cert.fingerprint(hashes.SHA256()).hex()
                   for c in self.remote_candidates.values()):
                raise ValueError("CERTIFICATE_FINGERPRINT_MISMATCH")
            self.remote_pem, self.remote_cert = pem, cert
        elif "nativeCandidate" in p:
            self.candidate_count += 1
            if self.candidate_count > self.adapter.budget.candidates:
                raise ValueError("CANDIDATE_LIMIT")
            c = p["nativeCandidate"]
            remote = validate_candidate(c)
            if c["transport"] != self.candidate["transport"] or c["family"] != self.candidate["family"]:
                raise ValueError("CANDIDATE_INCOMPATIBLE")
            if self.remote_socket_id is not None and c["socketId"] != self.remote_socket_id:
                raise ValueError("CANDIDATE_SOCKET_CHANGED")
            if self.remote_pem and c.get("certificateFingerprint") != self.remote_cert.fingerprint(hashes.SHA256()).hex():
                raise ValueError("CERTIFICATE_FINGERPRINT_MISMATCH")
            if self.remote_candidate and c.get("certificateFingerprint") != self.remote_candidate.get("certificateFingerprint"):
                raise ValueError("CERTIFICATE_FINGERPRINT_MISMATCH")
            if self.mechanism not in {"udp-probe", "quic"} and self.remote is not None and self.remote != remote:
                raise ValueError("TCP_TUPLE_REQUIRES_NEW_ATTEMPT")
            self.remote_socket_id = c["socketId"]
            if remote not in self.remote_candidates:
                self.remote_candidates[remote] = dict(c)
                auth = Auth(self.auth.room, self.auth.key.decode(), self.connection, self.id, self.auth.local, self.peer)
                # One attempt/socket nonce, but separate received-hello/ACK state:
                # proofs from distinct source tuples cannot be combined into direct.
                auth.nonce = self.auth.nonce
                self.candidate_auth[remote] = auth
            if self.remote is None:
                self.remote, self.remote_candidate = remote, self.remote_candidates[remote]
        else:
            raise ValueError("INVALID_SIGNAL")
        if self.remote and (self.mechanism == "udp-probe" or self.remote_pem):
            if self.remote_pem and self.remote_candidate.get("certificateFingerprint") != self.remote_cert.fingerprint(hashes.SHA256()).hex():
                raise ValueError("CERTIFICATE_FINGERPRINT_MISMATCH")
            self.signal_ready.set()

    async def run(self):
        try:
            await asyncio.wait_for(self.signal_ready.wait(), self.timeout)
            self.transition("probing")
            self.probe_start = time.monotonic()
            if self.mechanism in {"udp-probe", "quic"}:
                self.spawn(self.receive_udp())
                self.spawn(self.udp_clock())
            else:
                self.spawn(self.connect_tcp())
            deadline = time.monotonic() + self.timeout
            while self.state not in TERMINAL and self.state != "direct":
                if time.monotonic() > deadline:
                    await self.fail("PROBE_TIMEOUT", "timeout")
                    return
                await asyncio.sleep(.02)
            if self.state == "direct":
                self.spawn(self.keepalive())
        except asyncio.TimeoutError:
            await self.fail("SIGNAL_TIMEOUT", "timeout")
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.fail("TRANSPORT_FAILED")

    async def udp_clock(self):
        next_send = 0
        try:
            while self.state not in TERMINAL:
                now = time.monotonic()
                if not self.selected and now >= next_send:
                    tuples = list(self.remote_candidates)
                    # Round-robin trickled candidates, aggregate <=20 probes/sec.
                    for offset in range(len(tuples)):
                        index = (self.probe_cursor + offset) % len(tuples)
                        target = tuples[index]
                        due, delay = self.probe_schedule.get(target, (0, .1))
                        if now >= due:
                            try:
                                await self.raw_udp(b"P2POBS1" + packed(self.candidate_auth[target].frame()), target)
                            except OSError:
                                # An unroutable host candidate cannot kill later srflx.
                                if target not in self.probe_schedule:
                                    self.event("diagnostic", code="CANDIDATE_SEND_UNAVAILABLE")
                            self.probe_schedule[target] = (now + delay, min(1, delay * 2))
                            self.probe_cursor = (index + 1) % len(tuples)
                            next_send = now + .05
                            break
                if self.quic:
                    timer = self.quic.get_timer()
                    if timer is not None and timer <= now:
                        self.quic.handle_timer(now=now)
                    await self.quic_flush()
                    await self.quic_events()
                await asyncio.sleep(.01)
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.fail("UDP_IO_FAILED")

    async def raw_udp(self, data, target=None):
        await asyncio.get_running_loop().sock_sendto(self.sock, data, target or self.remote)

    async def receive_udp(self):
        try:
            while self.state not in TERMINAL:
                data, addr = await asyncio.get_running_loop().sock_recvfrom(self.sock, MAX_WIRE)
                source = addr[:2]
                if source not in self.remote_candidates or (self.selected and source != self.remote):
                    continue
                if data.startswith(b"P2POBS1"):
                    if time.monotonic() - self.rx_window >= 1:
                        self.rx_window, self.rx_packets = time.monotonic(), 0
                    self.rx_packets += 1
                    if self.rx_packets > 40:
                        continue
                    if len(data) > 4096:
                        continue
                    try:
                        frame = json.loads(data[7:])
                        if frame.get("kind") in {"hello", "hello-ack"}:
                            candidate_auth = self.candidate_auth[source]
                            response = candidate_auth.receive(frame)
                            if response:
                                await self.raw_udp(b"P2POBS1" + packed(response), source)
                            if candidate_auth.direct and not self.selected:
                                self.auth = candidate_auth
                                self.remote = source
                                self.remote_candidate = self.remote_candidates[source]
                                self.selected = True
                                self.last_receive = time.monotonic()
                                self.rtt = (time.monotonic() - self.probe_start) * 1000
                                if self.mechanism == "udp-probe":
                                    if self.state != "direct":
                                        self.transition("direct")
                                elif not self.quic_started and self.role == "offerer":
                                    self.init_quic()
                                    self.quic.connect(self.remote, now=time.monotonic())
                                    await self.quic_flush()
                        elif self.auth.direct and frame.get("kind") in {"ping", "pong"}:
                            nonce = self.auth.verify_control(frame)
                            if frame["kind"] == "ping":
                                await self.raw_udp(b"P2POBS1" + packed(self.auth.control("pong", nonce)))
                            else:
                                started = self.pings.pop(nonce, None)
                                if started is not None:
                                    self.rtt = (time.monotonic() - started) * 1000
                                    self.last_receive = time.monotonic()
                        else:
                            continue
                        if not self.auth.direct:
                            self.last_receive = time.monotonic()
                    except (ValueError, TypeError, KeyError):
                        continue  # unauthenticated packets cannot kill another peer's attempt
                elif self.mechanism == "quic" and self.auth.direct:
                    if not self.quic:
                        if self.role != "answerer":
                            continue
                        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                        self.init_quic(header.destination_cid)
                    self.quic.receive_datagram(data, addr, now=time.monotonic())
                    await self.quic_events()
                    await self.quic_flush()
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.fail("UDP_IO_FAILED")

    def init_quic(self, original=None):
        conf = QuicConfiguration(is_client=self.role == "offerer", alpn_protocols=["p2pobs-v1"],
                                 server_name="p2p-peer", idle_timeout=20, max_data=1024 * 1024,
                                 max_stream_data=256 * 1024, verify_mode=ssl.CERT_REQUIRED)
        conf.certificate, conf.private_key = self.cert, self.key
        conf.load_verify_locations(cadata=self.remote_pem.encode())
        self.quic = MutualQuicConnection(configuration=conf, original_destination_connection_id=original)
        self.quic_started = True
        self.transition("authenticating")

    async def quic_flush(self):
        for data, addr in self.quic.datagrams_to_send(now=time.monotonic()):
            # aioquic may suggest migration; this adapter only permits the authenticated tuple.
            if addr[:2] == self.remote:
                await asyncio.get_running_loop().sock_sendto(self.sock, data, addr)

    async def quic_events(self):
        while self.quic:
            event = self.quic.next_event()
            if event is None:
                break
            if isinstance(event, HandshakeCompleted):
                peer_cert = self.quic.tls._peer_certificate
                now = datetime.datetime.now(datetime.timezone.utc)
                if (peer_cert is None or peer_cert.fingerprint(hashes.SHA256()).hex() !=
                        self.remote_candidate["certificateFingerprint"] or
                        not peer_cert.not_valid_before_utc <= now <= peer_cert.not_valid_after_utc):
                    await self.fail("CERTIFICATE_FINGERPRINT_MISMATCH")
                    return
                self.transport_ready = True
                # Re-authenticate inside the encrypted stream, binding QUIC to this peer/attempt.
                self.channel_auth = Auth(self.auth.room, self.auth.key.decode(), self.connection,
                                         self.id, self.auth.local, self.peer)
                await self.write_frame(self.channel_auth.frame())
            elif isinstance(event, StreamDataReceived):
                if event.stream_id not in {0, 4}:
                    await self.fail("UNEXPECTED_STREAM")
                    return
                buf = self.stream_buffers.setdefault(event.stream_id, bytearray())
                buf.extend(event.data)
                await self.consume_buffer(buf, "benchmark" if event.stream_id == 4 else "chat")
            elif isinstance(event, ConnectionTerminated):
                await self.fail("QUIC_TLS_OR_CONNECTION_FAILED")
                return

    def tls_context(self, server):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_verify_locations(cadata=self.remote_pem)
        self._temp = tempfile.TemporaryDirectory(prefix="p2pobs-tls-")
        cert_path, key_path = os.path.join(self._temp.name, "cert.pem"), os.path.join(self._temp.name, "key.pem")
        for path, data in [(cert_path, self.cert.public_bytes(serialization.Encoding.PEM)),
                           (key_path, self.key.private_bytes(serialization.Encoding.PEM,
                                                            serialization.PrivateFormat.PKCS8,
                                                            serialization.NoEncryption()))]:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(data)
        ctx.load_cert_chain(cert_path, key_path)
        return ctx

    async def connect_tcp(self):
        try:
            loop = asyncio.get_running_loop()
            if self.mechanism == "tcp" and self.role == "answerer":
                self.sock.listen(4)
                while True:
                    connected, addr = await loop.sock_accept(self.sock)
                    if addr[:2] == self.remote:
                        self.sock.close()
                        self.sock = connected
                        break
                    connected.close()
            else:
                # simultaneous-open: BOTH roles bind+connect, neither listens nor accepts.
                # A refusal/race is explicitly failed, never disguised with a listening fallback.
                await asyncio.wait_for(loop.sock_connect(self.sock, self.remote), self.timeout)
            self.transition("authenticating")
            server_side = self.role == "answerer"
            ctx = self.tls_context(server_side)
            reader = asyncio.StreamReader(limit=MAX_WIRE)
            protocol = asyncio.StreamReaderProtocol(reader)
            transport, _ = await loop.connect_accepted_socket(lambda: protocol, self.sock)
            transport = await loop.start_tls(transport, protocol, ctx, server_side=server_side,
                                             server_hostname=None if server_side else "p2p-peer",
                                             ssl_handshake_timeout=self.timeout)
            self.writer = asyncio.StreamWriter(transport, protocol, reader, loop)
            peer_der = transport.get_extra_info("ssl_object").getpeercert(binary_form=True)
            if hashlib.sha256(peer_der).hexdigest() != self.remote_candidate["certificateFingerprint"]:
                raise ValueError("CERTIFICATE_FINGERPRINT_MISMATCH")
            self.transport_ready = True
            self.channel_auth = self.auth
            await self.write_frame(self.auth.frame())
            while self.state not in TERMINAL:
                size = struct.unpack("!I", await reader.readexactly(4))[0]
                if size > MAX_WIRE:
                    raise ValueError("FRAME_LIMIT")
                frame = json.loads(await reader.readexactly(size))
                await self.handle_frame(frame, "chat")
        except asyncio.CancelledError:
            raise
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError):
            await self.fail("TCP_SIMOPEN_UNAVAILABLE" if self.mechanism == "tcp-simopen" else "TCP_TLS_OR_CONNECT_FAILED")
        except Exception:
            await self.fail("TCP_IO_FAILED")

    async def consume_buffer(self, buf, lane):
        if len(buf) > 2 * MAX_WIRE:
            raise ValueError("FRAME_LIMIT")
        while len(buf) >= 4:
            size = struct.unpack("!I", buf[:4])[0]
            if size > MAX_WIRE:
                raise ValueError("FRAME_LIMIT")
            if len(buf) < size + 4:
                break
            frame = json.loads(bytes(buf[4:4+size]))
            del buf[:size+4]
            await self.handle_frame(frame, lane)

    async def handle_frame(self, frame, lane):
        kind = frame.get("kind")
        if kind in {"hello", "hello-ack"}:
            response = self.channel_auth.receive(frame)
            if response:
                await self.write_frame(response)
            if self.channel_auth.direct and self.state != "direct":
                self.direct_time = time.monotonic()
                self.rtt = (self.direct_time - self.probe_start) * 1000
                self.transition("direct")
        elif self.state != "direct":
            raise ValueError("AUTH_REQUIRED")
        elif kind == "data":
            if frame.get("lane") != lane:
                raise ValueError("LANE_MISMATCH")
            data = base64.b64decode(frame["dataB64"], validate=True)
            if len(data) > MAX_FRAME:
                raise ValueError("FRAME_LIMIT")
            self.rx += len(data)
            self.event("data", lane=lane, dataB64=frame["dataB64"])
        elif kind == "ping":
            await self.write_frame({"kind": "pong", "nonce": frame["nonce"]})
        elif kind == "pong":
            started = self.pings.pop(frame.get("nonce"), None)
            if started is not None:
                self.rtt = (time.monotonic() - started) * 1000
        else:
            raise ValueError("UNKNOWN_FRAME")
        self.last_receive = time.monotonic()

    async def write_frame(self, frame, lane="chat"):
        data = packed(frame)
        if len(data) > MAX_WIRE:
            raise ValueError("FRAME_LIMIT")
        wire = struct.pack("!I", len(data)) + data
        if self.mechanism == "quic":
            self.quic.send_stream_data(4 if lane == "benchmark" else 0, wire)
            await self.quic_flush()
        else:
            self.writer.write(wire)
            await self.writer.drain()

    async def send(self, lane, data):
        if self.state != "direct" or self.mechanism == "udp-probe":
            raise ValueError("NOT_MESSAGE_CAPABLE")
        if lane not in {"chat", "benchmark"} or len(data) > MAX_FRAME:
            raise ValueError("FRAME_LIMIT")
        if lane == "benchmark" and self.mechanism != "quic":
            raise ValueError("BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION")
        if self.queued + len(data) > self.adapter.budget.queued_bytes:
            raise ValueError("BACKPRESSURE")
        # QUIC internal retransmit storage needs ACK backpressure, not just the UDP socket.
        if self.quic:
            pending = sum(s.sender._buffer_stop - s.sender._buffer_start for s in self.quic._streams.values())
            if pending + len(data) * 1.4 > self.adapter.budget.queued_bytes:
                raise ValueError("BACKPRESSURE")
        self.queued += len(data)
        try:
            async with self.send_lock:
                await asyncio.wait_for(self.write_frame({"kind": "data", "lane": lane,
                    "dataB64": base64.b64encode(data).decode()}, lane), 5)
                self.tx += len(data)
        finally:
            self.queued -= len(data)
        return {"queuedBytes": self.queued}

    async def keepalive(self):
        try:
            while self.state == "direct":
                await asyncio.sleep(5)
                if time.monotonic() - self.last_receive > 20:
                    await self.fail("KEEPALIVE_TIMEOUT", "timeout")
                    return
                nonce = secrets.token_hex(16)
                self.pings[nonce] = time.monotonic()
                if self.mechanism == "udp-probe":
                    await self.raw_udp(b"P2POBS1" + packed(self.auth.control("ping", nonce)))
                else:
                    await self.write_frame({"kind": "ping", "nonce": nonce})
                self.pings = {k: v for k, v in self.pings.items() if time.monotonic()-v < 20}
        except asyncio.CancelledError:
            raise
        except Exception:
            await self.fail("KEEPALIVE_IO_FAILED")

    async def fail(self, code, state="failed"):
        if self.state in TERMINAL:
            return
        self.transition(state, code)
        await self.cleanup()

    async def cleanup(self):
        current = asyncio.current_task()
        tasks = [task for task in self.tasks if task is not current]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.writer:
            self.writer.close()
            try:
                await asyncio.wait_for(self.writer.wait_closed(), 1)
            except Exception:
                pass
            self.writer = None
        if self.sock:
            self.sock.close()
            self.sock = None
        if self._temp:
            self._temp.cleanup()
            self._temp = None
        self.auth.clear()
        for auth in self.candidate_auth.values():
            auth.clear()
        self.candidate_auth.clear()
        self.remote_candidates.clear()
        self.probe_schedule.clear()
        if hasattr(self, "channel_auth"):
            self.channel_auth.clear()
        self.key = self.cert = self.remote_cert = self.remote_pem = self.quic = None
        self.stream_buffers.clear()

    async def close(self, reason):
        self.transition("closed", reason if reason in {"NETWORK_CHANGED", "SUPERSEDED"} else "USER_CLOSED")
        await self.cleanup()
