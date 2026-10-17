from __future__ import annotations

import asyncio
import errno
import ipaddress
import json
import secrets
import socket
import ssl
import struct
import sys
import time
from collections import deque

from aioquic import __version__ as aioquic_version
from aioquic.buffer import Buffer
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicConnection
from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted, StreamDataReceived, StreamReset
from aioquic.quic.packet import QuicPacketType, pull_quic_header
from cryptography.exceptions import InvalidSignature

from .common import ALPN, Identity, encode_frame, endpoint, extract_frames, new_socket, packed, sockaddr
from .quic_timer import QuicTimer
from .session import BENCH_STREAM_CAPABILITY, Path
from .stun import FilteringObserver, StunMixin, resolve_observers

MAGIC = b"P2L1"
PROFILES = {
    "balanced": {"initial": 0.1, "ceiling": 0.8, "offset": 0.0},
    "fast": {"initial": 0.05, "ceiling": 0.25, "offset": 0.0},
    "staggered": {"initial": 0.2, "ceiling": 1.0, "offset": 0.35},
}


def probe_packet(body, size=512):
    raw = packed(body)
    if len(raw) + 6 > size:
        raise ValueError("PROBE_SIZE_TOO_SMALL")
    return MAGIC + struct.pack("!H", len(raw)) + raw + b"\0" * (size - len(raw) - 6)


def parse_probe(data):
    if len(data) < 6 or len(data) > 1500 or data[:4] != MAGIC:
        raise ValueError("INVALID_PROBE")
    size = struct.unpack_from("!H", data, 4)[0]
    if size > len(data) - 6 or any(data[6 + size :]):
        raise ValueError("PROBE_PADDING")
    body = json.loads(data[6 : 6 + size])
    if not isinstance(body, dict) or body.get("size") != len(data):
        raise ValueError("PROBE_SIZE_MISMATCH")
    return body


class UdpAttempt(asyncio.DatagramProtocol, StunMixin):
    def __init__(self, owner, spec, host):
        self.owner, self.spec, self.host = owner, spec, host
        self.attempt = spec["attempt"]
        self.peer = dict(owner.peer)
        self.pair, self.local_id = owner.pair, owner.peer_id
        self.transport = None
        self.candidates = []
        self.remote_candidates = []
        self.remote = None
        self.nonce = secrets.token_hex(16)
        self.local_nonces = {}
        self.challenge_started = {}
        self.probe_rtt = 0.0
        self.auth = {}
        self.direct = asyncio.Event()
        self.candidates_ready = asyncio.Event()
        self.probes = {}
        self.hairpin_pending = {}
        self.received = deque()
        self.quic = None
        self.closed = False
        self.sends, self.rejected = 0, 0
        self.received_probes = 0
        self.stun_observations, self.stun_failures = [], []
        self.last_error = None
        self.init_stun()

    async def open(self):
        sock = new_socket(self.host, socket.SOCK_DGRAM, self.spec.get("bind_port", 0))
        # Ask the kernel not to silently fragment IPv4 probes, when the platform supports it.
        if sys.platform.startswith("linux"):
            if sock.family == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_MTU_DISCOVER", 10), 2)
            else:
                sock.setsockopt(socket.IPPROTO_IPV6, getattr(socket, "IPV6_MTU_DISCOVER", 23), 2)
        elif sock.family == socket.AF_INET and hasattr(socket, "IP_DONTFRAGMENT"):
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_DONTFRAGMENT, 1)
        await asyncio.get_running_loop().create_datagram_endpoint(lambda: self, sock=sock)
        self.candidates = [list(sock.getsockname()[:2])]
        self.owner.log.event("udp.bound", attempt=self.attempt, local=self.candidates[0])

    def connection_made(self, transport):
        self.transport = transport

    def error_received(self, exc):
        self.last_error = type(exc).__name__ + ":" + str(exc)
        self.owner.log.event(
            "udp.socket_error",
            self.last_error,
            "WARNING",
            attempt=self.attempt,
            errno=getattr(exc, "errno", None),
            winerror=getattr(exc, "winerror", None),
            mtu_evidence=getattr(exc, "errno", None) == errno.EMSGSIZE,
        )

    def nonce_for(self, target):
        if target not in self.local_nonces and len(self.local_nonces) >= 512:
            raise ValueError("CANDIDATE_CHALLENGE_LIMIT")
        return self.local_nonces.setdefault(target, secrets.token_hex(16))

    def frame(self, kind, *, target, size=512, **extra):
        return self.owner.identity.sign(
            {
                "v": 1,
                "kind": kind,
                "pair": self.pair,
                "attempt": self.attempt,
                "from": self.local_id,
                "to": self.peer["id"],
                "nonce": self.nonce_for(target),
                "size": size,
                **extra,
            }
        )

    def send(self, target, body):
        if not self.closed:
            self.transport.sendto(probe_packet(body, body["size"]), sockaddr(target))
            if body["kind"] == "hello":
                self.challenge_started.setdefault(target, time.monotonic())
            self.sends += 1

    def datagram_received(self, data, addr):
        if self.receive_stun(data, addr):
            return
        source = (addr[0], addr[1])
        if not data.startswith(MAGIC):
            if self.quic and source == self.remote:
                self.quic.receive(data, addr)
            return
        self.received_probes += 1
        try:
            own = parse_probe(data)
            if own.get("kind") == "hairpin" and own.get("from") == self.local_id:
                frame = Identity.verify(own, self.owner.identity.public)
                if any(frame.get(key) != value for key, value in (("pair", self.pair), ("attempt", self.attempt),
                    ("to", self.local_id), ("v", 1))):
                    return
                pending = self.hairpin_pending.get(frame.get("nonce"))
                if pending and not pending.done():
                    pending.set_result(list(source))
                return
        except (ValueError, KeyError, TypeError, InvalidSignature):
            self.rejected += 1
            return
        now = time.monotonic()
        while self.received and self.received[0] < now - 1:
            self.received.popleft()
        if len(self.received) >= 80:
            self.rejected += 1
            return
        self.received.append(now)
        try:
            source = endpoint(*source)
            body = Identity.verify(parse_probe(data), self.peer["public"])
            if any(
                body.get(k) != v
                for k, v in (
                    ("pair", self.pair),
                    ("attempt", self.attempt),
                    ("from", self.peer["id"]),
                    ("to", self.local_id),
                    ("v", 1),
                )
            ):
                raise ValueError("PROBE_CONTEXT_MISMATCH")
            if self.remote is not None and source != self.remote and not self.spec.get("pool_unselected"):
                return
            if source not in self.auth and len(self.auth) >= (512 if self.spec.get("pool_unselected") else 24):
                raise ValueError("PEER_REFLEXIVE_LIMIT")
            auth = self.auth.setdefault(source, {"hello": False, "ack": False, "nonce": None})
            if auth["nonce"] is not None and auth["nonce"] != body["nonce"]:
                if self.direct.is_set() and not self.spec.get("pool_unselected"):
                    raise ValueError("PROBE_NONCE_CHANGED")
                auth["ack"] = False
            auth["nonce"] = body["nonce"]
            kind = body["kind"]
            if kind == "hello":
                auth["hello"] = True
                self.send(source, self.frame("hello_ack", target=source, echo=body["nonce"]))
                # Challenge observed, authenticated peer-reflexive source ports, not only signaled ports.
                if not auth["ack"]:
                    self.send(source, self.frame("hello", target=source))
            elif kind == "hello_ack":
                if body.get("echo") != self.nonce_for(source):
                    raise ValueError("PROBE_CHALLENGE_MISMATCH")
                if not auth["ack"] and source in self.challenge_started:
                    auth["challenge_rtt"] = now - self.challenge_started[source]
                auth["ack"] = True
            elif kind == "mtu":
                if body.get("echo") != self.nonce_for(source):
                    raise ValueError("MTU_CHALLENGE_MISMATCH")
                self.send(
                    source,
                    self.frame(
                        "mtu_ack",
                        target=source,
                        probe=body["probe"],
                        echo=body["nonce"],
                        tested_size=body["size"],
                    ),
                )
            elif kind == "mtu_ack":
                if body.get("echo") != self.nonce_for(source):
                    raise ValueError("MTU_ACK_MISMATCH")
                future = self.probes.get(body.get("probe"))
                if future and not future.done():
                    future.set_result(body["tested_size"])
            else:
                raise ValueError("UNKNOWN_PROBE_KIND")
            if auth["hello"] and auth["ack"] and not self.direct.is_set():
                self.remote = source
                self.direct.set()
                self.owner.log.event(
                    "udp.authenticated",
                    attempt=self.attempt,
                    local=self.candidates[0],
                    remote=source,
                    peer_reflexive=list(source) not in self.remote_candidates,
                    evidence="both-hello-and-challenge-ack",
                    data_path=False,
                )
        except Exception:
            self.rejected += 1

    async def observe(self, observers):
        samples, endpoint_samples = [], []
        self.stun_observations = samples
        filtering = None
        for observer in observers[:4]:
            try:
                version = socket.AF_INET6 if ":" in self.host else socket.AF_INET
                targets = await asyncio.wait_for(resolve_observers(observer, family=version), 3)
                result, last_failure = None, None
                for target in targets[:2]:
                    try:
                        result = await self.binding(target, timeout=1.5)
                        break
                    except (OSError, TimeoutError, ValueError) as exc:
                        last_failure = exc
                        failure = {"observer": observer, "target": list(target),
                                   "reason": type(exc).__name__ + ":" + str(exc)}
                        self.stun_failures.append(failure)
                        self.owner.log.event("stun.target_failed", attempt=self.attempt,
                                             level="WARNING", **failure)
                if result is None:
                    raise last_failure
                if not samples:
                    try:
                        filtering = await FilteringObserver().test(self.host, target)
                        self.owner.log.event("nat.filtering", attempt=self.attempt, **filtering)
                    except (OSError, TimeoutError, ValueError) as exc:
                        filtering = {"behavior": "undetermined", "reason": type(exc).__name__}
                        self.owner.log.event("nat.filtering", attempt=self.attempt, behavior="undetermined",
                                             fresh_socket=True, reason=type(exc).__name__ + ":" + str(exc))
                for repeat in range(2):
                    if repeat:
                        result = await self.binding(target, timeout=1.5)
                    mapped = list(result["mapped"])
                    if mapped not in self.candidates:
                        self.candidates.append(mapped)
                    sample = {
                        "observer": target,
                        "mapped": mapped,
                        "repeat": repeat,
                        "local": self.candidates[0],
                        "evidence": "same-socket-mapping-only",
                    }
                    samples.append(sample)
                    endpoint_samples.append((target, tuple(mapped)))
                    self.owner.log.event("stun.observed", attempt=self.attempt, **sample)
                if "other" in result:
                    alternate = result["other"]
                    if alternate[0] != target[0]:
                        for dest in ((alternate[0], target[1]), alternate):
                            extra = await self.binding(dest, timeout=1)
                            endpoint_samples.append((dest, extra["mapped"]))
            except Exception as exc:
                self.stun_failures.append({"observer": observer, "reason": type(exc).__name__ + ":" + str(exc)})
                self.owner.log.event(
                    "stun.failed", type(exc).__name__ + ":" + str(exc), "WARNING",
                    attempt=self.attempt, observer=observer, exception=type(exc).__name__,
                )
        behavior = "undetermined"
        repeat_mappings = {}
        for dest, mapped in endpoint_samples:
            repeat_mappings.setdefault(dest, set()).add(mapped)
        if any(len(values) > 1 for values in repeat_mappings.values()):
            behavior = "unstable-mapping-inconclusive"
        elif len({dest[0] for dest, _ in endpoint_samples}) >= 2:
            mappings = {mapped for _, mapped in endpoint_samples}
            behavior = (
                "endpoint-independent-observed" if len(mappings) == 1 else "destination-dependent-observed"
            )
        self.owner.log.event("nat.mapping", attempt=self.attempt, behavior=behavior, observations=samples)
        if ":" not in self.host:
            self.owner.record_nat_probe(
                attempt=self.attempt,
                local=self.candidates[0],
                mapping=behavior,
                filtering=(filtering or {}).get("behavior", "undetermined"),
                samples=samples,
            )
        return samples

    def candidate_evidence(self):
        def public(candidates):
            return any(ipaddress.ip_address(ep[0]).is_global for ep in candidates)

        if self.owner.loopback or ":" in self.host:
            diagnosis = "DIRECT_ADDRESS_CANDIDATES"
        elif not public(self.candidates):
            diagnosis = "LOCAL_PUBLIC_UDP_MAPPING_MISSING"
        elif not public(self.remote_candidates):
            diagnosis = "PEER_PUBLIC_UDP_CANDIDATE_MISSING"
        else:
            diagnosis = "PUBLIC_UDP_CANDIDATES_PRESENT"
        return {
            "local_candidates": [list(ep) for ep in self.candidates],
            "remote_candidates": [list(ep) for ep in self.remote_candidates],
            "stun_observations": self.stun_observations,
            "stun_failures": self.stun_failures,
            "diagnosis": diagnosis,
            "socket_error": self.last_error,
            "probe_sends": self.sends,
            "received_probes": self.received_probes,
            "rejected_probes": self.rejected,
            "scope": "missing-public-candidates-does-not-rule-out-LAN-or-routed-private-connectivity",
        }

    def set_candidates(self, candidates):
        if not isinstance(candidates, list) or len(candidates) > 256:
            raise ValueError("CANDIDATE_LIMIT")
        version = ipaddress.ip_address(self.host).version
        self.remote_candidates = []
        for item in candidates:
            candidate = endpoint(*item)
            if ipaddress.ip_address(candidate[0]).is_loopback and not self.owner.loopback:
                raise ValueError("UNEXPECTED_LOOPBACK_CANDIDATE")
            if ipaddress.ip_address(candidate[0]).version != version:
                raise ValueError("CANDIDATE_FAMILY_MISMATCH")
            self.remote_candidates.append(list(candidate))
        self.candidates_ready.set()

    async def punch(self, timeout):
        await asyncio.wait_for(self.candidates_ready.wait(), timeout)
        profile = PROFILES[self.spec.get("profile", "balanced")]
        offset = self.spec.get("offset", profile["offset"]) if not self.spec["initiator"] else 0
        await asyncio.sleep(offset)
        ttl = self.spec.get("ttl")
        if ttl:
            sock = self.transport.get_extra_info("socket")
            level = socket.IPPROTO_IPV6 if ":" in self.host else socket.IPPROTO_IP
            option = socket.IPV6_UNICAST_HOPS if ":" in self.host else socket.IP_TTL
            original = sock.getsockopt(level, option)
            try:
                sock.setsockopt(level, option, ttl)
                for target in self.remote_candidates[:32]:
                    self.send(tuple(target), self.frame("hello", target=tuple(target)))
                await asyncio.sleep(0.15)
            finally:
                sock.setsockopt(level, option, original)
            self.owner.log.event("udp.ttl_warmup", attempt=self.attempt, ttl=ttl, restored=original,
                                 evidence="low-TTL-state-warmup;final-authentication-at-normal-TTL")
        self.owner.log.event("udp.punch_started", attempt=self.attempt, local_monotonic=time.monotonic(),
                             offset=offset, **self.candidate_evidence())
        started, wait = time.monotonic(), profile["initial"]
        while not self.direct.is_set() and time.monotonic() - started < timeout:
            for target in self.remote_candidates:
                self.send(tuple(target), self.frame("hello", target=tuple(target)))
            try:
                await asyncio.wait_for(self.direct.wait(), wait)
            except TimeoutError:
                pass
            wait = min(profile["ceiling"], wait * 1.6)
        self.owner.log.event(
            "udp.result",
            attempt=self.attempt,
            state="success" if self.direct.is_set() else "timeout",
            elapsed_ms=(time.monotonic() - started) * 1000,
            sends=self.sends,
            rejected=self.rejected,
            parameters=profile,
            socket_error=self.last_error,
            candidate_evidence=self.candidate_evidence(),
        )
        if not self.direct.is_set():
            raise TimeoutError("UDP_AUTHENTICATED_PUNCH_TIMEOUT")

    async def mtu(self):
        result = []
        for size in (512, 900, 1200, 1400):
            hits, errors = await self.mtu_trials(size)
            item = {"udp_payload_bytes": size, "confirmed": hits, "trials": 2, "errors": errors}
            if not hits and size > 512:
                small_hits, _ = await self.mtu_trials(512)
                item["small_payload_recheck"] = small_hits
                item["classification"] = (
                    "suspected-size-blackhole" if small_hits else "path-loss-inconclusive"
                )
            result.append(item)
        self.owner.log.event(
            "mtu.directional",
            attempt=self.attempt,
            remote=self.remote,
            results=result,
            conclusion="size-specific-evidence-not-certified-pmtu",
            kernel_error=self.last_error,
            probe_timeout_seconds=self.mtu_timeout(),
        )
        return result

    def mtu_timeout(self):
        # A valid challenge can include retransmission time; err on the side of waiting.
        rtt = max(self.probe_rtt, self.auth.get(self.remote, {}).get("challenge_rtt", 0))
        return min(4.0, max(0.6, rtt * 2 + 0.2))

    async def mtu_trials(self, size):
        hits, errors = 0, []
        timeout = self.mtu_timeout()
        for _ in range(2):
            pid = secrets.token_hex(8)
            future = asyncio.get_running_loop().create_future()
            self.probes[pid] = future
            try:
                started = time.monotonic()
                self.send(
                    self.remote,
                    self.frame(
                        "mtu", target=self.remote, size=size, probe=pid, echo=self.auth[self.remote]["nonce"]
                    ),
                )
                returned = await asyncio.wait_for(future, timeout)
                hits += returned == size
                if returned == size:
                    self.probe_rtt = time.monotonic() - started
                    timeout = self.mtu_timeout()
            except (TimeoutError, OSError) as exc:
                errors.append(type(exc).__name__)
                if isinstance(exc, TimeoutError):
                    timeout = min(4.0, timeout * 2)
            finally:
                self.probes.pop(pid, None)
            await asyncio.sleep(0.05)
        return hits, errors

    async def start_quic(self, size=1200):
        if size not in (1200, 1400):
            raise ValueError("QUIC_PAYLOAD_MUST_BE_1200_OR_1400_NEVER_BELOW_1200")
        self.quic = QuicDriver(self, client=self.spec["initiator"], size=size)
        await self.quic.start()
        return self.quic.path

    async def hairpin(self, timeout):
        candidates = [ep for ep in self.candidates if ipaddress.ip_address(ep[0]).is_global]
        if not candidates and self.owner.loopback:
            candidates = self.candidates[:1]
        if not candidates:
            raise ValueError("NO_MAPPED_ENDPOINT_FOR_HAIRPIN")
        results = []
        for target in candidates[:4]:
            nonce = secrets.token_hex(16)
            future = asyncio.get_running_loop().create_future()
            self.hairpin_pending[nonce] = future
            start = time.monotonic()
            try:
                body = self.owner.identity.sign({"kind": "hairpin", "v": 1, "pair": self.pair,
                    "attempt": self.attempt, "from": self.local_id, "to": self.local_id, "nonce": nonce, "size": 512})
                self.send(tuple(target), body)
                source = await asyncio.wait_for(future, min(2, timeout))
                results.append({"target": target, "source": source, "confirmed": True,
                                "elapsed_ms": (time.monotonic() - start) * 1000})
            except TimeoutError:
                results.append({"target": target, "confirmed": False, "reason": "TIMEOUT_INCONCLUSIVE"})
            finally:
                self.hairpin_pending.pop(nonce, None)
        evidence = {"confirmed": any(item["confirmed"] for item in results), "results": results,
                    "scope": "self-mapping-loopback;not-peer-connectivity;not-a-NAT-type-proof"}
        self.owner.log.event("nat.hairpin", attempt=self.attempt, **evidence)
        return evidence

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.quic:
            await self.quic.close()
        if self.transport:
            self.transport.close()
        for future, _ in self.stun_pending.values():
            if not future.done():
                future.cancel()


class QuicDriver:
    """aioquic public sans-I/O API, reusing the authenticated hole-punch socket."""

    def __init__(self, udp, *, client, size):
        self.udp, self.owner, self.client = udp, udp.owner, client
        # Promote only authenticated QUIC sockets; do not enlarge every exploratory punch socket.
        self.socket_buffers = {}
        sock = udp.transport.get_extra_info("socket")
        if sock is not None:
            for name, option in (("receive", socket.SO_RCVBUF), ("send", socket.SO_SNDBUF)):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, option, 4 * 1024 * 1024)
                    self.socket_buffers[name + "_bytes"] = sock.getsockopt(socket.SOL_SOCKET, option)
                except OSError as exc:
                    self.owner.log.event("quic.buffer_tuning_failed", str(exc), "WARNING",
                                         attempt=udp.attempt, direction=name)
        self.configuration = QuicConfiguration(
            is_client=client,
            alpn_protocols=[ALPN],
            server_name="p2p-peer",
            verify_mode=ssl.CERT_REQUIRED,
            cadata=self.owner.peer["certificate"].encode(),
            idle_timeout=30,
            congestion_control_algorithm=udp.spec.get("quic_congestion_control", "reno"),
            max_datagram_size=size,
            max_data=32 * 1024 * 1024,
            max_stream_data=16 * 1024 * 1024,
            certificate=self.owner.identity.certificate,
            private_key=self.owner.identity.tls_key,
        )
        self.connection = None
        self.path = Path(
            self.owner, udp.attempt, "quic", ipaddress.ip_address(udp.host).version, self.send, self.close
        )
        self.buffers = {}
        self.bench_streams = {}
        self.receiving_bench_streams = {}
        self.queue = asyncio.PriorityQueue(maxsize=160)
        self.queue_serial = 0
        self.flush_handle = None
        self.timer = QuicTimer(self.tick, precise=udp.spec.get("quic_precise_timer", True))
        self.counters = {k: 0 for k in (
            "tx_datagrams", "rx_datagrams", "flushes", "timer_fires", "timer_late_seconds",
            "pacing_fires", "pacing_requested_seconds", "pacing_late_seconds",
        )}
        self.pacing_deadline = False
        self.timer_requested = 0.0
        self.timer_overdue = 0.0
        self.path.transport_diagnostics = self.diagnostics
        self.path.abort_benchmark = self.abort_benchmark
        self.path.finish_benchmark = lambda bid: self.bench_streams.pop(bid, None)
        self.owner.log.event("quic.runtime", attempt=udp.attempt, timer_backend=self.timer.backend,
                             backend_version=aioquic_version, socket_buffers=self.socket_buffers,
                             requested_socket_buffer_bytes=4 * 1024 * 1024,
                             scope="per-socket;no-system-sysctl-change")
        self.closed = False
        self.sent_app = 0
        self.processed_app = 0
        self.worker = asyncio.create_task(self.consume(), name=f"quic-receive:{udp.attempt}")

    async def start(self):
        if self.client:
            self.connection = QuicConnection(configuration=self.configuration)
            self.connection.connect(sockaddr(self.udp.remote), now=time.monotonic())
            self.transmit()
        await self.path.wait_ready(self.owner.timeout + 8)

    def receive(self, data, addr):
        try:
            if self.closed:
                return
            if self.connection is None:
                header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                if header.packet_type != QuicPacketType.INITIAL or len(data) < 1200:
                    return
                self.connection = QuicConnection(
                    configuration=self.configuration,
                    original_destination_connection_id=header.destination_cid,
                )
            self.connection.receive_datagram(data, addr, now=time.monotonic())
            self.counters["rx_datagrams"] += 1
            self.events()
            self.request_transmit()
        except Exception as exc:
            self.owner.log.exception("quic.receive_failed", exc, attempt=self.udp.attempt)
            asyncio.create_task(self.path.close("QUIC_PROTOCOL_FAILED"))

    def events(self):
        while self.connection:
            event = self.connection.next_event()
            if event is None:
                break
            if isinstance(event, HandshakeCompleted):
                self.owner.log.event(
                    "quic.tls_completed",
                    attempt=self.udp.attempt,
                    alpn=event.alpn_protocol,
                    authentication="trusted-peer-server-cert-and-mutual-app-signatures",
                )
                asyncio.create_task(self.path.start())
            elif isinstance(event, StreamDataReceived):
                dedicated = event.stream_id % 4 == (3 if self.client else 2)
                if dedicated and BENCH_STREAM_CAPABILITY not in self.path.remote_capabilities:
                    raise ValueError("QUIC_BENCH_STREAM_NOT_NEGOTIATED")
                if not dedicated and event.stream_id not in (0, 1, 4, 5):
                    raise ValueError("QUIC_UNEXPECTED_STREAM")
                buf = self.buffers.get(event.stream_id)
                if buf is None:
                    buf = self.buffers[event.stream_id] = bytearray()
                buf.extend(event.data)
                for frame in extract_frames(buf):
                    if dedicated:
                        bid = self.receiving_bench_streams.get(event.stream_id)
                        if bid is None:
                            if frame.get("kind") != "bench_start" or len(self.receiving_bench_streams) >= 4:
                                raise ValueError("QUIC_BENCH_STREAM_START_REQUIRED")
                            bid = self.receiving_bench_streams[event.stream_id] = frame.get("id")
                        if frame.get("id") != bid or frame.get("kind") not in ("bench_start", "bench_chunk", "bench_end"):
                            raise ValueError("QUIC_BENCH_STREAM_CONTEXT")
                    self.enqueue(frame)
                if event.end_stream:
                    if dedicated:
                        if buf:
                            raise ValueError("QUIC_BENCH_STREAM_TRUNCATED")
                        self.buffers.pop(event.stream_id, None)
                        self.receiving_bench_streams.pop(event.stream_id, None)
                    else:
                        asyncio.create_task(self.path.close("QUIC_STREAM_ENDED"))
            elif isinstance(event, StreamReset):
                self.buffers.pop(event.stream_id, None)
                bid = self.receiving_bench_streams.pop(event.stream_id, None)
                if bid is not None:
                    self.enqueue({"kind": "bench_cancel", "id": bid})
                elif event.stream_id in (0, 1, 4, 5):
                    asyncio.create_task(self.path.close("QUIC_STREAM_RESET"))
            elif isinstance(event, ConnectionTerminated):
                self.owner.log.event(
                    "quic.terminated",
                    attempt=self.udp.attempt,
                    code=event.error_code,
                    reason=event.reason_phrase,
                )
                asyncio.create_task(self.path.close("QUIC_TERMINATED"))

    def request_transmit(self):
        if not self.closed and self.flush_handle is None:
            self.flush_handle = asyncio.get_running_loop().call_soon(self.flush)

    def enqueue(self, frame):
        kind = frame.get("kind", "")
        control = (kind in ("hello", "hello_ack", "ping", "pong", "bench_ready", "bench_ack",
                            "bench_result", "bench_error", "bench_cancel")
                   or kind.startswith(("chat", "reverse_speed")))
        if not control and self.queue.qsize() >= 128:
            raise asyncio.QueueFull
        self.queue_serial += 1
        self.queue.put_nowait((0 if control else 1, self.queue_serial, frame))

    def abort_benchmark(self, bid):
        stream = self.bench_streams.pop(bid, None)
        if stream is not None and self.connection and not self.closed:
            self.connection.reset_stream(stream, error_code=0x100)
            self.request_transmit()
            self.owner.log.event("quic.benchmark_stream_reset", attempt=self.udp.attempt,
                                 benchmark=bid, stream=stream, reason="BENCH_ABORTED")

    def flush(self):
        try:
            self.transmit()
        except Exception as exc:
            self.owner.log.exception("quic.transmit_failed", exc, attempt=self.udp.attempt)
            asyncio.create_task(self.path.close("QUIC_TRANSMIT_FAILED"))

    def diagnostics(self):
        result = {**self.counters, "backend": "aioquic", "backend_version": aioquic_version,
                  "timer_backend": self.timer.backend,
                  "socket_buffers": self.socket_buffers,
                  "datagram_bytes": self.configuration.max_datagram_size,
                  "congestion_control": self.configuration.congestion_control_algorithm}
        result.update(benchmark_streams=len(self.bench_streams), receive_queue_frames=self.queue.qsize())
        # Read-only, version-guarded adapter. No private congestion/pacing state is modified.
        loss = getattr(self.connection, "_loss", None)
        cc = getattr(loss, "_cc", None)
        rtt = getattr(loss, "_rtt_smoothed", 0)
        cwnd = getattr(loss, "congestion_window", 0)
        if rtt and cwnd:
            result.update(cwnd_bytes=cwnd, rtt_ms=rtt * 1000,
                          cwnd_rtt_mbps=cwnd * 8 / rtt / 1e6,
                          inflight_fraction=getattr(loss, "bytes_in_flight", 0) / cwnd)
        recovery = getattr(cc, "_congestion_recovery_start_time", None)
        if recovery is not None:
            result["congestion_recovery_time"] = recovery
        try:
            connection_credit = self.connection._remote_max_data - self.connection._remote_max_data_used
            stream_credits = [
                stream.max_stream_data_remote - stream.sender.highest_offset
                for stream_id, stream in self.connection._streams.items()
                if stream_id in (4, 5, *self.bench_streams.values())
            ]
            if stream_credits:
                result["send_flow_control_remaining_bytes"] = max(
                    0, min(connection_credit, *stream_credits)
                )
                result["send_flow_control_blocked_streams"] = sum(
                    bool(stream.is_blocked)
                    for stream_id, stream in self.connection._streams.items()
                    if stream_id in (4, 5, *self.bench_streams.values())
                )
        except (AttributeError, TypeError):
            pass
        return result

    def transmit(self):
        if self.flush_handle:
            self.flush_handle.cancel()
            self.flush_handle = None
        if self.closed or not self.connection:
            return
        now = time.monotonic()
        self.counters["flushes"] += 1
        for data, addr in self.connection.datagrams_to_send(now):
            self.udp.transport.sendto(data, addr)
            self.counters["tx_datagrams"] += 1
        timer = self.connection.get_timer()
        if timer != self.timer.deadline:
            # Diagnostic only: identify pacing deadlines without enabling expensive full qlog.
            pacing_at = getattr(self.connection, "_pacing_at", None)
            self.pacing_deadline = timer is not None and timer == pacing_at
            armed_at = time.monotonic()
            self.timer_requested = max(0, timer - armed_at) if timer is not None else 0
            self.timer_overdue = max(0, armed_at - timer) if timer is not None else 0
        self.timer.arm(timer)

    def tick(self, deadline):
        if self.closed or not self.connection:
            return
        try:
            # Packet generation may itself outlast the pacing interval; do not blame timer precision for that.
            late = max(0, time.monotonic() - deadline - self.timer_overdue)
            self.counters["timer_fires"] += 1
            self.counters["timer_late_seconds"] += late
            if self.pacing_deadline:
                self.counters["pacing_fires"] += 1
                self.counters["pacing_requested_seconds"] += self.timer_requested
                self.counters["pacing_late_seconds"] += late
            self.connection.handle_timer(time.monotonic())
            self.events()
            self.transmit()
        except Exception as exc:
            self.owner.log.exception("quic.timer_failed", exc, attempt=self.udp.attempt)
            asyncio.create_task(self.path.close("QUIC_TIMER_FAILED"))

    async def consume(self):
        try:
            while not self.closed:
                _, _, frame = await self.queue.get()
                await self.path.receive(frame)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("quic.application_failed", exc, attempt=self.udp.attempt)
            await self.path.close("QUIC_APPLICATION_FAILED")

    async def send(self, body):
        if self.closed or not self.connection:
            raise ConnectionError("QUIC_CLOSED")
        data = encode_frame(body)
        kind = body["kind"]
        dedicated = kind in ("bench_start", "bench_chunk", "bench_end") and \
            BENCH_STREAM_CAPABILITY in self.path.remote_capabilities
        if dedicated:
            bid = body["id"]
            stream = self.bench_streams.get(bid)
            if stream is None:
                if kind != "bench_start":
                    raise ValueError("QUIC_BENCH_STREAM_START_REQUIRED")
                stream = self.connection.get_next_available_stream_id(is_unidirectional=True)
                self.bench_streams[bid] = stream
            self.connection.send_stream_data(stream, data, end_stream=kind == "bench_end")
        else:
            bulk = kind in ("bench_start", "bench_chunk", "bench_end", "file_chunk")
            stream = (4 if bulk else 0) + (0 if self.client else 1)
            self.connection.send_stream_data(stream, data)
        self.request_transmit()
        # Yield once per bounded batch, not once per UDP-sized packet or control frame.
        self.sent_app += len(data)
        if self.sent_app >= 256 * 1024:
            self.sent_app = 0
            await asyncio.sleep(0)

    async def close(self):
        if self.closed:
            return
        try:
            if self.connection:
                self.connection.close()
                self.transmit()
        except Exception as exc:
            self.owner.log.exception("quic.close_failed", exc, attempt=self.udp.attempt)
        self.closed = True
        self.timer.close()
        if self.flush_handle:
            self.flush_handle.cancel()
            self.flush_handle = None
        if self.worker is not asyncio.current_task():
            self.worker.cancel()
            await asyncio.gather(self.worker, return_exceptions=True)
