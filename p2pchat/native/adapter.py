"""Async direct-only transport adapter; all remote endpoints come from paired signaling.

No discovery, TURN, fallback relaying, automatic gateway changes or traffic benchmarks.
The caller MUST authenticate signaling before calling signal(). UDP is a probe only.
"""
import asyncio
import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import ssl
import struct
import sys
import tempfile
import time
import urllib.parse
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

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
from .stun import canonical_endpoint, socket_address, udp_unreachable, receive_udp_retry

MAX_FRAME = 65536
MAX_WIRE = 100000
TERMINAL = {"closed", "failed", "timeout", "unsupported"}
METHODS = ("udp-probe", "quic", "tcp", "tcp-simopen", "upnp", "pcp", "natpmp")
# Gateway mapping is an explicit opt-in *action* (open a port), never a data path:
# it cannot carry messages and must be requested by the operator, not by connecting.
GATEWAY_METHODS = ("upnp", "pcp", "natpmp")
ROUTE_TABLE_V4 = "/proc/net/route"


def gateway_platform_capability(platform=None, route_path=ROUTE_TABLE_V4):
    """按平台如实报告网关放行能力；不假装不可用，也不默认声称可用。

    只有 Linux 有可只读核对的本机路由表（gateway.GatewayPolicy.validate 依赖它）。
    其它平台我们不认识的转发规则可能让"网关"变成任意地址，因此明确报不支持。
    """
    platform = platform or sys.platform
    if not platform.startswith("linux"):
        return {"status": "unsupported", "reason": "PLATFORM_VALIDATION_UNAVAILABLE", "platform": platform}
    if not os.path.exists(route_path):
        return {"status": "unsupported", "reason": "NO_LOCAL_ROUTING_TABLE", "platform": platform}
    return {"status": "available", "reason": "EXPLICIT_OPT_IN_REQUIRED", "platform": platform}


def default_gateway_v4(route_text=None):
    """只读解析 /proc/net/route 的默认网关；没有任何写操作。"""
    text = route_text
    if text is None:
        try:
            text = Path(ROUTE_TABLE_V4).read_text()
        except OSError:
            return None
    for row in text.splitlines()[1:]:
        fields = row.split()
        if len(fields) > 3 and fields[1] == "00000000" and int(fields[3], 16) & 2:
            try:
                return str(ipaddress.IPv4Address(bytes.fromhex(fields[2])[::-1]))
            except ValueError:
                return None
    return None


async def discover_upnp_control(gateway, timeout=2.0):
    """有界 SSDP 搜索 IGD 并返回 (control_url, service)；只接受网关自己地址上的控制 URL。

    只发标准 UPnP 组播地址/端口，超时即放弃；不扫描网段，不重试放大。
    """
    import aiohttp

    targets = ("urn:schemas-upnp-org:device:InternetGatewayDevice:1",
               "urn:schemas-upnp-org:service:WANIPConnection:1",
               "urn:schemas-upnp-org:service:WANPPPConnection:1")
    template = ("M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\nMX: 1\r\nST: {st}\r\n\r\n')
    locations = []
    for st in targets:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.bind(("", 0))
            loop = asyncio.get_running_loop()
            await loop.sock_sendto(sock, template.format(st=st).encode(), ("239.255.255.250", 1900))
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                try:
                    reply, _ = await asyncio.wait_for(receive_udp_retry(sock, 4096), deadline - time.monotonic())
                except asyncio.TimeoutError:
                    break
                except (OSError, ValueError):
                    continue
                for line in reply.decode("utf-8", "replace").splitlines():
                    if line.lower().startswith("location:"):
                        locations.append(line.split(":", 1)[1].strip())
        finally:
            sock.close()
        if locations:
            break
    from .gateway import UPnP

    for location in locations:
        try:
            url = urllib.parse.urlsplit(location)
            if url.scheme != "http" or url.hostname != gateway:
                continue
            async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=min(3.0, timeout)), trust_env=False) as session:
                async with session.get(location, allow_redirects=False) as response:
                    raw = await response.content.read(65537)
                    if len(raw) > 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                        continue
                    root = ET.fromstring(raw)
                    base = location if location.endswith("/") else location.rsplit("/", 1)[0] + "/"
                    for service in root.iter():
                        if not service.tag.endswith("}service") and service.tag != "service":
                            continue
                        found = {child.tag.split("}")[-1]: (child.text or "").strip() for child in service}
                        if found.get("serviceType") in UPnP.SERVICES and found.get("controlURL"):
                            return urllib.parse.urljoin(base, found["controlURL"]), found["serviceType"]
        except Exception:
            continue
    raise TimeoutError("UPNP_CONTROL_NOT_FOUND")


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
    return canonical_endpoint((c["address"], c["port"]))


# --------------------------------------------------------------- port prediction
NAT_SAMPLES_TYPE = "nat-samples"
MAX_PREDICTION_SAMPLES = 64
MAX_PREDICTION_NONCES = 64
PREDICTION_PROBE_BUDGET = 2  # bounded probes per predicted port
PREDICTION_HEX48 = re.compile("[0-9a-f]{48}")
PREDICTION_HEX64 = re.compile("[0-9a-f]{64}")
PREDICTION_PRIORITY_NOTE = ("优先 IPv6 直连，其次在自家路由器/网关上显式放行，最后才是端口预测；"
                            "对称 NAT 下命中概率有限，失败属正常结果。")
PREDICTION_FAILURE_STATES = ("NO_AUTHENTICATED_REPLY", "REPLIES_REJECTED", "DEADLINE_REACHED", "SEND_FAILED")


def prediction_samples_payload(samples):
    """Wire form of observed allocation samples. Only ports and observation points.

    The sender's public mapped endpoints never travel: the peer needs the port
    sequence, not where those ports were observed.
    """
    payload = []
    for sample in list(samples)[:MAX_PREDICTION_SAMPLES]:
        payload.append({"sequence": int(sample.sequence), "localPort": int(sample.local_port),
                        "destination": [sample.destination[0], int(sample.destination[1])],
                        "mappedPort": int(sample.mapped_port)})
    return payload


def samples_digest(payload_samples):
    return hashlib.sha256(packed(payload_samples)).hexdigest()


def samples_proof(key, room, connection, attempt, sender, receiver, nonce, digest):
    """Room-key HMAC over the sample payload; the server never sees the key."""
    values = ["p2pobs-v1-samples", room, connection, attempt, sender, receiver, nonce, digest]
    return hmac.new(key, packed(values), hashlib.sha256).hexdigest()


def validate_samples_message(payload):
    """Strict local validation of a peer's samples; server-side schema is never trusted."""
    if not isinstance(payload, dict):
        raise ValueError("INVALID_SAMPLES")
    required = {"v", "type", "connectionId", "attemptId", "mechanism", "nonce", "proof", "samples"}
    if not required <= set(payload) or set(payload) - required - {"from", "profile", "to"}:
        raise ValueError("INVALID_SAMPLES")
    if payload["v"] != 1 or payload["type"] != NAT_SAMPLES_TYPE:
        raise ValueError("INVALID_SAMPLES")
    if payload["mechanism"] not in {"udp-probe", "quic"}:
        raise ValueError("INVALID_SAMPLES")
    if not isinstance(payload["nonce"], str) or not PREDICTION_HEX48.fullmatch(payload["nonce"]):
        raise ValueError("INVALID_SAMPLES")
    if not isinstance(payload["proof"], str) or not PREDICTION_HEX64.fullmatch(payload["proof"]):
        raise ValueError("INVALID_SAMPLES")
    samples = payload["samples"]
    if not isinstance(samples, list) or not 1 <= len(samples) <= MAX_PREDICTION_SAMPLES:
        raise ValueError("SAMPLES_LIMIT")
    from .port_prediction import AllocationSample

    result = []
    for item in samples:
        if not isinstance(item, dict) or set(item) != {"sequence", "localPort", "destination", "mappedPort"}:
            raise ValueError("INVALID_SAMPLES")
        sequence, local_port, mapped_port = item["sequence"], item["localPort"], item["mappedPort"]
        if any(type(value) is not int or isinstance(value, bool) for value in (sequence, local_port, mapped_port)):
            raise ValueError("INVALID_SAMPLES")
        if not 0 <= sequence <= 4095 or not 1 <= local_port <= 65535 or not 1 <= mapped_port <= 65535:
            raise ValueError("INVALID_SAMPLES")
        destination = item["destination"]
        if not isinstance(destination, (list, tuple)) or len(destination) != 2:
            raise ValueError("INVALID_SAMPLES")
        host, port = canonical_endpoint((destination[0], destination[1]))
        result.append(AllocationSample(sequence, local_port, (host, port), mapped_port))
    return result


@dataclass
class Budget:
    attempts: int = 16
    candidates: int = 64
    queued_bytes: int = 512 * 1024
    # Bounded wait for ACK-driven drain of the QUIC retransmit buffer. A momentary
    # full buffer must not fail a healthy burst (Windows ACK cadence is slower than
    # Linux loopback); a peer that never drains still fails loudly after this bound.
    drain_timeout: float = 5.0


# aioquic keeps retransmittable copies, so its buffer is larger than the payload.
QUIC_RETRANSMIT_FACTOR = 1.4
QUIC_DRAIN_INTERVAL = 0.005


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
    def __init__(self, bind_host="127.0.0.1", budget=None, stun_server=None, prediction=None):
        self.bind_host = bind_host
        self.stun_server = stun_server  # explicit trusted configuration, never IPC-specified arbitrary scans
        # Port prediction is OFF unless the operator enables it AND names at least
        # two observation points; those points are the only extra destinations ever
        # contacted. Never discovered, never a third-party default.
        self.prediction = dict(prediction or {})
        self.budget = budget or Budget()
        self.attempts = {}
        self.handlers = []
        self.seen = set()
        self.gateway_sessions = {}  # protocol -> (service, lease); explicit opt-in only

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
        gateway = gateway_platform_capability()
        methods = []
        for m in METHODS:
            if m in GATEWAY_METHODS:
                # 如实报告：Linux 有可核对的本机路由表时才 available，其它平台明确不支持。
                # 两种情况下都要求用户显式同意（requiresExplicitConsent），且都不能传消息。
                methods.append({"mechanism": m, "status": gateway["status"],
                                "canMessage": False, "requiresExplicitConsent": True,
                                "reason": gateway["reason"],
                                "limits": {"maxFrameBytes": MAX_FRAME, "benchmark": False,
                                           "independentBenchmark": False, "maxMappings": 8,
                                           "maxLifetimeSeconds": 7200, "maxAttempts": self.budget.attempts}})
                continue
            methods.append({"mechanism": m, "status": "available",
                            "canMessage": m in {"quic", "tcp", "tcp-simopen"},
                            "requiresExplicitConsent": False,
                            "reason": "PROBE_ONLY" if m == "udp-probe" else "EXPERIMENTAL_PLATFORM_UNVERIFIED",
                            "limits": {"maxFrameBytes": MAX_FRAME, "benchmark": m == "quic",
                                       "independentBenchmark": m == "quic", "maxAttempts": self.budget.attempts}})
        return {"v": 1, "methods": methods, "prediction": self.prediction_capability()}

    def prediction_capability(self):
        """Honest report: default off, needs >=2 explicit observation points, symmetric only."""
        from .port_prediction import PredictionLimits

        config = self.prediction or {}
        enabled = bool(config.get("enabled"))
        points = []
        for point in config.get("points") or ():
            try:
                points.append(canonical_endpoint(point))
            except (ValueError, TypeError):
                continue
        if not enabled:
            status, reason = "disabled", "PREDICTION_DISABLED"
        elif len(set(points)) < 2:
            status, reason = "unavailable", "OBSERVATION_POINTS_REQUIRED"
        else:
            status, reason = "available", "SYMMETRIC_ONLY"
        limits = PredictionLimits(**{key: value for key, value in (config.get("limits") or {}).items()
                                     if key in PredictionLimits.__dataclass_fields__}).validate()
        return {"v": 1, "status": status, "enabled": enabled, "reason": reason,
                "observationPoints": len(set(points)), "requiresExplicitConsent": True,
                "limits": {"maxCandidates": limits.max_candidates, "maxSpan": limits.max_span,
                           "probesPerCandidate": PREDICTION_PROBE_BUDGET,
                           "totalTimeoutSeconds": limits.total_timeout},
                "priority": ["ipv6-direct", "gateway-optin", "port-prediction"],
                "hitRateNote": PREDICTION_PRIORITY_NOTE,
                "failureStates": list(PREDICTION_FAILURE_STATES)}

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

    async def prediction_signal(self, params):
        """Peer's authenticated allocation samples (relayed as a nat-samples frame)."""
        attempt = self.attempts.get(params.get("attemptId"))
        if attempt is None:
            raise ValueError("UNKNOWN_ATTEMPT")
        if params.get("connectionId") != attempt.connection or params.get("from") != attempt.peer:
            raise ValueError("SIGNAL_IDENTITY_MISMATCH")
        await attempt.prediction_signal(params)

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
        await self.gateway_release_all()

    # ------------------------------------------------------------ gateway opt-in
    def gateway_capability(self, platform=None):
        """如实的能力报告：平台能不能核对 + 默认网关 + 必须显式同意（默认关闭）。"""
        support = gateway_platform_capability(platform)
        gateway = None
        if support["status"] == "available":
            gateway = default_gateway_v4()
            if gateway is None:
                support = {"status": "unsupported", "reason": "NO_DEFAULT_GATEWAY", "platform": support["platform"]}
        return {"v": 1, "status": support["status"], "reason": support["reason"], "platform": support["platform"],
                "gateway": gateway, "consentRequired": True, "mockLoopbackAllowed": False,
                "mechanisms": ["pcp", "natpmp", "upnp", "upnp-pinhole"],
                "limits": {"maxMappings": 8, "maxLifetimeSeconds": 7200},
                "note": "只有操作者点同意之后才会向路由器请求；默认不做任何映射，也不在启动/连接时偷偷映射。"}

    def _gateway_policy(self, params):
        from .gateway import GatewayPolicy

        support = self.gateway_capability()
        if support["status"] != "available" and not params.get("mockLoopback"):
            raise NotImplementedError(support["reason"])
        gateway = params.get("gateway") or support["gateway"]
        if not gateway:
            raise ValueError("NO_DEFAULT_GATEWAY")
        policy = GatewayPolicy(gateway=gateway, local_address=params.get("localAddress") or self.bind_host,
                               enabled=True, mock_loopback=bool(params.get("mockLoopback")),
                               port=int(params.get("gatewayPort", 5351)),
                               timeout=float(params.get("timeoutSeconds", 1.0)))
        policy.validate()
        return policy

    async def gateway_map(self, params):
        """唯一生产入口：显式同意后才向路由器请求一次映射。

        没有 ``consent=True`` 时不会创建任何 socket（直接 PermissionError）。
        映射只有在外部对端验证通过后才会被认定为已建立（gateway.Gateway.verify）。
        """
        if params.get("consent") is not True:
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        from .gateway import PCP, NATPMP, UPnP

        policy = self._gateway_policy(params)
        internal = int(params["internalPort"])
        external = int(params.get("externalPort", 0))
        lifetime = int(params.get("lifetimeSeconds", 120))
        validator = params.get("validator")
        failures = {}
        for name in list(params.get("protocols") or ("pcp", "natpmp", "upnp")):
            try:
                if name == "pcp":
                    service = PCP(policy)
                elif name == "natpmp":
                    service = NATPMP(policy)
                elif name == "upnp":
                    control, stype = await discover_upnp_control(policy.gateway, timeout=max(1.0, policy.timeout * 2))
                    service = UPnP(policy, control, stype)
                else:
                    raise ValueError("UNSUPPORTED_GATEWAY_PROTOCOL")
                lease = await service.map(internal, external, lifetime, validator=validator)
                self.gateway_sessions[name] = (service, lease)
                return {"protocol": name, "leaseProtocol": lease.protocol, "internalPort": lease.internal_port,
                        "externalPort": lease.external_port, "externalAddress": lease.external_address,
                        "lifetimeSeconds": lease.lifetime, "verified": lease.verified}
            except (TimeoutError, OSError, ValueError, NotImplementedError, PermissionError) as exc:
                failures[name] = str(exc) or type(exc).__name__
        raise RuntimeError("GATEWAY_MAPPING_FAILED:" + ",".join(f"{k}={v}" for k, v in sorted(failures.items())))

    async def gateway_pinhole(self, params):
        """IPv6 防火墙 pinhole：同样只在显式同意后请求。"""
        if params.get("consent") is not True:
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        from .gateway import UPnP

        policy = self._gateway_policy(params)
        control, stype = await discover_upnp_control(policy.gateway, timeout=max(1.0, policy.timeout * 2))
        service = UPnP(policy, control, stype)
        lease = await service.pinhole(int(params["internalPort"]), params["remoteAddress"],
                                      int(params["remotePort"]), int(params.get("lifetimeSeconds", 120)),
                                      validator=params.get("validator"))
        self.gateway_sessions["upnp-pinhole"] = (service, lease)
        return {"protocol": "upnp-pinhole", "internalPort": lease.internal_port,
                "remoteAddress": str(params["remoteAddress"]), "remotePort": int(params["remotePort"]),
                "lifetimeSeconds": lease.lifetime, "verified": lease.verified}

    async def gateway_renew(self, params):
        if params.get("consent") is not True:
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        name = params.get("protocol") or next(iter(self.gateway_sessions), None)
        if name not in self.gateway_sessions:
            raise KeyError("NO_ACTIVE_MAPPING")
        service, lease = self.gateway_sessions[name]
        lease = await service.renew(lease, params.get("validator"), int(params.get("lifetimeSeconds", 120)))
        self.gateway_sessions[name] = (service, lease)
        return {"protocol": name, "internalPort": lease.internal_port, "externalPort": lease.external_port,
                "lifetimeSeconds": lease.lifetime, "verified": lease.verified}

    async def gateway_release(self, params=None):
        """删除映射：按协议逐个释放，返回释放失败的原因（人话可用）。"""
        params = params or {}
        if params.get("consent") is not True and self.gateway_sessions:
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        failures = []
        names = [params["protocol"]] if params.get("protocol") in self.gateway_sessions else list(self.gateway_sessions)
        for name in names:
            service, lease = self.gateway_sessions.pop(name)
            try:
                await service.release(lease)
            except (TimeoutError, OSError, ValueError) as exc:
                failures.append({"protocol": name, "reason": str(exc) or type(exc).__name__})
        return {"released": names, "failures": failures}

    async def gateway_release_all(self):
        if not self.gateway_sessions:
            return {"released": [], "failures": []}
        return await self.gateway_release({"consent": True})


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
        self.socket_error = None
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
        # Symmetric-NAT port prediction (opt-in, udp-probe/quic only, IPv4 only).
        self.prediction_enabled = bool((adapter.prediction or {}).get("enabled")) and \
            p.get("prediction", True) is not False and self.mechanism in {"udp-probe", "quic"}
        self.prediction = {"enabled": self.prediction_enabled,
                           "state": "pending" if self.prediction_enabled else "disabled",
                           "reason": None, "candidates": [], "sends": 0, "localSymmetric": None,
                           "peerSamples": 0, "hit": False}
        self.predicted_targets = {}  # predicted ports are probe targets, never signaled candidates
        self.predicted_sends = {}
        self.predicted_rejected = 0
        self.predicted_hit = False
        self.peer_samples = None
        self.peer_samples_event = asyncio.Event()
        self.prediction_nonces = []

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

    def record_socket_error(self, exc):
        # Bounded numeric diagnostics only: no exception text, endpoints or payload.
        if isinstance(exc, OSError):
            self.socket_error = {"errno": exc.errno, "winerror": getattr(exc, "winerror", None)}

    def stats(self):
        return {"state": self.state, "mechanism": self.mechanism, "profile": self.profile,
                "family": self.candidate["family"] if self.candidate else None,
                "protocol": self.candidate["transport"] if self.candidate else None,
                "localCandidateType": self.candidate["kind"] if self.candidate else None,
                "remoteCandidateType": self.remote_candidate["kind"] if self.remote_candidate else None,
                "localTuple": [self.candidate["address"], self.candidate["port"]] if self.candidate else None,
                "remoteTuple": list(self.remote) if self.remote else None,
                "rttMs": self.rtt, "txBytes": self.tx, "rxBytes": self.rx,
                "goodput": None, "failureCode": self.failure, "socketError": self.socket_error,
                "prediction": {**self.prediction, "candidates": list(self.prediction["candidates"])},
                "observability": {"scope": "native-local-socket", "goodput": "MEASURE_WITH_EXPLICIT_BENCHMARK_ACK"}}

    async def start(self):
        if self.mechanism not in {"udp-probe", "quic", "tcp", "tcp-simopen"}:
            if self.mechanism in GATEWAY_METHODS:
                # 网关放行不是数据通道：它的生产调用点是 NativeAdapter.gateway_map()，
                # 而且必须由用户显式同意。这里既不假装平台不支持，也不默认说可用。
                support = gateway_platform_capability()
                self.transition("unsupported", "GATEWAY_MAPPING_IS_NOT_A_DATA_PATH"
                                if support["status"] == "available" else support["reason"])
            else:
                self.transition("unsupported", "UNSUPPORTED_METHOD")
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
        except (OSError, ValueError) as exc:
            self.record_socket_error(exc)
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
                # Independent unpredictable challenge for this exact observed source.
                # Never reuse the attempt/TCP nonce: a captured complete hello+ACK
                # exchange for another candidate must not answer this challenge.
                # Only nonces (not locally observed tuple strings) enter the MAC,
                # because each side may observe different addresses behind NAT.
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
                if self.prediction_enabled:
                    self.spawn(self.prediction_clock())
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
                    # Predicted ports join the same round-robin, with their own bounded
                    # per-target budget: they are never probed forever.
                    for target in self.predicted_targets:
                        if self.predicted_sends.get(target, 0) < PREDICTION_PROBE_BUDGET:
                            tuples.append(target)
                    # Round-robin trickled candidates, aggregate <=20 probes/sec.
                    for offset in range(len(tuples)):
                        index = (self.probe_cursor + offset) % len(tuples)
                        target = tuples[index]
                        due, delay = self.probe_schedule.get(target, (0, .1))
                        if now >= due:
                            try:
                                await self.raw_udp(b"P2POBS1" + packed(self.candidate_auth[target].frame()), target)
                                if target in self.predicted_sends:
                                    self.predicted_sends[target] = self.predicted_sends.get(target, 0) + 1
                                    self.prediction["sends"] = self.prediction["sends"] + 1
                            except OSError as exc:
                                self.record_socket_error(exc)
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
        except Exception as exc:
            self.record_socket_error(exc)
            await self.fail("UDP_IO_FAILED")

    async def raw_udp(self, data, target=None):
        try:
            await asyncio.get_running_loop().sock_sendto(
                self.sock, data, socket_address(target or self.remote, self.sock.family))
        except OSError as exc:
            self.record_socket_error(exc)
            if not udp_unreachable(exc):
                raise

    # ------------------------------------------------------------ port prediction
    def event_prediction(self):
        self.event("prediction.state", **self.prediction)

    def prediction_message(self, samples):
        """Signed sample-exchange frame for the host to relay; carries no mapped address."""
        payload = prediction_samples_payload(samples)
        if len(payload) < 2:
            return None
        nonce = secrets.token_hex(24)
        digest = samples_digest(payload)
        proof = samples_proof(self.auth.key, self.auth.room, self.connection, self.id,
                              self.auth.local, self.peer, nonce, digest)
        return {"v": 1, "type": NAT_SAMPLES_TYPE, "to": self.peer, "connectionId": self.connection,
                "attemptId": self.id, "mechanism": self.mechanism, "profile": self.profile,
                "nonce": nonce, "proof": proof, "samples": payload}

    async def prediction_signal(self, params):
        """Verify a peer's samples (HMAC + one-time nonce), then keep them locally."""
        if not self.prediction_enabled:
            raise ValueError("PREDICTION_DISABLED")
        if self.state in TERMINAL:
            raise ValueError("ATTEMPT_TERMINAL")
        payload = params
        samples = validate_samples_message(payload)
        if (payload.get("connectionId") != self.connection or payload.get("attemptId") != self.id
                or payload.get("mechanism") != self.mechanism):
            raise ValueError("SAMPLES_IDENTITY_MISMATCH")
        nonce = payload["nonce"]
        if nonce in self.prediction_nonces:
            raise ValueError("SAMPLES_REPLAY")
        expected = samples_proof(self.auth.key, self.auth.room, self.connection, self.id,
                                 self.auth.remote, self.auth.local, nonce, samples_digest(payload["samples"]))
        if not hmac.compare_digest(expected, payload["proof"]):
            raise ValueError("SAMPLES_PROOF_MISMATCH")
        if len(self.prediction_nonces) >= MAX_PREDICTION_NONCES:
            self.prediction_nonces.pop(0)
        self.prediction_nonces.append(nonce)
        self.peer_samples = samples
        self.prediction["peerSamples"] = len(samples)
        self.peer_samples_event.set()
        self.event("diagnostic", code="PREDICTION_SAMPLES_VERIFIED", samples=len(samples))

    def register_predicted_targets(self, candidates):
        """Predicted ports become probe targets at the signaled address only.

        Each target still goes through the same validate_candidate rule set (the
        signaled candidate metadata with the predicted port), so nothing is relaxed
        and no new candidate kind exists.
        """
        if not self.remote or not isinstance(self.remote_candidate, dict):
            return []
        base = self.remote_candidate
        fingerprint = base.get("certificateFingerprint")
        if self.remote_cert is not None:
            fingerprint = self.remote_cert.fingerprint(hashes.SHA256()).hex()
        targets = []
        for port in candidates:
            if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
                continue
            record = {key: value for key, value in base.items()
                      if key in {"id", "family", "transport", "address", "kind", "socketId", "certificateFingerprint"}}
            record["port"] = port
            try:
                endpoint = validate_candidate(record)
            except (ValueError, KeyError, TypeError):
                continue
            if endpoint[0] != self.remote[0]:
                continue  # never leave the signaled peer address
            if endpoint in self.remote_candidates or endpoint in self.predicted_targets:
                continue
            if len(targets) >= self.adapter.budget.candidates:
                break
            self.candidate_auth[endpoint] = Auth(self.auth.room, self.auth.key.decode(), self.connection,
                                                 self.id, self.auth.local, self.peer)
            self.predicted_targets[endpoint] = {
                "id": str(uuid.uuid4()), "family": base["family"], "transport": base["transport"],
                "address": endpoint[0], "port": endpoint[1], "kind": "predicted-port",
                "socketId": base["socketId"], "certificateFingerprint": fingerprint, "predicted": True}
            targets.append(endpoint)
        return targets

    async def prediction_clock(self):
        config = self.adapter.prediction or {}
        try:
            if not self.candidate or self.candidate.get("family") != 4:
                self.prediction.update(state="not-applicable", reason="IPV6_NO_NAT_PORT_PREDICTION")
                self.event_prediction()
                return
            points = []
            for point in config.get("points") or ():
                try:
                    points.append(canonical_endpoint(point))
                except (ValueError, TypeError):
                    continue
            if len(set(points)) < 2:
                self.prediction.update(state="unavailable", reason="OBSERVATION_POINTS_REQUIRED")
                self.event_prediction()
                return
            from .nat_behavior import NatProbeConfig, StunObservationPoint
            from .port_prediction import PredictionLimits, collect_samples, infer_allocation, predict_candidates

            limits = PredictionLimits(**{key: value for key, value in (config.get("limits") or {}).items()
                                         if key in PredictionLimits.__dataclass_fields__}).validate()
            probe = NatProbeConfig(self.adapter.bind_host,
                                   tuple(StunObservationPoint(host, port) for host, port in points),
                                   local_ports=int(config.get("localPorts", 2)),
                                   repeats=int(config.get("repeats", 2)),
                                   timeout=float(config.get("timeout", 1.0)))
            self.prediction.update(state="sampling")
            self.event_prediction()
            sampling = await collect_samples(probe)
            self.event("diagnostic", code="PREDICTION_SAMPLING_DONE", symmetric=bool(sampling.symmetric),
                       samples=len(sampling.samples))
            if not sampling.symmetric:
                # Non-symmetric networks get zero extra packets.
                self.prediction.update(state="not-symmetric", reason="NOT_SYMMETRIC_MAPPING_BEHAVIOR",
                                       localSymmetric=False, observedMapping=sampling.profile.mapping)
                self.event_prediction()
                return
            self.prediction.update(localSymmetric=True)
            message = self.prediction_message(sampling.samples)
            if message is None:
                self.prediction.update(state="unpredictable", reason="INSUFFICIENT_ALLOCATION_SAMPLES")
                self.event_prediction()
                return
            self.event("prediction.samples", message=message)
            self.prediction.update(state="waiting-samples")
            self.event_prediction()
            try:
                await asyncio.wait_for(self.peer_samples_event.wait(), min(self.timeout, limits.total_timeout))
            except asyncio.TimeoutError:
                self.prediction.update(state="timeout", reason="PEER_SAMPLES_TIMEOUT")
                self.event_prediction()
                return
            model = infer_allocation(self.peer_samples, limits)
            candidates = predict_candidates(model, limits)
            if not candidates:
                self.prediction.update(state="unpredictable",
                                       reason=model.reason or "ALLOCATION_NOT_EXTRAPOLABLE")
                self.event_prediction()
                return
            targets = self.register_predicted_targets(candidates)
            if not targets:
                self.prediction.update(state="unavailable", reason="NOTHING_TO_PROBE_AT_SIGNALED_ADDRESS")
                self.event_prediction()
                return
            self.prediction.update(state="probing", reason="PROBING_PREDICTED_PORTS",
                                   candidates=[target[1] for target in targets])
            self.event("diagnostic", code="PREDICTION_PROBING_PREDICTED_PORTS", candidates=len(targets))
            self.event_prediction()
            deadline = time.monotonic() + min(self.timeout, limits.total_timeout)
            while time.monotonic() < deadline and self.state not in TERMINAL and not self.predicted_hit:
                await asyncio.sleep(.05)
            if self.predicted_hit:
                self.prediction.update(state="hit", reason="HIT")
            elif self.prediction["sends"] == 0:
                self.prediction.update(state="no-hit", reason="SEND_FAILED")
            elif self.predicted_rejected >= self.prediction["sends"]:
                self.prediction.update(state="no-hit", reason="REPLIES_REJECTED")
            elif time.monotonic() >= deadline:
                self.prediction.update(state="no-hit", reason="DEADLINE_REACHED")
            else:
                self.prediction.update(state="no-hit", reason="NO_AUTHENTICATED_REPLY")
            self.event_prediction()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.record_socket_error(exc)
            self.prediction.update(state="error", reason="PREDICTION_INTERNAL_ERROR")
            self.event_prediction()

    async def receive_udp(self):
        try:
            while self.state not in TERMINAL:
                data, addr = await receive_udp_retry(self.sock, MAX_WIRE)
                try:
                    source = canonical_endpoint(addr, self.sock.family)
                except ValueError:
                    continue
                if source not in self.remote_candidates and source not in self.predicted_targets:
                    continue
                if self.selected and source != self.remote:
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
                                self.remote_candidate = self.remote_candidates.get(source) or self.predicted_targets[source]
                                if source in self.predicted_targets:
                                    # A prediction hit is labelled as such: not an observed
                                    # candidate, and still only usable through the normal flow.
                                    self.predicted_hit = True
                                    self.prediction.update(state="hit", reason="HIT", hit=True)
                                    self.event("prediction.hit", endpoint=list(source),
                                               note="预测端口上收到通过同一 HMAC 认证的对端映射；仍须按既有候选流程使用")
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
                        if source in self.predicted_targets:
                            self.predicted_rejected += 1
                        continue  # unauthenticated packets cannot kill another peer's attempt
                elif self.mechanism == "quic" and self.auth.direct:
                    if not self.quic:
                        if self.role != "answerer":
                            continue
                        header = pull_quic_header(Buffer(data=data), host_cid_length=8)
                        self.init_quic(header.destination_cid)
                    self.quic.receive_datagram(data, source, now=time.monotonic())
                    await self.quic_events()
                    await self.quic_flush()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.record_socket_error(exc)
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
            try:
                target = canonical_endpoint(addr, self.sock.family)
            except ValueError:
                continue
            if target == self.remote:
                await self.raw_udp(data, target)

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
                    try:
                        source = canonical_endpoint(addr, self.sock.family)
                    except ValueError:
                        connected.close()
                        continue
                    if source == self.remote:
                        self.sock.close()
                        self.sock = connected
                        break
                    connected.close()
            else:
                # simultaneous-open: BOTH roles bind+connect, neither listens nor accepts.
                # A refusal/race is explicitly failed, never disguised with a listening fallback.
                await asyncio.wait_for(loop.sock_connect(self.sock, socket_address(self.remote, self.sock.family)), self.timeout)
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
        except (OSError, ValueError, asyncio.IncompleteReadError, asyncio.TimeoutError, ssl.SSLError) as exc:
            self.record_socket_error(exc)
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

    async def quic_pending_bytes(self):
        """Bytes aioquic still holds for retransmission; drops as the peer's ACKs arrive."""
        if not self.quic:
            return 0
        return sum(s.sender._buffer_stop - s.sender._buffer_start for s in self.quic._streams.values())

    async def wait_for_quic_drain(self, needed):
        """Wait (bounded) for ACK-driven drain of the QUIC retransmit buffer.

        Returns as soon as the buffer plus this frame fits the budget. Only a peer
        that keeps not acknowledging reaches the bound, and then this raises
        BACKPRESSURE: nothing is buffered without limit and no timeout is relaxed.
        """
        if not self.quic:
            return
        budget = self.adapter.budget
        deadline = time.monotonic() + max(0.0, float(budget.drain_timeout))
        while True:
            if await self.quic_pending_bytes() + needed <= budget.queued_bytes:
                return
            if time.monotonic() >= deadline:
                raise ValueError("BACKPRESSURE")
            # Yielding is what lets this attempt's UDP task process the peer's ACKs.
            await asyncio.sleep(QUIC_DRAIN_INTERVAL)

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
        # Wait (bounded) for the peer's ACKs to drain it instead of failing instantly:
        # a momentary full buffer used to abort a healthy file/benchmark burst, which is
        # exactly what Windows loopback ACK cadence produced.
        if self.quic:
            await self.wait_for_quic_drain(int(len(data) * QUIC_RETRANSMIT_FACTOR))
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
        # Predicted/observed public endpoints and sample nonces are local private data.
        self.predicted_targets.clear()
        self.predicted_sends.clear()
        self.peer_samples = None
        self.prediction_nonces.clear()
        if hasattr(self, "channel_auth"):
            self.channel_auth.clear()
        self.key = self.cert = self.remote_cert = self.remote_pem = self.quic = None
        self.stream_buffers.clear()

    async def close(self, reason):
        self.transition("closed", reason if reason in {"NETWORK_CHANGED", "SUPERSEDED"} else "USER_CLOSED")
        await self.cleanup()
