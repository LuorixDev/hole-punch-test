"""Same-LAN direct discovery: no signaling server, no relay, no hole punching.

Why this exists
---------------
Two devices on the same Wi-Fi/Ethernet segment can reach each other directly.
They do not need a rendezvous server, a STUN observation, port prediction or a
punch: the peer address is already routable on the link. This module finds those
peers and hands out a *candidate* the existing direct transport can dial. It is
discovery + a local candidate only: it never carries chat, never forwards
another peer's datagram, and never falls back to a relay.

What an announce carries (and nothing else)
-------------------------------------------
``{v, scope, nonce, ts, port, identity, mac}``

* ``scope``  - room scope tag = HMAC(derived room key, "p2pobs-lan-scope-v1:room").
  The raw room name is never sent, and neither is the room key.
* ``nonce``  - one-time 32-byte random value, unique per announce.
* ``ts``     - wall-clock seconds for a bounded freshness window.
* ``port``   - the sender's UDP listen port for the direct connection.
* ``identity`` - sha256 of the sender's ephemeral public key (DER): an identity
  fingerprint, not a certificate and not a secret; the private key never leaves
  the process.
* ``mac``    - HMAC-SHA256 (domain-separated from the signaling handshake) over
  every other field with the room-key-derived LAN key.

No address is ever sent: the peer address is taken from the observed datagram
source. No certificate, no chat, no file, no file name, no user content and no
room key is ever put on the wire or into diagnostics.

Rejection rules (all before a candidate exists)
-----------------------------------------------
unauthenticated/forged MAC, cross-room scope tag, stale nonce/timestamp, replayed
nonce, self announce, over-rate flood, and any source address or port that the
existing candidate validation refuses (unspecified, multicast, link-local,
broadcast, zone-scoped, non-numeric, out-of-range port). The candidate builder
calls the same ``validate_candidate`` the signaling path uses; no rule is
relaxed, and the signaling-side scope rules are untouched.

Bounds (bounded by construction, not by luck)
---------------------------------------------
bounded announce rate, bounded inbound processing rate (global and per source),
bounded reactive responses, bounded tracked sources, peers, seen nonces,
candidates and datagram size, plus saturating integer counters. A flood cannot
grow memory without limit and cannot keep the receiver from serving a real peer
afterwards. ``close()`` is explicit and releases the derived key.

Browsers have no UDP/multicast API
----------------------------------
``lan_capability(runtime="browser")`` reports ``unsupported`` with reason
``NO_UDP_MULTICAST_API`` instead of pretending to work; the same reason is used
when the OS/runtime lacks the IP multicast constants.

Known limitations (NOT_RUN, not bypassed)
-----------------------------------------
* IPv4 only here: an IPv6 peer on a link would be discovered via its link-local
  source (fe80::/10), which the candidate schema rejects, and the candidate
  schema does not negotiate IPv6 interface scopes. That is reported as an
  explicit unsupported reason, never worked around.
* Real two-device same-Wi-Fi discovery/connection is NOT_RUN. On-host loopback
  multicast (``restricted_local=True``) is protocol evidence only and is never
  evidence of a home LAN.
* LAN discovery supplies the endpoint. The connection certificate description
  (needed by the quic/tcp lanes) is still a peer-to-peer control-plane exchange;
  a fully serverless LAN certificate exchange is out of scope for this task.
* The MAC covers only what is on the wire, and no address is trusted from the
  wire, so a captured *fresh* announce replayed on-link from a different source
  address can create a bogus endpoint for that identity within the freshness
  window. The subsequent direct handshake still requires the room key (and, for
  the certificate lanes, the pinned certificate), so this cannot impersonate a
  conversation; it can only waste one attempt. Binding a claim to a source
  address would require trusting sender-supplied addressing, which is refused
  here on purpose.
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from .adapter import validate_candidate
from .auth import packed
from .stun import receive_udp_retry

PROTOCOL = "p2pobs-lan-announce-v1"
KEY_LABEL = b"p2pobs-lan-key-v1"
SCOPE_LABEL = "p2pobs-lan-scope-v1"
GROUP4 = "239.255.42.99"  # administratively scoped (239.0.0.0/8): never routed off-link
DEFAULT_PORT = 41420
MAX_DATAGRAM = 512
MAX_SEND_PER_SECOND = 4
MAX_RESPONSE_PER_SECOND = 4
RESPONSE_COOLDOWN = 2.0
MAX_INBOUND_PER_SECOND = 64
MAX_INBOUND_PER_SOURCE = 16
MAX_SOURCES = 64
MAX_PEERS = 32
MAX_SEEN_NONCES = 256
MAX_REJECTED = 1 << 20
PEER_TTL = 90.0
FRESHNESS = 120.0
ANNOUNCE_FIELDS = {"v", "scope", "nonce", "ts", "port", "identity", "mac"}
REJECTIONS = ("malformed", "scope", "stale", "mac", "replay", "selfAnnounce",
              "rateLimited", "invalidCandidate", "transport")
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")


class LanRejected(ValueError):
    """Stable rejection reason; never carries the rejected bytes."""

    def __init__(self, reason):
        super().__init__(reason)
        self.reason = reason


def derive_key(secret):
    """Room-key -> LAN key. Domain separation: never reuse a signaling MAC key."""
    raw = secret.encode() if isinstance(secret, str) else bytes(secret)
    return hmac.new(raw, KEY_LABEL, hashlib.sha256).digest()


def room_scope(key, room):
    """Keyed room scope tag. Does not reveal the room name to the link."""
    return hmac.new(key, (SCOPE_LABEL + ":" + room).encode(), hashlib.sha256).hexdigest()[:32]


def announce_mac(key, scope, nonce, ts, port, identity):
    body = [PROTOCOL, scope, nonce, str(int(ts)), str(int(port)), identity]
    return hmac.new(key, packed(body), hashlib.sha256).hexdigest()


def build_announce(*, key, scope, nonce, ts, port, identity):
    frame = {"v": 1, "scope": scope, "nonce": nonce, "ts": int(ts), "port": int(port),
             "identity": identity, "mac": announce_mac(key, scope, nonce, ts, port, identity)}
    payload = packed(frame)
    if len(payload) > MAX_DATAGRAM:
        raise ValueError("ANNOUNCE_TOO_LARGE")
    return payload


def parse_announce(payload, *, key, scope, now, freshness=FRESHNESS, max_datagram=MAX_DATAGRAM):
    """Authenticate one announce. Raises LanRejected; returns fields only on success."""
    if not isinstance(payload, (bytes, bytearray)) or len(payload) > max_datagram:
        raise LanRejected("malformed")
    try:
        frame = json.loads(bytes(payload))
    except (ValueError, UnicodeDecodeError):
        raise LanRejected("malformed") from None
    if (not isinstance(frame, dict) or set(frame) != ANNOUNCE_FIELDS or frame.get("v") != 1
            or not isinstance(frame.get("scope"), str) or not HEX32.fullmatch(frame.get("scope") or "")
            or not isinstance(frame.get("nonce"), str) or not HEX64.fullmatch(frame.get("nonce") or "")
            or not isinstance(frame.get("identity"), str) or not HEX64.fullmatch(frame.get("identity") or "")
            or not isinstance(frame.get("mac"), str) or not HEX64.fullmatch(frame.get("mac") or "")
            or type(frame.get("ts")) is not int or type(frame.get("port")) is not int
            or not 1 <= frame["port"] <= 65535):
        raise LanRejected("malformed")
    # Scope is a keyed tag: comparing it first is cheap and never needs the secret key.
    if not hmac.compare_digest(frame["scope"], scope):
        raise LanRejected("scope")
    if abs(now - frame["ts"]) > freshness:
        raise LanRejected("stale")
    expected = announce_mac(key, scope, frame["nonce"], frame["ts"], frame["port"], frame["identity"])
    if not hmac.compare_digest(expected, frame["mac"]):
        raise LanRejected("mac")
    return {"scope": frame["scope"], "nonce": frame["nonce"], "ts": frame["ts"],
            "port": frame["port"], "identity": frame["identity"]}


def lan_socket_id(identity):
    """Stable socket label for a discovered peer; derived from the identity, no secret."""
    return "lan-" + identity[:32]


def lan_candidate(address, port, *, family=4, transport="udp", kind="host",
                  socket_id=None, certificate_fingerprint=None):
    """Build a discovered candidate and push it through the existing validator.

    ``validate_candidate`` is the same function the signaling path uses; a
    discovered endpoint gets no exemption whatsoever.
    """
    candidate = {"id": str(uuid.uuid4()), "family": family, "transport": transport,
                 "address": address, "port": port, "kind": kind}
    if socket_id is not None:
        if not isinstance(socket_id, str) or not 1 <= len(socket_id) <= 100:
            raise ValueError("INVALID_CANDIDATE")
        candidate["socketId"] = socket_id
    if certificate_fingerprint is not None:
        if not isinstance(certificate_fingerprint, str) or not HEX64.fullmatch(certificate_fingerprint):
            raise ValueError("INVALID_CANDIDATE")
        candidate["certificateFingerprint"] = certificate_fingerprint
    validate_candidate(candidate)
    return candidate


def detect_runtime():
    """A browser/Pyodide runtime has no UDP or multicast API; say so, do not pretend."""
    if os.environ.get("P2POBS_RUNTIME") == "browser" or sys.platform in {"emscripten", "wasi"}:
        return "browser"
    return "native"


def multicast_available(sockmod=socket):
    """Real probe: create a UDP socket and join a group on the loopback interface."""
    required = ("AF_INET", "SOCK_DGRAM", "IPPROTO_IP", "IP_ADD_MEMBERSHIP",
                "IP_MULTICAST_IF", "IP_MULTICAST_TTL", "IP_MULTICAST_LOOP")
    if any(not hasattr(sockmod, name) for name in required):
        return False
    probe = None
    try:
        probe = sockmod.socket(sockmod.AF_INET, sockmod.SOCK_DGRAM)
        probe.bind(("127.0.0.1", 0))
        probe.setsockopt(sockmod.IPPROTO_IP, sockmod.IP_ADD_MEMBERSHIP,
                         struct.pack("4s4s", sockmod.inet_aton(GROUP4), sockmod.inet_aton("127.0.0.1")))
        return True
    except (OSError, AttributeError, struct.error):
        return False
    finally:
        if probe is not None:
            probe.close()


def lan_capability(runtime=None, sockmod=socket):
    """Capability surface for the three-screen UI; never claims more than it can do."""
    runtime = runtime or detect_runtime()
    limits = {"maxDatagramBytes": MAX_DATAGRAM, "maxPeers": MAX_PEERS,
              "announcePerSecond": MAX_SEND_PER_SECOND, "responsePerSecond": MAX_RESPONSE_PER_SECOND}
    if runtime != "native":
        return {"mechanism": "lan-direct", "status": "unsupported", "reason": "NO_UDP_MULTICAST_API",
                "runtime": runtime, "canMessage": False, "limits": limits}
    if not multicast_available(sockmod):
        return {"mechanism": "lan-direct", "status": "unsupported", "reason": "NO_UDP_MULTICAST_API",
                "runtime": runtime, "canMessage": False, "limits": limits}
    return {"mechanism": "lan-direct", "status": "available", "reason": None, "runtime": runtime,
            "canMessage": True, "family": 4, "group": GROUP4, "limits": limits,
            "knownLimitation": "IPV4_ONLY_LINK_LOCAL_UNUSABLE"}


@dataclass(frozen=True)
class LanPolicy:
    """Explicit opt-in configuration; disabled by default in the product surface."""
    room: str
    secret: str
    peer_id: str
    listen_port: int
    discovery_port: int = DEFAULT_PORT
    family: int = 4
    group: str | None = None
    interface: str | None = None
    announce_interval: float = 2.0
    enabled: bool = True
    restricted_local: bool = False  # TEST-ONLY loopback mode, never LAN evidence

    def resolved_group(self):
        return self.group or GROUP4

    def validate(self):
        if not self.enabled:
            raise PermissionError("LAN_DISCOVERY_DISABLED")
        if not isinstance(self.room, str) or not 1 <= len(self.room.encode()) <= 64:
            raise ValueError("INVALID_LAN_ROOM")
        if not isinstance(self.secret, str) or not 8 <= len(self.secret.encode()) <= 256:
            raise ValueError("INVALID_LAN_SECRET")
        if not isinstance(self.peer_id, str) or not 1 <= len(self.peer_id) <= 100:
            raise ValueError("INVALID_LAN_PEER")
        if self.family != 4:
            # Not a silent fallback: an IPv6 link would only yield a link-local
            # source, which the candidate rules refuse, and scopes are not negotiated.
            raise NotImplementedError("LAN_IPV6_LINK_LOCAL_UNUSABLE")
        for name in ("listen_port", "discovery_port"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 65535:
                raise ValueError("INVALID_LAN_PORT")
        if not 0.5 <= self.announce_interval <= 60:
            raise ValueError("INVALID_LAN_INTERVAL")
        group = ipaddress.IPv4Address(self.resolved_group())
        if not group.is_multicast or not ipaddress.IPv4Address(group).packed[0] == 239:
            raise ValueError("LAN_GROUP_NOT_LINK_SCOPED")
        if not isinstance(self.interface, str):
            raise ValueError("LAN_INTERFACE_REQUIRED")
        interface = ipaddress.IPv4Address(self.interface)
        if interface.is_multicast or interface.is_unspecified or str(interface) == "255.255.255.255":
            raise ValueError("INVALID_LAN_INTERFACE")
        if self.restricted_local != interface.is_loopback:
            # Production must use a real interface; loopback is an explicit test
            # mode so a same-host run can never masquerade as a LAN result.
            raise PermissionError("LOOPBACK_REQUIRES_RESTRICTED_LOCAL" if interface.is_loopback
                                  else "RESTRICTED_LOCAL_MUST_BE_LOOPBACK")
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            probe.bind((str(interface), 0))
        except OSError:
            raise ValueError("LAN_INTERFACE_UNAVAILABLE") from None
        finally:
            probe.close()
        return str(group)


class _Rate:
    """Fixed-window limiter with a bounded key table (no unbounded growth)."""

    def __init__(self, limit, window=1.0, max_keys=MAX_SOURCES):
        self.limit, self.window, self.max_keys = limit, window, max_keys
        self.keys = {}

    def allow(self, key, now):
        start, count = self.keys.get(key, (now, 0))
        if now - start >= self.window:
            start, count = now, 0
        if count >= self.limit:
            self.keys[key] = (start, count)
            return False
        self.keys[key] = (start, count + 1)
        if len(self.keys) > self.max_keys:
            oldest = min(self.keys, key=lambda item: self.keys[item][0])
            del self.keys[oldest]
        return True


@dataclass(frozen=True)
class LanPeer:
    address: str
    port: int
    identity: str
    family: int
    first_seen: float
    last_seen: float

    def candidate(self, transport="udp", certificate_fingerprint=None):
        return lan_candidate(self.address, self.port, family=self.family, transport=transport,
                             socket_id=lan_socket_id(self.identity),
                             certificate_fingerprint=certificate_fingerprint)

    def diagnostic(self):
        """Bounded, secret-free view for the UI/logging (no key, no content)."""
        return {"address": self.address, "port": self.port, "identity": self.identity,
                "family": self.family, "lastSeen": round(self.last_seen, 3)}


class LanDiscovery:
    """Link-scoped discovery of same-segment peers; explicit start and close."""

    def __init__(self, policy, *, monotonic=time.monotonic, wall=time.time,
                 runtime=None, sockmod=socket):
        self.policy = policy
        self.runtime = runtime or detect_runtime()
        self._monotonic, self._wall, self._socket_module = monotonic, wall, sockmod
        self.key = derive_key(policy.secret)
        self.scope = room_scope(self.key, policy.room)
        identity_key = ec.generate_private_key(ec.SECP256R1())
        self.identity = hashlib.sha256(identity_key.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
        self._identity_key = identity_key
        self.sock = None
        self.closed = False
        self.handlers = []
        self._peers = {}
        self.seen = {}
        self.sock_error = None
        self.announces_sent = 0
        self.responses_sent = 0
        self.rejected = {reason: 0 for reason in REJECTIONS}
        self._tasks = set()
        self._send = _Rate(MAX_SEND_PER_SECOND)
        self._inbound = _Rate(MAX_INBOUND_PER_SECOND)
        self._inbound_source = _Rate(MAX_INBOUND_PER_SOURCE)
        self._responses = _Rate(MAX_RESPONSE_PER_SECOND)
        self._response_source = _Rate(1, RESPONSE_COOLDOWN)
        self._status = {"mechanism": "lan-direct", "status": "idle", "reason": "NOT_STARTED"}

    # -- wiring -------------------------------------------------------------
    def subscribe(self, handler):
        self.handlers.append(handler)
        return lambda: self.handlers.remove(handler) if handler in self.handlers else None

    def emit(self, event, params):
        for handler in tuple(self.handlers):
            try:
                handler(event, params)
            except Exception:
                pass  # a consumer must not break discovery or leak payloads

    def record_socket_error(self, exc):
        # Bounded numeric diagnostics only: no exception text, endpoint or payload.
        if isinstance(exc, OSError):
            self.sock_error = {"errno": exc.errno, "winerror": getattr(exc, "winerror", None)}

    # -- lifecycle ----------------------------------------------------------
    def capability(self):
        return lan_capability(runtime=self.runtime, sockmod=self._socket_module)

    async def start(self):
        if self.closed:
            raise ValueError("LAN_DISCOVERY_CLOSED")
        group = self.policy.validate()  # raises on disabled/loopback/interface problems
        capability = self.capability()
        if capability["status"] != "available":
            self._status = dict(capability)
            self.emit("lan-status", dict(self._status))
            raise NotImplementedError(capability["reason"])
        self.sock = self._open_socket(group)
        self._status = {**capability, "status": "running", "discoveryPort": self.policy.discovery_port,
                        "listenPort": self.policy.listen_port, "scope": self.scope, "identity": self.identity}
        self._tasks = {asyncio.create_task(self._announce_loop()), asyncio.create_task(self._receive_loop())}
        self.emit("lan-status", {k: v for k, v in self._status.items() if k != "scope"})
        await self.announce_once()
        return dict(self._status)

    async def close(self):
        if self.closed:
            return
        self.closed = True
        for task in list(self._tasks):
            task.cancel()
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()
        if self.sock is not None:
            self.sock.close()
            self.sock = None
        # Release every derived/secret material on explicit disposal.
        self.key = b""
        self._identity_key = None
        self._peers.clear()
        self.seen.clear()
        for limiter in (self._send, self._inbound, self._inbound_source, self._responses, self._response_source):
            limiter.keys.clear()
        self._status = {"mechanism": "lan-direct", "status": "closed", "reason": "EXPLICIT_CLOSE",
                        "identity": self.identity}
        self.emit("lan-status", dict(self._status))

    # -- socket -------------------------------------------------------------
    def _open_socket(self, group):
        sock = self._socket_module.socket(self._socket_module.AF_INET, self._socket_module.SOCK_DGRAM)
        try:
            sock.setsockopt(self._socket_module.SOL_SOCKET, self._socket_module.SO_REUSEADDR, 1)
            if hasattr(self._socket_module, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(self._socket_module.SOL_SOCKET, self._socket_module.SO_REUSEPORT, 1)
                except OSError:
                    pass  # multi-instance on one host is a convenience, not a requirement
            # Multicast receive: bind the group where the OS permits, otherwise the
            # wildcard. Either way nothing is accepted without a room-key MAC.
            try:
                sock.bind((group, self.policy.discovery_port))
            except OSError:
                sock.bind(("", self.policy.discovery_port))
            sock.setsockopt(self._socket_module.IPPROTO_IP, self._socket_module.IP_ADD_MEMBERSHIP,
                            struct.pack("4s4s", self._socket_module.inet_aton(group),
                                        self._socket_module.inet_aton(self.policy.interface)))
            # TTL 1: the packet dies at the first router. Loopback stays on so a
            # second instance on the same host can be tested; it is never relayed.
            sock.setsockopt(self._socket_module.IPPROTO_IP, self._socket_module.IP_MULTICAST_TTL, 1)
            sock.setsockopt(self._socket_module.IPPROTO_IP, self._socket_module.IP_MULTICAST_LOOP, 1)
            sock.setsockopt(self._socket_module.IPPROTO_IP, self._socket_module.IP_MULTICAST_IF,
                            self._socket_module.inet_aton(self.policy.interface))
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise

    # -- sending ------------------------------------------------------------
    async def _send_announce(self):
        if self.sock is None or self.closed:
            raise ValueError("LAN_DISCOVERY_CLOSED")
        payload = build_announce(key=self.key, scope=self.scope, nonce=secrets.token_hex(32),
                                 ts=int(self._wall()), port=self.policy.listen_port, identity=self.identity)
        loop = asyncio.get_running_loop()
        try:
            await loop.sock_sendto(self.sock, payload, (self.policy.resolved_group(), self.policy.discovery_port))
        except OSError as exc:
            self.record_socket_error(exc)
            return False
        self.announces_sent += 1
        return True

    async def announce_once(self):
        """One rate-limited announce; returns whether it was actually sent."""
        if self.closed or self.sock is None:
            raise ValueError("LAN_DISCOVERY_CLOSED")
        now = self._monotonic()
        if not self._send.allow("announce", now):
            return False
        return await self._send_announce()

    async def _announce_loop(self):
        while not self.closed:
            try:
                await self.announce_once()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.record_socket_error(exc)  # a failed send must not stop announcing forever
            # Jitter avoids lock-step collisions when a whole room starts together.
            jitter = self.policy.announce_interval * 0.2
            await asyncio.sleep(self.policy.announce_interval + secrets.randbelow(1000) / 1000 * jitter)

    # -- receiving ----------------------------------------------------------
    async def _receive_loop(self):
        while not self.closed and self.sock is not None:
            try:
                data, addr = await receive_udp_retry(self.sock, MAX_DATAGRAM)
            except asyncio.CancelledError:
                raise
            except OSError as exc:
                self.record_socket_error(exc)
                await asyncio.sleep(0.01)
                continue
            try:
                await self.handle_datagram(data, addr)
            except asyncio.CancelledError:
                raise
            except Exception:
                self._count("transport")  # one bad datagram cannot kill discovery

    def _count(self, reason):
        self.rejected[reason] = min(self.rejected[reason] + 1, MAX_REJECTED)

    def _remember(self, nonce_key, now):
        self.seen[nonce_key] = now
        while len(self.seen) > MAX_SEEN_NONCES:
            oldest = min(self.seen, key=lambda item: self.seen[item])
            del self.seen[oldest]

    def _insert_peer(self, peer):
        self._peers[peer.identity] = peer
        if len(self._peers) > MAX_PEERS:
            oldest = min(self._peers, key=lambda item: self._peers[item].last_seen)
            del self._peers[oldest]

    async def handle_datagram(self, data, addr):
        """Process one datagram. Counters are bounded; memory is bounded."""
        now_m, now_w = self._monotonic(), self._wall()
        try:
            source = addr[0]
        except (TypeError, IndexError):
            self._count("malformed")
            return
        # Cheapest bounds first: bounded CPU under flood before any HMAC work.
        if not self._inbound.allow("all", now_m) or not self._inbound_source.allow(source, now_m):
            self._count("rateLimited")
            return
        self._expire_peers(now_m)
        try:
            info = parse_announce(data, key=self.key, scope=self.scope, now=now_w)
        except LanRejected as exc:
            self._count(exc.reason)
            return
        if info["identity"] == self.identity:
            self._count("selfAnnounce")  # our own multicast loopback
            return
        nonce_key = (info["identity"], info["nonce"])
        if nonce_key in self.seen:
            self._count("replay")
            return
        self._remember(nonce_key, now_m)
        try:
            lan_candidate(source, info["port"], family=self.policy.family, transport="udp")
        except (ValueError, TypeError, KeyError):
            self._count("invalidCandidate")  # existing rules: no exemption for LAN
            return
        existing = self._peers.get(info["identity"])
        peer = LanPeer(address=source, port=info["port"], identity=info["identity"], family=self.policy.family,
                       first_seen=existing.first_seen if existing else now_m, last_seen=now_m)
        self._insert_peer(peer)
        if existing is not None and (existing.address, existing.port) == (peer.address, peer.port):
            return  # already known: no event, no reactive announce, no response ping-pong
        self.emit("lan-peer", peer.diagnostic())  # announce only on change, never per packet
        if not self._responses.allow("response", now_m) or not self._response_source.allow(source, now_m):
            return
        # A reactive announce to the fixed link-scoped group (never to an arbitrary
        # unicast source), so a spoofed source cannot turn us into a reflector.
        try:
            if await self._send_announce():
                self.responses_sent += 1
        except ValueError:
            pass

    def _expire_peers(self, now):
        for identity in [key for key, peer in self._peers.items() if now - peer.last_seen > PEER_TTL]:
            del self._peers[identity]

    # -- reads --------------------------------------------------------------
    def peers(self):
        """Bounded snapshot, newest first; expired entries are dropped on read."""
        self._expire_peers(self._monotonic())
        return sorted(self._peers.values(), key=lambda peer: peer.last_seen, reverse=True)

    def candidates(self, transport="udp", certificate_fingerprint=None):
        return [peer.candidate(transport, certificate_fingerprint) for peer in self.peers()]

    def stats(self):
        """Secret-free diagnostics: identity/scope are keyed tags, never the key."""
        return {"status": self._status.get("status"), "reason": self._status.get("reason"),
                "mechanism": "lan-direct", "runtime": self.runtime, "identity": self.identity,
                "scopeTag": self.scope, "listenPort": self.policy.listen_port,
                "discoveryPort": self.policy.discovery_port, "announcesSent": self.announces_sent,
                "responsesSent": self.responses_sent, "peers": [peer.diagnostic() for peer in self.peers()],
                "rejected": dict(self.rejected), "socketError": self.sock_error,
                "bounds": {"maxPeers": MAX_PEERS, "maxSeenNonces": MAX_SEEN_NONCES,
                           "maxSources": MAX_SOURCES, "maxDatagramBytes": MAX_DATAGRAM},
                "observability": {"scope": "lan-link-local",
                                  "evidence": "REAL_LAN_REQUIRES_TWO_DEVICES_NOT_RUN"}}
