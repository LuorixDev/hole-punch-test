"""One-shot local network environment health check (native, UI-free).

What it is
----------
A single bounded pass that gathers what this machine can actually observe about its
own network, states each finding as *determined*, *insufficient evidence*, *not
tested* or *unavailable*, and turns that into honest hole-punching advice in the
fixed priority order IPv6 direct > gateway mapping > port prediction. It has no UI
imports and returns plain JSON-able data so the desktop client and a future native
Android port can share it.

What it reuses (never re-implements)
------------------------------------
* ``native/nat_behavior.py`` for mapping/filtering inference: this module calls
  ``probe_nat_behavior`` and copies ``NatProfile.report()``; it never derives a NAT
  type from a single mapped address and never invents one.
* ``native/ipv6_reach.py`` (task t48) for the local IPv6 address list, the default
  IPv6 route question and the inbound-reachability probe. If that module is missing
  the component is *not tested* with a reason, never guessed.
* ``native/stun.py`` for the explicit observation-point Binding transaction.

What it never does
------------------
* No implicit third party: every external observation goes to a literal IP:PORT the
  caller configured. No discovery, no DNS, no scan, no unknown-address probe.
* No relay, no traffic forwarding, no host network/firewall change.
* No credential in any output: this module's configuration carries no password, key
  or token, and a reach-probe token (owned by t48) is never copied into a report.
* No conflation: a probe round trip is reported as ``probeRttMs`` with an explicit
  meaning marker and is never presented as chat latency. A local address/route
  observation is never presented as NAT evidence.

Honesty vocabulary
------------------
``determined``             - measured; the reason names the measurement
``insufficient-evidence``  - measured, but not enough to conclude (says why)
``not-tested``             - deliberately not attempted (no observation point, no
                             consent, missing context, platform table absent)
``unavailable``            - attempted and failed at the OS/host level
``not-applicable``         - the question does not apply to this host

Nothing here is real-home-network evidence by itself: a NAT classification is an
inference about the configured observation path, and whether a real ISP allows
inbound IPv6 can only be confirmed on a real home network (see ``unmeasured``).

Center-log reporting
--------------------
``NetEnvReport.center_events(...)`` returns events that satisfy the existing
allowlist in ``backend/telemetry.py`` (exact envelope keys, allowlisted data keys,
<= 30 events, <= 2048 bytes each); the tests validate every event through
``backend.telemetry.validate_event``. Because that allowlist has no field for
net-environment semantics, the inference detail (mapping/filtering, address
stability, NAT64 signs) currently stays local: ``center_report()`` carries it with
``ingest.localOnlyFields`` and ``ingest.allowlistFieldsNeeded`` naming the exact
extra keys an ingest allowlist change would need. This module does not edit that
shared allowlist and does not smuggle the detail into unrelated fields.
"""
from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import socket
import struct
import sys
import time
import uuid
from dataclasses import dataclass, field, replace
from typing import Any, Callable

from . import nat_behavior as nat
from .stun import binding as stun_binding

try:  # t48 integration point; absence is reported, never guessed
    from . import ipv6_reach as reach
except ImportError:  # pragma: no cover - only when the t48 module is missing
    reach = None

try:
    import fcntl
except ImportError:  # pragma: no cover - Windows / POSIX without fcntl
    fcntl = None

SCHEMA = "p2pobs.net-env.v1"

# ---------------------------------------------------------------- vocabularies
DETERMINED = "determined"
INSUFFICIENT = "insufficient-evidence"
NOT_TESTED = "not-tested"
UNAVAILABLE = "unavailable"
NOT_APPLICABLE = "not-applicable"
STATUSES = (DETERMINED, INSUFFICIENT, NOT_TESTED, UNAVAILABLE, NOT_APPLICABLE)

RECOMMENDED = "recommended"
POSSIBLE = "possible"
UNKNOWN = "unknown"
RECOMMENDATION_STATUSES = (RECOMMENDED, POSSIBLE, UNAVAILABLE, UNKNOWN, NOT_TESTED)

IPV6_DIRECT = "ipv6-direct"
GATEWAY_MAPPING = "gateway-mapping"
PORT_PREDICTION = "port-prediction"
METHOD_ORDER = (IPV6_DIRECT, GATEWAY_MAPPING, PORT_PREDICTION)
COMPONENTS = ("addresses", "routes", "udpEgress", "natBehavior", "inboundReachability", "ipv6Only", "nat64")

NON_GLOBAL_SCOPES = {"loopback", "link-local", "multicast", "unspecified", "ula"}

# Every loop, table and error list below is capped.
MAX_POINTS = 4
MAX_ADDRESSES = 64
MAX_INTERFACES = 32
MAX_ROUTE_BYTES = 64 * 1024
MAX_ERRORS = 32
MAX_EVENTS = 8
MAX_EVENT_BYTES = 2048
MAX_TOTAL_SECONDS = 60.0
DEFAULT_TOTAL_SECONDS = 20.0
MIN_COMPONENT_TIMEOUT = 0.2
MAX_COMPONENT_TIMEOUT = 10.0

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B
RTF_GATEWAY = 0x0002
NAT64_WKP = ipaddress.IPv6Network("64:ff9b::/96")

UNMEASURED = (
    ("REAL_NAT_TYPE", "配置的观测点只能说明这条路径上的映射/过滤行为；真实家宽的 NAT 类型必须在真实网络复测"),
    ("REAL_IPV6_INBOUND_ALLOWED", "本机是否真的能从公网被回连，取决于运营商与路由器防火墙，只能在真实家宽确认"),
    ("REAL_PORT_PREDICTION_SUCCESS", "端口预测能否成功取决于对端与真实 NAT，本机体检给不出保证"),
    ("REAL_MULTIPLE_PATHS", "真实环境里是否有可用的多条候选路径，需要两端真实探测后才知道"),
)

LOCAL_ONLY_FIELDS = (
    "addresses.records", "routes.gatewayAddress", "routes.interfaceNames", "natBehavior.mapping",
    "natBehavior.filtering", "natBehavior.mappingEvidence", "natBehavior.filteringEvidence",
    "inboundReachability.verdict", "inboundReachability.note", "nat64.signs", "udpEgress.bindings", "errors",
)
ALLOWLIST_FIELDS_NEEDED = (
    "netEnvOverall", "netEnvComponent", "netEnvStatus", "netEnvReason", "netEnvMapping", "netEnvFiltering",
    "netEnvAddressStability", "netEnvNat64", "netEnvRecommendation", "netEnvUnmeasured",
)


class NetEnvError(ValueError):
    """Stable configuration error; never contains an address or a credential."""


# ------------------------------------------------------------------- addresses
@dataclass(frozen=True)
class AddressRecord:
    family: int
    address: str
    scope: str
    is_global: bool
    temporary: bool | None = None       # None = the OS did not expose RFC 4941 state
    prefix_length: int | None = None
    interface: str = ""
    deprecated: bool = False
    dynamic: bool = False

    def stability(self):
        if self.scope in NON_GLOBAL_SCOPES:
            return "not-global"
        if self.temporary is True:
            return "temporary"
        if self.temporary is False:
            return "stable"
        return "unverified"

    def view(self, redact=False):
        view = {"family": self.family, "scope": self.scope, "isGlobal": bool(self.is_global),
                "stability": self.stability(), "temporary": self.temporary,
                "prefixLength": self.prefix_length, "deprecated": bool(self.deprecated),
                "dynamic": bool(self.dynamic), "address": None if redact else self.address}
        view["interfaceTag" if redact else "interface"] = (redact_interface(self.interface) if redact
                                                           else self.interface)
        return view


def redact_interface(name):
    """Stable short tag for an interface name: correlates without publishing the name."""
    if not name:
        return ""
    return hashlib.sha256(name.encode("utf-8", "replace")).hexdigest()[:8]


def classify_scope(address):
    parsed = ipaddress.ip_address(address)
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_link_local:
        return "link-local"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_unspecified:
        return "unspecified"
    if parsed.version == 4 and parsed in ipaddress.IPv4Network("100.64.0.0/10"):
        return "shared-cgnat"
    if parsed.version == 6 and parsed in ipaddress.IPv6Network("fc00::/7"):
        return "ula"
    if parsed.version == 4 and parsed.is_private:
        return "private"
    if parsed.is_global:
        return "global"
    return "other"


def build_address_records(ipv4_raw, ipv6_raw):
    """Normalise both families into one bounded, classified list."""
    records, errors = [], []
    for entry in list(ipv4_raw or [])[:MAX_ADDRESSES]:
        try:
            address = str(ipaddress.IPv4Address(str(entry["address"])))
        except (KeyError, ValueError, TypeError):
            errors.append("INVALID_LOCAL_ADDRESS")
            continue
        records.append(AddressRecord(family=4, address=address, scope=classify_scope(address),
                                     is_global=ipaddress.IPv4Address(address).is_global,
                                     temporary=entry.get("temporary") if isinstance(entry.get("temporary"), bool) else None,
                                     prefix_length=entry.get("prefixLength") if isinstance(entry.get("prefixLength"), int)
                                     else None,
                                     interface=str(entry.get("interface", "") or "")))
    for entry in list(ipv6_raw or [])[:MAX_ADDRESSES]:
        try:
            address = str(ipaddress.IPv6Address(str(getattr(entry, "address", entry))))
        except (ValueError, TypeError, AttributeError):
            errors.append("INVALID_LOCAL_ADDRESS")
            continue
        temporary = getattr(entry, "temporary", None)
        prefix = getattr(entry, "prefix_length", None)
        records.append(AddressRecord(family=6, address=address, scope=classify_scope(address),
                                     is_global=ipaddress.IPv6Address(address).is_global,
                                     temporary=temporary if isinstance(temporary, bool) else None,
                                     prefix_length=prefix if isinstance(prefix, int) else None,
                                     interface=str(getattr(entry, "interface", "") or ""),
                                     deprecated=bool(getattr(entry, "deprecated", False)),
                                     dynamic=bool(getattr(entry, "dynamic", False))))
    return records[:MAX_ADDRESSES], errors[:MAX_ERRORS]


def summarize_addresses(records):
    def count(predicate):
        return sum(1 for record in records if predicate(record))
    globals_v6 = [record for record in records if record.family == 6 and record.is_global]
    return {
        "total": len(records),
        "ipv4": count(lambda record: record.family == 4),
        "ipv6": count(lambda record: record.family == 6),
        "loopback": count(lambda record: record.scope == "loopback"),
        "linkLocal": count(lambda record: record.scope == "link-local"),
        "ula": count(lambda record: record.scope == "ula"),
        "sharedCgnat": count(lambda record: record.scope == "shared-cgnat"),
        "globalV4": count(lambda record: record.family == 4 and record.is_global),
        "privateV4": count(lambda record: record.family == 4 and record.scope == "private"),
        "globalV6": len(globals_v6),
        "globalV6Stable": sum(1 for record in globals_v6 if record.stability() == "stable"),
        "globalV6Temporary": sum(1 for record in globals_v6 if record.stability() == "temporary"),
        "globalV6Unverified": sum(1 for record in globals_v6 if record.stability() == "unverified"),
        "hasGlobalV4": any(record.family == 4 and record.is_global for record in records),
        "hasPrivateV4": any(record.family == 4 and record.scope in {"private", "shared-cgnat"} for record in records),
        "hasGlobalV6Stable": any(record.stability() == "stable" for record in globals_v6),
        "hasGlobalV6TemporaryOnly": bool(globals_v6) and all(record.stability() == "temporary" for record in globals_v6),
        "hasGlobalV6UnverifiedOnly": bool(globals_v6) and all(record.stability() != "stable" for record in globals_v6),
    }


def linux_ipv4_addresses():
    """Local IPv4 addresses via the interface list + ioctl: no subprocess, no DNS, no scan."""
    if fcntl is None or not hasattr(socket, "if_nameindex"):
        return None
    try:
        names = socket.if_nameindex()
    except OSError:
        return None
    records = []
    for _, name in names[:MAX_INTERFACES]:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                request = struct.pack("256s", name.encode("utf-8", "replace")[:15])
                address = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), SIOCGIFADDR, request)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(probe.fileno(), SIOCGIFNETMASK, request)[20:24])
            prefix = ipaddress.IPv4Network("0.0.0.0/" + mask).prefixlen
        except (OSError, ValueError, UnicodeEncodeError):
            continue
        records.append({"address": address, "interface": name, "prefixLength": prefix, "temporary": None})
    return records


# ---------------------------------------------------------------------- routes
def read_text_bounded(path, limit=MAX_ROUTE_BYTES):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            return handle.read(limit)
    except OSError:
        return None


def linux_ipv4_routes():
    return read_text_bounded("/proc/net/route")


def linux_ipv6_routes():
    return read_text_bounded("/proc/net/ipv6_route")


def parse_ipv4_routes(text):
    """IPv4 default route and gateway presence from /proc/net/route text."""
    if text is None:
        return None
    for line in str(text).splitlines()[1:]:
        fields = line.split()
        if len(fields) < 8 or fields[0] == "Iface":
            continue
        try:
            destination, gateway, flags, mask = (int(fields[1], 16), int(fields[2], 16),
                                                 int(fields[3], 16), int(fields[7], 16))
        except ValueError:
            continue
        if destination == 0 and mask == 0:
            return {"present": True, "gatewayPresent": bool(gateway) and bool(flags & RTF_GATEWAY),
                    "interface": fields[0],
                    "gateway": str(ipaddress.IPv4Address(struct.pack("<I", gateway))) if gateway else None}
    return {"present": False, "gatewayPresent": False, "interface": None, "gateway": None}


def parse_ipv6_routes(text):
    """IPv6 default route and gateway presence from /proc/net/ipv6_route text."""
    if text is None:
        return None
    for line in str(text).splitlines():
        fields = line.split()
        if len(fields) < 10 or set(fields[0]) != {"0"} or fields[1] != "00":
            continue
        try:
            populated = int(fields[4], 16) != 0
        except ValueError:
            populated = False
        address = None
        if populated:
            try:
                address = str(ipaddress.IPv6Address(int(fields[4], 16)))
            except ValueError:
                address = None
        return {"present": True, "gatewayPresent": populated, "interface": fields[9], "gateway": address}
    return {"present": False, "gatewayPresent": False, "interface": None, "gateway": None}


# ------------------------------------------------------------------ components
@dataclass(frozen=True)
class Component:
    name: str
    status: str
    reason: str
    evidence: str = ""
    detail: dict = field(default_factory=dict)

    def local_view(self):
        return {"status": self.status, "reason": self.reason, "evidence": self.evidence, "detail": dict(self.detail)}


def _component(name, status, reason, evidence="", detail=None):
    return Component(name, status, reason, evidence, detail or {})


def not_tested(name, reason, evidence=""):
    return _component(name, NOT_TESTED, reason, evidence)


def _flag_view(detail):
    """Center-safe projection: booleans, counts and stable codes only."""
    result = {}
    for key, value in detail.items():
        if isinstance(value, bool):
            result[key] = value
        elif isinstance(value, (int, float)):
            result[key] = value
        elif isinstance(value, str) and (key.endswith(("Status", "Reason", "Code", "Scope", "Stability"))
                                         or key in {"pointsAnswered", "next"}):
            result[key] = value
    return result


# -------------------------------------------------------------------- config
@dataclass(frozen=True)
class NetEnvConfig:
    """Explicit configuration. Nothing external is contacted unless it is named here."""

    observation_points: tuple = ()
    bind_host_v4: str | None = None
    bind_host_v6: str | None = None
    udp_probe_timeout: float = 2.0
    nat_local_ports: int = 2
    nat_repeats: int = 2
    nat_timeout: float = 2.0
    inbound_probe: bool = False
    consent: bool = False
    connection_id: str = ""
    attempt_id: str = ""
    session: str = ""
    allow_temporary: bool = True
    nat64_probe: bool = False
    total_budget_seconds: float = DEFAULT_TOTAL_SECONDS
    include_addresses: bool = False

    def validate(self):
        for name in ("bind_host_v4", "bind_host_v6"):
            value = getattr(self, name)
            if value is None:
                continue
            address = ipaddress.ip_address(value)
            if address.is_unspecified or address.is_multicast or address.is_link_local:
                raise NetEnvError("EXPLICIT_BIND_REQUIRED")
            if address.version != (4 if name.endswith("v4") else 6):
                raise NetEnvError("BIND_FAMILY_MISMATCH")
        if not isinstance(self.observation_points, tuple) or len(self.observation_points) > MAX_POINTS:
            raise NetEnvError("INVALID_OBSERVATION_POINTS")
        for point in self.observation_points:
            if not isinstance(point, nat.StunObservationPoint):
                raise NetEnvError("INVALID_OBSERVATION_POINTS")
            ipaddress.ip_address(point.host)  # literal IP only; canonical_endpoint rejects names
        for name in ("udp_probe_timeout", "nat_timeout"):
            value = getattr(self, name)
            if not isinstance(value, (int, float)) or isinstance(value, bool) \
                    or not MIN_COMPONENT_TIMEOUT <= float(value) <= MAX_COMPONENT_TIMEOUT:
                raise NetEnvError("INVALID_TIMEOUT")
        if not 1 <= self.nat_local_ports <= 4 or not 1 <= self.nat_repeats <= 4:
            raise NetEnvError("INVALID_NAT_PROBE_BOUNDS")
        if not isinstance(self.total_budget_seconds, (int, float)) or isinstance(self.total_budget_seconds, bool) \
                or not 1 <= float(self.total_budget_seconds) <= MAX_TOTAL_SECONDS:
            raise NetEnvError("INVALID_TOTAL_BUDGET")
        return self


@dataclass
class Sources:
    """Injection seams. Defaults are the real OS/module behaviour."""

    platform: str = sys.platform
    ipv4_addresses: Callable[[], Any] | None = None
    ipv6_addresses: Callable[[], Any] | None = None
    ipv4_routes: Callable[[], Any] | None = None
    ipv6_routes: Callable[[], Any] | None = None
    nat_probe: Callable[..., Any] | None = None
    udp_binding: Callable[..., Any] | None = None
    reach_probe: Callable[..., Any] | None = None
    reach_module: Any = None
    monotonic: Callable[[], float] = time.monotonic
    wall: Callable[[], float] = time.time


class _Budget:
    def __init__(self, total, monotonic):
        self.total = float(total)
        self.monotonic = monotonic
        self.start = monotonic()

    def elapsed(self):
        return self.monotonic() - self.start

    def remaining(self):
        return max(0.0, self.total - self.elapsed())

    def expired(self):
        return self.remaining() <= 0


@dataclass
class NetEnvReport:
    components: dict
    recommendations: list
    overall: dict
    duration_ms: float
    checked_at_ms: float
    config_view: dict = field(default_factory=dict)
    errors: list = field(default_factory=list)
    errors_truncated: bool = False
    identity: dict = field(default_factory=dict)

    def component(self, name):
        return self.components[name]

    def local_report(self):
        """Everything this machine observed, including raw local addressing."""
        return {
            "schema": SCHEMA,
            "checkedAtMs": self.checked_at_ms,
            "durationMs": self.duration_ms,
            "identity": dict(self.identity),
            "config": dict(self.config_view),
            "overall": dict(self.overall),
            "components": {name: component.local_view() for name, component in self.components.items()},
            "recommendations": [dict(item) for item in self.recommendations],
            "unmeasured": [{"code": code, "plain": text} for code, text in UNMEASURED],
            "errors": list(self.errors),
            "errorsTruncated": self.errors_truncated,
        }

    def center_report(self):
        """Desensitised, bounded structure for the central log / merged review.

        No raw address, no gateway address, no interface name, no credential; every
        component is reduced to status + reason code + flags.
        """
        return {
            "schema": SCHEMA,
            "checkedAtMs": self.checked_at_ms,
            "durationMs": round(self.duration_ms, 3),
            "session": self.identity.get("session"),
            "connectionId": self.identity.get("connectionId"),
            "attemptId": self.identity.get("attemptId"),
            "overall": {"status": self.overall.get("status"), "reasons": list(self.overall.get("reasons", []))},
            "components": {
                name: {"status": component.status, "reason": component.reason, "flags": _flag_view(component.detail)}
                for name, component in self.components.items()},
            "recommendations": [{"rank": item["rank"], "method": item["method"], "status": item["status"],
                                 "reason": item["reason"]} for item in self.recommendations],
            "unmeasured": [code for code, _ in UNMEASURED],
            "errorCount": len(self.errors),
            "errorsTruncated": self.errors_truncated,
            "redaction": {"rawAddresses": "local-only", "gatewayAddresses": "local-only",
                          "interfaceNames": "sha256-prefix-tag", "credentials": "never-included",
                          "probeRtt": "probe-round-trip-only-not-chat-latency"},
            "ingest": {"envelope": "p2pobs telemetry v1", "eventsEmittedBy": "center_events()",
                       "localOnlyFields": list(LOCAL_ONLY_FIELDS),
                       "allowlistFieldsNeeded": list(ALLOWLIST_FIELDS_NEEDED)},
        }

    def center_events(self, *, session, connection_id=None, attempt_id=None, start_seq=0, now_ms=None):
        """Schema-valid telemetry events (allowlisted keys only) for the central log.

        Field meanings are fixed here so nothing can be misread downstream:

        * ``client.boot`` - one marker that the environment check completed.
          ``ok`` = this check finished and the report was built; ``canMessage`` = UDP
          direct messaging is *confirmed* on this host (i.e. an observation point
          answered). ``family`` = the family the check ran on.
        * ``probe.ack``   - one UDP round trip to a configured observation point that
          answered; ``rttMs`` is that round trip, never chat latency.
        * ``stun.binding``- one STUN Binding observation (family, request bytes, RTT).
          ``responseBytes`` is omitted because this wrapper does not measure it.
        * ``client.error``- the UDP path failed at the OS level, or no entry point
          could be observed at all.

        The NAT mapping/filtering inference, address stability and NAT64 signs are NOT
        encoded here: the ingest allowlist has no field for them, and inventing one out
        of an unrelated enum would be a mislabel (see ``center_report()['ingest']``).
        """
        _validate_uuid(session, "session")
        for value, name in ((connection_id, "connectionId"), (attempt_id, "attemptId")):
            if value is not None:
                _validate_uuid(value, name)
        wall = now_ms if now_ms is not None else self.checked_at_ms
        if not isinstance(wall, (int, float)) or isinstance(wall, bool) or wall <= 0:
            raise NetEnvError("INVALID_TIMESTAMP")
        seq = int(start_seq)
        events = []

        def emit(kind, data):
            nonlocal seq
            seq += 1
            events.append({"v": 1, "id": str(uuid.uuid4()), "clientSessionId": session, "seq": seq,
                           "tsWallMs": float(wall), "monoMs": 0.0, "connectionId": connection_id,
                           "attemptId": attempt_id, "event": kind, "data": data})

        summary = self.components["addresses"].detail
        family = 4 if summary.get("ipv4") else (6 if summary.get("ipv6") else "unknown")
        egress = self.components["udpEgress"]
        emit("client.boot", {"family": family, "protocol": "udp",
                             "canMessage": egress.status == DETERMINED, "ok": True})
        if egress.status == DETERMINED:
            emit("probe.ack", {"family": egress.detail.get("family", family), "protocol": "udp",
                               "rttMs": egress.detail.get("probeRttMs"), "ok": True})
        for entry in list(egress.detail.get("bindings", []))[:2]:
            # responseBytes is deliberately absent: this wrapper does not count response
            # bytes, and publishing a fabricated 0 would be a false measurement.
            emit("stun.binding", {"family": entry.get("family"), "protocol": "udp",
                                  "requestBytes": entry.get("requestBytes"), "rttMs": entry.get("probeRttMs")})
        if egress.status == UNAVAILABLE:
            emit("client.error", {"error": "INTERNAL_ERROR", "reason": "UNSUPPORTED"})
        elif egress.status == INSUFFICIENT and self.components["natBehavior"].status == NOT_TESTED:
            emit("client.error", {"error": "UNSUPPORTED", "reason": "ENDPOINT_UNOBSERVABLE"})
        if len(events) > MAX_EVENTS:
            raise NetEnvError("EVENT_LIMIT")
        for event in events:
            if len(json.dumps(event).encode()) > MAX_EVENT_BYTES:
                raise NetEnvError("EVENT_LIMIT")
        return events

    def center_message(self, *, session, connection_id=None, attempt_id=None, start_seq=0, now_ms=None):
        """One ready-to-send telemetry message: the exact wire shape the server accepts.

        The caller only needs to hand this to the existing signaling link; nothing else
        about the report is transmitted.
        """
        events = self.center_events(session=session, connection_id=connection_id, attempt_id=attempt_id,
                                    start_seq=start_seq, now_ms=now_ms)
        return {"v": 1, "type": "telemetry", "clientSessionId": session, "events": events}


def _validate_uuid(value, name):
    if not isinstance(value, str):
        raise NetEnvError("INVALID_IDENTITY")
    try:
        uuid.UUID(value)
    except (ValueError, AttributeError):
        raise NetEnvError("INVALID_IDENTITY") from None


# --------------------------------------------------------------- sub-probes
def _addresses_component(config, sources, errors):
    v4_provider = sources.ipv4_addresses or (linux_ipv4_addresses if sources.platform.startswith("linux") else None)
    module = sources.reach_module if sources.reach_module is not None else reach
    v6_provider = sources.ipv6_addresses or (module.enumerate_addresses if module is not None else None)
    v4_raw = v4_provider() if v4_provider is not None else None
    v6_raw = v6_provider() if v6_provider is not None else None
    if v4_raw is None and v6_raw is None:
        return not_tested("addresses", "ADDRESS_ENUMERATION_UNAVAILABLE",
                          "本平台没有可用的地址枚举来源；未做任何猜测"), []
    records, invalid = build_address_records(v4_raw, v6_raw)
    errors.extend(invalid[:max(0, MAX_ERRORS - len(errors))])
    detail = summarize_addresses(records)
    detail["records"] = [record.view(redact=False) for record in records]
    detail["temporaryConcept"] = "RFC 4941 临时地址只适用于 IPv6；IPv4 地址没有临时/稳定之分"
    return _component("addresses", DETERMINED, "LOCAL_ADDRESSES_ENUMERATED",
                      f"枚举到 {detail['ipv4']} 个 IPv4 与 {detail['ipv6']} 个 IPv6 本机地址", detail), records


def _routes_component(config, sources):
    v4_provider = sources.ipv4_routes or (linux_ipv4_routes if sources.platform.startswith("linux") else None)
    v6_provider = sources.ipv6_routes or (linux_ipv6_routes if sources.platform.startswith("linux") else None)
    v4 = v4_provider() if v4_provider is not None else None
    v6 = v6_provider() if v6_provider is not None else None
    if v4 is None and v6 is None:
        return not_tested("routes", "ROUTE_TABLE_UNREADABLE_ON_PLATFORM",
                          "读不到本机路由表，未运行任何路由探测")
    detail = {"ipv4Default": None, "ipv4GatewayPresent": None, "ipv4Interface": None, "ipv4GatewayAddress": None,
              "ipv6Default": None, "ipv6GatewayPresent": None, "ipv6Interface": None, "ipv6GatewayAddress": None,
              "routeSource": "os-routing-table-read-only"}
    if v4 is not None:
        parsed = parse_ipv4_routes(v4)
        detail.update({"ipv4Default": parsed["present"], "ipv4GatewayPresent": parsed["gatewayPresent"],
                       "ipv4Interface": parsed["interface"], "ipv4GatewayAddress": parsed["gateway"]})
    if v6 is not None:
        parsed = parse_ipv6_routes(v6)
        detail.update({"ipv6Default": parsed["present"], "ipv6GatewayPresent": parsed["gatewayPresent"],
                       "ipv6Interface": parsed["interface"], "ipv6GatewayAddress": parsed["gateway"],
                       "ipv6DefaultSource": "local-route-table-parse"})
        module = sources.reach_module if sources.reach_module is not None else reach
        # The IPv6 default-route question belongs to t48's module: reuse its answer
        # instead of keeping a second, possibly divergent, rule.
        if module is not None and hasattr(module, "has_default_v6_route"):
            detail["ipv6Default"] = bool(module.has_default_v6_route(v6))
            detail["ipv6DefaultSource"] = "ipv6_reach.has_default_v6_route"
    status, reason = DETERMINED, "ROUTES_READ"
    if detail["ipv4Default"] is None or detail["ipv6Default"] is None:
        status, reason = INSUFFICIENT, "ROUTE_FAMILY_PARTIALLY_READABLE"
    return _component("routes", status, reason, "只读本机路由表，未改路由也未发起路由探测", detail)


def _pick_bind_hosts(config, records, addresses_status):
    """Explicit config wins; otherwise only an OS-enumerated local address is used."""
    hosts = {4: config.bind_host_v4, 6: config.bind_host_v6}
    source = "explicit-config" if any(value is not None for value in hosts.values()) else "os-enumeration"
    if addresses_status == DETERMINED:
        if hosts[4] is None:
            candidates = [record for record in records if record.family == 4 and record.scope not in NON_GLOBAL_SCOPES]
            candidates.sort(key=lambda record: 0 if record.scope == "global" else 1)
            if candidates:
                hosts[4] = candidates[0].address
        if hosts[6] is None:
            candidates = [record for record in records if record.family == 6 and record.is_global
                          and not record.deprecated]
            order = {"stable": 0, "unverified": 1, "temporary": 2}
            candidates.sort(key=lambda record: order.get(record.stability(), 3))
            if candidates and (candidates[0].stability() != "temporary" or config.allow_temporary):
                hosts[6] = candidates[0].address
    return hosts, source


def _points_by_family(config):
    grouped = {4: [], 6: []}
    for point in config.observation_points:
        try:
            grouped[ipaddress.ip_address(point.host).version].append(point)
        except ValueError:
            continue
    return grouped


async def _udp_egress(config, sources, budget, errors):
    grouped = _points_by_family(config)
    if not config.observation_points:
        return not_tested("udpEgress", "NO_OBSERVATION_POINT", "没有配置任何观测点，因此没有做 UDP 出站探测")
    probe = sources.udp_binding or stun_binding
    bindings, answered, failures, attempts, wanted = [], 0, [], 0, 0
    for family in (4, 6):
        host = config.bind_host_v4 if family == 4 else config.bind_host_v6
        for point in grouped[family][:MAX_POINTS]:
            if host is None:
                failures.append(f"NO_LOCAL_ADDRESS:{family}")
                continue
            if budget.expired():
                failures.append("TOTAL_BUDGET_EXCEEDED")
                break
            attempts += 1
            sock = socket.socket(socket.AF_INET if family == 4 else socket.AF_INET6, socket.SOCK_DGRAM)
            if family == 6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.setblocking(False)
            started = budget.monotonic()
            try:
                sock.bind((host, 0))
                allowance = min(config.udp_probe_timeout, budget.remaining())
                result = await asyncio.wait_for(probe(sock, (point.host, point.port), allowance), allowance + 0.05)
                answered += 1
                mapped = result.get("address")
                bindings.append({"family": family, "scope": classify_scope(mapped) if mapped else "unknown",
                                 "probeRttMs": round((budget.monotonic() - started) * 1000, 3),
                                 "requestBytes": 20, "pointPort": point.port,  # RFC5389 header only
                                 "observation": result.get("observation", "mapped-address-only-not-nat-type")})
            except asyncio.TimeoutError:
                failures.append(f"NO_RESPONSE:{family}")
            except OSError as exc:
                failures.append(f"SEND_FAILED:{getattr(exc, 'errno', 'unknown')}")
            except (KeyError, TypeError, AttributeError):
                failures.append("PROBE_RESULT_INVALID")
            finally:
                sock.close()
    detail = {"attemptedPoints": attempts, "answeredPoints": answered, "bindings": bindings,
              "mappedScopes": [entry["scope"] for entry in bindings], "failures": failures[:MAX_ERRORS],
              "probeRttMeaning": "observation-round-trip-only-not-chat-latency"}
    if answered:
        detail["family"] = bindings[0]["family"]
        detail["probeRttMs"] = bindings[0]["probeRttMs"]
        return _component("udpEgress", DETERMINED, "UDP_OUTBOUND_CONFIRMED",
                          f"{answered}/{attempts} 个观测点回了包，UDP 出站可用", detail)
    if not attempts:
        reason = "NO_USABLE_LOCAL_ADDRESS" if config.observation_points else "NO_OBSERVATION_POINT"
        return not_tested("udpEgress", reason, "配置了观测点但没有可用的本机地址（或没有对应协议族）")
    if all(entry.startswith(("SEND_FAILED", "TOTAL_BUDGET_EXCEEDED")) for entry in failures):
        return _component("udpEgress", UNAVAILABLE, "UDP_SEND_FAILED",
                          "操作系统拒绝了 UDP 发送（这不是“被防火墙挡住”的结论）", detail)
    return _component("udpEgress", INSUFFICIENT, "NO_RESPONSE_FROM_OBSERVATION_POINT",
                      "包发出去了但没有观测点回包；可能是指定观测点不可用或 UDP 被过滤，不能据此断言被封", detail)


def _nat_destinations(points):
    destinations = []
    for point in points:
        endpoint = (point.host, point.port)
        if endpoint not in destinations:
            destinations.append(endpoint)
    return destinations


async def _nat_component(config, sources, budget, hosts, errors):
    if not config.observation_points:
        return not_tested("natBehavior", "NO_OBSERVATION_POINT",
                          "映射/过滤行为必须由用户显式给出的观测点测量；本机不做任何推测")
    grouped = _points_by_family(config)
    family = None
    for candidate in (4, 6):
        if len(_nat_destinations(grouped[candidate])) >= 2 and hosts.get(candidate):
            family = candidate
            break
    if family is None:
        insufficient = any(len(_nat_destinations(grouped[candidate])) < 2 and grouped[candidate] for candidate in (4, 6))
        reason = "INSUFFICIENT_OBSERVATION_POINTS" if insufficient else "NO_USABLE_LOCAL_ADDRESS"
        return _component("natBehavior", INSUFFICIENT, reason,
                          "nat_behavior 要求同一协议族至少两个不同观测点且有可用本机地址；未做任何 NAT 判断",
                          {"requiredPoints": 2, "configuredFamilies": sorted(f for f in (4, 6) if grouped[f])})
    bind_host = hosts[family]
    probe = sources.nat_probe or nat.probe_nat_behavior
    try:
        nat_config = nat.NatProbeConfig(bind_host, tuple(grouped[family]), config.nat_local_ports,
                                        config.nat_repeats, config.nat_timeout).validate()
    except ValueError as exc:
        return _component("natBehavior", INSUFFICIENT, str(exc),
                          "观测点配置没通过 nat_behavior 的校验；未做 NAT 判断")
    if budget.expired():
        return _component("natBehavior", UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED", "总时长预算用尽，未开始 NAT 行为探测")
    try:
        profile = await asyncio.wait_for(probe(nat_config), budget.remaining())
    except asyncio.TimeoutError:
        errors.append("NAT_PROBE_TIMEOUT")
        return _component("natBehavior", UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED", "NAT 行为探测超出总时长预算")
    except (OSError, ValueError):
        errors.append("NAT_PROBE_FAILED")
        return _component("natBehavior", UNAVAILABLE, "NAT_PROBE_FAILED", "NAT 行为探测在主机层面失败")
    detail = profile.report(include_mappings=False)
    detail["mappingStability"] = "inference-from-configured-observation-points"
    if profile.mapping == nat.UNDETERMINED or profile.filtering == nat.UNDETERMINED:
        return _component("natBehavior", INSUFFICIENT, "NAT_BEHAVIOR_UNDETERMINED",
                          "nat_behavior 判定为无法判定；本模块不会把它写成对称型或可打洞", detail)
    return _component("natBehavior", DETERMINED, "NAT_BEHAVIOR_CLASSIFIED",
                      "映射/过滤行为由 nat_behavior 依据观测到的映射端点变化得出", detail)


async def _inbound_component(config, sources, budget, errors):
    module = sources.reach_module if sources.reach_module is not None else reach
    if module is None:
        return not_tested("inboundReachability", "IPV6_REACH_MODULE_UNAVAILABLE",
                          "IPv6 入站可达性模块（t48）不可用；未做任何替代探测")
    if not config.inbound_probe:
        return not_tested("inboundReachability", "INBOUND_PROBE_NOT_REQUESTED",
                          "用户未开启入站回连探测；本模块不会自行开监听器")
    if not config.consent:
        return not_tested("inboundReachability", "CONSENT_REQUIRED", "未获得用户明确同意，拒绝开启任何监听器")
    if not (config.session and config.connection_id and config.attempt_id):
        return not_tested("inboundReachability", "REACH_CONTEXT_REQUIRED",
                          "缺少 session/connection/attempt 关联信息，无法把回连结果与本次体检关联")
    options_factory = getattr(module, "ReachOptions", None)
    probe = sources.reach_probe or getattr(module, "probe_reachability", None)
    if options_factory is None or probe is None:
        return not_tested("inboundReachability", "IPV6_REACH_PROBE_MISSING",
                          "t48 模块没有提供 ReachOptions/probe_reachability，未做任何替代探测")
    if budget.expired():
        return _component("inboundReachability", UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED", "总时长预算用尽，未开始入站回连探测")
    try:
        options = options_factory(consent=True, connection_id=config.connection_id, attempt_id=config.attempt_id,
                                  session=config.session,
                                  timeout=min(8.0, max(MIN_COMPONENT_TIMEOUT, budget.remaining())),
                                  allow_temporary=config.allow_temporary)
        result = await asyncio.wait_for(probe(options), budget.remaining())
    except asyncio.TimeoutError:
        errors.append("REACH_PROBE_TIMEOUT")
        return _component("inboundReachability", UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED", "入站回连探测超出总时长预算")
    except (OSError, ValueError, TypeError):
        errors.append("REACH_PROBE_FAILED")
        return _component("inboundReachability", UNAVAILABLE, "REACH_PROBE_FAILED", "入站回连探测在主机层面失败")
    verdict = getattr(result, "verdict", None)
    note = str(getattr(result, "note", "") or "")
    # The t48 one-time token / offer is deliberately never copied into a report.
    detail = {"verdict": verdict, "addressType": getattr(result, "address_type", None), "note": note,
              "probeRttMeaning": "reachability-callback-only-not-chat-latency"}
    if verdict is not None:
        if verdict == getattr(module, "REACHED_BY_SERVER", "REACHED_BY_SERVER"):
            return _component("inboundReachability", DETERMINED, "INBOUND_REACHED_BY_SERVER",
                              "服务端按一次性 token 回连成功：入站可达（只对当次地址成立）", detail)
        if verdict in {getattr(module, "NO_GLOBAL_V6", "NO_GLOBAL_V6"), getattr(module, "NO_V6_ROUTE", "NO_V6_ROUTE")}:
            return _component("inboundReachability", DETERMINED, verdict,
                              "本机没有可用的全局 IPv6 地址/路由，入站回连不适用", detail)
        if verdict == getattr(module, "REFUSED_BY_LOCAL_POLICY", "REFUSED_BY_LOCAL_POLICY"):
            return _component("inboundReachability", DETERMINED, "REFUSED_BY_LOCAL_POLICY", "本机策略拒绝，未开监听器", detail)
        if verdict == getattr(module, "ADDRESS_ROTATED", "ADDRESS_ROTATED"):
            return _component("inboundReachability", INSUFFICIENT, "ADDRESS_ROTATED",
                              "地址在探测期间轮换，本次结果对长期入站没有意义", detail)
        if verdict == getattr(module, "TIMEOUT", "TIMEOUT"):
            return _component("inboundReachability", INSUFFICIENT, "INBOUND_NOT_PROVEN",
                              "没有观测到回连；这不能证明入站被封锁（也可能是路由或对端问题）", detail)
    return _component("inboundReachability", INSUFFICIENT, "UNKNOWN_REACH_VERDICT",
                      "入站探测返回了未知结论；不做任何推断", detail)


def _ipv6_only_component(addresses, routes):
    if addresses.status != DETERMINED or routes.status not in {DETERMINED, INSUFFICIENT}:
        return not_tested("ipv6Only", "INSUFFICIENT_ADDRESS_OR_ROUTE_EVIDENCE",
                          "地址或路由证据不足，无法判断是否 IPv6-only")
    detail = addresses.detail
    ipv4_path = bool(detail.get("hasGlobalV4") or detail.get("hasPrivateV4")) or routes.detail.get("ipv4Default") is True
    ipv6_path = bool(detail.get("globalV6")) or routes.detail.get("ipv6Default") is True
    if ipv6_path and not ipv4_path:
        return _component("ipv6Only", DETERMINED, "IPV6_ONLY_LIKELY",
                          "本机没有可用的 IPv4 地址/默认路由，但有 IPv6 路径", {"likelyIpv6Only": True})
    if not ipv4_path and not ipv6_path:
        return _component("ipv6Only", DETERMINED, "NO_IP_PATH_OBSERVED",
                          "既没有 IPv4 也没有 IPv6 路径证据", {"likelyIpv6Only": False})
    return _component("ipv6Only", DETERMINED, "IPV4_PATH_PRESENT",
                      "存在 IPv4 地址或默认路由，因此不是 IPv6-only", {"likelyIpv6Only": False})


async def _nat64_component(config, sources, budget, addresses, ipv6_only, hosts, errors):
    detail = {"signs": "none-observed", "probeAttempted": False}
    for record in addresses.detail.get("records", []) if addresses.status == DETERMINED else []:
        if record.get("family") != 6 or not record.get("address"):
            continue
        try:
            if ipaddress.IPv6Address(record["address"]) in NAT64_WKP:
                detail["signs"] = "well-known-prefix-address-present"
                return _component("nat64", DETERMINED, "NAT64_WELL_KNOWN_PREFIX_ADDRESS",
                                  "本机地址落在 NAT64 知名前缀 64:ff9b::/96 内", detail), detail
        except ValueError:
            continue
    if ipv6_only.get("likelyIpv6Only") is not True:
        return _component("nat64", NOT_APPLICABLE, "IPV4_PATH_PRESENT",
                          "本机有 IPv4 路径，NAT64 迹象对本机的直连没有意义", detail), detail
    if not config.nat64_probe:
        return _component("nat64", NOT_TESTED, "NAT64_PROBE_NOT_REQUESTED",
                          "IPv6-only 环境下要判断 NAT64，需要用户显式开启知名前缀合成探测", detail), detail
    ipv4_points = [point for point in config.observation_points if ipaddress.ip_address(point.host).version == 4]
    host6 = hosts.get(6)
    if not ipv4_points or host6 is None:
        return _component("nat64", NOT_TESTED, "NAT64_PROBE_TARGET_REQUIRED",
                          "知名前缀探测需要一个显式 IPv4 观测点与一个本机 IPv6 地址", detail), detail
    if budget.expired():
        return _component("nat64", UNAVAILABLE, "TOTAL_BUDGET_EXCEEDED", "总时长预算用尽，未做 NAT64 探测", detail), detail
    point = ipv4_points[0]
    synthesized = str(ipaddress.IPv6Address(int(NAT64_WKP.network_address) + int(ipaddress.IPv4Address(point.host))))
    probe = sources.udp_binding or stun_binding
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
    sock.setblocking(False)
    detail["probeAttempted"] = True
    try:
        sock.bind((host6, 0))
        allowance = min(config.udp_probe_timeout, budget.remaining())
        await asyncio.wait_for(probe(sock, (synthesized, point.port), allowance), allowance + 0.05)
    except asyncio.TimeoutError:
        return _component("nat64", INSUFFICIENT, "NAT64_SYNTHESIZED_PROBE_NO_RESPONSE",
                          "合成地址没有回包；不能据此断言没有 NAT64", detail), detail
    except OSError:
        return _component("nat64", UNAVAILABLE, "NAT64_PROBE_SEND_FAILED", "无法向合成地址发送探测包", detail), detail
    finally:
        sock.close()
    detail["signs"] = "synthesized-probe-answered"
    return _component("nat64", DETERMINED, "NAT64_SIGNS_PRESENT",
                      "向 64:ff9b::/96 合成地址的探测收到了应答，存在 NAT64 迹象", detail), detail


# ------------------------------------------------------------- recommendations
def _item(rank, method, status, reason, plain):
    return {"rank": rank, "method": method, "status": status, "reason": reason, "plain": plain}


def recommendation_order(items):
    """Stable priority: IPv6 direct > gateway mapping > port prediction."""
    return sorted(items, key=lambda item: METHOD_ORDER.index(item["method"]))


def _recommend(addresses, routes, nat_component, inbound):
    items = []
    summary = addresses.detail if addresses.status == DETERMINED else None
    if summary is None:
        items.append(_item(1, IPV6_DIRECT, UNKNOWN, "ADDRESS_EVIDENCE_MISSING",
                           "本机地址没枚举出来，无法判断 IPv6 直连是否可行；请先补齐地址信息"))
    elif summary.get("hasGlobalV6Stable"):
        confirmed = inbound.status == DETERMINED and inbound.reason == "INBOUND_REACHED_BY_SERVER"
        items.append(_item(1, IPV6_DIRECT, RECOMMENDED, "INBOUND_CONFIRMED" if confirmed else "STABLE_GLOBAL_V6_PRESENT",
                           "有稳定的全局 IPv6 地址，优先直连"
                           + ("，且服务端回连成功" if confirmed else "；入站是否放行尚未验证（未测，不是失败）")))
    elif summary.get("hasGlobalV6TemporaryOnly"):
        items.append(_item(1, IPV6_DIRECT, POSSIBLE, "ONLY_TEMPORARY_GLOBAL_V6",
                           "只有临时全局 IPv6 地址，可能会轮换，只能当作短期路径"))
    elif summary.get("hasGlobalV6UnverifiedOnly"):
        items.append(_item(1, IPV6_DIRECT, POSSIBLE, "GLOBAL_V6_STABILITY_UNVERIFIED",
                           "有全局 IPv6 地址但拿不到临时/稳定标志，不可当作长期稳定路径"))
    else:
        items.append(_item(1, IPV6_DIRECT, UNAVAILABLE, "NO_GLOBAL_V6",
                           "本机没有全局 IPv6 地址，IPv6 直连暂不可用"))
    if routes.status == NOT_TESTED:
        items.append(_item(2, GATEWAY_MAPPING, UNKNOWN, "ROUTE_EVIDENCE_MISSING",
                           "读不到默认路由，无法判断网关注册放行是否有意义"))
    elif routes.detail.get("ipv4GatewayPresent") or routes.detail.get("ipv6GatewayPresent"):
        items.append(_item(2, GATEWAY_MAPPING, POSSIBLE, "GATEWAY_PRESENT_OPT_IN_REQUIRED",
                           "存在默认网关，可在用户明确同意后尝试网关注册放行（默认关闭）"))
    else:
        items.append(_item(2, GATEWAY_MAPPING, UNAVAILABLE, "NO_DEFAULT_GATEWAY",
                           "本机没有默认网关，网关注册放行不适用"))
    mapping = nat_component.detail.get("mapping") if nat_component.status == DETERMINED else None
    if nat_component.status == NOT_TESTED:
        items.append(_item(3, PORT_PREDICTION, NOT_TESTED, nat_component.reason, "没有观测点，端口预测适用性未测"))
    elif mapping == nat.MAPPING_ADDRESS_AND_PORT_DEPENDENT:
        items.append(_item(3, PORT_PREDICTION, POSSIBLE, "SYMMETRIC_MAPPING_OBSERVED",
                           "观测到地址+端口相关映射（对称型），前两条都不行时端口预测是合理后备"))
    elif mapping is not None:
        items.append(_item(3, PORT_PREDICTION, UNAVAILABLE, "MAPPING_NOT_SYMMETRIC",
                           "映射行为不是对称型，正常打洞比端口预测更合适"))
    else:
        items.append(_item(3, PORT_PREDICTION, UNKNOWN, "NAT_BEHAVIOR_EVIDENCE_INSUFFICIENT",
                           "NAT 行为无法判定，端口预测是否可行未知；不要据此下结论"))
    return recommendation_order(items)


def _overall(components):
    blocking, determined, resolved = [], 0, 0
    for name in COMPONENTS:
        component = components[name]
        if component.status == DETERMINED:
            determined += 1
            resolved += 1
        elif component.status == NOT_APPLICABLE:
            resolved += 1
        else:
            blocking.append(f"{name}:{component.status}:{component.reason}")
    if determined == 0:
        status = NOT_TESTED
    elif resolved == len(COMPONENTS):
        status = DETERMINED
    else:
        status = INSUFFICIENT
    return {"status": status, "reasons": blocking[:MAX_ERRORS],
            "coverage": {"determined": determined, "resolved": resolved, "total": len(COMPONENTS)}}


# ----------------------------------------------------------------- public API
async def health_check(config=None, *, sources=None):
    """Run one bounded environment check and return a NetEnvReport."""
    config = (config or NetEnvConfig()).validate()
    sources = sources or Sources()
    budget = _Budget(config.total_budget_seconds, sources.monotonic)
    errors: list = []
    checked_at_ms = sources.wall() * 1000
    addresses, records = _addresses_component(config, sources, errors)
    routes = _routes_component(config, sources)
    hosts, host_source = _pick_bind_hosts(config, records, addresses.status)
    config = replace(config, bind_host_v4=hosts[4], bind_host_v6=hosts[6]).validate()
    udp = await _udp_egress(config, sources, budget, errors)
    nat_component = await _nat_component(config, sources, budget, hosts, errors)
    ipv6_only_component = _ipv6_only_component(addresses, routes)
    inbound = await _inbound_component(config, sources, budget, errors)
    nat64, _ = await _nat64_component(config, sources, budget, addresses, ipv6_only_component.detail or {},
                                      hosts, errors)
    components = {"addresses": addresses, "routes": routes, "udpEgress": udp, "natBehavior": nat_component,
                  "inboundReachability": inbound, "ipv6Only": ipv6_only_component, "nat64": nat64}
    return NetEnvReport(components=components, recommendations=_recommend(addresses, routes, nat_component, inbound),
                        overall=_overall(components), duration_ms=budget.elapsed() * 1000,
                        checked_at_ms=checked_at_ms,
                        config_view={"observationPointCount": len(config.observation_points),
                                     "inboundProbe": config.inbound_probe, "consent": config.consent,
                                     "nat64Probe": config.nat64_probe,
                                     "totalBudgetSeconds": config.total_budget_seconds,
                                     "bindHostSource": host_source,
                                     "bindFamilies": sorted(family for family in (4, 6) if hosts[family])},
                        errors=errors[:MAX_ERRORS], errors_truncated=len(errors) > MAX_ERRORS,
                        identity={"session": config.session or None,
                                  "connectionId": config.connection_id or None,
                                  "attemptId": config.attempt_id or None})


def run_sync(config=None, *, sources=None):
    """Blocking convenience wrapper for callers without an event loop."""
    return asyncio.run(health_check(config, sources=sources))
