"""Client-side IPv6 inbound reachability probe (native, UI-free).

What it does, and what it deliberately does not do:

* It enumerates the machine's own IPv6 addresses and distinguishes **stable** global
  addresses from **RFC 4941 temporary** ones and from link-local/loopback/ULA ones.
  A temporary address may rotate at any time, so a callback result measured on it is
  only valid for that moment; that is stated in the verdict instead of being hidden.
* It opens a **short-lived HTTP listener** on the chosen address and an ephemeral port.
  Only a request carrying the one-time token is accepted, the response body is always
  empty (the listener proves reachability and serves no data), the listener never binds
  ``::``/``0.0.0.0`` unless the caller explicitly allows it, and it is always closed
  (port released) when the probe finishes.
* It never scans, never contacts third parties, and reports honestly: "no address" is
  never reported as "firewall", and an unmeasured probe is never reported as a pass.

The peer/server side (task t47) receives ``SIGNAL_TYPE`` over signaling, tries to call
back, and returns ``SIGNAL_RESULT_TYPE``. Both sides log the same fields (see
``LOG_FIELDS``); the full address is only logged when the user agreed to share it,
otherwise just the prefix length and the scope are recorded.

Result contract (aligned with the live server)
----------------------------------------------
The server's ``code``/``ok`` is the **authoritative** conclusion; its ``verdict`` is
only a convenience word and must agree with ``code``. ``CONNECTION_REFUSED``,
``TOKEN_MISMATCH`` and ``REJECTED_BY_POLICY`` are decoded into their own client
verdicts - they are never folded into ``TIMEOUT``/``NO_V6_ROUTE``/a success. A word
this module does not know raises ``UNRECOGNIZED_REACH_CODE`` from
``parse_reach_verdict`` and ends a probe as ``RESULT_UNRECOGNIZED`` ("don't
understand" is stated, never guessed); disagreeing fields raise
``INCONSISTENT_REACH_VERDICT`` instead of silently picking one.

Central log
-----------
``telemetry_payload``/``emit_telemetry`` project a conclusion onto the existing
telemetry allowlist (``path.state`` plus state/reason/ok/family/mechanism/protocol and
a probe-round-trip ``rttMs``), using exactly the ``(state, reason)`` pairs the server
writes for the same conclusion so the two sides merge. Pass ``telemetry_store`` to
``probe_reachability`` and the conclusion is really written (see
``ReachProbe.telemetry_event_id``); ``rttMs`` here is the offer-to-conclusion probe
round trip and is never chat latency.
"""
from __future__ import annotations

import asyncio
import hmac
import ipaddress
import os
import re
import secrets
import socket
import subprocess
import time
from dataclasses import dataclass, field, replace

# --------------------------------------------------------------------- verdicts
REACHED_BY_SERVER = "REACHED_BY_SERVER"
TIMEOUT = "TIMEOUT"
REFUSED_BY_LOCAL_POLICY = "REFUSED_BY_LOCAL_POLICY"
NO_GLOBAL_V6 = "NO_GLOBAL_V6"
NO_V6_ROUTE = "NO_V6_ROUTE"
ADDRESS_ROTATED = "ADDRESS_ROTATED"
# Server-reported refusals keep their own names: folding "the port refused" or "the
# token did not match" into TIMEOUT/NO_V6_ROUTE/a success would be a lie. "We could
# not read the server's word" is also its own name, never a guess.
CONNECTION_REFUSED = "CONNECTION_REFUSED"
TOKEN_MISMATCH = "TOKEN_MISMATCH"
REJECTED_BY_POLICY = "REJECTED_BY_POLICY"
RESULT_UNRECOGNIZED = "RESULT_UNRECOGNIZED"
VERDICTS = (REACHED_BY_SERVER, TIMEOUT, REFUSED_BY_LOCAL_POLICY, NO_GLOBAL_V6, NO_V6_ROUTE, ADDRESS_ROTATED,
            CONNECTION_REFUSED, TOKEN_MISMATCH, REJECTED_BY_POLICY, RESULT_UNRECOGNIZED)
# A "pass" must never be inferred: only a callback we observed (or that the server
# reported with a matching token) counts.
POSITIVE_VERDICTS = frozenset({REACHED_BY_SERVER})

# ------------------------------------------- server result contract (t47, live)
# The server's `v6-reach-result` carries `code` + `ok` as the AUTHORITATIVE conclusion
# and fills `verdict` only for the words that have an honest client counterpart
# (server.py's INBOUND_CHECK_CLIENT_VERDICT). A word we do not know is refused by the
# parser and surfaced as RESULT_UNRECOGNIZED by the probe - never guessed.
SERVER_RESULT_CODES = ("REACHABLE", "TIMEOUT", "CONNECTION_REFUSED", "UNREACHABLE_NO_ROUTE",
                       "TOKEN_MISMATCH", "REJECTED_BY_POLICY")
SERVER_CODE_VERDICT = {
    "REACHABLE": REACHED_BY_SERVER,
    "TIMEOUT": TIMEOUT,
    "UNREACHABLE_NO_ROUTE": NO_V6_ROUTE,
    "CONNECTION_REFUSED": CONNECTION_REFUSED,
    "TOKEN_MISMATCH": TOKEN_MISMATCH,
    "REJECTED_BY_POLICY": REJECTED_BY_POLICY,
}
#: Central-log projection: for every server code this is exactly the (state, reason)
#: pair the server writes for the same conclusion (server.py's INBOUND_CHECK_LOG), so
#: the two sides' records merge; the client-local verdicts get their own allowlisted
#: pairs. Keys and values must stay inside the backend telemetry allowlist.
CLIENT_VERDICT_LOG = {
    REACHED_BY_SERVER: ("completed", None),
    TIMEOUT: ("timeout", "TIMEOUT"),
    CONNECTION_REFUSED: ("failed", "CLOSED"),
    NO_V6_ROUTE: ("failed", "ENDPOINT_UNOBSERVABLE"),
    TOKEN_MISMATCH: ("failed", "AUTH_FAILED"),
    REJECTED_BY_POLICY: ("unsupported", "SCHEMA_INVALID"),
    REFUSED_BY_LOCAL_POLICY: ("unsupported", "SCHEMA_INVALID"),
    NO_GLOBAL_V6: ("unsupported", "UNSUPPORTED"),
    ADDRESS_ROTATED: ("failed", "ENDPOINT_UNOBSERVABLE"),
    RESULT_UNRECOGNIZED: ("failed", "SCHEMA_INVALID"),
}
SERVER_CODE_LOG = {code: CLIENT_VERDICT_LOG[verdict] for code, verdict in SERVER_CODE_VERDICT.items()}
#: Event name both sides use for a reachability conclusion's central-log record.
TELEMETRY_EVENT = "path.state"

# --------------------------------------------------------------- address kinds
STABLE = "stable"
TEMPORARY = "temporary"
UNVERIFIED = "unverified"
LINK_LOCAL = "link-local"
LOOPBACK = "loopback"
ULA = "ula"
MULTICAST = "multicast"
UNSPECIFIED = "unspecified"
OTHER = "other"
ADDRESS_TYPES = (STABLE, TEMPORARY, UNVERIFIED, LINK_LOCAL, LOOPBACK, ULA, MULTICAST, UNSPECIFIED, OTHER)
IPV6_GLOBAL = ipaddress.IPv6Network("2000::/3")
TEMPORARY_NOTE = "地址可能轮换，回连结果只对当前时刻成立"
TEMPORARY_ADVICE = "需要稳定入站时，请让路由器/运营商下发稳定的公网 IPv6 前缀，或只用网关显式放行；不要用临时地址的结论判断长期可达性。"
UNVERIFIED_NOTE = "拿不到 RFC 4941 临时地址标志，无法确认该地址是稳定还是临时，不得当作稳定地址"
UNVERIFIED_ADVICE = "先用 `ip -6 addr`（Linux/Android）或系统工具确认该地址是否带 temporary/dynamic 标志，再决定是否依赖它。"
STABLE_ADVICE = "稳定全局地址上的结论可以被引用；仍建议在真实家宽上复测，因为入站是否放行取决于运营商与防火墙。"

# ------------------------------------------------------------- signaling names
SIGNAL_TYPE = "v6-reach"                 # client -> server offer
SIGNAL_RESULT_TYPE = "v6-reach-result"   # server -> client conclusion
REACH_PATH = "/p2p-reach"
OFFER_FIELDS = ("v", "type", "connectionId", "attemptId", "session", "address", "addressType",
                "scope", "prefixLength", "port", "token", "mechanism", "expiresInMs", "fullAddressShared")
RESULT_FIELDS = ("v", "type", "connectionId", "attemptId", "verdict", "code", "ok", "token", "port",
                 "addressType", "elapsedMs", "failureCode", "note")
#: Central-log schema shared by both sides: same names, correlatable, redacted.
LOG_FIELDS = ("event", "connectionId", "attemptId", "session", "addressType", "scope",
              "prefixLength", "port", "verdict", "tokenConsumed", "rejected", "note")
_SESSION_RE = re.compile(r"^[A-Za-z0-9_.:-]{0,100}$")


class ReachError(ValueError):
    """Stable enumerated error for bad reach messages/config (never echoes payloads)."""


@dataclass(frozen=True)
class Ipv6Address:
    """One address as reported by the OS, with the flags we could actually observe."""

    address: str
    interface: str = ""
    scope: str = "global"
    temporary: bool | None = None      # None = 系统没给 RFC 4941 标志（不得当成稳定）
    deprecated: bool = False
    dynamic: bool = False              # SLAAC 自动配置；dynamic 不等于 RFC 4941 temporary
    prefix_length: int | None = None
    preferred_lft: int | None = None
    valid_lft: int | None = None

    @property
    def network_prefix(self) -> str:
        return str(ipaddress.IPv6Address(self.address))

    def kind(self) -> str:
        if self.scope in {LOOPBACK, LINK_LOCAL, ULA, MULTICAST, UNSPECIFIED}:
            return self.scope
        if self.temporary is True:
            return TEMPORARY
        if self.temporary is False:
            return STABLE
        return UNVERIFIED

    def is_global(self) -> bool:
        try:
            return ipaddress.IPv6Address(self.address) in IPV6_GLOBAL
        except ValueError:
            return False


@dataclass
class AddressChoice:
    """What the probe will offer, plus the honesty note that goes with it."""

    record: Ipv6Address | None = None
    address_type: str = "none"
    note: str = ""
    advice: str = ""
    counts: dict = field(default_factory=dict)

    @property
    def usable(self) -> bool:
        return self.record is not None


# ------------------------------------------------------------------ enumeration
def classify_scope(address):
    """Scope/kind of a literal IPv6 address; raises ValueError for non-literals."""
    ip = ipaddress.IPv6Address(address)
    if ip.is_unspecified:
        return UNSPECIFIED
    if ip.is_multicast:
        return MULTICAST
    if ip.is_loopback:
        return LOOPBACK
    if ip.is_link_local:
        return LINK_LOCAL
    if ip in ipaddress.IPv6Network("fc00::/7"):
        return ULA
    return "global"


def parse_lifetime(value):
    """`ip -6 addr` lifetime: '3600sec'/'forever'/'1d2h' -> seconds, None if unknown."""
    if value is None:
        return None
    text = str(value).strip().lower()
    if text in {"forever", "infinity"}:
        return None
    match = re.fullmatch(r"(\d+)sec", text)
    if match:
        return int(match.group(1))
    match = re.fullmatch(r"(\d+)d(\d+)h", text)
    if match:
        return int(match.group(1)) * 86400 + int(match.group(2)) * 3600
    return None


def parse_ip_addr_output(text):
    """Parse `ip -6 addr show` into Ipv6Address records (temporary/deprecated flags).

    This is the Linux/Android source of truth for RFC 4941 state: the flags are only
    visible here (and via getifaddrs on platforms that expose them), so a source that
    cannot report them must not be treated as "stable". Lifetimes may be inline or on
    the indented continuation line the tool normally prints.
    """
    records, interface, last = [], "", None
    lifetime_re = re.compile(r"valid_lft\s+(\S+)\s+preferred_lft\s+(\S+)")
    for line in str(text or "").splitlines():
        header = re.match(r"^\d+:\s+([^:@\s]+)[:@]", line)
        if header:
            interface, last = header.group(1), None
            continue
        body = line.strip()
        if body.startswith("inet6 "):
            parts = body.split()
            literal = parts[1]
            address = literal.split("/")[0]
            prefix = int(literal.split("/")[1]) if "/" in literal else None
            flags, scope, life = [], "global", (None, None)
            index = 2
            while index < len(parts):
                token = parts[index]
                if token == "scope" and index + 1 < len(parts):
                    scope = parts[index + 1]
                    index += 2
                    continue
                if token.startswith("valid_lft") and index + 1 < len(parts):
                    life = (parse_lifetime(parts[index + 1]), life[1])
                    index += 2
                    continue
                if token.startswith("preferred_lft") and index + 1 < len(parts):
                    life = (life[0], parse_lifetime(parts[index + 1]))
                    index += 2
                    continue
                flags.append(token)
                index += 1
            # Only the explicit `temporary` flag marks an RFC 4941 privacy address;
            # `dynamic`/`mngtmpaddr` alone only says the address came from SLAAC.
            temporary = "temporary" in flags  # `ip` always reports the RFC 4941 flag state
            records.append(Ipv6Address(address=address, interface=interface, scope=scope,
                                       temporary=temporary, deprecated="deprecated" in flags,
                                       dynamic="dynamic" in flags, prefix_length=prefix,
                                       preferred_lft=life[1], valid_lft=life[0]))
            last = len(records) - 1
            continue
        match = lifetime_re.search(body) if last is not None else None
        if match:
            records[last] = replace(records[last], valid_lft=parse_lifetime(match.group(1)),
                                    preferred_lft=parse_lifetime(match.group(2)))
            last = None
    return records


def parse_ipconfig_output(text):
    """Best-effort Windows `ipconfig` parser (temporary state is not exposed there)."""
    records = []
    for block in re.split(r"\r?\n(?=\S)", str(text or "")):
        header = re.match(r"^(\S.*?)\s*:", block)
        if not header:
            continue
        interface = header.group(1).strip()
        for match in re.finditer(r"(?:IPv6 Address|IPv6 \u5730\u5740)[^:]*:\s*([0-9A-Fa-f:]+)(?:%(\d+))?", block):
            address = match.group(1)
            try:
                scope = classify_scope(address)
            except ValueError:
                continue
            if scope == MULTICAST:
                continue
            records.append(Ipv6Address(address=address, interface=interface, scope=scope, temporary=None))
    return records


def enumerate_via_getifaddrs():
    """Portable fallback (Python 3.13+); flags are unavailable there -> temporary=None."""
    getter = getattr(socket, "getifaddrs", None)
    if getter is None:
        return None
    records = []
    for entry in getter():
        if entry.family != socket.AF_INET6:
            continue
        address = entry.address[0].split("%")[0]
        try:
            scope = classify_scope(address)
        except ValueError:
            continue
        records.append(Ipv6Address(address=address, interface=entry.name, scope=scope, temporary=None))
    return records


def run_ip_command():
    """Run `ip -6 addr show` without a shell; no other command is ever invoked.

    The encoding is explicit: a default-encoding `text=True` subprocess raises
    `EncodingWarning` under the project's encoding gate, and the platform default is
    not UTF-8 everywhere (Windows cp1252). Undecodable bytes become replacement
    characters instead of crashing the enumeration.
    """
    for command in (["ip", "-6", "addr", "show"], ["ip", "addr", "show"]):
        try:
            result = subprocess.run(command, capture_output=True, text=True, timeout=2, check=False,
                                    encoding="utf-8", errors="replace")
        except (OSError, subprocess.SubprocessError):
            continue
        if result.returncode == 0 and "inet6" in (result.stdout or ""):
            return result.stdout
    return None


def enumerate_addresses(runner=None):
    """All local IPv6 addresses: `ip` if available, else getifaddrs, else ipconfig."""
    if runner is not None:
        return list(runner())
    text = run_ip_command()
    if text:
        return parse_ip_addr_output(text)
    fallback = enumerate_via_getifaddrs()
    if fallback is not None:
        return fallback
    try:
        result = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=2, check=False,
                                encoding="utf-8", errors="replace")
    except (OSError, subprocess.SubprocessError):
        return []
    return parse_ipconfig_output(result.stdout)


def has_default_v6_route(route_text=None):
    """True when the host has an IPv6 default route (no global address => still NO_GLOBAL_V6)."""
    if route_text is not None:
        for line in str(route_text).splitlines():
            parts = line.split()
            if len(parts) >= 2 and set(parts[0]) == {"0"} and parts[1] == "00":
                return True
        return False
    path = "/proc/net/ipv6_route"
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                return has_default_v6_route(handle.read())
        except OSError:
            pass
    # No routing table to read: ask the kernel without sending a packet.
    try:
        probe = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        probe.connect(("2001:4860:4860::8888", 53))
        return True
    except OSError:
        return False
    finally:
        probe.close()


def select_address(records, allow_temporary=True):
    """Pick the address to offer: stable global > unverified global > temporary global."""
    counts = {kind: 0 for kind in ADDRESS_TYPES}
    candidates = []
    for record in records:
        kind = record.kind()
        counts[kind] = counts.get(kind, 0) + 1
        if record.is_global() and not record.deprecated:
            candidates.append(record)
    stable = [record for record in candidates if record.kind() == STABLE]
    unverified = [record for record in candidates if record.kind() == UNVERIFIED]
    temporary = [record for record in candidates if record.kind() == TEMPORARY]
    counts["global"] = len(candidates)
    if stable:
        return AddressChoice(record=stable[0], address_type=STABLE, note="使用稳定全局地址", advice=STABLE_ADVICE, counts=counts)
    if unverified:
        return AddressChoice(record=unverified[0], address_type=UNVERIFIED, note=UNVERIFIED_NOTE, advice=UNVERIFIED_ADVICE, counts=counts)
    if temporary and allow_temporary:
        return AddressChoice(record=temporary[0], address_type=TEMPORARY, note=TEMPORARY_NOTE, advice=TEMPORARY_ADVICE, counts=counts)
    if temporary:
        return AddressChoice(record=None, address_type=TEMPORARY,
                             note=f"{TEMPORARY_NOTE}；本次策略不允许使用临时地址", advice=TEMPORARY_ADVICE, counts=counts)
    return AddressChoice(record=None, address_type="none",
                         note="本机没有全局 IPv6 地址（只有链路本地/回环/ULA 或什么都没枚举到）",
                         advice="请确认运营商/路由器是否下发公网 IPv6 前缀；这不是防火墙结论。", counts=counts)


# ------------------------------------------------------------------- the probe
@dataclass
class ReachOptions:
    consent: bool = False
    connection_id: str = ""
    attempt_id: str = ""
    session: str = ""
    timeout: float = 8.0
    port: int = 0
    allow_wildcard: bool = False
    allow_temporary: bool = True
    share_full_address: bool = False
    max_request_bytes: int = 8192
    max_connections: int = 4
    watch_interval: float = 0.3
    wait_interval: float = 0.02

    def validate(self):
        for name in ("connection_id", "attempt_id", "session"):
            value = getattr(self, name)
            if not isinstance(value, str) or not _SESSION_RE.match(value):
                raise ReachError("INVALID_REACH_CONFIG")
        if not isinstance(self.timeout, (int, float)) or not 0 < float(self.timeout) <= 120:
            raise ReachError("INVALID_REACH_CONFIG")
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 0 <= self.port <= 65535:
            raise ReachError("INVALID_REACH_CONFIG")
        if not isinstance(self.max_request_bytes, int) or not 128 <= self.max_request_bytes <= 65536:
            raise ReachError("INVALID_REACH_CONFIG")
        return self


@dataclass
class ReachProbe:
    """Result of one probe attempt; every field is measured, never assumed."""

    verdict: str
    address: str | None = None
    port: int | None = None
    address_type: str | None = None
    connection_id: str = ""
    attempt_id: str = ""
    session: str = ""
    note: str = ""
    advice: str = ""
    offer: dict | None = None
    result: dict | None = None
    counts: dict = field(default_factory=dict)
    reached: bool = False
    valid_requests: int = 0
    rejected_requests: int = 0
    listening: bool = False
    #: Offer-to-conclusion duration of this probe (a probe round trip, never chat latency).
    elapsed_ms: float | None = None
    #: Id of the allowlisted telemetry record, when the caller supplied a store.
    telemetry_event_id: str | None = None

    def log_event(self, event, share_full_address=False):
        """Central-log payload; the full address only with explicit user consent."""
        return log_fields(event, connection_id=self.connection_id, attempt_id=self.attempt_id,
                          session=self.session,
                          address_type=self.address_type, scope=(self.offer or {}).get("scope"),
                          prefix_length=(self.offer or {}).get("prefixLength"), port=self.port,
                          verdict=self.verdict, token_consumed=self.valid_requests > 0,
                          rejected=self.rejected_requests, note=self.note,
                          address=self.address, share_full_address=share_full_address)


class ReachListener:
    """Short-lived HTTP listener that only proves reachability with a one-time token."""

    def __init__(self, address, *, token, port=0, host=None, max_request_bytes=8192, max_connections=4):
        self.address = address
        self.host = host or address
        self.token = token
        self.port = port
        self.max_request_bytes = max_request_bytes
        self.max_connections = max_connections
        self.server = None
        self.reached = asyncio.Event()
        self.valid_requests = 0
        self.rejected_requests = 0
        self._consumed = False
        self._in_flight = 0
        self._sockets = []
        self._listen_socket = None

    def bound_socket(self):
        """The listening socket, for tests that assert the exact bound address."""
        return self._sockets[0] if self._sockets else None

    async def start(self):
        # The listener socket is created (and later closed) explicitly, so "the port
        # is really released" is a property we control and tests can assert.
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.host, self.port))
        sock.listen(self.max_connections)
        sock.setblocking(False)
        self._listen_socket = sock
        self._sockets = [sock]
        self.port = sock.getsockname()[1]
        self.server = await asyncio.start_server(self._handle, sock=sock, limit=self.max_request_bytes)
        return self.address, self.port

    async def close(self):
        if self.server is not None:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:  # never mask the verdict with a shutdown error
                pass
            self.server = None
        if self._listen_socket is not None:
            self._listen_socket.close()
            self._listen_socket = None
        self._sockets = []

    def _request_line(self, data):
        head = data.split(b"\r\n\r\n", 1)[0]
        lines = head.split(b"\r\n")
        return lines[0].decode("latin-1") if lines else ""

    async def _handle(self, reader, writer):
        self._in_flight += 1
        try:
            if self._in_flight > self.max_connections:
                writer.close()
                return
            try:
                async with asyncio.timeout(2):
                    data = await reader.read(self.max_request_bytes)
            except (asyncio.TimeoutError, ConnectionError):
                writer.close()
                return
            request_line = self._request_line(data)
            method, _, rest = request_line.partition(" ")
            target = rest.split(" ", 1)[0]  # request-target only: never the HTTP version
            token = ""
            if "?" in target:
                query = target.split("?", 1)[1]
                for pair in query.split("&"):
                    key, _, value = pair.partition("=")
                    if key == "token":
                        token = value
            accepted = (method == "GET" and target.split("?", 1)[0] == REACH_PATH
                        and bool(token) and hmac.compare_digest(token, self.token) and not self._consumed)
            if accepted:
                self._consumed = True          # 一次性：同一个 token 不再接受
                self.valid_requests += 1
                writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                self.reached.set()
            elif method != "GET":
                self.rejected_requests += 1
                writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            else:
                self.rejected_requests += 1
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
        except (ConnectionError, OSError):
            self.rejected_requests += 1
        finally:
            self._in_flight -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except (ConnectionError, OSError):
                pass


def build_offer(options, choice, port, token, *, now=None, expires_in_ms=None):
    """The signaling offer. The address is needed for the callback; logging is separate."""
    record = choice.record
    return {"v": 1, "type": SIGNAL_TYPE, "connectionId": options.connection_id,
            "attemptId": options.attempt_id, "session": options.session,
            "address": record.address, "addressType": choice.address_type, "scope": record.scope,
            "prefixLength": record.prefix_length, "port": port, "token": token,
            "mechanism": "ipv6-inbound", "expiresInMs": int((expires_in_ms if expires_in_ms is not None else options.timeout * 1000)),
            "fullAddressShared": bool(options.share_full_address)}


def parse_reach_verdict(payload, *, token=None):
    """Parse the server's callback conclusion; unknown shapes never become a pass.

    The server's ``code``/``ok`` are the authoritative conclusion (t47 contract);
    ``verdict`` is its optional convenience word and must agree with ``code``. A word
    in the shared vocabulary is decoded to the matching client verdict; a word we do
    not know raises ``UNRECOGNIZED_REACH_CODE`` ("don't understand" is never guessed
    into TIMEOUT, NO_V6_ROUTE or a success), and fields that disagree raise
    ``INCONSISTENT_REACH_VERDICT`` instead of silently picking one of them.
    """
    if not isinstance(payload, dict):
        raise ReachError("INVALID_REACH_VERDICT")
    if set(payload) - set(RESULT_FIELDS):
        raise ReachError("INVALID_REACH_VERDICT")
    if payload.get("v") != 1 or payload.get("type") != SIGNAL_RESULT_TYPE:
        raise ReachError("INVALID_REACH_VERDICT")
    for name in ("connectionId", "attemptId"):
        value = payload.get(name)
        if not isinstance(value, str) or not _SESSION_RE.match(value):
            raise ReachError("INVALID_REACH_VERDICT")
    code, word, ok = payload.get("code"), payload.get("verdict"), payload.get("ok")
    if code is None and word is None:
        raise ReachError("UNRECOGNIZED_REACH_CODE")
    if code is not None:
        if not isinstance(code, str) or code not in SERVER_RESULT_CODES:
            raise ReachError("UNRECOGNIZED_REACH_CODE")
        verdict = SERVER_CODE_VERDICT[code]
        expected_ok = code == "REACHABLE"
    else:
        if not isinstance(word, str) or word not in VERDICTS:
            raise ReachError("UNRECOGNIZED_REACH_CODE")
        verdict = word
        expected_ok = word in POSITIVE_VERDICTS
    if word is not None and word != verdict:
        raise ReachError("INCONSISTENT_REACH_VERDICT")
    if ok is not None and (not isinstance(ok, bool) or ok != expected_ok):
        raise ReachError("INCONSISTENT_REACH_VERDICT")
    if token is not None and payload.get("token") not in (None, token):
        raise ReachError("REACH_TOKEN_MISMATCH")
    return {"verdict": verdict, "code": code, "ok": expected_ok,
            "note": str(payload.get("note", ""))[:200], "elapsedMs": payload.get("elapsedMs"),
            "failureCode": payload.get("failureCode", ""), "tokenConsumed": payload.get("token") == token}


def log_fields(event, *, connection_id="", attempt_id="", session="", address_type=None, scope=None,
               prefix_length=None, port=None, verdict=None, token_consumed=False, rejected=0, note="",
               address=None, share_full_address=False):
    """Shared central-log record: correlatable by session+attempt, redacted by default."""
    record = {"event": event, "connectionId": connection_id, "attemptId": attempt_id, "session": session,
              "addressType": address_type, "scope": scope, "prefixLength": prefix_length, "port": port,
              "verdict": verdict, "tokenConsumed": bool(token_consumed), "rejected": int(rejected),
              "note": str(note)[:200]}
    if share_full_address and address:
        record["address"] = address
    return record


def telemetry_payload(verdict, *, rtt_ms=None, error=None):
    """Project one conclusion onto the existing telemetry allowlist.

    This mirrors what the server writes for the same conclusion (same ``state`` and
    ``reason`` pairs), which is what lets the two sides' records be merged. Every key
    here is in ``backend/telemetry.py``'s allowlist, so a client store keeps the row
    instead of silently dropping unknown keys.
    """
    if verdict not in CLIENT_VERDICT_LOG:
        raise ReachError("UNRECOGNIZED_REACH_VERDICT")
    state, reason = CLIENT_VERDICT_LOG[verdict]
    data = {"state": state, "family": 6, "ok": verdict in POSITIVE_VERDICTS,
            "mechanism": "tcp", "protocol": "tcp"}
    if reason is not None:
        data["reason"] = reason
    if rtt_ms is not None:
        data["rttMs"] = rtt_ms
    if error:
        data["error"] = error
    return data


def emit_telemetry(store, probe, *, rtt_ms=None, error=None):
    """Write one conclusion into an existing telemetry store; returns the stored event.

    ``store`` is the caller's store/queue (``backend.telemetry.LocalQueue`` exposes
    ``emit(kind, data, connection_id=..., attempt_id=...)``); the emitted record uses
    only allowlisted keys, so it survives both the local queue and the server's strict
    ingest instead of being dropped or rejected. Failures propagate: a reachability
    probe must not look successfully logged when the log write failed.
    """
    verdict = getattr(probe, "verdict", probe)
    if verdict not in CLIENT_VERDICT_LOG:
        raise ReachError("UNRECOGNIZED_REACH_VERDICT")
    if rtt_ms is None:
        rtt_ms = getattr(probe, "elapsed_ms", None)
    return store.emit(TELEMETRY_EVENT, telemetry_payload(verdict, rtt_ms=rtt_ms, error=error),
                      connection_id=getattr(probe, "connection_id", None) or None,
                      attempt_id=getattr(probe, "attempt_id", None) or None)


async def probe_reachability(options=None, *, provider=None, route_check=None, on_event=None,
                             on_listening=None, verdict_waiter=None, listener_factory=None,
                             token=None, clock=time.monotonic, telemetry_store=None):
    """Run one inbound-reachability probe and return an honest verdict.

    Only the user's explicit consent (``options.consent``) opens a listener. The
    verdict is one of ``VERDICTS``; "no address" and "no route" are never reported as
    a firewall problem and nothing is reported as reachable without a real callback
    (or a matching server verdict carrying the same one-time token).

    When ``telemetry_store`` is given, the conclusion is also written there as one
    allowlisted ``path.state`` event (the same fields the server logs), so a probe is
    never only a local variable.
    """
    probe = await _run_reach_probe(options, provider=provider, route_check=route_check, on_event=on_event,
                                   on_listening=on_listening, verdict_waiter=verdict_waiter,
                                   listener_factory=listener_factory, token=token, clock=clock)
    if telemetry_store is not None:
        recorded = emit_telemetry(telemetry_store, probe)
        probe.telemetry_event_id = recorded.get("id") if isinstance(recorded, dict) else None
    return probe


async def _run_reach_probe(options=None, *, provider=None, route_check=None, on_event=None,
                           on_listening=None, verdict_waiter=None, listener_factory=None,
                           token=None, clock=time.monotonic):
    """The probe itself. Returns a ReachProbe; never infers a pass from silence."""
    options = (options or ReachOptions()).validate()
    if not options.consent:
        # Local policy refuses before any socket is created.
        return ReachProbe(verdict=REFUSED_BY_LOCAL_POLICY, connection_id=options.connection_id,
                          attempt_id=options.attempt_id, session=options.session,
                          note="本地策略未同意：没有用户显式同意就不会对外监听",
                          advice="需要入站探测时请在本会话内显式同意；默认关闭。")

    records = list(enumerate_addresses(provider))
    choice = select_address(records, allow_temporary=options.allow_temporary)
    counts = dict(choice.counts)
    if not choice.usable:
        return ReachProbe(verdict=NO_GLOBAL_V6, address_type=choice.address_type, note=choice.note,
                          advice=choice.advice, counts=counts, connection_id=options.connection_id,
                          attempt_id=options.attempt_id, session=options.session)
    route = has_default_v6_route() if route_check is None else bool(route_check())
    if not route:
        return ReachProbe(verdict=NO_V6_ROUTE, address=choice.record.address, address_type=choice.address_type,
                          connection_id=options.connection_id, attempt_id=options.attempt_id,
                          session=options.session, note="本机没有 IPv6 默认路由", advice="先让本机拿到 IPv6 默认路由再探测；这不是入站被挡的结论。",
                          counts=counts)

    token = token or secrets.token_urlsafe(24)
    listen_host = "::" if options.allow_wildcard else choice.record.address
    listener = (listener_factory or ReachListener)(choice.record.address, token=token, port=options.port,
                                                   host=listen_host,
                                                   max_request_bytes=options.max_request_bytes,
                                                   max_connections=options.max_connections)
    await listener.start()
    bindings = [sock.getsockname() for sock in (listener._sockets or [])]
    if not options.allow_wildcard and any(binding[0] in {"::", "0.0.0.0"} for binding in bindings):
        await listener.close()
        return ReachProbe(verdict=REFUSED_BY_LOCAL_POLICY, connection_id=options.connection_id,
                          attempt_id=options.attempt_id, session=options.session,
                          note="拒绝绑定通配地址", counts=counts)
    offer = build_offer(options, choice, listener.port, token)
    probe = ReachProbe(verdict=TIMEOUT, address=choice.record.address, port=listener.port,
                       address_type=choice.address_type, note=choice.note, advice=choice.advice,
                       offer=offer, counts=counts, listening=True, connection_id=options.connection_id,
                       attempt_id=options.attempt_id, session=options.session)
    if on_event is not None:
        on_event("ipv6.reach.offer", log_fields("ipv6.reach.offer", connection_id=options.connection_id,
                                                attempt_id=options.attempt_id, session=options.session,
                                                address_type=choice.address_type, scope=choice.record.scope,
                                                prefix_length=choice.record.prefix_length, port=listener.port,
                                                verdict=None, note=choice.note, address=choice.record.address,
                                                share_full_address=options.share_full_address))
    if on_listening is not None:
        awaited = on_listening(offer)
        if asyncio.iscoroutine(awaited):
            await awaited

    waiter = asyncio.create_task(verdict_waiter(offer)) if verdict_waiter is not None else None
    started = clock()
    deadline = clock() + float(options.timeout)
    next_watch = clock() + float(options.watch_interval)
    while True:
        if listener.reached.is_set():
            probe.verdict = REACHED_BY_SERVER
            probe.reached = True
            probe.note = f"服务端用一次性 token 回连成功（{choice.address_type}）" + (
                f"；{TEMPORARY_NOTE}" if choice.address_type == TEMPORARY else "")
            break
        if waiter is not None and waiter.done():
            try:
                payload = waiter.result()
            except Exception:
                payload = None
            if payload is not None:
                try:
                    parsed = parse_reach_verdict(payload, token=token)
                except ReachError:
                    # "We do not understand this word" is its own outcome: it is never
                    # a pass, never a timeout, and the listener is still closed below.
                    probe.verdict = RESULT_UNRECOGNIZED
                    probe.note = "服务端回报的结论无法识别；看不懂就不猜，既不当作成功也不当作超时"
                    break
                probe.result = parsed
                probe.verdict = parsed["verdict"]
                probe.reached = parsed["verdict"] in POSITIVE_VERDICTS
                probe.note = parsed["note"] or f"服务端结论：{parsed['verdict']}"
                break
        if provider is not None and clock() >= next_watch and clock() < deadline:
            next_watch = clock() + float(options.watch_interval)
            current = {record.address for record in enumerate_addresses(provider)}
            if choice.record.address not in current:
                probe.verdict = ADDRESS_ROTATED
                probe.note = f"探测期间地址消失/轮换；{TEMPORARY_NOTE}" if choice.address_type == TEMPORARY else "探测期间地址消失/轮换"
                break
        if clock() >= deadline:
            probe.verdict = TIMEOUT
            probe.note = "服务端未能在时限内用一次性 token 回连（可能被防火墙或运营商入站策略挡住）"
            if choice.address_type in {TEMPORARY, UNVERIFIED}:
                probe.note += f"；{choice.note}"
            break
        await asyncio.sleep(options.wait_interval)

    if waiter is not None and not waiter.done():
        waiter.cancel()
        try:
            await waiter
        except (asyncio.CancelledError, Exception):
            pass
    probe.valid_requests = listener.valid_requests
    probe.rejected_requests = listener.rejected_requests
    probe.elapsed_ms = round((clock() - started) * 1000, 3)
    await listener.close()
    probe.listening = False
    if on_event is not None:
        on_event(f"ipv6.reach.{probe.verdict.lower()}", probe.log_event("ipv6.reach.verdict",
                                                                        share_full_address=options.share_full_address))
    return probe
