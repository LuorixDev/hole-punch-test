"""In-process desktop engine: one asyncio loop, reused peers, no relay.

Responsibilities
----------------
* reuse :class:`p2pchat.peer.Peer` unchanged for WebRTC/ICE, the authenticated
  echo and the data-channel message protocol;
* reuse :class:`p2pchat.native.NativeAdapter` in-process for UDP probe, QUIC,
  TCP and TCP simultaneous-open;
* own the one extra room membership needed to carry non-WebRTC signaling, because
  ``p2pchat.peer`` intentionally drops unknown mechanisms;
* expose a bounded, UI-agnostic event stream and a strict no-relay policy: a
  failed method stays failed and is reported with its real reason.

The only interface relied upon beyond the public classes is ``Peer``'s documented
``websocket_factory`` hook. Nothing in ``peer.py``, ``server.py`` or ``native/``
is modified by this package.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib
import ipaddress
import json
import os
import secrets
import socket as socket_module
import struct
import time
import uuid
from dataclasses import dataclass, field

from urllib.parse import urlparse

from aiohttp import ClientSession
from p2pchat.native.adapter import METHODS as NATIVE_METHODS, NativeAdapter
from p2pchat.peer import Peer, frame as peer_frame

from . import methods as plain
from .gateway_optin import GatewayOptIn, plain_reason
from .lan_client import LanDirect
from .native_session import MAX_FILE_BYTES, MAX_TEXT_BYTES, NativeSession
from .signal_session import SignalSession

WEBRTC_PROFILES = ("ice-dual", "ice-v6", "ice-v4")
DEFAULT_TIMEOUT_MS = 15000
MAX_PEERS = 12
MAX_MESSAGES = 500

# 路由器放行（UI 第 9 条）在适配器里以这几个 mechanism 上报；能力查询必须对齐到
# 同一个集合，否则查不到能力就会被误判成「不支持」。
GATEWAY_MECHANISMS = ("upnp", "pcp", "natpmp")

# Matches the wording shown in the UI: 最多 5 秒或 32 MiB.
BENCHMARK_MAX_BYTES = 32 * 1024 * 1024

# Plaintext ws:// is only acceptable to a literal loopback host, or after an
# explicit operator confirmation for this session. There is no trust-all mode.
PLAINTEXT_REFUSED_TEXT = (
    "公网服务器必须用加密的 wss://；只有本机地址才允许 ws://。"
    "如果确实要在这条未加密的连接上继续，需要你显式确认，并在会话期间一直显示未加密提示。"
)


def plaintext_risk(url: str) -> str | None:
    """Return a warning when this URL would carry the room secret unencrypted."""
    parsed = urlparse(url)
    if parsed.scheme != "ws":
        return None
    host = (parsed.hostname or "").strip("[]")
    if not host:
        return "服务器地址缺少主机名，无法确认是否安全。"
    if host == "localhost":
        return None
    try:
        if ipaddress.ip_address(host).is_loopback:
            return None
    except ValueError:
        pass
    return (
        f"这条连接用的是未加密的 ws://（{host}）：信令和房间密码在网络上都是明文，"
        "同一网络上的任何人都可能看到。只有确认这是你自己的可信服务器时才继续。"
    )


def validate_endpoint(url: str, allow_plaintext: bool) -> str | None:
    """Raise for an unconfirmed unencrypted endpoint; return the warning otherwise."""
    parsed = urlparse(url)
    if parsed.scheme not in {"ws", "wss"}:
        raise ValueError("UNSUPPORTED_URL_SCHEME")
    risk = plaintext_risk(url)
    if risk is None:
        return None
    if not allow_plaintext:
        raise ValueError("PLAINTEXT_REFUSED")
    return risk


# Both memberships of one desktop client join under the same name; the
# non-WebRTC one is suffixed so the roster stays unambiguous.
NATIVE_SUFFIX = "（原生方式）"
NATIVE_SELF_NAME = "本机原生信令"

# A failed ICE round is retried no faster than this; the server bounds attempts
# per peer, and an unbounded re-offer loop would starve other methods.
WEBRTC_RETRY_SECONDS = 20.0

_SHIM = {"engines": 0, "original": None}


@dataclass
class EngineConfig:
    url: str
    room: str
    secret: str
    name: str = "Explorer"
    bind_host: str = "127.0.0.1"
    data_dir: str = "desktop-data"
    origin: str | None = None
    stun_url: str | None = None
    echo: bool = False
    allow_native: bool = True
    # Plaintext ws:// to a non-loopback host is refused unless the operator
    # explicitly confirms it for this session. There is no trust-all mode.
    allow_plaintext: bool = False
    # Symmetric-NAT port prediction is OFF by default. When enabled it only ever
    # contacts these explicitly configured observation points (never discovered).
    prediction_enabled: bool = False
    prediction_points: tuple = ()


@dataclass
class MethodState:
    method_id: str
    mechanism: str
    state: str = "pending"
    failure: str | None = None
    rtt: float | None = None
    attempt: str | None = None
    capability: dict | None = None
    probe_only: bool = False
    detail: str = ""


@dataclass
class Target:
    """One remote client, however many room memberships it opened."""

    key: str
    name: str = ""
    webrtc_id: str | None = None
    native_id: str | None = None
    methods: dict = field(default_factory=dict)
    observation: dict = field(default_factory=dict)
    webrtc_started: bool = False
    webrtc_attempt_at: float = 0.0


@dataclass
class Message:
    direction: str
    peer: str
    kind: str
    id: str
    text: str = ""
    name: str = ""
    mime: str = ""
    bytes: int = 0
    data: bytes | None = None
    mechanism: str = ""
    at: float = 0.0


class _ClientSessionProxy:
    """Transparent session shim used by the reused ``p2pchat.peer`` code.

    ``peer.run`` builds its own ``aiohttp.ClientSession``, so the engine installs
    this in the peer module's namespace for the lifetime of the run. Only
    ``ws_connect`` differs: it wraps the socket. Everything else is delegated.
    """

    def __init__(self, engine: "DesktopEngine", inner: ClientSession, from_native: bool = False):
        self._engine = engine
        self._inner = inner
        self._from_native = from_native

    async def __aenter__(self):
        await self._inner.__aenter__()
        return self

    async def __aexit__(self, *exc):
        return await self._inner.__aexit__(*exc)

    async def ws_connect(self, *args, **kwargs):
        socket = await self._inner.ws_connect(*args, **kwargs)
        return _PeerSocket(self._engine, socket, from_native=self._from_native)


class _PeerSocket:
    """Lets peer.py keep speaking its own protocol while the engine observes it.

    Outbound native signaling frames are diverted to the native adapter; every
    inbound frame is passed through unchanged after the engine has inspected it
    for roster updates. Message payloads are never rewritten.
    """

    def __init__(self, engine: "DesktopEngine", socket, from_native: bool = False):
        self._engine = engine
        self._socket = socket
        self._from_native = from_native

    def __getattr__(self, name):
        return getattr(self._socket, name)

    async def send_json(self, data):
        if isinstance(data, dict) and data.get("type") == "signal" and data.get("mechanism") != "webrtc":
            self._engine.route_outbound_native(data)
            return None
        return await self._socket.send_json(data)

    async def close(self, *args, **kwargs):
        return await self._socket.close(*args, **kwargs)

    def __aiter__(self):
        return self._iterate()

    async def _iterate(self):
        async for message in self._socket:
            self._engine.inspect_inbound(message, from_native=self._from_native)
            yield message


class DesktopEngine:
    def __init__(self, config: EngineConfig, events: asyncio.Queue | None = None):
        self.config = config
        self.client_session = secrets.token_hex(16)
        self.events = events if events is not None else asyncio.Queue(maxsize=4096)
        self.origin = config.origin or None
        self.peer: Peer | None = None
        self.signaling: SignalSession | None = None
        self.adapter: NativeAdapter | None = None
        self.native_capabilities: list = []
        self.gateway_optin: GatewayOptIn | None = None
        self.lan_direct: LanDirect | None = None
        self.local_candidates: dict = {}
        self.targets: dict[str, Target] = {}
        self.native_sessions: dict[str, NativeSession] = {}
        self.messages: list[Message] = []
        self.active_target: str | None = None
        self.closed = False
        self.errors: list[str] = []
        self._tasks: set[asyncio.Task] = set()
        self._futures: dict[str, asyncio.Future] = {}
        self._observed = False
        self.plaintext_warning: str | None = None
        self._roster_snapshot: list = []
        self._session_restore = None
        self.peer_ids: set = set()
        self._pending_roster: list = []
        self.native_self_name = NATIVE_SELF_NAME
        # Central diagnostic collection is on by default and can be paused from
        # the settings panel; local records are never silently discarded.
        self.telemetry_paused = False
        self.telemetry_incomplete = False

    # ------------------------------------------------------------------ plumbing
    def _emit(self, kind: str, **payload) -> None:
        event = {"kind": kind, "at": time.time(), **payload}
        try:
            self.events.put_nowait(event)
        except asyncio.QueueFull:
            try:
                self.events.get_nowait()
                self.events.put_nowait(event)
            except (asyncio.QueueEmpty, asyncio.QueueFull):
                pass

    # -------------------------------------------- 网关放行 / 局域网直连的生产接线
    def _audit_sink(self, event: dict) -> None:
        """桌面端审计 → 诊断事件流；剔除密钥类字段，只留动作与原因。"""
        payload = {k: v for k, v in event.items() if k not in {"secret", "key", "privateKey", "password"}}
        self._emit("diagnostic", code=f"{str(event.get('kind', 'audit')).upper()}:{event.get('action')}",
                   mechanism=event.get("kind"), detail=payload)

    def _capture_local_candidate(self, event, params) -> None:
        """记住原生尝试真正绑定的本地端口：放行必须指向一个在听的端口。"""
        candidate = params.get("nativeCandidate") if isinstance(params, dict) else None
        if event != "candidate" or not candidate or not candidate.get("port"):
            return
        self.local_candidates[str(params.get("attemptId"))] = {
            "address": candidate.get("address"), "port": int(candidate["port"]),
            "transport": candidate.get("transport"), "kind": candidate.get("kind"),
        }

    def local_data_port(self):
        for candidate in self.local_candidates.values():
            if candidate.get("transport") in {"udp", "quic"} and candidate.get("kind") == "host":
                return candidate["port"]
        return None

    def gateway_capability(self) -> dict:
        return (self.gateway_optin or GatewayOptIn()).capability()

    def gateway_consent_text(self) -> str:
        return (self.gateway_optin or GatewayOptIn()).consent_text()

    def gateway_technical_detail(self) -> str:
        return (self.gateway_optin or GatewayOptIn()).technical_detail()

    def gateway_audit(self) -> list:
        return list(self.gateway_optin.audit.events) if self.gateway_optin else []

    def gateway_failure_hint(self, code: str) -> str:
        return plain_reason(code)

    async def gateway_consent(self, source: str = "ui") -> dict:
        if self.gateway_optin is None:
            raise RuntimeError("ENGINE_NOT_STARTED")
        return self.gateway_optin.grant_consent(source)

    async def gateway_open_port(self, internal_port=None, *, lifetime_seconds: int = 120,
                               protocols=None, mock_loopback: bool = False,
                               validator=None) -> dict:
        """生产调用点：显式同意后让路由器开一个端口；没有同意时零网络请求。"""
        if self.gateway_optin is None:
            raise RuntimeError("ENGINE_NOT_STARTED")
        port = int(internal_port) if internal_port else self.local_data_port()
        if not port:
            raise ValueError("NO_LOCAL_DATA_PORT")
        result = await self.gateway_optin.map_port(port, lifetime_seconds=lifetime_seconds,
                                                   protocols=protocols, mock_loopback=mock_loopback,
                                                   validator=validator)
        self._emit("gateway.mapping", protocol=result.get("protocol"), externalPort=result.get("externalPort"),
                   lifetimeSeconds=result.get("lifetimeSeconds"), verified=bool(result.get("verified")))
        return result

    async def gateway_close_port(self) -> dict:
        if self.gateway_optin is None:
            return {"released": [], "failures": []}
        result = await self.gateway_optin.close()
        self._emit("gateway.release", released=result.get("released", []), failures=result.get("failures", []))
        return result

    def lan_capability(self) -> dict:
        return (self.lan_direct or LanDirect()).capability()

    def lan_consent_text(self) -> str:
        return (self.lan_direct or LanDirect()).consent_text()

    def lan_technical_detail(self) -> str:
        return (self.lan_direct or LanDirect()).technical_detail()

    def lan_diagnostics(self) -> list:
        return self.lan_direct.diagnostics() if self.lan_direct else []

    async def lan_enable(self, consent: bool = False, internal_port=None, interface=None) -> dict:
        """生产调用点：显式同意后开始同网段发现；没有同意时不发任何组播。"""
        if self.lan_direct is None:
            raise RuntimeError("ENGINE_NOT_STARTED")
        port = int(internal_port) if internal_port else self.local_data_port()
        if not port:
            raise ValueError("NO_LOCAL_DATA_PORT")
        return await self.lan_direct.enable(room=self.config.room, secret=self.config.secret,
                                            peer_id=self.config.name, listen_port=port,
                                            consent=consent, interface=interface)

    async def lan_disable(self) -> dict:
        if self.lan_direct is None:
            return {"status": "not-running"}
        return await self.lan_direct.disable()

    def spawn(self, coroutine):
        task = asyncio.create_task(coroutine)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return task

    async def drain_events(self, limit: int = 128) -> list[dict]:
        out = []
        while len(out) < limit:
            try:
                out.append(self.events.get_nowait())
            except asyncio.QueueEmpty:
                break
        return out

    # ------------------------------------------------------------------ lifecycle
    def _install_session_shim(self) -> None:
        """Process-local, transparent: only our own sockets are wrapped.

        ``peer.run`` builds its own ``aiohttp.ClientSession``, so for the
        lifetime of the run this shim is installed in the peer module's
        namespace (and, reference-counted, restored when the last engine
        stops). The non-WebRTC session is tagged so its frames are attributed
        to the right membership.
        """
        import aiohttp

        module = importlib.import_module("p2pchat.peer")
        engine = self
        if not _SHIM["engines"]:
            _SHIM["original"] = module.ClientSession
            _SHIM["aiohttp"] = aiohttp.ClientSession
        _SHIM["engines"] += 1
        original = _SHIM["original"] or module.ClientSession

        def factory(*args, **kwargs):
            from_native = bool(kwargs.pop("__native__", False))
            return _ClientSessionProxy(engine, original(*args, **kwargs), from_native=from_native)

        self._session_restore = original

        def peer_factory(*args, **kwargs):
            return _ClientSessionProxy(engine, original(*args, **kwargs), from_native=False)

        self._peer_session_factory = peer_factory
        self._native_session_factory = lambda *args, **kwargs: _ClientSessionProxy(
            engine, aiohttp.ClientSession(*args, **kwargs), from_native=True
        )
        module.ClientSession = peer_factory

    def _remove_session_shim(self) -> None:
        if getattr(self, "_session_restore", None) is None:
            return
        self._session_restore = None
        _SHIM["engines"] = max(0, _SHIM["engines"] - 1)
        if _SHIM["engines"] == 0 and _SHIM["original"] is not None:
            importlib.import_module("p2pchat.peer").ClientSession = _SHIM["original"]
            _SHIM["original"] = None
            _SHIM["aiohttp"] = None

    async def start(self) -> None:
        # Refuse an unencrypted non-loopback endpoint before opening any socket.
        risk = validate_endpoint(self.config.url, self.config.allow_plaintext)
        if risk:
            self.plaintext_warning = risk
            self._emit("engine.warning", code="PLAINTEXT_CONFIRMED", text=risk)
        self.adapter = NativeAdapter(
            bind_host=self.config.bind_host,
            stun_server=None,
            # 端口预测默认关闭；只有用户显式同意并给出观测点后才会采样与探测。
            prediction={"enabled": bool(self.config.prediction_enabled),
                        "points": [tuple(point) for point in (self.config.prediction_points or ())]},
        )
        capabilities = await self.adapter.capabilities()
        self.native_capabilities = capabilities.get("methods", [])
        self.prediction_capabilities = capabilities.get("prediction", {})
        self.prediction_states: dict = {}
        # 网关放行 / 局域网直连：只接线，默认关闭；启动与连接都不会产生任何映射或组播。
        self.gateway_optin = GatewayOptIn(adapter=self.adapter, audit_sink=self._audit_sink)
        self.lan_direct = LanDirect(audit_sink=self._audit_sink)
        self.adapter.subscribe(self._capture_local_candidate)
        room_capabilities = ["webrtc"] + [entry["mechanism"] for entry in self.native_capabilities if entry.get("status") == "available"]
        self.peer = Peer(
            self.config.url,
            self.config.room,
            self.config.secret,
            self.config.name,
            os.path.join(self.config.data_dir, "webRTC"),
            echo=self.config.echo,
            origin=self.origin,
        )
        # Wrap the durable local queue so the UI can pause central collection
        # without touching peer.py or dropping local diagnostic records.
        self.peer.store = _TelemetryGate(self, self.peer.store)
        self._install_session_shim()
        self.signaling = SignalSession(
            self.config.url,
            self.config.room,
            self.config.secret,
            self.native_self_name,
            room_capabilities,
            self.client_session,
            origin=self.origin,
        )
        self.signaling.on_signal = self.route_inbound_native
        self.signaling.on_nat_samples = self.route_inbound_prediction
        self.signaling.on_error = self._on_signaling_error
        self.signaling.factory = self._native_session_factory
        self.spawn(self.peer.run())
        self.spawn(self.signaling.run())
        self.spawn(self._consumer())
        self.spawn(self._ticker())
        self.spawn(self._latency_sweep())
        self._emit("engine.started", clientSession=self.client_session, native=self.native_capabilities)

    async def _consumer(self) -> None:
        """Surface peer.py outcomes (echo replies, receipts, files) to the UI."""
        assert self.peer is not None
        while not self.closed:
            try:
                peer_id, message = await self.peer.received.get()
            except asyncio.CancelledError:
                return
            kind = message.get("kind")
            key = self.membership_key(peer_id)
            if kind == "delivered":
                self._emit("message.delivered", peer=key, id=message.get("id"))
            elif kind == "server.error":
                self._on_signaling_error(str(message.get("reason")))
            elif kind == "pong":
                self._resolve_webrtc_pong(str(message.get("id")))
            elif kind == "bench-ack":
                future = self._futures.get(f"bench:{message.get('id')}")
                if future is not None and not future.done():
                    future.set_result(message)
            elif kind == "bench-error":
                # Explicit peer-side failure: resolve as a failure, never fabricate a speed.
                future = self._futures.get(f"bench:{message.get('id')}")
                if future is not None and not future.done():
                    future.set_result({"ok": False, "bytes": 0, "code": str(message.get("code") or "BENCH_FAILED")})
            elif kind == "text":
                self._record(
                    Message(
                        direction="in",
                        peer=key,
                        kind="text",
                        id=str(message.get("id")),
                        text=message.get("text", ""),
                        mechanism="webrtc",
                        at=time.time(),
                    )
                )
            elif kind == "file":
                self._record(
                    Message(
                        direction="in",
                        peer=key,
                        kind="file",
                        id=str(message.get("id")),
                        bytes=int(message.get("bytes") or 0),
                        mechanism="webrtc",
                        at=time.time(),
                    )
                )
            elif kind in {"file-progress", "file-ready"}:
                self._emit("transfer.progress", id=message.get("id"), bytes=message.get("receivedBytes"), ok=message.get("ok"))

    def _record(self, message: Message) -> None:
        self.messages.append(message)
        if len(self.messages) > MAX_MESSAGES:
            self.messages = self.messages[-MAX_MESSAGES:]
        self._emit("message", message=message)

    def membership_key(self, peer_id: str) -> str:
        """Map a room membership back to the single logical remote client."""
        for key, target in self.targets.items():
            if peer_id in {target.webrtc_id, target.native_id}:
                return key
        return peer_id

    def membership_key_for_client(self, client_session: str) -> str:
        return client_session

    def _on_signaling_error(self, code: str) -> None:
        self.errors.append(code)
        self._emit("engine.error", code=code, text=plain.reason(code))

    # ----------------------------------------------------------- peer.py bridge
    def inspect_inbound(self, message, from_native: bool = False) -> None:
        """Called for every inbound signaling frame before peer.py sees it."""
        try:
            if getattr(message, "type", None) is None or str(getattr(message, "type", "")) == "WSMsgType.CLOSED":
                return
            if getattr(message, "type", None) != 1:  # WSMsgType.TEXT == 1
                return
            data = json.loads(message.data)
        except Exception:
            return
        if not isinstance(data, dict):
            return
        if data.get("type") == "roster" and not from_native:
            self.on_roster(data.get("peers", []))
        elif data.get("type") == "roster" and from_native:
            # This socket's own membership must never become a chat target.
            candidates = [entry for entry in data.get("peers", []) if isinstance(entry, dict) and entry.get("name") != self.native_self_name]
            if not candidates:
                return
            data = {**data, "peers": candidates}
            self.on_roster(candidates)
        elif data.get("type") == "welcome":
            # Which of our memberships this socket became, so roster grouping can
            # tell our own entries from the remote client's entries.
            if not from_native and self.peer is not None:
                self.peer_ids.add(data.get("id"))
            if self._pending_roster:
                self._apply_roster()
            self._emit("session.welcome", serverId=data.get("id"))

    # -------------------------------------------------------------- target model
    def target_for(self, key: str) -> Target:
        target = self.targets.get(key)
        if target is None:
            if len(self.targets) >= MAX_PEERS:
                raise RuntimeError("LIMIT_EXCEEDED")
            target = Target(key=key)
            self.targets[key] = target
            self._emit("target.added", key=key)
        return target

    def _method(self, target: Target, method: dict) -> MethodState:
        state = target.methods.get(method["id"])
        if state is None:
            capability = None
            if method["mechanism"] not in {"webrtc", "observation"}:
                capability = next(
                    (entry for entry in self.native_capabilities if entry.get("mechanism") == method["mechanism"]), None
                )
            state = MethodState(
                method_id=method["id"],
                mechanism=method["mechanism"],
                capability=capability,
                probe_only=plain.probe_only(method),
            )
            if self._is_gateway_method(method):
                state = self._apply_gateway_capability(state)
            target.methods[method["id"]] = state
        return state

    # ------------------------------------------------------- capability semantics
    @staticmethod
    def _is_gateway_method(method: dict) -> bool:
        """路由器放行：UI 上的第 9 条，适配器里以 upnp/pcp/natpmp 上报。"""
        return bool(method.get("opt_in")) or method.get("mechanism") in GATEWAY_MECHANISMS

    def _apply_gateway_capability(self, state: MethodState) -> MethodState:
        """网关方式的初始状态直接消费适配器的真实能力报告。

        平台能核对（Linux 且有默认网关）时它是**可用**的，只是默认关闭、需要操作者
        显式同意；把"还没同意"写成「不支持」会让用户根本不去点同意。平台无法核对时
        才是不支持，并带上真实原因。
        """
        capability = self.gateway_capability() or {}
        state.capability = capability
        if capability.get("status") == "available":
            state.state = "pending"
            state.failure = None
            state.detail = plain.reason("OPT_IN_GATEWAY_API_ONLY")
        else:
            state.state = "unsupported"
            state.failure = capability.get("reason") or "PLATFORM_VALIDATION_UNAVAILABLE"
            state.detail = self.gateway_failure_hint(state.failure)
        return state

    def rows(self, key: str) -> list[dict]:
        """UI rows: human title, one-line explanation, status, measured latency."""
        target = self.targets.get(key)
        rows = []
        for method in plain.METHODS:
            state = target.methods.get(method["id"]) if target else None
            if state is None:
                # Availability is always one of 可用/不可用/不支持; "we have no
                # result yet" belongs in the note, never in the vocabulary.
                availability = self.availability_for(method, None)
                rows.append(
                    {
                        "id": method["id"],
                        "title": method["title"],
                        "explain": method["explain"],
                        "works": method["works"],
                        "failureHint": method["failure"],
                        "status": "等待中",
                        "state": "pending",
                        "latency": None,
                        "availability": availability,
                        "availabilityNote": self.availability_note_for(availability, "pending"),
                        "detail": self.method_detail_hint(method, availability),
                        "probeOnly": bool(method.get("probe_only")),
                        "canMessage": False,
                        **self.consent_fields(method),
                    }
                )
                continue
            # METHODS-PLAIN.md: only a message-capable path may read 已打通; a
            # successful probe/observation reads 已观测 and says so.
            if state.probe_only and state.state == "direct":
                status = f"{plain.STATUS['observed']}（仅探测，不传内容）"
                state_note = "observed"
            else:
                status = plain.STATUS.get(state.state, "等待中")
                state_note = state.state
            detail = plain.reason(state.failure) if state.failure else state.detail
            availability = self.availability_for(method, state)
            # M2: a probe/observation round-trip never occupies the 实测延迟 slot.
            # Only a message-capable direct path may report a chat latency.
            can_message = state.state == "direct" and not state.probe_only and state.mechanism != "observation"
            measured = None if state.rtt is None else round(state.rtt, 1)
            rows.append(
                {
                    "id": method["id"],
                    "title": method["title"],
                    "explain": method["explain"],
                    "works": method["works"],
                    "failureHint": method["failure"],
                    "status": status,
                    "state": state_note,
                    "latency": measured if can_message else None,
                    "availability": availability,
                    "availabilityNote": self.availability_note_for(availability, state_note),
                    "detail": detail or self.method_detail_hint(method, availability, state),
                    "probeRtt": measured if (measured is not None and not can_message) else None,
                    "probeOnly": state.probe_only,
                    "canMessage": can_message,
                    **self.consent_fields(method),
                }
            )
        return rows

    def consent_fields(self, method: dict) -> dict:
        """让界面能说"可用，但需要你点同意"，而不必把同意混进可用性。"""
        gateway = self._is_gateway_method(method)
        return {
            "consentRequired": gateway,
            "consented": self.gateway_consented() if gateway else False,
            "capabilityLine": self.gateway_capability_line() if gateway else "",
        }

    def method_detail_hint(self, method: dict, availability: str, state=None) -> str:
        """行内说明：不可用/不支持时说清为什么；可用但需要同意时也说清"还没同意"。"""
        if method["mechanism"] == "observation" and availability != plain.AVAILABILITY["available"]:
            return plain.reason("NO_STUN_SERVER")
        if self._is_gateway_method(method):
            if availability != plain.AVAILABILITY["available"]:
                capability = self.gateway_capability() or {}
                return capability.get("note") or self.gateway_failure_hint(capability.get("reason") or "")
            if not self.gateway_consented():
                # 可用 ≠ 已经同意：默认关闭，必须由操作者显式授权。
                return plain.reason("OPT_IN_GATEWAY_API_ONLY")
            return ""
        if availability == plain.AVAILABILITY["available"]:
            return ""
        # 其它原生方式：能用就用适配器的原因说清楚，还没探测过就如实说还没探测。
        mechanism = method["mechanism"]
        capability = getattr(state, "capability", None) if state is not None else None
        if not capability:
            capability = next((entry for entry in self.native_capabilities if entry.get("mechanism") == mechanism), None)
        if capability and capability.get("reason"):
            return plain.reason(capability["reason"])
        if not self.native_capabilities:
            return "本机原生能力还没探测：连上服务器后这里会给出结论。"
        return ""

    def availability_for(self, method: dict, state) -> str:
        """可用 / 不可用 / 不支持 — the documented three, always one of them.

        可用性只描述"这台机器/这条链路上能不能做这件事"，不描述"现在有没有成功"，
        也不描述"用户有没有同意"。所以：
          * WebRTC 三档：组件可用即可用；
          * STUN 观测：有没有服务器下发的 STUN 端点；
          * 路由器放行：适配器对平台能力的真实报告（upnp/pcp/natpmp），默认关闭
            与"尚未同意"只体现在状态/说明里；
          * 其它原生方式：适配器对应 mechanism 的能力报告。
        """
        mechanism = method["mechanism"]
        if mechanism == "webrtc":
            return plain.AVAILABILITY["available"]
        if mechanism == "observation":
            return self.observation_availability(state)
        if self._is_gateway_method(method):
            return self.gateway_availability()
        capability = getattr(state, "capability", None)
        if capability is None:
            capability = next(
                (entry for entry in self.native_capabilities if entry.get("mechanism") == mechanism),
                None,
            )
        return plain.AVAILABILITY[plain.availability(mechanism, capability)]

    # ------------------------------------------------------------- availability
    def stun_endpoint(self) -> str | None:
        """服务器下发（或命令行显式给出）的 STUN 端点；没有就观测不了出口。"""
        return self.config.stun_url or self._server_stun_url()

    def observation_availability(self, state=None) -> str:
        """STUN 观测的可用性只取决于"有没有可用的 STUN 端点"。

        没有端点 → 不支持（服务器没下发 STUN 地址），而不是"可用但还是失败了"；
        有端点但这次没问到 → 不可用；有端点且有结果 → 可用。
        """
        if not self.stun_endpoint():
            return plain.AVAILABILITY["unsupported"]
        if state is not None:
            if state.state == "unavailable":
                return plain.AVAILABILITY["unavailable"]
            if state.state == "unsupported":
                return plain.AVAILABILITY["unsupported"]
        return plain.AVAILABILITY["available"]

    def gateway_availability(self) -> str:
        """路由器放行的可用性 = 适配器的平台能力报告（默认关闭不是"不支持"）。"""
        status = (self.gateway_capability() or {}).get("status")
        if status == "available":
            return plain.AVAILABILITY["available"]
        if status == "unavailable":
            return plain.AVAILABILITY["unavailable"]
        return plain.AVAILABILITY["unsupported"]

    def gateway_capability_line(self) -> str:
        return (self.gateway_optin or GatewayOptIn()).capability_line()

    def gateway_consented(self) -> bool:
        return bool((self.gateway_capability() or {}).get("consented"))

    def availability_note_for(self, availability: str, state_name: str) -> str:
        """"尚未出结果"只在方式本身可用时才是准确的说明。"""
        if availability != plain.AVAILABILITY["available"]:
            return ""
        if state_name in {"pending", "trying"}:
            return plain.AVAILABILITY_NOTE["pending"]
        return ""

    def summary(self, key: str) -> dict:
        rows = self.rows(key)
        direct = [row for row in rows if row["canMessage"]]
        pending = [row for row in rows if row["state"] in {"pending", "trying"}]
        unavailable = [row for row in rows if row["state"] in {"unavailable", "unsupported"}]
        observed = [row for row in rows if row["state"] == "observed"]
        # 实测延迟 only ever comes from a message-capable path. A probe/observation
        # RTT is reported separately as probeRtt, never as the chat latency.
        latencies = [row["latency"] for row in direct if row["latency"] is not None]
        probe_rtts = [row["probeRtt"] for row in rows if row.get("probeRtt") is not None]
        return {
            "rows": rows,
            "directCount": len(direct),
            "remaining": [row["title"] for row in pending],
            "unavailable": [{"title": row["title"], "detail": row["detail"]} for row in unavailable],
            "latency": min(latencies) if latencies else None,
            "latencyNote": "没有可聊天直连时不给延迟数值" if not latencies else "",
            # Probe/observation round-trips are measured, but they are not chat
            # latency and are named separately so they are never mislabelled.
            "probeRtt": min(probe_rtts) if probe_rtts else None,
            "probeRttLabel": "仅探测/观测方式的往返时间（不是聊天延迟）",
            "canSend": bool(direct),
            "probeOnly": [row["title"] for row in rows if row["state"] == "observed"],
            "observed": [row["title"] for row in rows if row["state"] == "observed"],
            "direct": [row["title"] for row in direct],
            "webRtcProfileNote": plain.WEBRTC_PROFILE_NOTE,
            # 面板文案只在数据层决定一次：暂停优先于"已开启"，两个界面（以及 Qt 版）
            # 都直接渲染 telemetry['text']，不各自判断。
            "telemetry": self.telemetry_status(),
            "observation": None if not self.targets.get(key) else self.targets[key].observation,
        }

    # ------------------------------------------------------------- native routing
    def route_outbound_native(self, frame: dict) -> None:
        if self.signaling is None or self.signaling.id is None:
            return
        payload = {key: value for key, value in frame.items() if key != "from"}
        try:
            self.signaling.send_signal(**payload)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self._emit("engine.error", code=code, text=plain.reason(code))

    # ----------------------------------------------------- 端口预测：只做接线
    PREDICTION_NOTE = ("对称 NAT 下端口预测命中概率有限，失败属正常结果。优先顺序：IPv6 直连 > 网关注册放行 > 端口预测。")

    def prediction_capability(self) -> dict:
        if self.adapter is not None:
            return self.adapter.prediction_capability()
        return {"v": 1, "status": "unavailable", "enabled": False, "reason": "ENGINE_NOT_STARTED",
                "hitRateNote": self.PREDICTION_NOTE}

    def prediction_consent_text(self) -> str:
        return ("端口预测会先问你自己配置的 STUN 观测点，看你的对外端口分配是不是有规律；只有双方都同意时，"
                "才会对**已经信令交换过的对端地址**做少量认证探测。它只尝试，不保证成功：对称 NAT 下命中概率有限，"
                "失败属正常结果。优先顺序：IPv6 直连 > 网关注册放行 > 端口预测。默认关闭。")

    def prediction_hit_rate_note(self) -> str:
        return self.PREDICTION_NOTE

    def prediction_failure_states(self) -> list:
        return ["NO_AUTHENTICATED_REPLY", "REPLIES_REJECTED", "DEADLINE_REACHED", "SEND_FAILED"]

    async def prediction_enable(self, consent: bool = False, points=None) -> dict:
        """生产调用点：显式同意 + 显式观测点后，才允许采样与探测。"""
        if self.adapter is None:
            raise RuntimeError("ENGINE_NOT_STARTED")
        if not consent:
            raise PermissionError("PREDICTION_OPT_IN_REQUIRED")
        configured = [tuple(point) for point in (points if points is not None else self.adapter.prediction.get("points") or ())]
        config = dict(self.adapter.prediction)
        config.update({"enabled": True, "points": configured})
        self.adapter.prediction = config
        self.prediction_capabilities = self.adapter.prediction_capability()
        self._emit("prediction.enabled", status=self.prediction_capabilities.get("status"),
                   observationPoints=self.prediction_capabilities.get("observationPoints", 0))
        return self.prediction_capabilities

    async def prediction_disable(self) -> dict:
        if self.adapter is None:
            raise RuntimeError("ENGINE_NOT_STARTED")
        config = dict(self.adapter.prediction)
        config["enabled"] = False
        self.adapter.prediction = config
        self.prediction_capabilities = self.adapter.prediction_capability()
        self.prediction_states.clear()
        self._emit("prediction.disabled")
        return self.prediction_capabilities

    def prediction_status(self, key: str | None = None) -> dict:
        states = {k: v for k, v in self.prediction_states.items() if key is None or k.startswith(f"{key}:")}
        return {"capability": self.prediction_capabilities or self.prediction_capability(),
                "note": self.PREDICTION_NOTE, "attempts": states}

    def route_outbound_prediction(self, message: dict) -> None:
        """Send the adapter's signed NAT samples over the signaling channel.

        These are hole-punch timing/probe samples, not chat content: they travel
        the same signaling path the room already uses, and no chat message is
        ever passed through the server.
        """
        if self.signaling is None or self.signaling.id is None or not isinstance(message, dict):
            return
        payload = {key: value for key, value in message.items() if key != "from"}
        try:
            self.signaling.send_nat_samples(**payload)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self._emit("engine.error", code=code, text=plain.reason(code))

    def route_inbound_prediction(self, frame: dict) -> None:
        attempt = frame.get("attemptId")
        sender = frame.get("from")
        if not attempt or not sender or sender == self.signaling_id:
            return
        session = self.native_sessions.get(str(attempt))
        if session is None:
            self._emit("diagnostic", code="PREDICTION_SAMPLES_UNKNOWN_ATTEMPT")
            return
        self.spawn(self._prediction_signal(session, frame))

    async def _prediction_signal(self, session, frame: dict) -> None:
        try:
            await session.prediction_signal(frame)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self._emit("engine.error", code=code, text=plain.reason(code))

    def route_inbound_native(self, frame: dict) -> None:
        mechanism = frame.get("mechanism")
        if mechanism in {None, "webrtc"}:
            return
        sender = frame.get("from")
        if not sender or sender == self.signaling_id:
            return
        key = self.membership_key(sender)
        target = self.target_for(key)
        if sender != (self.peer.id if self.peer else None):
            target.native_id = target.native_id or sender
        attempt = frame.get("attemptId")
        connection = frame.get("connectionId")
        if not attempt or not connection:
            return
        session = self.native_sessions.get(str(attempt))
        if session is not None:
            self.spawn(self._signal_native(session, frame))
            return
        if self.adapter is None or self.signaling_id is None:
            return
        session = NativeSession(
            self.adapter,
            mechanism=mechanism,
            room=self.config.room,
            secret=self.config.secret,
            local_id=self.signaling_id,
            peer_id=sender,
            connection_id=str(connection),
            attempt_id=str(attempt),
            role="answerer",
            on_event=self.on_native_event,
        )
        self.native_sessions[str(attempt)] = session
        self._method(target, plain.method_for(mechanism) or plain.METHOD_BY_ID["quic"]).attempt = str(attempt)
        self.spawn(self._start_native(session, target))

    async def _signal_native(self, session: NativeSession, frame: dict) -> None:
        payload = {
            key: frame[key]
            for key in ("description", "nativeCandidate", "connectionId", "attemptId", "mechanism", "profile", "from")
            if key in frame
        }
        try:
            await session.signal(payload)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self._emit("engine.error", code=code, text=plain.reason(code))

    async def _start_native(self, session: NativeSession, target: Target) -> None:
        try:
            await session.start()
        except Exception as error:
            code = str(error.args[0]) if error.args else "START_FAILED"
            self._native_state(target, session, "unavailable", code)
            return
        for frame in session.take_handshake():
            self.route_outbound_native(session.envelope(**frame))

    async def start_method(self, key: str, method_id: str) -> MethodState:
        """Start exactly one method for one peer, addressed by its plain-language id."""
        target = self.target_for(key)
        method = plain.METHOD_BY_ID.get(method_id)
        if method is None:
            raise ValueError("SCHEMA_INVALID")
        state = self._method(target, method)
        if state.state == "direct":
            return state
        if self._is_gateway_method(method):
            # 不再无条件写 unsupported：平台能核对时它是可用但需显式同意。
            state = self._apply_gateway_capability(state)
            self._emit("method", key=key, methodId=method_id, state=state.state, failureCode=state.failure)
            return state
        if method["mechanism"] == "observation":
            self.spawn(self.observe(key))
            return state
        if method["mechanism"] == "webrtc":
            state.state = "trying"
            state.detail = "由浏览器直连组件同时尝试三种地址组合，等待对方确认。"
            self._emit("method", key=key, methodId=method_id, state="trying")
            self._ensure_webrtc(target)
            return state
        if not self.config.allow_native:
            state.state = "unsupported"
            state.failure = "UNSUPPORTED_METHOD"
            self._emit("method", key=key, methodId=method_id, state="unsupported", failureCode=state.failure)
            return state
        capability = next((entry for entry in self.native_capabilities if entry.get("mechanism") == method["mechanism"]), None)
        if capability is None or capability.get("status") != "available":
            state.state = "unsupported"
            state.failure = (capability or {}).get("reason") or "UNSUPPORTED_METHOD"
            self._emit("method", key=key, methodId=method_id, state="unsupported", failureCode=state.failure)
            return state
        if self.adapter is None or target.native_id is None or self.signaling_id is None:
            state.state = "pending"
            state.detail = "等对方加入并交换地址后再试。"
            self._emit("method", key=key, methodId=method_id, state="pending")
            return state
        if not self.should_initiate(target.native_id):
            # The lower room id announces the connection; the other side answers
            # the frames it receives. Server-side binding stays unambiguous.
            state.state = "pending"
            state.detail = "等对方先发起这条方式。"
            self._emit("method", key=key, methodId=method_id, state="pending")
            return state
        attempt = str(uuid.uuid4())
        session = NativeSession(
            self.adapter,
            mechanism=method["mechanism"],
            room=self.config.room,
            secret=self.config.secret,
            local_id=self.signaling_id,
            peer_id=target.native_id,
            connection_id=str(uuid.uuid4()),
            attempt_id=attempt,
            role="offerer",
            on_event=self.on_native_event,
        )
        self.native_sessions[attempt] = session
        state.attempt = attempt
        state.state = "trying"
        self._emit("method", key=key, methodId=method_id, state="trying")
        self.spawn(self._start_native(session, target))
        return state

    # ----------------------------------------------------------------- observation
    async def observe(self, key: str) -> None:
        """STUN mapping observation. It observes an address; it forwards nothing."""
        target = self.target_for(key)
        method = plain.METHOD_BY_ID["stun-observation"]
        state = self._method(target, method)
        stun_url = self.config.stun_url or self._server_stun_url()
        if not stun_url:
            state.state = "unsupported"
            state.failure = "NO_STUN_SERVER"
            state.detail = plain.reason("NO_STUN_SERVER")
            self._observed = True
            self._emit("method", key=key, methodId=method["id"], state="unsupported", failureCode=state.failure)
            return
        state.state = "trying"
        self._emit("method", key=key, methodId=method["id"], state="trying")
        try:
            mapped = await self._stun_binding(stun_url)
        except Exception:
            state.state = "unavailable"
            state.failure = "STUN_MAPPING_UNAVAILABLE"
            state.detail = plain.reason("STUN_MAPPING_UNAVAILABLE")
            self._observed = True
            self._emit("method", key=key, methodId=method["id"], state="unavailable", failureCode=state.failure)
            return
        state.state = "direct"
        state.detail = f"观测到的出口是 {mapped['address']}:{mapped['port']}（只观测地址，不转发任何数据）"
        target.observation = mapped
        self._observed = True
        self._emit("method", key=key, methodId=method["id"], state="direct")
        self._emit("observation", key=key, **mapped)

    def _server_stun_url(self) -> str | None:
        # 服务器还没连上 / 测试替身没有 ice 时，如实回答"没有端点"，不要抛异常。
        ice = getattr(self.peer, "ice", None) if self.peer is not None else None
        for server in ice or []:
            urls = getattr(server, "urls", None)
            if isinstance(urls, str):
                urls = [urls]
            for url in urls or []:
                if not isinstance(url, str) or not url.startswith("stun:"):
                    continue
                host = url[len("stun:") :]
                address, _, _ = host.rpartition(":")
                try:
                    parsed = ipaddress.ip_address(address.strip("[]"))
                except ValueError:
                    continue
                if parsed.version == 4:
                    return url
        return None

    async def _stun_binding(self, url: str) -> dict:
        host = url[len("stun:") :]
        address, _, port = host.rpartition(":")
        port = int(port or 3478)
        address = address.strip("[]")
        family = socket_module.AF_INET6 if ":" in address else socket_module.AF_INET
        sock = socket_module.socket(family, socket_module.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            sock.bind((address, 0))
            transaction = os.urandom(12)
            request = struct.pack("!HHI", 1, 0, 0x2112A442) + transaction
            loop = asyncio.get_running_loop()
            target = (address, port, 0, 0) if family == socket_module.AF_INET6 else (address, port)
            await loop.sock_sendto(sock, request, target)
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                try:
                    data, source = await asyncio.wait_for(loop.sock_recvfrom(sock, 2048), max(0.05, deadline - time.monotonic()))
                except asyncio.TimeoutError:
                    break
                except OSError:
                    break
                if len(data) < 20 or data[8:20] != transaction:
                    continue
                offset = 20
                while offset + 4 <= len(data):
                    kind, size = struct.unpack("!HH", data[offset : offset + 4])
                    offset += 4
                    value = data[offset : offset + size]
                    offset += (size + 3) & ~3
                    if kind != 0x0020 or len(value) < 4 or value[1] not in {1, 2}:
                        continue
                    port_value = value[2] ^ 0x2112
                    if value[1] == 1 and len(value) >= 8:
                        return {"address": ".".join(str(b) for b in value[4:8]), "port": port_value, "server": f"{source[0]}:{source[1]}"}
                    if value[1] == 2 and len(value) >= 20:
                        mask = struct.pack("!I", 0x2112A442) + transaction
                        raw = bytes(a ^ b for a, b in zip(value[4:20], mask))
                        return {"address": str(ipaddress.IPv6Address(raw)), "port": port_value, "server": f"{source[0]}:{source[1]}"}
            raise TimeoutError("STUN_MAPPING_UNAVAILABLE")
        finally:
            sock.close()

    # ------------------------------------------------------------------- callbacks
    def on_native_event(self, event: str, params: dict) -> None:
        session = self.native_sessions.get(str(params.get("attemptId")))
        if session is None:
            return
        target = self.target_of_session(session)
        if event == "state":
            state = params.get("state")
            if state == "direct":
                detail = None if session.capable else "仅探测，不传内容"
                self._native_state(target, session, "direct", None, detail=detail)
                if session.capable:
                    self.spawn(self._measure(session))
                else:
                    self.spawn(self._release_probe(session))
            elif state in {"unavailable", "unsupported"}:
                self._native_state(target, session, state, params.get("failureCode") or "TIMEOUT")
            elif state in {"trying", "pending"}:
                self._native_state(target, session, "trying", None)
        elif event == "chat.received":
            if params.get("kind") == "text":
                self._record(
                    Message(
                        direction="in",
                        peer=target.key,
                        kind="text",
                        id=str(params.get("id")),
                        text=params.get("text", ""),
                        mechanism=session.mechanism,
                        at=time.time(),
                    )
                )
            else:
                self._record(
                    Message(
                        direction="in",
                        peer=target.key,
                        kind="file",
                        id=str(params.get("id")),
                        name=params.get("name", ""),
                        mime=params.get("mime", ""),
                        bytes=int(params.get("bytes") or 0),
                        data=params.get("data"),
                        mechanism=session.mechanism,
                        at=time.time(),
                    )
                )
        elif event == "latency":
            self._native_state(target, session, session.state, session.failure, rtt=params.get("rttMs"))
        elif event == "transfer.sent":
            self._emit("transfer.sent", id=params.get("id"), bytes=params.get("bytes"), mechanism=session.mechanism, elapsedMs=params.get("elapsedMs"))
        elif event == "transfer.ack":
            self._emit("transfer.ack", id=params.get("id"), ok=params.get("ok"), bytes=params.get("bytes"))
        elif event == "diagnostic":
            self._emit("diagnostic", code=params.get("code"), mechanism=session.mechanism)
        elif event == "prediction.state":
            record = {
                "state": params.get("state"), "reason": params.get("reason"),
                "candidates": params.get("candidates") or [], "hit": bool(params.get("hit")),
                "localSymmetric": params.get("localSymmetric"), "peerSamples": params.get("peerSamples", 0),
                "note": self.PREDICTION_NOTE,
            }
            self.prediction_states[f"{target.key}:{session.id}"] = record
            self._emit("prediction.state", peer=target.key, attemptId=session.id, mechanism=session.mechanism,
                       **record)
        elif event == "prediction.samples":
            message = params.get("message")
            if isinstance(message, dict):
                self.route_outbound_prediction(message)
        elif event == "prediction.hit":
            self._emit("prediction.hit", peer=target.key, attemptId=session.id, mechanism=session.mechanism,
                       note=params.get("note"), hitRateNote=self.PREDICTION_NOTE)
        elif event == "peer-candidate":
            for frame in params.get("frames", []):
                self.route_outbound_native(session.envelope(**frame))

    def target_of_session(self, session: NativeSession) -> Target:
        for target in self.targets.values():
            for state in target.methods.values():
                if state.attempt == session.id:
                    return target
        return self.target_for(session.peer_id)

    async def _release_probe(self, session: NativeSession) -> None:
        await asyncio.sleep(0.5)
        await session.close()

    async def _latency_sweep(self) -> None:
        """Fill in measured latency as soon as a path is usable.

        Not measured yet is reported as "not measured" (rendered as —), never as
        zero, so nothing here invents a value; it only fills what is measurable.
        """
        while not self.closed:
            await asyncio.sleep(2)
            for key in list(self.targets):
                target = self.targets.get(key)
                if target is None or target.webrtc_id is None:
                    continue
                if not any(
                    row["state"] == "direct" and row["latency"] is None
                    for row in self.rows(key)
                    if row["id"] in {"ice-dual", "ice-v6", "ice-v4"}
                ):
                    continue
                try:
                    await self.measure_webrtc_latency(key)
                except Exception:
                    pass

    async def _measure(self, session: NativeSession) -> None:
        for _ in range(3):
            if session.state != "direct":
                return
            try:
                await session.ping()
            except Exception:
                return
            await asyncio.sleep(2)

    def _native_state(self, target: Target, session: NativeSession, state: str, failure: str | None, detail: str | None = None, rtt: float | None = None) -> None:
        method = plain.method_for(session.mechanism)
        if method is None:
            return
        entry = self._method(target, method)
        if entry.attempt is None:
            entry.attempt = session.id
        entry.state = state
        entry.failure = failure
        if rtt is not None:
            entry.rtt = rtt
        elif session.rtt is not None:
            entry.rtt = session.rtt
        if detail:
            entry.detail = detail
        self._emit("method", key=target.key, methodId=method["id"], state=state, failureCode=failure, detail=detail, mechanism=session.mechanism)

    async def _ticker(self) -> None:
        """Refresh reused-path state and latency; never invents a success."""
        while not self.closed:
            await asyncio.sleep(3)
            if self.peer is not None:
                for path in list(self.peer.paths.values()):
                    key = self.membership_key(path["peer"])
                    target = self.targets.get(key)
                    if target is None:
                        continue
                    entry = self._method(target, plain.method_for("webrtc", path["profile"]))
                    if path.get("hello"):
                        entry.state = "direct"
                        entry.failure = None
                        actual = path.get("actual") or {}
                        if actual.get("protocol"):
                            entry.detail = f"实际使用：{actual.get('protocol')} / {'IPv6' if actual.get('family') == 6 else 'IPv4 或未知类型'}"
                    elif path["closing"]:
                        if entry.state != "direct":
                            entry.state = "unavailable"
                            entry.failure = entry.failure or "CLOSED"
                    else:
                        entry.state = "trying"
            for session in list(self.native_sessions.values()):
                if session.state == "direct":
                    await session.refresh_stats()
            # Bounded retry: methods that could not start before the peer's
            # memberships were both known are attempted again here.
            if any(
                state.state == "pending"
                for target in self.targets.values()
                for state in target.methods.values()
            ):
                await self._discover_all()

    # ------------------------------------------------------------------ room view
    def on_roster(self, peers: list) -> None:
        """Group the remote client's room memberships into one logical target.

        A desktop client opens two memberships (WebRTC and non-WebRTC
        signaling). They are the same person, so the UI shows one chat partner
        while both membership ids stay tracked for routing.
        """
        self._pending_roster = [entry for entry in peers if isinstance(entry, dict)]
        self._apply_roster()

    def _apply_roster(self) -> None:
        """Group the remote client's memberships into one logical target.

        The roster carries only ``id``/``name``/``capabilities`` (see
        ``server.py``), so the name is the stable grouping signal: both
        memberships of one desktop client join with the same name, the
        non-WebRTC one suffixed. ``clientSessionId`` is honoured when present.
        """
        mine = self.my_ids()
        groups: dict[str, list] = {}
        for entry in self._pending_roster:
            peer_id = entry.get("id")
            if not peer_id:
                continue
            name = str(entry.get("name") or "")
            if name == self.native_self_name or name.endswith(NATIVE_SUFFIX):
                # Our own non-WebRTC membership (or its own suffix form).
                continue
            base = name
            key = entry.get("clientSessionId") or f"name:{base}"
            groups.setdefault(key, []).append(entry)
        snapshot = []
        for key, entries in groups.items():
            session = entries[0].get("clientSessionId")
            if session == self.client_session:
                continue
            entries = sorted(entries, key=lambda item: item["id"])
            remote_ids = {entry["id"] for entry in entries} - mine
            if not remote_ids:
                continue
            rep = min(remote_ids)
            name = next((entry.get("name") for entry in entries if entry["id"] == rep), "") or "房间成员"
            display = name[: -len(NATIVE_SUFFIX)] if name.endswith(NATIVE_SUFFIX) else name
            target = self.target_for(key)
            target.name = display
            # The lower id is the one that announces a new connection, so it is
            # reachable for both ICE signaling and native signaling.
            if rep in mine:
                continue
            if getattr(self.peer, "id", None) and rep == self.peer.id:
                target.webrtc_id = rep
            elif self.signaling_id and rep == self.signaling_id:
                target.native_id = rep
            elif target.webrtc_id is None and target.native_id is None:
                target.webrtc_id = target.native_id = rep
            elif target.native_id is None:
                target.native_id = rep
            elif target.webrtc_id is None:
                target.webrtc_id = rep
            snapshot.append({"key": key, "name": target.name, "webrtc": target.webrtc_id, "native": target.native_id})
            self._emit("target", key=key, name=target.name, webrtc=target.webrtc_id, native=target.native_id)
        self._prune_targets()
        self._roster_snapshot = snapshot
        self.spawn(self._discover_all())

    def _prune_targets(self) -> None:
        """Drop targets whose memberships turned out to be our own ids."""
        mine = self.my_ids()
        for key in list(self.targets):
            target = self.targets[key]
            ids = {target.webrtc_id, target.native_id} - {None}
            if ids and ids <= mine:
                self.targets.pop(key, None)

    def native_membership_ids(self) -> set:
        """Ids whose roster name is our own non-WebRTC membership."""
        return {
            entry["id"]
            for entry in self._pending_roster
            if entry.get("id") and entry.get("name") == self.native_self_name
        }

    def my_ids(self) -> set:
        # Membership ids this process currently holds: the WebRTC membership
        # (learned from the welcome held by peer.py) plus the non-WebRTC one.
        # Stale ids from a closed membership are deliberately excluded, so a
        # remote peer is never mistaken for ourselves.
        ids = {value for value in (self.signaling_id, self.peer.id if self.peer else None) if value}
        if self.signaling is not None and self.signaling.id:
            ids.add(self.signaling.id)
        if self.peer is not None and self.peer.id:
            ids.add(self.peer.id)
        return ids

    def lowest_my_id(self) -> str | None:
        ids = sorted(self.my_ids())
        return ids[0] if ids else None

    async def _discover_all(self) -> None:
        for key in list(self.targets):
            await self._rediscover(key)

    async def _rediscover(self, key: str) -> None:
        target = self.targets.get(key)
        if target is None:
            return
        for method in plain.METHODS:
            state = self._method(target, method)
            if state.state == "direct":
                continue
            if self._is_gateway_method(method):
                # 重新寻找可用连接也不会偷偷去改路由器：能力如实刷新，仍等显式同意。
                self._apply_gateway_capability(state)
                continue
            if method["mechanism"] == "observation":
                if not self._observed:
                    await self.observe(key)
                continue
            if method["mechanism"] == "webrtc":
                if target.webrtc_id is not None:
                    state.state = "trying" if state.state == "pending" else state.state
                    self._ensure_webrtc(target)
                continue
            if state.state in {"trying", "unavailable", "unsupported"}:
                continue
            await self.start_method(key, method["id"])

    # --------------------------------------------------------------- public API
    @property
    def signaling_id(self) -> str | None:
        return self.signaling.id if self.signaling else None

    def should_initiate(self, remote_id: str) -> bool:
        """Mirror the deterministic room rule peer.py uses for ICE.

        ``peer.py`` initiates only when ``self.id < peer`` where ``self.id`` is
        the *ICE* membership id. Comparing our lowest membership id instead
        would let both sides initiate (one via RTC, one via the native
        membership), which produced duplicate connection attempts that the
        server rejects.
        """
        local = self.peer.id if self.peer is not None and self.peer.id else self.signaling_id
        if not local or not remote_id:
            return False
        return local < remote_id

    async def select(self, key: str) -> None:
        self.active_target = key

    def set_telemetry_paused(self, paused: bool) -> dict:
        """Pause/resume automatic central diagnostic collection.

        Local records keep accumulating; while paused the centre's copy is
        explicitly reported as incomplete instead of pretending nothing is
        missing.
        """
        self.telemetry_paused = bool(paused)
        if self.telemetry_paused:
            # Any still-queued record means the centre no longer has the full set.
            store = getattr(self.peer, "store", None)
            if store is not None and store.pending(1):
                self.telemetry_incomplete = True
        status = self.telemetry_status()
        self._emit("telemetry", **status)
        return status

    def telemetry_status(self) -> dict:
        """自动汇集的状态与面板文案（唯一来源，界面不重复判断优先级）。

        * 暂停优先：`uploadEnabled=False` 时文案一定是「已暂停」；
        * 暂停且本机还有没上传的记录 → `complete=False` 且文案为「中心记录不完整」；
        * 暂停但队列已空 → `complete=True`（中心那份其实是完整的），文案仍是「已暂停」，
          不得出现「已开启」。
        """
        if self.telemetry_paused:
            incomplete = bool(self.telemetry_incomplete)
            return {
                "uploadEnabled": False,
                "paused": True,
                "complete": not incomplete,
                "note": plain.TELEMETRY_NOTE if incomplete else "",
                "text": plain.TELEMETRY_NOTE if incomplete else plain.TELEMETRY_PAUSED_TEXT,
            }
        return {
            "uploadEnabled": True,
            "paused": False,
            "complete": True,
            "note": "",
            "text": plain.TELEMETRY_ON_TEXT,
        }

    async def send_text(self, text: str) -> dict:
        if len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("TEXT_LIMIT")
        key = self.active_target
        if not key:
            raise RuntimeError("NO_PEER")
        message_id = str(uuid.uuid4())
        for mechanism, target_id, session in self._message_routes(key):
            try:
                if mechanism == "webrtc":
                    assert self.peer is not None
                    self.peer.send(self._peer_path(target_id), {"kind": "text", "id": message_id, "text": text})
                else:
                    await session.send_text(message_id, text)
            except Exception:
                continue
            self._record(Message(direction="out", peer=key, kind="text", id=message_id, text=text, mechanism=mechanism, at=time.time()))
            return {"id": message_id, "mechanism": mechanism}
        raise RuntimeError("NO_DIRECT_PATH")

    def webrtc_healthy(self, target: Target) -> bool:
        """True while at least one authenticated ICE path is still usable."""
        if self.peer is None or target.webrtc_id is None:
            return False
        for path in self.peer.paths.values():
            if path["peer"] == target.webrtc_id and path.get("hello") and not path["closing"]:
                return True
        return False

    def _ensure_webrtc(self, target: Target) -> None:
        """Reuse ``Peer.initiate`` (all ICE profiles) for a discovered peer id.

        ``peer.py`` only auto-initiates for peers present when its own roster
        arrives; the empty roster at join time is the common case, so the engine
        asks the same method for the peer it discovered later.
        """
        if self.peer is None or target.webrtc_id is None:
            return
        if not self.should_initiate(target.webrtc_id):
            return
        # Cooling-off between rounds: an unbounded re-offer loop would exhaust
        # the server's per-peer attempt budget and starve the other methods.
        if target.webrtc_started and time.monotonic() - target.webrtc_attempt_at < WEBRTC_RETRY_SECONDS:
            return
        target.webrtc_started = True
        target.webrtc_attempt_at = time.monotonic()
        self.peer.spawn(self.peer.initiate(target.webrtc_id))

    def _peer_path(self, peer_id: str):
        assert self.peer is not None
        for path in self.peer.paths.values():
            if path["peer"] == peer_id and path.get("hello") and not path["closing"]:
                return path
        raise RuntimeError("NO_DIRECT_PATH")

    async def send_file(self, source: str, name: str, mime: str) -> dict:
        data = await asyncio.to_thread(_read_bounded, source, MAX_FILE_BYTES)
        key = self.active_target
        if not key:
            raise RuntimeError("NO_PEER")
        for mechanism, target_id, session in self._message_routes(key):
            try:
                if mechanism == "webrtc":
                    assert self.peer is not None
                    file_id = await self.peer.send_file(self._peer_path(target_id), data, name, mime)
                else:
                    file_id = await session.send_file(data, name, mime)
            except Exception:
                continue
            self._record(
                Message(direction="out", peer=key, kind="file", id=file_id, name=name, mime=mime, bytes=len(data), data=data, mechanism=mechanism, at=time.time())
            )
            return {"id": file_id, "mechanism": mechanism, "bytes": len(data)}
        raise RuntimeError("NO_DIRECT_PATH")

    def _message_routes(self, key: str):
        """Direct, message-capable routes only, measured WebRTC first."""
        routes = []
        target = self.targets.get(key)
        if target is None:
            return routes
        for method in plain.METHODS:
            state = target.methods.get(method["id"])
            if not state or state.state != "direct" or state.probe_only or state.mechanism in {"observation", "webrtc"}:
                continue
            session = self.native_sessions.get(state.attempt) if state.attempt else None
            if session is not None and session.state == "direct" and session.capable:
                routes.append((state.mechanism, session.peer_id, session))
        if target.webrtc_id:
            try:
                self._peer_path(target.webrtc_id)
            except RuntimeError:
                pass
            else:
                routes.append(("webrtc", target.webrtc_id, None))
        return routes

    def _resolve_webrtc_pong(self, identifier: str) -> None:
        if not identifier.startswith("desktop-"):
            return
        future = self._futures.get(f"ping:{identifier[len('desktop-'):]}")
        if future is not None and not future.done():
            future.set_result(True)

    async def measure_webrtc_latency(self, key: str) -> float | None:
        """Round-trip probe on the reused data channel; local timing only."""
        if self.peer is None:
            return None
        target = self.targets.get(key)
        if target is None or target.webrtc_id is None:
            return None
        try:
            path = self._peer_path(target.webrtc_id)
        except RuntimeError:
            return None
        nonce = secrets.token_hex(8)
        loop = asyncio.get_running_loop()
        future: asyncio.Future = loop.create_future()
        self._futures[f"ping:{nonce}"] = future
        started = time.perf_counter_ns()
        try:
            self.peer.send(path, {"kind": "ping", "id": f"desktop-{nonce}"})
            await asyncio.wait_for(future, 5)
        except (asyncio.TimeoutError, RuntimeError):
            return None
        finally:
            self._futures.pop(f"ping:{nonce}", None)
        elapsed_ns = time.perf_counter_ns() - started
        if elapsed_ns <= 0:
            return None
        rtt = elapsed_ns / 1e6
        entry = self._method(target, plain.method_for("webrtc", path["profile"]))
        entry.rtt = rtt
        entry.state = "direct"
        self._emit("method", key=key, methodId=entry.method_id, state="direct", rttMs=rtt)
        return rtt

    async def benchmark(self, key: str | None = None, seconds: float = 5.0, max_bytes: int = BENCHMARK_MAX_BYTES) -> dict:
        """Isolated-lane speed test on an already-direct path. Not line bandwidth.

        Bounded on purpose: the peer's isolated receiver keeps a 10 s window and a
        32 MiB ceiling, so the run stops at whichever bound is reached first and
        reports the bytes the peer actually confirmed.
        """
        key = key or self.active_target
        target = self.targets.get(key) if key else None
        if target is None:
            raise RuntimeError("NO_PEER")
        for method in plain.METHODS:
            state = target.methods.get(method["id"])
            if state and state.state == "direct" and state.mechanism == "quic" and state.attempt:
                session = self.native_sessions.get(state.attempt)
                if session is not None and session.state == "direct":
                    return await session.benchmark(seconds=seconds, max_bytes=BENCHMARK_MAX_BYTES)
        if self.peer is not None and target.webrtc_id:
            path = await self._live_peer_path(target.webrtc_id)
            if path is None:
                raise RuntimeError("NO_DIRECT_PATH")
            return await self._webrtc_benchmark(path, seconds, max_bytes)
        raise RuntimeError("BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION")

    async def _live_peer_path(self, peer_id: str):
        """Pick an ICE path that answers a round-trip right now.

        A path can report ``hello`` locally while its peer stopped responding;
        probing before a measurement avoids attributing a dead path's result to
        a live connection.
        """
        if self.peer is None:
            return None
        for path in list(self.peer.paths.values()):
            if path["peer"] != peer_id or not path.get("hello") or path["closing"]:
                continue
            marker = f"desktop-probe-{secrets.token_hex(4)}"
            loop = asyncio.get_running_loop()
            future: asyncio.Future = loop.create_future()
            self._futures[f"ping:{marker}"] = future
            try:
                self.peer.send(path, {"kind": "ping", "id": f"desktop-{marker}"})
                await asyncio.wait_for(future, 3)
                return path
            except Exception:
                continue
            finally:
                self._futures.pop(f"ping:{marker}", None)
        return None

    async def _webrtc_benchmark(self, path, seconds: float, max_bytes: int = BENCHMARK_MAX_BYTES) -> dict:
        assert self.peer is not None
        peer = self.peer
        dc = await peer.wait_benchmark(path, 5)
        bench_id = str(uuid.uuid4())
        loop = asyncio.get_running_loop()
        ack: asyncio.Future = loop.create_future()
        self._futures[f"bench:{bench_id}"] = ack
        started = time.perf_counter_ns()
        sent = 0
        sequence = 0
        deadline = time.monotonic() + seconds
        block = bytes(4096)
        try:
            # Announce the drain allowance: the receiver's benchmark window is
            # progress-based and adds its own margin, so a long drain cannot be
            # mistaken for a dead round.
            dc.send(json.dumps({"v": 1, "kind": "bench-start", "id": bench_id, "drainMs": 10000}))
            stall = time.monotonic() + 10
            while sent < max_bytes and time.monotonic() < deadline:
                # Explicit bounded backpressure check: never block the loop on a
                # data channel the peer stopped reading. Yielding every frame is
                # deliberate: the peer's receiver drains on this same loop, and
                # a burst that outruns it is reported as backpressure instead of
                # a fabricated success.
                if dc.readyState != "open" or path.get("closing"):
                    return {"ok": False, "reason": "CHANNEL_CLOSED", "bytes": sent}
                if dc.bufferedAmount > 32768:
                    await asyncio.sleep(0.002)
                    if time.monotonic() > stall:
                        return {"ok": False, "reason": "BACKPRESSURE", "bytes": sent}
                    continue
                stall = time.monotonic() + 10
                dc.send(peer_frame(bench_id, block, sequence))
                sequence += 1
                sent += len(block)
                await asyncio.sleep(0)
            # Bounded wait instead of peer.drain: the event loop must stay free
            # to deliver the peer's own ACKs while the channel drains.
            drain_deadline = time.monotonic() + 10
            while dc.bufferedAmount > 131072 and dc.readyState == "open" and time.monotonic() < drain_deadline:
                await asyncio.sleep(0.01)
            dc.send(json.dumps({"v": 1, "kind": "bench-end", "id": bench_id, "bytes": sent}))
            try:
                answer = await asyncio.wait_for(ack, 20)
            except asyncio.TimeoutError:
                return {"ok": False, "reason": "ACK_TIMEOUT", "bytes": sent}
            elapsed_ns = time.perf_counter_ns() - started
            elapsed_ms = None if elapsed_ns <= 0 else elapsed_ns / 1e6
            confirmed = int(answer.get("bytes") or 0)
            ok = bool(answer.get("ok", True)) and not answer.get("code")
            speed = None
            if ok and elapsed_ms and confirmed:
                speed = round(confirmed * 8 / 1_000_000 / (elapsed_ms / 1000), 2)
            # A peer-side failure frame is reported as a failure, never as a fake success.
            return {"ok": ok, "bytes": confirmed, "elapsedMs": elapsed_ms, "mbps": speed,
                    "reason": None if ok else (answer.get("code") or answer.get("reason") or "BENCH_FAILED"),
                    "note": "应用层速度，不是线路带宽"}
        finally:
            self._futures.pop(f"bench:{bench_id}", None)

    async def close(self) -> None:
        self.closed = True
        self._remove_session_shim()
        for session in list(self.native_sessions.values()):
            await asyncio.gather(session.close(), return_exceptions=True)
        self.native_sessions.clear()
        if self.signaling is not None:
            await self.signaling.close()
        if self.peer is not None:
            await self.peer.close()
        if self.lan_direct is not None:
            try:
                await self.lan_direct.disable()
            except Exception as error:
                self.errors.append(f"LAN_DISABLE_FAILED:{type(error).__name__}")
        if self.gateway_optin is not None:
            try:
                await self.gateway_optin.close()
            except Exception as error:
                # 关闭时的失败要留下痕迹：映射可能还在路由器上。
                self.errors.append(f"GATEWAY_RELEASE_FAILED:{type(error).__name__}")
        if self.adapter is not None:
            await self.adapter.shutdown()
        for future in list(self._futures.values()):
            if not future.done():
                future.cancel()
        self._futures.clear()
        for task in list(self._tasks):
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()


class _TelemetryGate:
    """Wraps peer.py's durable LocalQueue so central collection can be paused.

    Delegates everything; only ``pending()`` changes. While paused the uploader in
    :mod:`p2pchat.peer` sees an empty queue, local records stay on disk, and the
    engine records that the central copy is incomplete — which the settings panel
    surfaces as 「中心记录不完整」. Nothing is deleted or rewritten.
    """

    def __init__(self, engine: "DesktopEngine", inner):
        self._engine = engine
        self._inner = inner
        self.session = inner.session

    def emit(self, kind, data, connection_id=None, attempt_id=None):
        return self._inner.emit(kind, data, connection_id, attempt_id)

    def pending(self, limit=30):
        queued = self._inner.pending(limit)
        if self._engine.telemetry_paused:
            if queued:
                self._engine.telemetry_incomplete = True
            return []
        if not queued:
            # Everything local has been acknowledged by the centre again.
            self._engine.telemetry_incomplete = False
        return queued

    def ack(self, session, ids):
        return self._inner.ack(session, ids)

    def close(self):
        return self._inner.close()

    def __getattr__(self, name):
        return getattr(self._inner, name)


def _read_bounded(source: str, limit: int) -> bytes:
    if os.path.getsize(source) > limit:
        raise ValueError("FILE_TOO_LARGE")
    with open(source, "rb") as handle:
        return handle.read(limit + 1)
