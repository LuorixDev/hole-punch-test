"""桌面端「同一网段直连发现」的接线：默认关闭，开启是一次显式动作。

native/lan_discovery.py 已经实现组播 239.255.42.99、房间作用域 HMAC、速率与表规模
有界、默认 enabled=False、生产拒绝回环接口。这里补上的是：桌面端的生产调用点、
能力文案、审计记录，以及候选校验（仍然走 adapter.validate_candidate，不放宽）。

边界：
* 默认关闭（``enabled`` 为 False），不因为连接服务器或导入 STUN 就偷偷开始组播；
* 只有真实网卡地址才允许生产启用；回环只有显式 ``restricted_local``（测试模式）才允许，
  并且这种候选会被标记 ``testOnly``，never 当作“局域网可用”的证据；
* 候选一律过一遍 ``validate_candidate``，本模块再额外拒绝回环/组播等。
"""
from __future__ import annotations

import logging
import socket
from dataclasses import dataclass, field

from p2pchat.native.adapter import validate_candidate
from p2pchat.native.lan_discovery import LanDiscovery, LanPolicy, lan_candidate, lan_capability, lan_socket_id

LOG = logging.getLogger("p2pchat.desktop.lan")
MAX_AUDIT_EVENTS = 200


def primary_ipv4(destination: str = "192.0.2.1"):
    """找到本机默认出口的 IPv4 地址；UDP connect 不发包，只做路由选择。

    用 RFC 5737 TEST-NET-1 作占位目标，避免把任何真实主机当依赖。
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect((destination, 9))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


@dataclass
class LanAudit:
    events: list = field(default_factory=list)
    sink: object = None

    def record(self, action: str, **fields):
        event = {"kind": "lan-direct", "action": action, **fields}
        self.events.append(event)
        if len(self.events) > MAX_AUDIT_EVENTS:
            del self.events[: len(self.events) - MAX_AUDIT_EVENTS]
        if callable(self.sink):
            try:
                self.sink(event)
            except Exception:
                LOG.debug("lan audit sink failed", exc_info=True)
        LOG.info("lan-direct %s %s", action, fields)
        return event


class LanDirect:
    """桌面端的局域网直连发现控制器：默认关闭、显式开启、候选必须过校验。"""

    def __init__(self, *, audit_sink=None, discovery_factory=LanDiscovery,
                 interface_resolver=primary_ipv4, capability_fn=lan_capability):
        self.audit = LanAudit(sink=audit_sink)
        self._factory = discovery_factory
        self._interface_resolver = interface_resolver
        self._capability_fn = capability_fn
        self.discovery: LanDiscovery | None = None
        self.room = ""
        self.secret = ""
        self.peer_id = ""
        self.listen_port = 0
        self.restricted_local = False
        self.peers: dict = {}
        self.last_status: dict = {"mechanism": "lan-direct", "status": "idle", "reason": "NOT_STARTED"}

    # ------------------------------------------------------------------ 能力与文案
    @property
    def enabled(self) -> bool:
        return self.discovery is not None and not self.discovery.closed

    def capability(self) -> dict:
        capability = dict(self._capability_fn())
        capability["enabled"] = self.enabled
        capability["testMode"] = bool(self.restricted_local)
        return capability

    def capability_line(self) -> str:
        capability = self.capability()
        if capability.get("enabled"):
            return (f"同一网段直连发现：已开启（{len(self.peers)} 个同网段设备）"
                    + ("【测试模式，不算局域网证据】" if self.restricted_local else ""))
        if capability.get("status") != "available":
            reason = capability.get("reason")
            human = {
                "NO_UDP_MULTICAST_API": "这台设备没有可用的 UDP 组播能力（浏览器内或系统限制）。",
            }.get(reason, f"不可用（{reason}）")
            return "同一网段直连发现：不可用——" + human
        return "同一网段直连发现：可用，但默认关闭（需要你点开启）"

    def consent_text(self) -> str:
        return (
            "开启后本机每隔几秒在**同一网段**里发一次很小的组播消息（只在本网段的设备之间，不经过路由器转发，也不上传服务器）。\n"
            "· 消息用你们房间密码派生的密钥签名，同房间的人才会回应；\n"
            "· 默认关闭；关掉后立即停止并清空已发现的设备；\n"
            "· 不扫描端口、不主动连接陌生设备，只把回应你的同房间设备作为候选。"
        )

    def technical_detail(self) -> str:
        capability = self.capability()
        return (f"机制={capability.get('mechanism')}；组播组={capability.get('group')}；"
                f"状态={capability.get('status')}；原因={capability.get('reason')}；"
                f"上限={capability.get('limits')}；接口={capability.get('interface')}")

    # ------------------------------------------------------------------ 生命周期
    async def enable(self, *, room: str, secret: str, peer_id: str, listen_port: int,
                     consent: bool = False, interface: str | None = None,
                     restricted_local: bool = False) -> dict:
        """显式开启。未同意 / 平台不支持 / 没有真实网卡地址都如实失败。"""
        capability = self._capability_fn()
        if not consent:
            self.audit.record("enable-denied", reason="LAN_OPT_IN_REQUIRED")
            raise PermissionError("LAN_OPT_IN_REQUIRED")
        if capability.get("status") != "available":
            self.audit.record("enable-denied", reason=capability.get("reason"))
            raise NotImplementedError(str(capability.get("reason")))
        if self.enabled:
            return {"status": "already-running", **self.last_status}
        address = interface or self._interface_resolver()
        resolved = None
        if address:
            try:
                import ipaddress

                candidate_address = ipaddress.ip_address(address)
                if not (candidate_address.is_loopback and not restricted_local):
                    resolved = str(candidate_address)
            except ValueError:
                resolved = None
        if resolved is None:
            self.audit.record("enable-denied", reason="NO_LAN_INTERFACE")
            raise ValueError("NO_LAN_INTERFACE")
        policy = LanPolicy(room=room, secret=secret, peer_id=peer_id, listen_port=int(listen_port),
                           interface=resolved, enabled=True, restricted_local=bool(restricted_local))
        discovery = self._factory(policy)
        discovery.subscribe(self._on_event)
        self.room, self.secret, self.peer_id = room, secret, peer_id
        self.listen_port, self.restricted_local = int(listen_port), bool(restricted_local)
        self.audit.record("enable-requested", interface=resolved, discoveryPort=policy.discovery_port,
                          restrictedLocal=bool(restricted_local))
        try:
            status = await discovery.start()
        except (NotImplementedError, PermissionError, ValueError) as exc:
            self.audit.record("enable-failed", reason=str(exc) or type(exc).__name__)
            raise
        self.discovery = discovery
        self.last_status = dict(status)
        self.audit.record("enabled", interface=resolved, status=status.get("status"),
                          discoveryPort=status.get("discoveryPort"), testMode=bool(restricted_local))
        return dict(status)

    async def disable(self) -> dict:
        if self.discovery is None:
            return {"status": "not-running"}
        discovery, self.discovery = self.discovery, None
        peers = len(self.peers)
        self.peers.clear()
        await discovery.close()
        self.last_status = {"mechanism": "lan-direct", "status": "closed", "reason": "EXPLICIT_CLOSE"}
        self.audit.record("disabled", peersFound=peers)
        return {"status": "closed", "peersFound": peers}

    # ------------------------------------------------------------------ 事件与候选
    def _on_event(self, event, params):
        if event == "lan-status":
            self.last_status = dict(params)
            self.audit.record("status", status=params.get("status"), reason=params.get("reason"))
            return
        if event != "lan-peer":
            return
        # diagnostic 只含 {address, port, identity, family, lastSeen}，没有密钥。
        identity = str(params.get("identity") or "")
        address, port, family = params.get("address"), params.get("port"), params.get("family", 4)
        if not identity or not address or not port:
            self.audit.record("peer-rejected", reason="MALFORMED_PEER")
            return
        try:
            candidate = lan_candidate(address, port, family=family, transport="udp",
                                      socket_id=lan_socket_id(identity))
        except (ValueError, TypeError) as exc:
            self.audit.record("peer-rejected", reason=str(exc) or "INVALID_CANDIDATE")
            return
        ok, reason = self.accept_candidate(candidate)
        if not ok:
            self.audit.record("peer-rejected", reason=reason, address=address, port=port)
            return
        candidate["testOnly"] = bool(self.restricted_local and _is_loopback(address))
        self.peers[identity] = {"candidate": candidate, "address": address, "port": port,
                                "family": int(family), "lastSeen": params.get("lastSeen")}
        self.audit.record("peer-found", address=address, port=port, family=int(family),
                          testOnly=bool(candidate.get("testOnly")))

    def accept_candidate(self, candidate) -> tuple:
        """候选校验：先过 adapter.validate_candidate，再拒绝生产路径里的回环地址。"""
        try:
            validate_candidate(candidate)
        except (ValueError, KeyError, TypeError) as exc:
            return False, str(exc) or "INVALID_CANDIDATE"
        if _is_loopback(candidate.get("address")) and not self.restricted_local:
            return False, "LOOPBACK_NOT_ALLOWED_IN_PRODUCTION"
        return True, None

    def candidates(self) -> list:
        return [entry["candidate"] for entry in self.peers.values()]

    def diagnostics(self) -> list:
        return [{"address": entry["address"], "port": entry["port"], "family": entry["family"],
                 "lastSeen": entry.get("lastSeen"), "testOnly": bool(entry["candidate"].get("testOnly"))}
                for entry in self.peers.values()]


def _is_loopback(address) -> bool:
    import ipaddress

    try:
        return ipaddress.ip_address(str(address)).is_loopback
    except ValueError:
        return False
