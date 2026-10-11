"""桌面端「让路由器开一个端口」的接线：默认关闭，必须由用户单独点同意。

人话优先：界面标题与按钮只说“让路由器开一个端口/撤销这个端口”，
UPnP / PCP / NAT-PMP / IPv6 pinhole 只出现在技术详情里（见 ``technical_detail``）。

安全边界（与 native/gateway.py 一致，不在这里放宽）：
* 没有 ``grant_consent()`` 就不产生任何网络请求——连 socket 都不会建；
* 平台不能真实核对路由（Windows/macOS）时如实报不可用；
* 映射只有经过**外部对端**验证才算建立；没有验证者时按 gateway.py 的原义失败并撤销；
* 审计记录不含密钥、私钥、房间密码，失败原因都是可解释的短代号。
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from p2pchat.native.adapter import GATEWAY_METHODS, default_gateway_v4, gateway_platform_capability

LOG = logging.getLogger("p2pchat.desktop.gateway")
MAX_AUDIT_EVENTS = 200

# 这些代号要能直接给人看；界面会在旁边补一句人话。
PLAIN_FAILURES = {
    "GATEWAY_OPT_IN_REQUIRED": "还没有得到你的同意，所以完全没有去动路由器。",
    "PLATFORM_VALIDATION_UNAVAILABLE": "这个系统上我们没法真实核对“哪个地址才是你家路由器”，所以不做这件事。",
    "NO_LOCAL_ROUTING_TABLE": "这台机器上没有可读的路由表，无法确认网关地址。",
    "NO_DEFAULT_GATEWAY": "没有找到默认网关（可能不在家庭/办公室网络里）。",
    "GATEWAY_TIMEOUT": "路由器没有回应（可能关掉了 UPnP/PCP/NAT-PMP，或路由器不认这个请求）。",
    "EXTERNAL_VALIDATION_REQUIRED": "路由器给了端口，但还没有外部对端确认，按规则不算建立（已撤销）。",
    "EXTERNAL_VALIDATION_FAILED": "外部对端没有确认这个端口，已撤销。",
    "UPNP_CONTROL_NOT_FOUND": "没有搜到路由器的控制接口（UPnP 可能被关闭）。",
    "NOT_LOCAL_ROUTED_GATEWAY": "这个地址不是本机路由表里的默认网关，拒绝操作。",
    "MAPPING_LIMIT": "已经开满 8 个端口映射了，先撤销一些再试。",
    "INVALID_MAPPING_REQUEST": "请求的端口或时长不合法（端口 1-65535，时长 ≤ 7200 秒）。",
    "LEASE_TOO_SHORT": "租约太短（至少 30 秒）。",
}


def plain_reason(code: str | None) -> str:
    """把代号翻成人话；认不出的代号原样返回，绝不编造成功。"""
    if not code:
        return "没有可解释的原因。"
    code = str(code)
    head = code.split(":", 1)[0]
    if head in PLAIN_FAILURES:
        return PLAIN_FAILURES[head]
    for key, value in PLAIN_FAILURES.items():
        if code.startswith(key):
            return value
    return f"技术原因：{code}"


@dataclass
class AuditTrail:
    """有界、可关联、可复核的审计记录（不含任何密钥）。"""

    events: list = field(default_factory=list)
    sink: object = None

    def record(self, action: str, **fields):
        event = {"kind": "gateway", "action": action, **fields}
        self.events.append(event)
        if len(self.events) > MAX_AUDIT_EVENTS:
            del self.events[: len(self.events) - MAX_AUDIT_EVENTS]
        if callable(self.sink):
            try:
                self.sink(event)
            except Exception:  # 记录失败不能影响功能
                LOG.debug("gateway audit sink failed", exc_info=True)
        LOG.info("gateway %s %s", action, {k: v for k, v in fields.items() if k != "secret"})
        return event


class GatewayOptIn:
    """把 native/gateway.py 的能力接到桌面端：显式同意 + 审计 + 人话文案。"""

    def __init__(self, adapter=None, audit_sink=None, platform=None):
        self.adapter = adapter
        self.platform = platform
        self.audit = AuditTrail(sink=audit_sink)
        self.consented = False
        self.leases: dict = {}

    # ------------------------------------------------------------------ 能力与文案
    def capability(self) -> dict:
        """真实能力：优先问适配器；没有适配器时按平台如实判断，不默认说可用。"""
        if self.adapter is not None and hasattr(self.adapter, "gateway_capability"):
            capability = dict(self.adapter.gateway_capability())
        else:
            support = gateway_platform_capability(self.platform)
            detected = None
            if support["status"] == "available":
                detected = default_gateway_v4()  # 只读路由表；没有适配器也能如实显示网关
                if detected is None:
                    support = {"status": "unsupported", "reason": "NO_DEFAULT_GATEWAY",
                               "platform": support["platform"]}
            capability = {"v": 1, **support, "gateway": detected, "consentRequired": True,
                          "mockLoopbackAllowed": False, "mechanisms": list(GATEWAY_METHODS) + ["upnp-pinhole"],
                          "limits": {"maxMappings": 8, "maxLifetimeSeconds": 7200},
                          "note": "没有可用的原生适配器时，这里只报告平台能力。"}
        capability["consented"] = self.consented
        return capability

    def available(self) -> bool:
        return self.capability().get("status") == "available"

    def capability_line(self) -> str:
        capability = self.capability()
        if capability.get("status") != "available":
            return "不可用：" + plain_reason(capability.get("reason"))
        state = "已同意，可以试一次" if self.consented else "可用，但需要你点同意"
        return f"路由器放行：{state}（网关 {capability.get('gateway') or '未识别'}）"

    def consent_text(self) -> str:
        """点同意之前给用户看的人话说明。技术名词只出现在最后一行的详情里。"""
        capability = self.capability()
        if capability.get("status") != "available":
            return "这台机器上不会去动你的路由器。" + plain_reason(capability.get("reason"))
        return (
            "接下来要做的事：让家里的路由器临时开一个 UDP 端口，好让外面的朋友能直接连到你。\n"
            "· 只在你点“同意并试一次”之后才做；不勾选就永远不做。\n"
            "· 路由器给的端口如果不被外部对端确认，会立即撤销，不当作成功。\n"
            "· 不改路由器其它设置，不做端口扫描，失败就用别的方式打洞。\n"
            "技术详情：依次尝试 PCP → NAT-PMP → UPnP IGD；只读路由表核对网关；"
            "单次租约 ≤ 7200 秒，最多 8 条映射。"
        )

    def technical_detail(self) -> str:
        capability = self.capability()
        return (f"网关={capability.get('gateway') or '无'}；平台={capability.get('platform')}；"
                f"状态={capability.get('status')}；原因={capability.get('reason')}；"
                f"协议={'/'.join(capability.get('mechanisms', []))}")

    # ------------------------------------------------------------------ 同意
    def grant_consent(self, source: str = "ui") -> dict:
        self.consented = True
        return self.audit.record("consent-granted", source=source, platform=self.capability().get("platform"))

    def revoke_consent(self) -> dict:
        self.consented = False
        return self.audit.record("consent-revoked")

    # ------------------------------------------------------------------ 生产调用点
    async def map_port(self, internal_port: int, *, external_port: int = 0, lifetime_seconds: int = 120,
                       validator=None, protocols=None, mock_loopback: bool = False) -> dict:
        """请求一次端口映射；没有同意时**零网络请求**。"""
        capability = self.capability()
        if not self.consented:
            self.audit.record("mapping-denied", reason="GATEWAY_OPT_IN_REQUIRED",
                              internalPort=int(internal_port), platform=capability.get("platform"))
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        if self.adapter is None:
            self.audit.record("mapping-denied", reason="NO_NATIVE_ADAPTER", internalPort=int(internal_port))
            raise NotImplementedError("NO_NATIVE_ADAPTER")
        request = {"consent": True, "internalPort": int(internal_port), "externalPort": int(external_port),
                   "lifetimeSeconds": int(lifetime_seconds), "validator": validator,
                   "protocols": protocols, "mockLoopback": bool(mock_loopback),
                   "platform": capability.get("platform")}
        self.audit.record("mapping-requested", internalPort=request["internalPort"],
                          externalPort=request["externalPort"], lifetimeSeconds=request["lifetimeSeconds"],
                          protocols=list(protocols) if protocols else None, mockLoopback=bool(mock_loopback))
        try:
            result = await self.adapter.gateway_map(request)
        except PermissionError as exc:
            self.audit.record("mapping-denied", reason=str(exc) or "GATEWAY_PERMISSION", internalPort=request["internalPort"])
            raise
        except NotImplementedError as exc:
            self.audit.record("mapping-denied", reason=str(exc) or "PLATFORM_UNAVAILABLE", internalPort=request["internalPort"])
            raise
        except (RuntimeError, ValueError, TimeoutError, OSError) as exc:
            reason = str(exc) or type(exc).__name__
            self.audit.record("mapping-failed", reason=reason, plain=plain_reason(reason.split(",", 1)[0]),
                              internalPort=request["internalPort"])
            raise
        verified = bool(result.get("verified"))
        self.leases[result.get("protocol", "?")] = result
        self.audit.record("mapping-established" if verified else "mapping-unverified",
                          protocol=result.get("protocol"), externalPort=result.get("externalPort"),
                          lifetimeSeconds=result.get("lifetimeSeconds"), verified=verified)
        return result

    async def renew(self, *, protocol=None, lifetime_seconds: int = 120, validator=None) -> dict:
        if not self.consented:
            self.audit.record("renew-denied", reason="GATEWAY_OPT_IN_REQUIRED")
            raise PermissionError("GATEWAY_OPT_IN_REQUIRED")
        if self.adapter is None:
            raise NotImplementedError("NO_NATIVE_ADAPTER")
        self.audit.record("renew-requested", protocol=protocol, lifetimeSeconds=int(lifetime_seconds))
        result = await self.adapter.gateway_renew({"consent": True, "protocol": protocol,
                                                   "lifetimeSeconds": int(lifetime_seconds), "validator": validator})
        self.leases[result.get("protocol", protocol or "?")] = result
        self.audit.record("renew-ok", protocol=result.get("protocol"), lifetimeSeconds=result.get("lifetimeSeconds"),
                          verified=bool(result.get("verified")))
        return result

    async def close(self) -> dict:
        """撤销所有映射；关闭时不需要重新点同意（用户已经同意过那次操作）。"""
        if self.adapter is None or not self.leases:
            self.leases.clear()
            self.audit.record("release-skipped", reason="NO_ACTIVE_MAPPING")
            return {"released": [], "failures": []}
        result = await self.adapter.gateway_release({"consent": True})
        for protocol in result.get("released", []):
            self.leases.pop(protocol, None)
        self.audit.record("release-ok", released=list(result.get("released", [])),
                          failures=[f.get("reason") for f in result.get("failures", [])])
        return result
