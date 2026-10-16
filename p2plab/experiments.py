from __future__ import annotations

import asyncio
import ipaddress
import math
import platform
import secrets
import time
from collections import Counter, deque

from .gateway import create_lease
from .network import command
from .research import (
    GATEWAY_METHODS,
    POOL_METHODS,
    RESEARCH_METHODS,
    TCP_METHODS,
    SocketPoolAttempt,
    Synchronizer,
    add_research_variants,
)
from .rtc import RtcAttempt
from .tcp import TcpAttempt
from .tcp_race import TcpRaceAttempt
from .udp import PROFILES, UdpAttempt


def scheme_nickname(spec):
    method = spec.get("method", "未知")
    host = spec.get("a_host") or spec.get("host") or spec.get("b_host") or ""
    family = "IPv6" if ":" in host else "IPv4" if host else "双栈"
    names = {
        "udp": "UDP开门探测",
        "quic": "QUIC打洞",
        "tcp": "TCP直连",
        "tcp-simopen": "TCP同时打开",
        "prediction": "NAT端口预测",
        "prediction-wide": "宽窗端口预测",
        "quic-sync": "同步UDP打洞",
        "quic-ttl": "低TTL预热",
        "tcp-race": "TCP监听竞争",
        "tcp-sync": "TCP同步打洞",
        "tcp-ttl": "TCP低TTL预热",
        "tcp-stunt": "TCP预热后反转",
        "udp-birthday": "单侧端口碰撞",
        "udp-birthday-dual": "双侧端口碰撞",
        "udp-port-search": "分轮端口搜索",
        "lan": "局域网发现",
        "hairpin": "NAT回环探测",
        "nat64": "NAT64跨族",
        "ice-tcp": "原生ICE-TCP",
        "ice-native": "原生ICE-UDP",
        "utp": "uTP直连",
        "pwnat": "ICMP关联",
        "natblaster": "原始TCP研究",
        "webrtc": "ICE直连",
        "pinhole": "UPnP防火墙开孔",
        "upnp": "UPnP映射",
        "natpmp": "NAT-PMP映射",
        "pcp": "PCP放行" if family == "IPv6" else "PCP映射",
    }
    if method in ("webrtc", "ice-tcp", "ice-native"):
        family = {"4": "IPv4", "6": "IPv6", "dual": "双栈"}.get(spec.get("profile"), "双栈")
    if method == "nat64":
        family = "IPv6/IPv4"
    if method in GATEWAY_METHODS:
        base = method.removesuffix("-tcp")
        names.update({"upnp-any": "UPnP自动选端口", "pcp-peer": "PCP对端映射",
                      "pcp-filter": "PCP指定对端", "pcp-prefer": "PCP严格端口"})
        return family + " " + names.get(base, base) + (" TCP" if method.endswith("-tcp") else " UDP")
    return family + " " + names.get(method, method)


def scheme_explanation(spec):
    """Describe the attempted mechanism, not an unmeasured NAT/firewall classification."""
    method = spec.get("method")
    from .research_info import explanation

    extra = explanation(spec)
    if extra:
        return extra
    host = spec.get("a_host") or spec.get("host") or spec.get("b_host") or ""
    ipv6 = ":" in host
    udp = (
        "IPv6 入站打洞：双方先发 UDP，让状态防火墙可能放行对应回包；无需 IPv4 NAT 端口映射"
        if ipv6
        else "IPv4 NAT 打洞：交换同一 UDP 套接字的 STUN 映射后互发；能否连通取决于 NAT 映射与过滤行为"
    )
    if method == "udp":
        return udp + "；仅认证探测，不承载聊天"
    if method == "quic":
        return udp + "；再用 QUIC 加密可靠流聊天，报文过大时按 MTU 证据降级"
    if method == "prediction":
        return "IPv4 NAT 端口预测：多观察点验证目的相关的稳定端口规律，有限预测后互发 UDP；保留获胜套接字建立 QUIC 聊天"
    if method == "tcp":
        return (
            "IPv6 TCP 直连：一端监听、另一端主动连接，再用 TLS 聊天；未主动打开双向入站状态"
            if ipv6
            else "IPv4 TCP 直连：主动端连接对端监听候选地址，再用 TLS 聊天；需要路由及 NAT/防火墙放行"
        )
    if method == "tcp-simopen":
        return (
            "IPv6 TCP 入站打洞：双方从各自绑定端口主动发 SYN，尝试建立双向防火墙状态，再用 TLS 聊天；无监听兜底"
            if ipv6
            else "IPv4 TCP 同时打开：双方从各自绑定端口主动发 SYN，尝试穿过 NAT/过滤后用 TLS 聊天；无监听兜底，不是普通单向直连"
        )
    if method == "webrtc":
        family = {"dual": "IPv4/IPv6 双栈", "4": "IPv4", "6": "IPv6"}.get(spec.get("profile"), "未知地址族")
        return f"{family} WebRTC：ICE 检查直连候选，经 DTLS/SCTP 数据通道聊天；不使用 TURN 中继"
    if method == "pinhole":
        return "IPv6 UPnP 防火墙开孔：请求网关为指定对端建立入站规则，再验证 UDP/QUIC；租约不等于连通"
    if method == "upnp":
        return "IPv4 UPnP 端口映射：请求网关将外部 UDP 端口转发到本机，再验证 UDP/QUIC；无租约时仍测打洞"
    if method == "natpmp":
        return "IPv4 NAT-PMP 端口映射：向默认网关申请 UDP 转发租约，再验证 UDP/QUIC；无租约时仍测打洞"
    if method == "pcp":
        return (
            "IPv6 PCP 入站放行：向网关申请 UDP MAP 租约，再验证 UDP/QUIC；是否获准与是否连通分别记录"
            if ipv6
            else "IPv4 PCP 端口映射：向网关申请外部 UDP MAP 租约，再验证 UDP/QUIC；无租约时仍测打洞"
        )
    return "未识别方案；请查看原始尝试参数"


MAX_ATTEMPTS = 200
MAX_RESEARCH_ATTEMPTS = 1024
MAX_CONCURRENT_ATTEMPTS = 4
PEER_RESULT_TIMEOUT = 130


def attempt_resource_keys(spec):
    method = spec["method"]
    if (
        spec.get("phase") == "gateway"
        or method in POOL_METHODS
        or method in ("nat64", "pwnat", "natblaster")
    ):
        return frozenset({"exclusive"})

    if method in ("webrtc", "ice-tcp", "ice-native"):
        profile = spec.get("profile", "dual")
        families = (4, 6) if profile == "dual" else (int(profile),)
    else:
        address = spec.get("host") or spec.get("a_host") or spec.get("b_host")
        families = (ipaddress.ip_address(address).version,) if address else (4, 6)

    protocol = "tcp" if method in TCP_METHODS or method.endswith("-tcp") else "udp"
    return frozenset(("network", family, protocol) for family in families)


def build_plan(
    left, right, profiles, *, gateway=True, prediction=True, max_pairs=4, expanded=False, coverage=None, research=False
):
    prefix = secrets.token_hex(6)
    plan = []

    def add(method, a=None, b=None, **params):
        plan.append(
            {
                "attempt": f"{prefix}-{len(plan):03d}-{method}",
                "method": method,
                "a_host": a,
                "b_host": b,
                "leader_initiator": True,
                **params,
            }
        )

    groups = {}
    for version in (6, 4):
        local = [a for a in left if ipaddress.ip_address(a).version == version]
        remote = [a for a in right if ipaddress.ip_address(a).version == version]
        # Start on the diagonal so a small budget samples both sides' stable/temporary addresses.
        groups[version] = [
            (a, remote[(index + offset) % len(remote)])
            for offset in range(len(remote))
            for index, a in enumerate(local)
        ]
    pairs = []
    for index in range(max((len(values) for values in groups.values()), default=0)):
        for version in (6, 4):
            if index < len(groups[version]) and len(pairs) < max_pairs:
                pairs.append(groups[version][index])
    for a, b in pairs:
        for trial in range(1, 3 if expanded else 2):
            for profile in profiles:
                # Only staggered UDP changes its timing when roles are reversed.
                for role in (True, False) if profile == "staggered" else (True,):
                    add("udp", a, b, profile=profile, leader_initiator=role, trial=trial, phase="baseline")
            for size, role in ((1200, True), (1400, False), (1400, True), (1200, False)):
                for profile in profiles:
                    add(
                        "quic",
                        a,
                        b,
                        profile=profile,
                        datagram_size=size,
                        leader_initiator=role,
                        trial=trial,
                        phase="baseline",
                    )
            for role in (True, False):
                add("tcp", a, b, leader_initiator=role, trial=trial, phase="baseline", offset=0)
        offsets = (0, 0.15, 0.4, 1.0, 0.05) if expanded else (0, 0.15, 0.4)
        for complement in (False, True):
            for index, offset in enumerate(offsets):
                role = (index % 2 == 0) != complement
                add("tcp-simopen", a, b, leader_initiator=role, phase="baseline", offset=offset)
        if prediction and ":" not in a:
            add("prediction", a, b, profile="balanced", phase="baseline")
    for profile in ("dual", "4", "6"):
        for role in (True, False):
            add("webrtc", profile=profile, leader_initiator=role, phase="baseline")
    if research:
        add_research_variants(add, pairs, gateway=gateway, prediction=prediction)
        cross = [(a, b) for a in left for b in right if ipaddress.ip_address(a).version != ipaddress.ip_address(b).version]
        for a, b in cross[:max_pairs]:
            for role in (True, False):
                add("nat64", a, b, profile="fast", leader_initiator=role, phase="baseline")
    if gateway:
        # All baseline tests finish before any router state is changed.
        for a, b in pairs:
            methods = ("pinhole", "pcp") if ":" in a else ("upnp", "pcp", "natpmp")
            for method in methods:
                for role in (True, False):
                    add(
                        method,
                        a,
                        b,
                        profile="balanced",
                        datagram_size=1200,
                        leader_initiator=role,
                        phase="gateway",
                    )
    plan.sort(key=lambda spec: spec["phase"] != "baseline")
    requested = list(plan)
    budget = MAX_RESEARCH_ATTEMPTS if research else MAX_ATTEMPTS
    if len(plan) > budget:
        reserved = [s for s in plan if s["phase"] == "gateway" or s["method"] == "webrtc"]
        selected = {s["attempt"] for s in reserved}
        queues = {}
        for spec in plan:
            if spec["attempt"] not in selected:
                key = (spec["method"], spec["a_host"], spec["b_host"])
                queues.setdefault(key, deque()).append(spec)
        while len(selected) < budget and any(queues.values()):
            for queue in queues.values():
                if queue and len(selected) < budget:
                    selected.add(queue.popleft()["attempt"])
        plan = [s for s in plan if s["attempt"] in selected]
    if coverage is not None:
        selected = {s["attempt"] for s in plan}
        coverage.update(
            budget=budget,
            requested=len(requested),
            selected=len(plan),
            omitted_count=len(requested) - len(plan),
            omitted=[s for s in requested if s["attempt"] not in selected],
            method_counts=dict(Counter(s["method"] for s in plan)),
            address_pairs=[list(pair) for pair in pairs],
            policy="bounded-coverage-not-guaranteed-success;reserve-gateways-and-ICE;fair-method-pair-sampling",
        )
        if plan:
            plan[0]["matrix_coverage"] = {
                key: coverage[key] for key in ("budget", "requested", "selected", "omitted_count")
            }
    return plan


class Experiments:
    def __init__(self, owner):
        self.owner = owner
        self.peer_ready = asyncio.Event()
        self.plan_ready = asyncio.Event()
        self.remote_hosts = []
        self.plan = []
        self.attempts = {}
        self.pending = {}
        self.remote_done = {}
        self.remote_done_events = {}
        self.results = []
        self.coverage = {}
        self.task = None
        self.closed = False
        self.signal_tasks = set()
        self.synchronizers = {}
        self.plan_parts = {}
        self.plan_part_total = None

    async def start(self):
        if self.closed:
            return
        await self.owner.network_ready.wait()
        if self.closed:
            return
        hosts = [record["address"] for record in self.owner.network["addresses"]]
        await self.owner.signal({"kind": "ready", "attempt": "setup", "addresses": hosts})
        self.task = asyncio.create_task(self.run(), name="experiment-matrix")

    def dispatch(self, data):
        task = asyncio.create_task(self.handle(data), name="experiment-signal:" + data.get("kind", "unknown"))
        self.signal_tasks.add(task)
        task.add_done_callback(self.signal_tasks.discard)
        task.add_done_callback(self.signal_finished)

    def signal_finished(self, task):
        if not task.cancelled() and task.exception():
            self.owner.log.exception("experiment.signal_failed", task.exception())

    async def handle(self, data):
        kind, attempt = data["kind"], data.get("attempt")
        if kind == "sync":
            if attempt in self.attempts and self.attempts[attempt].__class__.__name__ == "ExternalAttempt":
                await self.attempts[attempt].handle(data)
            elif attempt not in self.attempts and attempt.endswith(("-utp", "-pwnat", "-natblaster")):
                self.pending.setdefault(attempt, []).append(data)
            else:
                await self.synchronizers.setdefault(attempt, Synchronizer(self.owner, attempt)).handle(data)
            return
        if kind == "plan_part":
            index, total, part = data.get("index"), data.get("total"), data.get("plan")
            if self.owner.leader or type(index) is not int or type(total) is not int or not 0 <= index < total <= 64:
                raise ValueError("PLAN_PART_SCHEMA")
            if not isinstance(part, list) or len(part) > 16 or self.plan_part_total not in (None, total):
                raise ValueError("PLAN_PART_LIMIT")
            if index in self.plan_parts and self.plan_parts[index] != part:
                raise ValueError("PLAN_PART_CHANGED")
            self.plan_part_total = total
            self.plan_parts[index] = part
            if len(self.plan_parts) == total:
                await self.handle({"kind": "plan", "attempt": "setup",
                    "plan": [spec for i in range(total) for spec in self.plan_parts[i]]})
                self.plan_parts.clear()
            return
        if kind == "ready" and attempt == "setup":
            addresses = data.get("addresses")
            if not isinstance(addresses, list) or len(addresses) > 8:
                raise ValueError("REMOTE_ADDRESS_LIMIT")
            self.remote_hosts = []
            for address in addresses:
                ip = ipaddress.ip_address(address)
                if ip.is_unspecified or ip.is_multicast or ip.is_link_local:
                    raise ValueError("REMOTE_ADDRESS_SCOPE")
                self.remote_hosts.append(ip.compressed)
            self.peer_ready.set()
        elif kind == "plan":
            if self.owner.leader:
                raise ValueError("ONLY_LEADER_CAN_PLAN")
            plan = data.get("plan")
            if not isinstance(plan, list) or len(plan) > MAX_RESEARCH_ATTEMPTS:
                raise ValueError("PLAN_LIMIT")
            hosts = {r["address"] for r in self.owner.network["addresses"]}
            methods = {
                "udp",
                "quic",
                "tcp",
                "tcp-simopen",
                "prediction",
                "webrtc",
                "upnp",
                "pcp",
                "natpmp",
                "pinhole",
            }
            methods |= RESEARCH_METHODS
            seen = set()
            for spec in plan:
                if (
                    not isinstance(spec, dict)
                    or not isinstance(spec.get("method"), str)
                    or spec["method"] not in methods
                    or not isinstance(spec.get("attempt"), str)
                    or not 1 <= len(spec["attempt"]) <= 120
                    or spec["attempt"] in seen
                ):
                    raise ValueError("PLAN_SCHEMA")
                seen.add(spec["attempt"])
                if not isinstance(spec.get("leader_initiator"), bool):
                    raise ValueError("PLAN_ROLE")
                expected_phase = (
                    "gateway" if spec["method"] in GATEWAY_METHODS else "baseline"
                )
                if spec.get("phase") != expected_phase:
                    raise ValueError("PLAN_PHASE")
                trial = spec.get("trial", 1)
                offset = spec.get("offset", 0)
                if isinstance(trial, bool) or not isinstance(trial, int) or not 1 <= trial <= 2:
                    raise ValueError("PLAN_TRIAL")
                if (
                    isinstance(offset, bool)
                    or not isinstance(offset, (int, float))
                    or not math.isfinite(offset)
                    or not 0 <= offset <= 5
                ):
                    raise ValueError("PLAN_OFFSET")
                if spec["method"] not in ("webrtc", "ice-tcp", "ice-native"):
                    if (
                        not isinstance(spec.get("a_host"), str)
                        or not isinstance(spec.get("b_host"), str)
                        or spec["b_host"] not in hosts
                    ):
                        raise ValueError("PLAN_UNOWNED_LOCAL_ADDRESS")
                    version = ipaddress.ip_address(spec["b_host"]).version
                    if (
                        (ipaddress.ip_address(spec["a_host"]).version != version and spec["method"] != "nat64")
                        or ((spec["method"].startswith(("upnp", "natpmp", "prediction", "udp-birthday", "udp-port-search"))
                             or spec["method"] in ("pwnat", "natblaster")) and version != 4)
                        or (spec["method"].startswith("pinhole") and version != 6)
                    ):
                        raise ValueError("PLAN_ADDRESS_FAMILY")
                if spec.get("datagram_size", 1200) not in (1200, 1400):
                    raise ValueError("QUIC_MTU_PARAMETER")
                valid_profiles = ("dual", "4", "6") if spec["method"] in ("webrtc", "ice-tcp", "ice-native") else PROFILES
                if (
                    not isinstance(spec.get("profile", "balanced"), str)
                    or spec.get("profile", "balanced") not in valid_profiles
                ):
                    raise ValueError("PLAN_PROFILE")
                for key, low, high in (("ttl", 1, 8), ("socket_count", 1, 256), ("target_count", 1, 128),
                                       ("rounds", 1, 4), ("prediction_window", 1, 32), ("prediction_radius", 0, 8)):
                    if key in spec and (type(spec[key]) is not int or not low <= spec[key] <= high):
                        raise ValueError("PLAN_RESEARCH_PARAMETER")
                if "synchronized" in spec and type(spec["synchronized"]) is not bool:
                    raise ValueError("PLAN_SYNC_PARAMETER")
                for key in ("hard_side", "gateway_side"):
                    if key in spec and spec[key] not in ("a", "b", "both"):
                        raise ValueError("PLAN_SIDE_PARAMETER")
            summary = plan[0].get("matrix_coverage") if plan else None
            if summary:
                keys = ("budget", "requested", "selected", "omitted_count")
                if (
                    not isinstance(summary, dict)
                    or set(summary) != set(keys)
                    or not all(
                        isinstance(summary.get(key), int) and not isinstance(summary[key], bool)
                        for key in keys
                    )
                ):
                    raise ValueError("PLAN_COVERAGE_SCHEMA")
                if (
                    summary["budget"] not in (MAX_ATTEMPTS, MAX_RESEARCH_ATTEMPTS)
                    or len(plan) > summary["budget"]
                    or summary["selected"] != len(plan)
                    or not (
                        len(plan) <= summary["requested"] <= 8192
                        and summary["omitted_count"] == summary["requested"] - len(plan)
                    )
                ):
                    raise ValueError("PLAN_COVERAGE_COUNTS")
                self.coverage = dict(summary)
            self.plan = plan
            self.plan_ready.set()
        elif kind == "done":
            self.remote_done[attempt] = data.get("result", {})
            self.remote_done_events.setdefault(attempt, asyncio.Event()).set()
            obj = self.attempts.get(attempt)
            if (
                isinstance(obj, RtcAttempt)
                and self.remote_done[attempt].get("state") != "success"
                and not obj.path.ready.is_set()
            ):
                await obj.path.close("PEER_WEBRTC_ATTEMPT_FAILED")
        elif kind in ("candidate", "offer", "answer", "pool_select", "race_choice", "native_ice", "raw_meta"):
            obj = self.attempts.get(attempt)
            if obj is None:
                if len(self.pending) >= MAX_RESEARCH_ATTEMPTS or len(self.pending.get(attempt, [])) >= 16:
                    raise ValueError("EARLY_SIGNAL_LIMIT")
                self.pending.setdefault(attempt, []).append(data)
            elif kind == "candidate":
                obj.set_candidates(data["candidates"])
            else:
                await obj.handle(data)

    async def register(self, spec, obj):
        self.attempts[spec["attempt"]] = obj
        for data in self.pending.pop(spec["attempt"], []):
            if data["kind"] == "candidate":
                obj.set_candidates(data["candidates"])
            else:
                await obj.handle(data)
        previous_result = self.remote_done.get(spec["attempt"])
        if isinstance(obj, RtcAttempt) and previous_result and previous_result.get("state") != "success":
            await obj.path.close("PEER_WEBRTC_ATTEMPT_FAILED_BEFORE_REGISTRATION")

    async def run(self):
        try:
            # The peer may still be collecting diagnostics and running its bounded startup WAN test.
            await asyncio.wait_for(self.peer_ready.wait(), 420)
            hosts = [r["address"] for r in self.owner.network["addresses"]]
            if self.owner.leader:
                self.plan = build_plan(
                    hosts,
                    self.remote_hosts,
                    self.owner.profiles,
                    gateway=self.owner.gateway_enabled,
                    prediction=self.owner.prediction_enabled,
                    max_pairs=self.owner.max_pairs,
                    expanded=self.owner.expanded,
                    coverage=self.coverage,
                    research=self.owner.research_enabled,
                )
                if len(self.plan) <= MAX_ATTEMPTS:
                    await self.owner.signal({"kind": "plan", "attempt": "setup", "plan": self.plan})
                else:
                    total = (len(self.plan) + 15) // 16
                    for part in range(total):
                        await self.owner.signal({"kind": "plan_part", "attempt": "setup", "index": part,
                            "total": total, "plan": self.plan[part * 16:(part + 1) * 16]})
            else:
                await asyncio.wait_for(self.plan_ready.wait(), 30)
            self.owner.log.event(
                "experiment.plan",
                count=len(self.plan),
                plan=self.plan,
                policy="all-presets-even-after-success;bounded-independent-lanes;gateway-exclusive",
                coverage=self.coverage,
            )
            versions = {ipaddress.ip_address(a).version for a in hosts} & {
                ipaddress.ip_address(a).version for a in self.remote_hosts
            }
            for version in (4, 6):
                if version not in versions:
                    self.owner.log.event(
                        "experiment.not_applicable",
                        family=version,
                        reason="NO_SHARED_ADDRESS_FAMILY_NOT_FIREWALL_FAILURE",
                    )
            await self.run_plan()
            self.owner.log.event(
                "experiment.completed",
                count=len(self.results),
                success=sum(r["state"] == "success" for r in self.results),
                results=self.results,
                real_home_network="NOT_RUN_UNLESS_THIS_IS_A_REAL_CROSS_NETWORK_SESSION",
            )
            await self.owner.publish_status()
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.owner.log.exception("experiment.failed", exc)

    async def run_plan(self):
        pending = list(enumerate(self.plan))
        active = {}
        active_keys = set()
        self.owner.log.event(
            "experiment.scheduler_started",
            max_concurrency=MAX_CONCURRENT_ATTEMPTS,
            lanes=["IPv4 UDP", "IPv4 TCP", "IPv6 UDP", "IPv6 TCP"],
            exclusive=["gateway", "socket-pool", "raw-probe", "NAT64"],
        )
        try:
            while pending or active:
                if self.closed:
                    break

                while pending and len(active) < MAX_CONCURRENT_ATTEMPTS:
                    selected = None
                    for position, (index, original) in enumerate(pending):
                        spec = dict(original)
                        spec["initiator"] = spec["leader_initiator"] == self.owner.leader
                        spec["tls_client"] = spec["initiator"]
                        spec["host"] = spec["a_host"] if self.owner.leader else spec["b_host"]
                        keys = attempt_resource_keys(spec)
                        exclusive = "exclusive" in keys
                        if exclusive:
                            if active:
                                break
                            selected = (position, index, spec, keys)
                            break
                        if "exclusive" in active_keys:
                            break
                        if keys.isdisjoint(active_keys):
                            selected = (position, index, spec, keys)
                            break
                    if selected is None:
                        break
                    position, index, spec, keys = selected
                    pending.pop(position)
                    active_keys.update(keys)
                    task = asyncio.create_task(
                        self.run_attempt(spec, index), name="matrix-attempt:" + spec["attempt"]
                    )
                    active[task] = (spec, keys)
                    self.owner.log.event(
                        "experiment.scheduler_launch",
                        attempt=spec["attempt"],
                        method=spec["method"],
                        active=len(active),
                        max_concurrency=MAX_CONCURRENT_ATTEMPTS,
                        resources=sorted(map(str, keys)),
                    )

                if not active:
                    if pending and not self.closed:
                        raise RuntimeError("MATRIX_SCHEDULER_NO_RUNNABLE_ATTEMPT")
                    break

                completed, _ = await asyncio.wait(active, return_when=asyncio.FIRST_COMPLETED)
                for task in completed:
                    spec, keys = active.pop(task)
                    active_keys.difference_update(keys)
                    local_result, peer_result = task.result()
                    if local_result["data_path"] and peer_result.get("data_path"):
                        path = next((p for p in self.owner.paths if p.attempt == spec["attempt"]), None)
                        if path:
                            path.pool_managed = True
                            if path.closed:
                                path.parked = True
                    await self.owner.park_idle_paths()
                    if spec["phase"] == "gateway":
                        leases = [
                            r.get("gateway_action") == "lease-created" for r in (local_result, peer_result)
                        ]
                        self.owner.log.event(
                            "gateway.combined_evidence",
                            attempt=spec["attempt"],
                            local_lease=leases[0],
                            peer_lease=leases[1],
                            data_path=local_result["data_path"],
                            conclusion="lease-response-and-connectivity-are-independent;no-causality-claim",
                            selected_udp_remote=local_result.get("udp_remote"),
                            local_mapping=local_result.get("mapping_endpoint"),
                            peer_mapping=peer_result.get("mapping_endpoint"),
                        )
        finally:
            remaining = tuple(active)
            for task in remaining:
                task.cancel()
            if remaining:
                await asyncio.gather(*remaining, return_exceptions=True)

    async def run_attempt(self, spec, index):
        local_result = await self.execute(spec, index)
        try:
            await asyncio.wait_for(
                self.remote_done_events.setdefault(spec["attempt"], asyncio.Event()).wait(),
                PEER_RESULT_TIMEOUT,
            )
        except TimeoutError:
            self.owner.log.event(
                "experiment.peer_result_missing", attempt=spec["attempt"], level="WARNING"
            )
        return local_result, self.remote_done.get(spec["attempt"]) or {}

    async def execute(self, spec, index):
        started = time.monotonic()
        result = {
            "attempt": spec["attempt"],
            "method": spec["method"],
            "parameters": spec,
            "state": "failed",
            "data_path": False,
            "scheme_explanation": scheme_explanation(spec),
        }
        self.owner.log.event("experiment.started", index=index + 1, total=len(self.plan), **spec)
        obj, lease = None, None
        try:
            async with asyncio.timeout(self.owner.timeout * 3 + 20):
                if spec.get("host") and ":" in spec["host"]:
                    result["local_address_record"] = await self.owner.validate_local_address(spec["host"])
                if spec["method"] == "webrtc":
                    profile = spec["profile"]
                    hosts = [r["address"] for r in self.owner.network["addresses"]]
                    if profile != "dual" and not any(
                        ipaddress.ip_address(a).version == int(profile) for a in hosts
                    ):
                        raise ValueError("WEBRTC_ADDRESS_FAMILY_UNAVAILABLE")
                    obj = RtcAttempt(self.owner, spec)
                    await self.register(spec, obj)
                    path = await obj.connect()
                elif spec["method"] in ("ice-tcp", "ice-native"):
                    from .native_ice import NativeIceAttempt

                    obj = NativeIceAttempt(self.owner, spec)
                    await self.register(spec, obj)
                    path = await obj.connect()
                elif spec["method"] in ("utp", "pwnat", "natblaster"):
                    from .external import ExternalAttempt

                    obj = ExternalAttempt(self.owner, spec)
                    await self.register(spec, obj)
                    path = await obj.connect()
                elif spec["method"] in TCP_METHODS or spec["method"].endswith("-tcp"):
                    gateway_tcp = spec["method"] in GATEWAY_METHODS
                    tcp_spec = {**spec, "method": "tcp-race"} if gateway_tcp else spec
                    cls = TcpRaceAttempt if tcp_spec["method"] == "tcp-race" else TcpAttempt
                    if spec["method"] == "tcp-stunt":
                        from .tcp_stunt import StuntAttempt

                        cls = StuntAttempt
                    obj = cls(self.owner, tcp_spec, spec["host"])
                    if spec["method"] == "tcp-stunt":
                        obj.sync = self.synchronizers.setdefault(spec["attempt"], Synchronizer(self.owner, spec["attempt"]))
                    await obj.prepare()
                    await self.register(spec, obj)
                    await self.owner.signal(
                        {"kind": "candidate", "attempt": spec["attempt"], "candidates": obj.candidates}
                    )
                    await asyncio.wait_for(obj.candidates_ready.wait(), self.owner.timeout + 15)
                    if gateway_tcp:
                        lease = await self.gateway(spec, obj, result)
                    if spec.get("synchronized") or gateway_tcp:
                        await self.synchronizers.setdefault(spec["attempt"], Synchronizer(self.owner, spec["attempt"])).synchronize(self.owner.timeout + 10)
                    path = await obj.connect()
                else:
                    cls = SocketPoolAttempt if spec["method"] in POOL_METHODS else UdpAttempt
                    if spec["method"] == "lan":
                        from .lan import LanAttempt

                        cls = LanAttempt
                    elif spec["method"] == "nat64":
                        from .nat64 import Nat64Attempt

                        cls = Nat64Attempt
                    obj = cls(self.owner, spec, spec["host"])
                    await obj.open()
                    await self.register(spec, obj)
                    samples = [] if spec["method"] in POOL_METHODS or spec["method"] == "lan" else await obj.observe(self.owner.observers)
                    if spec["method"] in ("prediction", "prediction-wide"):
                        candidates = prediction_candidates(samples, window=spec.get("prediction_window", 4),
                                                           radius=spec.get("prediction_radius", 0))
                        result["prediction_candidates"] = candidates
                        result["local_prediction_available"] = bool(candidates)
                        obj.candidates += [candidate for candidate in candidates if candidate not in obj.candidates]
                    if spec["method"] == "hairpin":
                        evidence = await obj.hairpin(self.owner.timeout)
                        result["hairpin_evidence"] = evidence
                        result["state"] = "success" if evidence["confirmed"] else "failed"
                        result["reason"] = "AUTHENTICATED_HAIRPIN_PROBE_ONLY" if evidence["confirmed"] else "HAIRPIN_INCONCLUSIVE"
                        return result
                    if spec["method"] == "lan":
                        await obj.discover(self.owner.timeout)
                    else:
                        await self.owner.signal(
                            {"kind": "candidate", "attempt": spec["attempt"], "candidates": obj.candidates}
                        )
                    await asyncio.wait_for(obj.candidates_ready.wait(), self.owner.timeout + 15)
                    if spec["phase"] == "gateway":
                        lease = await self.gateway(spec, obj, result)
                    if spec.get("synchronized") or spec["method"] in ("prediction", "prediction-wide") or spec["phase"] == "gateway":
                        await self.synchronizers.setdefault(spec["attempt"], Synchronizer(self.owner, spec["attempt"])).synchronize(self.owner.timeout + 10)
                    await obj.punch(self.owner.timeout)
                    result["udp_remote"] = list(obj.remote)
                    if platform.system() == "Linux":
                        route = await command("ip", "-j", "route", "get", obj.remote[0], "from", spec["host"])
                        self.owner.log.event("network.path_route", attempt=spec["attempt"], evidence=route)
                    evidence = await obj.mtu()
                    result["mtu_evidence"] = evidence
                    if spec["method"] == "udp":
                        result["state"] = "success"
                        result["reason"] = "AUTHENTICATED_PROBE_ONLY_NO_CHAT_CHANNEL"
                        path = None
                    else:
                        requested = spec.get("datagram_size", 1200)
                        size = select_quic_payload(evidence, requested)
                        result["effective_datagram_size"] = size
                        if requested != size:
                            result["original_parameter_state"] = "size-not-confirmed;fallback-to-1200"
                            self.owner.log.event(
                                "quic.mtu_avoidance",
                                attempt=spec["attempt"],
                                requested=requested,
                                used=size,
                                original_variant="not-confirmed-not-counted-as-1400-success",
                            )
                        path = await obj.start_quic(size=size)
                    if spec["method"] in ("prediction", "prediction-wide") and not result.get("local_prediction_available"):
                        result["reason"] = "CONNECTED_WITHOUT_LOCAL_PORT_PREDICTION"
                if path:
                    result["rtt_ms"] = await path.ping()
                    result["state"], result["data_path"] = "success", True
                    if spec["phase"] == "gateway" and lease is None:
                        result["state"] = "connected-without-local-gateway-lease"
                    if spec["method"] == "pwnat":
                        result["icmp_association"] = obj.backend.association_evidence
                        if not result["icmp_association"] or not result["icmp_association"]["received"]:
                            result["state"] = "connected-without-icmp-association"
                    self.owner.log.event(
                        "path.verified",
                        attempt=spec["attempt"],
                        method=spec["method"],
                        rtt_ms=result["rtt_ms"],
                        evidence="mutual-authentication-and-data-channel-pong",
                    )
        except asyncio.CancelledError:
            result["state"] = "cancelled"
            result["reason"] = "CLIENT_SHUTDOWN_OR_SESSION_CHANGE"
            raise
        except Exception as exc:
            result["reason"] = type(exc).__name__ + ":" + str(exc)
            if any(
                word in str(exc)
                for word in ("UNAVAILABLE", "NO_STABLE", "NO_TRUSTED", "NO_CANDIDATES", "DISABLED")
            ):
                result["state"] = "not-applicable"
            self.owner.log.exception("experiment.attempt_failed", exc, attempt=spec["attempt"])
        finally:
            backend = getattr(obj, "backend", obj)
            if backend and hasattr(backend, "candidate_evidence"):
                result["candidate_evidence"] = backend.candidate_evidence()
            elif backend and hasattr(backend, "candidates"):
                result["candidate_evidence"] = {
                    "local_candidates": [list(ep) for ep in backend.candidates],
                    "remote_candidates": [list(ep) for ep in backend.remote_candidates],
                }
            result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
            if obj and not result["data_path"]:
                path = getattr(obj, "path", None) or (
                    obj.quic.path if isinstance(obj, UdpAttempt) and obj.quic else None
                )
                if path:
                    await path.close("ATTEMPT_NOT_VERIFIED")
                await obj.close()
                if lease:
                    await lease.release()
            self.results.append(result)
            self.owner.log.event("experiment.result", **result)
            try:
                await self.owner.signal(
                    {
                        "kind": "done",
                        "attempt": spec["attempt"],
                        "result": {
                            k: v for k, v in result.items() if k not in ("parameters", "mtu_evidence")
                        },
                    }
                )
            except ConnectionError:
                self.owner.log.event(
                    "experiment.result_signal_pending", attempt=spec["attempt"], level="WARNING"
                )
        return result

    async def gateway(self, spec, obj, result):
        side = "a" if self.owner.leader else "b"
        if spec.get("gateway_side", "both") not in (side, "both"):
            result["gateway_action"] = "not-requested"
            return None
        try:
            remote = min(obj.remote_candidates, key=lambda ep: not ipaddress.ip_address(ep[0]).is_global)
            lease = await create_lease(self.owner, spec["method"], obj, remote=tuple(remote))
            obj.gateway_lease = lease
            if list(lease.external) not in obj.candidates:
                obj.candidates.append(list(lease.external))
            result["gateway_action"] = "lease-created"
            result["mapping_endpoint"] = list(lease.external)
            await self.owner.signal({"kind": "candidate", "attempt": spec["attempt"], "candidates": obj.candidates})
            return lease
        except Exception as exc:
            result["gateway_action"] = "unavailable"
            result["gateway_reason"] = str(exc)
            self.owner.log.event("gateway.unavailable", str(exc), "WARNING", attempt=spec["attempt"],
                                 method=spec["method"], fallback="still-test-peer-assisted-connectivity")
            return None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.owner.log.event(
            "experiment.closed",
            completed=len(self.results),
            planned=len(self.plan),
            remaining_not_run=max(0, len(self.plan) - len(self.results)),
        )
        for task in [self.task, *self.signal_tasks]:
            if task and task is not asyncio.current_task():
                task.cancel()
        await asyncio.gather(
            *(t for t in [self.task, *self.signal_tasks] if t and t is not asyncio.current_task()),
            return_exceptions=True,
        )
        for obj in tuple(self.attempts.values()):
            path = getattr(obj, "path", None) or (
                obj.quic.path if isinstance(obj, UdpAttempt) and obj.quic else None
            )
            if path:
                await path.close("EXPERIMENT_CLOSED")
            await obj.close()

    async def stop_preserving_paths(self):
        self.closed = True
        if self.task and not self.task.done():
            self.task.cancel()
            await asyncio.gather(self.task, return_exceptions=True)
        for task in tuple(self.signal_tasks):
            task.cancel()
        await asyncio.gather(*self.signal_tasks, return_exceptions=True)
        for obj in tuple(self.attempts.values()):
            path = getattr(obj, "path", None) or (
                obj.quic.path if isinstance(obj, UdpAttempt) and obj.quic else None)
            if not path or path.closed or not path.ready.is_set():
                await obj.close()
        self.owner.log.event("experiment.replaced", completed=len(self.results), planned=len(self.plan),
                             remaining_not_run=max(0, len(self.plan) - len(self.results)), preserved_verified_paths=True)


def prediction_candidates(samples, *, window=4, radius=0):
    # Predictions are tied to observed public IPs, never guessed Internet hosts.
    if len(samples) < 4 or len({tuple(s["observer"]) for s in samples}) < 2:
        return []
    by_dest = {}
    for sample in samples:
        by_dest.setdefault(tuple(sample["observer"]), set()).add(tuple(sample["mapped"]))
    if any(len(values) != 1 for values in by_dest.values()):
        return []
    observed = [next(iter(values)) for values in by_dest.values()]
    result = []
    for address in dict.fromkeys(ep[0] for ep in observed):
        ports = [port for ip, port in observed if ip == address]
        deltas = [b - a for a, b in zip(ports, ports[1:])]
        if not deltas or not all(d == deltas[0] and 0 < abs(d) <= 8 for d in deltas):
            continue
        anchor, step = ports[-1], deltas[0]
        for n in range(1, min(window, 32) + 1):
            for offset in range(-min(radius, 8), min(radius, 8) + 1):
                candidate = [address, anchor + step * n + offset]
                if 1 <= candidate[1] <= 65535 and candidate not in result:
                    result.append(candidate)
    return result[:256]


def select_quic_payload(evidence, requested):
    confirmed = {item["udp_payload_bytes"] for item in evidence if item["confirmed"] > 0}
    if requested in confirmed and requested >= 1200:
        return requested
    if requested > 1200 and 1200 in confirmed:
        return 1200
    raise ValueError("QUIC_MINIMUM_PAYLOAD_NOT_CONFIRMED")
