"""Bounded benchmark telemetry and conservative, evidence-based attribution."""

from __future__ import annotations

import asyncio
import math
import statistics
import time
from pathlib import Path

from .status import speed_assessment


def udp_errors():
    result = {}
    try:
        lines = Path("/proc/net/snmp").read_text().splitlines()
        for header, values in zip(lines, lines[1:]):
            if header.startswith("Udp:") and values.startswith("Udp:"):
                fields = dict(zip(header.split()[1:], map(int, values.split()[1:]), strict=True))
                result.update({k: fields[k] for k in ("RcvbufErrors", "SndbufErrors")})
                break
    except (OSError, ValueError, KeyError):
        pass
    try:
        fields = dict(line.split() for line in Path("/proc/net/snmp6").read_text().splitlines())
        result.update({k: int(fields[k]) for k in ("Udp6RcvbufErrors", "Udp6SndbufErrors")})
    except (OSError, ValueError, KeyError):
        pass
    return result


class BenchProbe:
    """50ms sampling; no per-packet logging or unbounded qlog allocations."""

    interval = 0.05

    def __init__(self, path):
        self.path = path
        self.start = time.perf_counter()
        self.cpu = time.process_time()
        self.thread_cpu = time.thread_time()
        self.udp_start = udp_errors()
        self.transport_start = self.transport()
        self.competing = self.competing_work()
        self.recovery = self.transport_start.get("congestion_recovery_time")
        self.reductions = 0
        self.lag, self.windows, self.inflight = [], [], []
        self.deadline = self.start + self.interval
        self.handle = asyncio.get_running_loop().call_later(self.interval, self.sample)

    def competing_work(self):
        owner = self.path.owner
        managers = getattr(owner, "managers", [])
        transfers = getattr(getattr(owner, "transfers", None), "records", {})
        return bool(any(getattr(m, "task", None) and not m.task.done() for m in managers)
                    or any(r.get("state") in ("sending", "receiving", "verifying") for r in transfers.values()))

    def transport(self):
        getter = getattr(self.path, "transport_diagnostics", None)
        if getter:
            try:
                return getter()
            except (AttributeError, TypeError, ValueError):
                pass
        return {}

    def sample(self):
        now = time.perf_counter()
        self.lag.append(max(0, now - self.deadline) * 1000)
        self.competing = self.competing or self.competing_work()
        self.lag = self.lag[-2400:]
        data = self.transport()
        recovery = data.get("congestion_recovery_time")
        if recovery is not None and self.recovery is not None and recovery > self.recovery:
            self.reductions += 1
        self.recovery = recovery
        if "cwnd_rtt_mbps" in data:
            self.windows.append(data["cwnd_rtt_mbps"])
            self.inflight.append(data["inflight_fraction"])
            self.windows, self.inflight = self.windows[-2400:], self.inflight[-2400:]
        self.deadline = now + self.interval
        self.handle = asyncio.get_running_loop().call_later(self.interval, self.sample)

    def cancel(self):
        self.handle.cancel()

    def finish(self):
        self.cancel()
        seconds = max(1e-6, time.perf_counter() - self.start)
        transport = self.transport()
        for key, value in tuple(transport.items()):
            if key in self.transport_start and key in (
                "tx_datagrams", "rx_datagrams", "flushes", "timer_fires", "timer_late_seconds",
                "pacing_fires", "pacing_requested_seconds", "pacing_late_seconds",
            ):
                transport[key] = max(0, value - self.transport_start[key])
        if self.windows:
            transport.update(cwnd_rtt_mbps_median=statistics.median(self.windows),
                             inflight_fraction_median=statistics.median(self.inflight),
                             congestion_reductions_observed=self.reductions)
        return {
            "seconds": seconds,
            "process_cpu_seconds": time.process_time() - self.cpu,
            "event_loop_core_fraction": (time.thread_time() - self.thread_cpu) / seconds,
            "event_loop_lag_p95_ms": sorted(self.lag)[min(len(self.lag) - 1, int(len(self.lag) * .95))]
            if self.lag else None,
            "samples": len(self.lag),
            "competing_work": self.competing or self.competing_work(),
            "transport": transport,
            "udp_buffer_errors": {k: max(0, v - self.udp_start[k]) for k, v in udp_errors().items()
                                  if k in self.udp_start},
            "scope": "process-and-event-loop-thread;udp-counters-network-namespace-wide",
        }


def finite(value):
    return isinstance(value, (float, int)) and not isinstance(value, bool) and math.isfinite(value)


def bottleneck_assessment(result, reference=None, *, competing=False):
    """Never label a punch/NAT method intrinsically slow, or low Mbps as a CPU limit."""
    def verdict(state, label, reason, evidence=None):
        return {"state": state, "label": label, "reason": reason, "evidence": evidence or [],
                "confidence": "probable" if state in ("implementation", "network") else "observed"}

    def unknown(reason):
        return verdict("unknown", "未确定", reason)
    duration = result.get("seconds")
    if not finite(duration) or duration < 1 or result.get("short_sample"):
        return unknown("样本不足1秒；请增加测速大小")
    if competing:
        return unknown("打洞矩阵或文件传输仍在运行，共享CPU/带宽，需空闲复测")
    probes = [result.get("sender_runtime"), result.get("receiver_runtime")]
    if not all(isinstance(p, dict) and finite(p.get("samples")) and p["samples"] >= 10 for p in probes):
        return unknown("缺少足够的双端运行时采样；旧版对端可能不支持")
    if any(p.get("competing_work") for p in probes):
        return unknown("一端打洞矩阵或文件传输仍在运行，需双端空闲复测")
    evidence, ambiguous, all_quiet = [], [], True
    for role, probe in zip(("发送端", "接收端"), probes):
        cpu, lag = probe.get("event_loop_core_fraction"), probe.get("event_loop_lag_p95_ms")
        if not finite(cpu) or not finite(lag):
            return unknown("双端CPU/事件循环数据不完整")
        all_quiet = all_quiet and cpu < .65 and lag < 5
        if cpu >= .85:
            evidence.append(f"{role}事件循环线程占用{cpu:.0%}单核")
        elif lag >= 10:
            evidence.append(f"{role}事件循环P95延迟{lag:.1f}ms（可能受系统负载影响）")
        errors = probe.get("udp_buffer_errors") or {}
        if not isinstance(errors, dict):
            return unknown("UDP诊断格式不完整")
        if any(finite(v) and v > 0 for v in errors.values()):
            ambiguous.append(f"{role}所在网络命名空间发生UDP缓冲丢包（可能涉及其他程序）")
    sender = probes[0].get("transport") or {}
    if not isinstance(sender, dict):
        return unknown("传输后端诊断格式不完整")
    fires = sender.get("pacing_fires", 0)
    late, requested = sender.get("pacing_late_seconds", 0), sender.get("pacing_requested_seconds", 0)
    if all(finite(v) for v in (fires, late, requested)) and fires >= 20 and late > max(.1 * duration, 3 * requested):
        evidence.append("发送端QUIC pacing唤醒延误占比高，事件循环定时精度可能限速")
    wan = speed_assessment(result, reference)
    if evidence:
        return verdict("implementation", "实现限制（疑似）", "；".join(evidence + ambiguous), evidence + ambiguous)
    if ambiguous:
        return unknown("；".join(ambiguous) + "；无法仅凭命名空间计数归因到此链路")
    if all_quiet and wan and wan["state"] == "near-limit":
        return verdict("normal", "正常", "已达双端WAN参考/配置上限的90%，未发现明显实现瓶颈")
    bound, rate = sender.get("cwnd_rtt_mbps_median"), result.get("mbps")
    reductions, inflight = sender.get("congestion_reductions_observed", 0), sender.get("inflight_fraction_median", 0)
    if (all_quiet and all(finite(v) for v in (bound, rate, reductions, inflight)) and bound > 0
            and reductions >= 2 and inflight >= .75 and .65 <= rate / bound <= 1.3):
        return verdict("network", "方案/网络限制（疑似）",
                       "双端实现负载低，QUIC反复拥塞恢复且接近cwnd/RTT约束；不代表换实现也无法更快",
                       [f"拥塞恢复至少{reductions}次", f"cwnd/RTT中位参考{bound:.1f}Mbps"])
    if wan and wan["state"] == "above-reference":
        return unknown("超过WAN参考，参考可能低估或路由不同，不能据此归因")
    return unknown("未发现明确瓶颈；低速本身不能证明网络限制，需对照其他链路/更长样本")
