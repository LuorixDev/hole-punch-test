"""Symmetric-NAT port prediction on top of t10's multi-observer NAT classification.

Only for NATs classified as address-and-port-dependent (symmetric): every new
destination gets a new external port, so the peer's next external port can be
extrapolated from the ports it already allocated. This module:

- collects mapping samples with t10's probe (several observation points, several
  local ports, repeats) and reads the ordered allocation sequence from them;
- infers the allocation law (incremental / block / hash / random) from those
  samples only, and refuses to predict when the samples are insufficient or the
  law is not extrapolable;
- generates a strictly bounded candidate set, never wider than `max_span` ports
  around the last observed port and never more than `max_candidates`;
- optionally sends authenticated probes (same `Auth` HMAC frame as the adapter's
  candidate probes, one independent nonce per predicted candidate) to those
  candidates, only toward addresses that were already exchanged through
  signaling, with rate, attempt and total-time limits and a terminal reason.

What this module is not: no relay/TURN, no scanning of third-party hosts or port
ranges, no relaxed candidate validation, no change to the pairing HMAC or the
per-candidate nonce semantics. A predicted candidate is only a hint; it must
still pass the same candidate authentication before it can carry data.

Honesty: prediction hits are limited. On symmetric NATs, missing is a normal
outcome, and prediction ranks below IPv6 direct and below an explicit
router/gateway mapping request.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import time
from dataclasses import dataclass, field

from .auth import Auth, packed
from .nat_behavior import (
    MAPPING_ADDRESS_AND_PORT_DEPENDENT,
    NatProfile,
    NatProbeConfig,
    probe_nat_behavior,
)
from .stun import canonical_endpoint, receive_udp_retry, socket_address, udp_unreachable

PATTERN_INCREMENTAL = "incremental"
PATTERN_BLOCK = "block"
PATTERN_HASH = "hash"
PATTERN_RANDOM = "random"
PATTERN_UNDETERMINED = "undetermined"

STATE_HIT = "hit"
STATE_NO_HIT = "no_hit"
STATE_NOT_ATTEMPTED = "not_attempted"

OUTCOME_HIT = "hit"
OUTCOME_NO_RESPONSE = "no_response"
OUTCOME_REJECTED = "rejected"
OUTCOME_SKIPPED = "skipped"

PROBE_PREFIX = b"P2POBS1"
MAX_PORT = 65535

REASON_NOT_SYMMETRIC = "NOT_SYMMETRIC_MAPPING_BEHAVIOR"
REASON_INSUFFICIENT_SAMPLES = "INSUFFICIENT_ALLOCATION_SAMPLES"
REASON_UNPREDICTABLE = "ALLOCATION_NOT_EXTRAPOLABLE"
REASON_NO_CANDIDATES = "NO_PREDICTED_CANDIDATES"

HONESTY_NOTE = (
    "对称 NAT 下端口预测的命中概率有限，失败是正常结果，不能把它当成普遍可用的直连手段。"
    "优先顺序：1) 优先 IPv6 直连（家宽多有 IPv6，一般不受 NAT 端口分配影响）；"
    "2) 其次在自家路由器/网关上显式放行（UPnP/PCP/NAT-PMP 授权映射）；"
    "3) 最后才用端口预测，并且必须双方同时向对方发包。"
)


@dataclass(frozen=True)
class PredictionLimits:
    """Hard bounds. Everything here is enforced, not advisory."""

    max_candidates: int = 8
    max_span: int = 32
    probes_per_candidate: int = 2
    min_interval: float = 0.04
    per_candidate_timeout: float = 0.4
    total_timeout: float = 6.0
    min_samples: int = 4
    hash_window: int = 256

    def validate(self):
        if not 1 <= self.max_candidates <= 32:
            raise ValueError("INVALID_CANDIDATE_LIMIT")
        if not 1 <= self.max_span <= 512:
            raise ValueError("INVALID_SPAN_LIMIT")
        if not 1 <= self.probes_per_candidate <= 4:
            raise ValueError("INVALID_PROBE_LIMIT")
        if not 0.01 <= self.min_interval <= 1:
            raise ValueError("INVALID_RATE_LIMIT")
        if not 0.05 <= self.per_candidate_timeout <= 5:
            raise ValueError("INVALID_PROBE_TIMEOUT")
        if not 0.1 <= self.total_timeout <= 30:
            raise ValueError("INVALID_TOTAL_TIMEOUT")
        if not 1 <= self.min_samples <= 32:
            raise ValueError("INVALID_SAMPLE_MINIMUM")
        if not 16 <= self.hash_window <= 4096:
            raise ValueError("INVALID_HASH_WINDOW")
        return self


@dataclass(frozen=True)
class AllocationSample:
    """One distinct mapping: the sequence is the observed creation order."""

    sequence: int
    local_port: int
    destination: tuple[str, int]
    mapped_port: int
    mapped_address: str | None = None


@dataclass(frozen=True)
class AllocationModel:
    pattern: str
    predictable: bool
    reason: str
    evidence: str
    step: int | None = None
    block_size: int | None = None
    group_size: int | None = None
    last_base: int | None = None
    last_mapped_port: int | None = None
    sample_count: int = 0
    mapping_count: int = 0
    destination_count: int = 0
    local_port_count: int = 0


@dataclass
class SamplingReport:
    profile: NatProfile
    samples: tuple[AllocationSample, ...] = ()
    symmetric: bool = False
    reason: str = ""

    def report(self):
        payload = dict(self.profile.report())
        payload.update({
            "symmetric": self.symmetric,
            "reason": self.reason,
            "allocationSampleCount": len(self.samples),
            "destinationCount": len({sample.destination for sample in self.samples}),
            "localPortCount": len({sample.local_port for sample in self.samples}),
            "sampledMappingsIncluded": False,
            "privacy": "allocation samples name public mapped endpoints and stay local; they are not part of this report",
        })
        return payload


def samples_from_profile(profile: NatProfile):
    """Ordered distinct mappings from a t10 profile; repeats of one mapping collapse."""
    seen = {}
    samples = []
    for observation in profile.observations:
        key = (observation.local_port, observation.destination)
        if key in seen:
            continue
        seen[key] = len(seen)
        samples.append(AllocationSample(seen[key], observation.local_port, observation.destination,
                                        observation.mapped[1], observation.mapped[0]))
    return tuple(samples)


async def collect_samples(config: NatProbeConfig):
    """Run t10's probe and return its classification plus the ordered port samples."""
    if not isinstance(config, NatProbeConfig):
        raise TypeError("NatProbeConfig required")
    profile = await probe_nat_behavior(config)
    samples = samples_from_profile(profile)
    symmetric = profile.mapping == MAPPING_ADDRESS_AND_PORT_DEPENDENT
    reason = "SYMMETRIC_OBSERVED" if symmetric else f"NOT_SYMMETRIC:{profile.mapping}"
    return SamplingReport(profile, samples, symmetric, reason)


def infer_allocation(samples, limits=None):
    """Infer the external-port allocation law from observed samples only."""
    limits = (limits or PredictionLimits()).validate()
    ordered = sorted(samples, key=lambda sample: sample.sequence)
    stats = dict(sample_count=len(ordered),
                 mapping_count=len({(s.local_port, s.destination) for s in ordered}),
                 destination_count=len({s.destination for s in ordered}),
                 local_port_count=len({s.local_port for s in ordered}))
    if len(ordered) < limits.min_samples:
        return AllocationModel(PATTERN_UNDETERMINED, False, REASON_INSUFFICIENT_SAMPLES,
                               f"only {len(ordered)} distinct mappings were observed and the minimum for any "
                               f"inference is {limits.min_samples}; no port is predicted", **stats)
    ports = [sample.mapped_port for sample in ordered]
    deltas = [later - earlier for earlier, later in zip(ports, ports[1:])]
    groups = {}
    for sample in ordered:
        groups.setdefault(sample.destination, []).append(sample.mapped_port)
    group_ports = list(groups.values())
    if len(group_ports) >= 2 and all(len(ports_of_group) >= 2 for ports_of_group in group_ports):
        bases = [min(ports_of_group) for ports_of_group in group_ports]
        base_deltas = [later - earlier for earlier, later in zip(bases, bases[1:])]
        internal = [[later - earlier for earlier, later in zip(sorted(ports_of_group), sorted(ports_of_group)[1:])]
                    for ports_of_group in group_ports]
        if (len(set(base_deltas)) == 1 and base_deltas[0] > 4
                and all(step and all(1 <= delta <= 4 for delta in step) for step in internal)):
            return AllocationModel(
                PATTERN_BLOCK, True, "BLOCK_ALLOCATION_OBSERVED",
                f"{len(group_ports)} destination blocks each held {min(len(g) for g in group_ports)} or more "
                f"contiguous ports and the block base advanced by {base_deltas[0]} every time",
                block_size=base_deltas[0], group_size=min(len(ports_of_group) for ports_of_group in group_ports),
                last_base=bases[-1], last_mapped_port=ports[-1], **stats)
    if deltas and all(delta > 0 for delta in deltas) and max(deltas) <= 4:
        step = max(set(deltas), key=deltas.count)
        if all(abs(delta - step) <= 1 for delta in deltas):
            return AllocationModel(
                PATTERN_INCREMENTAL, True, "INCREMENTAL_ALLOCATION_OBSERVED",
                f"{len(deltas)} consecutive new mappings increased by {step} (within one port); the next mapping "
                f"continues that sequence", step=step, last_mapped_port=ports[-1], **stats)
    span = max(ports) - min(ports)
    repeated = len(set(ports)) < len(ports)
    if repeated or span <= limits.hash_window:
        return AllocationModel(
            PATTERN_HASH, False, REASON_UNPREDICTABLE,
            f"ports show no ordering ({len(deltas)} deltas are not a constant small step) and either repeat across "
            f"different mappings or stay inside a {span}-port window, which is what a hash-style allocator looks "
            f"like; such a law cannot be extrapolated from observations", **stats)
    return AllocationModel(
        PATTERN_RANDOM, False, REASON_UNPREDICTABLE,
        f"ports show no ordering and spread over {span} ports, so the allocator looks random and cannot be "
        f"extrapolated", **stats)


def predict_candidates(model: AllocationModel, limits=None):
    """Bounded candidate ports from a predictable model; empty when not predictable."""
    limits = (limits or PredictionLimits()).validate()
    if not model.predictable or model.last_mapped_port is None:
        return ()
    candidates = []
    if model.pattern == PATTERN_INCREMENTAL:
        step = max(1, model.step or 1)
        for index in range(1, limits.max_candidates + 1):
            port = model.last_mapped_port + step * index
            if not _port_ok(port, model.last_mapped_port, limits):
                break
            candidates.append(port)
    elif model.pattern == PATTERN_BLOCK:
        if model.block_size is None or model.last_base is None or not model.group_size:
            return ()
        base = model.last_base + model.block_size
        for offset in range(model.group_size):
            port = base + offset
            if not _port_ok(port, model.last_mapped_port, limits):
                break
            candidates.append(port)
    else:
        return ()
    return tuple(dict.fromkeys(candidates))[:limits.max_candidates]


def _port_ok(port, anchor, limits):
    return 1 <= port <= MAX_PORT and abs(port - anchor) <= limits.max_span


def _empty_model(reason):
    return AllocationModel(PATTERN_UNDETERMINED, False, reason, "", sample_count=0)


@dataclass(frozen=True)
class PeerAuthContext:
    """The existing attempt-bound room-key context; the HMAC itself is unchanged."""

    room: str
    secret: str
    connection: str
    attempt: str
    local_id: str
    peer_id: str

    def new_auth(self):
        return Auth(self.room, self.secret, self.connection, self.attempt, self.local_id, self.peer_id)


@dataclass(frozen=True)
class ProbeOutcome:
    target: tuple[str, int]
    state: str
    reason: str
    sends: int
    rtt_ms: float | None = None


@dataclass
class PunchReport:
    model: AllocationModel
    candidates: tuple[tuple[str, int], ...]
    outcomes: tuple[ProbeOutcome, ...]
    state: str
    reason: str
    duration_ms: float = 0.0
    sends: int = 0
    limits: PredictionLimits = field(default_factory=PredictionLimits)

    @property
    def hit(self):
        return any(outcome.state == OUTCOME_HIT for outcome in self.outcomes)

    def report(self, include_endpoints=False):
        payload = {
            "state": self.state,
            "reason": self.reason,
            "pattern": self.model.pattern,
            "predictable": self.model.predictable,
            "modelEvidence": self.model.evidence,
            "allocationSamples": self.model.sample_count,
            "distinctMappings": self.model.mapping_count,
            "destinations": self.model.destination_count,
            "localPorts": self.model.local_port_count,
            "candidateCount": len(self.candidates),
            "probeSends": self.sends,
            "durationMs": self.duration_ms,
            "outcomeStates": [outcome.state for outcome in self.outcomes],
            "note": HONESTY_NOTE,
            "inferenceNote": ("predicted ports are extrapolated from observed mapped ports; a predicted candidate "
                              "must still pass the normal candidate authentication before it can carry data"),
            "privacy": "predicted and observed public endpoints stay local unless include_endpoints is True",
        }
        if include_endpoints:
            payload["candidates"] = [list(candidate) for candidate in self.candidates]
            payload["outcomes"] = [{"target": list(outcome.target), "state": outcome.state,
                                    "reason": outcome.reason, "sends": outcome.sends,
                                    "rttMs": outcome.rtt_ms} for outcome in self.outcomes]
        return payload


def plan_from_profile(profile: NatProfile, limits=None):
    """Pure planning step: classification -> samples -> model -> bounded candidates."""
    limits = (limits or PredictionLimits()).validate()
    if profile.mapping != MAPPING_ADDRESS_AND_PORT_DEPENDENT:
        return AllocationModel(PATTERN_UNDETERMINED, False, REASON_NOT_SYMMETRIC,
                               f"mapping behavior is {profile.mapping}, not address-and-port-dependent; port "
                               f"prediction is only defined for symmetric NATs"), (), limits
    samples = samples_from_profile(profile)
    model = infer_allocation(samples, limits)
    candidates = predict_candidates(model, limits)
    return model, candidates, limits


class PredictionPuncher:
    """Bounded, rate-limited, single-socket authenticated probes toward signaled addresses."""

    def __init__(self, signaled_addresses, auth_context, limits=None, *, bind_host, anchor_port=None):
        self.limits = (limits or PredictionLimits()).validate()
        self.context = auth_context
        self.anchor_port = anchor_port
        self.addresses = []
        for address in signaled_addresses:
            host, _ = canonical_endpoint((address, 1))  # rejects unspecified/multicast/link-local/non-literal
            if host not in self.addresses:
                self.addresses.append(host)
        if not self.addresses:
            raise ValueError("SIGNALED_ADDRESS_REQUIRED")
        self.family = socket.AF_INET6 if ipaddress.ip_address(self.addresses[0]).version == 6 else socket.AF_INET
        if any(ipaddress.ip_address(address).version != ipaddress.ip_address(self.addresses[0]).version
               for address in self.addresses):
            raise ValueError("SIGNALED_FAMILY_MISMATCH")
        self.bind_host = canonical_endpoint((bind_host, 1), self.family)[0]

    def expand(self, candidate_ports):
        """Port-major, hard-capped expansion over the signaled addresses only."""
        targets = []
        for port in candidate_ports:
            for address in self.addresses:
                if len(targets) >= self.limits.max_candidates:
                    return tuple(targets)
                targets.append((address, port))
        return tuple(targets)

    def validate_candidates(self, candidates):
        targets = []
        for endpoint in candidates:
            host, port = canonical_endpoint(endpoint, self.family)
            if host not in self.addresses:
                raise ValueError("UNSIGNALED_TARGET_ADDRESS")
            if self.anchor_port is not None and abs(port - self.anchor_port) > self.limits.max_span:
                raise ValueError("PREDICTION_WINDOW_EXCEEDED")
            targets.append((host, port))
        targets = list(dict.fromkeys(targets))
        if len(targets) > self.limits.max_candidates:
            raise ValueError("CANDIDATE_LIMIT")
        return targets

    async def punch(self, candidates, model=None):
        started = time.monotonic()
        targets = self.validate_candidates(candidates)
        if not targets:
            return PunchReport(model or _empty_model(REASON_NO_CANDIDATES), (), (), STATE_NOT_ATTEMPTED,
                               REASON_NO_CANDIDATES, limits=self.limits)
        sock = socket.socket(self.family, socket.SOCK_DGRAM)
        if self.family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        sock.setblocking(False)
        outcomes = []
        deadline = started + self.limits.total_timeout
        next_send = 0.0
        try:
            sock.bind((self.bind_host, 0))
            for target in targets:
                outcome, sends, next_send, stop = await self._probe(sock, target, deadline, next_send)
                outcomes.append(outcome)
                if stop:
                    break
        finally:
            sock.close()
        state = STATE_HIT if any(outcome.state == OUTCOME_HIT for outcome in outcomes) else STATE_NO_HIT
        reason = "AUTHENTICATED_HIT" if state == STATE_HIT else (outcomes[-1].reason if outcomes
                                                                else REASON_NO_CANDIDATES)
        return PunchReport(model or _empty_model(reason), tuple(targets), tuple(outcomes), state, reason,
                           (time.monotonic() - started) * 1000, sum(o.sends for o in outcomes), self.limits)

    async def _probe(self, sock, target, deadline, next_send):
        loop = asyncio.get_running_loop()
        sends = 0
        hit = False
        rejected = False
        rtt_ms = None
        auth = self.context.new_auth()  # one independent nonce per predicted candidate, reused by its retries
        for _ in range(self.limits.probes_per_candidate):
            now = time.monotonic()
            if now >= deadline:
                break
            if next_send > now:
                await asyncio.sleep(min(next_send - now, max(0.0, deadline - now)))
            if time.monotonic() >= deadline:
                break
            next_send = max(time.monotonic(), next_send) + self.limits.min_interval
            request = PROBE_PREFIX + packed(auth.frame())
            sends += 1
            try:
                await loop.sock_sendto(sock, request, socket_address(target, self.family))
            except OSError as exc:
                if not udp_unreachable(exc):
                    return ProbeOutcome(target, OUTCOME_SKIPPED, "SEND_FAILED", sends), sends, next_send, True
            sent_at = time.monotonic()
            wait = min(sent_at + self.limits.per_candidate_timeout, deadline)
            while time.monotonic() < wait:
                try:
                    packet, remote = await asyncio.wait_for(receive_udp_retry(sock, 2048),
                                                            wait - time.monotonic())
                except asyncio.TimeoutError:
                    break
                try:
                    source = canonical_endpoint(remote, self.family)
                except ValueError:
                    continue
                if source != target:
                    continue  # never accept a reply from a host we did not target
                if not packet.startswith(PROBE_PREFIX):
                    rejected = True
                    continue
                try:
                    frame = json.loads(packet[len(PROBE_PREFIX):])
                    if not isinstance(frame, dict):
                        raise ValueError("AUTH_FAILED")
                    response = auth.receive(frame)
                except (ValueError, TypeError):
                    rejected = True
                    continue
                if response:
                    try:
                        await loop.sock_sendto(sock, PROBE_PREFIX + packed(response),
                                               socket_address(target, self.family))
                    except OSError:
                        pass
                hit = True
                rtt_ms = (time.monotonic() - sent_at) * 1000
                break
            if hit:
                break
        if hit:
            return ProbeOutcome(target, OUTCOME_HIT, "AUTHENTICATED_HIT", sends, rtt_ms), sends, next_send, True
        if time.monotonic() >= deadline:
            return ProbeOutcome(target, OUTCOME_NO_RESPONSE, "DEADLINE_REACHED", sends), sends, next_send, False
        if rejected:
            return ProbeOutcome(target, OUTCOME_REJECTED, "REPLIES_REJECTED", sends), sends, next_send, False
        return ProbeOutcome(target, OUTCOME_NO_RESPONSE, "NO_AUTHENTICATED_REPLY", sends), sends, next_send, False


async def punch_with_prediction(profile, signaled_addresses, auth_context, *, bind_host, limits=None):
    """Plan from a t10 profile and, if predictable, probe the bounded candidates once."""
    model, candidates, limits = plan_from_profile(profile, limits)
    started = time.monotonic()
    if not candidates:
        return PunchReport(model, (), (), STATE_NOT_ATTEMPTED, model.reason, (time.monotonic() - started) * 1000,
                           0, limits)
    puncher = PredictionPuncher(signaled_addresses, auth_context, limits, bind_host=bind_host,
                                anchor_port=model.last_mapped_port)
    targets = puncher.expand(candidates)
    report = await puncher.punch(targets, model)
    return report
