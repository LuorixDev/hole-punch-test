from __future__ import annotations

import asyncio
import ipaddress
import secrets
import statistics
import time

from .udp import UdpAttempt

POOL_METHODS = {"udp-birthday", "udp-birthday-dual", "udp-port-search"}
TCP_METHODS = {"tcp", "tcp-simopen", "tcp-race", "tcp-sync", "tcp-ttl", "tcp-stunt"}
GATEWAY_METHODS = {
    "upnp", "upnp-any", "pcp", "pcp-peer", "pcp-filter", "pcp-prefer", "natpmp", "pinhole",
}
GATEWAY_METHODS |= {method + "-tcp" for method in tuple(GATEWAY_METHODS)}
RESEARCH_METHODS = POOL_METHODS | TCP_METHODS | GATEWAY_METHODS | {
    "quic-sync", "quic-ttl", "prediction-wide", "lan", "hairpin", "nat64", "ice-tcp", "ice-native",
    "utp", "pwnat", "natblaster",
}


def add_research_variants(add, pairs, *, gateway, prediction):
    for a, b in pairs:
        for role in (True, False):
            add("quic-sync", a, b, profile="fast", synchronized=True, leader_initiator=role, phase="baseline")
            for ttl in (1, 2, 3):
                add("quic-ttl", a, b, profile="fast", ttl=ttl, leader_initiator=role, phase="baseline")
            for offset in (0, 0.5, 2.0):
                add("tcp-race", a, b, offset=offset, leader_initiator=role, phase="baseline")
            add("tcp-sync", a, b, synchronized=True, leader_initiator=role, phase="baseline")
            for ttl in (1, 2, 3):
                add("tcp-ttl", a, b, ttl=ttl, synchronized=True, leader_initiator=role, phase="baseline")
                add("tcp-stunt", a, b, ttl=ttl, leader_initiator=role, phase="baseline")
            for offset in (0.5, 2.0, 5.0):
                add("quic-sync", a, b, profile="staggered", synchronized=True, offset=offset,
                    leader_initiator=role, phase="baseline")
        add("lan", a, b, profile="fast", phase="baseline")
        add("hairpin", a, b, phase="baseline")
        for role in (True, False):
            add("utp", a, b, profile="fast", leader_initiator=role, phase="baseline")
        if ":" not in a:
            if prediction:
                for window, radius in ((16, 2), (32, 4)):
                    add("prediction-wide", a, b, profile="balanced", prediction_window=window,
                        prediction_radius=radius, phase="baseline")
            for count in (16, 64, 256):
                for hard_side in ("a", "b"):
                    add("udp-birthday", a, b, profile="fast", socket_count=count,
                        hard_side=hard_side, target_count=64, rounds=2, phase="baseline")
                add("udp-birthday-dual", a, b, profile="fast", socket_count=count,
                    hard_side="both", target_count=64, rounds=2, phase="baseline")
            add("udp-port-search", a, b, profile="fast", socket_count=16, hard_side="both",
                target_count=128, rounds=4, phase="baseline")
            for role in (True, False):
                add("pwnat", a, b, profile="fast", leader_initiator=role, phase="baseline")
                for ttl in (1, 2, 3):
                    add("natblaster", a, b, ttl=ttl, leader_initiator=role, phase="baseline")
    for method in ("ice-tcp", "ice-native"):
        for profile in ("dual", "4", "6"):
            for role in (True, False):
                add(method, profile=profile, leader_initiator=role, phase="baseline")
    if gateway:
        for a, b in pairs:
            methods = ("pcp", "pcp-peer", "pcp-filter", "pcp-prefer", "pinhole") if ":" in a else (
                "upnp", "upnp-any", "pcp", "pcp-peer", "pcp-filter", "pcp-prefer", "natpmp")
            for method in methods:
                for protocol in ("", "-tcp"):
                    for side in ("a", "b", "both"):
                        add(method + protocol, a, b, profile="fast", gateway_side=side,
                            phase="gateway", leader_initiator=side != "b")


class Synchronizer:
    def __init__(self, owner, attempt):
        self.owner, self.attempt = owner, attempt
        self.remote_ready, self.go = asyncio.Event(), asyncio.Event()
        self.pending = {}
        self.rtts = []

    async def send(self, stage, nonce=""):
        await self.owner.signal({"kind": "sync", "attempt": self.attempt, "stage": stage, "nonce": nonce})

    async def handle(self, data):
        stage, nonce = data.get("stage"), data.get("nonce")
        if stage not in ("ready", "probe", "echo", "go") or not isinstance(nonce, str) or len(nonce) > 32:
            raise ValueError("SYNC_SCHEMA")
        if stage == "ready":
            self.remote_ready.set()
        elif stage == "probe":
            await self.send("echo", nonce)
        elif stage == "echo":
            entry = self.pending.get(nonce)
            if entry and not entry.done():
                entry.set_result(time.monotonic())
        else:
            self.go.set()

    async def synchronize(self, timeout):
        async with asyncio.timeout(timeout):
            await self.send("ready")
            await self.remote_ready.wait()
            if self.owner.leader:
                for _ in range(3):
                    nonce = secrets.token_hex(8)
                    future = asyncio.get_running_loop().create_future()
                    self.pending[nonce] = future
                    start = time.monotonic()
                    try:
                        await self.send("probe", nonce)
                        self.rtts.append(await future - start)
                    finally:
                        self.pending.pop(nonce, None)
                await self.send("go")
                await asyncio.sleep(statistics.median(self.rtts) / 2)
            else:
                await self.go.wait()
        self.owner.log.event("experiment.synchronized", attempt=self.attempt,
                             local_monotonic=time.monotonic(), rtt_seconds=self.rtts,
                             jitter_seconds=max(self.rtts) - min(self.rtts) if self.rtts else None,
                             evidence="control-channel-RTT-half;no-wall-clock-assumption;asymmetry-not-excluded")


class SocketPoolAttempt:
    """Bounded birthday/segmented searches, with authenticated winner agreement."""

    def __init__(self, owner, spec, host):
        self.owner, self.spec, self.host = owner, spec, host
        self.attempt = spec["attempt"]
        self.sockets, self.candidates, self.remote_candidates = [], [], []
        self.candidates_ready, self.selection = asyncio.Event(), asyncio.Event()
        self.selected_nonce = None
        self.winner = self.path = None
        self.closed = False

    async def open(self):
        side = "a" if self.owner.leader else "b"
        count = self.spec["socket_count"] if self.spec["hard_side"] in (side, "both") else 1
        try:
            for _ in range(count):
                udp = UdpAttempt(self.owner, {**self.spec, "pool_unselected": True}, self.host)
                self.sockets.append(udp)
                await udp.open()
                self.candidates.extend(udp.candidates)
            available = await self.owner.stun_selector.available(self.owner.observers, [self.host],
                                                               attempt=self.attempt)
            targets = list(dict.fromkeys(tuple(item["target"]) for item in available))[:2]
            semaphore = asyncio.Semaphore(16)

            async def observe(udp):
                async with semaphore:
                    for target in targets:
                        try:
                            mapping = (await udp.binding(target, timeout=1))["mapped"]
                            if list(mapping) not in udp.candidates:
                                udp.candidates.append(list(mapping))
                                self.candidates.append(list(mapping))
                            self.owner.log.event("pool.mapping", attempt=self.attempt,
                                local=udp.candidates[0], observer=target, mapped=mapping)
                        except (OSError, TimeoutError, ValueError) as exc:
                            self.owner.log.event("pool.mapping_failed", str(exc), "WARNING", attempt=self.attempt,
                                                 local=udp.candidates[0], observer=target)

            await asyncio.gather(*(observe(udp) for udp in self.sockets))
            self.candidates = self.candidates[:512]
            self.owner.log.event("pool.prepared", attempt=self.attempt, sockets=count,
                                 candidates=self.candidates, maximum_packets_per_second=200)
        except BaseException:
            await self.close()
            raise

    def set_candidates(self, candidates):
        if not isinstance(candidates, list) or len(candidates) > 512:
            raise ValueError("POOL_CANDIDATE_LIMIT")
        from .common import endpoint

        result = [endpoint(*candidate) for candidate in candidates]
        if any(ipaddress.ip_address(ip).version != 4 or ipaddress.ip_address(ip).is_loopback
               and not self.owner.loopback for ip, _ in result):
            raise ValueError("POOL_ADDRESS_SCOPE")
        self.remote_candidates = sorted(result, key=lambda item: not ipaddress.ip_address(item[0]).is_global)
        self.candidates_ready.set()

    async def handle(self, data):
        if data.get("kind") != "pool_select" or not isinstance(data.get("nonce"), str) or len(data["nonce"]) != 32:
            raise ValueError("POOL_SELECTION_SCHEMA")
        self.selected_nonce = data["nonce"]
        self.selection.set()

    async def punch(self, timeout):
        await asyncio.wait_for(self.candidates_ready.wait(), timeout)
        if not self.remote_candidates:
            raise ValueError("POOL_NO_CANDIDATES")
        observed_ips = list(dict.fromkeys(ip for ip, _ in self.remote_candidates))[:4]
        count, rounds = self.spec["target_count"], self.spec["rounds"]
        started, sent = time.monotonic(), 0
        frame_cache = {}
        selected = None
        while not self.closed and time.monotonic() - started < timeout:
            progress = min(rounds - 1, int((time.monotonic() - started) * rounds / timeout))
            if selected != progress:
                selected = progress
                low, high = 1024, 65536
                if self.spec["method"] == "udp-port-search":
                    width = (65536 - 1024) // rounds
                    low, high = 1024 + progress * width, min(65536, 1024 + (progress + 1) * width)
                targets = self.remote_candidates[:64] + [
                    (ip, low + secrets.randbelow(high - low)) for ip in observed_ips for _ in range(count)
                ]
                targets = list(dict.fromkeys(targets))[:512]
                self.owner.log.event("pool.round", attempt=self.attempt, round=progress + 1,
                                     target_ips=observed_ips, port_range=[low, high - 1], targets=len(targets),
                                     target_endpoints=[list(ep) for ep in targets])
            if self.owner.leader:
                winners = [udp for udp in self.sockets if udp.direct.is_set()]
                if winners:
                    self.winner = winners[0]
                    await self.owner.signal({"kind": "pool_select", "attempt": self.attempt,
                        "nonce": self.winner.nonce_for(self.winner.remote)})
                    break
            elif self.selected_nonce:
                matches = [(udp, source) for udp in self.sockets for source, auth in udp.auth.items()
                    if auth["hello"] and auth["ack"] and auth["nonce"] == self.selected_nonce]
                if matches:
                    self.winner, source = matches[0]
                    self.winner.remote = source
                if self.winner:
                    break
            udp = self.sockets[sent % len(self.sockets)]
            target = targets[(sent // len(self.sockets)) % len(targets)]
            key = (id(udp), target)
            body = frame_cache.setdefault(key, None)
            if body is None:
                body = udp.frame("hello", target=target)
                frame_cache[key] = body
            udp.send(target, body)
            sent += 1
            await asyncio.sleep(0.005)
        if not self.winner:
            raise TimeoutError("POOL_NO_AUTHENTICATED_WINNER")
        self.winner.spec["pool_unselected"] = False
        await asyncio.gather(*(udp.close() for udp in self.sockets if udp is not self.winner))
        self.owner.log.event("pool.winner", attempt=self.attempt, local=self.winner.candidates[0],
                             remote=self.winner.remote, packets=sent,
                             evidence="same-socket-mutual-challenge;leader-nonce-selection")

    @property
    def remote(self):
        return self.winner.remote if self.winner else None

    async def mtu(self):
        return await self.winner.mtu()

    async def start_quic(self, size=1200):
        self.path = await self.winner.start_quic(size)
        return self.path

    async def close(self):
        if self.closed:
            return
        self.closed = True
        await asyncio.gather(*(udp.close() for udp in self.sockets))
