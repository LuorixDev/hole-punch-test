from __future__ import annotations

import argparse
import asyncio
import collections
import contextlib
import ipaddress
import json
import math
import os
import secrets
import shlex
import signal
import socket
import ssl
import sys
import time
import tomllib
import uuid
from pathlib import Path as FilePath
from urllib.parse import parse_qs, urlsplit, urlunsplit

import aiohttp
import psutil
from rich.console import Console
from rich.text import Text

from .common import MAX_TEXT, Identity
from .console import ConsoleReader
from .experiments import Experiments
from .inbound import SCOPE, assessment, message
from .journal import Journal
from .logcodec import CODEC, MAX_BATCH_BYTES, MAX_BATCH_EVENTS, encode_batch
from .network import (
    address_fingerprint,
    address_rejection,
    apply_address_inventory,
    read_address_inventory,
    select_addresses,
    snapshot,
)
from .performance import bottleneck_assessment
from .runtime import application_directory, configure_console_encoding, default_client_data
from .session import PATH_LIFECYCLE_CAPABILITY, Dedup
from .status import direction_reference, public_ip_evidence, speed_assessment, utcnow, validate_status
from .transfers import RECEIPT_CAPABILITY, TransferManager, disk_call, open_source, validate_receipt
from .udp import PROFILES
from .wan import configured_families
from .wan import measure as measure_wan

NETWORK_TEST_NOTICE = "真实网络测试前请关闭 VPN、代理和 TUN，避免测到代理出口。"


def normalize_server_address(address):
    address = address.strip()
    if not address or any(char.isspace() or ord(char) < 32 for char in address):
        raise ValueError("服务器地址不能为空或包含空白")
    explicit_scheme = "://" in address
    if not explicit_scheme:
        try:
            host = ipaddress.ip_address(address)
        except ValueError:
            pass
        else:
            if host.version == 6:
                address = f"[{address}]"
        address = "ws://" + address
    try:
        url = urlsplit(address)
        port = url.port
        scheme = {"http": "ws", "https": "wss"}.get(url.scheme, url.scheme)
        if (scheme not in ("ws", "wss") or not url.hostname or url.username is not None
                or url.password is not None or url.query or url.fragment or "\\" in address):
            raise ValueError
        if port == 0 or url.netloc.endswith(":"):
            raise ValueError
        authority = url.netloc
        if port is None and not explicit_scheme:
            authority += ":8443"
        normalized = urlunsplit((scheme, authority, "/ws" if url.path in ("", "/") else url.path, "", ""))
    except ValueError as exc:
        raise ValueError("服务器地址无效，请填写 IP:端口或 ws://、wss:// 地址") from exc
    try:
        unspecified = ipaddress.ip_address(url.hostname).is_unspecified
    except ValueError:
        unspecified = False
    if unspecified:
        raise ValueError("不能连接监听地址 0.0.0.0 或 ::，请填写服务器实际地址")
    return normalized


class Client:
    def __init__(self, config, room, *, console=True):
        self.config, self.room = config, room
        self.server_url = config.get("server", "ws://127.0.0.1:8443/ws")
        url = urlsplit(self.server_url)
        if url.scheme not in ("ws", "wss") or not url.hostname or url.username or url.password or url.query:
            raise ValueError("INVALID_SIGNALING_URL")
        try:
            local = ipaddress.ip_address(url.hostname).is_loopback
        except ValueError:
            local = url.hostname == "localhost"
        if url.scheme == "ws" and not local and not config.get("allow_insecure"):
            raise ValueError("PUBLIC_SIGNALING_REQUIRES_WSS_OR_EXPLICIT_ALLOW_INSECURE")
        self.server_host = url.hostname
        self.name = str(config.get("name", socket.gethostname()))[:64]
        self.data = FilePath(config.get("data_dir", default_client_data()))
        self.loopback = bool(config.get("loopback", False))
        options = config.get("experiment", {})
        for key in ("comprehensive", "raw_probes", "auto_retry"):
            if key in options and type(options[key]) is not bool:
                raise ValueError("EXPERIMENT_BOOLEAN_REQUIRED:" + key)
        prefixes = options.get("nat64_prefixes", [])
        if not isinstance(prefixes, list) or len(prefixes) > 4:
            raise ValueError("NAT64_PREFIX_CONFIGURATION_LIMIT")
        for prefix in prefixes:
            if not isinstance(prefix, str) or ipaddress.IPv6Network(prefix).prefixlen not in (32, 40, 48, 56, 64, 96):
                raise ValueError("NAT64_PREFIX_CONFIGURATION_INVALID")
        self.timeout = float(options.get("timeout", 12))
        if not 1 <= self.timeout <= 30:
            raise ValueError("EXPERIMENT_TIMEOUT_MUST_BE_1_TO_30_SECONDS")
        self.profiles = options.get("profiles", ["balanced", "fast", "staggered"])
        if not self.profiles or not all(p in PROFILES for p in self.profiles) or len(self.profiles) > 3:
            raise ValueError("INVALID_RETRY_PROFILES")
        self.gateway_enabled = bool(options.get("gateway", True))
        self.prediction_enabled = bool(options.get("port_prediction", True))
        self.diagnostics_enabled = bool(options.get("diagnostics", True))
        self.max_addresses = min(max(int(options.get("max_addresses", 4)), 1), 8)
        self.max_pairs = min(max(int(options.get("max_pairs", 4)), 1), 8)
        self.expanded = bool(options.get("expanded", False))
        self.research_enabled = bool(options.get("comprehensive", not self.loopback))
        self.extra_observers = options.get("stun", ["stun.l.google.com:19302", "stun.cloudflare.com:3478"])
        if not isinstance(self.extra_observers, list) or len(self.extra_observers) > 3:
            raise ValueError("STUN_OBSERVER_LIMIT")
        log_options = config.get("logs", {})
        if not isinstance(log_options, dict):
            raise ValueError("LOG_CONFIGURATION_INVALID")
        self.upload_interval = float(log_options.get("upload_interval", 5))
        self.upload_retry = float(log_options.get("retry_interval", 10))
        self.upload_batch_events = log_options.get("batch_events", MAX_BATCH_EVENTS)
        if not math.isfinite(self.upload_interval) or not 0.1 <= self.upload_interval <= 60:
            raise ValueError("LOG_UPLOAD_INTERVAL_MUST_BE_0_1_TO_60_SECONDS")
        if not math.isfinite(self.upload_retry) or not self.upload_interval <= self.upload_retry <= 120:
            raise ValueError("LOG_RETRY_INTERVAL_MUST_BE_AT_LEAST_UPLOAD_INTERVAL_AND_AT_MOST_120")
        if type(self.upload_batch_events) is not int or not 1 <= self.upload_batch_events <= MAX_BATCH_EVENTS:
            raise ValueError("LOG_BATCH_EVENTS_MUST_BE_1_TO_1024")
        self.log_encoding = None
        self.transfers = TransferManager(self)
        self.identity = Identity(self.data)
        self.log = Journal(self.data / "client.sqlite3", role="client", room=room, console=console)
        self.observers = []
        self.tcp_observer = None
        self.tcp_observer_protocol = "raw"
        self.observation_token = None
        self.inbound_supported = False
        self.inbound_task = None
        self.network = {}
        self.network_ready = asyncio.Event()
        self.connected = asyncio.Event()
        self.paired = asyncio.Event()
        self.stop = asyncio.Event()
        self.peer_id = None
        self.peer = None
        self.pair = None
        self.leader = False
        self.ws = None
        self.manager = None
        self.paths = []
        self.active_path = None
        self.leases = []
        self.chat_acks = {}
        self.dedup = Dedup()
        self.reach_requests = {}
        self.speed_lock = asyncio.Lock()
        self.command_lock = asyncio.Lock()
        self.tasks = set()
        self.signal_lock = asyncio.Lock()
        self.diagnostic_lock = asyncio.Lock()
        self.closed = False
        self.upload_inflight = set()
        self.early_signals = []
        self.managers = []
        self.chat_display = None
        self.link_monitor_active = False
        self.rtt_monitor_enabled = False
        self.path_maintenance_task = None
        self.cold_paths_supported = False
        self.reopen_lock = asyncio.Lock()
        self.reopen_futures = {}
        self.reopen_managers = {}
        self.park_futures = {}
        self.batch_speed_state = {}
        self.inbound_results = {}
        self.peer_network = {}
        self.server_observed_ipv4 = None
        self.last_ip_evidence = None
        self.inbound_ipv4_supported = False
        self.wan_options = config.get("wan", {})
        configured_families(self.wan_options, [])
        self.wan_result = {"state": "not-tested", "families": {}, "reason": "STARTUP_PENDING"}
        self.wan_task = None
        self.pair_task = None
        self.pending_pair_peer = None
        self.wan_lock = asyncio.Lock()
        self.status_revision = 0
        self.chat_receipts = collections.OrderedDict()
        self.retry_lock = asyncio.Lock()
        self.auto_retry = bool(options.get("auto_retry", not self.loopback))
        self.auto_retry_task = None
        self.last_auto_retry = 0.0
        self.retired_attempts = set()

    def spawn(self, coroutine, name):
        task = asyncio.create_task(coroutine, name=name)
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

        def done(task):
            if not task.cancelled() and task.exception():
                self.log.exception("client.background_failed", task.exception(), task=task.get_name())

        task.add_done_callback(done)
        return task

    def path_opened(self, path):
        self.paths.append(path)
        if path.attempt in self.reopen_managers:
            path.lifecycle_pins = 1
        if self.path_maintenance_task is None or self.path_maintenance_task.done():
            self.path_maintenance_task = self.spawn(self.maintain_paths(), "path-maintenance")
        if self.active_path is None or self.active_path.closed:
            self.active_path = path
        self.log.event(
            "path.opened",
            attempt=path.attempt,
            mechanism=path.mechanism,
            family=path.family,
            active=self.active_path is path,
            peer=path.peer["id"],
            evidence="mutually-authenticated-reliable-encrypted-data-channel",
            cold_path_server_support=self.cold_paths_supported,
            cold_path_peer_support=PATH_LIFECYCLE_CAPABILITY in path.remote_capabilities,
            rtt_policy="on-demand;opt-in-current-path-only",
        )

    def path_busy(self, path):
        return bool(
            getattr(path, "benches", {}) or getattr(path, "receive_benches", {})
            or getattr(path, "reverse_tests", {}) or getattr(path, "pings", {})
            or getattr(path, "chat_ready", {}) or self.chat_acks
            or any(item["path"] is path for item in self.transfers.outgoing.values())
            or any(item["path"] is path for item in self.transfers.incoming.values())
        )

    def can_reopen(self, path):
        return bool(
            self.cold_paths_supported and self.connected.is_set() and self.paired.is_set()
            and getattr(path, "pool_managed", False) and getattr(path, "pair", None) == self.pair
            and PATH_LIFECYCLE_CAPABILITY in getattr(path, "remote_capabilities", set())
        )

    async def park_path(self, path, *, notify=True):
        if (path.closed or path is self.active_path or self.path_busy(path)
                or path.parking or path.lifecycle_pins):
            return
        path.parking = True
        path.park_finished.clear()
        request = secrets.token_hex(8)
        try:
            if notify:
                future = asyncio.get_running_loop().create_future()
                self.park_futures[request] = future
                await self.signal({"kind": "path_park", "attempt": path.attempt, "request": request})
                if not await asyncio.wait_for(future, 5):
                    return
            await self.finish_park(path)
        except (ConnectionError, TimeoutError):
            self.log.event("path.park_deferred", attempt=path.attempt, level="WARNING",
                           reason="PEER_IDLE_CONFIRMATION_UNAVAILABLE")
        finally:
            future = self.park_futures.pop(request, None)
            if future and not future.done():
                future.cancel()
            path.parking = False
            path.park_finished.set()

    async def finish_park(self, path):
        try:
            path.parked = True
            await path.close("STANDBY_PARKED")
            self.log.event("path.parked", attempt=path.attempt, source=path.source_attempt,
                           policy="bilateral-idle-check;history-retained;sockets-released;reopen-on-demand")
        finally:
            path.parking = False
            path.park_finished.set()

    async def release_path_resources(self, path):
        for manager in self.managers:
            obj = manager.attempts.get(path.attempt)
            if obj:
                await obj.close()
                lease = getattr(obj, "gateway_lease", None)
                if lease:
                    await lease.release()
                if manager.attempts.get(path.attempt) is obj:
                    manager.attempts.pop(path.attempt)

    async def park_idle_paths(self):
        for path in tuple(self.paths):
            if self.can_reopen(path) and not getattr(path, "lifecycle_pins", 0):
                await self.park_path(path)

    async def maintain_paths(self):
        try:
            while not self.stop.is_set():
                live = [p for p in self.paths if not p.closed and p.ready.is_set()]
                if not live:
                    return
                now = time.monotonic()
                for path in live:
                    await path.expire(now)
                    if (path.ephemeral and not self.path_busy(path)
                            and now - max(path.last_rx, path.last_tx) > 30):
                        path.lifecycle_pins = 0
                await self.park_idle_paths()
                # One primary only; benchmarks never compete with a periodic RTT sweep.
                path = self.active_path
                bench_busy = self.speed_lock.locked() or any(p.benches or p.receive_benches for p in live)
                if path and not path.closed and not self.path_busy(path):
                    now = time.monotonic()
                    measure = self.rtt_monitor_enabled and self.link_monitor_active and not bench_busy
                    due = now - path.last_liveness >= 2 if measure else now - max(path.last_rx, path.last_tx) >= 12
                    if due:
                        try:
                            rtt = await path.ping(timeout=4, measure=measure)
                            if measure:
                                self.log.event("path.rtt_sample", attempt=path.attempt, rtt_ms=rtt,
                                               interval_seconds=2, scope="opt-in-current-path-only")
                        except (TimeoutError, ConnectionError, OSError) as exc:
                            self.log.event("path.liveness_failed", str(exc), "WARNING", attempt=path.attempt)
                            await path.close("KEEPALIVE_FAILED")
                        finally:
                            path.last_liveness = time.monotonic()
                try:
                    await asyncio.wait_for(self.stop.wait(), 1)
                except TimeoutError:
                    pass
        except asyncio.CancelledError:
            raise

    def reopen_source(self, source):
        path = next((p for p in self.paths if p.source_attempt == source and self.can_reopen(p)), None)
        if path is None:
            raise ValueError("SOURCE_UNKNOWN")
        spec = next((s for m in self.managers for s in m.plan if s["attempt"] == source), None)
        if spec is None:
            raise ValueError("SOURCE_UNKNOWN")
        return path, dict(spec)

    def start_reopen(self, data, *, released=False):
        if data["attempt"] in self.reopen_managers:
            raise ValueError("DUPLICATE_REOPEN_ATTEMPT")
        original, spec = self.reopen_source(data["source"])
        manager = Experiments(self)
        spec["attempt"] = data["attempt"]
        spec["source_attempt"] = data["source"]
        spec.pop("matrix_coverage", None)
        manager.plan = [spec]
        self.managers.append(manager)
        self.reopen_managers[data["attempt"]] = manager
        manager.reopen_start = asyncio.Event()
        task = self.spawn(self.run_reopen(manager, original, data), "path-reopen:" + data["attempt"])
        if released:
            manager.reopen_start.set()
        return task

    async def run_reopen(self, manager, original, data):
        pair = self.pair
        path = None
        try:
            await manager.reopen_start.wait()
            spec = dict(manager.plan[0])
            spec["initiator"] = spec["leader_initiator"] == self.leader
            spec["tls_client"] = spec["initiator"]
            spec["host"] = spec["a_host"] if self.leader else spec["b_host"]
            self.log.event("path.reopen_started", attempt=spec["attempt"], source=data["source"], mode=data["mode"])
            await manager.execute(spec, 0)
            await asyncio.wait_for(manager.remote_done_events.setdefault(spec["attempt"], asyncio.Event()).wait(), 130)
            if pair != self.pair or self.closed:
                raise ConnectionError("SESSION_CHANGED")
            if not manager.results[-1]["data_path"] or not manager.remote_done[spec["attempt"]].get("data_path"):
                raise ConnectionError("REOPEN_FAILED")
            path = next(p for p in self.paths if p.attempt == spec["attempt"] and not p.closed)
            path.pool_managed, path.source_attempt = True, data["source"]
            path.ephemeral = data["mode"] == "measure"
            path.latest_speed = original.latest_speed
            # Keep the row/index stable while the authenticated session gets a fresh ID.
            if original in self.paths and path is not original:
                self.paths.remove(path)
                self.paths[self.paths.index(original)] = path
            if data["mode"] == "use":
                self.active_path = path
                path.lifecycle_pins = 0
            self.log.event("path.reopen_verified", attempt=path.attempt, source=path.source_attempt,
                           evidence="fresh-punch-and-bilateral-data-channel-verification")
            future = self.reopen_futures.get(data["request"])
            if future and not future.done():
                future.set_result(path)
            await self.park_idle_paths()
            return path
        except BaseException as exc:
            future = self.reopen_futures.get(data["request"])
            if future and not future.done():
                future.set_exception(ConnectionError("REOPEN_FAILED"))
            for candidate in tuple(self.paths):
                if candidate.attempt == data["attempt"]:
                    if candidate is self.active_path:
                        self.active_path = None
                    candidate.lifecycle_pins = 0
                    await candidate.close("REOPEN_FAILED")
            await manager.close()
            if not isinstance(exc, asyncio.CancelledError):
                self.log.exception("path.reopen_failed", exc, source=data["source"], attempt=data["attempt"])
            raise
        finally:
            self.reopen_managers.pop(data["attempt"], None)

    async def coordinate_reopen(self, source, request, mode):
        try:
            async with self.reopen_lock:
                _, spec = self.reopen_source(source)
                data = {"kind": "path_reopen", "attempt": secrets.token_hex(6) + "-wake-" + spec["method"],
                        "source": source, "request": request, "mode": mode}
                # Register the receiver before publishing any candidate-producing work.
                task = self.start_reopen(data)
                try:
                    await self.signal(data)
                except BaseException:
                    task.cancel()
                    await asyncio.gather(task, return_exceptions=True)
                    raise
                self.reopen_managers[data["attempt"]].reopen_start.set()
                await task
        except Exception as exc:
            future = self.reopen_futures.get(request)
            if future and not future.done():
                future.set_exception(ConnectionError("REOPEN_FAILED"))
            self.log.exception("path.reopen_request_failed", exc, source=source)
            with contextlib.suppress(ConnectionError):
                await self.signal({"kind": "path_reopen_reject", "attempt": source,
                                   "request": request, "reason": "REOPEN_FAILED"})

    async def ensure_path(self, path, *, activate=False):
        if getattr(path, "parking", False):
            await asyncio.wait_for(path.park_finished.wait(), 7)
        if not path.closed and path.ready.is_set():
            path.lifecycle_pins = max(1, getattr(path, "lifecycle_pins", 0))
            return path
        if not self.can_reopen(path):
            raise ConnectionError("PATH_UNAVAILABLE_OR_REOPEN_REQUIRES_SIGNALING")
        request = secrets.token_hex(8)
        future = asyncio.get_running_loop().create_future()
        self.reopen_futures[request] = future
        try:
            mode = "use" if activate else "measure"
            if self.leader:
                self.spawn(self.coordinate_reopen(path.source_attempt, request, mode), "path-reopen-coordinator")
            else:
                await self.signal({"kind": "path_reopen_request", "attempt": path.source_attempt,
                                   "request": request, "mode": mode})
            return await asyncio.wait_for(future, 150)
        finally:
            self.reopen_futures.pop(request, None)
            if not future.done():
                future.cancel()

    async def active_data_path(self):
        try:
            return self.choose_path()
        except ConnectionError:
            candidates = sorted((p for p in self.paths if self.can_reopen(p)),
                                key=lambda p: (p.family != 6, p.last_rtt or float("inf")))
            for path in candidates[:3]:
                try:
                    return await self.ensure_path(path, activate=True)
                except (ConnectionError, TimeoutError):
                    continue
            raise ConnectionError("NO_AUTHENTICATED_P2P_DATA_PATH_YET") from None

    def remember_chat(self, mid):
        return self.dedup.remember(mid)

    def display_chat(self, name, text, metrics=None):
        # Chat content is intentionally excluded from central diagnostics; metadata is persisted.
        if self.chat_display:
            self.chat_display(name, text, metrics)
            return
        if self.log.console:
            safe_name = "".join(c if ord(c) >= 32 and ord(c) != 127 else "?" for c in name)
            safe_text = "".join(c if c in "\n\t" or ord(c) >= 32 and ord(c) != 127 else "?" for c in text)
            line = Text(f"\n{safe_name}> {safe_text}")
            if metrics:
                speed = metrics.get("mbps")
                line.append("  接收 ", style="italic grey62")
                line.append(metrics["received_at"], style="italic bright_cyan")
                line.append(" · 均速 ", style="italic grey62")
                line.append(f"{speed:.3f}" if speed is not None else "未测", style="italic yellow")
                line.append(" Mbps", style="italic grey62")
            Console().print(line, markup=False, highlight=False)

    def choose_path(self):
        if self.active_path and not self.active_path.closed and self.active_path.ready.is_set():
            return self.active_path
        candidates = [p for p in self.paths if p.ready.is_set() and not p.closed]
        if not candidates:
            raise ConnectionError("NO_AUTHENTICATED_P2P_DATA_PATH_YET")
        self.active_path = min(candidates, key=lambda p: (p.family != 6, p.last_rtt or float("inf")))
        self.log.event(
            "path.failover", attempt=self.active_path.attempt, mechanism=self.active_path.mechanism
        )
        return self.active_path

    async def signal(self, data):
        if not self.pair:
            raise ConnectionError("NO_SIGNALING_PAIR")
        await self.send_control({"type": "signal", "pair": self.pair, "data": data})

    async def send_control(self, body):
        async with self.signal_lock:
            if not self.ws or self.ws.closed:
                raise ConnectionError("SIGNALING_OFFLINE_P2P_CAN_CONTINUE")
            if body.get("type") == "signal" and (not self.pair or body.get("pair") != self.pair):
                raise ConnectionError("SIGNALING_PAIR_CHANGED")
            await asyncio.wait_for(self.ws.send_json({"v": 1, **body}), 5)

    def prepare_log_upload(self):
        compressed = self.log_encoding == CODEC
        batch = self.log.pending(
            limit=self.upload_batch_events if compressed else 64,
            max_bytes=MAX_BATCH_BYTES - 4096 if compressed else 220_000,
        )
        if not batch:
            return None, set()
        if not compressed:
            return {"type": "logs", "events": batch}, {e["id"] for e in batch}
        while True:
            try:
                body = encode_batch(batch)
                return body, {e["id"] for e in batch}
            except ValueError as exc:
                if str(exc) != "LOG_COMPRESSED_LIMIT" or len(batch) <= 1:
                    raise
                # Incompressible diagnostics get smaller batches, never dropped events.
                batch = batch[:max(1, len(batch) // 2)]

    async def upload_logs(self):
        body, ids = await asyncio.to_thread(self.prepare_log_upload)
        if body is None:
            self.upload_inflight.clear()
            return False
        self.upload_inflight = ids
        try:
            await self.send_control(body)
        except (ConnectionError, TimeoutError):
            self.upload_inflight.clear()
            raise
        return True

    async def uploader(self):
        last_sent = -float("inf")
        while not self.stop.is_set():
            if self.ws and not self.ws.closed and self.connected.is_set():
                interval = self.upload_retry if self.upload_inflight else self.upload_interval
                if time.monotonic() - last_sent >= interval:
                    try:
                        await self.upload_logs()
                        last_sent = time.monotonic()
                    except (ConnectionError, TimeoutError):
                        self.upload_inflight.clear()
                        last_sent = time.monotonic()
            try:
                await asyncio.wait_for(self.stop.wait(), min(self.upload_interval, 0.5))
            except TimeoutError:
                pass

    async def collect_network(self):
        async with self.diagnostic_lock:
            previous = address_fingerprint(self.network.get("address_inventory", []))
            try:
                self.network = await snapshot(
                    self.log,
                    server_host=self.server_host,
                    external=self.diagnostics_enabled,
                    loopback=self.loopback,
                    maximum=self.max_addresses,
                )
            except (OSError, psutil.Error) as exc:
                self.log.exception("network.failed", exc)
                self.network = {
                    "addresses": [], "address_inventory": [], "gateways": [], "gateways6": [],
                    "http_observations": [{"state": "unavailable", "reason": "NETWORK_DIAGNOSTICS_FAILED"}],
                }
            if previous and previous != address_fingerprint(self.network.get("address_inventory", [])):
                self.wan_result = {"state": "not-tested", "families": {}, "reason": "NETWORK_CHANGED"}
                self.inbound_results.clear()
            self.network_ready.set()
        await self.publish_status()

    async def watch_network(self):
        while not self.stop.is_set():
            await asyncio.sleep(60)
            previous = address_fingerprint(self.network.get("address_inventory", []))
            current = address_fingerprint(await self.refresh_address_inventory())
            if current != previous:
                self.wan_result = {"state": "not-tested", "families": {}, "reason": "NETWORK_CHANGED"}
                self.inbound_results.clear()
                self.log.event("network.changed", old=previous, new=current)
                await self.collect_network()
                self.request_auto_retry("LOCAL_ADDRESS_OR_INTERFACE_CHANGED")
            await self.publish_status()

    def network_status(self):
        inventory = self.network.get("address_inventory", self.network.get("addresses", []))
        addresses = [
            {
                "address": r["address"],
                "family": r["family"],
                "interface": r.get("interface", ""),
                "type": r.get("type", "unverified"),
            }
            for r in inventory
            if not address_rejection(r)
        ][:16]
        public_ips = []
        if self.server_observed_ipv4:
            public_ips.append({"address": self.server_observed_ipv4, "family": 4, "source": "signaling"})
        public_ips.extend(
            {"address": r["address"], "family": r["family"], "source": "http"}
            for r in self.network.get("http_observations", [])
            if r.get("state") == "observed" and r.get("address")
        )
        public_ips = list({(r["address"], r["family"], r["source"]): r for r in public_ips}.values())[:8]
        configured = configured_families(self.wan_options, inventory)
        measured = {
            f: row
            for f, row in self.wan_result["families"].items()
            if any(
                r["address"] == row["source"] and r.get("interface", "") == row["interface"]
                for r in addresses
            )
        }
        families = configured or measured
        wan_state = "configured" if configured else self.wan_result["state"]
        return {
            "addresses": addresses,
            "public_ips": public_ips,
            "inbound": list(self.inbound_results.values())[:8],
            "wan": {"state": wan_state, "families": families},
            "updated_at": utcnow(),
        }

    async def publish_status(self):
        if self.closed:
            return
        status = self.network_status()
        evidence = public_ip_evidence(status)
        if evidence != self.last_ip_evidence and (status["public_ips"] or self.last_ip_evidence is not None):
            self.last_ip_evidence = evidence
            self.log.event("network.ip_sources", "HTTP 出口与信令观察分开记录；均非 UDP 映射", evidence=evidence)
        if not self.pair or not self.paired.is_set() or not self.connected.is_set():
            return
        validate_status(status)
        self.status_revision += 1
        try:
            await self.signal(
                {
                    "kind": "network_status",
                    "attempt": f"network-{self.status_revision // 100}",
                    "status": status,
                }
            )
            self.log.event("network.status_sent", evidence=status)
        except (ConnectionError, TimeoutError):
            self.log.event(
                "network.status_pending", "Will resend diagnostics after signaling reconnect", "WARNING"
            )

    def receive_status(self, data):
        try:
            status = validate_status(data.get("status"))
        except (ValueError, TypeError, KeyError) as exc:
            self.log.event("network.peer_status_rejected", str(exc), "WARNING")
            return
        self.peer_network = status
        self.log.event("network.peer_status", evidence=status)

    async def startup_wan(self):
        await self.network_ready.wait()
        if not self.wan_options.get("enabled", self.diagnostics_enabled) or self.loopback:
            self.wan_result["reason"] = "WAN_TEST_DISABLED_OR_ISOLATED"
            self.log.event("wan.not_tested", reason=self.wan_result["reason"])
            return
        await self.connected.wait()
        if self.inbound_task:
            await asyncio.shield(self.inbound_task)
        await self.test_wan()

    async def test_wan(self):
        if self.wan_lock.locked():
            raise ValueError("WAN_TEST_ALREADY_RUNNING")
        if self.manager and self.manager.task and not self.manager.task.done():
            raise ValueError("WAIT_FOR_CURRENT_MATRIX_TO_FINISH_BEFORE_WAN")
        if any(getattr(path, "receive_benches", {}) for path in self.paths):
            raise ValueError("P2P_BENCH_RECEIVER_BUSY")
        if self.loopback or not self.diagnostics_enabled:
            self.log.event("wan.not_tested", reason="WAN_TEST_DISABLED_OR_ISOLATED")
            return
        async with self.wan_lock, self.speed_lock:
            self.wan_result = {"state": "running", "families": {}}
            self.log.event(
                "wan.started",
                "公网测速将产生较多流量；所得为参考值，不是运营商理论上限",
                engine="librespeed-cli",
                duration=self.wan_options.get("duration", 8),
                servers_per_family=self.wan_options.get("servers_per_family", 2),
            )
            await self.publish_status()
            try:
                async with asyncio.timeout(150):
                    # A VPN toggle or IPv6 rotation can invalidate the startup snapshot.
                    await self.refresh_address_inventory()
                    self.wan_result = await measure_wan(
                        self.network, self.wan_options, self.log, validate_source=self.validate_local_address,
                    )
            except asyncio.CancelledError:
                self.wan_result = {"state": "cancelled", "families": {}, "reason": "CANCELLED"}
                raise
            except Exception as exc:
                self.wan_result = {
                    "state": "failed",
                    "families": {},
                    "reason": type(exc).__name__ + ":" + str(exc),
                }
            finally:
                self.log.event("wan.completed", evidence=self.wan_result)
                if not self.closed:
                    await self.publish_status()

    def path_reference(self, path, direction):
        local = self.network_status()
        family = getattr(path, "family", None)
        spec = next((s for m in self.managers for s in m.plan if s["attempt"] == path.attempt), {})
        local_host = spec.get("a_host" if self.leader else "b_host") or getattr(path, "local_host", None)
        peer_host = spec.get("b_host" if self.leader else "a_host") or getattr(path, "peer_host", None)
        peer_family = ipaddress.ip_address(peer_host).version if peer_host else family
        reference = direction_reference(local, self.peer_network, family, direction, peer_family=peer_family)
        if not reference:
            return None
        # Do not compare a secondary NIC or an ICE-selected unknown route with a default-NIC WAN test.
        for status, host, version in (
            (local, local_host, family),
            (self.peer_network, peer_host, peer_family),
        ):
            row = status["wan"]["families"][str(version)]
            if row["basis"] == "measured":
                address = next((r for r in status["addresses"] if r["address"] == host), {})
                if not address or address.get("interface") != row["interface"]:
                    return None
        return reference

    async def refresh_address_inventory(self):
        async with self.diagnostic_lock:
            previous = self.network.get("address_inventory", self.network.get("addresses", []))
            records, evidence = await read_address_inventory(loopback=self.loopback)
            commands = self.network.setdefault("system_commands", [])
            if commands:
                commands[0] = evidence
            else:
                commands.append(evidence)
            changed = address_fingerprint(previous) != address_fingerprint(records)
            apply_address_inventory(self.network, records, maximum=self.max_addresses)
            if changed:
                self.log.event(
                    "network.address_selection_refreshed",
                    "Local address membership or eligibility changed; established paths are not closed",
                    inventory=records,
                    selected=self.network["addresses"],
                    excluded=self.network["excluded_addresses"],
                    address_evidence_state=evidence.get("state"),
                )
            return records

    async def validate_local_address(self, host, *, expected=None):
        records = await self.refresh_address_inventory()
        record = next(
            (
                r
                for r in records
                if r["address"] == host and (not expected or r.get("interface") == expected.get("interface"))
            ),
            None,
        )
        reason = address_rejection(record) if record else "ADDRESS_REMOVED_OR_INTERFACE_CHANGED"
        if reason:
            self.log.event(
                "network.address_unavailable",
                "Skipping a new connection; this is local address evidence, not a firewall verdict",
                address=host,
                reason=reason,
                record=record,
                previous_record=expected,
            )
            raise ValueError("LOCAL_IPV6_ADDRESS_UNAVAILABLE:" + reason)
        return record

    async def signaling(self):
        delay = 0.5
        context = (
            ssl.create_default_context(cafile=self.config.get("ca_file"))
            if self.server_url.startswith("wss://")
            else True
        )
        if self.server_url.startswith("ws://"):
            self.log.event(
                "signaling.insecure",
                "Plain WS has no transport encryption: signaling, addresses, tokens and diagnostics "
                "are exposed in transit. P2P data channels still use encryption.",
                "WARNING",
            )
        token = (
            FilePath(self.config["token_file"]).read_text().strip() if self.config.get("token_file") else ""
        )
        while not self.stop.is_set():
            try:
                self.log.event("signaling.connecting", server=self.server_url)
                connector = aiohttp.TCPConnector(ssl=context, family=socket.AF_INET, limit=4)
                async with aiohttp.ClientSession(
                    connector=connector,
                    trust_env=False,
                    timeout=aiohttp.ClientTimeout(total=None, connect=8, sock_connect=8),
                ) as session:
                    async with session.ws_connect(self.server_url, heartbeat=20, max_msg_size=300_000) as ws:
                        self.ws = ws
                        challenge = await asyncio.wait_for(ws.receive_json(), 8)
                        if challenge.get("type") != "challenge":
                            raise ValueError("SERVER_CHALLENGE_REQUIRED")
                        proof = self.identity.sign(
                            {
                                "v": 1,
                                "kind": "join",
                                "nonce": challenge["nonce"],
                                "client": self.log.client,
                                "room": self.room,
                                "name": self.name,
                                "public": self.identity.public,
                                "certificate_fingerprint": self.identity.fingerprint,
                            }
                        )
                        await self.send_control(
                            {
                                "type": "join",
                                "room": self.room,
                                "client": self.log.client,
                                "name": self.name,
                                "public": self.identity.public,
                                "certificate": self.identity.cert_pem,
                                "token": token,
                                "proof": proof,
                            }
                        )
                        async for msg in ws:
                            if msg.type == aiohttp.WSMsgType.TEXT:
                                await self.handle_control(json.loads(msg.data))
                                delay = 0.5
                            elif msg.type == aiohttp.WSMsgType.ERROR:
                                raise ConnectionError(str(ws.exception()))
                if not self.stop.is_set():
                    raise ConnectionError("SIGNALING_DISCONNECTED")
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                self.log.exception(
                    "signaling.offline", exc, active_data_paths=sum(not p.closed for p in self.paths)
                )
            finally:
                self.ws = None
                self.connected.clear()
                await self.invalidate_pair()
                self.upload_inflight.clear()
            if not self.stop.is_set():
                try:
                    await asyncio.wait_for(self.stop.wait(), delay + secrets.randbelow(100) / 500)
                except TimeoutError:
                    pass
                delay = min(10, delay * 1.8)

    async def handle_control(self, body):
        kind = body.get("type")
        if kind == "welcome":
            await self.invalidate_pair()
            self.server_observed_ipv4 = None
            self.cold_paths_supported = body.get("cold_paths") is True
            self.log_encoding = CODEC if CODEC in body.get("log_encodings", []) else None
            observed = body.get("observed_ipv4")
            if isinstance(observed, str):
                with contextlib.suppress(ValueError):
                    if ipaddress.ip_address(observed).version == 4:
                        self.server_observed_ipv4 = observed
            self.peer_id = body["id"]
            self.observation_token = body["observation_token"]
            rows = await asyncio.get_running_loop().getaddrinfo(
                self.server_host, body["stun_port"], family=socket.AF_INET, type=socket.SOCK_DGRAM
            )
            ipv4 = rows[0][4][0]
            non_global_source = bool(self.server_observed_ipv4
                                    and not ipaddress.ip_address(self.server_observed_ipv4).is_global
                                    and not self.loopback)
            forwarded = body.get("observation_mode") == "forwarded" or non_global_source
            self.observers = [*([f"{ipv4}:{body['stun_port']}"] if not forwarded else []),
                              *self.extra_observers]
            self.tcp_observer = None if forwarded else (ipv4, body["tcp_port"])
            protocol = body.get("tcp_observer_protocol", "raw")
            if protocol not in ("raw", "http"):
                raise ValueError("TCP_OBSERVER_PROTOCOL_UNSUPPORTED")
            self.tcp_observer_protocol = protocol
            self.inbound_supported = body.get("inbound_check", False)
            self.inbound_ipv4_supported = body.get("inbound_ipv4_check", False) and not forwarded
            if forwarded:
                self.log.event(
                    "network.server_forwarded",
                    "服务端转发或非公网来源：不使用本站 TCP/STUN 映射，不以转发器为 IPv4 回连目标；保留公共 STUN 和 IPv6 回连",
                    "WARNING", signaling_source=self.server_observed_ipv4,
                    mode=body.get("observation_mode", "non-global-source"), observers=self.observers,
                )
            if self.inbound_task and not self.inbound_task.done():
                self.inbound_task.cancel()
            self.inbound_task = self.spawn(self.inbound_check(), "ipv6-inbound-check")
            self.connected.set()
            self.log.event(
                "signaling.connected",
                peer_id=self.peer_id,
                server_ipv4=ipv4,
                stun_port=body["stun_port"],
                tcp_observer_port=body["tcp_port"],
                tcp_observer_protocol=protocol,
                strict_p2p=body.get("strict_p2p"),
                admission="room-number-only-trusted-signaling-server",
                log_encoding=self.log_encoding or "legacy-json",
                log_upload_interval=self.upload_interval,
                log_batch_events=self.upload_batch_events,
            )
        elif kind == "waiting":
            self.log.event("room.waiting", "Room created; waiting for the second device", room=self.room)
        elif kind == "paired":
            self.pending_pair_peer = body["peer"]["id"]
            if self.pair_task and not self.pair_task.done():
                self.pair_task.cancel()
                await asyncio.gather(self.pair_task, return_exceptions=True)
            self.pair_task = self.spawn(self.begin_pair(body), "pair-setup")
        elif kind == "signal":
            if body.get("pair") == self.pair and body.get("data", {}).get("kind") == "network_status":
                self.receive_status(body["data"])
                return
            if body.get("pair") == self.pair:
                data = body["data"]
                subtype = data.get("kind")
                if subtype == "path_reopen_request":
                    if not self.leader:
                        raise ValueError("ONLY_COORDINATOR_CAN_REOPEN")
                    self.spawn(self.coordinate_reopen(data["attempt"], data["request"], data["mode"]),
                               "path-reopen-coordinator")
                    return
                if subtype == "path_reopen":
                    if self.leader:
                        raise ValueError("ONLY_COORDINATOR_CAN_REOPEN")
                    self.start_reopen(data, released=True)
                    return
                if subtype == "path_reopen_reject":
                    future = self.reopen_futures.get(data["request"])
                    if future and not future.done():
                        future.set_exception(ConnectionError(data["reason"]))
                    return
                if subtype == "path_park_ack":
                    future = self.park_futures.get(data["request"])
                    if future and not future.done():
                        future.set_result(data["allowed"])
                    return
                if subtype in ("path_select", "path_park"):
                    path = next((p for p in self.paths if p.attempt == data["attempt"] and not p.closed), None)
                    if subtype == "path_park":
                        allowed = bool(path and self.can_reopen(path) and path is not self.active_path
                                       and not self.path_busy(path)
                                       and (not path.lifecycle_pins or path.ephemeral))
                        reserved = allowed and not path.parking
                        if reserved:
                            path.parking = True
                            path.park_finished.clear()
                        try:
                            await self.signal({"kind": "path_park_ack", "attempt": data["attempt"],
                                               "request": data["request"], "allowed": allowed})
                        except BaseException:
                            if reserved:
                                path.parking = False
                                path.park_finished.set()
                            raise
                        if allowed:
                            path.lifecycle_pins = 0
                            # A simultaneous local park owns its own close; do not await it here.
                            if reserved:
                                self.spawn(self.finish_park(path), "peer-path-park:" + path.attempt)
                        return
                    if (path and path.ready.is_set() and path.pair == self.pair
                            and PATH_LIFECYCLE_CAPABILITY in path.remote_capabilities):
                        self.active_path = path
                        path.lifecycle_pins = 0
                        # The WS reader must stay free to receive the cleanup ACKs.
                        self.spawn(self.park_idle_paths(), "path-idle-cleanup")
                    return
                replay = self.reopen_managers.get(data.get("attempt"))
                if replay:
                    replay.dispatch(data)
                    return
            if body.get("pair") == self.pair and self.manager:
                if body["data"]["kind"] == "phase" and body["data"].get("phase") == "retry":
                    if self.leader:
                        raise ValueError("ONLY_COORDINATOR_CAN_RESTART_MATRIX")
                    self.spawn(self.restart_experiments(remote=True, automatic=True), "retry-experiments")
                elif body["data"]["kind"] == "phase" and body["data"].get("phase") == "retry-request":
                    self.request_auto_retry("PEER_NETWORK_OR_PATH_CHANGED")
                else:
                    if body["data"].get("attempt") not in self.retired_attempts:
                        self.manager.dispatch(body["data"])
                    else:
                        self.log.event("experiment.stale_signal", attempt=body["data"].get("attempt"))
            elif len(self.early_signals) < 128:
                self.early_signals.append(body)
        elif kind == "logs_ack":
            ids = body.get("ids", [])
            if not isinstance(ids, list) or len(ids) > MAX_BATCH_EVENTS or not all(isinstance(i, str) for i in ids):
                raise ValueError("LOG_ACK_INVALID")
            await asyncio.to_thread(self.log.ack, ids)
            self.upload_inflight.difference_update(ids)
        elif kind == "reach_result":
            future = self.reach_requests.get(body.get("request"))
            if future and not future.done():
                future.set_result(body)
        elif kind == "peer_left":
            current_peer = self.pending_pair_peer or (self.peer["id"] if self.peer else None)
            if current_peer and body.get("peer") != current_peer:
                return
            self.log.event(
                "room.peer_signaling_left",
                "Existing authenticated P2P paths remain until timeout",
                peer=body.get("peer"),
            )
            await self.invalidate_pair()
        elif kind == "error":
            self.log.event("server.error", str(body.get("code")), "ERROR")
            if body.get("code") in (
                "ROOM_FULL",
                "AUTH_FAILED",
                "INVALID_ROOM",
                "SESSION_REPLACED",
                "CLIENT_IDENTITY_CHANGED",
            ):
                self.stop.set()

    async def invalidate_pair(self):
        self.paired.clear()
        self.pair = None
        self.early_signals.clear()
        self.peer_network = {}
        self.pending_pair_peer = None
        if self.pair_task and not self.pair_task.done():
            self.log.event("experiment.setup_cancelled", "Pair ended before setup completed; live P2P paths preserved")
            self.pair_task.cancel()
            await asyncio.gather(self.pair_task, return_exceptions=True)
        if self.manager and not self.manager.closed:
            await self.manager.stop_preserving_paths()

    async def begin_pair(self, body):
        for manager in self.managers:
            await manager.close()
        for future in self.reopen_futures.values():
            if not future.done():
                future.set_exception(ConnectionError("SESSION_CHANGED"))
        self.reopen_managers.clear()
        for lease in self.leases:
            await lease.release()
        self.leases.clear()
        self.peer, self.pair, self.leader = body["peer"], body["pair"], body["leader"]
        self.peer_network = {}
        self.active_path = None
        self.manager = Experiments(self)
        self.managers.append(self.manager)
        manager, pair = self.manager, self.pair
        for early in self.early_signals:
            if early.get("pair") == self.pair:
                if early["data"].get("kind") == "network_status":
                    self.receive_status(early["data"])
                else:
                    self.manager.dispatch(early["data"])
        self.early_signals.clear()
        self.paired.set()
        self.log.event(
            "room.paired",
            peer=self.peer["id"],
            name=self.peer["name"],
            leader=self.leader,
            pair=self.pair,
            role="experiment-coordinator" if self.leader else "experiment-participant",
        )
        # Finish the inbound baseline before any matrix can create gateway mappings.
        if self.inbound_task:
            if not self.inbound_task.done():
                self.log.event("experiment.setup_waiting", "等待入站基线探测完成", reason="INBOUND_BASELINE")
            await asyncio.shield(self.inbound_task)
        await self.publish_status()
        if self.wan_task:
            if not self.wan_task.done():
                self.log.event("experiment.setup_waiting", "等待启动公网测速完成，再运行打洞矩阵", reason="STARTUP_WAN")
            await asyncio.shield(self.wan_task)
        if self.paired.is_set() and manager is self.manager and pair == self.pair and not self.closed:
            await manager.start()

    def request_auto_retry(self, reason):
        if not self.auto_retry or self.closed or not self.paired.is_set() or not self.connected.is_set():
            self.log.event("network.retry_deferred", reason, enabled=self.auto_retry)
            return
        if self.auto_retry_task and not self.auto_retry_task.done():
            return
        self.auto_retry_task = self.spawn(self.automatic_retry(reason), "network-auto-retry")

    async def automatic_retry(self, reason):
        pair = self.pair
        await asyncio.sleep(max(2, 120 - (time.monotonic() - self.last_auto_retry)))
        if self.closed or pair != self.pair or not self.connected.is_set():
            return
        self.last_auto_retry = time.monotonic()
        if self.leader:
            self.log.event("network.auto_retry", reason, policy="coordinated-rebuild;preserve-live-paths")
            await self.restart_experiments(automatic=True)
        else:
            await self.signal({"kind": "phase", "attempt": "setup", "phase": "retry-request"})
            self.log.event("network.retry_requested", reason)

    async def restart_experiments(self, *, remote=False, automatic=False):
        if not self.paired.is_set():
            raise ConnectionError("NO_SIGNALING_PAIR")
        if not remote and not self.leader:
            raise ValueError("RETRY_MUST_BE_REQUESTED_ON_COORDINATOR")
        if not automatic and self.manager and self.manager.task and not self.manager.task.done():
            raise ValueError("WAIT_FOR_CURRENT_MATRIX_TO_FINISH_BEFORE_RETRY")
        async with self.retry_lock:
            previous = self.manager
            if previous:
                self.retired_attempts.update(spec["attempt"] for spec in previous.plan)
            # Install the new signal receiver before any awaits; queued ready packets belong to it.
            self.manager = Experiments(self)
            self.managers.append(self.manager)
            self.network_ready.clear()
            if previous:
                await previous.stop_preserving_paths()
            if not remote:
                await self.signal({"kind": "phase", "attempt": "setup", "phase": "retry"})
            await self.collect_network()
            if self.inbound_supported:
                await self.inbound_check()
            await self.manager.start()

    async def inbound_check(self):
        if not self.inbound_supported:
            self.log.event(
                "ipv6.inbound_not_tested",
                "Server IPv6 HTTP callbacks are disabled; firewall status is unknown.",
                reason="OBSERVER_DISABLED_NOT_A_FIREWALL_VERDICT",
                firewall_assessment="NOT_TESTED",
                scope=SCOPE,
            )
            return
        await self.network_ready.wait()
        inventory = await self.refresh_address_inventory()
        if self.inbound_ipv4_supported and self.server_observed_ipv4:
            local_v4 = [r for r in select_addresses(inventory, maximum=None) if r["family"] == 4]
            if local_v4:
                record = next((r for r in local_v4 if r["address"] == self.server_observed_ipv4), local_v4[0])
                await self.inbound_http_probe(
                    record["address"], self.peer_id, expected=record, destination=self.server_observed_ipv4
                )
        candidates = select_addresses(inventory, maximum=None, inbound=True, loopback=self.loopback)
        if not candidates:
            self.log.event(
                "ipv6.inbound_not_tested",
                "No eligible IPv6 address; client firewall status is unknown.",
                reason="NO_USABLE_GLOBAL_V6_NOT_A_FIREWALL_VERDICT",
                excluded=self.network.get("excluded_addresses", []),
                firewall_assessment="NOT_TESTED",
                scope=SCOPE,
            )
            return
        self.log.event(
            "ipv6.inbound_plan",
            "Testing server-to-client HTTP before P2P/gateway experiments; no second client is required",
            addresses=[r["address"] for r in candidates[:2]],
            address_records=candidates[:2],
            untested_addresses=[r["address"] for r in candidates[2:]],
            policy="preferred-stable-and-temporary;fresh-per-interface-state;30s-minimum-lifetime",
            maximum=2,
            protocol="http/tcp",
        )
        session_id = self.peer_id
        attempted, tried_types, submitted = set(), set(), 0
        # Local rotation/bind failures do not consume remote checks; retries still have a hard cap.
        for index in range(8):
            if self.peer_id != session_id or submitted >= 2:
                return
            if index:
                inventory = await self.refresh_address_inventory()
                candidates = select_addresses(inventory, maximum=None, inbound=True, loopback=self.loopback)
            pending = [r for r in candidates if r["address"] not in attempted]
            if not pending:
                return
            record = next((r for r in pending if r.get("type") not in tried_types), pending[0])
            attempted.add(record["address"])
            tried_types.add(record.get("type"))
            if await self.inbound_http_probe(record["address"], session_id, expected=record):
                submitted += 1

    async def inbound_http_probe(self, host, session_id, *, expected=None, destination=None):
        destination = destination or host
        family = ipaddress.ip_address(destination).version
        event_prefix = "ipv6" if family == 6 else "ipv4"
        token, request_id = secrets.token_urlsafe(24), secrets.token_hex(12)
        used = False
        writers = set()
        started = time.monotonic()
        address_record = None
        submitted = False

        async def reach(reader, writer):
            nonlocal used
            import hmac

            if len(writers) >= 4:
                writer.close()
                await writer.wait_closed()
                return
            writers.add(writer)
            try:
                headers = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 2)
                if len(headers) > 8192:
                    raise ValueError("INBOUND_REQUEST_LIMIT")
                first = headers.split(b"\r\n", 1)[0].decode("ascii").split()
                target = urlsplit(first[1]) if len(first) == 3 else None
                query = parse_qs(target.query, max_num_fields=4) if target else {}
                valid = bool(
                    target
                    and first[0] == "GET"
                    and target.path == "/reach"
                    and not target.netloc
                    and not target.scheme
                    and query.get("token") == [token]
                    and not used
                )
                if valid and hmac.compare_digest(query["token"][0], token):
                    used = True
                    response = f"HTTP/1.1 204 No Content\r\nX-P2P-Token: {token}\r\n"
                    self.log.event(
                        event_prefix + ".listener_authenticated",
                        f"Authenticated IPv{family} HTTP request received from the observer",
                        request_id=request_id,
                        remote=writer.get_extra_info("peername"),
                    )
                else:
                    response = "HTTP/1.1 403 Forbidden\r\n"
                    self.log.event(event_prefix + ".listener_rejected", request_id=request_id)
                writer.write((response + "Content-Length: 0\r\nConnection: close\r\n\r\n").encode())
                await asyncio.wait_for(writer.drain(), 1)
            except Exception as exc:
                self.log.event(
                    event_prefix + ".listener_failed", str(exc), "WARNING", exception=type(exc).__name__
                )
            finally:
                writer.close()
                with contextlib.suppress(OSError, TimeoutError):
                    await asyncio.wait_for(writer.wait_closed(), 1)
                writers.discard(writer)

        listener = None
        sock = None
        port = None
        future = asyncio.get_running_loop().create_future()
        self.reach_requests[request_id] = future
        try:
            from .common import new_socket

            address_record = await self.validate_local_address(host, expected=expected)
            sock = new_socket(host, socket.SOCK_STREAM)
            sock.listen(4)
            port = sock.getsockname()[1]
            listener = await asyncio.start_server(reach, sock=sock, limit=8192)
            self.log.event(
                event_prefix + ".listener_started",
                f"Temporary IPv{family} HTTP listener ready for a direct server callback",
                address=host,
                target=destination,
                family=family,
                port=port,
                request_id=request_id,
                protocol="http/tcp",
                phase="before-p2p-and-gateway",
                address_record=address_record,
            )
            proof = self.identity.sign(
                {
                    "session": session_id,
                    "address": destination,
                    "port": port,
                    "request": request_id,
                    "token": token,
                }
            )
            submitted = True
            await self.send_control(
                {
                    "type": "reach",
                    "address": destination,
                    "port": port,
                    "request": request_id,
                    "token": token,
                    "proof": proof,
                }
            )
            result = await asyncio.wait_for(future, 6)
            code = result.get("code", "RESULT_UNRECOGNIZED")
            if code == "REACHABLE" and not used:
                code = "INCONSISTENT_OBSERVER_AND_LISTENER"
            elif used and code != "REACHABLE":
                code = "LISTENER_REACHED_OBSERVER_RESPONSE_FAILED"
            self.log.event(
                event_prefix + ".inbound_result",
                message(code).replace("IPv6", f"IPv{family}"),
                code=code,
                observer_code=result.get("code"),
                listener_received=used,
                address=host,
                target=destination,
                family=family,
                port=port,
                request_id=request_id,
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                observer_elapsed_ms=result.get("elapsed_ms"),
                os_errno=result.get("os_errno"),
                detail=result.get("detail"),
                protocol="http/tcp",
                scope=SCOPE,
                firewall_assessment=assessment(code),
                address_record=address_record,
            )
        except Exception as exc:
            self.log.exception(event_prefix + ".inbound_failed", exc)
            code = (
                "CONTROL_RESULT_TIMEOUT"
                if isinstance(exc, TimeoutError)
                else "LOCAL_LISTENER_OR_SIGNALING_FAILED"
            )
            if isinstance(exc, ValueError) and str(exc).startswith("LOCAL_IPV6_ADDRESS_UNAVAILABLE:"):
                code = "LOCAL_ADDRESS_NOT_AVAILABLE"
            if used:
                code = "LISTENER_REACHED_OBSERVER_RESPONSE_FAILED"
            self.log.event(
                event_prefix + ".inbound_result",
                message(code).replace("IPv6", f"IPv{family}"),
                "WARNING",
                code=code,
                address=host,
                target=destination,
                family=family,
                port=port,
                request_id=request_id,
                listener_received=used,
                elapsed_ms=round((time.monotonic() - started) * 1000, 2),
                protocol="http/tcp",
                scope=SCOPE,
                firewall_assessment=assessment(code),
                address_record=address_record,
                reason=str(exc),
            )
        finally:
            self.reach_requests.pop(request_id, None)
            if listener:
                listener.close()
                await listener.wait_closed()
            elif sock:
                sock.close()
            for writer in tuple(writers):
                writer.close()
        self.inbound_results[host] = {
            "address": host,
            "code": code,
            "listener_received": used,
            "tested_at": utcnow(),
        }
        await self.publish_status()
        return submitted

    async def chat(self, text):
        if not text or len(text.encode()) > MAX_TEXT:
            raise ValueError("CHAT_MUST_BE_1_TO_16384_UTF8_BYTES")
        mid = str(uuid.uuid4())
        future = asyncio.get_running_loop().create_future()
        self.chat_acks[mid] = future
        try:
            for retry in range(3):
                path = await self.active_data_path()
                try:
                    if RECEIPT_CAPABILITY in path.remote_capabilities:
                        await path.begin_chat(mid, len(text.encode()))
                    await path.send({"kind": "chat", "id": mid, "text": text})
                    response = await asyncio.wait_for(asyncio.shield(future), 5)
                    metrics = (
                        validate_receipt(response, len(text.encode()))
                        if RECEIPT_CAPABILITY in path.remote_capabilities else None
                    )
                    self.log.event(
                        "chat.delivered",
                        message_id=mid,
                        attempt=path.attempt,
                        bytes=len(text.encode()),
                        retries=retry,
                        receipt=metrics,
                    )
                    return metrics
                except (ConnectionError, TimeoutError, OSError):
                    if retry == 2:
                        raise
                    await path.close("CHAT_ACK_OR_IO_TIMEOUT")
        finally:
            self.chat_acks.pop(mid, None)
            if not future.done():
                future.cancel()

    async def command(self, line):
        line = line.strip()
        if not line:
            return
        if not line.startswith("/"):
            return await self.chat(line)
        parts = line.split()
        cmd = parts[0]
        self.log.event("terminal.command", command=cmd, arguments=parts[1:])
        if cmd in ("/file", "/image"):
            source = line.partition(" ")[2].strip()
            if source.startswith(('"', "'")):
                quoted = shlex.split(source)
                if len(quoted) != 1:
                    raise ValueError("FILE_PATH_REQUIRED")
                source = quoted[0]
            if not source:
                raise ValueError("FILE_PATH_REQUIRED")
            return await self.transfers.send(await self.active_data_path(), source, image=cmd == "/image")
        elif cmd in ("/accept", "/reject", "/cancel"):
            if len(parts) != 2:
                raise ValueError("FILE_TRANSFER_ID_REQUIRED")
            if cmd == "/accept":
                await self.transfers.accept(parts[1])
            elif cmd == "/reject":
                if parts[1] not in self.transfers.incoming:
                    raise ValueError("FILE_TRANSFER_NOT_ACTIVE")
                await self.transfers.abort(parts[1], "FILE_REJECTED")
            else:
                await self.transfers.cancel(parts[1])
        elif cmd == "/transfers":
            self.log.event("file.status", transfers=list(self.transfers.records.values()))
        elif cmd in ("/view", "/open-dir"):
            if cmd == "/open-dir":
                target = self.transfers.directory
                await disk_call(target.mkdir, 0o700, True, True)
            else:
                if len(parts) != 2:
                    raise ValueError("FILE_TRANSFER_ID_REQUIRED")
                item = self.transfers.records.get(parts[1], {})
                if item.get("state") != "completed" or item.get("media") != "image" or not item.get("saved_path"):
                    raise ValueError("IMAGE_NOT_RECEIVED")
                target = FilePath(item["saved_path"]).resolve()
                if target.parent != self.transfers.directory.resolve():
                    raise ValueError("IMAGE_PATH_INVALID")
                stream, _ = await disk_call(open_source, target, True, cleanup=lambda result: result[0].close())
                await disk_call(stream.close)
            await self.open_desktop(target)
        elif cmd == "/quit":
            self.stop.set()
        elif cmd == "/ping":
            path = await self.active_data_path()
            samples = []
            for _ in range(5):
                samples.append(await path.ping())
                await asyncio.sleep(0.1)
            self.log.event(
                "ping.result",
                attempt=path.attempt,
                samples_ms=samples,
                min_ms=min(samples),
                mean_ms=sum(samples) / len(samples),
                max_ms=max(samples),
                scope="current-p2p-application-channel-rtt-not-one-way-latency",
            )
        elif cmd in ("/speed", "/speed-all"):
            if self.wan_lock.locked() or self.peer_network.get("wan", {}).get("state") == "running":
                raise ValueError("WAN_TEST_RUNNING_SPEED_DEFERRED")
            mib = int(parts[1]) if len(parts) > 1 else 4
            if not 1 <= mib <= 1024:
                raise ValueError("SPEED_SIZE_MUST_BE_1_TO_1024_MIB")
            async with self.speed_lock:
                if cmd == "/speed-all":
                    await self.speed_all(mib * 1024 * 1024)
                else:
                    await self.measure_path(await self.active_data_path(), mib * 1024 * 1024)
        elif cmd == "/paths":
            self.log.event(
                "paths.status",
                paths=[
                    {
                        "index": i,
                        "attempt": p.attempt,
                        "mechanism": p.mechanism,
                        "family": p.family,
                        "ready": p.ready.is_set(),
                        "closed": p.closed,
                        "cold_standby": getattr(p, "parked", False),
                        "rtt_ms": p.last_rtt,
                        "active": p is self.active_path,
                    }
                    for i, p in enumerate(self.paths)
                ],
            )
        elif cmd == "/use":
            index = int(parts[1])
            path = self.paths[index]
            path = await self.ensure_path(path, activate=True)
            self.active_path = path
            path.lifecycle_pins = 0
            if self.can_reopen(path):
                await self.signal({"kind": "path_select", "attempt": path.attempt})
                await self.park_idle_paths()
            self.log.event("path.selected", index=index, attempt=path.attempt)
        elif cmd == "/wan":
            await self.test_wan()
        elif cmd == "/net":
            await self.collect_network()
        elif cmd == "/results":
            self.log.event("results.status", results=self.manager.results if self.manager else [])
        elif cmd == "/retry":
            await self.restart_experiments()
        elif cmd == "/help":
            self.log.event(
                "terminal.help",
                "/file PATH /image PATH /accept ID /reject ID /cancel ID /transfers /view ID /open-dir "
                "/ping /speed [MiB] /speed-all [MiB] /wan /paths /use INDEX /net /results /retry /quit",
            )
        else:
            raise ValueError("UNKNOWN_COMMAND;USE_/help")

    async def measure_path(self, path, size):
        try:
            path = await self.ensure_path(path)
            path.lifecycle_pins = max(1, getattr(path, "lifecycle_pins", 0))
            path.speed_state = "running"
            path.speed_run = secrets.token_hex(8)
            for direction in ("local-to-peer", "peer-to-local"):
                if path.closed or not path.ready.is_set():
                    raise ConnectionError("PATH_UNAVAILABLE")
                result = await asyncio.wait_for(
                    path.speed(size) if direction == "local-to-peer" else path.reverse_speed(size), 125
                )
                path.latest_speed[direction] = {
                    **result,
                    "measured_at": time.monotonic(),
                    "measurement_run": path.speed_run,
                }
                assessment = speed_assessment(result, self.path_reference(path, direction))
                competing = bool(self.manager and self.manager.task and not self.manager.task.done())
                bottleneck = bottleneck_assessment(result, self.path_reference(path, direction), competing=competing)
                path.latest_speed[direction]["wan_assessment"] = assessment
                path.latest_speed[direction]["bottleneck"] = bottleneck
                path.latest_speed[direction]["measurement_contended"] = competing
                self.log.event(
                    "speed.result",
                    wan_assessment=assessment,
                    bottleneck=bottleneck,
                    attempt=path.attempt,
                    **result,
                    direction=direction,
                    scope="confirmed-application-goodput-not-line-rate",
                    matrix_in_progress=competing,
                )
            path.speed_state = "success"
            return path
        except asyncio.CancelledError:
            path.speed_state = "cancelled"
            raise
        except Exception:
            path.speed_state = "failed"
            raise
        finally:
            path.lifecycle_pins = max(0, getattr(path, "lifecycle_pins", 0) - 1)
            await self.park_idle_paths()

    async def speed_all(self, size):
        paths = [p for p in self.paths if p.ready.is_set() and (not p.closed or self.can_reopen(p))]
        if not paths:
            raise ConnectionError("NO_AUTHENTICATED_P2P_DATA_PATH_YET")
        self.batch_speed_state = {"state": "running", "completed": 0, "total": len(paths), "failed": 0}
        self.log.event("speed.batch_started", paths=[p.attempt for p in paths], bytes_per_direction=size)
        try:
            for path in paths:
                self.batch_speed_state["attempt"] = path.attempt
                path.speed_state = "running"
                try:
                    path = await self.measure_path(path, size)
                    path.speed_state = "success"
                except Exception as exc:
                    path.speed_state = "failed"
                    self.batch_speed_state["failed"] += 1
                    self.log.event(
                        "speed.batch_path_failed",
                        str(exc),
                        "WARNING",
                        attempt=path.attempt,
                        exception=type(exc).__name__,
                    )
                self.batch_speed_state["completed"] += 1
            self.batch_speed_state["state"] = "completed"
        except asyncio.CancelledError:
            self.batch_speed_state["state"] = "cancelled"
            path.speed_state = "cancelled"
            raise
        finally:
            self.log.event("speed.batch_finished", **self.batch_speed_state)

    async def terminal(self):
        transport = None
        if sys.platform == "win32":
            reader = ConsoleReader(sys.stdin)
            reader.start()
        else:
            reader = asyncio.StreamReader(limit=64 * 1024)
            protocol = asyncio.StreamReaderProtocol(reader)
            source = sys.stdin
            if source.isatty():
                # dup() still shares O_NONBLOCK with stdout on a PTY; reopen the device.
                descriptor = os.open(os.ttyname(source.fileno()), os.O_RDONLY | os.O_NOCTTY)
                source = os.fdopen(descriptor, "rb", buffering=0)
            try:
                transport, _ = await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, source)
            except BaseException:
                if source is not sys.stdin:
                    source.close()
                raise
        self.log.event("terminal.ready", "Type chat text or /help; experiments continue after any success")
        try:
            while not self.stop.is_set():
                line = await reader.readline()
                if not line:
                    self.log.event("terminal.eof")
                    self.stop.set()
                    return
                text = line.decode("utf-8", errors="replace")
                command_name = text.strip().split(maxsplit=1)[0] if text.strip() else ""
                if command_name in ("/speed", "/ping", "/net", "/file", "/image"):
                    name = "terminal-command:" + command_name
                    if any(task.get_name() == name for task in self.tasks):
                        self.log.event(
                            "terminal.command_busy",
                            "This command is already running",
                            "WARNING",
                            command=command_name,
                        )
                    else:
                        self.spawn(self.terminal_command(text), name)
                else:
                    await self.terminal_command(text)
        finally:
            transport.close() if transport else reader.close()

    async def terminal_command(self, text):
        try:
            metrics = await self.command(text)
            if text.strip() and not text.strip().startswith("/"):
                self.display_chat("我 · 已送达", text.strip(), metrics)
        except Exception as exc:
            self.log.exception("terminal.command_failed", exc)

    async def open_desktop(self, target):
        if os.name == "nt":
            os.startfile(str(FilePath(target).resolve()))
            self.log.event("file.opened", path=str(target))
            return
        process = await asyncio.create_subprocess_exec(
            "open" if sys.platform == "darwin" else "xdg-open", str(target),
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            async with asyncio.timeout(10):
                code = await process.wait()
            if code:
                raise OSError("DESKTOP_OPEN_FAILED")
            self.log.event("file.opened", path=str(target))
        finally:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.kill()
                await process.wait()

    async def run(self, *, interactive=True, signal_stop=None):
        self.log.install()
        loop = asyncio.get_running_loop()
        previous_handler = loop.get_exception_handler()
        loop.set_exception_handler(
            lambda loop, ctx: self.log.exception(
                "runtime.asyncio_error",
                ctx.get("exception", RuntimeError(ctx.get("message", "asyncio error"))),
            )
        )
        for sig in (signal.SIGINT, signal.SIGTERM):
            with contextlib.suppress(NotImplementedError):
                loop.add_signal_handler(sig, signal_stop or self.stop.set)
        self.log.event(
            "client.started",
            room=self.room,
            server=self.server_url,
            name=self.name,
            profiles=self.profiles,
            gateway=self.gateway_enabled,
            comprehensive=self.research_enabled,
            raw_probes=self.config.get("experiment", {}).get("raw_probes", False),
            auto_retry=self.auto_retry,
            loopback_test_mode=self.loopback,
            journal=str(self.data / "client.sqlite3"),
            transfer={"download_dir": str(self.transfers.directory), "max_bytes": self.transfers.max_bytes,
                      "auto_accept": self.transfers.auto_accept},
        )
        if self.diagnostics_enabled and not self.loopback:
            self.log.event("network.test_notice", NETWORK_TEST_NOTICE, "WARNING")
        self.wan_task = self.spawn(self.startup_wan(), "startup-wan")
        self.spawn(self.signaling(), "signaling")
        self.spawn(self.uploader(), "log-uploader")
        self.spawn(self.collect_network(), "network-diagnostics")
        self.spawn(self.watch_network(), "network-watcher")
        if interactive:
            self.spawn(self.terminal(), "terminal")
        try:
            await self.stop.wait()
        finally:
            await self.close()
            loop.set_exception_handler(previous_handler)

    async def close(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        self.log.event("client.stopping")
        await self.transfers.close()
        for manager in self.managers:
            await manager.close()
        for path in self.paths:
            await path.close("CLIENT_SHUTDOWN")
        for lease in self.leases:
            await lease.release()
        self.log.event("client.stopped", "Pending unacknowledged events remain on disk for next launch")
        # Final bounded drain keeps shutdown finite if the server is unavailable.
        if self.ws and not self.ws.closed:
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline:
                with contextlib.suppress(ConnectionError, TimeoutError):
                    if not await self.upload_logs():
                        break
                await asyncio.sleep(0.15)
        for task in tuple(self.tasks):
            if task is not asyncio.current_task():
                task.cancel()
        if self.ws:
            await self.ws.close()
        await asyncio.gather(
            *(t for t in tuple(self.tasks) if t is not asyncio.current_task()), return_exceptions=True
        )
        self.identity.close()
        self.log.close()


def main():
    configure_console_encoding()
    parser = argparse.ArgumentParser(description="Two-person terminal P2P connectivity lab")
    parser.add_argument("--config", default="client.local.toml")
    parser.add_argument("--server")
    parser.add_argument("--room")
    parser.add_argument("--name")
    parser.add_argument("--data")
    parser.add_argument("--allow-insecure", action="store_true")
    parser.add_argument(
        "--loopback", action="store_true", help="Use only loopback candidates for local tests"
    )
    parser.add_argument("--no-external-diagnostics", action="store_true")
    parser.add_argument("--no-gateway", action="store_true")
    parser.add_argument("--expanded", action="store_true")
    interface = parser.add_mutually_exclusive_group()
    interface.add_argument("--tui", action="store_true", help="Use the Chinese full-screen interface")
    interface.add_argument("--plain", action="store_true", help="Use line-oriented terminal output")
    args = parser.parse_args()
    config = {}
    path = FilePath(args.config)
    if args.config == "client.local.toml" and getattr(sys, "frozen", False):
        path = application_directory() / args.config
    if path.exists():
        with path.open("rb") as f:
            config = tomllib.load(f)
    elif args.config != "client.local.toml":
        parser.error("Config file does not exist")
    for arg, key in ((args.server, "server"), (args.name, "name"), (args.data, "data_dir")):
        if arg is not None:
            config[key] = arg
    if args.allow_insecure:
        config["allow_insecure"] = True
    config["loopback"] = args.loopback
    options = config.setdefault("experiment", {})
    if args.no_external_diagnostics:
        options["diagnostics"] = False
        options["stun"] = []
    if args.no_gateway:
        options["gateway"] = False
    if args.expanded:
        options["expanded"] = True
    try:
        use_tui = args.tui or (not args.plain and sys.stdin.isatty() and sys.stdout.isatty())
        if use_tui:
            from .tui import P2PApp

            if args.room is not None and (not args.room or len(args.room) > 64):
                parser.error("Room must contain 1 to 64 characters")
            P2PApp(config, room=args.room).run()
            return
        room = args.room or input("Room number: ").strip()
        if not room or len(room) > 64:
            parser.error("Room must contain 1 to 64 characters")
        asyncio.run(Client(config, room).run())
    except (KeyboardInterrupt, EOFError):
        pass
    except ValueError as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    main()
