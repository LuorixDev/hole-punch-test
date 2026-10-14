from __future__ import annotations

import argparse
import asyncio
import errno
import hmac
import ipaddress
import json
import secrets
import signal
import socket
import ssl
import time
import uuid
from collections import defaultdict, deque
from pathlib import Path

import aiohttp
from aiohttp import web
from cryptography import x509

from .common import VERSION, Identity, endpoint, packed, unb64
from .inbound import SCOPE, assessment, message
from .journal import Journal
from .logcodec import CODEC, decode_batch
from .runtime import configure_console_encoding
from .stun import StunServer

SIGNAL_ATTEMPT_LIMIT = 4096


class Hub:
    def __init__(
        self,
        journal,
        *,
        admin_token,
        access_token="",
        stun_port=3478,
        tcp_port=3479,
        tcp_observer_protocol="raw",
        forwarded=False,
        allow_inbound=False,
        allow_loopback=False,
        inbound_prefixes=(),
    ):
        self.log, self.admin_token, self.access_token = journal, admin_token, access_token
        self.stun_port, self.tcp_port = stun_port, tcp_port
        self.tcp_observer_protocol = tcp_observer_protocol
        self.forwarded = forwarded
        self.allow_inbound, self.allow_loopback = allow_inbound, allow_loopback
        self.rooms, self.peers, self.observation_tokens = {}, {}, {}
        self.reach_active = asyncio.Semaphore(2)
        self.connection_rates = defaultdict(deque)
        self.inbound_prefixes = [ipaddress.ip_network(prefix) for prefix in inbound_prefixes]
        self.reach_rates = defaultdict(deque)

    def app(self):
        app = web.Application(client_max_size=1_000_000)
        app.router.add_get("/health", self.health)
        app.router.add_get("/ws", self.websocket)
        app.router.add_get("/logs", self.logs)
        app.router.add_post("/tcp-observe", self.observe_http)
        return app

    async def health(self, request):
        return web.json_response(
            {"version": VERSION, "strict_p2p": True, "rooms": len(self.rooms), "clients": len(self.peers)}
        )

    async def logs(self, request):
        if not hmac.compare_digest(request.headers.get("Authorization", ""), f"Bearer {self.admin_token}"):
            raise web.HTTPUnauthorized()
        try:
            events = self.log.query(
                after=int(request.query.get("after", 0)),
                room=request.query.get("room"),
                client=request.query.get("client"),
                limit=int(request.query.get("limit", 1000)),
            )
        except ValueError:
            raise web.HTTPBadRequest(text="INVALID_CURSOR") from None
        self.log.event("logs.export", count=len(events), room=request.query.get("room"))
        response = web.Response(
            body=packed({"events": events, "next": events[-1]["cursor"] if events
                         else int(request.query.get("after", 0))}),
            content_type="application/json",
            zlib_executor_size=64 * 1024,
        )
        response.enable_compression()
        return response

    async def send(self, peer, body):
        await peer["ws"].send_json({"v": VERSION, **body})

    async def websocket(self, request):
        source = request.remote or "unknown"
        now = time.monotonic()
        times = self.connection_rates[source]
        while times and times[0] < now - 60:
            times.popleft()
        if len(times) >= 30 or len(self.peers) >= 256:
            raise web.HTTPTooManyRequests()
        times.append(now)
        if len(self.connection_rates) > 2048:
            self.connection_rates = defaultdict(
                deque, {k: v for k, v in self.connection_rates.items() if v and v[-1] > now - 60}
            )
        ws = web.WebSocketResponse(heartbeat=20, max_msg_size=300_000)
        await ws.prepare(request)
        peer = None
        try:
            challenge = secrets.token_urlsafe(24)
            await ws.send_json({"v": VERSION, "type": "challenge", "nonce": challenge})
            msg = await asyncio.wait_for(ws.receive(), 10)
            if msg.type != aiohttp.WSMsgType.TEXT:
                raise ValueError("JOIN_REQUIRED")
            body = json.loads(msg.data)
            self.validate_join(body)
            certificate = x509.load_pem_x509_certificate(body["certificate"].encode())
            from cryptography.hazmat.primitives import hashes

            expected = {
                "v": VERSION,
                "kind": "join",
                "nonce": challenge,
                "room": body["room"],
                "client": body["client"],
                "public": body["public"],
                "name": body["name"],
                "certificate_fingerprint": certificate.fingerprint(hashes.SHA256()).hex(),
            }
            if Identity.verify(body["proof"], body["public"]) != expected:
                raise ValueError("JOIN_PROOF_MISMATCH")
            if self.access_token and not hmac.compare_digest(body.get("token", ""), self.access_token):
                raise ValueError("AUTH_FAILED")
            self.log.bind_client(body["client"], body["public"])
            room = body["room"]
            members = self.rooms.setdefault(room, [])
            # Replacing the same persistent client releases a stale WS before capacity checks.
            for old in tuple(members):
                if old["client"] == body["client"]:
                    await old["ws"].close(code=4001, message=b"SESSION_REPLACED")
                    await self.leave(old)
            members = self.rooms.setdefault(room, [])
            if len(members) >= 2:
                raise ValueError("ROOM_FULL")
            pid = str(uuid.uuid4())
            obs = secrets.token_urlsafe(24)
            peer = {
                "id": pid,
                "client": body["client"],
                "room": room,
                "name": body["name"],
                "public": body["public"],
                "certificate": body["certificate"],
                "ws": ws,
                "source": source,
                "obs": obs,
                "pair": None,
                "signals": {},
                "retired_pairs": deque(maxlen=32),
                "checks": 0,
                "checks4": 0,
                "reach_requests": set(),
            }
            members.append(peer)
            self.peers[pid] = peer
            self.observation_tokens[obs] = (pid, now + 3600)
            await self.send(
                peer,
                {
                    "type": "welcome",
                    "id": pid,
                    "observation_token": obs,
                    "stun_port": self.stun_port,
                    "tcp_port": self.tcp_port,
                    "tcp_observer_protocol": self.tcp_observer_protocol,
                    "observation_mode": "forwarded" if self.forwarded else "direct",
                    "inbound_check": self.allow_inbound,
                    "inbound_ipv4_check": self.allow_inbound and not self.forwarded,
                    "inbound_max_checks": 2,
                    "strict_p2p": True,
                    "log_encodings": [CODEC],
                    "cold_paths": True,
                    "observed_ipv4": source if ":" not in source and source != "unknown" else None,
                },
            )
            self.log.event("room.join", room=room, peer=pid, client=peer["client"], source=source)
            if len(members) == 2:
                pair = str(uuid.uuid4())
                for index, member in enumerate(members):
                    member["pair"] = pair
                    other = members[1 - index]
                    await self.send(
                        member,
                        {
                            "type": "paired",
                            "pair": pair,
                            "leader": index == 0,
                            "peer": {k: other[k] for k in ("id", "client", "name", "public", "certificate")},
                        },
                    )
            else:
                await self.send(peer, {"type": "waiting"})
            rate = deque()
            async for msg in ws:
                if msg.type != aiohttp.WSMsgType.TEXT:
                    if msg.type == aiohttp.WSMsgType.ERROR:
                        raise ConnectionError(str(ws.exception()))
                    continue
                now = time.monotonic()
                while rate and rate[0] < now - 1:
                    rate.popleft()
                if len(rate) >= 120:
                    raise ValueError("MESSAGE_RATE_LIMIT")
                rate.append(now)
                await self.dispatch(peer, json.loads(msg.data))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            self.log.exception("signaling.error", exc, source=source)
            if not ws.closed:
                try:
                    await ws.send_json({"type": "error", "code": str(exc)[:200]})
                except (ConnectionError, aiohttp.ClientError, RuntimeError) as send_error:
                    self.log.event("signal.error_delivery_failed", str(send_error), "WARNING", source=source)
        finally:
            if peer:
                await self.leave(peer)
            await ws.close()
        return ws

    @staticmethod
    def validate_join(body):
        if not isinstance(body, dict) or body.get("type") != "join" or body.get("v") != VERSION:
            raise ValueError("UNSUPPORTED_JOIN")
        uuid.UUID(body["client"])
        room = body["room"]
        if not isinstance(room, str) or not 1 <= len(room) <= 64 or any(ord(c) < 32 for c in room):
            raise ValueError("INVALID_ROOM")
        if not isinstance(body["name"], str) or len(body["name"]) > 64:
            raise ValueError("INVALID_NAME")
        if len(unb64(body["public"])) != 32 or len(body["certificate"]) > 8192:
            raise ValueError("INVALID_IDENTITY")
        x509.load_pem_x509_certificate(body["certificate"].encode())

    async def leave(self, peer):
        if self.peers.pop(peer["id"], None) is None:
            return
        self.observation_tokens.pop(peer["obs"], None)
        members = self.rooms.get(peer["room"], [])
        if peer in members:
            members.remove(peer)
        self.log.event("room.leave", room=peer["room"], peer=peer["id"])
        if not members:
            self.rooms.pop(peer["room"], None)
        for other in members:
            if other["pair"]:
                other["retired_pairs"].append(other["pair"])
            other["pair"] = None
            other["signals"].clear()
            if not other["ws"].closed:
                try:
                    await self.send(other, {"type": "peer_left", "peer": peer["id"]})
                except (ConnectionError, aiohttp.ClientError, RuntimeError) as exc:
                    self.log.event("signal.peer_left_delivery_failed", str(exc), "WARNING", room=peer["room"])

    async def dispatch(self, peer, body):
        if not isinstance(body, dict) or body.get("v") != VERSION:
            raise ValueError("INVALID_MESSAGE")
        kind = body.get("type")
        if kind == "logs":
            def commit_logs():
                records = decode_batch(body) if "encoding" in body else body.get("events")
                if "encoding" not in body and (not isinstance(records, list) or len(records) > 64):
                    raise ValueError("LOG_BATCH_LIMIT")
                return self.log.ingest(records, peer["client"])

            ids = await asyncio.to_thread(commit_logs)
            await self.send(peer, {"type": "logs_ack", "ids": ids})
            self.log.event(
                "logs.committed", room=peer["room"], client=peer["client"], count=len(ids),
                encoding=body.get("encoding", "legacy-json"),
                raw_bytes=body.get("raw_bytes"),
                encoded_bytes=len(body["data"]) if isinstance(body.get("data"), str) else None,
            )
        elif kind == "signal":
            if not peer["pair"] or body.get("pair") != peer["pair"]:
                if not peer["pair"] or body.get("pair") in peer["retired_pairs"]:
                    self.log.event("signal.stale_pair", "Dropped signal from a departed pair; session remains online",
                                   room=peer["room"], peer=peer["id"], pair=body.get("pair"))
                    return
                raise ValueError("PAIR_MISMATCH")
            data = body.get("data")
            if not isinstance(data, dict) or data.get("kind") not in (
                "plan",
                "candidate",
                "ready",
                "offer",
                "answer",
                "phase",
                "done",
                "network_status",
                "sync", "pool_select", "race_choice", "plan_part", "native_ice", "raw_meta",
                "path_reopen_request", "path_reopen", "path_select", "path_park",
                "path_reopen_reject",
                "path_park_ack",
            ):
                raise ValueError("SIGNAL_ONLY_NO_APPLICATION_RELAY")
            schema = {
                "plan": {"kind", "attempt", "plan"},
                "candidate": {"kind", "attempt", "candidates"},
                "ready": {"kind", "attempt", "addresses"},
                "offer": {"kind", "attempt", "sdp"},
                "answer": {"kind", "attempt", "sdp"},
                "phase": {"kind", "attempt", "phase"},
                "done": {"kind", "attempt", "result"},
                "network_status": {"kind", "attempt", "status"},
                "sync": {"kind", "attempt", "stage", "nonce"},
                "pool_select": {"kind", "attempt", "nonce"},
                "race_choice": {"kind", "attempt", "choice"},
                "plan_part": {"kind", "attempt", "index", "total", "plan"},
                "native_ice": {"kind", "attempt", "sdp"},
                "raw_meta": {"kind", "attempt", "meta"},
                "path_reopen_request": {"kind", "attempt", "request", "mode"},
                "path_reopen": {"kind", "attempt", "source", "request", "mode"},
                "path_select": {"kind", "attempt"},
                "path_park": {"kind", "attempt", "request"},
                "path_park_ack": {"kind", "attempt", "request", "allowed"},
                "path_reopen_reject": {"kind", "attempt", "request", "reason"},
            }
            if set(data) != schema[data["kind"]]:
                raise ValueError("INVALID_SIGNAL_FIELDS_NO_APPLICATION_RELAY")
            if data["kind"] in ("path_park", "path_park_ack"):
                if (not isinstance(data["request"], str) or len(data["request"]) != 16
                        or any(c not in "0123456789abcdef" for c in data["request"])
                        or data["kind"] == "path_park_ack" and type(data["allowed"]) is not bool):
                    raise ValueError("PATH_PARK_SCHEMA")
            if data["kind"] == "path_reopen_reject":
                if (data["reason"] != "REOPEN_FAILED" or self.rooms[peer["room"]][0] is not peer
                        or not isinstance(data["request"], str) or len(data["request"]) != 16
                        or any(c not in "0123456789abcdef" for c in data["request"])):
                    raise ValueError("PATH_REOPEN_REJECT_SCHEMA")
            if data["kind"] in ("path_reopen_request", "path_reopen"):
                request_id = data["request"]
                if (not isinstance(request_id, str) or len(request_id) != 16
                        or any(c not in "0123456789abcdef" for c in request_id)
                        or data["mode"] not in ("use", "measure")):
                    raise ValueError("PATH_REOPEN_SCHEMA")
                if data["kind"] == "path_reopen":
                    if self.rooms[peer["room"]][0] is not peer:
                        raise ValueError("ONLY_COORDINATOR_CAN_REOPEN")
                    if not isinstance(data["source"], str) or not 1 <= len(data["source"]) <= 120:
                        raise ValueError("PATH_REOPEN_SOURCE")
            if data["kind"] == "network_status":
                from .status import validate_status

                validate_status(data["status"])
            if data["kind"] == "raw_meta":
                meta = data["meta"]
                if not isinstance(meta, dict) or set(meta) not in ({"sequence"}, {"observer", "identifier", "public"}):
                    raise ValueError("RAW_METADATA_SCHEMA")
                key = "sequence" if "sequence" in meta else "identifier"
                if type(meta[key]) is not int or not 0 <= meta[key] < (2**32 if key == "sequence" else 65536):
                    raise ValueError("RAW_METADATA_RANGE")
                for key in ("observer", "public"):
                    if key in meta and (not isinstance(meta[key], str) or ipaddress.ip_address(meta[key]).version != 4):
                        raise ValueError("RAW_METADATA_FAMILY")
            if data["kind"] == "phase":
                if data["phase"] not in ("retry", "retry-request"):
                    raise ValueError("PHASE_SCHEMA")
                if data["phase"] == "retry":
                    if self.rooms[peer["room"]][0] is not peer:
                        raise ValueError("ONLY_COORDINATOR_CAN_RESTART_MATRIX")
                    for member in self.rooms[peer["room"]]:
                        member["signals"].clear()
            attempt = data.get("attempt", "")
            if not isinstance(attempt, str) or len(attempt) > 120:
                raise ValueError("INVALID_ATTEMPT")
            if data["kind"] in ("offer", "answer", "native_ice") and (
                not isinstance(data["sdp"], str) or len(data["sdp"]) > 65536
            ):
                raise ValueError("SDP_LIMIT")
            if data["kind"] == "sync" and (data["stage"] not in ("ready", "probe", "echo", "go")
                    or not isinstance(data["nonce"], str) or len(data["nonce"]) > 32):
                raise ValueError("SYNC_SCHEMA")
            if data["kind"] == "pool_select" and (not isinstance(data["nonce"], str) or len(data["nonce"]) != 32):
                raise ValueError("POOL_SELECTION_SCHEMA")
            if data["kind"] == "race_choice" and data["choice"] not in ("primary", "reverse"):
                raise ValueError("TCP_RACE_CHOICE_INVALID")
            if data["kind"] == "plan_part" and (type(data["index"]) is not int or type(data["total"]) is not int
                    or not 0 <= data["index"] < data["total"] <= 64 or not isinstance(data["plan"], list)
                    or len(data["plan"]) > 16):
                raise ValueError("PLAN_PART_SCHEMA")
            peer["signals"][attempt] = peer["signals"].get(attempt, 0) + 1
            if len(peer["signals"]) > 2048 or peer["signals"][attempt] > SIGNAL_ATTEMPT_LIMIT:
                raise ValueError("SIGNAL_LIMIT")
            others = [p for p in self.rooms[peer["room"]] if p is not peer]
            if others:
                await self.send(
                    others[0], {"type": "signal", "pair": peer["pair"], "from": peer["id"], "data": data}
                )
                self.log.event(
                    "signal.forward",
                    room=peer["room"],
                    peer=peer["id"],
                    attempt=attempt,
                    kind=data["kind"],
                    bytes=len(packed(data)),
                )
        elif kind == "reach":
            await self.inbound(peer, body)
        else:
            raise ValueError("UNKNOWN_MESSAGE_TYPE")

    def observed_mapping(self, token, remote):
        if self.forwarded:
            raise ValueError("TCP_OBSERVER_DISABLED_FOR_FORWARDED_SERVER")
        record = self.observation_tokens.get(token)
        if not record or record[1] < time.monotonic():
            raise ValueError("OBSERVATION_TOKEN_INVALID")
        peer = self.peers.get(record[0])
        if not peer or not remote or remote[0] != peer["source"]:
            raise ValueError("OBSERVATION_SOURCE_MISMATCH")
        ip = ipaddress.ip_address(remote[0])
        if not ip.is_global and not (self.allow_loopback and ip.is_loopback):
            raise ValueError("TCP_OBSERVER_NON_GLOBAL_SOURCE_NOT_A_PUBLIC_MAPPING")
        self.log.event("tcp.observation", room=peer["room"], peer=peer["id"], mapped=remote[:2])
        return {"mapped": remote[:2]}

    async def observe_http(self, request):
        try:
            if any(name in request.headers for name in ("Forwarded", "X-Forwarded-For", "X-Real-IP")):
                raise ValueError("TCP_OBSERVER_REQUIRES_DIRECT_CONNECTION")
            authorization = request.headers.get("Authorization", "")
            token = authorization.removeprefix("Bearer ") if authorization.startswith("Bearer ") else ""
            remote = request.transport.get_extra_info("peername")
            response = web.json_response(self.observed_mapping(token, remote))
            response.force_close()
            return response
        except ValueError as exc:
            self.log.event("tcp.observation_rejected", str(exc), "WARNING")
            raise web.HTTPForbidden(text=str(exc)) from None

    async def observe_tcp(self, reader, writer):
        try:
            request = json.loads(await asyncio.wait_for(reader.readline(), 3))
            token = request.get("token", "")
            remote = writer.get_extra_info("peername")
            writer.write(packed(self.observed_mapping(token, remote)) + b"\n")
            await writer.drain()
        except Exception as exc:
            self.log.exception("tcp.observation_failed", exc)
        finally:
            writer.close()
            await writer.wait_closed()

    async def inbound(self, peer, body):
        started = time.monotonic()
        family = 6
        result = {
            "type": "reach_result",
            "request": body.get("request"),
            "code": "REJECTED_BY_POLICY",
            "protocol": "http/tcp",
            "direction": "server-to-client",
            "scope": SCOPE,
        }
        try:
            host, port = endpoint(body["address"], body["port"])
            result.update(address=host, port=port)
            ip = ipaddress.ip_address(host)
            family = ip.version
            counter = "checks4" if ip.version == 4 else "checks"
            if not self.allow_inbound or peer.get(counter, 0) >= (1 if ip.version == 4 else 2):
                raise ValueError("INBOUND_DISABLED_OR_LIMIT")
            allowed_prefix = not self.inbound_prefixes or any(ip in prefix for prefix in self.inbound_prefixes)
            allowed = (
                ((ip.is_global and allowed_prefix) or (self.allow_loopback and ip.is_loopback))
                if ip.version == 6
                else (
                    host == peer["source"]
                    and not self.forwarded
                    and (ip.is_global or self.allow_loopback and ip.is_loopback)
                    and not ip.is_multicast
                    and not ip.is_unspecified
                    and (not ip.is_loopback or self.allow_loopback)
                )
            )
            if port < 1024 or not allowed:
                raise ValueError("INBOUND_TARGET_POLICY")
            now = time.monotonic()
            rates = self.reach_rates[peer["source"]]
            while rates and rates[0] < now - 60:
                rates.popleft()
            if len(rates) >= 8 or self.reach_active.locked():
                raise ValueError("INBOUND_SOURCE_OR_CONCURRENCY_LIMIT")
            request_id, token = body["request"], body["token"]
            if (
                not isinstance(request_id, str)
                or not 1 <= len(request_id) <= 64
                or not isinstance(token, str)
                or not token.isascii()
                or not 16 <= len(token) <= 128
                or request_id in peer["reach_requests"]
            ):
                raise ValueError("INBOUND_INVALID_OR_REPLAYED_REQUEST")
            # A session ID remains valid when a waiting client becomes paired mid-check.
            proof = Identity.verify(body["proof"], peer["public"])
            if proof != {
                "session": peer["id"],
                "address": host,
                "port": port,
                "request": body["request"],
                "token": body["token"],
            }:
                raise ValueError("INBOUND_PROOF_MISMATCH")
            peer[counter] = peer.get(counter, 0) + 1
            peer["reach_requests"].add(request_id)
            rates.append(now)
            self.log.event(
                f"ipv{ip.version}.inbound_started",
                f"Connecting directly to the client's temporary IPv{ip.version} HTTP listener",
                room=peer["room"],
                peer=peer["id"],
                address=host,
                port=port,
                request=request_id,
                protocol="http/tcp",
            )
            async with self.reach_active:
                connector = aiohttp.TCPConnector(
                    family=socket.AF_INET6 if ip.version == 6 else socket.AF_INET, limit=1
                )
                async with aiohttp.ClientSession(
                    connector=connector, trust_env=False, timeout=aiohttp.ClientTimeout(total=4)
                ) as session:
                    async with session.get(
                        f"http://{'[' + host + ']' if ip.version == 6 else host}:{port}/reach",
                        params={"token": body["token"]},
                        allow_redirects=False,
                    ) as response:
                        # Require echo evidence; an unrelated empty HTTP 204 is not sufficient.
                        result["code"] = (
                            "REACHABLE"
                            if response.status == 204
                            and hmac.compare_digest(response.headers.get("X-P2P-Token", ""), body["token"])
                            else "TOKEN_MISMATCH"
                        )
        except TimeoutError:
            result["code"] = "TIMEOUT_INCONCLUSIVE"
        except aiohttp.ClientConnectorError as exc:
            result["os_errno"] = exc.os_error.errno
            if exc.os_error.errno == errno.ENETUNREACH:
                result["code"] = "OBSERVER_NO_ROUTE"
            elif exc.os_error.errno == errno.EHOSTUNREACH:
                result["code"] = "OBSERVER_OR_DESTINATION_UNREACHABLE"
            elif exc.os_error.errno == errno.ECONNREFUSED:
                result["code"] = "CONNECTION_REFUSED"
            else:
                result["code"] = "CONNECT_FAILED"
        except Exception as exc:
            result["detail"] = type(exc).__name__ + ":" + str(exc)
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
        result["firewall_assessment"] = assessment(result["code"])
        result["message"] = message(result["code"]).replace("IPv6", f"IPv{family}")
        result["family"] = family
        self.log.event(f"ipv{family}.inbound", room=peer["room"], peer=peer["id"], **result)
        await self.send(peer, result)


async def serve(args):
    data = Path(args.data)
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    token_file = data / "admin.token"
    if not token_file.exists():
        with token_file.open("x") as f:
            token_file.chmod(0o600)
            f.write(secrets.token_urlsafe(32))
    journal = Journal(data / "central.sqlite3", role="server")
    journal.install()
    hub = Hub(
        journal,
        admin_token=token_file.read_text().strip(),
        access_token=Path(args.token_file).read_text().strip() if args.token_file else "",
        stun_port=args.stun_port,
        tcp_port=args.tcp_port,
        tcp_observer_protocol="http" if args.tcp_port == args.port else "raw",
        forwarded=args.forwarded,
        allow_inbound=args.allow_inbound_check,
        allow_loopback=args.allow_loopback_check,
    )
    hub.inbound_prefixes = [ipaddress.ip_network(prefix) for prefix in args.inbound_prefix]
    if args.public_port:
        if args.stun_port == args.port:
            hub.stun_port = args.public_port
        if args.tcp_port == args.port:
            hub.tcp_port = args.public_port
    runner, udp_transports, tcp = web.AppRunner(hub.app(), access_log=None), [], None
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass
    try:
        await runner.setup()
        context = None
        if args.cert or args.key:
            if not args.cert or not args.key:
                raise ValueError("BOTH_CERT_AND_KEY_REQUIRED")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(args.cert, args.key)
        await web.TCPSite(runner, args.host, args.port, ssl_context=context).start()
        sockets = {}
        points = [(args.stun_host or args.host, args.stun_port)]
        if args.stun_alt_ip:
            points = [
                (host, port)
                for host in (args.stun_host or args.host, args.stun_alt_ip)
                for port in (args.stun_port, args.stun_port + 1)
            ]
        for host, port in ([] if args.forwarded else points):
            alt = None
            if args.stun_alt_ip:
                alt = (
                    args.stun_alt_ip if host != args.stun_alt_ip else args.stun_host or args.host,
                    args.stun_port + 1 if port == args.stun_port else args.stun_port,
                )
            transport, _ = await loop.create_datagram_endpoint(
                lambda h=host, p=port, a=alt: StunServer(journal, sockets, (h, p), a),
                local_addr=(host, port),
                family=socket.AF_INET,
            )
            udp_transports.append(transport)
        if args.tcp_port != args.port and not args.forwarded:
            tcp = await asyncio.start_server(hub.observe_tcp, args.host, args.tcp_port, limit=4096)
        journal.event(
            "server.started",
            signaling=f"{'https' if context else 'http'}://{args.host}:{args.port}",
            stun=[] if args.forwarded else points,
            tcp_observer=None if args.forwarded else args.tcp_port,
            tcp_observer_protocol=hub.tcp_observer_protocol,
            shared_port=args.port == args.stun_port == args.tcp_port,
            observation_mode="forwarded" if args.forwarded else "direct",
            advertised_stun_port=hub.stun_port,
            advertised_tcp_port=hub.tcp_port,
            log_database=str(data / "central.sqlite3"),
            admin_token_file=str(token_file),
            inbound_check=args.allow_inbound_check,
            inbound_ipv6_policy="prefix-allowlist" if hub.inbound_prefixes else "any-global-ipv6",
            inbound_prefixes=[str(prefix) for prefix in hub.inbound_prefixes],
        )
        if args.forwarded:
            journal.event(
                "server.forwarded", "转发模式：本站 TCP/STUN 观察及 IPv4 回连禁用；信令、日志、IPv6 回连保留",
                "WARNING",
            )
        if not context and not ipaddress.ip_address(args.host).is_loopback:
            journal.event(
                "server.insecure",
                "Plain HTTP/WS is enabled without TLS or Nginx; clients need --allow-insecure. "
                "Signaling, addresses, tokens and diagnostics are exposed in transit.",
                "WARNING",
            )
        await stop.wait()
    finally:
        if tcp:
            tcp.close()
            await tcp.wait_closed()
        for transport in udp_transports:
            transport.close()
        for peer in tuple(hub.peers.values()):
            await peer["ws"].close(code=1001, message=b"SERVER_SHUTDOWN")
        await runner.cleanup()
        journal.event("server.stopped")
        journal.close()


def main():
    configure_console_encoding()
    parser = argparse.ArgumentParser(description="IPv4 rendezvous + STUN + persistent diagnostics; no relay")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--public-port", type=int, help="Advertised shared external port for source-preserving NAT")
    parser.add_argument("--forwarded", action="store_true",
                        help="socat/reverse-proxy signaling: disable invalid local TCP/STUN observations and IPv4 callbacks")
    parser.add_argument("--stun-host")
    parser.add_argument("--stun-port", type=int, help="UDP STUN port; defaults to --port")
    parser.add_argument("--stun-alt-ip", help="Second IPv4 on this host for complete RFC 5780 tests")
    parser.add_argument("--tcp-port", type=int, help="TCP observer port; defaults to the shared HTTP --port")
    parser.add_argument("--data", default="data/server")
    parser.add_argument("--cert")
    parser.add_argument("--key")
    parser.add_argument("--token-file")
    parser.add_argument("--allow-inbound-check", action="store_true")
    parser.add_argument("--allow-loopback-check", action="store_true", help="Local tests only")
    parser.add_argument(
        "--inbound-prefix",
        action="append",
        default=[],
        help="Optional global IPv6 callback prefix restriction; omit to allow any global IPv6; repeatable",
    )
    args = parser.parse_args()
    if args.stun_port is None:
        args.stun_port = args.port
    if args.tcp_port is None:
        args.tcp_port = args.port
    if not all(1 <= port <= 65535 for port in (args.port, args.stun_port, args.tcp_port)):
        parser.error("Ports must be between 1 and 65535")
    if args.public_port is not None and not 1 <= args.public_port <= 65535:
        parser.error("--public-port must be between 1 and 65535")
    if args.public_port is not None and args.stun_alt_ip:
        parser.error("--public-port cannot describe the alternate IP/port topology of --stun-alt-ip")
    if args.stun_alt_ip and args.stun_port == 65535:
        parser.error("--stun-alt-ip needs an alternate UDP port below 65536")
    if args.stun_alt_ip and (not args.stun_host or ipaddress.ip_address(args.stun_host).is_unspecified):
        parser.error("--stun-alt-ip requires an explicit non-wildcard --stun-host")
    try:
        asyncio.run(serve(args))
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
