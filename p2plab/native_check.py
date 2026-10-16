"""Loopback acceptance test, also executed inside the frozen client."""

import asyncio
import json
import secrets
import tempfile
from pathlib import Path

from .native_ice import NativeIceAttempt
from .native_utp import UtpAttempt


async def check_native(report):
    from .client import Client

    results, errors = [], []
    loop = asyncio.get_running_loop()
    previous_handler = loop.get_exception_handler()
    loop.set_exception_handler(lambda loop, context: errors.append(str(context)))
    try:
        with tempfile.TemporaryDirectory(prefix="p2plab-native-") as temporary:
            directory = Path(temporary)
            for method in ("ice-native", "ice-tcp", "utp"):
                for host in ("127.0.0.1", "::1"):
                    label = method + ("-v6" if ":" in host else "-v4")
                    config = {"loopback": True, "experiment": {"timeout": 3, "stun": [],
                              "gateway": False, "diagnostics": False}}
                    peers = [Client({**config, "data_dir": str(directory / label / name)},
                                    "native-check", console=False) for name in ("a", "b")]
                    attempts = []
                    try:
                        a, b = peers
                        a.peer_id, b.peer_id = secrets.token_hex(16), secrets.token_hex(16)
                        a.pair = b.pair = secrets.token_hex(8)
                        for local, remote in ((a, b), (b, a)):
                            local.peer = {"id": remote.peer_id, "name": "peer",
                                          "public": remote.identity.public,
                                          "certificate": remote.identity.cert_pem}
                        aid = secrets.token_hex(8)
                        for index, owner in enumerate(peers):
                            spec = {"attempt": aid, "method": method, "profile": "6" if ":" in host else "4",
                                    "initiator": index == 0, "tls_client": index == 0, "host": host}
                            if method == "utp":
                                spec["profile"] = "fast"
                            attempts.append(UtpAttempt(owner, spec, host) if method == "utp" else
                                            NativeIceAttempt(owner, spec))
                        left, right = attempts
                        if method != "utp":
                            a.signal, b.signal = right.handle, left.handle
                        async with asyncio.timeout(60):
                            if method == "utp":
                                await asyncio.gather(left.open(), right.open())
                                left.set_candidates(right.candidates)
                                right.set_candidates(left.candidates)
                                await asyncio.gather(left.punch(2), right.punch(2))
                                pa, pb = await asyncio.gather(left.connect_stream(), right.connect_stream())
                            else:
                                pa, pb = await asyncio.gather(left.connect(), right.connect())
                            await a.chat("native backend check")
                            rtt = await pa.ping()
                            source = directory / label / "payload.bin"
                            source.write_bytes(bytes(range(256)) * 4096)
                            transfer = await a.transfers.send(pa, source)
                            received = list((directory / label / "b/downloads").glob("*.bin"))
                            if len(received) != 1 or received[0].read_bytes() != source.read_bytes():
                                raise RuntimeError("NATIVE_FILE_CONTENT_MISMATCH")
                            speeds = [await path.speed(1024 * 1024) for path in (pa, pb)]
                            if any(row["bytes"] != 1024 * 1024 or row["mbps"] <= 0 for row in speeds):
                                raise RuntimeError("NATIVE_SPEED_INVALID")
                            results.append({"method": method, "host": host, "chat": True, "rtt_ms": rtt,
                                            "file_bytes": transfer["bytes"],
                                            "mbps": [row["mbps"] for row in speeds]})
                    finally:
                        for owner in peers:
                            await owner.close()
                        for attempt in attempts:
                            await attempt.close()
                        await asyncio.sleep(0)
        if errors:
            raise RuntimeError("NATIVE_BACKGROUND_ERRORS:" + repr(errors))
        evidence = {"state": "passed", "cases": results, "background_errors": errors,
                    "scope": "IPv4/IPv6 loopback; not WAN performance acceptance"}
        Path(report).write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        return evidence
    finally:
        loop.set_exception_handler(previous_handler)
