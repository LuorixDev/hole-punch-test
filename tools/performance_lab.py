"""Measure real encrypted transports in two local Python processes, without a relay."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import resource
import secrets
import sys
import time
import uuid
from pathlib import Path

from p2plab.client import Client
from p2plab.performance import bottleneck_assessment
from p2plab.rtc import RtcAttempt
from p2plab.tcp import TcpAttempt
from p2plab.udp import UdpAttempt


def publish(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


async def read_when_ready(path, timeout=30):
    async with asyncio.timeout(timeout):
        while not path.exists():
            await asyncio.sleep(0.01)
    return json.loads(path.read_text())


async def worker(args):
    root, role = args.data, args.role
    other = "b" if role == "a" else "a"
    client = Client(
        {
            "data_dir": str(root / role),
            "loopback": True,
            "experiment": {"stun": [], "diagnostics": False, "gateway": False, "timeout": 5},
        },
        "performance-lab",
        console=False,
    )
    client.peer_id = str(uuid.uuid5(uuid.NAMESPACE_URL, str(root) + role))
    client.pair = str(uuid.uuid5(uuid.NAMESPACE_URL, str(root)))
    publish(
        root / (role + "-identity.json"),
        {
            "id": client.peer_id,
            "name": role,
            "public": client.identity.public,
            "certificate": client.identity.cert_pem,
        },
    )
    obj, signal_task = None, None
    lag, measuring = [], True

    async def monitor():
        while measuring:
            started = time.monotonic()
            await asyncio.sleep(0.01)
            lag.append(max(0, time.monotonic() - started - 0.01) * 1000)

    monitor_task = asyncio.create_task(monitor())
    try:
        client.peer = await read_when_ready(root / (other + "-identity.json"))
        spec = {
            "attempt": "performance-" + args.transport,
            "method": args.transport,
            "profile": "4" if args.transport == "webrtc" else "fast",
            "host": args.hosts[0 if role == "a" else 1],
            "initiator": role == "a",
            "tls_client": role == "a",
            "quic_precise_timer": args.quic_timer == "precise",
            "quic_congestion_control": args.quic_cc,
        }
        if args.transport == "tcp":
            obj = TcpAttempt(client, spec, spec["host"])
            await obj.prepare()
        elif args.transport == "quic":
            obj = UdpAttempt(client, spec, spec["host"])
            await obj.open()
        else:
            obj = RtcAttempt(client, spec)

            async def signal(data):
                publish(root / (role + "-" + data["kind"] + ".json"), data)

            async def receive_signal():
                kind = "answer" if role == "a" else "offer"
                await obj.handle(await read_when_ready(root / (other + "-" + kind + ".json")))

            client.signal = signal
            signal_task = asyncio.create_task(receive_signal())
        if args.transport != "webrtc":
            publish(root / (role + "-candidates.json"), obj.candidates)
            obj.set_candidates(await read_when_ready(root / (other + "-candidates.json")))
        if args.transport == "quic":
            await obj.punch(5)
            path = await obj.start_quic(size=args.quic_datagram_size)
        else:
            path = await obj.connect()
        if args.legacy and hasattr(path, "remote_capabilities"):
            path.remote_capabilities.discard("bench-binary-v1")
        publish(root / (role + "-connected.json"), True)
        await read_when_ready(root / (other + "-connected.json"))
        lag.clear()
        cpu_started, wall_started = time.process_time(), time.monotonic()
        measurements = []
        if role == "a":
            for _ in range(args.runs):
                for direction in ("local-to-peer", "peer-to-local"):
                    result = await (
                        path.speed(args.size * 1024 * 1024)
                        if direction == "local-to-peer"
                        else path.reverse_speed(args.size * 1024 * 1024)
                    )
                    client.log.event("speed.result", direction=direction, **result)
                    reference = {"mbps": args.reference_mbps, "basis": "configured",
                                 "scope": "explicit-lab-reference-not-WAN"} if args.reference_mbps else None
                    measurements.append({"direction": direction, **result,
                                         "bottleneck": bottleneck_assessment(result, reference)})
            publish(root / "finished.json", True)
        else:
            await read_when_ready(root / "finished.json", 900)
        elapsed, cpu = time.monotonic() - wall_started, time.process_time() - cpu_started
        report = {
            "role": role,
            "transport": args.transport,
            "legacy": args.legacy,
            "size_mib": args.size,
            "runs": args.runs,
            "quic_timer": args.quic_timer,
            "quic_datagram_size": args.quic_datagram_size,
            "quic_cc": args.quic_cc,
            "reference_mbps": args.reference_mbps,
            "measurements": measurements,
            "wall_seconds": elapsed,
            "process_cpu_seconds": cpu,
            "process_core_utilization": cpu / elapsed,
            "event_loop_lag_p95_ms": sorted(lag)[int(len(lag) * 0.95)] if lag else 0,
            "rss_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss,
        }
        publish(root / (role + "-report.json"), report)
        await read_when_ready(root / (other + "-report.json"))
    finally:
        measuring = False
        monitor_task.cancel()
        if signal_task:
            signal_task.cancel()
        await asyncio.gather(monitor_task, *([signal_task] if signal_task else []), return_exceptions=True)
        for path in client.paths:
            await path.close("PERFORMANCE_LAB_DONE")
        if obj:
            await obj.close()
        await asyncio.gather(*client.tasks, return_exceptions=True)
        client.identity.close()
        client.log.close()


async def run(args):
    args.data.mkdir(parents=True, exist_ok=True)
    reports = []
    methods = ("tcp", "quic", "webrtc") if args.transport == "all" else (args.transport,)
    for method in methods:
        directory = args.data / (method + "-" + secrets.token_hex(4))
        directory.mkdir()
        processes = []
        try:
            for role in ("a", "b"):
                command = [
                    sys.executable,
                    str(Path(__file__).resolve()),
                    "--role",
                    role,
                    "--data",
                    str(directory),
                    "--transport",
                    method,
                    "--size",
                    str(args.size),
                    "--runs",
                    str(args.runs),
                    "--hosts",
                    *args.hosts,
                    "--quic-timer", args.quic_timer,
                    "--quic-datagram-size", str(args.quic_datagram_size),
                    "--quic-cc", args.quic_cc,
                    "--reference-mbps", str(args.reference_mbps),
                ] + (["--legacy"] if args.legacy else [])
                if args.namespace_pids:
                    pid = args.namespace_pids[0 if role == "a" else 1]
                    if os.readlink(f"/proc/{pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                        raise RuntimeError("PERFORMANCE_WORKER_MUST_BE_ISOLATED")
                    command = ["nsenter", "-t", str(pid), "-n", *command]
                processes.append(
                    await asyncio.create_subprocess_exec(
                        *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                    )
                )
            async with asyncio.timeout(900):
                outputs = await asyncio.gather(*(p.communicate() for p in processes))
            for process, (out, err) in zip(processes, outputs):
                if process.returncode:
                    raise RuntimeError(out.decode() + err.decode())
            records = [json.loads((directory / (r + "-report.json")).read_text()) for r in ("a", "b")]
            reports.append({"transport": method, "processes": records, "data_dir": str(directory)})
            print(json.dumps(reports[-1], ensure_ascii=False), flush=True)
        finally:
            for process in processes:
                if process.returncode is None:
                    process.terminate()
            await asyncio.gather(*(p.wait() for p in processes))
    publish(args.data / ("legacy-summary.json" if args.legacy else "summary.json"), reports)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--transport", choices=("all", "tcp", "quic", "webrtc"), default="all")
    parser.add_argument("--data", type=Path, default=Path("data/verification/performance"))
    parser.add_argument("--size", type=int, choices=range(1, 1025), default=64)
    parser.add_argument("--runs", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--legacy", action="store_true")
    parser.add_argument("--quic-timer", choices=("precise", "asyncio"), default="precise")
    parser.add_argument("--quic-datagram-size", type=int, choices=(1200, 1400), default=1200)
    parser.add_argument("--quic-cc", choices=("reno", "cubic"), default="reno")
    parser.add_argument("--reference-mbps", type=int, choices=range(0, 10001), default=0)
    parser.add_argument("--hosts", nargs=2, default=["127.0.0.1", "127.0.0.1"])
    parser.add_argument("--namespace-pids", type=int, nargs=2, help=argparse.SUPPRESS)
    parser.add_argument("--role", choices=("a", "b"), help=argparse.SUPPRESS)
    args = parser.parse_args()
    asyncio.run(worker(args) if args.role else run(args))


if __name__ == "__main__":
    main()
