"""Gigabit/latency shaping in disposable namespaces; never modify the host network."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def controller(args):
    if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == args.host_netns:
        raise RuntimeError("ISOLATED_USER_AND_NETWORK_NAMESPACE_REQUIRED")
    keepers = []

    def command(values, pid=None):
        prefix = ["nsenter", "-t", str(pid), "-n"] if pid else []
        return subprocess.run(
            [*prefix, *map(str, values)], check=True, capture_output=True, timeout=10
        ).stdout.decode()

    try:
        for _ in range(2):
            keeper = subprocess.Popen(["unshare", "-n", "sleep", "3600"])
            keepers.append(keeper)
            deadline = time.monotonic() + 5
            while os.readlink(f"/proc/{keeper.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                if keeper.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("PERFORMANCE_NAMESPACE_NOT_READY")
                time.sleep(0.01)
        command(["ip", "link", "add", "perf-a", "type", "veth", "peer", "name", "perf-b"])
        for index, keeper in enumerate(keepers):
            name = "perf-a" if index == 0 else "perf-b"
            command(["ip", "link", "set", name, "netns", keeper.pid])
            command(["ip", "link", "set", "lo", "up"], keeper.pid)
            command(["ip", "link", "set", name, "mtu", "1500", "up"], keeper.pid)
            command(["ip", "address", "add", f"10.202.0.{index + 1}/24", "dev", name], keeper.pid)
            command(
                [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    name,
                    "root",
                    "netem",
                    "limit",
                    str(args.queue_packets),
                    "delay",
                    f"{args.delay_ms}ms",
                    "rate",
                    f"{args.rate_mbps}mbit",
                    "loss", f"{args.loss_percent}%",
                ],
                keeper.pid,
            )
            if args.tcp_buffer_mib:
                maximum = args.tcp_buffer_mib * 1024 * 1024
                command(["sysctl", "-q", "-w", f"net.ipv4.tcp_rmem=4096 262144 {maximum}"], keeper.pid)
                command(["sysctl", "-q", "-w", f"net.ipv4.tcp_wmem=4096 262144 {maximum}"], keeper.pid)
        args.data.mkdir(parents=True, exist_ok=True)
        (args.data / "topology.json").write_text(
            json.dumps(
                {
                    "evidence": "isolated-veth-not-a-physical-gigabit-interface",
                    "rate_mbps": args.rate_mbps,
                    "one_way_delay_ms": args.delay_ms,
                    "mtu": 1500,
                    "loss_percent": args.loss_percent,
                    "queue_packets": args.queue_packets,
                    "host_network_modified": False,
                    "tcp_buffers": command(
                        ["sysctl", "net.ipv4.tcp_rmem", "net.ipv4.tcp_wmem"], keepers[0].pid
                    ),
                },
                indent=2,
            )
        )
        benchmark_command = [
            sys.executable,
            str(Path(__file__).with_name("performance_lab.py")),
            "--data",
            str(args.data),
            "--transport",
            args.transport,
            "--size",
            str(args.size),
            "--runs",
            str(args.runs),
            "--quic-timer", args.quic_timer,
            "--quic-datagram-size", str(args.quic_datagram_size),
            "--quic-cc", args.quic_cc,
            "--direction-order", args.direction_order,
            "--reference-mbps", str(args.rate_mbps),
            "--cancel-after", str(args.cancel_after),
            *(["--probe-recovery"] if args.probe_recovery else []),
            "--hosts",
            "10.202.0.1",
            "10.202.0.2",
            "--namespace-pids",
            *[str(k.pid) for k in keepers],
        ]
        subprocess.run(benchmark_command, check=True)
    finally:
        for keeper in keepers:
            if keeper.poll() is None:
                keeper.terminate()
        for keeper in keepers:
            keeper.wait(timeout=10)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("data/verification/performance-gigabit"))
    parser.add_argument("--transport", choices=("all", "tcp", "quic", "webrtc", "utp"), default="tcp")
    parser.add_argument("--size", type=int, choices=range(1, 1025), default=256)
    parser.add_argument("--runs", type=int, choices=range(1, 11), default=3)
    parser.add_argument("--delay-ms", type=int, choices=range(0, 101), default=25)
    parser.add_argument("--rate-mbps", type=float, default=1000)
    parser.add_argument("--queue-packets", type=int, default=20000)
    parser.add_argument("--probe-recovery", action="store_true")
    parser.add_argument("--cancel-after", type=float, default=0)
    parser.add_argument("--tcp-buffer-mib", type=int, choices=(0, 32), default=0)
    parser.add_argument("--quic-timer", choices=("precise", "asyncio"), default="precise")
    parser.add_argument("--quic-datagram-size", type=int, choices=(1200, 1400), default=1200)
    parser.add_argument("--quic-cc", choices=("reno", "cubic"), default="reno")
    parser.add_argument("--direction-order", choices=("forward-first", "reverse-first"),
                        default="forward-first")
    parser.add_argument("--loss-percent", type=float, default=0)
    parser.add_argument("--host-netns", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if not 0 <= args.loss_percent <= 10:
        parser.error("loss-percent must be between 0 and 10")
    if not 0.01 <= args.rate_mbps <= 10000 or not 16 <= args.queue_packets <= 20000:
        parser.error("invalid rate or queue size")
    if not 0 <= args.cancel_after <= 120 or (args.cancel_after and not args.probe_recovery):
        parser.error("--cancel-after requires --probe-recovery and a delay in [0, 120]")
    if args.host_netns:
        controller(args)
    else:
        command = [
            "unshare",
            "-Urn",
            sys.executable,
            str(Path(__file__).resolve()),
            "--host-netns",
            os.readlink("/proc/self/ns/net"),
            "--data",
            str(args.data.resolve()),
            "--transport",
            args.transport,
            "--size",
            str(args.size),
            "--runs",
            str(args.runs),
            "--delay-ms",
            str(args.delay_ms),
            "--rate-mbps",
            str(args.rate_mbps),
            "--queue-packets", str(args.queue_packets),
            "--cancel-after", str(args.cancel_after),
            *(["--probe-recovery"] if args.probe_recovery else []),
            "--tcp-buffer-mib",
            str(args.tcp_buffer_mib),
            "--quic-timer", args.quic_timer,
            "--quic-datagram-size", str(args.quic_datagram_size),
            "--quic-cc", args.quic_cc,
            "--direction-order", args.direction_order,
            "--loss-percent", str(args.loss_percent),
        ]
        result = subprocess.run(command)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
