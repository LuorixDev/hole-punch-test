"""Real server/two-client chat soak with optional isolated netem and headless TUI."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import json
import os
import resource
import sys
import time
from pathlib import Path

from p2plab.client import Client
from p2plab.journal import Journal
from tools.performance_lab import publish, read_when_ready
from tools.smoke_frozen import free_shared_port


def summary(values):
    values = sorted(values)
    if not values:
        return {"count": 0}
    return {"count": len(values), "p50": values[len(values) // 2],
            "p95": values[min(len(values) - 1, int(len(values) * 0.95))], "max": values[-1]}


async def worker(args):
    from p2plab.tui import HistoryLog, P2PApp

    config = {
        "server": args.server, "allow_insecure": True,
        "data_dir": str(args.data / args.role), "name": args.role, "loopback": True,
        "experiment": {"stun": [], "diagnostics": False, "gateway": False,
                       "timeout": 1, "profiles": ["fast"], "max_pairs": 2,
                       "port_prediction": False, "comprehensive": args.research},
    }
    client = Client(config, "chat-latency-lab", console=False)
    samples, timings, errors = [], [], []
    phase, flush_enabled = "startup", True
    original_event = client.log.event
    original_flush = HistoryLog.flush_history
    original_refresh = P2PApp.refresh_state

    def event(*a, **kw):
        started = time.monotonic()
        try:
            return original_event(*a, **kw)
        finally:
            timings.append((phase, "journal_ms", (time.monotonic() - started) * 1000))

    def flush(widget):
        if not flush_enabled:
            return
        started = time.monotonic()
        try:
            return original_flush(widget)
        finally:
            timings.append((phase, "flush_ms", (time.monotonic() - started) * 1000))

    def refresh(app):
        started = time.monotonic()
        try:
            return original_refresh(app)
        finally:
            timings.append((phase, "refresh_ms", (time.monotonic() - started) * 1000))

    client.log.event = event
    HistoryLog.flush_history, P2PApp.refresh_state = flush, refresh
    app = P2PApp(client=client)
    running, pressure = True, False

    async def monitor():
        while running:
            started = time.monotonic()
            await asyncio.sleep(0.01)
            timings.append((phase, "loop_lag_ms", max(0, time.monotonic() - started - 0.01) * 1000))

    async def log_pressure():
        index = 0
        while running:
            if pressure:
                # Synthetic socket-error-shaped records, all persisted and uploaded.
                client.log.event("lab.synthetic_socket_error", "Synthetic log pressure", "WARNING",
                                 attempt="lab-pressure", errno=1231, index=index,
                                 source=["127.0.0.1", 42000], target=["127.0.0.1", 43000])
                index += 1
            await asyncio.sleep(1 / args.log_rate)

    async def chat_load():
        serial = 0
        if args.role == "b":
            await asyncio.sleep(0.25)
        while running:
            if phase not in ("startup", "history_seed", "waiting"):
                sent, label = time.monotonic(), phase
                text = json.dumps({"lab": True, "phase": label, "sent": sent, "serial": serial})
                record = {"phase": label, "serial": serial, "sent": sent,
                          "attempt": client.active_path.attempt if client.active_path else None}
                try:
                    receipt = await client.chat(text)
                    record.update(ack_ms=(time.monotonic() - sent) * 1000, receipt=receipt)
                except Exception as exc:
                    record.update(error=repr(exc), ack_ms=(time.monotonic() - sent) * 1000)
                    errors.append({"phase": label, "error": repr(exc)})
                samples.append(record)
                serial += 1
            await asyncio.sleep(args.chat_interval)

    def received(name, text, metrics=None):
        app.receive_chat(name, text, metrics)
        packet = json.loads(text)
        record = {"phase": packet["phase"], "received": True, "serial": packet["serial"],
                  "sent": packet["sent"], "display_ms": (time.monotonic() - packet["sent"]) * 1000}
        samples.append(record)
        app.call_after_refresh(lambda: record.update(render_ms=(time.monotonic() - packet["sent"]) * 1000))

    def seed_history():
        history = Journal(client.data / "client.sqlite3", role="client", room=client.room, console=False)
        try:
            for index in range(args.history_rows):
                history.event("lab.previous_run", index=index)
        finally:
            history.close()

    tasks = []
    try:
        async with app.run_test(size=(140, 40)):
            client.chat_display = received
            tasks = [asyncio.create_task(monitor()), asyncio.create_task(log_pressure()),
                     asyncio.create_task(chat_load())]
            async with asyncio.timeout(90):
                while not (client.active_path and client.active_path.ready.is_set()):
                    if client.closed:
                        raise RuntimeError("Client backend closed before connecting")
                    await asyncio.sleep(0.1)
            if args.transport != "auto":
                async with asyncio.timeout(90):
                    if args.role == "a":
                        while True:
                            path = next((p for p in client.paths if p.mechanism == args.transport
                                         and p.ready.is_set() and not p.closed and client.can_reopen(p)), None)
                            if path:
                                await client.command(f"/use {client.paths.index(path)}")
                                # /use may replace a just-parked path with a rebuilt instance.
                                publish(args.data / "selected.json", {"attempt": client.active_path.attempt})
                                break
                            await asyncio.sleep(0.05)
                    else:
                        selected = await read_when_ready(args.data / "selected.json", 90)
                        while not (client.active_path and client.active_path.attempt == selected["attempt"]):
                            await asyncio.sleep(0.05)
            publish(args.data / (args.role + "-ready.json"), {"pid": os.getpid()})
            await read_when_ready(args.data / "go.json", 90)
            phase_reports = []

            async def run_phase(label, *, logs=False, render=True):
                nonlocal phase, pressure, flush_enabled
                phase, pressure, flush_enabled = label, logs, render
                started, cpu = time.monotonic(), time.process_time()
                status = {"role": args.role, "phase": label, "started": started}
                publish(args.data / (args.role + "-phase.json"), status)
                print(json.dumps(status), file=sys.__stdout__, flush=True)
                await asyncio.sleep(args.phase_seconds)
                phase_reports.append({"phase": label, "wall_seconds": time.monotonic() - started,
                                      "cpu_seconds": time.process_time() - cpu,
                                      "rows": app.reader.stats()["total"],
                                      "activity_entries": len(app.query_ui("#activity", HistoryLog).history),
                                      "matrix_done": len(client.manager.results),
                                      "matrix_total": len(client.manager.plan),
                                      "paths": len(client.paths),
                                      "active_mechanism": client.active_path.mechanism if client.active_path else None,
                                      "rss_peak_kib": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss})

            await run_phase("matrix")
            phase = "waiting"
            async with asyncio.timeout(600):
                while client.experiment_matrix_running():
                    await asyncio.sleep(0.25)
            await run_phase("idle")
            phase = "history_seed"
            await asyncio.to_thread(seed_history)
            await run_phase("history")
            await run_phase("pressure_warm", logs=True)
            await run_phase("pressure_full", logs=True)
            await run_phase("pressure_no_flush", logs=True, render=False)
            await run_phase("pressure_restored", logs=True)
            phase, pressure = "finished", False
            running = False
            # Finish in-flight chats before either backend closes its data path.
            await asyncio.wait_for(tasks[2], 15)
            for task in tasks[:2]:
                task.cancel()
            await asyncio.gather(*tasks[:2], return_exceptions=True)
            publish(args.data / (args.role + "-drained.json"), True)
            await read_when_ready(args.data / (("b" if args.role == "a" else "a") + "-drained.json"), 20)
            phases = [row["phase"] for row in phase_reports]
            report = {
                "role": args.role, "config": config, "phases": phase_reports,
                "samples": samples, "errors": errors,
                "metrics_ms": {
                    label: {
                        **{kind: summary([value for p, k, value in timings if p == label and k == kind])
                           for kind in ("loop_lag_ms", "journal_ms", "flush_ms", "refresh_ms")},
                        **{kind: summary([row[kind] for row in samples if row["phase"] == label and kind in row])
                           for kind in ("display_ms", "render_ms", "ack_ms")},
                    } for label in phases
                },
            }
            publish(args.data / (args.role + "-report.json"), report)
            client.stop.set()
            if app.backend_task:
                await asyncio.wait_for(app.backend_task, 20)
    finally:
        running = False
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        HistoryLog.flush_history, P2PApp.refresh_state = original_flush, original_refresh
        if not client.closed:
            await client.close()


async def run(args):
    if args.netem_ms and not args.isolated_from:
        command = [sys.executable, "-m", "tools.chat_latency_lab", *sys.argv[1:],
                   "--isolated-from", os.readlink("/proc/self/ns/net")]
        process = await asyncio.create_subprocess_exec("unshare", "-Urn", *command)
        try:
            if await process.wait():
                raise RuntimeError("Isolated lab failed")
        finally:
            if process.returncode is None:
                process.terminate()
                await process.wait()
        return
    args.data.mkdir(parents=True, exist_ok=False)
    if args.netem_ms:
        # Caller must enter a fresh namespace; never alter the desktop host network.
        if os.readlink("/proc/self/ns/net") == args.isolated_from:
            raise RuntimeError("--netem-ms requires unshare -Urn")
        for command in (("ip", "link", "set", "lo", "up"),
                        ("tc", "qdisc", "add", "dev", "lo", "root", "netem",
                         "delay", str(args.netem_ms) + "ms", "limit", "10000")):
            process = await asyncio.create_subprocess_exec(*command)
            if await process.wait():
                raise RuntimeError("Namespace network setup failed")
    port = free_shared_port()
    server_url = f"ws://127.0.0.1:{port}/ws"
    processes, pumps = [], []

    async def pump(name, process):
        with (args.data / (name + ".stdout")).open("wb") as output:
            while line := await process.stdout.readline():
                output.write(line)
                output.flush()
                if name != "server":
                    print(line.decode(errors="replace").rstrip(), flush=True)

    async def spawn(name, *command):
        process = await asyncio.create_subprocess_exec(
            *command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT)
        processes.append(process)
        pumps.append(asyncio.create_task(pump(name, process)))
        return process

    try:
        server = await spawn("server", sys.executable, "server.py", "--host", "0.0.0.0", "--port", str(port),
                             "--allow-inbound-check", "--allow-loopback-check", "--data", str(args.data / "server"))
        async with asyncio.timeout(20):
            while True:
                if server.returncode is not None:
                    raise RuntimeError("Server failed; inspect server.stdout")
                try:
                    _, writer = await asyncio.open_connection("127.0.0.1", port)
                except OSError:
                    await asyncio.sleep(0.1)
                else:
                    writer.close()
                    await writer.wait_closed()
                    break
        for role in ("a", "b"):
            await spawn(role, sys.executable, "-m", "tools.chat_latency_lab", "--role", role,
                        "--server", server_url, "--data", str(args.data),
                        "--phase-seconds", str(args.phase_seconds), "--log-rate", str(args.log_rate),
                        "--chat-interval", str(args.chat_interval), "--history-rows", str(args.history_rows),
                        "--transport", args.transport,
                        *(["--research"] if args.research else []))
        async with asyncio.timeout(90):
            while not all((args.data / (role + "-ready.json")).exists() for role in ("a", "b")):
                if any(process.returncode is not None for process in processes):
                    raise RuntimeError("Worker failed; inspect worker stdout")
                await asyncio.sleep(0.1)
        publish(args.data / "go.json", {"started": time.monotonic()})
        async with asyncio.timeout(1200):
            while any(process.returncode is None for process in processes[1:]):
                if any(process.returncode not in (None, 0) for process in processes):
                    raise RuntimeError("Worker failed; inspect worker stdout")
                await asyncio.sleep(0.5)
        if any(process.returncode != 0 for process in processes[1:]):
            raise RuntimeError("Worker exited unsuccessfully")
        reports = [json.loads((args.data / (role + "-report.json")).read_text()) for role in ("a", "b")]
        publish(args.data / "report.json", {"netem_egress_ms": args.netem_ms, "headless_tui": True,
                                           "synthetic_log_rate_per_client": args.log_rate, "workers": reports})
        for report in reports:
            for phase, metrics in report["metrics_ms"].items():
                print(json.dumps({"role": report["role"], "phase": phase,
                                  "ack_p95_ms": metrics["ack_ms"].get("p95"),
                                  "display_p95_ms": metrics["display_ms"].get("p95"),
                                  "flush_p95_ms": metrics["flush_ms"].get("p95")}), flush=True)
    finally:
        for process in processes:
            if process.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    process.terminate()
        for process in processes:
            try:
                await asyncio.wait_for(process.wait(), 15)
            except TimeoutError:
                process.kill()
                await process.wait()
        await asyncio.gather(*pumps, return_exceptions=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, required=True)
    parser.add_argument("--role", choices=("a", "b"))
    parser.add_argument("--server")
    parser.add_argument("--phase-seconds", type=float, default=30)
    parser.add_argument("--chat-interval", type=float, default=0.5)
    parser.add_argument("--log-rate", type=float, default=40)
    parser.add_argument("--history-rows", type=int, default=20000)
    parser.add_argument("--netem-ms", type=float, default=0)
    parser.add_argument("--isolated-from", help=argparse.SUPPRESS)
    parser.add_argument("--research", action="store_true")
    parser.add_argument("--transport", choices=("auto", "tcp", "quic"), default="auto")
    args = parser.parse_args()
    if args.phase_seconds <= 0 or args.chat_interval <= 0 or args.log_rate <= 0 or args.history_rows < 0:
        parser.error("Durations/rate must be positive and history rows nonnegative")
    asyncio.run(worker(args) if args.role else run(args))


if __name__ == "__main__":
    main()
