"""Replay retained matrix metadata in a headless TUI, without opening peer sockets."""

from __future__ import annotations

import argparse
import asyncio
import collections
import hashlib
import json
import sqlite3
import statistics
import tempfile
import time
from pathlib import Path as FilePath
from types import SimpleNamespace

from rich.text import Text

from p2plab.client import Client
from p2plab.logcodec import load_document
from p2plab.session import Path
from p2plab.tui import HistoryLog, P2PApp


def metadata(database, client_prefix):
    with sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True) as db:
        rows = [load_document(d) for d, in db.execute("SELECT document FROM events ORDER BY seq")]
    groups = collections.defaultdict(list)
    for row in rows:
        if row["event"] == "journal.fragment":
            groups[row["fields"]["original_id"]].append(row)
    for parts in groups.values():
        parts.sort(key=lambda r: r["fields"]["index"])
        if [r["fields"]["index"] for r in parts] == list(range(parts[0]["fields"]["parts"])):
            rows.append(json.loads("".join(r["fields"]["json_part"] for r in parts)))
    completed = next(r for r in rows if r["event"] == "experiment.completed"
                     and r["client"].startswith(client_prefix))
    plan = next(r["fields"]["plan"] for r in rows if r["event"] == "experiment.plan"
                and r["client"] == completed["client"] and r["run"] == completed["run"])
    rtts = {r["fields"]["attempt"]: r["fields"]["rtt_ms"] for r in rows
            if r["event"] == "path.verified" and r["client"] == completed["client"]}
    return plan, completed["fields"]["results"], rtts


async def run(args):
    plan, results, rtts = metadata(args.database, args.client_prefix)

    async def noop(*unused):
        pass

    with tempfile.TemporaryDirectory() as directory:
        client = Client({"server": "ws://127.0.0.1:1/ws", "data_dir": directory, "loopback": True,
                         "experiment": {"diagnostics": False, "gateway": False, "stun": []}},
                        "ui-replay", console=False)
        client.peer = {}
        done = asyncio.get_running_loop().create_future()
        done.set_result(None)
        manager = SimpleNamespace(plan=plan, results=results, remote_done={r["attempt"]: r for r in results},
                                  task=done)
        client.manager, client.managers = manager, [manager]
        for row in results:
            if not row.get("data_path"):
                continue
            host = row.get("parameters", {}).get("host") or row.get("parameters", {}).get("a_host") or ""
            path = Path(client, row["attempt"], row["method"], 6 if ":" in host else 4, noop, noop)
            path.ready.set()
            path.closed = True
            path.last_rtt, path.rtt_state = rtts.get(row["attempt"], 50), "measured"
            path.rtt_measured_at = time.monotonic() - 3600
            client.paths.append(path)
        app = P2PApp(client=client, start_backend=False)
        report = {"scope": "metadata-replay-only-no-network-throughput-evidence",
                  "sha256": hashlib.sha256(args.database.read_bytes()).hexdigest(),
                  "plans": len(plan), "paths": len(client.paths), "tabs": {}}
        try:
            async with app.run_test(size=(160, 48)) as pilot:
                history = app.query_one("#activity", HistoryLog)
                for i in range(1000):
                    history.append_entry(Text(f"{i} retained log\nmethod and outcome\n"))
                for tab in ("chat", "paths", "matrix"):
                    app.action_tab(tab)
                    await pilot.pause(0.2)
                    durations = []
                    for _ in range(args.iterations):
                        started = time.perf_counter()
                        app.refresh_state()
                        durations.append((time.perf_counter() - started) * 1000)
                        await pilot.pause(0.12)
                    report["tabs"][tab] = {"refresh_ms": durations, "median_ms": statistics.median(durations)}
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(json.dumps(report, indent=2))
            print(json.dumps(report))
        finally:
            client.identity.close()
            client.log.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=FilePath, required=True)
    parser.add_argument("--client-prefix", required=True)
    parser.add_argument("--output", type=FilePath, required=True)
    parser.add_argument("--iterations", type=int, default=8)
    args = parser.parse_args()
    if not 1 <= args.iterations <= 100:
        parser.error("iterations must be in [1, 100]")
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
