"""Black-box two-peer chat, ping, throughput and durable-log test of release files."""

import argparse
import asyncio
import collections
import gzip
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from p2plab.journal import Journal
from p2plab.runtime import configure_console_encoding


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


async def stop_process(process, timeout=10):
    if process.returncode is not None:
        return
    if sys.platform == "win32":
        # One-file bootloaders have an application child holding the output pipe.
        result = await asyncio.to_thread(
            subprocess.run, ["taskkill.exe", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True, timeout=timeout, check=False,
        )
        if result.returncode and process.returncode is None:
            raise RuntimeError(f"Could not stop test process tree {process.pid}: {result.stderr!r}")
    else:
        try:
            process.terminate()
        except ProcessLookupError:
            pass
    try:
        await asyncio.wait_for(process.wait(), timeout)
    except TimeoutError:
        if process.returncode is None:
            process.kill()
        await asyncio.wait_for(process.wait(), timeout)


async def finish_pumps(pumps, timeout=10):
    done, pending = await asyncio.wait(pumps, timeout=timeout) if pumps else (set(), set())
    for task in pending:
        task.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for task in done:
        task.result()
    if pending:
        raise RuntimeError("Timed out closing frozen test log pipes")


async def smoke(client, server, output):
    if output.exists() and any(output.iterdir()):
        raise ValueError("SMOKE_OUTPUT_MUST_BE_EMPTY; existing logs and identities will not be deleted")
    output.mkdir(parents=True, exist_ok=True)
    processes, pumps, lines = {}, [], {}
    environment = {**os.environ, "NO_COLOR": "1", "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"}
    for key in ("PYTHONHOME", "PYTHONPATH"):
        environment.pop(key, None)

    async def launch(name, binary, *args):
        process = await asyncio.create_subprocess_exec(
            str(binary), *[str(arg) for arg in args], cwd=output, env=environment,
            stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        processes[name] = process
        print(f"smoke: started {name}, pid={process.pid}", flush=True)
        lines[name] = collections.deque(maxlen=4000)

        async def pump():
            with gzip.open(output / (name + ".log.gz"), "wt", encoding="utf-8") as capture:
                while raw := await process.stdout.readline():
                    line = raw.decode("utf-8", errors="replace")
                    lines[name].append(line)
                    capture.write(line)

        pumps.append(asyncio.create_task(pump()))
        return process

    async def contains(name, needle, timeout=60):
        try:
            async with asyncio.timeout(timeout):
                while not any(needle in line for line in lines[name]):
                    if processes[name].returncode is not None:
                        raise RuntimeError(f"{name} exited before {needle}: " + "".join(lines[name])[-6000:])
                    await asyncio.sleep(0.05)
        except TimeoutError as error:
            raise RuntimeError(f"{name} timed out waiting for {needle}: " + "".join(lines[name])[-12000:]) from error
        print(f"smoke: {name} observed {needle}", flush=True)

    def send(name, text):
        processes[name].stdin.write(text.encode("utf-8"))

    port, tcp_port = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_STREAM)
    while tcp_port == port:
        tcp_port = free_port(socket.SOCK_STREAM)
    message = "release-smoke-private-chat-\u4e2d\u6587\u6d88\u606f"
    try:
        await launch("server", server, "--host", "127.0.0.1", "--port", port,
                     "--stun-port", free_port(socket.SOCK_DGRAM), "--tcp-port", tcp_port,
                     "--data", output / "server")
        await contains("server", "server.started")
        for name in ("a", "b"):
            config = output / (name + ".toml")
            config.write_text(
                f'server = "ws://127.0.0.1:{port}/ws"\n'
                f'data_dir = {json.dumps((output / name).as_posix())}\n'
                f'name = "{name}"\n'
                '[experiment]\ntimeout = 1.0\nprofiles = ["fast"]\ngateway = false\n'
                'diagnostics = false\nstun = []\nmax_pairs = 1\nport_prediction = false\n'
                'comprehensive = false\n', encoding="utf-8",
            )
            await launch(name, client, "--config", config, "--loopback", "--room", "release", "--plain")
        await asyncio.gather(contains("a", "path.opened"), contains("b", "path.opened"))
        send("a", message + "\n/ping\n/speed 1\n")
        await processes["a"].stdin.drain()
        await asyncio.gather(contains("b", message), contains("a", "ping.result"))
        async with asyncio.timeout(45):
            while sum("speed.result:" in line for line in lines["a"]) < 2:
                if processes["a"].returncode is not None:
                    raise RuntimeError("Client exited during bidirectional speed test")
                await asyncio.sleep(0.05)
        attachment = output / "private release file.bin"
        content = b"private-release-file-bytes\x00\r\n" * 4096
        attachment.write_bytes(content)
        send("a", "/file " + json.dumps(attachment.as_posix(), ensure_ascii=False) + "\n")
        await processes["a"].stdin.drain()
        await asyncio.gather(contains("a", "file.delivered"), contains("b", "file.received"))
        received = list((output / "b/downloads").glob("*.bin"))
        if len(received) != 1 or received[0].read_bytes() != content:
            raise RuntimeError("Frozen file transfer did not preserve binary content")
        await asyncio.gather(contains("a", "experiment.completed", 120), contains("b", "experiment.completed", 120))
        for name in ("a", "b"):
            send(name, "/quit\n")
            await processes[name].stdin.drain()
        await asyncio.wait_for(asyncio.gather(*(processes[name].wait() for name in ("a", "b"))), 30)
        if any(processes[name].returncode != 0 for name in ("a", "b")):
            raise RuntimeError("Frozen client did not exit cleanly")
    finally:
        cleanup = await asyncio.gather(*(stop_process(process) for process in processes.values()),
                                       return_exceptions=True)
        await finish_pumps(pumps)
        for result in cleanup:
            if isinstance(result, BaseException):
                raise result
    journal = Journal(output / "server/central.sqlite3", role="server", console=False)
    try:
        events = journal.query(room="release", limit=10000)
    finally:
        journal.close()
    failures = [event for event in events if event["event"] in (
        "runtime.asyncio_error", "client.background_failed", "runtime.unhandled_exception",
    )]
    serialized = json.dumps(events, ensure_ascii=False)
    if failures or message in serialized or "private-release-file-bytes" in serialized:
        raise RuntimeError("Runtime errors or chat content leaked into central diagnostics")
    counts = collections.Counter(event["event"] for event in events)
    if counts["client.stopped"] != 2 or counts["speed.result"] != 2 or not counts["chat.delivered"]:
        raise RuntimeError("Central logs are missing acknowledged client/chat/speed events")
    if counts["file.received"] != 1 or counts["file.delivered"] != 1:
        raise RuntimeError("Central logs are missing file transfer receipts")
    report = {"state": "passed", "chat": True, "unicode_chat": True, "ping": True,
              "bidirectional_speed": True, "file_transfer": True,
              "central_client_stops": counts["client.stopped"], "central_chat_deliveries": counts["chat.delivered"],
              "central_speed_results": counts["speed.result"], "background_errors": len(failures),
              "scope": "IPv4/IPv6 loopback only, not WAN or cross-ISP acceptance"}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report))


def main():
    configure_console_encoding()
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--client", type=Path, required=True)
    parser.add_argument("--server", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    asyncio.run(smoke(args.client.resolve(), args.server.resolve(), args.output.resolve()))


if __name__ == "__main__":
    main()
