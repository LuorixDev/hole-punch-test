"""Three Konsole application nodes behind two isolated Linux virtual CPEs."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import datetime as dt
import fcntl
import json
import os
import shutil
import signal
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
PYTHON = PROJECT / ".venv/bin/python"
SCRIPT = Path(__file__).resolve()
ROOM = "demo-1001"
DEFAULT_DATA = PROJECT / "data/interactive-lab"
SERVER_IP = "198.51.100.1"


def process_record(pid):
    # /proc comm may contain spaces, so split only after its closing parenthesis.
    fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    return {
        "pid": pid,
        "start_ticks": fields[19],
        "netns": os.readlink(f"/proc/{pid}/ns/net"),
        "userns": os.readlink(f"/proc/{pid}/ns/user"),
    }


def process_alive(record):
    try:
        status = Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()[0]
        return status not in ("Z", "X") and process_record(record["pid"]) == record
    except (OSError, KeyError):
        return False


def signal_process(record, sig):
    if process_alive(record):
        os.kill(record["pid"], sig)


def load_state(root):
    return json.loads((root / "state.json").read_text())


def update_state(root, **changes):
    with (root / "state.lock").open("a+") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        state = load_state(root) if (root / "state.json").exists() else {}
        for key, value in changes.items():
            if key in ("nodes", "windows"):
                state.setdefault(key, {}).update(value)
            else:
                state[key] = value
        with tempfile.NamedTemporaryFile(mode="w", dir=root, delete=False) as output:
            json.dump(state, output, indent=2)
            output.flush()
            os.fsync(output.fileno())
            temporary = Path(output.name)
        temporary.replace(root / "state.json")
        return state


def namespace_command(state, role, args):
    record = state["namespaces"][role]
    if not process_alive(record) or record["netns"] == state["host_netns"]:
        raise RuntimeError("LAB_NAMESPACE_MISSING_OR_NOT_ISOLATED:" + role)
    return ["nsenter", "-t", str(record["pid"]), "-U", "-n", "--preserve-credentials", *map(str, args)]


def write_config(root, role, *, smoke=False):
    name = ("smoke-" if smoke else "") + role
    path = root / (name + ".toml")
    directory = root / name
    options = {
        "timeout": 1.0 if smoke else 3.0,
        "profiles": ["fast"] if smoke else ["balanced", "fast", "staggered"],
        "gateway": not smoke,
        "diagnostics": False,
        "stun": [],
        "max_addresses": 4,
        "max_pairs": 2 if smoke else 4,
        "port_prediction": True,
    }
    if smoke:
        options.update(comprehensive=False, auto_retry=False)
    lines = [
        'server = "ws://' + SERVER_IP + ':8443/ws"',
        "allow_insecure = true",
        "name = " + json.dumps(name),
        "data_dir = " + json.dumps(str(directory)),
        "",
        "[experiment]",
    ]
    lines += [f"{key} = {json.dumps(value)}" for key, value in options.items()]
    path.write_text("\n".join(lines) + "\n")
    path.chmod(0o600)
    return path


def server_command(root):
    return [
        PYTHON,
        PROJECT / "server.py",
        "--host",
        "0.0.0.0",
        "--port",
        "8443",
        "--stun-host",
        SERVER_IP,
        "--data",
        root / "server",
        "--allow-inbound-check",
        "--inbound-prefix",
        "2001:db9:a::/64",
        "--inbound-prefix",
        "2001:db9:b::/64",
    ]


def client_command(root, role, *, smoke=False):
    return [
        PYTHON,
        PROJECT / "client.py",
        "--config",
        write_config(root, role, smoke=smoke),
        "--room",
        "lab-smoke" if smoke else ROOM,
    ]


def controller(root, host_netns, mode, mtu):
    if os.geteuid() != 0 or os.readlink("/proc/self/ns/net") == host_netns:
        raise RuntimeError("ISOLATED_USER_AND_NETWORK_NAMESPACE_REQUIRED")
    keepers = {}
    stopping = False

    def stop(*args):
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    def command(args, role="server", text=None):
        prefix = [] if role == "server" else ["nsenter", "-t", str(keepers[role].pid), "-n"]
        result = subprocess.run(
            [*prefix, *map(str, args)], input=text, text=True, capture_output=True, timeout=6
        )
        if result.returncode:
            raise RuntimeError(f"{role}: {args}: {result.stderr.strip()}")
        return result.stdout

    def pair(left, right, left_name, right_name, v4_left, v4_right, v6_left, v6_right):
        a, b = "x" + left_name + left[-1], "x" + right_name + right[-1]
        command(["ip", "link", "add", a, "type", "veth", "peer", "name", b])
        for role, temporary, name, v4, v6 in (
            (left, a, left_name, v4_left, v6_left),
            (right, b, right_name, v4_right, v6_right),
        ):
            if role != "server":
                command(["ip", "link", "set", temporary, "netns", keepers[role].pid])
            command(["ip", "link", "set", temporary, "name", name], role)
            command(["ip", "link", "set", name, "mtu", mtu], role)
            command(["ip", "link", "set", name, "up"], role)
            command(["ip", "address", "add", v4, "dev", name], role)
            if role.startswith("client"):
                command(["sysctl", "-q", "-w", f"net.ipv6.conf.{name}.use_tempaddr=2"], role)
            args = ["ip", "-6", "address", "add", v6, "dev", name, "nodad"]
            if role.startswith("client"):
                args += ["mngtmpaddr", "valid_lft", "7200", "preferred_lft", "3600"]
            command(args, role)

    try:
        for role in ("router-a", "router-b", "client-a", "client-b"):
            process = subprocess.Popen(["unshare", "-n", "sleep", "86400"])
            keepers[role] = process
            deadline = time.monotonic() + 3
            while os.readlink(f"/proc/{process.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("CHILD_NAMESPACE_SETUP_FAILED:" + role)
                time.sleep(0.02)
        for role in ("server", *keepers):
            command(["ip", "link", "set", "lo", "up"], role)
        pair(
            "server",
            "router-a",
            "ca",
            "wan",
            "198.51.100.1/30",
            "198.51.100.2/30",
            "2001:db9:100::1/64",
            "2001:db9:100::2/64",
        )
        pair(
            "server",
            "router-b",
            "cb",
            "wan",
            "203.0.113.1/30",
            "203.0.113.2/30",
            "2001:db9:200::1/64",
            "2001:db9:200::2/64",
        )
        pair(
            "router-a",
            "client-a",
            "lan",
            "eth",
            "192.168.10.1/24",
            "192.168.10.2/24",
            "2001:db9:a::1/64",
            "2001:db9:a::2/64",
        )
        pair(
            "router-b",
            "client-b",
            "lan",
            "eth",
            "192.168.20.1/24",
            "192.168.20.2/24",
            "2001:db9:b::1/64",
            "2001:db9:b::2/64",
        )
        for role in ("server", "router-a", "router-b"):
            command(["sysctl", "-q", "-w", "net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"], role)
        for suffix, lan, wan, prefix in (("a", "10", "198.51.100", "100"), ("b", "20", "203.0.113", "200")):
            router, client = "router-" + suffix, "client-" + suffix
            command(["ip", "route", "add", "default", "via", wan + ".1", "dev", "wan"], router)
            command(
                ["ip", "-6", "route", "add", "default", "via", f"2001:db9:{prefix}::1", "dev", "wan"], router
            )
            command(["ip", "route", "add", "default", "via", f"192.168.{lan}.1", "dev", "eth"], client)
            command(
                ["ip", "-6", "route", "add", "default", "via", f"2001:db9:{suffix}::1", "dev", "eth"], client
            )
            command(["ip", "-6", "route", "add", f"2001:db9:{suffix}::/64", "via", f"2001:db9:{prefix}::2"])
            policy = "accept" if mode == "open" else "drop"
            static = 'iifname "wan" meta nfproto ipv6 counter drop' if mode == "static-block" else ""
            rules = f"""table inet p2plab_demo {{
              chain forward {{
                type filter hook forward priority 0; policy {policy};
                {static}
                ct state established,related counter accept
                iifname "lan" oifname "wan" counter accept
                counter
              }}
            }}
            table ip p2plab_nat {{
              chain postrouting {{
                type nat hook postrouting priority srcnat; policy accept;
                oifname "wan" masquerade
              }}
            }}"""
            command(["nft", "-f", "-"], router, rules)
        deadline = time.monotonic() + 8
        while True:
            addresses = {
                role: json.loads(command(["ip", "-j", "address", "show"], role))
                for role in ("client-a", "client-b")
            }
            if all(
                any(
                    a.get("temporary") and not a.get("tentative")
                    for i in rows
                    for a in i.get("addr_info", [])
                )
                for rows in addresses.values()
            ):
                break
            if time.monotonic() > deadline:
                raise RuntimeError("KERNEL_PRIVACY_IPV6_NOT_READY")
            time.sleep(0.1)
        record = process_record(os.getpid())
        update_state(
            root,
            controller=record,
            namespaces={"server": record, **{role: process_record(p.pid) for role, p in keepers.items()}},
            host_netns=host_netns,
            ready=True,
            mode=mode,
            mtu=mtu,
            room=ROOM,
            data_root=str(root),
            addresses=addresses,
            nodes={},
            windows={},
            started_at=dt.datetime.now(dt.timezone.utc).isoformat(),
            evidence="isolated-virtual-networks-and-CPEs-not-real-home-routers",
        )
        print("Isolated network ready; kernel-generated temporary IPv6 confirmed", flush=True)
        while not stopping:
            time.sleep(0.2)
    finally:
        with contextlib.suppress(OSError, ValueError):
            state = load_state(root)
            nodes = state.get("nodes", {})
            for role in ("client-a", "client-b", "server"):
                node_record = nodes.get(role, {}).get("wrapper")
                if node_record:
                    signal_process(node_record, signal.SIGTERM)
                deadline = time.monotonic() + 6
                while node_record and process_alive(node_record) and time.monotonic() < deadline:
                    time.sleep(0.1)
                app = nodes.get(role, {}).get("app")
                if app:
                    signal_process(app, signal.SIGKILL)
            update_state(root, ready=False)
        for process in keepers.values():
            if process.poll() is None:
                process.terminate()
        for process in keepers.values():
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()


def node(root, role):
    state = load_state(root)
    actual = os.readlink("/proc/self/ns/net")
    if actual != state["namespaces"][role]["netns"] or actual == state["host_netns"]:
        raise RuntimeError("NODE_IS_NOT_IN_ITS_ISOLATED_NAMESPACE")
    print(f"\033]0;P2P Lab | {role}\007", end="", flush=True)
    print(f"P2P Lab | {role} | {actual}\nRoom: {ROOM} | Firewall: {state['mode']} | MTU: {state['mtu']}")
    print("Three isolated application nodes plus two virtual CPEs; no host firewall changes.")
    print("Synthetic IPv6 prefixes exist only in this isolated lab. No Internet uplink.")
    if role != "server":
        print("Chat text, /ping, /speed 1, /paths, /results, /quit\n", flush=True)
    args = server_command(root) if role == "server" else client_command(root, role)
    app = subprocess.Popen(list(map(str, args)), cwd=PROJECT)
    update_state(root, nodes={role: {"wrapper": process_record(os.getpid()), "app": process_record(app.pid)}})

    def forward(signum, frame):
        if app.poll() is None:
            app.send_signal(signal.SIGTERM)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    try:
        return app.wait()
    finally:
        if app.poll() is None:
            app.terminate()
            try:
                app.wait(timeout=8)
            except subprocess.TimeoutExpired:
                app.kill()
                app.wait()


async def verify(root):
    from p2plab.logcodec import load_document

    started_at = dt.datetime.now(dt.timezone.utc).isoformat()
    state = load_state(root)
    if any(process_alive(n["app"]) for n in state.get("nodes", {}).values()):
        raise RuntimeError("VERIFY_REQUIRES_NO_INTERACTIVE_APPLICATIONS_RUNNING")
    processes, pumps, output = [], [], {}

    async def launch(role, args):
        process = await asyncio.create_subprocess_exec(
            *namespace_command(state, role, args),
            cwd=PROJECT,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        processes.append(process)
        output[role] = []

        async def pump():
            with (root / ("smoke-" + role + ".log")).open("w") as log:
                while line := await process.stdout.readline():
                    text = line.decode(errors="replace")
                    log.write(text)
                    log.flush()
                    output[role].append(text)

        pumps.append(asyncio.create_task(pump()))
        return process

    async def wait(role, needle, *, count=1, timeout=75):
        async with asyncio.timeout(timeout):
            while sum(needle in line for line in output.get(role, [])) < count:
                if any(p.returncode is not None for p in processes):
                    raise RuntimeError("LAB_APPLICATION_EXITED:" + json.dumps(output)[-6000:])
                await asyncio.sleep(0.1)

    try:
        server = await launch("server", server_command(root))
        await wait("server", "server.started", timeout=15)
        a = await launch("client-a", client_command(root, "client-a", smoke=True))
        b = await launch("client-b", client_command(root, "client-b", smoke=True))
        await asyncio.gather(wait("client-a", "path.verified"), wait("client-b", "path.verified"))
        a.stdin.write(b"lab-smoke-chat\n/ping\n/speed 1\n")
        await a.stdin.drain()
        await asyncio.gather(
            wait("client-b", "lab-smoke-chat"),
            wait("client-a", "ping.result"),
            wait("client-a", "speed.result:", count=2),
        )
        await asyncio.gather(
            wait("client-a", "experiment.completed", timeout=120),
            wait("client-b", "experiment.completed", timeout=120),
        )
        for process in (a, b):
            process.stdin.write(b"/quit\n")
            await process.stdin.drain()
        await asyncio.wait_for(asyncio.gather(a.wait(), b.wait()), 15)
        if a.returncode or b.returncode:
            raise RuntimeError("LAB_CLIENT_SHUTDOWN_FAILED")
        server.terminate()
        await asyncio.wait_for(server.wait(), 10)
        with sqlite3.connect(root / "server/central.sqlite3") as db:
            events = [
                load_document(row[0])
                for row in db.execute("SELECT document FROM events WHERE room='lab-smoke'")
            ]
        events = [event for event in events if event["time"] >= started_at]
        report = {
            "passed": True,
            "started_at": started_at,
            "evidence": state["evidence"],
            "chat": any(e["event"] == "chat.delivered" for e in events),
            "ping": any(e["event"] == "ping.result" for e in events),
            "speed_directions": sum(e["event"] == "speed.result" for e in events),
            "client_shutdown_logs": sum(e["event"] == "client.stopped" for e in events),
            "http_callbacks": [e["fields"]["code"] for e in events if e["event"] == "ipv6.inbound_result"],
            "path_families": sorted(
                {
                    e["fields"]["family"]
                    for e in events
                    if e["event"] == "path.opened" and e["fields"].get("family")
                }
            ),
            "matrix_completions": sum(e["event"] == "experiment.completed" for e in events),
            "mode": state["mode"],
            "mtu": state["mtu"],
        }
        if not (
            report["chat"]
            and report["ping"]
            and report["speed_directions"] == 2
            and report["client_shutdown_logs"] == 2
            and report["matrix_completions"] == 2
        ):
            raise RuntimeError("LAB_CENTRAL_EVIDENCE_INCOMPLETE:" + json.dumps(report))
        (root / "verification.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2), flush=True)
        return report
    finally:
        for process in processes:
            if process.returncode is None:
                process.terminate()
        for process in processes:
            try:
                await asyncio.wait_for(process.wait(), 10)
            except TimeoutError:
                process.kill()
                await process.wait()
        await asyncio.gather(*pumps, return_exceptions=True)


def stop_lab(root):
    state = load_state(root)
    record = state.get("controller", {})
    signal_process(record, signal.SIGTERM)
    deadline = time.monotonic() + 25
    while process_alive(record) and time.monotonic() < deadline:
        time.sleep(0.1)
    if process_alive(record):
        raise RuntimeError("LAB_SHUTDOWN_TIMEOUT; inspect controller.log before retrying")
    for window in state.get("windows", {}).values():
        signal_process(window, signal.SIGTERM)
    print("Isolated lab stopped. Logs retained in " + str(root), flush=True)


def start(root, mode, mtu, *, headless=False):
    required = ["unshare", "nsenter", "ip", "nft", "sysctl"] + ([] if headless else ["konsole"])
    missing = [name for name in required if not shutil.which(name)]
    if missing:
        raise RuntimeError("MISSING_TOOLS:" + ",".join(missing))
    if not headless and not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise RuntimeError("DESKTOP_SESSION_REQUIRED")
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    if (root / "state.json").exists() and process_alive(load_state(root).get("controller", {})):
        print("Lab is already running: " + str(root))
        return
    with (root / "controller.log").open("w") as log:
        process = subprocess.Popen(
            [
                "unshare",
                "-Urn",
                str(PYTHON),
                str(SCRIPT),
                "_controller",
                "--data",
                str(root),
                "--host-netns",
                os.readlink("/proc/self/ns/net"),
                "--mode",
                mode,
                "--mtu",
                str(mtu),
            ],
            cwd=PROJECT,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    windows = []
    try:
        deadline = time.monotonic() + 25
        while True:
            state = load_state(root) if (root / "state.json").exists() else {}
            if state.get("ready") and state.get("controller", {}).get("pid") == process.pid:
                break
            if process.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError((root / "controller.log").read_text())
            time.sleep(0.1)
        print("Network ready; running real CLI chat/ping/bidirectional-speed verification", flush=True)
        asyncio.run(verify(root))
        if headless:
            return
        for role in ("server", "client-a", "client-b"):
            command = namespace_command(
                state, role, [PYTHON, SCRIPT, "_node", "--data", root, "--role", role]
            )
            with (root / (role + "-konsole.log")).open("w") as log:
                window = subprocess.Popen(
                    [
                        "konsole",
                        "--separate",
                        "--hold",
                        "--workdir",
                        str(PROJECT),
                        "-p",
                        "tabtitle=P2P Lab | " + role,
                        "-p",
                        "TerminalColumns=112",
                        "-p",
                        "TerminalRows=34",
                        "-e",
                        *command,
                    ],
                    stdin=subprocess.DEVNULL,
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            windows.append(window)
            update_state(root, windows={role: process_record(window.pid)})
            deadline = time.monotonic() + 15
            while True:
                latest = load_state(root)
                app = latest.get("nodes", {}).get(role, {}).get("app")
                if app and process_alive(app):
                    break
                if window.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(
                        "KONSOLE_NODE_NOT_READY:" + role + ":" + (root / (role + "-konsole.log")).read_text()
                    )
                time.sleep(0.1)
            if role == "server":
                health = namespace_command(
                    state,
                    "server",
                    [
                        PYTHON,
                        "-c",
                        "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8443/health', timeout=1).status)",
                    ],
                )
                deadline = time.monotonic() + 10
                while subprocess.run(health, capture_output=True, timeout=3).returncode:
                    if time.monotonic() > deadline:
                        raise RuntimeError("INTERACTIVE_SERVER_STARTUP_FAILED")
                    time.sleep(0.1)
        print(
            f"Three Konsole windows opened. Room: {ROOM}. Logs: {root / 'server/central.sqlite3'}", flush=True
        )
    except BaseException:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=25)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        for window in windows:
            if window.poll() is None:
                window.terminate()
                try:
                    window.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    window.kill()
                    window.wait()
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["start", "stop", "status", "verify", "_controller", "_node"])
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--mode", choices=["stateful", "open", "static-block"], default="stateful")
    parser.add_argument("--mtu", type=int, choices=[1280, 1500], default=1500)
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--host-netns")
    parser.add_argument("--role", choices=["server", "client-a", "client-b"])
    args = parser.parse_args()
    root = args.data.resolve()
    if args.action == "start":
        start(root, args.mode, args.mtu, headless=args.headless)
    elif args.action == "stop":
        stop_lab(root)
    elif args.action == "status":
        state = load_state(root)
        print(json.dumps({**state, "controller_alive": process_alive(state.get("controller", {}))}, indent=2))
    elif args.action == "verify":
        asyncio.run(verify(root))
    elif args.action == "_controller":
        controller(root, args.host_netns, args.mode, args.mtu)
    elif args.action == "_node":
        raise SystemExit(node(root, args.role))


if __name__ == "__main__":
    main()
