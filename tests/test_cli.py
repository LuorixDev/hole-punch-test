import asyncio
import datetime as dt
import ipaddress
import json
import socket
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from tools.smoke_frozen import free_shared_port


def free_port(kind):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def local_certificate(directory):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                                        x509.DNSName("localhost")]), critical=False
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = directory / "server.crt", directory / "server.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )
    )
    key_path.chmod(0o600)
    return cert_path, key_path


@pytest.mark.parametrize("tls,shared", [(True, True), (False, True), (False, False)],
                         ids=["tls-shared", "plaintext-wildcard-shared", "plaintext-legacy"])
async def test_real_server_and_two_terminal_clients_and_export(tmp_path, tls, shared):
    cert, key = local_certificate(tmp_path) if tls else (None, None)
    port, stun_port, tcp_port = (
        free_shared_port() if shared else free_port(socket.SOCK_STREAM),
        free_port(socket.SOCK_DGRAM),
        free_port(socket.SOCK_STREAM),
    )
    if tcp_port == port:
        tcp_port = free_port(socket.SOCK_STREAM)
    server = await asyncio.create_subprocess_exec(
        sys.executable,
        "server.py",
        "--host",
        "127.0.0.1" if tls else "0.0.0.0",
        "--port",
        str(port),
        *([] if shared else ["--stun-port", str(stun_port), "--tcp-port", str(tcp_port)]),
        *(["--cert", str(cert), "--key", str(key)] if tls else []),
        "--allow-inbound-check",
        "--allow-loopback-check",
        "--data",
        str(tmp_path / "server"),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    processes, pumps, output = [server], [], {}

    async def pump(name, process):
        output[name] = []
        while line := await process.stdout.readline():
            output[name].append(line.decode(errors="replace"))

    async def contains(name, needle, timeout=15):
        async with asyncio.timeout(timeout):
            while not any(needle in line for line in output.get(name, [])):
                if processes[0].returncode is not None:
                    raise AssertionError("Server exited: " + "".join(output.get("server", [])))
                await asyncio.sleep(0.05)

    pumps.append(asyncio.create_task(pump("server", server)))
    try:
        await contains("server", "server.started")
        if not tls:
            await contains("server", "server.insecure")
        clients = []
        for name in ("a", "b"):
            config = tmp_path / (name + ".toml")
            config.write_text(
                f'server = "{"wss" if tls else "ws"}://127.0.0.1:{port}/ws"\n'
                + (
                    f'ca_file = "{cert}"\n'
                    if tls
                    else 'allow_insecure = true\nca_file = "/unused-in-plaintext"\n'
                )
                + f'data_dir = "{tmp_path / name}"\nname = "{name}"\n'
                '[experiment]\ntimeout = 1.0\nprofiles = ["fast"]\ngateway = false\n'
                "diagnostics = false\nstun = []\nmax_pairs = 2\nport_prediction = false\n"
            )
            client = await asyncio.create_subprocess_exec(
                sys.executable,
                "client.py",
                "--config",
                str(config),
                "--loopback",
                "--room",
                "cli",
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            clients.append(client)
            processes.append(client)
            pumps.append(asyncio.create_task(pump(name, client)))
        await asyncio.gather(contains("a", "path.opened"), contains("b", "path.opened"))
        await asyncio.gather(contains("a", "ipv6.inbound_result"), contains("b", "ipv6.inbound_result"))
        clients[0].stdin.write(b"private-cli-message\n/ping\n/speed 1\n")
        await clients[0].stdin.drain()
        await contains("b", "private-cli-message")
        await contains("a", "ping.result")
        async with asyncio.timeout(15):
            while sum("speed.result:" in line for line in output["a"]) < 2:
                await asyncio.sleep(0.05)
        await asyncio.gather(
            contains("a", "experiment.completed", 120), contains("b", "experiment.completed", 120)
        )
        for client in clients:
            client.stdin.write(b"/quit\n")
            await client.stdin.drain()
        await asyncio.wait_for(asyncio.gather(*(client.wait() for client in clients)), 10)
        assert all(client.returncode == 0 for client in clients)
        export_path = tmp_path / "export.jsonl"
        export = await asyncio.create_subprocess_exec(
            sys.executable,
            "export_logs.py",
            "--server",
            f"{'https' if tls else 'http'}://127.0.0.1:{port}",
            *(["--ca-file", str(cert)] if tls else []),
            "--token-file",
            str(tmp_path / "server" / "admin.token"),
            "--room",
            "cli",
            "--output",
            str(export_path),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        processes.append(export)
        out, _ = await asyncio.wait_for(export.communicate(), 15)
        assert export.returncode == 0, out.decode()
        events = [json.loads(line) for line in export_path.read_text().splitlines()]
        assert sum(e["event"] == "client.stopped" for e in events) == 2
        assert any(e["event"] == "chat.delivered" for e in events)
        assert sum(e["event"] == "speed.result" for e in events) == 2
        mapped = [e for e in events if e["event"] == "tcp.mapped"]
        assert mapped and all(e["fields"]["observer_protocol"] == ("http" if shared else "raw") for e in mapped)
        if shared:
            assert any(e["event"] == "stun.observed" and e["fields"]["observer"][1] == port for e in events)
        callbacks = [e for e in events if e["event"] == "ipv6.inbound_result"]
        assert len(callbacks) == 2
        assert all(e["fields"]["code"] == "REACHABLE" for e in callbacks)
        assert sum(e["event"] == "ipv6.inbound" for e in events) == 2
        for result in callbacks:
            plans = [e for e in events if e["client"] == result["client"] and e["event"] == "experiment.plan"]
            assert all(result["time"] <= plan["time"] for plan in plans)
        assert "private-cli-message" not in export_path.read_text()
        assert "private-cli-message" not in "".join(output["server"])
    finally:
        for process in processes:
            if process.returncode is None:
                process.terminate()
        for process in processes:
            try:
                await asyncio.wait_for(process.wait(), 8)
            except TimeoutError:
                process.kill()
                await process.wait()
        await asyncio.gather(*pumps, return_exceptions=True)
