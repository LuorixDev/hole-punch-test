import asyncio
import io
import json
import os
import socket
import sys
import zipfile
from copy import deepcopy
from types import SimpleNamespace

import pytest
from aiohttp import web

from p2plab.client import Client
from p2plab.common import Identity
from p2plab.console import ConsoleReader
from p2plab.network import command, query_ip, read_address_inventory, select_addresses, snapshot
from p2plab.runtime import application_directory, configure_console_encoding, default_client_data
from tests.test_network import Evidence
from tools.install_librespeed import install_archive


def test_windows_redirected_console_handles_chinese_independent_of_environment(tmp_path, monkeypatch):
    import p2plab.runtime as runtime
    from p2plab.journal import Journal

    content = "\u4e2d\u6587\u6d88\u606f\n"
    output = io.BytesIO()
    error = io.BytesIO()
    streams = SimpleNamespace(
        platform="win32", stdin=io.TextIOWrapper(io.BytesIO(content.encode("utf-8")), encoding="cp1252"),
        stdout=io.TextIOWrapper(output, encoding="cp1252"),
        stderr=io.TextIOWrapper(error, encoding="cp1252"),
    )
    monkeypatch.setattr(runtime, "sys", streams)
    configure_console_encoding()
    assert streams.stdin.readline() == content
    monkeypatch.setattr("p2plab.journal.sys.stdout", streams.stdout)
    journal = Journal(tmp_path / "unicode.sqlite3", role="client")
    try:
        journal.event("network.status", content.strip())
        assert content.strip() in output.getvalue().decode("utf-8")
        assert journal.query()[-1]["message"] == content.strip()
        streams.stderr.write(content)
        streams.stderr.flush()
        assert error.getvalue().decode("utf-8") == content.replace("\n", os.linesep)
    finally:
        journal.close()


@pytest.fixture
def windows_network(monkeypatch):
    rows = [{
        "address": address, "interface": "Ethernet", "prefixlen": 64 if ":" in address else 24,
        "state": state, "suffix_origin": origin, "valid_lifetime": 7200,
        "preferred_lifetime": 3600, "skip_as_source": skip,
    } for address, state, origin, skip in (
        ("192.168.1.10", "Preferred", "Dhcp", False),
        ("2606:4700::1", "Preferred", "Random", False),
        ("2606:4700::2", "Preferred", "Manual", False),
        ("2606:4700::3", "Tentative", "Random", False),
        ("2606:4700::4", "Duplicate", "Random", False),
        ("2606:4700::5", "Deprecated", "Random", False),
        ("2606:4700::6", "Preferred", "Manual", True),
    )]
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Windows")
    monkeypatch.setattr("p2plab.network.psutil.net_if_addrs", lambda: {})
    monkeypatch.setattr("p2plab.network.psutil.net_if_stats",
                        lambda: {"Ethernet": SimpleNamespace(isup=True, mtu=1500)})

    async def powershell(script):
        output = rows if "Get-NetIPAddress" in script else [
            {"prefix": "0.0.0.0/0", "gateway": "192.168.1.1", "dev": "Ethernet", "metric": 10},
            {"prefix": "::/0", "gateway": "fe80::1", "dev": "Ethernet", "metric": 10},
        ]
        return {"state": "completed", "output": deepcopy(output)}

    monkeypatch.setattr("p2plab.network.powershell", powershell)
    return rows


async def test_windows_state_filtering_routes_and_unknown_privacy_type(windows_network):
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert {r["address"] for r in result["addresses"]} == {
        "192.168.1.10", "2606:4700::1", "2606:4700::2",
    }
    randomized = next(r for r in result["addresses"] if r["address"] == "2606:4700::1")
    assert randomized["state"] == "preferred" and randomized["type"] == "unverified"
    assert randomized["temporary"] is None
    assert {r["reason"] for r in result["excluded_addresses"]} == {
        "ADDRESS_TENTATIVE", "ADDRESS_DADFAILED", "ADDRESS_DEPRECATED", "ADDRESS_SKIP_AS_SOURCE",
    }
    assert result["gateways"][0]["gateway"] == "192.168.1.1"
    assert len(result["gateways6"]) == 2
    assert all(r["gateway"] == "fe80::1" for r in result["gateways6"])


async def test_windows_lifetime_and_down_nic_fail_closed(windows_network, monkeypatch):
    windows_network[1]["preferred_lifetime"] = 0
    windows_network[2]["valid_lifetime"] = 10
    inventory, _ = await read_address_inventory()
    assert [r["address"] for r in select_addresses(inventory)] == ["192.168.1.10"]
    monkeypatch.setattr("p2plab.network.psutil.net_if_stats",
                        lambda: {"Ethernet": SimpleNamespace(isup=False, mtu=1500)})
    inventory, _ = await read_address_inventory()
    assert not select_addresses(inventory)


async def test_missing_windows_evidence_never_fakes_ipv6_state(windows_network, monkeypatch):
    monkeypatch.setattr("p2plab.network.psutil.net_if_addrs", lambda: {"Ethernet": [
        SimpleNamespace(family=socket.AF_INET6, address="2606:4700::1", netmask=None),
    ]})

    async def missing(script):
        return {"state": "unsupported", "reason": "COMMAND_MISSING"}

    monkeypatch.setattr("p2plab.network.powershell", missing)
    inventory, result = await read_address_inventory()
    assert result["reason"] == "COMMAND_MISSING"
    assert all(r["state"] == "unverified" for r in inventory)
    assert not select_addresses(inventory)


async def test_failed_command_launch_is_diagnostic_not_startup_crash(monkeypatch):
    monkeypatch.setattr("p2plab.network.shutil.which", lambda name: name)

    async def blocked(*args, **kwargs):
        raise PermissionError("execution denied")

    monkeypatch.setattr("p2plab.network.asyncio.create_subprocess_exec", blocked)
    result = await command("blocked")
    assert result["state"] == "failed" and "PermissionError" in result["reason"]


async def test_denied_network_inventory_does_not_leave_startup_waiting_forever(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client")}, "denied", console=False)

    async def denied(*args, **kwargs):
        raise PermissionError("network inventory denied")

    monkeypatch.setattr("p2plab.client.snapshot", denied)
    try:
        await client.collect_network()
        assert client.network_ready.is_set()
        assert not client.network["addresses"]
        assert any(e["event"] == "network.failed" for e in client.log.query())
    finally:
        await client.close()


def test_frozen_windows_paths_use_writable_user_state(tmp_path, monkeypatch):
    monkeypatch.setattr("p2plab.runtime.sys", SimpleNamespace(
        frozen=True, platform="win32", executable=str(tmp_path / "bundle/P2PLab-Client.exe"),
    ))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "user"))
    assert application_directory() == tmp_path / "bundle"
    assert default_client_data() == tmp_path / "user/P2PLab/client"


def test_identity_directory_cannot_be_shared_and_lock_is_released(tmp_path):
    first = Identity(tmp_path)
    try:
        with pytest.raises(ValueError, match="ALREADY_IN_USE"):
            Identity(tmp_path)
    finally:
        first.close()
    second = Identity(tmp_path)
    second.close()


def test_windows_speedtest_archive_installs_only_named_files(tmp_path):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("librespeed-cli.exe", b"MZtest")
        archive.writestr("LICENSE", b"LGPL")
        archive.writestr("../unexpected.exe", b"unwanted")
    binary = install_archive(stream.getvalue(), tmp_path, windows=True)
    assert binary.name == "librespeed-cli.exe" and binary.read_bytes() == b"MZtest"
    assert (tmp_path / "LIBRESPEED-LICENSE").read_bytes() == b"LGPL"
    assert len(list(tmp_path.iterdir())) == 2


async def test_windows_console_input_is_bounded_utf8_and_handles_eof():
    reader = ConsoleReader(io.StringIO("中文消息\n/quit\n"))
    reader.start()
    try:
        assert reader.queue.maxsize == 16
        assert await asyncio.wait_for(reader.readline(), 2) == "中文消息\n".encode()
        assert await asyncio.wait_for(reader.readline(), 2) == b"/quit\n"
        assert await asyncio.wait_for(reader.readline(), 2) == b""
    finally:
        reader.close()


async def test_windows_console_oversized_line_is_explicit_error():
    reader = ConsoleReader(io.StringIO("x" * 65537))
    reader.start()
    try:
        with pytest.raises(ValueError, match="TERMINAL_LINE_LIMIT"):
            await asyncio.wait_for(reader.readline(), 2)
    finally:
        reader.close()


async def test_windows_desktop_open_uses_default_handler(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client")}, "windows", console=False)
    opened = []
    monkeypatch.setattr("p2plab.client.os", SimpleNamespace(name="nt", startfile=opened.append))
    try:
        target = tmp_path / "test.png"
        await client.open_desktop(target)
        assert opened == [str(target.resolve())]
        assert client.log.query()[-1]["event"] == "file.opened"
    finally:
        await client.close()


@pytest.mark.parametrize("mode", ["ok", "ipv6", "private", "html", "large", "error", "chunked"])
async def test_ip_query_validates_real_http_responses_without_crashing(mode):
    async def handler(request):
        if mode == "chunked":
            response = web.StreamResponse()
            await response.prepare(request)
            await response.write(b"8.8.8.8")
            await asyncio.sleep(0.05)
            await response.write(b" trailing garbage")
            await response.write_eof()
            return response
        value = {"ok": "8.8.8.8", "ipv6": "2606:4700::1", "private": "192.168.1.1",
                 "html": "<html>blocked</html>", "large": "x" * 513, "error": "unavailable"}[mode]
        return web.Response(text=value, status=503 if mode == "error" else 200)

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = site._server.sockets[0].getsockname()[1]
        result = await query_ip("test", f"http://127.0.0.1:{port}/", 4)
        assert result["state"] == ("observed" if mode == "ok" else "unavailable")
        if mode == "ok":
            assert result["address"] == "8.8.8.8"
        assert result["elapsed_ms"] >= 0
    finally:
        await runner.cleanup()


@pytest.mark.skipif(sys.platform != "win32", reason="Requires an actual Windows host")
async def test_native_windows_read_only_network_snapshot():
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert result["system_commands"][0]["state"] == "completed", json.dumps(result["system_commands"])
    assert result["address_inventory"]
    assert all(r["source"] == "windows-netipaddress" for r in result["address_inventory"])


def test_regular_file_sender_does_not_require_posix_nonblocking_flag(tmp_path, monkeypatch):
    from p2plab.transfers import open_source

    monkeypatch.delattr(os, "O_NONBLOCK", raising=False)
    source = tmp_path / "binary.dat"
    content = b"binary\r\n\x00data\n"
    source.write_bytes(content)
    stream, info = open_source(source, False)
    try:
        assert stream.read() == content and info.st_size == len(content)
    finally:
        stream.close()
async def test_windows_cim_queries_allow_bounded_cold_start(monkeypatch):
    from p2plab.network import powershell

    async def command(*args, **kwargs):
        assert args[0] == "powershell.exe"
        assert kwargs["timeout"] == 30
        return {"state": "completed", "output": []}

    monkeypatch.setattr("p2plab.network.command", command)
    assert (await powershell("Get-NetIPAddress"))["state"] == "completed"


def test_windows_ice_ipv6_send_uses_four_tuple_without_changing_scope_or_ipv4():
    from p2plab.rtc import normalize_ice_transport

    sent = []
    transport = SimpleNamespace(sendto=lambda data, address: sent.append((data, address)))
    normalize_ice_transport(transport)
    normalize_ice_transport(transport)
    for address in (("::1", 3000), ("127.0.0.1", 3001), ("fe80::1", 3002, 4, 7)):
        transport.sendto(b"test", address)
    assert sent == [(b"test", ("::1", 3000, 0, 0)), (b"test", ("127.0.0.1", 3001)),
                    (b"test", ("fe80::1", 3002, 4, 7))]
