import asyncio
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from textual.widgets import Input, Static

from p2plab.client import main, normalize_server_address
from p2plab.tui import JoinScreen, P2PApp
from tests.test_server import cleanup_hub, start_hub


async def test_runtime_monitor_records_blocking_and_ui_cost_without_network_probe(peers):
    client, _ = peers
    client.ui_refresh_max_ms = 17.5
    client.active_path = SimpleNamespace(attempt="idle", transport_diagnostics=lambda: {"rtt_ms": 50})
    task = asyncio.create_task(client.monitor_runtime(sample_seconds=0.005, report_seconds=0.04))
    try:
        await asyncio.sleep(0.01)
        time.sleep(0.03)
        async with asyncio.timeout(2):
            while not any(r["event"] == "runtime.health" for r in client.log.query()):
                await asyncio.sleep(0.005)
        record = next(r for r in client.log.query() if r["event"] == "runtime.health")
        fields = record["fields"]
        assert fields["event_loop_lag_max_ms"] >= 20
        assert fields["ui_refresh_max_ms"] == 17.5
        assert fields["transport"] == {"rtt_ms": 50}
        assert fields["scope"] == "local-runtime-only-no-network-probes"
        assert fields["benchmark_senders"] == fields["benchmark_receivers"] == 0
        assert not fields["matrix_running"] and not fields["wan_running"]
        client.stop.set()
        await asyncio.wait_for(task, 1)
        assert client.ui_refresh_max_ms == 0
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        client.active_path = None


@pytest.mark.parametrize(("address", "expected"), [
    (" 198.51.100.1:8443 ", "ws://198.51.100.1:8443/ws"),
    ("example.org", "ws://example.org:8443/ws"),
    ("example.org/custom", "ws://example.org:8443/custom"),
    ("2001:db8::1", "ws://[2001:db8::1]:8443/ws"),
    ("[2001:db8::1]:9000", "ws://[2001:db8::1]:9000/ws"),
    ("ws://example.org", "ws://example.org/ws"),
    ("wss://example.org/", "wss://example.org/ws"),
    ("https://example.org/p2p", "wss://example.org/p2p"),
    ("http://example.org:8443/ws", "ws://example.org:8443/ws"),
])
def test_server_input_normalization(address, expected):
    assert normalize_server_address(address) == expected


@pytest.mark.parametrize("address", [
    "", "ws://", "0.0.0.0:8443", "::", "[::]:8443", "host:0", "host:65536",
    "host:bad", "host:", "ftp://host", "ws://user:password@host", "ws://host?token=x",
    "ws://host#fragment", "ws://host\\path", "ho st:8443", "ws://[invalid]",
])
def test_server_input_rejects_invalid_or_sensitive_addresses(address):
    with pytest.raises(ValueError):
        normalize_server_address(address)


def test_no_argument_terminal_launch_opens_tui_without_config(tmp_path, monkeypatch):
    observed = []
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "argv", ["client.py"])
    monkeypatch.setattr(sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(sys.stdout, "isatty", lambda: True)
    monkeypatch.setattr(P2PApp, "run", lambda app: observed.append(app))
    main()
    assert len(observed) == 1
    assert observed[0].room is None and observed[0].client is None
    assert "server" not in observed[0].config


def test_source_entry_uses_local_environment_from_system_python():
    result = subprocess.run(
        [sys._base_executable, "client.py", "--help"], capture_output=True, text=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert "--tui" in result.stdout and "--room" in result.stdout


@pytest.mark.parametrize("size", [(60, 24), (80, 24), (140, 42)])
async def test_two_field_form_validates_server_and_joins_without_password(tmp_path, size):
    config = {"data_dir": str(tmp_path / "client"), "experiment": {"diagnostics": False}}
    app = P2PApp(config, start_backend=False)
    try:
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            assert isinstance(app.screen, JoinScreen)
            assert app.focused.id == "server"
            assert len(app.screen.query(Input)) == 2
            notice = str(app.screen.query_one("#join-network-notice", Static).content)
            assert "关闭 VPN、代理和 TUN" in notice
            app.screen.query_one("#room", Input).value = "1001"
            await pilot.click("#join")
            assert app.client is None
            assert "服务器地址" in str(app.screen.query_one("#join-error", Static).content)
            app.screen.query_one("#server", Input).value = "198.51.100.1:8443"
            await pilot.pause(0.4)
            assert "不加密" in str(app.screen.query_one("#join-security", Static).content)
            join = app.screen.query_one("#join")
            assert join.region.bottom <= size[1]
            await pilot.click("#join")
            await pilot.pause()
            assert app.client is not None
            assert app.client.server_url == "ws://198.51.100.1:8443/ws"
            assert app.client.room == "1001"
            assert app.client.config["allow_insecure"] is True
            assert "token_file" not in app.client.config
            assert "server" not in config
    finally:
        if app.client:
            await app.client.close()


async def test_two_field_form_connects_to_real_passwordless_server(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    config = {
        "data_dir": str(tmp_path / "client"), "loopback": True,
        "experiment": {"diagnostics": False, "gateway": False, "stun": []},
    }
    app = P2PApp(config)
    try:
        async with app.run_test(size=(80, 24)) as pilot:
            await pilot.pause()
            app.screen.query_one("#server", Input).value = url.removeprefix("ws://").removesuffix("/ws")
            app.screen.query_one("#room", Input).value = "simple-start"
            await pilot.click("#join")
            async with asyncio.timeout(10):
                while not app.client or not app.client.connected.is_set():
                    await pilot.pause(0.05)
            assert app.client.server_url == url
            assert app.client.room == "simple-start"
            assert not hub.access_token
            app.action_quit()
            await asyncio.wait_for(app.backend_task, 10)
        events = journal.query(room="simple-start")
        assert any(e["event"] == "client.started" for e in events)
        assert any(e["event"] == "client.stopped" for e in events)
    finally:
        await cleanup_hub(journal, runner, transport, tcp)
