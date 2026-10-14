import ast
import asyncio
import hashlib
import json
import tomllib
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
from aiohttp import web

from tools.build_release import collect_licenses, write_checksums
from tools.smoke_frozen import finish_pumps, read_room_events, stop_process

ROOT = Path(__file__).resolve().parents[1]


def test_package_and_distribution_release_versions_match():
    from p2plab import __version__

    project = tomllib.loads((ROOT / "pyproject.toml").read_text())
    assert project["project"]["version"] == __version__
    assert "## v" + __version__ + ":" in (ROOT / "RELEASE-NOTES.md").read_text()


async def test_frozen_verification_reads_every_log_page_including_final_receipts(tmp_path):
    from p2plab.journal import Journal
    from p2plab.server import Hub

    journal = Journal(tmp_path / "central.sqlite3", role="server", room="release", console=False)
    runner = web.AppRunner(Hub(journal, admin_token="admin").app())
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    token = tmp_path / "admin.token"
    token.write_text("admin")
    try:
        for index in range(1005):
            journal.event("experiment.result", index=index)
        journal.event("client.stopped")
        journal.event("unrelated-room", room="other")
        assert len(journal.query(room="release", limit=10000)) == 1000
        events = await read_room_events(f"http://127.0.0.1:{port}", token, tmp_path / "central.log.gz")
        assert sum(e["event"] == "experiment.result" for e in events) == 1005
        assert sum(e["event"] == "client.stopped" for e in events) == 1
        assert len({e["cursor"] for e in events}) == len(events)
        assert all(e["room"] == "release" for e in events)
    finally:
        await runner.cleanup()
        journal.close()


@pytest.mark.asyncio
async def test_windows_frozen_cleanup_targets_only_test_process_tree(monkeypatch):
    import tools.smoke_frozen as frozen

    process = SimpleNamespace(pid=1234, returncode=None, wait=AsyncMock(), terminate=Mock(), kill=Mock())
    run = Mock(return_value=SimpleNamespace(returncode=0))
    monkeypatch.setattr(frozen.sys, "platform", "win32")
    monkeypatch.setattr(frozen.subprocess, "run", run)
    await stop_process(process)
    run.assert_called_once_with(["taskkill.exe", "/PID", "1234", "/T", "/F"],
                                capture_output=True, timeout=10, check=False)
    process.terminate.assert_not_called()
    process.wait.assert_awaited_once()


@pytest.mark.asyncio
async def test_frozen_cleanup_does_not_signal_exited_process(monkeypatch):
    import tools.smoke_frozen as frozen

    process = SimpleNamespace(pid=1234, returncode=0, wait=AsyncMock(), terminate=Mock(), kill=Mock())
    run = Mock()
    monkeypatch.setattr(frozen.sys, "platform", "win32")
    monkeypatch.setattr(frozen.subprocess, "run", run)
    await stop_process(process)
    run.assert_not_called()
    process.wait.assert_not_called()


@pytest.mark.asyncio
async def test_frozen_log_cleanup_cancels_stuck_pipe_and_fails():
    pump = asyncio.create_task(asyncio.Event().wait())
    with pytest.raises(RuntimeError, match="log pipes"):
        await finish_pumps([pump], timeout=0.01)
    assert pump.cancelled()


def test_both_specs_are_actual_onefile_and_do_not_collect_device_data():
    for role in ("client", "server"):
        source = (ROOT / f"packaging/{role}.spec").read_text()
        tree = ast.parse(source)
        calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call)]
        assert not any(isinstance(node.func, ast.Name) and node.func.id == "COLLECT" for node in calls)
        executable = next(node for node in calls if isinstance(node.func, ast.Name) and node.func.id == "EXE")
        assert [ast.unparse(arg) for arg in executable.args] == ["pyz", "a.scripts", "a.binaries", "a.datas"]
        assert "client.sqlite3" not in source and "admin.token" not in source and "client.local.toml" not in source


def test_release_checksums_cover_all_assets_and_exclude_checksum_files(tmp_path):
    binary = tmp_path / "P2PLab-Client-linux-x64"
    binary.write_bytes(b"single executable")
    (tmp_path / "SHA256SUMS-old.txt").write_text("old checksums")
    write_checksums(tmp_path)
    assert (tmp_path / "SHA256SUMS.txt").read_text() == (
        hashlib.sha256(binary.read_bytes()).hexdigest() + "  P2PLab-Client-linux-x64\n"
    )


def test_license_inventory_contains_exact_versions_and_only_license_related_files(tmp_path, monkeypatch):
    import tools.build_release as build

    root = tmp_path / "root"
    root.mkdir()
    (root / "requirements.lock").write_text("# locked\ndemo==1.2.3\n    # comment\n")
    (root / "LICENSE").write_text("MIT license")
    stdlib = tmp_path / "stdlib"
    stdlib.mkdir()
    (stdlib / "LICENSE.txt").write_text("Python license")
    installed = tmp_path / "installed"
    installed.mkdir()
    (installed / "LICENSE.txt").write_text("Original dependency license")
    (installed / "device.key").write_text("must not publish")

    class Metadata:
        def get(self, key):
            return "MIT" if key == "License-Expression" else None

        def get_all(self, key, default):
            return ["Source, https://example.org/demo"]

    distribution = SimpleNamespace(
        version="1.2.3", metadata=Metadata(), files=[Path("LICENSE.txt"), Path("device.key")],
        locate_file=lambda file: installed / file,
    )
    monkeypatch.setattr(build, "ROOT", root)
    monkeypatch.setattr(build.metadata, "distribution", lambda name: distribution)
    monkeypatch.setattr(build.sysconfig, "get_path", lambda name: str(stdlib))
    destination = tmp_path / "licenses"
    inventory = collect_licenses(destination)
    assert inventory[0]["version"] == "1.2.3"
    assert inventory[0]["license_files"] == ["demo/LICENSE.txt"]
    assert (destination / "PYTHON-LICENSE.txt").read_text() == "Python license"
    assert not list(destination.rglob("device.key"))
    assert json.loads((destination / "dependencies.json").read_text()) == inventory
