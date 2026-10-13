import ast
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

from tools.build_release import collect_licenses, write_checksums

ROOT = Path(__file__).resolve().parents[1]


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
