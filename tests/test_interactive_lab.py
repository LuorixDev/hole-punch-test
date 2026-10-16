import os
import sys
import tomllib

import pytest

from tools.interactive_lab import (
    namespace_command,
    process_alive,
    process_record,
    server_command,
    update_state,
    write_config,
)

pytestmark = pytest.mark.skipif(
    sys.platform != "linux",
    reason="The interactive lab drives Linux namespaces, /proc and konsole",
)


def test_process_identity_detects_missing_or_reused_pid():
    record = process_record(os.getpid())
    assert process_alive(record)
    assert not process_alive({**record, "start_ticks": "not-the-original-process"})
    assert not process_alive({})


def test_namespace_entry_rejects_host_and_stale_targets():
    record = process_record(os.getpid())
    state = {"host_netns": record["netns"], "namespaces": {"server": record}}
    with pytest.raises(RuntimeError, match="NOT_ISOLATED"):
        namespace_command(state, "server", ["true"])
    state["host_netns"] = "net:[different]"
    command = namespace_command(state, "server", ["true"])
    assert command[:4] == ["nsenter", "-t", str(os.getpid()), "-U"]
    assert "--preserve-credentials" in command
    state["namespaces"]["server"] = {**record, "start_ticks": "wrong"}
    with pytest.raises(RuntimeError, match="NAMESPACE_MISSING"):
        namespace_command(state, "server", ["true"])


def test_state_updates_preserve_each_node_and_do_not_rewrite_other_records(tmp_path):
    update_state(tmp_path, ready=True, data_root=str(tmp_path), nodes={"server": {"pid": 1}})
    state = update_state(tmp_path, nodes={"client-a": {"pid": 2}})
    assert state["ready"] is True
    assert state["data_root"] == str(tmp_path)
    assert state["nodes"] == {"server": {"pid": 1}, "client-a": {"pid": 2}}


@pytest.mark.parametrize("smoke", [True, False])
def test_generated_client_configs_are_valid_and_have_no_internet_diagnostics(tmp_path, smoke):
    path = write_config(tmp_path, "client-a", smoke=smoke)
    with path.open("rb") as source:
        config = tomllib.load(source)
    assert config["allow_insecure"] is True
    assert config["server"] == "ws://198.51.100.1:8443/ws"
    assert config["experiment"]["diagnostics"] is False
    assert config["experiment"]["stun"] == []
    assert config["experiment"]["gateway"] is not smoke
    assert config["experiment"]["profiles"] == (["fast"] if smoke else ["balanced", "fast", "staggered"])
    if smoke:
        assert config["experiment"]["comprehensive"] is False
        assert config["experiment"]["auto_retry"] is False
    else:
        assert "comprehensive" not in config["experiment"]
        assert "auto_retry" not in config["experiment"]
    assert str(tmp_path) in config["data_dir"]


def test_demo_server_uses_plain_ws_and_bounded_ipv6_target_prefixes(tmp_path):
    command = list(map(str, server_command(tmp_path)))
    assert "0.0.0.0" in command
    assert command[command.index("--stun-host") + 1] == "198.51.100.1"
    assert "--cert" not in command and "--key" not in command
    assert command.count("--inbound-prefix") == 2
    assert "2001:db9:a::/64" in command and "2001:db9:b::/64" in command
