import asyncio
import socket
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest

from p2plab.client import Client
from p2plab.experiments import Experiments
from p2plab.network import (
    address_fingerprint,
    address_rejection,
    read_address_inventory,
    select_addresses,
    snapshot,
)


def address(number, *, temporary=False, **fields):
    return {
        "address": f"2606:4700::{number}",
        "family": 6,
        "interface": "eth0",
        "interface_up": True,
        "type": "temporary" if temporary else "stable",
        "temporary": temporary,
        "state": "preferred",
        "valid_lifetime": 7200.0,
        "preferred_lifetime": 3600.0,
        "observed_monotonic": time.monotonic(),
        **fields,
    }


class Evidence:
    def __init__(self):
        self.events = []

    def event(self, name, *args, **fields):
        self.events.append((name, fields))


@pytest.fixture
def kernel(monkeypatch):
    rows = [
        {
            "family": "inet6",
            "local": "2606:4700::1",
            "temporary": True,
            "deprecated": True,
            "valid_life_time": 300,
            "preferred_life_time": 0,
        },
        {
            "family": "inet6",
            "local": "2606:4700::2",
            "temporary": True,
            "tentative": True,
            "valid_life_time": 1800,
            "preferred_life_time": 900,
        },
        {
            "family": "inet6",
            "local": "2606:4700::3",
            "temporary": True,
            "valid_life_time": 1800,
            "preferred_life_time": 900,
        },
        {"family": "inet6", "local": "2606:4700::4", "valid_life_time": 7200, "preferred_life_time": 3600},
        {
            "family": "inet",
            "local": "192.168.1.10",
            "valid_life_time": 4294967295,
            "preferred_life_time": 4294967295,
        },
    ]
    interfaces = [
        {"ifname": "eth0", "flags": ["UP"], "mtu": 1500, "address": "aa:bb:cc:dd:ee:ff", "addr_info": rows}
    ]
    for row in rows:
        row["prefixlen"] = 64 if row["family"] == "inet6" else 24
    stats = {"eth0": SimpleNamespace(isup=True, mtu=1500)}
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Linux")
    monkeypatch.setattr("p2plab.network.psutil.net_if_stats", lambda: stats)
    monkeypatch.setattr("p2plab.network.psutil.net_if_addrs", lambda: {})

    async def command(*args, **kwargs):
        if "address" in args:
            output = interfaces
        elif "show" in args and "-4" in args:
            output = [{"dst": "default", "gateway": "192.168.1.1", "dev": "eth0"}]
        elif "show" in args and "-6" in args:
            output = [{"dst": "default", "gateway": "fe80::1", "dev": "eth0"}]
        else:
            output = []
        return {"state": "completed", "output": deepcopy(output)}

    monkeypatch.setattr("p2plab.network.command", command)
    return interfaces, stats


async def test_snapshot_filters_states_before_budgets_and_preserves_both_ipv6_types(kernel):
    log = Evidence()
    result = await snapshot(log, server_host="127.0.0.1", external=False, maximum=4)
    assert [r["address"] for r in result["addresses"]] == ["2606:4700::4", "192.168.1.10", "2606:4700::3"]
    inventory = result["address_inventory"]
    assert len(inventory) == 5
    assert inventory[0]["temporary"] is True
    assert inventory[0]["deprecated"] is True
    assert inventory[0]["type"] == "temporary"
    assert inventory[0]["state"] == "deprecated"
    assert inventory[3]["prefix"] == "2606:4700::/64"
    assert {r["reason"] for r in result["excluded_addresses"]} == {"ADDRESS_DEPRECATED", "ADDRESS_TENTATIVE"}
    inbound = select_addresses(inventory, inbound=True, maximum=2)
    assert [r["type"] for r in inbound] == ["stable", "temporary"]
    assert [r["local"] for r in result["gateways6"]] == ["2606:4700::4", "2606:4700::3"]
    assert "aa:bb:cc:dd:ee:ff" not in str(result)
    assert kernel[0][0]["address"] == "aa:bb:cc:dd:ee:ff"
    assert any(name == "network.address_inventory" for name, _ in log.events)


@pytest.mark.parametrize(
    ("fields", "reason"),
    [
        ({"tentative": True}, "ADDRESS_TENTATIVE"),
        ({"dadfailed": True}, "ADDRESS_DADFAILED"),
        ({"deprecated": True}, "ADDRESS_DEPRECATED"),
        ({"valid_lifetime": 0}, "ADDRESS_EXPIRED"),
        ({"preferred_lifetime": 0}, "ADDRESS_DEPRECATED"),
        ({"interface_up": False}, "INTERFACE_DOWN"),
        ({"valid_lifetime": 10}, "ADDRESS_LIFETIME_TOO_SHORT"),
        ({"preferred_lifetime": 10}, "ADDRESS_LIFETIME_TOO_SHORT"),
        ({"state": "unverified"}, "IPV6_STATE_UNVERIFIED"),
    ],
)
def test_ineligible_ipv6_cannot_take_candidate_slots(fields, reason):
    record = address(1, **fields)
    assert address_rejection(record) == reason
    assert select_addresses([record]) == []
    assert select_addresses([record], inbound=True) == []


def test_lifetimes_age_and_state_only_changes_are_detected():
    record = address(1, preferred_lifetime=40)
    before = address_fingerprint([record])
    assert address_rejection(record, now=record["observed_monotonic"] + 11) == "ADDRESS_LIFETIME_TOO_SHORT"
    assert address_rejection(record, now=record["observed_monotonic"] + 41) == "ADDRESS_DEPRECATED"
    assert address_fingerprint([{**record, "deprecated": True}]) != before
    assert address_rejection(address(2, valid_lifetime=None, preferred_lifetime=None)) is None


def test_candidate_budget_reserves_families_types_and_other_nics():
    records = [address(i, temporary=True) for i in range(1, 20)]
    records += [address(20), address(21, interface="eth1")]
    records.append({"family": 4, "address": "192.168.1.10", "interface": "eth0", "state": "preferred"})
    selected = select_addresses(records, maximum=4)
    assert len(selected) == 4
    assert any(r["family"] == 4 for r in selected)
    assert any(r.get("type") == "temporary" for r in selected)
    assert any(r.get("type") == "stable" for r in selected)
    assert any(r["interface"] == "eth1" for r in selected)
    assert [r["type"] for r in select_addresses(records, inbound=True, maximum=2)] == ["stable", "temporary"]


def test_same_address_on_different_nics_keeps_eligible_record():
    records = [address(1, tentative=True), address(1, interface="eth1")]
    assert select_addresses(records)[0]["interface"] == "eth1"


def test_global_temporary_is_preferred_over_ula_stable_when_budget_is_tight():
    records = [address(1, address="fd00::1"), address(2, temporary=True)]
    assert select_addresses(records, maximum=1)[0]["address"] == "2606:4700::2"


async def test_kernel_flags_and_forever_lifetimes(kernel):
    rows = kernel[0][0]["addr_info"]
    rows[0].pop("temporary")
    rows[0].pop("deprecated")
    rows[0]["flags"] = ["temporary", "deprecated"]
    rows[3]["valid_life_time"] = "forever"
    rows[3]["preferred_life_time"] = 4294967295
    inventory, _ = await read_address_inventory()
    assert inventory[0]["temporary"] and inventory[0]["deprecated"]
    assert inventory[3]["valid_lifetime"] is None
    assert inventory[3]["preferred_lifetime"] is None


async def test_down_interface_addresses_are_retained_but_not_selected(kernel):
    kernel[0][0]["flags"] = []
    inventory, _ = await read_address_inventory()
    assert len(inventory) == 5
    assert select_addresses(inventory) == []
    assert all(address_rejection(r) == "INTERFACE_DOWN" for r in inventory)


async def test_missing_kernel_evidence_does_not_assume_ipv6_is_stable(kernel, monkeypatch):
    monkeypatch.setattr(
        "p2plab.network.psutil.net_if_addrs",
        lambda: {"eth0": [SimpleNamespace(family=socket.AF_INET6, address="2606:4700::1", netmask=None)]},
    )

    async def missing(*args, **kwargs):
        return {"state": "unsupported", "reason": "COMMAND_MISSING"}

    monkeypatch.setattr("p2plab.network.command", missing)
    inventory, evidence = await read_address_inventory()
    assert inventory[0]["type"] == "unverified"
    assert select_addresses(inventory) == []
    assert evidence["reason"] == "COMMAND_MISSING"


@pytest.mark.parametrize(
    "new_fields",
    [
        None,
        {"tentative": True},
        {"dadfailed": True},
        {"deprecated": True},
        {"valid_lifetime": 0},
        {"interface_up": False},
    ],
    ids=["removed", "tentative", "dadfailed", "deprecated", "expired", "nic-down"],
)
async def test_http_revalidates_and_never_binds_an_ineligible_address(tmp_path, monkeypatch, new_fields):
    client = Client({"data_dir": str(tmp_path / "client")}, "test", console=False)

    async def absent(**kwargs):
        return ([] if new_fields is None else [address(1, **new_fields)]), {"state": "completed"}

    def must_not_bind(*args, **kwargs):
        pytest.fail("Ineligible IPv6 address must not be bound")

    monkeypatch.setattr("p2plab.client.read_address_inventory", absent)
    monkeypatch.setattr("p2plab.common.new_socket", must_not_bind)
    try:
        assert await client.inbound_http_probe("2606:4700::1", "session", expected=address(1)) is False
        result = client.log.query()[-1]
        assert result["fields"]["code"] == "LOCAL_ADDRESS_NOT_AVAILABLE"
        assert result["fields"]["firewall_assessment"] == "NOT_TESTED"
        assert not client.reach_requests
    finally:
        await client.close()


@pytest.mark.parametrize("rotate_during_checks", [False, True], ids=["before-plan", "between-checks"])
async def test_http_rotation_uses_fresh_temporary_and_stable_addresses(
    tmp_path, monkeypatch, rotate_during_checks
):
    client = Client(
        {"data_dir": str(tmp_path / "client"), "experiment": {"max_addresses": 1}}, "test", console=False
    )
    old = [address(1), address(2, temporary=True)]
    fresh = [address(1), address(3, temporary=True)]
    calls = []

    async def inventory(**kwargs):
        return (old if rotate_during_checks and not calls else fresh), {"state": "completed"}

    async def probe(host, session, *, expected=None):
        calls.append((host, expected["type"]))
        return True

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr(client, "inbound_http_probe", probe)
    try:
        client.inbound_supported = True
        client.peer_id = "session"
        client.network = {"address_inventory": old, "addresses": [old[0]]}
        client.network_ready.set()
        await client.inbound_check()
        assert calls == [("2606:4700::1", "stable"), ("2606:4700::3", "temporary")]
        assert len(client.network["addresses"]) == 1
        assert len(client.network["address_inventory"]) == 2
        assert any(row["event"] == "network.address_selection_refreshed" for row in client.log.query())
    finally:
        await client.close()


async def test_local_bind_failures_have_bounded_retries(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client")}, "test", console=False)
    calls = []

    async def inventory(**kwargs):
        return [address(i) for i in range(1, 20)], {"state": "completed"}

    async def probe(host, session, **kwargs):
        calls.append(host)
        return False

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr(client, "inbound_http_probe", probe)
    try:
        client.inbound_supported = True
        client.network_ready.set()
        await asyncio.wait_for(client.inbound_check(), 2)
        assert len(calls) == 8
    finally:
        await client.close()


async def test_ipv6_p2p_attempt_checks_state_before_creating_transport(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client")}, "test", console=False)
    manager = Experiments(client)
    spec = {"attempt": "invalid-local", "method": "udp", "host": "2606:4700::1", "phase": "baseline"}
    manager.plan = [spec]
    signals = []

    async def inventory(**kwargs):
        return [address(1, tentative=True)], {"state": "completed"}

    async def signal(body):
        signals.append(body)

    def transport(*args, **kwargs):
        pytest.fail("Tentative address must be rejected before creating a UDP transport")

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr("p2plab.experiments.UdpAttempt", transport)
    monkeypatch.setattr(client, "signal", signal)
    try:
        await manager.execute(spec, 0)
        assert manager.results[0]["state"] == "not-applicable"
        assert "LOCAL_IPV6_ADDRESS_UNAVAILABLE:ADDRESS_TENTATIVE" in manager.results[0]["reason"]
        assert signals[-1]["kind"] == "done"
    finally:
        await manager.close()
        await client.close()
