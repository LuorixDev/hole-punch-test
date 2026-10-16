import asyncio
import socket
import time
from copy import deepcopy
from types import SimpleNamespace

import pytest

from p2plab import network
from p2plab.client import Client
from p2plab.experiments import Experiments
from p2plab.network import (
    address_fingerprint,
    address_rejection,
    read_address_inventory,
    route_to_server,
    select_addresses,
    snapshot,
)


def test_route_priority_preserves_wlan_ipv4_from_real_log_inventory():
    records = [
        address(1, address="2409:8a3c::1", interface="WLAN"),
        address(2, address="2409:8a3c::2", interface="WLAN", type="unverified"),
        address(3, address="192.168.67.1", family=4, interface="以太网 7", preferred_lifetime=None),
        address(4, address="192.168.121.1", family=4, interface="以太网 6", preferred_lifetime=None),
        address(5, address="192.168.1.22", family=4, interface="WLAN"),
    ]
    result = {"system_commands": [{}, {"output": [
        {"dst": "default", "gateway": "192.168.1.1", "dev": "WLAN", "metric": 25},
    ]}, {"output": [
        {"dst": "default", "gateway": "fe80::1", "dev": "WLAN", "metric": 25},
    ]}]}
    network.apply_address_inventory(result, records, maximum=4)
    selected = result["addresses"]
    assert len(selected) == 4
    assert next(r["address"] for r in selected if r["family"] == 4) == "192.168.1.22"
    assert {r["address"] for r in selected if r["family"] == 6} == {"2409:8a3c::1", "2409:8a3c::2"}
    assert result["gateways"] == [{"gateway": "192.168.1.1", "local": "192.168.1.22", "interface": "WLAN"}]
    assert any(r["interface"] != "WLAN" for r in selected)
    assert len(result["address_inventory"]) == 5
    from p2plab.experiments import build_plan

    plan = build_plan([r["address"] for r in selected], ["192.168.1.233", "240e::2"],
                      ["fast"], gateway=False, max_pairs=2)
    assert any(spec["a_host"] == "192.168.1.22" for spec in plan)


def test_route_priority_uses_metric_and_allows_real_virtual_default_exit():
    records = [address(i, address=f"10.0.{i}.2", family=4, interface=interface)
               for i, interface in enumerate(("WLAN", "tunnel", "host-only"), 1)]
    routes = [(4, {"dst": "default", "dev": "WLAN", "metric": 50}),
              (4, {"dst": "default", "dev": "tunnel", "metric": 5})]
    assert select_addresses(records, maximum=1, routes=routes)[0]["interface"] == "tunnel"
    records[1]["interface_up"] = False
    assert select_addresses(records, maximum=1, routes=routes)[0]["interface"] == "WLAN"


async def test_refresh_routes_reselects_exit_without_address_membership_change(peers, monkeypatch):
    client, _ = peers
    records = [address(i, address=f"192.168.{i}.2", family=4, interface=f"nic{i}") for i in (1, 2)]
    client.max_addresses = 1
    client.network = {"address_inventory": records, "system_commands": [{}, {"output": [
        {"dst": "default", "dev": "nic1", "gateway": "192.168.1.1"},
    ]}, {"output": []}]}

    async def inventory(**kwargs):
        return records, {"state": "completed"}

    async def routes():
        return [{"state": "completed", "output": [{"dst": "default", "dev": "nic2", "gateway": "192.168.2.1"}]},
                {"state": "completed", "output": []}]

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr("p2plab.client.read_default_routes", routes)
    await client.refresh_address_inventory(refresh_routes=True)
    assert client.network["addresses"][0]["address"] == "192.168.2.2"
    assert client.network["gateways"][0]["gateway"] == "192.168.2.1"


def test_route_fingerprint_ignores_order_and_nondefault_routes_and_failed_reads():
    rows = [{"dst": "default", "gateway": "192.168.1.1", "dev": "WLAN", "metric": 25},
            {"dst": "default", "gateway": "10.0.0.1", "dev": "tun", "metric": 50}]
    result = {"system_commands": [{}, {"state": "completed", "output": rows}, {"state": "completed", "output": []}]}
    original = network.route_fingerprint(result)
    rows.reverse()
    rows.append({"dst": "192.168.1.0/24", "dev": "WLAN"})
    assert network.route_fingerprint(result) == original
    result["system_commands"][1]["state"] = "failed"
    assert network.route_fingerprint(result) is None


async def test_temporary_route_read_failure_does_not_replace_known_exit(peers, monkeypatch):
    client, _ = peers
    records = [address(1, address="192.168.1.22", family=4, interface="WLAN")]
    routes = [{"state": "completed", "output": [{"dst": "default", "dev": "WLAN", "gateway": "192.168.1.1"}]},
              {"state": "completed", "output": []}]
    client.network = {"system_commands": [{}, *routes]}

    async def inventory(**kwargs):
        return records, {"state": "completed"}

    async def failed():
        return [{"state": "failed", "reason": "TimeoutError"} for _ in range(2)]

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr("p2plab.client.read_default_routes", failed)
    await client.refresh_address_inventory(refresh_routes=True)
    assert client.network["system_commands"][1:] == routes
    assert client.network["gateways"][0]["local"] == "192.168.1.22"


async def test_ipv4_callback_uses_default_exit_even_with_unlimited_inventory(peers, monkeypatch):
    client, _ = peers
    records = [address(1, address="192.168.67.1", family=4, interface="host-only", preferred_lifetime=None),
               address(2, address="192.168.1.22", family=4, interface="WLAN")]
    client.network = {"system_commands": [{}, {"output": [
        {"dst": "default", "dev": "WLAN", "gateway": "192.168.1.1"},
    ]}, {"output": []}]}
    client.inbound_supported = client.inbound_ipv4_supported = True
    client.server_observed_ipv4 = "125.111.10.112"
    client.network_ready.set()
    tested = []

    async def inventory(**kwargs):
        return records, {"state": "completed"}

    async def probe(host, *args, **kwargs):
        tested.append(host)
        return False

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr(client, "inbound_http_probe", probe)
    await client.inbound_check()
    assert tested == ["192.168.1.22"]


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


async def test_server_route_resolves_ipv4_domain_before_calling_ip_and_logs_evidence(kernel, monkeypatch):
    calls = []

    async def resolve(host, port, **options):
        assert host == "server.example" and options["family"] == socket.AF_INET
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("125.111.10.112", 0))]

    original = network.command

    async def run(*args, **options):
        calls.append(args)
        return await original(*args, **options)

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    monkeypatch.setattr("p2plab.network.command", run)
    log = Evidence()
    result = await snapshot(log, server_host="server.example", external=False)
    route = result["system_commands"][3]
    assert ("ip", "-j", "route", "get", "125.111.10.112") in calls
    assert not any("server.example" in args for args in calls)
    assert route["resolution"] == {"host": "server.example", "state": "resolved", "addresses": ["125.111.10.112"]}
    assert any(name == "network.system_commands" and fields["evidence"][3] == route for name, fields in log.events)


@pytest.mark.parametrize("failure", [socket.gaierror("not found"), TimeoutError("DNS timeout"), None])
async def test_server_route_dns_failure_is_recorded_without_running_bad_ip_command(monkeypatch, failure):
    async def resolve(*args, **kwargs):
        if failure:
            raise failure
        return []

    async def never(*args, **kwargs):
        pytest.fail("Unresolved hostname must not reach ip route get")

    monkeypatch.setattr(asyncio.get_running_loop(), "getaddrinfo", resolve)
    monkeypatch.setattr("p2plab.network.command", never)
    result = await route_to_server("server.example")
    assert result["state"] == "not-tested" and result["resolution"]["state"] == "failed"
    assert result["reason"]


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


async def test_path_route_evidence_uses_ip_route_get_on_linux(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Linux")
    calls = []

    async def run(*args, **options):
        calls.append(args)
        return {"command": list(args), "state": "completed", "returncode": 0, "stderr": "", "output": []}

    monkeypatch.setattr("p2plab.network.command", run)
    await network.path_route_evidence("203.0.113.5", "10.0.0.2")
    await network.path_route_evidence("203.0.113.5")
    assert calls == [
        ("ip", "-j", "route", "get", "203.0.113.5", "from", "10.0.0.2"),
        ("ip", "-j", "route", "get", "203.0.113.5"),
    ]
