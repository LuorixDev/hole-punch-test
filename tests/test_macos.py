import json
import os
import socket
import sys
from types import SimpleNamespace

import pytest

from p2plab import network
from p2plab.network import (
    address_rejection,
    darwin_routes,
    lifetimes_reported,
    parse_ifconfig,
    parse_netstat_defaults,
    parse_route_get,
    path_route_backend,
    path_route_evidence,
    read_address_inventory,
    select_addresses,
    snapshot,
    system_tool,
)
from p2plab.runtime import application_directory, default_client_data
from tests.test_network import Evidence

# Captured from `ifconfig -a` on macOS 26 (arm64) and reduced to the address lines whose handling
# matters: a link-local that must never become a candidate, IPv4 with a hex netmask, a
# point-to-point interface, and every IPv6 flag the kernel can set on an address.
IFCONFIG = """
lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
\toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
\tinet 127.0.0.1 netmask 0xff000000
\tinet6 ::1 prefixlen 128 
\tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1 
\tnd6 options=201<PERFORMNUD,DAD>
gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
stf0: flags=0<> mtu 1280
en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\toptions=6460<TSO4,TSO6,CHANNEL_IO,PARTIAL_CSUM,ZEROINVERT_CSUM>
\tether 22:d6:11:3f:22:85
\tinet6 fe80::cba:cc95:e00c:49f1%en0 prefixlen 64 secured scopeid 0xe 
\tinet 10.8.6.93 netmask 0xffff0000 broadcast 10.8.255.255
\tinet6 2606:4700:4700::1111 prefixlen 64 autoconf secured 
\tinet6 2606:4700:4700::2222 prefixlen 64 autoconf temporary 
\tinet6 2606:4700:4700::3333 prefixlen 64 tentative 
\tinet6 2606:4700:4700::4444 prefixlen 64 dadfailed 
\tinet6 2606:4700:4700::5555 prefixlen 64 autoconf deprecated 
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: autoselect
\tstatus: active
en5: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether 5e:9d:6c:27:21:17
\tinet6 2606:4700:4700::6666 prefixlen 64 autoconf 
\tnd6 options=201<PERFORMNUD,DAD>
\tmedia: none
\tstatus: inactive
utun8: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
bridge100: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
\tether ae:07:75:a2:a4:64
\tConfiguration:
\t\tid 0:0:0:0:0:0 priority 0 hellotime 0 fwddelay 0
\tmember: en1 flags=3<LEARNING,DISCOVER>
\t        ifmaxaddr 0 port 10 priority 0 path cost 0
\tinet 192.168.139.3 netmask 0xfffffe00 broadcast 192.168.139.255
\tinet6 fe80::ac07:75ff:fea2:a464%bridge100 prefixlen 64 scopeid 0x18 
\tmedia: <unknown type>
\tstatus: active
"""
NETSTAT_INET = """Routing tables

Internet:
Destination        Gateway            Flags               Netif Expire
default            10.8.1.254         UGScg                 en0       
default            link#24            UCSIg           bridge100      !
1                  198.18.0.1         UGSc                utun8       
127                127.0.0.1          UCS                   lo0       
224.0.0/4          link#14            UmCS                  en0       !
"""
NETSTAT_INET6 = """Routing tables

Internet6:
Destination                             Gateway                                 Flags               Netif Expire
default                                 fe80::1%en0                             UGcIg                 en0       
default                                 fe80::%utun0                            UGcIg               utun0       
::1                                     ::1                                     UHL                   lo0       
fe80::%lo0/64                           fe80::1%lo0                             UcI                   lo0       
ff00::/8                                link#14                                 UmCI                  en0       
"""
ROUTE_GET = """   route to: 1.1.1.1
destination: 1.0.0.0
       mask: 255.0.0.0
    gateway: 10.8.1.254
  interface: en0
      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING>
 recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       0         0         0         0         0         0      1500         0 
"""
ROUTE_NOT_IN_TABLE = "route: writing to routing socket: not in table\n"


def by_address(records):
    return {record["address"]: record for record in records}


@pytest.fixture
def macos_network(monkeypatch):
    """Serve the captured macOS command output; nothing here touches the host network."""
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")
    calls = []

    async def command(*args, **kwargs):
        calls.append(args)
        name = os.path.basename(args[0])
        if name == "ifconfig":
            return {
                "command": list(args),
                "state": "completed",
                "returncode": 0,
                "stderr": "",
                "output": IFCONFIG,
            }
        if name == "netstat":
            output = NETSTAT_INET6 if args[-1] == "inet6" else NETSTAT_INET
            return {
                "command": list(args),
                "state": "completed",
                "returncode": 0,
                "stderr": "",
                "output": output,
            }
        if name == "route":
            return {
                "command": list(args),
                "state": "completed",
                "returncode": 0,
                "stderr": "",
                "output": ROUTE_GET,
            }
        if name in ("ping", "traceroute"):
            return {"command": list(args), "state": "completed", "returncode": 0, "stderr": "", "output": ""}
        pytest.fail(f"Unexpected macOS command: {args}")

    monkeypatch.setattr("p2plab.network.command", command)
    return calls


def test_ifconfig_flags_ipv6_state_without_inventing_lifetimes():
    records = parse_ifconfig(IFCONFIG)
    found = by_address(records)
    assert set(found) == {
        "10.8.6.93",
        "192.168.139.3",
        "2606:4700:4700::1111",
        "2606:4700:4700::2222",
        "2606:4700:4700::3333",
        "2606:4700:4700::4444",
        "2606:4700:4700::5555",
        "2606:4700:4700::6666",
    }
    assert found["2606:4700:4700::1111"]["state"] == "preferred"
    assert found["2606:4700:4700::1111"]["type"] == "stable"
    assert found["2606:4700:4700::2222"]["state"] == "preferred"
    assert found["2606:4700:4700::2222"]["type"] == "temporary"
    assert found["2606:4700:4700::2222"]["temporary"] is True
    assert found["2606:4700:4700::3333"]["state"] == "tentative"
    assert found["2606:4700:4700::4444"]["state"] == "dadfailed"
    assert found["2606:4700:4700::5555"]["state"] == "deprecated"
    assert found["2606:4700:4700::5555"]["deprecated"] is True
    # ifconfig reports no lifetimes, so every record must say so instead of claiming "forever".
    assert all(record["valid_lifetime"] is None for record in records)
    assert all(record["preferred_lifetime"] is None for record in records)
    assert all(record["lifetime_source"] == "unreported" for record in records)
    assert all(not lifetimes_reported(record) for record in records)
    assert all(record["source"] == "darwin-ifconfig" for record in records)
    assert found["2606:4700:4700::1111"]["neighbor_discovery"] == "PERFORMNUD,DAD"
    assert "neighbor_discovery" not in found["10.8.6.93"]
    # IPv4 keeps its hex netmask as a prefix length; link-local and multicast stay out entirely.
    assert found["10.8.6.93"]["prefixlen"] == 16
    assert found["10.8.6.93"]["prefix"] == "10.8.0.0/16"
    assert not any("fe80::" in address or "::1" == address for address in found)
    # A point-to-point interface or an inactive one must not look like a usable P2P source.
    assert "198.18.0.1" not in found  # benchmark/utun range is excluded for every platform
    assert found["2606:4700:4700::6666"]["interface"] == "en5"
    assert found["2606:4700:4700::6666"]["interface_up"] is False


def test_ifconfig_loopback_collection_is_explicit():
    found = by_address(parse_ifconfig(IFCONFIG, loopback=True))
    assert set(found) == {"127.0.0.1", "::1"}


def test_darwin_records_select_ipv6_instead_of_rejecting_it_as_unverified():
    inventory = parse_ifconfig(IFCONFIG)
    selected = {record["address"] for record in select_addresses(inventory, maximum=4)}
    assert selected == {"10.8.6.93", "192.168.139.3", "2606:4700:4700::1111", "2606:4700:4700::2222"}
    reasons = {record["address"]: address_rejection(record) for record in inventory}
    assert "IPV6_STATE_UNVERIFIED" not in set(reasons.values())
    assert reasons["2606:4700:4700::3333"] == "ADDRESS_TENTATIVE"
    assert reasons["2606:4700:4700::4444"] == "ADDRESS_DADFAILED"
    assert reasons["2606:4700:4700::5555"] == "ADDRESS_DEPRECATED"
    assert reasons["2606:4700:4700::6666"] == "INTERFACE_DOWN"


def test_ifconfig_without_a_usable_netmask_keeps_the_address_but_states_nothing():
    records = parse_ifconfig("en0: flags=8863<UP,BROADCAST> mtu 1500\n\tinet 10.0.0.5\n")
    assert len(records) == 1
    assert records[0]["address"] == "10.0.0.5"
    assert records[0]["prefixlen"] is None and "prefix" not in records[0]


def test_ifconfig_absent_flags_never_become_a_guess():
    assert parse_ifconfig("") == []
    assert parse_ifconfig("not an interface listing at all\n") == []


def test_netstat_defaults_skip_kernel_only_and_interface_gateways():
    ipv4 = parse_netstat_defaults(NETSTAT_INET)
    assert ipv4 == [
        {
            "dst": "default",
            "gateway": "10.8.1.254",
            "dev": "en0",
            "metric": None,
            "flags": "UGScg",
            "scoped_gateway": "10.8.1.254",
        }
    ]
    ipv6 = parse_netstat_defaults(NETSTAT_INET6)
    assert [(route["gateway"], route["dev"]) for route in ipv6] == [
        ("fe80::1", "en0"),
        ("fe80::", "utun0"),
    ]
    assert ipv6[1]["scoped_gateway"] == "fe80::%utun0"


def test_route_get_text_is_structured_and_missing_routes_are_not_tested():
    assert parse_route_get(ROUTE_GET) == {
        "route_to": "1.1.1.1",
        "destination": "1.0.0.0",
        "mask": "255.0.0.0",
        "gateway": "10.8.1.254",
        "interface": "en0",
        "flags": "UP,GATEWAY,DONE,STATIC,PRCLONING",
    }
    assert parse_route_get(ROUTE_NOT_IN_TABLE) is None


async def test_snapshot_on_macos_populates_addresses_gateways_and_server_route(macos_network):
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert [record["source"] for record in result["address_inventory"]] == ["darwin-ifconfig"] * 8
    assert [gateway["gateway"] for gateway in result["gateways"]] == ["10.8.1.254"]
    assert (result["gateways"][0]["interface"], result["gateways"][0]["local"]) == ("en0", "10.8.6.93")
    assert [gateway["gateway"] for gateway in result["gateways6"]] == ["fe80::1", "fe80::1"]
    assert {gateway["local"] for gateway in result["gateways6"]} == {
        "2606:4700:4700::1111",
        "2606:4700:4700::2222",
    }
    assert result["ipv6_status"] == "GLOBAL_ADDRESS_PRESENT"
    assert not [r for r in result["excluded_addresses"] if r["reason"] == "IPV6_STATE_UNVERIFIED"]
    assert result["system_commands"][0]["state"] == "completed"
    assert (
        result["system_commands"][1]["family"] == "inet" and result["system_commands"][2]["family"] == "inet6"
    )
    assert result["system_commands"][3]["output"]["gateway"] == "10.8.1.254"
    assert result["system_commands"][3]["resolution"]["state"] == "literal"


async def test_macos_active_commands_use_macos_argument_forms(macos_network, monkeypatch):
    async def no_public_ips():
        return []

    monkeypatch.setattr("p2plab.network.query_public_ips", no_public_ips)
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=True)
    assert [(os.path.basename(call[0]), *call[1:]) for call in macos_network if "127.0.0.1" in call] == [
        ("route", "-n", "get", "127.0.0.1"),
        ("ping", "-n", "-c", "1", "-W", "2000", "127.0.0.1"),
        ("traceroute", "-n", "-w", "1", "-q", "1", "-m", "5", "127.0.0.1"),
    ]
    assert len(result["active_commands"]) == 2


async def test_macos_ipv6_server_route_is_unsupported_not_a_fabricated_answer(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")
    result = await network.route_to_server("2606:4700:4700::1111")
    assert result["state"] == "unsupported"
    assert result["reason"] == "DARWIN_ROUTE_GET_IPV6_UNSUPPORTED"
    assert result["resolution"] == {
        "host": "2606:4700:4700::1111",
        "state": "literal",
        "addresses": ["2606:4700:4700::1111"],
    }


async def test_macos_missing_route_entry_is_not_tested(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")

    async def command(*args, **kwargs):
        return {
            "command": list(args),
            "state": "completed",
            "returncode": 0,
            "stderr": ROUTE_NOT_IN_TABLE,
            "output": "",
        }

    monkeypatch.setattr("p2plab.network.command", command)
    result = await network.route_to_server("192.0.2.10")
    assert result["state"] == "not-tested" and result["reason"] == "DARWIN_ROUTE_NOT_IN_TABLE"
    assert "not in table" in result["stderr"]


async def test_unparsed_ifconfig_falls_back_to_psutil_without_claiming_ipv6_state(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")
    monkeypatch.setattr(
        "p2plab.network.psutil.net_if_stats", lambda: {"en0": SimpleNamespace(isup=True, mtu=1500)}
    )
    monkeypatch.setattr(
        "p2plab.network.psutil.net_if_addrs",
        lambda: {
            "en0": [
                SimpleNamespace(family=socket.AF_INET6, address="2606:4700:4700::1111", netmask=None),
            ]
        },
    )

    async def command(*args, **kwargs):
        return {
            "command": list(args),
            "state": "completed",
            "returncode": 0,
            "stderr": "",
            "output": "en0: <a format this parser does not know>\n",
        }

    monkeypatch.setattr("p2plab.network.command", command)
    inventory, evidence = await read_address_inventory()
    assert evidence["reason"] == "DARWIN_IFCONFIG_UNPARSED"
    assert [record["state"] for record in inventory] == ["unverified"]
    assert select_addresses(inventory) == []


async def test_missing_macos_tools_are_diagnostic_not_a_startup_failure(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")
    monkeypatch.setattr("p2plab.network.psutil.net_if_addrs", lambda: {})
    monkeypatch.setattr("p2plab.network.psutil.net_if_stats", lambda: {})

    async def missing(*args, **kwargs):
        return {"command": list(args), "state": "unsupported", "reason": "COMMAND_MISSING"}

    monkeypatch.setattr("p2plab.network.command", missing)
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert result["system_commands"][0]["reason"] == "COMMAND_MISSING"
    assert result["addresses"] == [] and result["gateways"] == [] and result["gateways6"] == []
    assert result["ipv6_status"] == "NO_USABLE_GLOBAL_V6_NOT_A_FIREWALL_VERDICT"


async def test_other_posix_systems_keep_their_explicit_unsupported_reason(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "FreeBSD")
    monkeypatch.setattr("p2plab.network.psutil.net_if_addrs", lambda: {})
    monkeypatch.setattr("p2plab.network.psutil.net_if_stats", lambda: {})
    inventory, evidence = await read_address_inventory()
    assert inventory == [] and evidence["reason"] == "LINUX_STRUCTURED_ADDRESS_ONLY"
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert result["system_commands"] == [{"state": "unsupported", "reason": "LINUX_STRUCTURED_ROUTE_ONLY"}]
    assert result["addresses"] == []


def test_lifetimes_reported_distinguishes_unreported_from_forever():
    assert lifetimes_reported({"valid_lifetime": None, "preferred_lifetime": None}) is True
    assert lifetimes_reported({"lifetime_source": "unreported"}) is False


def test_system_tool_falls_back_outside_a_restricted_path(monkeypatch):
    def which(name, path=None):
        return "/usr/sbin/netstat" if path else None

    monkeypatch.setattr("p2plab.network.shutil.which", which)
    assert system_tool("netstat") == "/usr/sbin/netstat"
    monkeypatch.setattr("p2plab.network.shutil.which", lambda name, path=None: None)
    assert system_tool("netstat") == "netstat"


async def test_darwin_routes_never_claim_gateways_when_netstat_is_missing(monkeypatch):
    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Darwin")

    async def missing(*args, **kwargs):
        return {"command": list(args), "state": "unsupported", "reason": "COMMAND_MISSING"}

    monkeypatch.setattr("p2plab.network.command", missing)
    assert [
        {key: value for key, value in route.items() if key in ("state", "reason", "output")}
        for route in await darwin_routes()
    ] == [
        {"state": "unsupported", "reason": "COMMAND_MISSING", "output": []},
        {"state": "unsupported", "reason": "COMMAND_MISSING", "output": []},
    ]


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires an actual macOS host")
async def test_native_darwin_read_only_network_snapshot():
    result = await snapshot(Evidence(), server_host="127.0.0.1", external=False)
    assert result["system_commands"][0]["state"] == "completed", json.dumps(result["system_commands"])
    assert result["address_inventory"]
    assert all(record["source"] == "darwin-ifconfig" for record in result["address_inventory"])
    assert result["system_commands"][1]["state"] == "completed"
    assert result["system_commands"][2]["state"] == "completed"
    assert not [r for r in result["excluded_addresses"] if r["reason"] == "IPV6_STATE_UNVERIFIED"]


def frozen(system, tmp_path):
    return SimpleNamespace(frozen=True, platform=system, executable=str(tmp_path / "bundle/P2PLab-Client"))


def test_frozen_macos_paths_use_application_support(tmp_path, monkeypatch):
    """macOS keeps writable state where Apple puts it, not in the Linux XDG location."""
    monkeypatch.setattr("p2plab.runtime.sys", frozen("darwin", tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.delenv("XDG_DATA_HOME", raising=False)
    assert application_directory() == tmp_path / "bundle"
    assert default_client_data() == tmp_path / "home/Library/Application Support/P2PLab/client"


def test_frozen_macos_data_still_honours_an_explicit_xdg_home(tmp_path, monkeypatch):
    """An explicitly exported XDG_DATA_HOME is a deliberate choice, so it still wins on macOS."""
    monkeypatch.setattr("p2plab.runtime.sys", frozen("darwin", tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_client_data() == tmp_path / "xdg/P2PLab/client"


def test_frozen_linux_data_still_uses_xdg(tmp_path, monkeypatch):
    monkeypatch.setattr("p2plab.runtime.sys", frozen("linux", tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert default_client_data() == tmp_path / "xdg/P2PLab/client"


def test_path_route_backend_selects_a_tool_per_platform():
    assert path_route_backend("linux") == "linux-ip-route"
    assert path_route_backend("darwin") == "darwin-route-get"
    assert path_route_backend("win32") is None
    assert path_route_backend("freebsd13") is None


async def test_darwin_path_route_evidence_reports_the_kernel_route(macos_network):
    """The route macOS would actually use, with the honest caveat that it cannot be source-pinned."""
    result = await path_route_evidence("198.51.100.7", "192.0.2.9")
    assert result["state"] == "completed"
    assert result["output"]["gateway"] == "10.8.1.254"
    assert result["output"]["interface"] == "en0"
    assert result["source"] == "192.0.2.9"
    assert result["source_scoped"] is False


async def test_darwin_path_route_evidence_is_honest_about_ipv6(macos_network):
    result = await path_route_evidence("2606:4700:4700::1111", "192.0.2.9")
    assert result["state"] == "unsupported"
    assert result["reason"] == "DARWIN_ROUTE_GET_IPV6_UNSUPPORTED"


async def test_path_route_evidence_is_absent_where_no_backend_exists(monkeypatch):
    async def never(*args, **kwargs):
        pytest.fail("a platform without a route tool must not run one")

    monkeypatch.setattr("p2plab.network.platform.system", lambda: "Windows")
    monkeypatch.setattr("p2plab.network.command", never)
    assert await path_route_evidence("198.51.100.7", "192.0.2.9") is None


async def test_darwin_path_route_evidence_degrades_on_a_non_address(macos_network):
    """Diagnostic evidence must never turn into an experiment failure."""
    result = await path_route_evidence("peer.example", "192.0.2.9")
    assert result["state"] == "not-tested"
    assert result["reason"] == "ROUTE_TARGET_NOT_AN_ADDRESS"
