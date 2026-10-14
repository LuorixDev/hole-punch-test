import asyncio
import copy
import datetime as dt
from types import SimpleNamespace

import aiohttp
import pytest

from p2plab.network import command
from p2plab.status import direction_reference, speed_assessment, utcnow, validate_status
from p2plab.wan import discover_servers, measure, parse_result, sources
from tests.test_server import cleanup_hub, join, start_hub


def status(*, upload=100, download=1000, family=6, basis="measured"):
    address = "2001:4860::1" if family == 6 else "192.168.1.2"
    return {
        "addresses": [{"address": address, "family": family, "interface": "eth0", "type": "stable"}],
        "public_ips": [],
        "inbound": [],
        "updated_at": utcnow(),
        "wan": {
            "state": "measured",
            "families": {
                str(family): {
                    "upload_mbps": upload,
                    "download_mbps": download,
                    "basis": basis,
                    "source": address,
                    "interface": "eth0",
                    "measured_at": utcnow(),
                }
            },
        },
    }


def test_both_endpoints_and_direction_and_family_control_ninety_percent():
    local, remote = status(upload=100, download=1000), status(upload=50, download=80)
    up = direction_reference(local, remote, 6, "local-to-peer")
    down = direction_reference(local, remote, 6, "peer-to-local")
    assert up["mbps"] == 80 and down["mbps"] == 50
    assert direction_reference(local, remote, 4, "local-to-peer") is None
    assert speed_assessment({"mbps": 72, "seconds": 2}, up)["state"] == "near-limit"
    assert speed_assessment({"mbps": 71.9, "seconds": 2}, up)["state"] == "below-limit"
    assert speed_assessment({"mbps": 200, "seconds": 2}, up)["state"] == "above-reference"
    assert speed_assessment({"mbps": 80, "seconds": 0.2, "short_sample": True}, up) is None
    assert speed_assessment({"mbps": 80, "seconds": 2}, None) is None


def test_nat64_reference_uses_ipv6_and_ipv4_endpoint_limits_independently(peers, monkeypatch):
    a, _ = peers
    local, remote = status(family=6, upload=100, download=1000), status(family=4, upload=50, download=80)
    assert direction_reference(local, remote, 6, "local-to-peer") is None
    up = direction_reference(local, remote, 6, "local-to-peer", peer_family=4)
    down = direction_reference(local, remote, 6, "peer-to-local", peer_family=4)
    assert up["mbps"] == 80 and down["mbps"] == 50
    a.peer_network = remote
    monkeypatch.setattr(a, "network_status", lambda: local)
    a.managers = [SimpleNamespace(plan=[{"attempt": "cross-family", "method": "nat64",
        "a_host": local["addresses"][0]["address"], "b_host": remote["addresses"][0]["address"]}])]
    path = SimpleNamespace(attempt="cross-family", family=6)
    assert a.path_reference(path, "local-to-peer")["mbps"] == 80
    assert a.path_reference(path, "peer-to-local")["mbps"] == 50
    assert speed_assessment({"mbps": 72, "seconds": 2}, up)["state"] == "near-limit"


@pytest.mark.parametrize("location", ["updated_at", "measured_at"])
def test_expired_or_missing_remote_baselines_are_not_eligible(location):
    local, remote = status(), status()
    old = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).isoformat()
    if location == "updated_at":
        remote[location] = old
    else:
        remote["wan"]["families"]["6"][location] = old
    assert direction_reference(local, remote, 6, "local-to-peer") is None
    assert direction_reference(local, {}, 6, "local-to-peer") is None


@pytest.mark.parametrize(
    "mutation",
    [
        lambda s: s.update(chat="not-a-relay"),
        lambda s: s["addresses"][0].update(payload="not-a-relay"),
        lambda s: s["addresses"][0].update(address="not-ip"),
        lambda s: s["addresses"][0].update(family=4),
        lambda s: s.update(addresses=s["addresses"] * 17),
        lambda s: s["wan"]["families"]["6"].update(upload_mbps=float("nan")),
        lambda s: s["wan"]["families"]["6"].update(download_mbps=-1),
        lambda s: s["wan"].update(families={"7": {}}),
        lambda s: s.update(updated_at="bad"),
    ],
)
def test_diagnostic_signal_schema_rejects_unbounded_or_non_diagnostic_data(mutation):
    s = status()
    validate_status(s)
    mutation(s)
    with pytest.raises(ValueError):
        validate_status(s)


def test_librespeed_mbps_are_not_bytes_per_second_and_missing_direction_is_rejected():
    raw = [{"upload": 100, "download": 900, "bytes_sent": 10000000, "bytes_received": 90000000}]
    assert parse_result(raw)["download"] == 900
    for bad in ([], {}, [{**raw[0], "upload": 0}], [{**raw[0], "bytes_sent": 0}]):
        with pytest.raises(ValueError):
            parse_result(bad)


def test_wan_source_uses_default_interface_and_preferred_ipv6():
    def address(host, family, interface, **kw):
        return {"address": host, "family": family, "interface": interface, "state": "preferred", **kw}

    network = {
        "address_inventory": [
            address("192.168.2.2", 4, "vpn"),
            address("192.168.1.2", 4, "eth0"),
            address("2001:4860::2", 6, "eth0", temporary=True),
            address("2001:4860::1", 6, "eth0"),
            address("2001:4860::3", 6, "eth0", deprecated=True),
        ],
        "gateways": [{"interface": "eth0"}],
        "gateways6": [{"interface": "eth0"}],
    }
    assert [r["address"] for r in sources(network)] == ["192.168.1.2", "2001:4860::1"]


async def test_wan_cli_arguments_raw_logs_best_directions_and_proxy_bypass(monkeypatch, tmp_path):
    import p2plab.wan as wan
    from p2plab.journal import Journal

    calls = []

    async def discovery(source, journal, **options):
        return [{"id": i, "server": "https://example.org", "name": str(i)} for i in (1, 2)]

    async def run(*args, **options):
        calls.append((args, options))
        i = int(args[args.index("--server") + 1])
        return {
            "state": "completed",
            "output": [
                {"upload": i * 100, "download": 1000 / i, "bytes_sent": 1000000, "bytes_received": 10000000}
            ],
        }

    monkeypatch.setenv("HTTPS_PROXY", "http://proxy.invalid:123")
    monkeypatch.setattr(wan, "executable", lambda opts: "/bin/librespeed-cli")
    monkeypatch.setattr(wan, "discover_servers", discovery)
    monkeypatch.setattr(wan, "command", run)
    journal = Journal(tmp_path / "wan.sqlite3", role="client", console=False)
    try:
        result = await measure(
            {
                "address_inventory": [
                    {"address": "2001:4860::1", "family": 6, "state": "preferred", "interface": "eth0"}
                ]
            },
            {},
            journal,
        )
        assert result["state"] == "measured"
        assert result["families"]["6"]["upload_mbps"] == 200
        assert result["families"]["6"]["download_mbps"] == 1000
        assert len(calls) == 2
        for args, opts in calls:
            assert "--ipv6" in args and "--source" in args and "--json" in args
            assert args[args.index("--telemetry-level") + 1] == "disabled"
            assert not any("proxy" in k.lower() for k in opts["env"])
            assert opts["timeout"] <= 55
        assert sum(e["event"] == "wan.cli_output" for e in journal.query()) == 2
        assert sum(e["event"] == "wan.sample" for e in journal.query()) == 2
    finally:
        journal.close()


async def test_disabled_isolated_startup_never_runs_external_speedtest(peers, monkeypatch):
    client, _ = peers
    client.network_ready.set()

    async def never(*args):
        raise AssertionError("External traffic in isolated lab")

    monkeypatch.setattr("p2plab.client.measure_wan", never)
    await client.startup_wan()
    assert client.wan_result["state"] == "not-tested"


async def test_network_status_uses_existing_pair_signal_and_is_centralized(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    try:
        async with aiohttp.ClientSession() as session:
            a, _ = await join(session, url, tmp_path / "a")
            await a.receive_json()
            b, _ = await join(session, url, tmp_path / "b")
            pa, pb = await asyncio.gather(a.receive_json(), b.receive_json())
            metadata = status()
            await a.send_json(
                {
                    "v": 1,
                    "type": "signal",
                    "pair": pa["pair"],
                    "data": {"kind": "network_status", "attempt": "network-0", "status": metadata},
                }
            )
            received = await asyncio.wait_for(b.receive_json(), 3)
            assert received["pair"] == pb["pair"]
            assert received["data"]["status"] == metadata
            invalid = copy.deepcopy(metadata)
            invalid["chat"] = "must-not-relay"
            await a.send_json(
                {
                    "v": 1,
                    "type": "signal",
                    "pair": pa["pair"],
                    "data": {"kind": "network_status", "attempt": "network-0", "status": invalid},
                }
            )
            assert (await a.receive_json())["code"] == "INVALID_NETWORK_STATUS_FIELDS"
            await a.close()
            await b.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_reference_does_not_compare_another_interface_or_unknown_ice_path(peers):
    client, _ = peers
    client.network = {
        "address_inventory": [
            {
                "address": "2001:4860::1",
                "family": 6,
                "interface": "eth0",
                "state": "preferred",
                "type": "stable",
            }
        ]
    }
    client.peer_network = status()
    client.wan_result = {"state": "measured", "families": status()["wan"]["families"]}
    path = SimpleNamespace(attempt="path", family=6)
    spec = {"attempt": "path", "a_host": "2001:4860::1", "b_host": "2001:4860::1"}
    client.managers = [SimpleNamespace(plan=[spec])]
    assert client.path_reference(path, "local-to-peer")["mbps"] == 100
    client.peer_network["wan"]["families"]["6"]["interface"] = "vpn"
    assert client.path_reference(path, "local-to-peer") is None
    client.managers = []
    assert client.path_reference(path, "local-to-peer") is None


async def test_command_timeout_kills_subprocess_and_limits_output():
    import sys

    result = await command(sys.executable, "-c", "import time; time.sleep(10)", timeout=0.05)
    assert result["state"] == "failed" and "TimeoutError" in result["reason"]
    result = await command(sys.executable, "-c", "print('x'*10000)", limit=100)
    assert result["state"] == "failed" and "COMMAND_OUTPUT_LIMIT" in result["reason"]


@pytest.mark.parametrize("oversized", [False, True])
async def test_wan_server_list_reads_fragmented_response_to_eof(tmp_path, monkeypatch, oversized):
    from aiohttp import web

    from p2plab.journal import Journal

    async def handler(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"[")
        await asyncio.sleep(0.03)
        await response.write(b" " * (131072 if oversized else 5000) + b"]")
        await response.write_eof()
        return response

    app = web.Application()
    app.router.add_get("/list", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    monkeypatch.setattr("p2plab.wan.SERVER_LIST", f"http://127.0.0.1:{port}/list")
    journal = Journal(tmp_path / "list.sqlite3", role="client", console=False)
    try:
        source = {"address": "127.0.0.1", "family": 4}
        if oversized:
            with pytest.raises(ValueError, match="WAN_SERVER_LIST_LIMIT"):
                await discover_servers(source, journal)
        else:
            assert await discover_servers(source, journal) == []
    finally:
        await runner.cleanup()
        journal.close()


async def test_wan_revalidates_rotated_source_before_cli_start(tmp_path, monkeypatch):
    import p2plab.wan as wan
    from p2plab.journal import Journal

    checked = []

    async def validate(host, *, expected):
        checked.append(host)
        if len(checked) == 2:
            raise ValueError("LOCAL_IPV6_ADDRESS_UNAVAILABLE:ADDRESS_REMOVED_OR_INTERFACE_CHANGED")

    async def discover(*args, **kwargs):
        return [{"id": 1, "server": "https://example.org"}]

    async def never(*args, **kwargs):
        pytest.fail("Removed source must not start a speedtest process")

    monkeypatch.setattr(wan, "executable", lambda options: "librespeed-cli")
    monkeypatch.setattr(wan, "discover_servers", discover)
    monkeypatch.setattr(wan, "command", never)
    journal = Journal(tmp_path / "rotation.sqlite3", role="client", console=False)
    try:
        result = await measure({"address_inventory": [
            {"address": "240e::1", "family": 6, "interface": "eth0", "state": "preferred"},
        ]}, {}, journal, validate_source=validate)
        assert result["state"] == "failed" and result["families"] == {}
        assert checked == ["240e::1", "240e::1"]
        assert any("ADDRESS_REMOVED" in r["message"] for r in journal.query())
    finally:
        journal.close()


async def test_client_wan_refreshes_startup_inventory_before_selecting_source(peers, monkeypatch):
    client, _ = peers
    client.loopback = False
    client.diagnostics_enabled = True
    client.network = {"address_inventory": [
        {"address": "10.255.115.19", "family": 4, "interface": "vpn", "state": "preferred"},
    ]}
    current = [{"address": "192.168.0.5", "family": 4, "interface": "eth0", "state": "preferred"}]

    async def inventory(**kwargs):
        return current, {"state": "completed"}

    async def measure(network, options, journal, *, validate_source):
        assert network["address_inventory"] == current
        assert validate_source == client.validate_local_address
        return {"state": "failed", "families": {}, "reason": "CONTROLLED_TEST"}

    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    monkeypatch.setattr("p2plab.client.measure_wan", measure)
    await client.test_wan()
    assert client.wan_result["reason"] == "CONTROLLED_TEST"


async def test_real_librespeed_binary_against_controlled_local_backend(tmp_path):
    import os

    from aiohttp import web

    from p2plab.wan import executable

    cli = executable({})
    if not cli:
        pytest.skip("Optional LibreSpeed binary is not installed")
    block = os.urandom(65536)
    received = 0

    async def empty(request):
        nonlocal received
        while chunk := await request.content.read(65536):
            received += len(chunk)
        return web.Response()

    async def download(request):
        return web.Response(body=block, content_type="application/octet-stream")

    async def ip_info(request):
        return web.json_response(
            {"processedString": "controlled-loopback-not-WAN", "rawIspInfo": {"ip": "127.0.0.1"}}
        )

    app = web.Application(client_max_size=16 * 1024 * 1024)
    app.router.add_route("*", "/empty.php", empty)
    app.router.add_get("/garbage.php", download)
    app.router.add_get("/getIP.php", ip_info)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    servers = tmp_path / "servers.json"
    import json

    servers.write_text(
        json.dumps(
            [
                {
                    "id": 1,
                    "name": "controlled-local-only",
                    "server": f"http://127.0.0.1:{port}/",
                    "dlURL": "garbage.php",
                    "ulURL": "empty.php",
                    "pingURL": "empty.php",
                    "getIpURL": "getIP.php",
                }
            ]
        )
    )
    try:
        raw = await command(
            cli,
            "--json",
            "--no-icmp",
            "--telemetry-level",
            "disabled",
            "--ipv4",
            "--source",
            "127.0.0.1",
            "--local-json",
            str(servers),
            "--server",
            "1",
            "--duration",
            "3",
            "--timeout",
            "2",
            "--concurrent",
            "3",
            timeout=30,
        )
        assert raw["state"] == "completed", raw
        row = parse_result(raw["output"])
        assert row["upload"] > 0 and row["download"] > 0 and received > 0
        assert row["server"]["name"] == "controlled-local-only"
    finally:
        await runner.cleanup()
