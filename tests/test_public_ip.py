import asyncio

import pytest
from aiohttp import web
from textual.widgets import DataTable, Static

from p2plab.network import http_ip_summary, parse_ip_response, query_ip, query_public_ips, snapshot
from p2plab.status import public_ip_evidence, validate_status
from p2plab.tui import P2PApp


@pytest.mark.parametrize(("provider", "raw", "family", "expected"), [
    ("3322", b"1.1.1.1\n", 4, "1.1.1.1"),
    ("ipw", b"240e::1\n", 6, "240e::1"),
    ("neu6", b"2408:8000::1", 6, "2408:8000::1"),
    ("oray", b"Current IP Address: 1.1.1.1", 4, "1.1.1.1"),
    ("oray", b"<html><head><title>Current IP Check</title></head>"
             b"<body>Current IP Address: 1.1.1.1</body></html>", 4, "1.1.1.1"),
])
def test_domestic_api_formats_are_explicit(provider, raw, family, expected):
    assert parse_ip_response(provider, raw, family) == expected


@pytest.mark.parametrize(("provider", "raw", "family"), [
    ("3322", b"<html>8.8.8.8</html>", 4),
    ("oray", b"<html><body>Please login: 8.8.8.8</body></html>", 4),
    ("oray", b"<html><body>Current IP Address: 8.8.8.8<script></script></body></html>", 4),
    ("oray", b"<html><body>Current IP Address: 8.8.8.8", 4),
    ("oray", b"<html><body>Current IP Address: 8.8.8.8</body></html>extra", 4),
    ("oray", b"Current IP Address: 8.8.8.8 1.1.1.1", 4),
    ("ipw", b"240e::1", 4),
    ("neu6", b"8.8.8.8", 6),
    ("neu6", b"240e::1%eth0", 6),
    ("ipw", b"fe80::1", 6),
    ("ipw", b"ff0e::1", 6),
    ("3322", b"224.0.0.1", 4),
    ("3322", b"192.168.1.1", 4),
    ("3322", b"100.64.1.1", 4),
    ("3322", b"198.18.0.2", 4),
    ("3322", b"\xff", 4),
])
def test_private_wrong_family_captive_portal_and_scoped_addresses_rejected(provider, raw, family):
    with pytest.raises(ValueError):
        parse_ip_response(provider, raw, family)


@pytest.mark.parametrize(("status", "body", "state", "retryable"), [
    (200, "Current IP Address: 1.1.1.1", "observed", False),
    (200, "<html>Login required</html>", "unavailable", False),
    (200, "x" * 513, "unavailable", False),
    (302, "Current IP Address: 1.1.1.1", "unavailable", False),
    (503, "unavailable", "unavailable", True),
    (429, "slow down", "unavailable", False),
])
async def test_domestic_http_response_validation_and_environment_proxy_ignored(
    status, body, state, retryable, monkeypatch,
):
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    monkeypatch.setenv("NO_PROXY", "")

    async def handler(request):
        return web.Response(text=body, status=status, headers={"Location": "/other"} if status == 302 else {})

    app = web.Application()
    app.router.add_get("/", handler)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    try:
        port = site._server.sockets[0].getsockname()[1]
        result = await query_ip("oray", f"http://127.0.0.1:{port}/", 4)
        assert result["state"] == state
        assert result.get("retryable", False) is retryable
        assert result["region"] == "domestic"
        if state == "observed":
            assert result["address"] == "1.1.1.1"
            assert result["evidence"] == "https-egress-not-udp-mapping"
    finally:
        await runner.cleanup()


async def test_bounded_domestic_retry_keeps_failed_request_and_does_not_skip_other_providers(monkeypatch):
    import p2plab.network as network

    calls = {}

    async def query(provider, url, family):
        calls[provider] = calls.get(provider, 0) + 1
        await asyncio.sleep(0)
        result = {"provider": provider, "family": family}
        if provider == "3322" and calls[provider] == 2:
            return {**result, "state": "observed", "address": "1.1.1.1"}
        return {**result, "state": "unavailable", "reason": "TimeoutError", "retryable": True}

    monkeypatch.setattr(network, "query_ip", query)
    monkeypatch.setattr(network, "IP_PROVIDERS", (
        ("3322", "https://ip.3322.net", 4), ("ipw", "https://6.ipw.cn", 6),
        ("aws", "https://checkip.amazonaws.com", 4),
    ))
    results = await query_public_ips()
    assert calls == {"3322": 2, "ipw": 2, "aws": 1}
    assert results[0]["state"] == "observed"
    assert results[0]["attempts"][0]["reason"] == "TimeoutError"
    assert len(results[1]["attempts"]) == 2
    assert len(results[2]["attempts"]) == 1


async def test_bad_payload_is_not_retried_and_domestic_failure_does_not_block_foreign_fallback(monkeypatch):
    import p2plab.network as network

    async def query(provider, url, family):
        if provider in network.DOMESTIC_IP_PROVIDERS:
            return {"provider": provider, "family": family, "state": "unavailable",
                    "reason": "IP_QUERY_RESPONSE_FORMAT", "retryable": False}
        return {"provider": provider, "family": family, "state": "observed",
                "address": "8.8.8.8" if family == 4 else "2606:4700::1"}

    monkeypatch.setattr(network, "query_ip", query)
    results = await query_public_ips()
    assert len(results) == len(network.IP_PROVIDERS)
    assert all(len(r["attempts"]) == 1 for r in results)
    assert any(r["state"] == "observed" and r["family"] == 4 for r in results)


def test_corroboration_counts_providers_not_retries_and_preserves_conflicting_addresses():
    def row(provider, address, family=4):
        return {"provider": provider, "address": address, "family": family, "state": "observed"}

    domestic = row("3322", "1.1.1.1")
    assert http_ip_summary([domestic, domestic], [])["4"]["state"] == "single-provider"
    rows = [domestic, row("oray", "1.1.1.1")]
    assert http_ip_summary(rows, [])["4"]["state"] == "corroborated"
    rows += [row("aws", "8.8.8.8"), row("ipw", "240e::1", 6)]
    result = http_ip_summary(rows, [])
    assert result["4"]["state"] == "multiple-egresses"
    assert len(result["4"]["addresses"]) == 2
    assert result["6"]["not_in_local_inventory"] == ["240e::1"]


async def test_http_ipv6_never_promoted_to_local_punching_candidate_and_evidence_is_logged(monkeypatch):
    import p2plab.network as network

    class Evidence:
        events = []

        def event(self, name, *args, **fields):
            self.events.append((name, fields))

    async def inventory(**kwargs):
        return [], {"state": "completed", "output": []}

    async def command(*args, **kwargs):
        return {"state": "completed", "output": []}

    async def public_ips():
        return [{"provider": "ipw", "family": 6, "state": "observed", "address": "240e::1"}]

    monkeypatch.setattr(network.platform, "system", lambda: "Linux")
    monkeypatch.setattr(network, "read_address_inventory", inventory)
    monkeypatch.setattr(network, "command", command)
    monkeypatch.setattr(network, "query_public_ips", public_ips)
    journal = Evidence()
    result = await snapshot(journal, server_host="127.0.0.1")
    assert result["addresses"] == [] and result["address_inventory"] == []
    assert result["http_ip_summary"]["6"]["not_in_local_inventory"] == ["240e::1"]
    assert any(event == "network.http_ip_summary" for event, _ in journal.events)


async def test_same_address_preserves_http_and_signaling_sources_and_logs_before_pairing(peers):
    client, _ = peers
    client.server_observed_ipv4 = "1.1.1.1"
    client.network["http_observations"] = [
        {"provider": "3322", "family": 4, "state": "observed", "address": "1.1.1.1"},
        {"provider": "oray", "family": 4, "state": "observed", "address": "1.1.1.1"},
    ]
    status = validate_status(client.network_status())
    assert len(status["public_ips"]) == 2
    assert {r["source"] for r in status["public_ips"]} == {"http", "signaling"}
    assert public_ip_evidence(status)["4"]["state"] == "observed"
    await client.publish_status()
    await client.publish_status()
    assert len([e for e in client.log.query() if e["event"] == "network.ip_sources"]) == 1


async def test_signaling_fallback_survives_all_api_failures_and_status_budget(peers):
    client, _ = peers
    client.server_observed_ipv4 = "1.1.1.1"
    client.network["http_observations"] = [{"state": "unavailable", "family": 4}]
    assert client.network_status()["public_ips"] == [
        {"address": "1.1.1.1", "family": 4, "source": "signaling"},
    ]
    client.network["http_observations"] = [
        {"state": "observed", "family": 4, "address": f"8.8.8.{i}"} for i in range(1, 15)
    ]
    result = validate_status(client.network_status())
    assert len(result["public_ips"]) == 8 and result["public_ips"][0]["source"] == "signaling"


async def test_closed_client_does_not_write_ip_evidence_to_closed_journal(peers):
    client, _ = peers
    await client.close()
    client.server_observed_ipv4 = "8.8.8.8"
    await client.publish_status()


async def test_tui_shows_conflicting_egresses_and_separate_signaling_observation(peers):
    client, _ = peers
    client.server_observed_ipv4 = "8.8.8.8"
    client.network["http_observations"] = [
        {"provider": "3322", "family": 4, "region": "domestic", "state": "observed", "address": "1.1.1.1"},
    ]
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        banner = str(app.query_one("#network-banner", Static).content)
        assert all(word in banner for word in ("出口不一致", "信令 8.8.8.8", "HTTP出口 1.1.1.1"))
        app.action_tab("network")
        await pilot.pause()
        table = app.query_one("#public-ips", DataTable)
        assert "信令" in str(table.get_row("0"))
        assert "国内适用" in str(table.get_row("1"))
