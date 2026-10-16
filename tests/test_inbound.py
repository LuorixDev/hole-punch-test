import errno
import secrets
import socket
import sys
from types import SimpleNamespace

import aiohttp
import pytest

from p2plab.client import Client, main
from p2plab.common import Identity
from p2plab.journal import Journal
from p2plab.server import Hub


@pytest.fixture
def callback(tmp_path, monkeypatch):
    log = Journal(tmp_path / "central.db", role="server", console=False)
    hub = Hub(log, admin_token="admin", allow_inbound=True, inbound_prefixes=["2606:4700::/32"])
    identity = Identity(tmp_path / "identity")
    peer = {
        "id": "session",
        "pair": "may-change-during-check",
        "public": identity.public,
        "source": "127.0.0.1",
        "room": "callback",
        "checks": 0,
        "reach_requests": set(),
    }
    body = {
        "address": "2606:4700::1111",
        "port": 12345,
        "request": secrets.token_hex(12),
        "token": secrets.token_urlsafe(24),
    }
    body["proof"] = identity.sign({"session": peer["id"], **body})
    results = []

    async def send(peer, result):
        results.append(result)

    monkeypatch.setattr(hub, "send", send)
    yield hub, peer, body, results
    identity.close()
    log.close()


@pytest.mark.parametrize(
    ("os_errno", "code"),
    [
        (None, "TIMEOUT_INCONCLUSIVE"),
        (errno.ENETUNREACH, "OBSERVER_NO_ROUTE"),
        (errno.EADDRNOTAVAIL, "OBSERVER_SOURCE_UNAVAILABLE"),
        (errno.EHOSTUNREACH, "OBSERVER_OR_DESTINATION_UNREACHABLE"),
        (errno.ECONNREFUSED, "CONNECTION_REFUSED"),
        (errno.EACCES, "CONNECT_FAILED"),
    ],
)
async def test_callback_network_failures_are_not_firewall_verdicts(callback, monkeypatch, os_errno, code):
    hub, peer, body, results = callback

    def failed_get(*args, **kwargs):
        if os_errno is None:
            raise TimeoutError()
        key = SimpleNamespace(host=body["address"], port=body["port"], ssl=False)
        raise aiohttp.ClientConnectorError(key, OSError(os_errno, "simulated-connect-failure"))

    monkeypatch.setattr(aiohttp.ClientSession, "get", failed_get)
    await hub.inbound(peer, body)
    result = results[0]
    assert result["code"] == code
    assert result["firewall_assessment"] == "INCONCLUSIVE"
    assert result["address"] == body["address"]
    assert result["elapsed_ms"] >= 0
    assert result.get("os_errno") == os_errno
    records = hub.log.query(room=peer["room"])
    assert any(row["event"] == "ipv6.inbound_started" for row in records)
    assert records[-1]["fields"]["code"] == code
    assert body["token"] not in str(records)


@pytest.mark.parametrize("bad_target", ["127.0.0.1", "::1", "2001:db8::1", "2607:f8b0::1"])
async def test_callback_policy_rejection_never_connects(callback, monkeypatch, bad_target):
    hub, peer, body, results = callback
    body["address"] = bad_target

    def forbidden_get(*args, **kwargs):
        pytest.fail("Policy-rejected targets must not receive network requests")

    monkeypatch.setattr(aiohttp.ClientSession, "get", forbidden_get)
    await hub.inbound(peer, body)
    assert results[0]["code"] == "REJECTED_BY_POLICY"
    assert results[0]["firewall_assessment"] == "NOT_TESTED"
    assert peer["checks"] == 0


@pytest.mark.parametrize("address", ["2606:4700::1111", "2607:f8b0::1"])
async def test_callback_without_prefix_restriction_accepts_global_ipv6(
    callback, monkeypatch, tmp_path, address
):
    hub, peer, body, results = callback
    hub.inbound_prefixes = []
    identity = Identity(tmp_path / "unrestricted-identity")
    peer["public"] = identity.public
    body["address"] = address
    body["proof"] = identity.sign(
        {"session": peer["id"], **{key: value for key, value in body.items() if key != "proof"}}
    )
    calls = []

    class Response:
        status = 204
        headers = {"X-P2P-Token": body["token"]}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    def get(self, url, **kwargs):
        calls.append(url)
        return Response()

    monkeypatch.setattr(aiohttp.ClientSession, "get", get)
    try:
        await hub.inbound(peer, body)
        assert results[-1]["code"] == "REACHABLE"
        assert calls == [f"http://[{address}]:12345/reach"]
        assert peer["checks"] == 1
    finally:
        identity.close()


@pytest.mark.parametrize("address", ["::1", "fe80::1", "fd00::1", "ff02::1", "::", "2001:db8::1"])
async def test_callback_without_prefix_restriction_still_rejects_non_global_ipv6(
    callback, monkeypatch, address
):
    hub, peer, body, results = callback
    hub.inbound_prefixes = []
    body["address"] = address

    def forbidden_get(*args, **kwargs):
        pytest.fail("Non-global targets must not receive network requests")

    monkeypatch.setattr(aiohttp.ClientSession, "get", forbidden_get)
    await hub.inbound(peer, body)
    assert results[-1]["code"] == "REJECTED_BY_POLICY"
    assert peer["checks"] == 0


async def test_callback_without_prefix_restriction_remains_disabled_unless_enabled(callback, monkeypatch):
    hub, peer, body, results = callback
    hub.inbound_prefixes = []
    hub.allow_inbound = False

    def forbidden_get(*args, **kwargs):
        pytest.fail("Disabled callbacks must not receive network requests")

    monkeypatch.setattr(aiohttp.ClientSession, "get", forbidden_get)
    await hub.inbound(peer, body)
    assert results[-1]["code"] == "REJECTED_BY_POLICY"
    assert "INBOUND_DISABLED" in results[-1]["detail"]


@pytest.mark.parametrize("source,forwarded", [("192.168.1.88", False), ("100.71.69.142", False),
                                              ("8.8.8.8", True)])
async def test_ipv4_callback_never_targets_forwarder_or_private_origin(callback, monkeypatch, source, forwarded):
    hub, peer, body, results = callback
    peer["source"] = body["address"] = source
    hub.forwarded = forwarded

    def never(*args, **kwargs):
        pytest.fail("Forwarded/private origin is not a client public inbound target")

    monkeypatch.setattr(aiohttp.ClientSession, "get", never)
    await hub.inbound(peer, body)
    assert results[-1]["code"] == "REJECTED_BY_POLICY"
    assert results[-1]["firewall_assessment"] == "NOT_TESTED"


async def test_callback_missing_echo_is_not_success_and_replay_is_rejected(callback, monkeypatch):
    hub, peer, body, results = callback
    calls = []

    class Response:
        status, headers = 204, {}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    def get(*args, **kwargs):
        calls.append(kwargs)
        return Response()

    monkeypatch.setattr(aiohttp.ClientSession, "get", get)
    await hub.inbound(peer, body)
    assert results[0]["code"] == "TOKEN_MISMATCH"
    assert results[0]["firewall_assessment"] == "INCONCLUSIVE"
    await hub.inbound(peer, body)
    assert results[1]["code"] == "REJECTED_BY_POLICY"
    assert "REPLAYED_REQUEST" in results[1]["detail"]
    assert len(calls) == 1
    assert calls[0]["allow_redirects"] is False


async def test_callback_proof_is_bound_to_signaling_session(callback, monkeypatch):
    hub, peer, body, results = callback
    peer["id"] = "new-session"

    def forbidden_get(*args, **kwargs):
        pytest.fail("Invalid proof must not trigger a network request")

    monkeypatch.setattr(aiohttp.ClientSession, "get", forbidden_get)
    await hub.inbound(peer, body)
    assert results[0]["code"] == "REJECTED_BY_POLICY"
    assert "PROOF_MISMATCH" in results[0]["detail"]


async def test_ipv4_callback_only_targets_observed_origin_and_has_separate_budget(
    callback, monkeypatch, tmp_path
):
    hub, peer, body, results = callback
    identity = Identity(tmp_path / "v4-identity")
    peer["source"] = "8.8.8.8"
    peer["public"] = identity.public
    original = dict(body)
    original["proof"] = identity.sign(
        {"session": peer["id"], **{k: v for k, v in original.items() if k != "proof"}}
    )
    calls = []

    class Response:
        status = 204
        headers = {"X-P2P-Token": body["token"]}

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

    def get(self, url, **kwargs):
        calls.append(url)
        return Response()

    monkeypatch.setattr(aiohttp.ClientSession, "get", get)
    try:
        body["address"] = "1.1.1.1"
        body["proof"] = identity.sign(
            {"session": peer["id"], **{k: v for k, v in body.items() if k != "proof"}}
        )
        await hub.inbound(peer, body)
        assert results[-1]["code"] == "REJECTED_BY_POLICY" and not calls
        body["address"] = peer["source"]
        body["proof"] = identity.sign(
            {"session": peer["id"], **{k: v for k, v in body.items() if k != "proof"}}
        )
        await hub.inbound(peer, body)
        assert results[-1]["code"] == "REACHABLE", results[-1].get("detail")
        assert calls == ["http://8.8.8.8:12345/reach"]
        assert peer["checks4"] == 1 and peer["checks"] == 0
        await hub.inbound(peer, body)
        assert results[-1]["code"] == "REJECTED_BY_POLICY"
        await hub.inbound(peer, original)
        assert "REPLAYED_REQUEST" in results[-1]["detail"]
    finally:
        identity.close()


async def test_client_selects_global_ipv6_and_bounds_callback_count(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client")}, "test", console=False)
    calls = []

    async def probe(host, session, **kwargs):
        calls.append((host, session))
        return True

    async def inventory(**kwargs):
        return client.network["addresses"], {"state": "completed"}

    monkeypatch.setattr(client, "inbound_http_probe", probe)
    monkeypatch.setattr("p2plab.client.read_address_inventory", inventory)
    try:
        client.inbound_supported = True
        client.peer_id = "session"
        client.network = {
            "addresses": [
                {"family": 6, "address": addr, "interface": "eth0", "state": "preferred", "type": "stable"}
                for addr in ["fd00::1", "2606:4700::1", "2606:4700::1", "2606:4700::2", "2606:4700::3"]
            ]
        }
        client.network_ready.set()
        await client.inbound_check()
        assert calls == [("2606:4700::1", "session"), ("2606:4700::2", "session")]
        plan = [row for row in client.log.query() if row["event"] == "ipv6.inbound_plan"][0]
        assert plan["fields"]["untested_addresses"] == ["2606:4700::3"]
        client.network = {
            "addresses": [{"family": 6, "address": "fd00::1", "interface": "eth0", "state": "preferred"}]
        }
        await client.inbound_check()
        assert client.log.query()[-1]["fields"]["firewall_assessment"] == "NOT_TESTED"
    finally:
        await client.close()


async def test_client_listener_rejects_wrong_tokens_and_reuse(tmp_path, monkeypatch):
    client = Client({"data_dir": str(tmp_path / "client"), "loopback": True}, "test", console=False)

    async def control(body):
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(family=socket.AF_INET6)) as session:
            url = f"http://[::1]:{body['port']}/reach"
            for token, status in [("wrong", 403), (body["token"], 204), (body["token"], 403)]:
                async with session.get(url, params={"token": token}) as response:
                    assert response.status == status
        client.reach_requests[body["request"]].set_result({"code": "REACHABLE"})

    monkeypatch.setattr(client, "send_control", control)
    try:
        await client.inbound_http_probe("::1", "session")
        assert client.log.query()[-1]["fields"]["code"] == "REACHABLE"
        assert not client.reach_requests
    finally:
        await client.close()


@pytest.mark.parametrize("code", ["OBSERVER_NO_ROUTE", "TIMEOUT_INCONCLUSIVE", "CONNECTION_REFUSED"])
async def test_client_prints_and_persists_inconclusive_callback_result(tmp_path, monkeypatch, capsys, code):
    client = Client({"data_dir": str(tmp_path / "client"), "loopback": True}, "test")

    async def control(body):
        client.reach_requests[body["request"]].set_result(
            {
                "code": code,
                "elapsed_ms": 1.25,
                "os_errno": errno.ENETUNREACH if code == "OBSERVER_NO_ROUTE" else None,
            }
        )

    monkeypatch.setattr(client, "send_control", control)
    try:
        await client.inbound_http_probe("::1", "session")
        result = client.log.query()[-1]
        assert result["event"] == "ipv6.inbound_result"
        assert result["fields"]["code"] == code
        assert result["fields"]["listener_received"] is False
        assert result["fields"]["firewall_assessment"] == "INCONCLUSIVE"
        assert result["fields"]["observer_elapsed_ms"] == 1.25
        assert code in capsys.readouterr().out
        assert (
            "unknown" in result["message"]
            or "not proven" in result["message"]
            or "possible" in result["message"]
        )
    finally:
        await client.close()


def test_cli_preserves_plaintext_opt_in_from_config(tmp_path, monkeypatch):
    config = tmp_path / "client.toml"
    config.write_text(
        'server = "ws://198.51.100.1:8443/ws"\nallow_insecure = true\n'
        f'data_dir = "{(tmp_path / "client").as_posix()}"\n'
    )
    observed = []

    async def run(client):
        observed.append(client.config["allow_insecure"])
        await client.close()

    monkeypatch.setattr(Client, "run", run)
    monkeypatch.setattr(sys, "argv", ["client.py", "--config", str(config), "--room", "test"])
    main()
    assert observed == [True]
