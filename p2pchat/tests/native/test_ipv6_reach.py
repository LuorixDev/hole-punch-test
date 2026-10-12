"""IPv6 inbound reachability probe: honest verdicts, one-time token, bounded listener.

Real loopback sockets cover the listener/callback paths; RFC 4941 state and routing
are injected where CI cannot provide them (this runner has no global IPv6 address).
Real residential evidence (public v6 prefix, inbound actually allowed) is NOT_RUN.
"""
import asyncio
import ipaddress
import json
import socket
import uuid

import pytest

from p2pchat import server
from p2pchat.backend import telemetry
from p2pchat.native import ipv6_reach as reach

IP_ADDR_SAMPLE = """\
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 state UNKNOWN
    inet6 ::1/128 scope host noprefixroute
       valid_lft forever preferred_lft forever
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet6 2001:db8:1234:5678:1111:2222:3333:4444/64 scope global
       valid_lft forever preferred_lft forever
    inet6 fe80::1/64 scope link
       valid_lft forever preferred_lft forever
3: wlan0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP
    inet6 2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff/64 scope global temporary dynamic
       valid_lft 86390sec preferred_lft 14390sec
    inet6 2001:db8:aaaa:bbbb:1:2:3:4/64 scope global dynamic mngtmpaddr
       valid_lft 2591900sec preferred_lft 604790sec
    inet6 2001:db8:aaaa:bbbb:dead:beef:0:1/64 scope global deprecated
       valid_lft 0sec preferred_lft 0sec
"""


def options(**overrides):
    base = dict(consent=True, connection_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                session=str(uuid.uuid4()), timeout=0.4, allow_temporary=True)
    base.update(overrides)
    return reach.ReachOptions(**base)


def record(address, *, scope="global", temporary=False, prefix=64, deprecated=False, interface="eth0"):
    return reach.Ipv6Address(address=address, interface=interface, scope=scope, temporary=temporary,
                             prefix_length=prefix, deprecated=deprecated)


class SpyFactory:
    """Records listener construction; the refusal/no-address paths must never call it."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise AssertionError("这条路径不应该开监听器")


async def http_request(address, port, path, *, method="GET", timeout=3.0, headers=b""):
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(address, port, family=socket.AF_INET6), timeout)
    try:
        writer.write(f"{method} {path} HTTP/1.1\r\nHost: [{address}]\r\n".encode() + headers +
                     b"Connection: close\r\n\r\n")
        await writer.drain()
        return await asyncio.wait_for(reader.read(8192), timeout)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (ConnectionError, OSError):
            pass


def status_of(raw):
    return int(raw.split(b" ", 2)[1])


def body_of(raw):
    return raw.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in raw else b""


async def connect_after_close(address, port, timeout=1.0):
    """Prove nothing listens any more: a fresh connect must be refused."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port, family=socket.AF_INET6), timeout)
    except (ConnectionRefusedError, OSError) as error:
        return type(error).__name__
    writer.close()
    return None


def bind_again(address, port):
    """Binding the same address/port again must work (listener socket really closed)."""
    again = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    again.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        again.bind((address, port))
    finally:
        again.close()


def loopback_global(monkeypatch):
    """Let ::1 stand in for a stable global address (real socket, no global v6 in CI)."""
    monkeypatch.setattr(reach, "IPV6_GLOBAL", ipaddress.IPv6Network("::1/128"))


# ------------------------------------------------------------------- enumeration
def test_parse_ip_addr_flags_distinguishes_stable_temporary_and_deprecated():
    records = {item.address: item for item in reach.parse_ip_addr_output(IP_ADDR_SAMPLE)}
    assert records["2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"].temporary is True
    assert records["2001:db8:aaaa:bbbb:1:2:3:4"].temporary is False
    assert records["2001:db8:aaaa:bbbb:1:2:3:4"].dynamic is True  # SLAAC dynamic != RFC 4941 temporary
    assert records["2001:db8:aaaa:bbbb:dead:beef:0:1"].deprecated is True
    assert records["2001:db8:1234:5678:1111:2222:3333:4444"].temporary is False
    assert records["fe80::1"].scope == "link"
    assert records["::1"].scope == "host"
    assert records["2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"].preferred_lft == 14390
    assert records["2001:db8:aaaa:bbbb:cccc:dddd:eeee:ffff"].kind() == reach.TEMPORARY
    assert records["2001:db8:1234:5678:1111:2222:3333:4444"].kind() == reach.STABLE


def test_classify_scope_never_guesses():
    assert reach.classify_scope("::1") == reach.LOOPBACK
    assert reach.classify_scope("fe80::1") == reach.LINK_LOCAL
    assert reach.classify_scope("fc00::1") == reach.ULA
    assert reach.classify_scope("2001:db8::1") == "global"
    assert reach.classify_scope("ff02::1") == reach.MULTICAST
    assert reach.classify_scope("::") == reach.UNSPECIFIED
    with pytest.raises(ValueError):
        reach.classify_scope("not-an-address")


def test_select_prefers_stable_and_flags_temporary_without_calling_it_stable():
    stable = record("2001:db8:1::1")
    temporary = record("2001:db8:1::2", temporary=True)
    choice = reach.select_address([temporary, stable])
    assert choice.address_type == reach.STABLE and choice.record.address == stable.address

    temporary_only = reach.select_address([temporary])
    assert temporary_only.address_type == reach.TEMPORARY
    assert reach.TEMPORARY_NOTE in temporary_only.note and temporary_only.advice
    assert temporary_only.record.address == temporary.address

    disallowed = reach.select_address([temporary], allow_temporary=False)
    assert not disallowed.usable and disallowed.address_type == reach.TEMPORARY
    assert reach.TEMPORARY_NOTE in disallowed.note

    assert not reach.select_address([record("fe80::1", scope="link"), record("::1", scope="host")]).usable
    assert not reach.select_address([record("2001:db8::9", deprecated=True)]).usable


def test_unknown_temporary_flag_is_not_treated_as_stable():
    unknown = reach.select_address([record("2001:db8::7", temporary=None)])
    assert unknown.address_type == reach.UNVERIFIED
    assert reach.UNVERIFIED_NOTE in unknown.note and unknown.advice
    assert unknown.address_type != reach.STABLE


def test_default_route_detection_reads_route_table_text():
    assert not reach.has_default_v6_route("fe800000000000000000000000000000 40 00000000000000000000000000000000 00 00 00000100 00000001 00000000 00000001 eth0\n")
    assert reach.has_default_v6_route("00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n")


def test_real_enumeration_is_honest_and_never_offers_link_local():
    records = reach.enumerate_addresses()
    for item in records:
        assert item.temporary in {True, False, None}
        assert reach.classify_scope(item.address) == item.scope or item.scope in {"global", "link", "host"}
    choice = reach.select_address(records)
    if choice.usable:
        assert choice.record.kind() in {reach.STABLE, reach.UNVERIFIED, reach.TEMPORARY}
        assert choice.record.is_global()
    else:
        assert choice.note and "防火墙" not in choice.note


# --------------------------------------------------------------------- verdicts
@pytest.mark.asyncio
async def test_missing_consent_refuses_before_touching_any_socket():
    factory = SpyFactory()
    provider_calls = []

    def provider():
        provider_calls.append(1)
        return [record("2001:db8::1")]

    probe = await reach.probe_reachability(options(consent=False), provider=provider, listener_factory=factory)
    assert probe.verdict == reach.REFUSED_BY_LOCAL_POLICY
    assert factory.calls == 0 and provider_calls == []
    assert probe.port is None and not probe.listening


@pytest.mark.asyncio
async def test_no_global_v6_is_not_reported_as_a_firewall_block():
    factory = SpyFactory()
    provider = lambda: [record("fe80::1", scope="link"), record("::1", scope="host")]
    probe = await reach.probe_reachability(options(), provider=provider, route_check=lambda: True,
                                           listener_factory=factory)
    assert probe.verdict == reach.NO_GLOBAL_V6
    assert factory.calls == 0
    assert "防火墙" not in probe.note
    assert "不是防火墙结论" in probe.advice


@pytest.mark.asyncio
async def test_missing_v6_route_has_its_own_verdict():
    factory = SpyFactory()
    probe = await reach.probe_reachability(options(), provider=lambda: [record("2001:db8::1")],
                                           route_check=lambda: False, listener_factory=factory)
    assert probe.verdict == reach.NO_V6_ROUTE
    assert factory.calls == 0
    assert "不是入站被挡的结论" in probe.advice


@pytest.mark.asyncio
async def test_real_callback_reaches_with_the_one_time_token(monkeypatch):
    loopback_global(monkeypatch)
    events, seen = [], {}

    async def callback(offer):
        seen.update(offer)
        raw = await http_request(offer["address"], offer["port"], f"{reach.REACH_PATH}?token={offer['token']}")
        seen["raw"] = raw

    probe = await reach.probe_reachability(options(), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, on_listening=callback,
                                           on_event=lambda kind, data: events.append((kind, data)))
    assert probe.verdict == reach.REACHED_BY_SERVER and probe.reached
    assert probe.valid_requests == 1 and probe.rejected_requests == 0
    assert seen["type"] == reach.SIGNAL_TYPE and seen["addressType"] == reach.STABLE
    assert seen["port"] == probe.port and seen["token"] and seen["expiresInMs"] > 0
    # 绑定的是选定地址本身，不是通配地址；响应不提供任何数据
    assert status_of(seen["raw"]) == 204 and body_of(seen["raw"]) == b""
    assert b"{" not in seen["raw"] and b"2001" not in seen["raw"]
    # 关闭后端口真的释放了：既没人监听，也能重新绑定
    assert await connect_after_close("::1", probe.port)
    bind_again("::1", probe.port)
    offer_events = [data for kind, data in events if kind == "ipv6.reach.offer"]
    assert offer_events and set(offer_events[0]) <= set(reach.LOG_FIELDS)
    assert "address" not in offer_events[0], "默认不把完整地址写进中心日志"
    assert offer_events[0]["addressType"] == reach.STABLE and offer_events[0]["port"] == probe.port


@pytest.mark.asyncio
async def test_shared_full_address_is_logged_only_with_consent(monkeypatch):
    loopback_global(monkeypatch)
    events = []
    probe = await reach.probe_reachability(options(share_full_address=True, timeout=0.2),
                                           provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True,
                                           on_event=lambda kind, data: events.append((kind, data)))
    assert probe.verdict == reach.TIMEOUT
    offer_events = [data for kind, data in events if kind == "ipv6.reach.offer"]
    assert offer_events and offer_events[0]["address"] == "::1"


@pytest.mark.asyncio
async def test_forged_token_is_refused_and_a_used_token_cannot_be_replayed():
    listener = reach.ReachListener("::1", token="one-time-token")
    await listener.start()
    try:
        raw = await http_request("::1", listener.port, f"{reach.REACH_PATH}?token=forged")
        assert status_of(raw) == 403 and not listener.reached.is_set()
        raw = await http_request("::1", listener.port, f"{reach.REACH_PATH}?token=one-time-token", method="POST")
        assert status_of(raw) == 405 and not listener.reached.is_set()
        raw = await http_request("::1", listener.port, f"{reach.REACH_PATH}?token=one-time-token")
        assert status_of(raw) == 204 and listener.reached.is_set()
        assert listener.valid_requests == 1
        raw = await http_request("::1", listener.port, f"{reach.REACH_PATH}?token=one-time-token")
        assert status_of(raw) == 403, "一次性 token 不能被复用"
        assert listener.valid_requests == 1 and listener.rejected_requests == 3
        raw = await http_request("::1", listener.port, f"/other?token=one-time-token")
        assert status_of(raw) == 403, "只接受约定的探测路径"
    finally:
        port = listener.port
        await listener.close()
    assert await connect_after_close("::1", port)
    bind_again("::1", port)


@pytest.mark.asyncio
async def test_probe_with_a_forged_callback_reports_timeout_not_reached(monkeypatch):
    loopback_global(monkeypatch)

    async def forged_callback(offer):
        raw = await http_request("::1", offer["port"], f"{reach.REACH_PATH}?token=not-the-token")
        assert status_of(raw) == 403

    probe = await reach.probe_reachability(options(timeout=0.4), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, on_listening=forged_callback)
    assert probe.verdict == reach.TIMEOUT and not probe.reached
    assert probe.rejected_requests >= 1 and probe.valid_requests == 0


@pytest.mark.asyncio
async def test_unreachable_callback_address_ends_in_an_honest_timeout(monkeypatch):
    loopback_global(monkeypatch)
    # 服务端视角：对不可路由的文档前缀发起真实连接尝试，必须失败（不能假装成功）
    failure = None
    try:
        await asyncio.wait_for(asyncio.open_connection("2001:db8::1", 80, family=socket.AF_INET6), 0.3)
    except (asyncio.TimeoutError, OSError) as error:
        failure = type(error).__name__
    assert failure, "不可达地址的回连必须失败"
    probe = await reach.probe_reachability(options(timeout=0.3), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True)
    assert probe.verdict == reach.TIMEOUT
    assert "防火墙" in probe.note, "超时只能如实说可能被挡住"
    assert "没有" not in probe.note
    assert await connect_after_close("::1", probe.port)
    bind_again("::1", probe.port)


@pytest.mark.asyncio
async def test_address_rotation_during_the_probe_is_reported(monkeypatch):
    loopback_global(monkeypatch)
    calls = {"count": 0}

    def provider():
        calls["count"] += 1
        if calls["count"] <= 2:
            return [record("::1", interface="lo")]
        return [record("2001:db8::1")]  # 选定地址消失

    probe = await reach.probe_reachability(options(timeout=2.0, watch_interval=0.05), provider=provider,
                                           route_check=lambda: True)
    assert probe.verdict == reach.ADDRESS_ROTATED
    assert calls["count"] > 2
    assert "轮换" in probe.note or "消失" in probe.note


@pytest.mark.asyncio
async def test_temporary_only_address_is_flagged_in_offer_and_log(monkeypatch):
    loopback_global(monkeypatch)
    events = []
    probe = await reach.probe_reachability(options(timeout=0.2), provider=lambda: [record("::1", interface="lo", temporary=True)],
                                           route_check=lambda: True,
                                           on_event=lambda kind, data: events.append((kind, data)))
    assert probe.verdict == reach.TIMEOUT
    assert probe.address_type == reach.TEMPORARY and reach.TEMPORARY_NOTE in probe.note
    assert probe.advice and probe.offer["addressType"] == "temporary"
    logged = [data for kind, data in events if kind == "ipv6.reach.offer"][0]
    assert logged["addressType"] == "temporary" and "address" not in logged
    assert logged["note"] and reach.TEMPORARY_NOTE in logged["note"]


@pytest.mark.asyncio
async def test_wildcard_bind_needs_explicit_permission(monkeypatch):
    loopback_global(monkeypatch)
    seen = {}

    def factory(*args, **kwargs):
        seen["listener"] = reach.ReachListener(*args, **kwargs)
        return seen["listener"]

    async def note_binding(offer):
        seen["bound"] = seen["listener"].bound_socket().getsockname()[0]

    probe = await reach.probe_reachability(options(timeout=0.2), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, listener_factory=factory,
                                           on_listening=note_binding)
    assert probe.verdict == reach.TIMEOUT
    assert seen["bound"] == "::1", "默认必须绑定选定地址，不得绑定通配地址"
    assert probe.offer["address"] == "::1"  # 信令里永远是具体地址

    allowed = await reach.probe_reachability(options(timeout=0.2, allow_wildcard=True),
                                             provider=lambda: [record("::1", interface="lo")],
                                             route_check=lambda: True, listener_factory=factory,
                                             on_listening=note_binding)
    assert allowed.verdict == reach.TIMEOUT
    assert seen["bound"] == "::", "只有显式同意才允许通配绑定"


@pytest.mark.asyncio
async def test_oversized_or_garbage_requests_are_refused_without_serving_data(monkeypatch):
    loopback_global(monkeypatch)

    async def abuse(offer):
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("::1", offer["port"], family=socket.AF_INET6), 2)
        writer.write(b"GET " + b"/" * 32768 + b" HTTP/1.1\r\n\r\n")
        await writer.drain()
        raw = await asyncio.wait_for(reader.read(4096), 2)
        writer.close()
        assert not raw.startswith(b"HTTP/1.1 2"), raw[:40]
        assert b"{" not in raw

    probe = await reach.probe_reachability(options(timeout=0.3), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, on_listening=abuse)
    assert probe.verdict == reach.TIMEOUT and not probe.reached


@pytest.mark.asyncio
async def test_verdict_event_is_logged_with_correlation_and_redaction(monkeypatch):
    loopback_global(monkeypatch)
    ids = options(timeout=0.2)
    events = []
    probe = await reach.probe_reachability(ids, provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True,
                                           on_event=lambda kind, data: events.append((kind, data)))
    verdict_events = [data for kind, data in events if kind.startswith("ipv6.reach.") and kind != "ipv6.reach.offer"]
    assert verdict_events and verdict_events[-1]["verdict"] == reach.TIMEOUT
    record_ = verdict_events[-1]
    assert set(record_) <= set(reach.LOG_FIELDS)
    assert (record_["connectionId"], record_["attemptId"], record_["session"]) == (
        ids.connection_id, ids.attempt_id, ids.session)
    assert "address" not in record_ and record_["port"] == probe.port


# ---------------------------------------------------------------- protocol/logs
def test_verdict_parsing_rejects_unknown_shapes_and_mismatched_tokens():
    base = {"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": str(uuid.uuid4()),
            "attemptId": str(uuid.uuid4()), "verdict": reach.TIMEOUT, "token": "t" * 8}
    assert reach.parse_reach_verdict(base, token="t" * 8)["verdict"] == reach.TIMEOUT
    # Structural problems are INVALID; an unknown *word* is its own, explicit refusal.
    for broken in ([], {**base, "extra": 1}, {**base, "type": "signal"}, {**base, "v": 2},
                   {**base, "attemptId": 5}):
        with pytest.raises(reach.ReachError, match="INVALID_REACH_VERDICT"):
            reach.parse_reach_verdict(broken)
    for unknown in ({**base, "verdict": "LOOKS_FINE"}, {**base, "code": "LOOKS_FINE", "ok": True},
                    {**base, "code": 5}, {k: v for k, v in base.items() if k != "verdict"}):
        with pytest.raises(reach.ReachError, match="UNRECOGNIZED_REACH_CODE"):
            reach.parse_reach_verdict(unknown)
    with pytest.raises(reach.ReachError, match="REACH_TOKEN_MISMATCH"):
        reach.parse_reach_verdict(base, token="other-token")
    with pytest.raises(reach.ReachError, match="INVALID_REACH_VERDICT"):
        reach.parse_reach_verdict(None)


def test_authoritative_code_and_ok_are_decoded_without_guessing():
    """The server's `code`/`ok` is the conclusion; `verdict` is only a convenience word."""
    identifiers = {"v": 1, "type": reach.SIGNAL_RESULT_TYPE,
                   "connectionId": str(uuid.uuid4()), "attemptId": str(uuid.uuid4()), "port": 41000}
    for code, verdict in reach.SERVER_CODE_VERDICT.items():
        parsed = reach.parse_reach_verdict({**identifiers, "code": code, "ok": code == "REACHABLE"})
        assert parsed["verdict"] == verdict and parsed["code"] == code
        assert parsed["ok"] is (code == "REACHABLE")
        # Never a pass, never a timeout, unless the authority really said so.
        assert (parsed["verdict"] in reach.POSITIVE_VERDICTS) is (code == "REACHABLE")
    for code, verdict in (("CONNECTION_REFUSED", reach.CONNECTION_REFUSED),
                          ("TOKEN_MISMATCH", reach.TOKEN_MISMATCH),
                          ("REJECTED_BY_POLICY", reach.REJECTED_BY_POLICY)):
        parsed = reach.parse_reach_verdict({**identifiers, "code": code, "ok": False,
                                            "failureCode": "DETAIL", "note": "服务端说明"})
        assert parsed["verdict"] == verdict
        assert parsed["verdict"] not in {reach.TIMEOUT, reach.NO_V6_ROUTE, reach.REACHED_BY_SERVER}
        assert parsed["ok"] is False and parsed["failureCode"] == "DETAIL"
    # The server's optional word must agree with the authority when both are present.
    agree = reach.parse_reach_verdict({**identifiers, "code": "TOKEN_MISMATCH", "ok": False,
                                       "verdict": reach.TOKEN_MISMATCH})
    assert agree["verdict"] == reach.TOKEN_MISMATCH


def test_disagreeing_authoritative_fields_are_refused_not_resolved():
    identifiers = {"v": 1, "type": reach.SIGNAL_RESULT_TYPE,
                   "connectionId": str(uuid.uuid4()), "attemptId": str(uuid.uuid4())}
    for payload in ({"code": "REACHABLE", "ok": False},
                    {"code": "TIMEOUT", "ok": True},
                    {"code": "CONNECTION_REFUSED", "verdict": reach.TIMEOUT},
                    {"code": "REACHABLE", "ok": True, "verdict": reach.TIMEOUT},
                    {"verdict": reach.REACHED_BY_SERVER, "ok": False}):
        with pytest.raises(reach.ReachError, match="INCONSISTENT_REACH_VERDICT"):
            reach.parse_reach_verdict({**identifiers, **payload})


def test_client_verdict_and_log_tables_match_the_server_contract():
    """The two sides must agree word-for-word, or the merged timeline would lie."""
    assert set(reach.SERVER_RESULT_CODES) == set(server.INBOUND_CHECK_LOG)
    for code, (state, reason) in server.INBOUND_CHECK_LOG.items():
        assert reach.SERVER_CODE_LOG[code] == (state, reason)
        assert reach.CLIENT_VERDICT_LOG[reach.SERVER_CODE_VERDICT[code]] == (state, reason)
    for code, word in server.INBOUND_CHECK_CLIENT_VERDICT.items():
        assert reach.SERVER_CODE_VERDICT[code] == word
    # The server deliberately fills no client word for the three refusals; we name them.
    assert set(server.INBOUND_CHECK_LOG) - set(server.INBOUND_CHECK_CLIENT_VERDICT) == {
        "CONNECTION_REFUSED", "TOKEN_MISMATCH", "REJECTED_BY_POLICY"}
    for code in ("CONNECTION_REFUSED", "TOKEN_MISMATCH", "REJECTED_BY_POLICY"):
        assert reach.SERVER_CODE_VERDICT[code] in reach.VERDICTS
        assert reach.SERVER_CODE_VERDICT[code] not in reach.POSITIVE_VERDICTS


@pytest.mark.asyncio
async def test_probe_keeps_a_server_refusal_instead_of_a_timeout(monkeypatch):
    """Real listener, real waiter payload: a refusal must survive as itself."""
    for code, verdict in (("CONNECTION_REFUSED", reach.CONNECTION_REFUSED),
                          ("TOKEN_MISMATCH", reach.TOKEN_MISMATCH),
                          ("REJECTED_BY_POLICY", reach.REJECTED_BY_POLICY)):
        loopback_global(monkeypatch)
        identifiers = options(timeout=2.0)

        async def waiter(offer, code=code, identifiers=identifiers):
            return {"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": identifiers.connection_id,
                    "attemptId": identifiers.attempt_id, "code": code, "ok": False,
                    "note": server.INBOUND_CHECK_NOTES[code]}

        probe = await reach.probe_reachability(identifiers, provider=lambda: [record("::1", interface="lo")],
                                               route_check=lambda: True, verdict_waiter=waiter)
        assert probe.verdict == verdict and not probe.reached
        assert probe.verdict != reach.TIMEOUT and probe.result["code"] == code
        assert probe.result["note"] == server.INBOUND_CHECK_NOTES[code]
        assert probe.listening is False and probe.elapsed_ms is not None


@pytest.mark.asyncio
async def test_probe_expresses_an_unrecognized_server_word_instead_of_guessing(monkeypatch):
    loopback_global(monkeypatch)
    identifiers = options(timeout=2.0)

    async def waiter(offer):
        return {"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": identifiers.connection_id,
                "attemptId": identifiers.attempt_id, "code": "SOMETHING_NEW", "ok": True}

    probe = await reach.probe_reachability(identifiers, provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, verdict_waiter=waiter)
    assert probe.verdict == reach.RESULT_UNRECOGNIZED and not probe.reached
    assert probe.verdict not in reach.POSITIVE_VERDICTS and probe.verdict != reach.TIMEOUT
    assert "无法识别" in probe.note and "不猜" in probe.note
    # The listener is closed even on this path: nothing is left listening.
    assert probe.listening is False
    assert await connect_after_close("::1", probe.port)
    bind_again("::1", probe.port)


def test_enumeration_subprocesses_are_encoding_explicit(monkeypatch):
    """The encoding gate's last failure was a default-encoding `text=True` subprocess."""
    calls = []

    class Result:
        returncode = 0
        stdout = IP_ADDR_SAMPLE
        stderr = ""

    def recording_run(command, **kwargs):
        calls.append((list(command), dict(kwargs)))
        return Result()

    monkeypatch.setattr(reach.subprocess, "run", recording_run)
    assert reach.run_ip_command() == IP_ADDR_SAMPLE
    assert calls and calls[0][0][:2] == ["ip", "-6"] and calls[0][1]["text"] is True
    assert all(kwargs["encoding"] == "utf-8" and kwargs["errors"] == "replace" for _, kwargs in calls)

    # The Windows ipconfig fallback must be just as explicit.
    calls.clear()
    monkeypatch.setattr(reach, "run_ip_command", lambda: None)
    monkeypatch.setattr(reach, "enumerate_via_getifaddrs", lambda: None)
    reach.enumerate_addresses()
    assert [command for command, _ in calls] == [["ipconfig"]]
    assert calls[0][1]["encoding"] == "utf-8" and calls[0][1]["errors"] == "replace"


def test_telemetry_projection_lands_in_a_client_store_and_in_the_center(tmp_path):
    """A conclusion must really be written, not silently dropped by the allowlist."""
    queue = telemetry.LocalQueue(str(tmp_path / "local"))
    cases = [(reach.REACHED_BY_SERVER, ("completed", None, True)),
             (reach.CONNECTION_REFUSED, ("failed", "CLOSED", False)),
             (reach.TIMEOUT, ("timeout", "TIMEOUT", False)),
             (reach.TOKEN_MISMATCH, ("failed", "AUTH_FAILED", False)),
             (reach.REJECTED_BY_POLICY, ("unsupported", "SCHEMA_INVALID", False)),
             (reach.RESULT_UNRECOGNIZED, ("failed", "SCHEMA_INVALID", False)),
             (reach.NO_GLOBAL_V6, ("unsupported", "UNSUPPORTED", False))]
    try:
        for verdict, (state, reason, ok) in cases:
            probe = reach.ReachProbe(verdict=verdict, connection_id=str(uuid.uuid4()),
                                     attempt_id=str(uuid.uuid4()), elapsed_ms=12.5)
            stored = reach.emit_telemetry(queue, probe)
            assert stored["event"] == reach.TELEMETRY_EVENT == "path.state"
            assert stored["data"]["state"] == state and stored["data"]["ok"] is ok
            assert stored["data"].get("reason") == reason
            assert stored["data"]["family"] == 6 and stored["data"]["mechanism"] == "tcp"
            assert stored["data"]["protocol"] == "tcp" and stored["data"]["rttMs"] == 12.5
            assert stored["connectionId"] == probe.connection_id and stored["attemptId"] == probe.attempt_id
        rows = queue.pending()
        assert len(rows) == len(cases)
        allowed = {"state", "reason", "ok", "family", "mechanism", "protocol", "rttMs", "error"}
        for row in rows:
            # Nothing was dropped: the strict allowlist returns the same keys unchanged.
            assert set(row["data"]) <= allowed
            assert row["data"] == telemetry.safe_data(row["data"], True)
            telemetry.validate_event(row, queue.session)
            assert "address" not in json.dumps(row) and "token" not in json.dumps(row["data"])
        # The center's own strict ingest accepts and really stores the same rows.
        center = telemetry.Store(str(tmp_path / "center"))
        try:
            assert center.ingest("room", "peer", queue.session, rows) == [row["id"] for row in rows]
            stored_rows = center.db.execute("SELECT COUNT(*) FROM diagnostics").fetchone()[0]
            assert stored_rows == len(cases)
        finally:
            center.close()
    finally:
        queue.close()


@pytest.mark.asyncio
async def test_telemetry_probe_writes_the_conclusion_when_a_store_is_given(monkeypatch, tmp_path):
    loopback_global(monkeypatch)
    identifiers = options(timeout=2.0)
    queue = telemetry.LocalQueue(str(tmp_path / "probe-queue"))
    try:
        async def waiter(offer):
            return {"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": identifiers.connection_id,
                    "attemptId": identifiers.attempt_id, "code": "CONNECTION_REFUSED", "ok": False}

        probe = await reach.probe_reachability(identifiers, provider=lambda: [record("::1", interface="lo")],
                                               route_check=lambda: True, verdict_waiter=waiter,
                                               telemetry_store=queue)
        assert probe.verdict == reach.CONNECTION_REFUSED and probe.telemetry_event_id
        rows = queue.pending()
        assert len(rows) == 1
        assert rows[0]["id"] == probe.telemetry_event_id
        assert rows[0]["data"]["state"] == "failed" and rows[0]["data"]["reason"] == "CLOSED"
        assert rows[0]["connectionId"] == identifiers.connection_id
        assert rows[0]["attemptId"] == identifiers.attempt_id
    finally:
        queue.close()


def test_telemetry_projection_refuses_a_verdict_it_cannot_log():
    with pytest.raises(reach.ReachError, match="UNRECOGNIZED_REACH_VERDICT"):
        reach.telemetry_payload("NOT_A_VERDICT")
    with pytest.raises(reach.ReachError, match="UNRECOGNIZED_REACH_VERDICT"):
        reach.emit_telemetry(_RefusingStore(), reach.ReachProbe(verdict="NOT_A_VERDICT"))


class _RefusingStore:
    def emit(self, *args, **kwargs):
        raise AssertionError("无法识别的结论不允许写日志")


@pytest.mark.asyncio
async def test_server_reported_verdict_is_used_and_never_inferred(monkeypatch):
    loopback_global(monkeypatch)
    identifiers = options(timeout=2.0)
    result = {"v": 1, "type": reach.SIGNAL_RESULT_TYPE, "connectionId": identifiers.connection_id,
              "attemptId": identifiers.attempt_id, "verdict": reach.TIMEOUT, "note": "服务端回连超时"}

    async def waiter(offer):
        return {**result, "token": offer["token"]}

    probe = await reach.probe_reachability(options(timeout=2.0), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, verdict_waiter=waiter)
    assert probe.verdict == reach.TIMEOUT and not probe.reached
    assert probe.result["note"] == "服务端回连超时" and probe.result["tokenConsumed"] is True

    reached = {**result, "verdict": reach.REACHED_BY_SERVER, "note": "服务端回连成功"}

    async def waiter_ok(offer):
        return {**reached, "token": offer["token"]}

    probe = await reach.probe_reachability(options(timeout=2.0), provider=lambda: [record("::1", interface="lo")],
                                           route_check=lambda: True, verdict_waiter=waiter_ok)
    assert probe.verdict == reach.REACHED_BY_SERVER and probe.reached


def test_log_fields_are_shared_correlatable_and_redacted_by_default():
    redacted = reach.log_fields("ipv6.reach.verdict", connection_id="c", attempt_id="a", session="s",
                                address_type=reach.STABLE, scope="global", prefix_length=64, port=40000,
                                verdict=reach.REACHED_BY_SERVER, token_consumed=True, note="ok",
                                address="2001:db8::1", share_full_address=False)
    assert set(redacted) <= set(reach.LOG_FIELDS)
    assert "address" not in redacted
    assert (redacted["connectionId"], redacted["attemptId"], redacted["session"]) == ("c", "a", "s")
    assert redacted["prefixLength"] == 64 and redacted["scope"] == "global"
    shared = reach.log_fields("ipv6.reach.verdict", connection_id="c", attempt_id="a", session="s",
                              address="2001:db8::1", share_full_address=True)
    assert shared["address"] == "2001:db8::1"


def test_config_validation_is_bounded():
    with pytest.raises(reach.ReachError, match="INVALID_REACH_CONFIG"):
        reach.ReachOptions(consent=True, connection_id="has space", attempt_id="a").validate()
    with pytest.raises(reach.ReachError, match="INVALID_REACH_CONFIG"):
        reach.ReachOptions(consent=True, attempt_id="a", timeout=0).validate()
    with pytest.raises(reach.ReachError, match="INVALID_REACH_CONFIG"):
        reach.ReachOptions(consent=True, attempt_id="a", max_request_bytes=10).validate()
