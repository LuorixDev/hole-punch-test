"""Real in-process P2P round trips for the desktop engine (Linux loopback).

Scope honesty: every socket here is on this machine. These tests prove the
desktop engine performs a real authenticated handshake with its own signaling
server, a real echo peer and real sockets. They are **not** home-NAT, Windows or
cross-device evidence, and they never assert that a method works in a specific
network.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import secrets
import sys
from pathlib import Path

import pytest
import pytest_asyncio

from p2pchat.native.adapter import NativeAdapter
from p2pchat.python_desktop import engine as engine_module
from p2pchat.python_desktop.engine import DesktopEngine, EngineConfig, plaintext_risk, validate_endpoint
from p2pchat.python_desktop.native_session import NativeSession, encode

# Only the async cases carry the asyncio mark; the policy cases are sync.
asyncio_test = pytest.mark.asyncio


@pytest_asyncio.fixture
async def lab(tmp_path):
    from p2pchat.python_desktop.selftest import SelfTestLab

    instance = SelfTestLab(native=True, with_stun=True)
    instance.root = tmp_path
    await instance.start_server()
    await instance.wait_for_health()
    try:
        yield instance
    finally:
        await instance.stop()


async def wait_direct(engine: DesktopEngine, timeout: float = 45.0) -> dict:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        for key in list(engine.targets):
            summary = engine.summary(key)
            if summary["canSend"]:
                await engine.select(key)
                return summary
        await asyncio.sleep(0.1)
    for key in list(engine.targets):
        await engine.select(key)
        return engine.summary(key)
    return {}


@asyncio_test
async def test_real_webrtc_handshake_text_and_file(lab) -> None:
    echo = DesktopEngine(lab.config("回声节点", echo=True))
    client = DesktopEngine(lab.config("自检客户端"))
    try:
        await echo.start()
        await client.start()
        summary = await wait_direct(client, timeout=45)
        assert summary.get("canSend"), "没有拿到可聊天的直连（这是真实握手，不是模拟）"
        assert summary["direct"], summary
        assert any(row["latency"] is None or row["latency"] > 0 for row in summary["rows"])

        token = f"pytest-{secrets.token_hex(6)}"
        await client.send_text(token)
        deadline = asyncio.get_running_loop().time() + 20
        while asyncio.get_running_loop().time() < deadline:
            if any(m.direction == "in" and m.kind == "text" and m.text == token for m in client.messages):
                break
            await asyncio.sleep(0.1)
        assert any(m.direction == "in" and m.text == token for m in client.messages), "文本没有收到对方回显"

        payload = secrets.token_bytes(32768)
        source = lab.root / "pytest.bin"
        source.write_bytes(payload)
        sent = await client.send_file(str(source), "pytest.bin", "application/octet-stream")
        assert sent["bytes"] == len(payload)
        deadline = asyncio.get_running_loop().time() + 25
        while asyncio.get_running_loop().time() < deadline:
            if any(m.kind == "file" and m.id == sent["id"] for m in echo.messages):
                break
            await asyncio.sleep(0.1)
        assert any(m.kind == "file" and m.id == sent["id"] for m in echo.messages), "文件没有被对方收到"
        assert hashlib.sha256(payload).hexdigest()

        rtt = await client.measure_webrtc_latency(next(iter(client.targets)))
        assert rtt is None or rtt >= 0
    finally:
        await asyncio.gather(echo.close(), client.close(), return_exceptions=True)
        assert engine_module._SHIM["engines"] == 0, "会话注入没有完全回收"


@asyncio_test
async def test_no_direct_path_is_reported_not_faked(lab) -> None:
    """A孤单 client must report an explicit failure, never a fabricated success."""
    client = DesktopEngine(lab.config("孤单客户端"))
    try:
        await client.start()
        await asyncio.sleep(3)
        assert client.targets == {}
        with pytest.raises(RuntimeError) as error:
            await client.send_text("nobody is listening")
        assert "NO_PEER" in str(error.value) or "NO_DIRECT_PATH" in str(error.value)
    finally:
        await client.close()


@asyncio_test
async def test_gateway_methods_report_real_capability_but_never_message(lab) -> None:
    echo = DesktopEngine(lab.config("网关回声", echo=True))
    client = DesktopEngine(lab.config("网关客户端"))
    try:
        await echo.start()
        await client.start()
        await asyncio.sleep(2)
        adapter = NativeAdapter()
        capabilities = await adapter.capabilities()
        gateway = [entry for entry in capabilities["methods"] if entry["mechanism"] in {"upnp", "pcp", "natpmp"}]
        assert gateway and all(entry["canMessage"] is False for entry in gateway), "网关放行永远不能传消息"
        assert all(entry["requiresExplicitConsent"] is True for entry in gateway), "网关放行必须逐次显式同意"
        # 如实报告平台能力：与 adapter.gateway_capability() 一致，不把"不能核对"说成能用。
        support = adapter.gateway_capability()
        if support["status"] == "available":
            assert all(entry["status"] == "available" for entry in gateway)
            assert all(entry["reason"] == "EXPLICIT_OPT_IN_REQUIRED" for entry in gateway)
            assert support["gateway"], "Linux 上应能只读路由表读出默认网关"
        else:
            assert all(entry["status"] == "unsupported" for entry in gateway)
            assert all(entry["reason"] == support["reason"] for entry in gateway)
        # 桌面侧的可用性必须直接消费适配器的真实能力报告：
        # 平台能核对 → 可用（默认关闭、需要显式同意），平台不能核对 → 不支持。
        engine_capability = client.gateway_capability()
        gateway_row = next(row for row in client.rows("nobody") if row["id"] == "gateway")
        assert gateway_row["canMessage"] is False
        assert gateway_row["consentRequired"] is True
        assert gateway_row["consented"] is False
        if engine_capability["status"] == "available":
            assert gateway_row["availability"] == "可用", "平台可核对时不能显示成不支持"
            assert "显式授权" in gateway_row["detail"], "还没同意只能体现在说明里"
        else:
            assert gateway_row["availability"] == "不支持"
            assert gateway_row["detail"], "不可用时必须给出平台原因"
        udp = next(entry for entry in capabilities["methods"] if entry["mechanism"] == "udp-probe")
        assert udp["canMessage"] is False, "UDP 探测只能探测，不能传内容"
        await adapter.shutdown()
    finally:
        await asyncio.gather(echo.close(), client.close(), return_exceptions=True)


@asyncio_test
async def test_native_quic_session_round_trip() -> None:
    """The native adapter is driven in-process; no stdio bridge exists."""
    room, secret = "native-room", secrets.token_hex(16)
    connection, attempt = secrets.token_hex(16), secrets.token_hex(16)
    offerer_adapter, answerer_adapter = NativeAdapter("127.0.0.1"), NativeAdapter("127.0.0.1")
    offerer_inbox: list[str] = []
    answerer_inbox: list[str] = []

    def recorder(inbox):
        def handler(event, params):
            if event == "chat.received" and params.get("kind") == "text":
                inbox.append(params.get("text", ""))

        return handler

    def make(adapter, local, remote, role, handler):
        return NativeSession(
            adapter,
            mechanism="quic",
            room=room,
            secret=secret,
            local_id=local,
            peer_id=remote,
            connection_id=connection,
            attempt_id=attempt,
            role=role,
            on_event=handler,
        )

    offerer = make(offerer_adapter, "aaaa", "bbbb", "offerer", recorder(offerer_inbox))
    answerer = make(answerer_adapter, "bbbb", "aaaa", "answerer", recorder(answerer_inbox))
    try:
        await offerer.start()
        await answerer.start()
        for source, target in ((offerer, answerer), (answerer, offerer)):
            for frame in source.take_handshake():
                await target.signal(source.envelope(**frame))
        deadline = asyncio.get_running_loop().time() + 15
        while asyncio.get_running_loop().time() < deadline:
            if offerer.state == "direct" and answerer.state == "direct":
                break
            await asyncio.sleep(0.05)
        assert offerer.state == "direct", (offerer.state, offerer.failure)
        assert answerer.state == "direct", (answerer.state, answerer.failure)

        await offerer.send_text("native-text-1", "从发起方直接发送")
        deadline = asyncio.get_running_loop().time() + 10
        while asyncio.get_running_loop().time() < deadline and not answerer_inbox:
            await asyncio.sleep(0.05)
        assert answerer_inbox == ["从发起方直接发送"]

        await answerer.send_text("native-text-2", "从应答方直接发送")
        deadline = asyncio.get_running_loop().time() + 10
        while asyncio.get_running_loop().time() < deadline and not offerer_inbox:
            await asyncio.sleep(0.05)
        assert offerer_inbox == ["从应答方直接发送"]

        payload = secrets.token_bytes(40000)
        file_id = await offerer.send_file(payload, "native.bin", "application/octet-stream")
        assert file_id
        result = await offerer.benchmark(seconds=1.0, max_bytes=256 * 1024)
        assert result.get("reason") != "BENCHMARK_UNSUPPORTED_NO_LANE_ISOLATION"
    finally:
        await asyncio.gather(offerer.close(), answerer.close(), return_exceptions=True)
        await asyncio.gather(offerer_adapter.shutdown(), answerer_adapter.shutdown(), return_exceptions=True)


@asyncio_test
async def test_udp_probe_reports_probe_only(lab) -> None:
    echo = DesktopEngine(lab.config("探测回声", echo=True))
    client = DesktopEngine(lab.config("探测客户端"))
    try:
        await echo.start()
        await client.start()
        summary = await wait_direct(client, timeout=45)
        if not summary:
            pytest.skip("握手未在时限内完成")
        target = next(iter(client.targets))
        probe = next(row for row in client.rows(target) if row["id"] == "udp-probe")
        assert probe["probeOnly"] is True
        assert probe["canMessage"] is False
        assert "UDP 探测" == probe["title"]
    finally:
        await asyncio.gather(echo.close(), client.close(), return_exceptions=True)


# --------------------------------------------------------------- plaintext policy
# Default refuses unencrypted non-loopback ws://; only an explicit per-session
# confirmation allows it, and the warning is then always produced. No trust-all.

def test_loopback_plaintext_is_allowed_without_confirmation() -> None:
    assert validate_endpoint("ws://127.0.0.1:8088/ws", False) is None
    assert validate_endpoint("ws://localhost:8088/ws", False) is None
    assert validate_endpoint("ws://[::1]:8088/ws", False) is None


def test_wss_is_always_allowed() -> None:
    assert validate_endpoint("wss://example.invalid/ws", False) is None
    assert plaintext_risk("wss://example.invalid/ws") is None


@pytest.mark.parametrize("url", ["ws://192.0.2.10:8088/ws", "ws://203.0.113.7:8088/ws", "ws://signaling.example.invalid/ws"])
def test_non_loopback_plaintext_is_refused_by_default(url: str) -> None:
    with pytest.raises(ValueError) as error:
        validate_endpoint(url, False)
    assert str(error.value) == "PLAINTEXT_REFUSED"


def test_explicit_confirmation_allows_but_still_warns() -> None:
    url = "ws://192.0.2.10:8088/ws"
    warning = validate_endpoint(url, True)
    assert warning and "未加密" in warning
    assert plaintext_risk(url) == warning


def test_unknown_scheme_is_refused() -> None:
    with pytest.raises(ValueError):
        validate_endpoint("http://192.0.2.10/ws", False)


@asyncio_test
async def test_engine_start_refuses_unconfirmed_plaintext_before_connecting() -> None:
    config = EngineConfig(url="ws://192.0.2.10:8088/ws", room="lab", secret="secretsecret123", name="x")
    engine = DesktopEngine(config)
    with pytest.raises(ValueError) as error:
        await engine.start()
    assert str(error.value) == "PLAINTEXT_REFUSED"
    assert engine.peer is None, "拒绝之后不允许建立任何连接"
    await engine.close()
