"""「检查我的网络」接线：本机环境体检 + IPv6 入站回连（同意、隐私、展示、上报）。

CI 没有公网 IPv6，所以 IPv6 入站的完整链路用注入的地址/路由/监听器替身跑**真实
engine 代码路径**（真 socket 的监听/回连由 tests/native 覆盖）。真实家宽是否放行
入站、是否只有临时地址仍是 NOT_RUN。
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import uuid

import pytest

from .test_ui import _destroy_window, qt_app  # noqa: F401  (session fixture: one QApplication per process)

from p2pchat.native import ipv6_reach as reach
from p2pchat.native import net_env
from p2pchat.python_desktop import engine as engine_module
from p2pchat.python_desktop.engine import DesktopEngine, EngineConfig


def make_engine(**kwargs):
    return DesktopEngine(EngineConfig(url="ws://127.0.0.1:1", room="room", secret="t" * 16, **kwargs))


class FakeSignaling:
    """Stands in for SignalSession: records the frames the engine enqueues."""

    def __init__(self):
        self.sent = []
        self.closed = False

    def _enqueue(self, frame):
        self.sent.append(dict(frame))

    def send_signal(self, **payload):
        self._enqueue({"v": 1, "type": "signal", **payload})

    def send_nat_samples(self, **payload):
        self._enqueue({"v": 1, "type": "nat-samples", **payload})


class FakeStore:
    def __init__(self):
        self.events = []
        self.session = "fake-store-session"

    def emit(self, kind, data, connection_id=None, attempt_id=None):
        self.events.append({"event": kind, "data": dict(data or {}), "connectionId": connection_id,
                            "attemptId": attempt_id})

    def pending(self, limit=30):
        return []


class FakePeer:
    def __init__(self):
        self.store = FakeStore()


class FakeSocket:
    def __init__(self, address, port):
        self._name = (address, port, 0, 0)

    def getsockname(self):
        return self._name


class FakeListener:
    """Never accepts anything; the verdict comes from the server frame instead."""

    def __init__(self, address, *, token, port=0, host=None, max_request_bytes=8192, max_connections=4):
        self.address = address
        self.token = token
        self.port = port or 40404
        self.reached = asyncio.Event()
        self.valid_requests = 0
        self.rejected_requests = 0
        self._sockets = [FakeSocket(address, self.port)]

    async def start(self):
        return self.address, self.port

    async def close(self):
        self._sockets = []


def v6_record(address="::1", *, temporary=False, scope="global"):
    return reach.Ipv6Address(address=address, interface="lo", scope=scope, temporary=temporary,
                             prefix_length=64)


def loopback_is_global(monkeypatch):
    monkeypatch.setattr(reach, "IPV6_GLOBAL", ipaddress.IPv6Network("::1/128"))


def report_with(component_status, *, verdict=None, note="", reason="TEST", detail=None):
    """A real NetEnvReport carrying one inbound verdict (everything else stays unmeasured)."""
    components = {name: net_env.not_tested(name, "NOT_TESTED_IN_THIS_UNIT") for name in
                  ("addresses", "routes", "udpEgress", "natBehavior", "ipv6Only", "nat64")}
    inbound_detail = {"verdict": verdict, "note": note, "probeRttMeaning": "not-chat-latency"}
    inbound_detail.update(detail or {})
    components["inboundReachability"] = net_env.Component("inboundReachability", component_status,
                                                          reason, "入站回连结论", inbound_detail)
    return net_env.NetEnvReport(components=components, recommendations=[], overall={"status": "insufficient-evidence", "reasons": ["INBOUND"]},
                                duration_ms=1.5, checked_at_ms=0.0)


# ------------------------------------------------------------------ 默认关闭 + 同意
def test_network_check_is_off_by_default_and_says_what_it_would_do():
    engine = make_engine()
    status = engine.network_check_status()
    assert status["consented"] is False and status["status"] == "disabled"
    assert status["reason"] == "EXPLICIT_OPT_IN_REQUIRED"
    assert "前缀长度/作用域/类型" in status["note"] and "完整地址不上报" in status["note"]
    summary = engine.network_summary()
    assert summary["rows"] == [] and summary["status"] == "not-tested"
    assert summary["probeRtt"] is None and "未测得显示「—」" in summary["text"]


@pytest.mark.asyncio
async def test_enabling_without_consent_is_refused_before_any_work():
    engine = make_engine()
    with pytest.raises(PermissionError, match="NETWORK_CHECK_OPT_IN_REQUIRED"):
        await engine.network_check_enable(consent=False)
    assert engine.network_check_status()["consented"] is False


@pytest.mark.asyncio
async def test_not_consented_opens_no_listener_and_asks_no_observation_point(monkeypatch):
    engine = make_engine()
    calls = {"listener": 0, "reach_probe": None, "config": None}

    class SpyListener:
        def __init__(self, *args, **kwargs):
            calls["listener"] += 1
            raise AssertionError("未同意不得开监听器")

    monkeypatch.setattr(reach, "ReachListener", SpyListener)

    async def spy_health(config=None, *, sources=None):
        calls["config"] = config
        calls["reach_probe"] = sources.reach_probe
        return net_env.NetEnvReport(components={}, recommendations=[], overall={"status": "not-tested", "reasons": []},
                                    duration_ms=0.0, checked_at_ms=0.0)

    monkeypatch.setattr(net_env, "health_check", spy_health)
    result = await engine.run_network_check()
    assert calls["config"].consent is False and calls["config"].inbound_probe is False
    assert calls["reach_probe"] is None and calls["listener"] == 0
    assert calls["config"].observation_points == ()
    assert result["status"] == "not-tested"  # 不是失败，只是“未测”


@pytest.mark.asyncio
async def test_real_run_without_consent_touches_no_socket(monkeypatch):
    engine = make_engine()
    opened = []

    def spy(*args, **kwargs):
        opened.append(args)
        raise AssertionError("未同意时不得创建监听器")

    monkeypatch.setattr(reach, "ReachListener", spy)
    result = await engine.run_network_check()
    assert opened == []
    inbound = next(row for row in result["rows"] if row["name"] == "inboundReachability")
    assert inbound["status"] == "not-tested"
    assert "没有地址" not in inbound["evidence"] and "防火墙" not in inbound["evidence"]


# ------------------------------------------------ 本机体检展示（状态/RTT/未测为“—”）
@pytest.mark.asyncio
async def test_real_health_check_shows_measured_and_unmeasured_without_zero_rtt():
    engine = make_engine()
    await engine.network_check_enable(consent=True, inbound=False, budget=8.0)
    result = await engine.run_network_check()
    names = [row["name"] for row in result["rows"]]
    assert names == ["addresses", "routes", "udpEgress", "natBehavior", "inboundReachability", "ipv6Only", "nat64"]
    assert {"determined", "not-tested"} <= {row["status"] for row in result["rows"]}
    for row in result["rows"]:
        assert row["probeRttMs"] is None or isinstance(row["probeRttMs"], (int, float))
        assert row["statusText"] in {"已判定", "证据不足", "未测", "不可用", "不适用"}
        assert row["evidence"], f"{row['name']} 必须给出人话"
    assert result["probeRtt"] is None, "没有观测点时不给数值，更不给 0"
    assert result["recommendations"] and result["unmeasured"]
    assert "未测" in result["text"]


def test_unmeasured_probe_rtt_is_a_dash_not_zero():
    import p2pchat.python_desktop.qt_ui as qt_ui  # noqa: F401  (imported to keep the render map honest)

    engine = make_engine()
    engine.network_report = report_with("not-tested", verdict=None)
    summary = engine.network_summary()
    assert summary["probeRtt"] is None
    assert all(row["probeRttMs"] is None for row in summary["rows"])
    assert summary["probeRttLabel"] == "探测/观测往返时间（不是聊天延迟）"


@pytest.mark.asyncio
async def test_progress_and_result_events_are_emitted_for_the_ui():
    engine = make_engine()
    events = []
    engine._emit = lambda kind, **payload: events.append((kind, payload))
    await engine.network_check_enable(consent=True, inbound=False, budget=8.0)
    result = await engine.run_network_check()
    kinds = [kind for kind, _ in events]
    assert kinds.count("network.check.progress") >= 2, kinds
    stages = [payload.get("stage") for kind, payload in events if kind == "network.check.progress"]
    assert "addresses" in stages and "done" in stages
    assert "network.check.result" in kinds
    assert result["rows"] and result["status"] in {"determined", "insufficient-evidence", "unavailable", "not-tested"}


# ------------------------------------- t58 语义：code/ok 权威；拒绝/看不懂不折成超时或成功
def test_server_refusals_are_shown_as_refusal_or_unreadable_never_as_timeout():
    engine = make_engine()
    expectations = {
        "CONNECTION_REFUSED": ("已判定", "被明确拒绝"),
        "TOKEN_MISMATCH": ("拒绝", "token 不符"),
        "REJECTED_BY_POLICY": ("拒绝", "策略拒绝"),
        "RESULT_UNRECOGNIZED": ("看不懂", "无法识别"),
    }
    for verdict, (status_word, phrase) in expectations.items():
        engine.network_report = report_with("insufficient-evidence", verdict=verdict, note="")
        row = next(row for row in engine.network_rows() if row["name"] == "inboundReachability")
        assert phrase in row["verdictText"], (verdict, row["verdictText"])
        # 被拒/看不懂不能被描述成 TIMEOUT 的措辞（“没有观测到回连”）或成功措辞
        assert "没有观测到回连" not in row["verdictText"], verdict
        assert "回连成功" not in row["verdictText"] and "入站可达" not in row["verdictText"], verdict
    # 未识别/拒绝都不算“已判定为可达”
    engine.network_report = report_with("determined", verdict="CONNECTION_REFUSED")
    summary = engine.network_summary()
    assert summary["inboundVerdict"] == "CONNECTION_REFUSED"
    assert "可达" not in summary["inboundText"]


def test_no_address_and_no_route_are_never_described_as_a_firewall_block():
    engine = make_engine()
    for verdict, phrase in (("NO_GLOBAL_V6", "没有可用的全局 IPv6 地址"),
                            ("NO_V6_ROUTE", "没有 IPv6 默认路由")):
        engine.network_report = report_with("determined", verdict=verdict)
        row = next(row for row in engine.network_rows() if row["name"] == "inboundReachability")
        assert phrase in row["verdictText"]
        assert "不是防火墙结论" in row["verdictText"] or "不是入站被挡的结论" in row["verdictText"]
        assert "防火墙" not in row["evidence"]


def test_temporary_only_address_keeps_the_rotation_warning():
    engine = make_engine()
    engine.network_report = report_with("insufficient-evidence", verdict="ADDRESS_ROTATED",
                                        note=reach.TEMPORARY_NOTE)
    summary = engine.network_summary()
    assert "地址可能轮换" in summary["inboundText"] or "地址可能轮换" in summary["inboundNote"]
    assert "只对当前时刻成立" in (summary["inboundText"] + summary["inboundNote"])


# ------------------------------------------------- 完整链路：offer → 服务器结论 → 展示
@pytest.mark.asyncio
async def test_v6_reach_chain_sends_the_offer_and_uses_the_server_code(monkeypatch):
    loopback_is_global(monkeypatch)
    engine = make_engine()
    engine.signaling = FakeSignaling()
    options = reach.ReachOptions(consent=True, connection_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                                 session=engine.client_session, timeout=2.0)
    probe = engine._v6_reach_probe(asyncio.get_running_loop())
    seen = {}

    def on_listening(offer):
        seen.update(offer)

    task = asyncio.ensure_future(probe(options, provider=lambda: [v6_record()], route_check=lambda: True,
                                       listener_factory=FakeListener, on_listening=on_listening))
    async with asyncio.timeout(5):
        while not engine.signaling.sent:
            await asyncio.sleep(0.01)
    offer = engine.signaling.sent[-1]
    assert offer["type"] == "v6-reach" and offer["address"] == "::1"
    assert offer["addressType"] == "stable" and offer["scope"] == "global" and offer["prefixLength"] == 64
    assert offer["port"] == 40404 and offer["token"] and offer["expiresInMs"] > 0
    assert seen["token"] == offer["token"]
    # 服务器 code 是权威结论：REACHABLE ⇒ 客户端判定 REACHED_BY_SERVER
    assert engine.on_v6_reach_frame({"v": 1, "type": "v6-reach-result", "code": "REACHABLE", "ok": True,
                                     "connectionId": offer["connectionId"], "attemptId": offer["attemptId"],
                                     "verdict": "REACHED_BY_SERVER", "token": offer["token"]}) is True
    result = await asyncio.wait_for(task, 5)
    assert result.verdict == reach.REACHED_BY_SERVER and result.reached
    assert engine.on_v6_reach_frame({"v": 1, "type": "signal"}) is False


@pytest.mark.asyncio
async def test_server_connection_refused_is_not_shown_as_timeout(monkeypatch):
    loopback_is_global(monkeypatch)
    engine = make_engine()
    engine.signaling = FakeSignaling()
    options = reach.ReachOptions(consent=True, connection_id=str(uuid.uuid4()), attempt_id=str(uuid.uuid4()),
                                 session=engine.client_session, timeout=2.0)
    task = asyncio.ensure_future(engine._v6_reach_probe(asyncio.get_running_loop())(
        options, provider=lambda: [v6_record()], route_check=lambda: True, listener_factory=FakeListener))
    async with asyncio.timeout(5):
        while not engine.signaling.sent:
            await asyncio.sleep(0.01)
    offer = engine.signaling.sent[-1]
    engine.on_v6_reach_frame({"v": 1, "type": "v6-reach-result", "code": "CONNECTION_REFUSED", "ok": False,
                              "connectionId": offer["connectionId"], "attemptId": offer["attemptId"],
                              "token": offer["token"]})
    result = await asyncio.wait_for(task, 5)
    assert result.verdict == reach.CONNECTION_REFUSED
    engine.network_report = report_with("insufficient-evidence", verdict=result.verdict)
    row = next(row for row in engine.network_rows() if row["name"] == "inboundReachability")
    assert "被明确拒绝" in row["verdictText"] and "没有观测到回连" not in row["verdictText"]


@pytest.mark.asyncio
async def test_inbound_needs_signaling_and_says_why_when_it_is_missing():
    engine = make_engine()
    await engine.network_check_enable(consent=True, inbound=True, budget=5.0)
    assert engine.signaling is None
    result = await engine.run_network_check()
    assert result["inboundSkipped"] == "SIGNALING_NOT_STARTED"
    inbound = next(row for row in result["rows"] if row["name"] == "inboundReachability")
    assert inbound["status"] == "not-tested"


# ------------------------------------------------------------- 中心日志上报与隐私
@pytest.mark.asyncio
async def test_center_events_are_forwarded_and_never_carry_a_full_address():
    engine = make_engine()
    engine.peer = FakePeer()
    await engine.network_check_enable(consent=True, inbound=False, share_full_address=True, budget=8.0)
    result = await engine.run_network_check()
    assert result["centerEvents"]["emitted"] > 0
    events = engine.peer.store.events
    assert events, "中心日志必须真的收到事件"
    blob = json.dumps(events, ensure_ascii=False)
    assert "2001:" not in blob and "::1" not in blob and "10." not in blob
    for event in events:
        assert "address" not in event["data"]
        assert event["connectionId"] and event["attemptId"], "必须可按 connection/attempt 关联"


@pytest.mark.asyncio
async def test_center_events_are_deferred_honestly_when_not_connected():
    engine = make_engine()
    await engine.network_check_enable(consent=True, inbound=False, budget=8.0)
    result = await engine.run_network_check()
    assert result["centerEvents"]["deferred"] > 0 and result["centerEvents"]["emitted"] == 0


@pytest.mark.asyncio
async def test_disabling_only_clears_the_network_consent():
    engine = make_engine()
    gateway_before, lan_before = engine.gateway_optin, engine.lan_direct
    await engine.network_check_enable(consent=True, share_full_address=True, inbound=True, budget=5.0)
    await engine.network_check_disable()
    status = engine.network_check_status()
    assert status["consented"] is False and status["shareFullAddress"] is False and status["inbound"] is False
    assert engine.network_report is None
    assert engine.gateway_optin is gateway_before and engine.lan_direct is lan_before
    assert engine.network_consent["points"] == ()


# ------------------------------------------------------------------- 界面入口
def test_settings_panel_exposes_the_entry_point_and_renders_rows(qt_app):
    from PySide6 import QtWidgets

    from p2pchat.python_desktop import qt_ui

    window = qt_ui.DesktopApp()
    try:
        engine = make_engine()
        window.engine = engine
        assert window._network_line_text().startswith("检查我的网络：默认关闭")
        assert "未测得显示「—」" in window._network_result_text()
        engine.network_report = report_with("determined", verdict="NO_GLOBAL_V6")
        window._refresh_optin(force=True)
        rendered = window.network_result.text()
        assert "IPv6 入站回连" in rendered and "不是防火墙结论" in rendered
        assert "探测往返：—" in rendered, "未测得必须渲染成「—」"
        assert not hasattr(window, "network_privacy") or window.network_privacy.isChecked() is False
        buttons = [button.text() for button in window.settings.findChildren(QtWidgets.QPushButton)]
        assert "检查我的网络" in buttons
        # 既有三件同意项仍在（不回退）
        assert window.gateway_line.text() and window.lan_line.text() and window.prediction_line.text()
    finally:
        _destroy_window(window, qt_app)


# ----------------------------- v6-reach 结论帧的分发（t62：权威结论不得被静默丢弃）
class FakeWsMessage:
    def __init__(self, payload):
        from aiohttp import WSMsgType

        self.type = WSMsgType.TEXT
        self.data = json.dumps(payload)


class FakeWs:
    """Yields scripted server frames, then ends the stream."""

    def __init__(self, frames):
        self.frames = list(frames)
        self.sent = []
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if not self.frames:
            raise StopAsyncIteration
        return FakeWsMessage(self.frames.pop(0))

    async def send_json(self, frame):
        self.sent.append(frame)

    async def close(self):
        self.closed = True


class FakeClientSession:
    def __init__(self, ws):
        self.ws = ws

    async def ws_connect(self, url, **kwargs):
        return self.ws

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def session_with_frames(monkeypatch, frames):
    """Drive the real SignalSession.run() dispatch with scripted frames."""
    from p2pchat.python_desktop import signal_session as session_module
    from p2pchat.python_desktop.signal_session import SignalSession

    ws = FakeWs(frames)

    async def fake_join(sock, room, secret, name, session_id, capabilities):
        return None

    monkeypatch.setattr(session_module, "join_v2", fake_join)
    session = SignalSession("ws://127.0.0.1:1/ws", "room", "s" * 16, "tester", ("webrtc",),
                            "client-session-0001", factory=lambda: FakeClientSession(ws))
    return session, ws


async def run_frames(session, predicate, timeout=5.0):
    import contextlib

    task = asyncio.ensure_future(session.run())
    try:
        async with asyncio.timeout(timeout):
            while not predicate():
                await asyncio.sleep(0.01)
    finally:
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task
        await session.close()


def result_frame(code, *, token="one-time-token", verdict=None):
    frame = {"v": 1, "type": "v6-reach-result", "code": code, "ok": code == "REACHABLE",
             "connectionId": str(uuid.uuid4()), "attemptId": str(uuid.uuid4()), "token": token}
    if verdict is not None:
        frame["verdict"] = verdict
    return frame


@pytest.mark.asyncio
async def test_signal_session_dispatches_every_authoritative_result_code(monkeypatch):
    codes = ("CONNECTION_REFUSED", "TOKEN_MISMATCH", "REJECTED_BY_POLICY", "SOMETHING_NEW")
    received = []
    session, _ = session_with_frames(monkeypatch, [result_frame(code, token=f"t-{code}") for code in codes])
    session.on_v6_reach_result = lambda frame: received.append(dict(frame))
    await run_frames(session, lambda: len(received) == len(codes))
    assert [frame["code"] for frame in received] == list(codes), "一帧都不许丢"
    assert session.dropped_frames == [] and session.hook_errors == []
    assert session.dropped_frame_count == 0 and session.hook_error_count == 0

    # 经 t58 语义（code 权威）与展示层：只允许「已判定/拒绝/看不懂」，绝不是成功或超时
    mapped = []
    for frame in received:
        try:
            verdict = reach.parse_reach_verdict(frame, token=frame["token"])["verdict"]
        except reach.ReachError:
            verdict = reach.RESULT_UNRECOGNIZED
        word, text = engine_module.V6_VERDICT_TEXT[verdict]
        assert word in {"已判定", "拒绝", "看不懂"}, (frame["code"], word)
        assert "回连成功" not in text and "入站可达" not in text, frame["code"]
        assert "没有观测到回连" not in text, frame["code"]  # 不许折成 TIMEOUT
        mapped.append((frame["code"], word))
    assert mapped == [("CONNECTION_REFUSED", "已判定"), ("TOKEN_MISMATCH", "拒绝"),
                      ("REJECTED_BY_POLICY", "拒绝"), ("SOMETHING_NEW", "看不懂")]


@pytest.mark.asyncio
async def test_signal_session_records_a_missing_hook_instead_of_dropping_silently(monkeypatch):
    connection_id, attempt_id = str(uuid.uuid4()), str(uuid.uuid4())
    frames = [{"v": 1, "type": "v6-reach-result", "code": "CONNECTION_REFUSED", "ok": False,
               "connectionId": connection_id, "attemptId": attempt_id, "token": "t-1"},
              {"v": 1, "type": "signal", "from": "peer-2", "attemptId": attempt_id}]
    session, _ = session_with_frames(monkeypatch, frames)   # 故意不装 on_v6_reach_result
    signals = []
    session.on_signal = signals.append
    await run_frames(session, lambda: bool(session.dropped_frames) and bool(signals))
    assert session.dropped_frames == ["v6-reach-result"] and session.dropped_frame_count == 1
    assert session.hook_errors == [] and session.hook_error_count == 0
    assert signals[0]["type"] == "signal", "会话没崩：后续帧照常分发"


@pytest.mark.asyncio
async def test_signal_session_keeps_a_failing_hook_distinct_from_a_dropped_frame(monkeypatch):
    session, _ = session_with_frames(monkeypatch, [result_frame("TOKEN_MISMATCH")])
    seen = []

    def raising(frame):
        seen.append(dict(frame))
        raise RuntimeError("hook blew up")

    session.on_v6_reach_result = raising
    await run_frames(session, lambda: bool(session.hook_errors))
    assert seen and seen[0]["code"] == "TOKEN_MISMATCH", "帧确实到达过 hook"
    assert session.hook_errors == [{"type": "v6-reach-result", "error": "RuntimeError"}]
    assert session.dropped_frames == [] and session.dropped_frame_count == 0
    assert session.hook_error_count == 1, "异常与丢弃必须区分开"


@pytest.mark.asyncio
async def test_the_engine_hook_receives_the_dispatch_through_the_session(monkeypatch):
    """把 t53 装好的 hook 接在会话上，结论必须一路到达引擎（不再停在会话里）。"""
    engine = make_engine()
    session, _ = session_with_frames(monkeypatch, [result_frame("CONNECTION_REFUSED")])
    session.on_v6_reach_result = engine.on_v6_reach_frame   # engine.start() 就是这么装的

    async def start():
        task = asyncio.ensure_future(session.run())
        engine._v6_result_future = asyncio.get_running_loop().create_future()
        try:
            async with asyncio.timeout(5):
                while not engine._v6_result_future.done():
                    await asyncio.sleep(0.01)
            return engine._v6_result_future.result()
        finally:
            task.cancel()
            import contextlib

            with contextlib.suppress(asyncio.CancelledError):
                await task
            await session.close()

    delivered = await start()
    assert delivered["code"] == "CONNECTION_REFUSED" and delivered["ok"] is False
    assert session.dropped_frames == [] and session.hook_errors == []
