"""Round-2 review contracts for the desktop client.

Each test pins one finding from REVIEW-ROUND1.md so the fix cannot silently
regress:

* H1  the pinned ``peer.join_v2`` dependency fails readably when it is absent;
* M1  ``works`` ("什么网络下可行") exists on the method data layer;
* M2  实测延迟 only ever comes from a message-capable path — a probe/observation
      round-trip is reported under its own name;
* M3  the three ICE rows are labelled as one protocol, on the interface-agnostic
      data/summary layer so the Qt port inherits it;
* plus the availability vocabulary, the pausable central diagnostic collection
      and the benchmark ceiling.

These checks deliberately avoid the UI toolkit: the desktop front end is being
ported from Tkinter to Qt, so anything asserted here must stay true across that
port. ``summary()``/``rows()``/``methods.py`` is the contract the port consumes.
"""
from __future__ import annotations

import ast
import importlib.util
import inspect
import sys
import types
from pathlib import Path

import pytest

from p2pchat.python_desktop import methods as plain
from p2pchat.python_desktop.engine import DesktopEngine, EngineConfig, _TelemetryGate

REPO = Path(__file__).resolve().parents[3]
DOC = REPO / "p2pchat" / "docs" / "DESKTOP-PYTHON.md"


def engine() -> DesktopEngine:
    return DesktopEngine(EngineConfig(url="ws://127.0.0.1:9/ws", room="lab", secret="secretsecret123"))


# --------------------------------------------------------------------------- H1
def test_signal_session_without_join_v2_fails_readably(monkeypatch) -> None:
    """A peer.py without join_v2 must explain itself, not raise a bare ImportError."""
    from p2pchat.python_desktop import signal_session as real_module

    fake_peer = types.ModuleType("p2pchat.peer")  # deliberately no join_v2
    monkeypatch.setitem(sys.modules, "p2pchat.peer", fake_peer)
    spec = importlib.util.spec_from_file_location("signal_session_guard_probe", real_module.__file__)
    fresh = importlib.util.module_from_spec(spec)
    with pytest.raises(ImportError) as error:
        spec.loader.exec_module(fresh)
    message = str(error.value)
    assert "join_v2" in message
    assert "t16" in message, "必须说明依赖随 t16 冻结"
    assert "peer.py" in message
    assert "cannot import name" in message, "保留原始原因便于定位"


def test_signal_session_pins_the_join_v2_dependency() -> None:
    from p2pchat.python_desktop import signal_session

    assert callable(signal_session.join_v2)
    assert "join_v2" in signal_session.JOIN_V2_REQUIREMENT
    assert "t16" in signal_session.JOIN_V2_REQUIREMENT
    documented = DOC.read_text(encoding="utf-8")
    assert "join_v2" in documented, "文档必须写明桌面依赖 peer.py 的 join_v2"
    assert "t16" in documented, "文档必须写明随 t16 一并冻结"
    assert "随 t16 一并冻结" in documented


def test_desktop_reuses_join_v2_instead_of_reimplementing_it() -> None:
    from p2pchat.python_desktop import signal_session

    source = (REPO / "p2pchat" / "python_desktop" / "signal_session.py").read_text(encoding="utf-8")
    assert "join_v2(" in source, "加入必须复用 peer.py 的 join_v2"
    tree = ast.parse(source)
    defined = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            defined.add(node.name)
        elif isinstance(node, ast.Assign):
            defined.update(target.id for target in node.targets if isinstance(target, ast.Name))
    for duplicated in ("derive_join_key", "join_proof", "join_key", "HKDF"):
        assert duplicated not in defined, f"signal_session.py 不应定义 {duplicated}"
    assert "join_challenge" not in source.replace("join_v2", ""), "不应自己发 join_challenge"
    for imported in ("HKDF", "hashes"):
        assert not hasattr(signal_session, imported), f"signal_session 不应引入 {imported}"


# --------------------------------------------------------------------------- M2
def test_latency_never_comes_from_a_probe_or_observation() -> None:
    client = engine()
    target = client.target_for("peer-key")
    probe = client._method(target, plain.METHOD_BY_ID["udp-probe"])
    probe.state = "direct"
    probe.rtt = 12.5
    summary = client.summary("peer-key")
    assert summary["canSend"] is False
    assert summary["latency"] is None, "没有可聊天直连时不得给出实测延迟"
    assert summary["probeRtt"] == 12.5, "探测往返时间必须单独命名"
    assert "不是聊天延迟" in summary["probeRttLabel"]
    # The row itself must not put the probe round-trip in the 实测延迟 slot either.
    probe_row = next(row for row in summary["rows"] if row["id"] == "udp-probe")
    assert probe_row["latency"] is None
    assert probe_row["probeRtt"] == 12.5
    assert probe_row["canMessage"] is False

    webrtc = client._method(target, plain.METHOD_BY_ID["ice-dual"])
    webrtc.state = "direct"
    webrtc.rtt = 3.5
    assert client.summary("peer-key")["latency"] == 3.5
    webrtc_row = next(row for row in client.summary("peer-key")["rows"] if row["id"] == "ice-dual")
    assert webrtc_row["latency"] == 3.5
    assert webrtc_row["probeRtt"] is None


def test_no_target_yields_no_latency_number() -> None:
    client = engine()
    summary = client.summary("nobody")
    assert summary["latency"] is None
    assert summary["probeRtt"] is None
    assert summary["canSend"] is False


# ----------------------------------------------------------------- item 7 (M2b)
def test_availability_is_always_one_of_the_documented_three() -> None:
    client = engine()
    client.target_for("peer-key")
    documented = set(plain.AVAILABILITY.values())
    assert documented == {"可用", "不可用", "不支持"}  # 词表本身是这三词
    for row in client.rows("peer-key"):
        assert row["availability"] in documented, row
    # "尚未出结果" 只描述"还没测出来"，所以只出现在方式本身可用的行上；不可用/不支持的行
    # 必须给出原因而不是含糊的"尚未出结果"。
    pending = [row for row in client.rows("peer-key") if row["state"] == "pending"]
    assert pending, "未开始时应至少有一行是等待中"
    for row in pending:
        if row["availability"] == "可用":
            assert row["availabilityNote"] == "尚未出结果"
        else:
            assert row["availabilityNote"] == ""
            assert row["detail"], f"{row['title']} 不可用/不支持时必须说明原因"


def test_started_capabilities_drive_availability() -> None:
    client = engine()
    client.target_for("peer-key")
    client.native_capabilities = [
        {"mechanism": "quic", "status": "available"},
        {"mechanism": "tcp", "status": "available"},
    ]
    rows = {row["id"]: row for row in client.rows("peer-key")}
    assert rows["quic"]["availability"] == "可用"
    assert rows["ice-dual"]["availability"] == "可用"
    # 原生方式的可用性必须来自适配器的 capability 报告，而不是硬编码。
    client.native_capabilities = [{"mechanism": "quic", "status": "unsupported", "reason": "PLATFORM"}]
    rows = {row["id"]: row for row in client.rows("peer-key")}
    assert rows["quic"]["availability"] == "不支持"


class FakeGateway:
    """只实现能力报告，用来把"平台能不能核对"与"用户同不同意"分开验证。"""

    def __init__(self, status: str, reason: str | None = None, consented: bool = False):
        self.status = status
        self.reason = reason or ("EXPLICIT_OPT_IN_REQUIRED" if status == "available" else "NO_LOCAL_ROUTING_TABLE")
        self.consented = consented
        self.audit = types.SimpleNamespace(events=[])

    def capability(self) -> dict:
        return {
            "v": 1,
            "status": self.status,
            "reason": self.reason,
            "gateway": "10.0.0.1" if self.status == "available" else None,
            "consentRequired": True,
            "consented": self.consented,
        }

    def capability_line(self) -> str:
        if self.status != "available":
            return "路由器放行：不可用"
        return "路由器放行：" + ("已同意，可以试一次" if self.consented else "可用，但需要你点同意")

    def consent_text(self) -> str:
        return "同意"

    def technical_detail(self) -> str:
        return "细节"


def test_gateway_availability_comes_from_the_platform_capability() -> None:
    """平台能核对 → 可用且携带 consentRequired；"还没同意"不是"不支持"。"""
    client = engine()
    client.target_for("peer-key")
    client.gateway_optin = FakeGateway("available")
    rows = {row["id"]: row for row in client.rows("peer-key")}
    gateway = rows["gateway"]
    assert gateway["availability"] == "可用", "平台可核对时必须是可用，不能显示成不支持"
    assert gateway["consentRequired"] is True
    assert gateway["consented"] is False
    assert gateway["canMessage"] is False, "路由器放行永远不能传消息"
    assert "显式授权" in gateway["detail"], "未同意只能体现在说明里"
    assert "可用，但需要你点同意" in gateway["capabilityLine"]
    # 说明里不得同时出现自相矛盾的"不支持"。
    assert "不支持" not in gateway["detail"]

    client.gateway_optin = FakeGateway("available", consented=True)
    gateway = {row["id"]: row for row in client.rows("peer-key")}["gateway"]
    assert gateway["availability"] == "可用"
    assert gateway["consented"] is True

    client.gateway_optin = FakeGateway("unsupported")
    gateway = {row["id"]: row for row in client.rows("peer-key")}["gateway"]
    assert gateway["availability"] == "不支持", "平台无法核对时才是 不支持"
    assert gateway["detail"], "不支持时必须给出平台原因"


def test_observation_availability_follows_the_server_stun_endpoint() -> None:
    """STUN 观测的可用性只取决于有没有可用的 STUN 端点。"""
    without = engine()
    without.target_for("peer-key")
    row = {r["id"]: r for r in without.rows("peer-key")}["stun-observation"]
    assert row["availability"] == "不支持", "服务器没下发 STUN 地址时不能显示为可用"
    assert row["availabilityNote"] == ""
    assert "STUN" in row["detail"] and "服务器" in row["detail"]
    assert plain.reason("NO_STUN_SERVER") == row["detail"]

    with_endpoint = DesktopEngine(
        EngineConfig(url="ws://127.0.0.1:9/ws", room="lab", secret="secretsecret123", stun_url="stun:127.0.0.1:3478")
    )
    with_endpoint.target_for("peer-key")
    row = {r["id"]: r for r in with_endpoint.rows("peer-key")}["stun-observation"]
    assert row["availability"] == "可用"
    assert row["availabilityNote"] == "尚未出结果"
    assert row["detail"] == ""

    # 观测失败（有端点但没问到）→ 不可用；服务器没下发端点（NO_STUN_SERVER）→ 不支持。
    target = with_endpoint.targets["peer-key"]
    state = with_endpoint._method(target, plain.METHOD_BY_ID["stun-observation"])
    state.state = "unavailable"
    state.failure = "STUN_MAPPING_UNAVAILABLE"
    assert with_endpoint.observation_availability(state) == "不可用"
    state.state = "unsupported"
    state.failure = "NO_STUN_SERVER"
    assert with_endpoint.observation_availability(state) == "不支持"


# --------------------------------------------------------------------------- M3
def test_three_address_selections_are_one_protocol_on_the_data_layer() -> None:
    """The Qt port consumes this; the sentence lives with the method data."""
    assert plain.WEBRTC_PROFILE_NOTE == "是同一个 WebRTC 直连的三种地址选择，不是三个独立协议"
    assert tuple(plain.WEBRTC_PROFILE_IDS) == ("ice-dual", "ice-v6", "ice-v4")
    for method_id in plain.WEBRTC_PROFILE_IDS:
        assert plain.METHOD_BY_ID[method_id]["mechanism"] == "webrtc"
    client = engine()
    client.target_for("peer-key")
    summary = client.summary("peer-key")
    assert summary["webRtcProfileNote"] == plain.WEBRTC_PROFILE_NOTE


# ------------------------------------------------------------ STUN is not a relay
def test_stun_row_is_not_a_relay_on_the_data_layer() -> None:
    stun = plain.METHOD_BY_ID["stun-observation"]
    assert "不是中继" in stun["explain"]
    assert "不转发" in stun["explain"]
    client = engine()
    client.target_for("peer-key")
    row = next(row for row in client.rows("peer-key") if row["id"] == "stun-observation")
    assert "不是中继" in row["explain"]


# ------------------------------------------------------------------ M1 works column
def test_works_column_is_on_the_method_data_and_every_row() -> None:
    client = engine()
    client.target_for("peer-key")
    for row in client.rows("peer-key"):
        assert row["works"] == plain.METHOD_BY_ID[row["id"]]["works"]
        assert row["works"], row["id"]
    doc = (REPO / "p2pchat" / "docs" / "METHODS-PLAIN.md").read_text(encoding="utf-8")
    for method in plain.METHODS:
        assert method["works"] in doc, f"{method['works']} 必须逐字来自文档第 4 列"


# -------------------------------------------------------- item 10 (telemetry switch)
def test_central_collection_is_on_by_default_and_pausable() -> None:
    client = engine()
    assert client.telemetry_paused is False
    status = client.telemetry_status()
    assert status["uploadEnabled"] is True
    assert status["complete"] is True
    assert status["note"] == ""

    class FakeQueue:
        session = "session-id"

        def __init__(self):
            self.events = [{"id": "1"}]

        def emit(self, *args, **kwargs):
            return None

        def pending(self, limit=30):
            return list(self.events[:limit])

        def ack(self, *args, **kwargs):
            return None

        def close(self):
            return None

    inner = FakeQueue()
    client.peer = types.SimpleNamespace(store=inner)
    client.peer.store = _TelemetryGate(client, inner)

    assert client.peer.store.pending(30) == [{"id": "1"}]
    paused = client.set_telemetry_paused(True)
    assert paused["uploadEnabled"] is False
    assert paused["complete"] is False
    assert paused["note"] == plain.TELEMETRY_NOTE
    assert "中心记录不完整" in paused["note"]
    assert client.peer.store.pending(30) == [], "暂停时不得上传"
    assert client.telemetry_incomplete is True
    assert client.summary("peer-key")["telemetry"]["note"].startswith("中心记录不完整")

    resumed = client.set_telemetry_paused(False)
    assert resumed["uploadEnabled"] is True
    assert resumed["text"] == plain.TELEMETRY_ON_TEXT
    assert "已开启" in resumed["text"]
    inner.events.clear()
    client.peer.store.pending(30)
    assert client.telemetry_incomplete is False, "全部确认后中心记录应恢复完整"


def test_paused_panel_copy_never_says_running_even_with_an_empty_queue() -> None:
    """R1：暂停后面板必须说「已暂停」，绝不能还说「已开启」。"""
    client = engine()
    client.target_for("peer-key")

    class EmptyQueue:
        session = "session-id"

        def emit(self, *args, **kwargs):
            return None

        def pending(self, limit=30):
            return []

        def ack(self, *args, **kwargs):
            return None

        def close(self):
            return None

    inner = EmptyQueue()
    client.peer = types.SimpleNamespace(store=inner)
    client.peer.store = _TelemetryGate(client, inner)
    assert client.peer.store.pending(30) == []

    status = client.set_telemetry_paused(True)
    assert status["uploadEnabled"] is False
    assert status["paused"] is True
    # 队列已空 → 中心那份其实是完整的，不能说「中心记录不完整」。
    assert status["complete"] is True
    assert status["note"] == ""
    text = status["text"]
    assert "已暂停" in text, text
    assert "已开启" not in text, text
    assert plain.TELEMETRY_NOTE not in text
    # summary() 与面板拿到的是同一份文案（唯一来源）。
    assert client.summary("peer-key")["telemetry"]["text"] == text

    # 暂停期间本机又攒了新记录 → 文案变成「中心记录不完整」，但仍不得说「已开启」。
    inner.pending = lambda limit=30: [{"id": "new"}]
    assert client.peer.store.pending(30) == []
    assert client.telemetry_incomplete is True
    text = client.summary("peer-key")["telemetry"]["text"]
    assert "中心记录不完整" in text
    assert "已暂停" in text and "已开启" not in text


def test_ui_has_one_telemetry_renderer_used_by_both_screens() -> None:
    """R1 的根因是两个渲染点各写一套判断，必须在界面上只有一个入口。

    t24 之后界面层是 Qt（``qt_ui.py``）；Tk 实现已移出产品路径。
    """
    source = (REPO / "p2pchat" / "python_desktop" / "qt_ui.py").read_text(encoding="utf-8")
    assert "def _apply_telemetry" in source
    render = source.split("def _render", 1)[1].split("def _target_name", 1)[0]
    refresh = source.split("def _refresh_paths", 1)[1].split("def _on_telemetry_toggle", 1)[0]
    assert "_apply_telemetry(event)" in render, "telemetry 事件必须走统一渲染点"
    assert "_apply_telemetry(" in refresh, "_refresh_paths 必须走统一渲染点"
    # 旧的反话（把暂停说成已开启）不得残留。
    assert "自动汇集已开启。" not in source
    assert "自动汇集已暂停；本机记录仍在本地累积。" not in source


# ------------------------------------------------------------------ item 8 (32 MiB)
def test_benchmark_default_matches_the_stated_32_mib_ceiling() -> None:
    from p2pchat.python_desktop import engine as engine_module

    assert engine_module.BENCHMARK_MAX_BYTES == 32 * 1024 * 1024
    for function in (DesktopEngine.benchmark, DesktopEngine._webrtc_benchmark):
        default = inspect.signature(function).parameters["max_bytes"].default
        assert default == 32 * 1024 * 1024, function
    source = (REPO / "p2pchat" / "python_desktop" / "engine.py").read_text(encoding="utf-8")
    assert "session.benchmark(seconds=seconds, max_bytes=BENCHMARK_MAX_BYTES)" in source, (
        "原生通道也必须用同一个 32 MiB 上限，界面上写的才不会是空话"
    )
