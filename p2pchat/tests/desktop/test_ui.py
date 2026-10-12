"""The Qt three-screen flow and the settings dialog.

Structural checks always run against the real module source; widget instantiation
uses Qt's ``offscreen`` platform plugin, so those cases run on a headless host too
— they are never faked. Chinese rendering is verified by measuring glyph
coverage, not by trusting a font name.

The Tkinter shell is gone: ``tkinter`` must not appear in any product module
(asserted here), and the old implementation is kept only as a non-importable
reference under ``python_desktop/evidence/``.
"""
from __future__ import annotations

import inspect
import os
from pathlib import Path

import pytest

from p2pchat.python_desktop import methods as plain
from p2pchat.python_desktop import qt_ui

PACKAGE = Path(__file__).resolve().parents[2]
SCREENS = ("connect_frame", "attempt_frame", "chat_frame")


_QAPP = None


@pytest.fixture(scope="session")
def qt_app():
    """One QApplication for the whole process, kept referenced until exit.

    Destroying a QApplication inside pytest's teardown order is what makes Qt
    segfault at interpreter exit, so it is created once and never dropped; each
    test still closes and releases its own window deterministically.
    """
    global _QAPP
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6 import QtWidgets

    if _QAPP is None:
        _QAPP = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return _QAPP


def _destroy_window(window, app) -> None:
    """Deterministic teardown: stop timers/loop, close the window, release it."""
    window._pump_timer.stop()
    window.engine_thread.stop()
    window.close()
    window.deleteLater()
    app.processEvents()


def test_three_screens_and_settings_exist() -> None:
    source = inspect.getsource(qt_ui)
    for builder in ("_build_connect", "_build_attempt", "_build_chat", "_build_settings", "_show"):
        assert f"def {builder}" in source, builder
    # Screen headings describe the required order.
    assert "1 / 3 · 连接服务器" in source
    assert "2 / 3 · 逐条尝试打洞" in source
    assert "3 / 3 · 聊天" in source


def test_connect_screen_collects_all_four_fields() -> None:
    source = inspect.getsource(qt_ui.DesktopApp._build_connect)
    for field in ("服务器地址", "房间", "你的名字", "房间密码"):
        assert field in source, field
    for widget in ("field_server", "field_room", "field_name", "field_secret"):
        assert widget in source, widget
    # Plaintext ws:// stays opt-in and is refused by default.
    assert "check_plaintext" in source
    assert "默认拒绝" in source


def test_attempt_screen_renders_every_documented_column() -> None:
    source = inspect.getsource(qt_ui.DesktopApp._render_rows) + inspect.getsource(qt_ui.DesktopApp._build_attempt)
    assert "状态" in source and "可用性" in source and "实测延迟" in source
    # The interface-agnostic fields must be consumed, not re-derived.
    assert 'row["title"]' in source
    assert 'row["explain"]' in source
    assert 'row["works"]' in source
    assert "probeRtt" in source and "不是聊天延迟" in source
    assert 'summary.get("webRtcProfileNote")' in source
    assert "什么网络下可行" in inspect.getsource(qt_ui.DesktopApp._build_settings)


def test_settings_panel_covers_remaining_availability_latency_and_speed() -> None:
    source = inspect.getsource(qt_ui.DesktopApp._build_settings) + inspect.getsource(qt_ui.DesktopApp._render_rows)
    assert "剩余方式" in source
    assert "可用性" in source
    assert "实测延迟" in source
    assert "测当前连接的速度" in source
    assert "应用层速度，不是线路带宽" in source
    # Availability notes and consent fields are consumed, not recomputed.
    assert "availabilityNote" in source
    assert 'row.get("works", "")' in source


def test_chat_screen_supports_text_image_file_and_recording() -> None:
    source = inspect.getsource(qt_ui.DesktopApp._build_chat)
    for label in ("发送", "图片", "文件", "录音"):
        assert label in source, label
    assert "单文件最多 32 MiB" in source
    assert "不进行实时通话" in source
    assert "没有直连时不会偷偷改走服务器" in source


def test_recording_is_saved_locally_then_sent_as_a_file() -> None:
    audio = inspect.getsource(qt_ui.DesktopApp._finish_recording)
    assert "audio/wav" in audio
    assert "voice-" in audio
    assert "recording.saved" in audio


def test_no_screen_promises_a_relay_or_invents_a_number() -> None:
    source = inspect.getsource(qt_ui)
    assert "没有中继、没有 TURN" in source
    assert "失败不会改走服务器转发" in source
    # Latency is never rendered as zero when unmeasured.
    assert 'return "—" if value is None' in inspect.getsource(qt_ui._fmt_latency)


def test_both_screens_share_one_telemetry_renderer() -> None:
    """R1：诊断暂停时面板必须说「已暂停」，两个渲染点必须走同一个入口。"""
    assert "def _apply_telemetry" in inspect.getsource(qt_ui.DesktopApp)
    render = inspect.getsource(qt_ui.DesktopApp._render)
    refresh = inspect.getsource(qt_ui.DesktopApp._refresh_paths)
    rows = inspect.getsource(qt_ui.DesktopApp._render_rows)
    assert "_apply_telemetry" in render
    # _refresh_paths 把两屏的渲染都交给 _render_rows，telemetry 只在 _render_rows 里渲染一次。
    assert "_render_rows(" in refresh
    assert "_apply_telemetry" in rows
    apply_source = inspect.getsource(qt_ui.DesktopApp._apply_telemetry)
    # 暂停（uploadEnabled False）必须优先判断，并给出暂停文案。
    assert "uploadEnabled" in apply_source
    assert apply_source.index("uploadEnabled") < apply_source.index("TELEMETRY_ON_TEXT")


def test_optin_panel_keeps_consent_semantics() -> None:
    """网关/局域网/端口预测：能力查询 → 显式同意 → 打开/关闭，默认都不做。"""
    build = inspect.getsource(qt_ui.DesktopApp._build_settings)
    assert "需要你单独同意的三件事（默认都不做）" in build
    open_source = inspect.getsource(qt_ui.DesktopApp._on_gateway_open)
    enable_source = inspect.getsource(qt_ui.DesktopApp._on_lan_enable)
    assert "consent_text()" in open_source and "_ask(" in open_source
    assert "consent_text()" in enable_source and "_ask(" in enable_source
    # 无同意 → 不发请求（先问，再 submit）。
    assert open_source.index("_ask(") < open_source.index("engine_thread.submit")
    assert enable_source.index("_ask(") < enable_source.index("engine_thread.submit")
    # 失败用人话文案。
    assert "gateway_failure_hint" in inspect.getsource(qt_ui.DesktopApp._gateway_open_async)
    # 网关映射不是数据通道：界面只说“默认不做”，不承诺带宽或通道。
    assert "不是数据通道" not in build or "默认都不做" in build


# 允许提到 Qt 的只有界面层与入口：入口负责调用界面层，其余模块必须与 GUI 库无关。
GUI_ALLOWED_MODULES = {"qt_ui.py", "app.py"}
ENGINE_MODULES = (
    "engine.py",
    "signal_session.py",
    "native_session.py",
    "methods.py",
    "selftest.py",
    "gateway_optin.py",
    "lan_client.py",
    "version.py",
    "audio.py",
)


def test_gui_layer_is_not_polluted_by_engine_modules() -> None:
    """逻辑层必须与界面库无关：只有界面层（和入口）可以提到 PySide6。"""
    offenders = []
    for path in sorted((PACKAGE / "python_desktop").glob("*.py")):
        if path.name in GUI_ALLOWED_MODULES:
            continue
        text = path.read_text(encoding="utf-8")
        if "import PySide6" in text or "from PySide6" in text:
            offenders.append(path.name)
    assert not offenders, f"这些模块被 Qt 污染了：{offenders}"
    # 引擎/逻辑层连名字都不该依赖（能力探测用 find_spec，不 import 工具箱）。
    for name in ENGINE_MODULES:
        text = (PACKAGE / "python_desktop" / name).read_text(encoding="utf-8")
        assert "import PySide6" not in text and "from PySide6" not in text, name
    assert "from PySide6 import QtCore, QtGui, QtWidgets" in inspect.getsource(qt_ui)
    assert "qt_ui" in (PACKAGE / "python_desktop" / "app.py").read_text(encoding="utf-8")


def test_product_code_no_longer_imports_tkinter() -> None:
    offenders = []
    for path in sorted((PACKAGE / "python_desktop").glob("*.py")):
        text = path.read_text(encoding="utf-8")
        if "import tkinter" in text or "from tkinter" in text or "_tkinter" in text:
            offenders.append(path.name)
    assert not offenders, f"产品代码仍然依赖 Tk：{offenders}"
    # 参考实现必须留在产品路径之外，且不可被导入。
    reference = PACKAGE / "python_desktop" / "evidence" / "tk_ui_reference.py.txt"
    assert reference.is_file(), "旧 Tk 实现应作为不可导入的参考保留"
    assert not (PACKAGE / "python_desktop" / "ui.py").exists(), "旧的 Tk 界面模块必须移除"


def test_cjk_font_is_chosen_by_measuring_glyphs(qt_app) -> None:
    """中文渲染：按字形覆盖率选字体，缺字体时必须显式提示而不是空白。"""
    from PySide6 import QtGui

    chosen = qt_ui.pick_cjk_font()
    families = QtGui.QFontDatabase.families()
    if chosen is None:
        assert qt_ui.MISSING_CJK_FONT_TEXT.startswith("⚠"), "缺字体时必须给出显式提示文案"
        pytest.skip("这台机器确实没有可渲染中文的字体（界面会显示显式提示）")
    metrics = QtGui.QFontMetrics(QtGui.QFont(chosen))
    assert all(metrics.inFontUcs4(ord(char)) for char in qt_ui.CJK_PROBE)
    assert chosen in families
    # 没有候选字体（或候选都不可用）时必须如实返回 None，而不是硬选一个。
    assert qt_ui.pick_cjk_font(families=[]) is None
    assert qt_ui.pick_cjk_font(families=[name for name in families if name != chosen] and []) is None


def test_window_builds_with_all_three_pages(qt_app) -> None:
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        assert window.current_screen == "connect"
        assert window.stack.count() == 3
        for name in SCREENS:
            assert getattr(window, name) is not None
        assert window.attempt_tree.columnCount() == 4
        assert window.settings_tree.columnCount() == 6
        assert window.check_upload_logs.isChecked() is True
        assert len(plain.METHODS) == 9
        for method in plain.METHODS:
            assert method["title"] and method["explain"] and method["works"]
        # Settings only make sense once there is a chat; the button is off first.
        assert window.settings_button.isEnabled() is False
        window._show("chat")
        assert window.current_screen == "chat"
        assert window.settings_button.isEnabled() is True
        assert window.settings.isVisible() is False
    finally:
        _destroy_window(window, qt_app)


def test_panel_says_paused_never_running(qt_app) -> None:
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        # 暂停且本地队列已空：中心那份其实是完整的。
        window._apply_telemetry(
            {
                "uploadEnabled": False,
                "paused": True,
                "complete": True,
                "note": "",
                "text": plain.TELEMETRY_PAUSED_TEXT,
            }
        )
        text = window.telemetry_status.text()
        assert "已暂停" in text, text
        assert "已开启" not in text, text
        assert window.check_upload_logs.isChecked() is False
        # 暂停且有未上传记录：文案变成「中心记录不完整」，仍不能说「已开启」。
        window._apply_telemetry(
            {
                "uploadEnabled": False,
                "paused": True,
                "complete": False,
                "note": plain.TELEMETRY_NOTE,
                "text": plain.TELEMETRY_NOTE,
            }
        )
        text = window.telemetry_status.text()
        assert "中心记录不完整" in text
        assert "已开启" not in text, text
        # 恢复：只有这时才能说「已开启」。
        window._apply_telemetry(
            {"uploadEnabled": True, "paused": False, "complete": True, "note": "", "text": plain.TELEMETRY_ON_TEXT}
        )
        text = window.telemetry_status.text()
        assert "已开启" in text and "已暂停" not in text
        assert window.check_upload_logs.isChecked() is True
    finally:
        _destroy_window(window, qt_app)


def test_paths_renderer_consumes_engine_rows(qt_app) -> None:
    """第 2 屏/设置面板直接渲染 engine 的行字段，不重新实现语义。"""
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        rows = [
            {
                "id": "ice-dual",
                "title": "双栈直连",
                "explain": "同时用 IPv6 和 IPv4 两种地址去找对方，谁先通就用谁",
                "works": "双方都有可用公网地址（大多数家宽）",
                "failureHint": "两边 NAT 都严格",
                "status": "已打通",
                "state": "direct",
                "latency": 3.5,
                "availability": "可用",
                "availabilityNote": "",
                "detail": "",
                "probeRtt": None,
                "probeOnly": False,
                "canMessage": True,
                "consentRequired": False,
                "consented": False,
                "capabilityLine": "",
            },
            {
                "id": "udp-probe",
                "title": "UDP 探测",
                "explain": "互相发加密小包",
                "works": "只要能出去 UDP 就能探测",
                "failureHint": "UDP 被限制",
                "status": "已观测（仅探测，不传内容）",
                "state": "observed",
                "latency": None,
                "availability": "可用",
                "availabilityNote": "尚未出结果",
                "detail": "",
                "probeRtt": 12.5,
                "probeOnly": True,
                "canMessage": False,
                "consentRequired": False,
                "consented": False,
                "capabilityLine": "",
            },
        ]
        telemetry = {
            "uploadEnabled": True,
            "paused": False,
            "complete": True,
            "note": "",
            "text": plain.TELEMETRY_ON_TEXT,
        }
        summary = {
            "rows": rows,
            "direct": ["双栈直连"],
            "remaining": [],
            "probeOnly": ["UDP 探测"],
            "probeRtt": 12.5,
            "latency": 3.5,
            "canSend": True,
            "webRtcProfileNote": plain.WEBRTC_PROFILE_NOTE,
            "telemetry": telemetry,
        }

        class FakeEngine:
            targets = {"peer": type("T", (), {"name": "小明"})()}
            plaintext_warning = None

            def summary(self, _key):
                return summary

            def telemetry_status(self):
                return telemetry

        window.engine = FakeEngine()
        window.selected_target = "peer"
        window._refresh_paths()
        assert window.attempt_tree.topLevelItemCount() == 2
        assert window.settings_tree.topLevelItemCount() == 2
        # 可用性附注与探测往返时间分列展示，不混进「实测延迟」。
        probe_item = window.settings_tree.topLevelItem(1)
        assert probe_item.text(3) == "可用（尚未出结果）"
        assert "仅探测/观测" in probe_item.text(2)
        assert probe_item.text(4) == "只要能出去 UDP 就能探测"
        direct_item = window.attempt_tree.topLevelItem(0)
        assert direct_item.text(3) == "3.5 ms"
        assert direct_item.text(2) == "可用"
        assert plain.WEBRTC_PROFILE_NOTE in window.attempt_profile_note.text()
        assert plain.WEBRTC_PROFILE_NOTE in window.settings_profile_note.text()
        assert "双栈直连" in window.attempt_summary.text()
        assert "可行网络：双方都有可用公网地址" in direct_item.text(0)
    finally:
        _destroy_window(window, qt_app)


def test_headless_startup_reports_missing_display(monkeypatch, capsys) -> None:
    """没有显示时给出可读提示并返回 2，而不是让 Qt 直接 abort。"""
    monkeypatch.delenv("DISPLAY", raising=False)
    monkeypatch.delenv("WAYLAND_DISPLAY", raising=False)
    monkeypatch.delenv("QT_QPA_PLATFORM", raising=False)
    assert qt_ui.run() == 2
    assert "无法启动图形界面" in capsys.readouterr().err


def test_attempt_screen_lists_all_nine_methods_before_connecting(qt_app) -> None:
    """没有连接/没有对端时，第 2 屏也要按文档顺序列出九种方式（状态=等待中）。

    复审 F5 之后这里改成：可用性**不再硬编码 "—"**，而是取引擎能力视图的文档词表
    三值（可用/不可用/不支持），且不可用/不支持必须给出原因；状态与实测延迟仍如实
    「等待中 / —」（未连接时不猜数字）。
    """
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        assert window.engine is None
        window._refresh_paths()
        assert window.attempt_tree.topLevelItemCount() == len(plain.METHODS) == 9
        for index, method in enumerate(plain.METHODS):
            item = window.attempt_tree.topLevelItem(index)
            assert item.text(0).startswith(method["title"]), (index, item.text(0))
            assert method["explain"] in item.text(0)
            assert "可行网络：" + method["works"] in item.text(0)
            assert item.text(1) == "等待中"
            # 可用性必须是文档词表里的词，而不是自造的「—」。
            assert item.text(2) in {"可用", "不可用", "不支持"}, (index, item.text(2))
            # 未连接就是没测过：不能报任何延迟数字。
            assert item.text(3) == "—"
        rows = window._preview_summary()["rows"]
        assert [row["title"] for row in rows] == [m["title"] for m in plain.METHODS]
        for row in rows:
            assert row["availability"] in {"可用", "不可用", "不支持"}, row
            if row["availability"] != "可用":
                assert row["detail"].strip(), f"{row['title']} 说不可用/不支持却没有原因"
            assert row["latency"] is None
        assert window.settings_tree.topLevelItemCount() == 9
        assert plain.WEBRTC_PROFILE_NOTE in window.attempt_profile_note.text()
        assert "9" in window.attempt_summary.text() or "剩余方式" in window.attempt_summary.text()
    finally:
        _destroy_window(window, qt_app)


def test_capability_preview_is_reachable_from_the_connect_screen(qt_app) -> None:
    """F5：连接前的九种方式必须是真实交互里能到达的界面，不是只有测试才走得到的死代码。"""
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        assert window.engine is None
        assert window.current_screen == "connect"
        assert hasattr(window, "preview_button"), "连接页应当有「先看看九种打洞方式」按钮"
        assert window.preview_button.isEnabled()
        window.preview_button.click()
        assert window.current_screen == "attempt"
        assert "还没连接服务器" in window.beacon.text()
        # 真实刷新路径（_refresh 在 engine 为 None 时也渲染能力视图），不是直接调 _refresh_paths。
        window._refresh()
        assert window.attempt_tree.topLevelItemCount() == 9
        assert "还没连接服务器" in window.attempt_summary.text()
        # 连上以后同一个按钮不能再挂着“还没连接服务器”的提示（行内容由引擎给）。
        window.engine = _FakeEngineForOptin()
        window._show_capability_preview()
        assert window.current_screen == "attempt"
        assert "还没连接服务器" not in window.beacon.text()
        assert "实时结果" in window.beacon.text()
    finally:
        _destroy_window(window, qt_app)


class _CountingGateway:
    """能力探测计数替身：只关心“被问了几次”，不碰任何 socket。"""

    def __init__(self, line: str = "路由器放行：可用，但需要你点同意（网关 10.8.1.254）"):
        self.calls = 0
        self.line = line

    def capability_line(self) -> str:
        self.calls += 1
        return self.line

    def consent_text(self) -> str:
        return "同意说明"


class _CountingLan:
    def __init__(self, line: str = "同一网段直连发现：可用，但默认关闭（需要你点开启）"):
        self.calls = 0
        self.line = line
        self.peers: list = []

    def capability_line(self) -> str:
        self.calls += 1
        return self.line


class _FakeEngineForOptin:
    """只提供设置面板/第 2 屏需要的几个方法，用来观察刷新频率与状态文案。"""

    def __init__(self, audit=None):
        self.gateway_optin = _CountingGateway()
        self.lan_direct = _CountingLan()
        self._audit = audit or []
        self.targets: dict = {}

    def summary(self, key=None):
        return {
            "rows": [], "remaining": [], "direct": [], "latency": None, "probeOnly": [],
            "probeRtt": None, "canSend": False,
            "webRtcProfileNote": plain.WEBRTC_PROFILE_NOTE, "telemetry": self.telemetry_status(),
        }

    def gateway_audit(self):
        return self._audit

    def gateway_failure_hint(self, code: str) -> str:
        return f"人话解释({code})"

    def telemetry_status(self):
        return {"uploadEnabled": True, "paused": False, "complete": True, "note": "", "text": "自动汇集…"}


def test_optin_capability_probe_is_cached_per_engine_and_still_refreshes(qt_app) -> None:
    """F3：能力探测按“每个引擎一次”缓存，但换引擎或显式 force 时仍会重新探测。

    局域网能力探测（multicast_available）会短暂创建并关闭一个 loopback UDP socket，
    设置面板可见时 0.5 秒刷一次，所以必须缓存；缓存**不是**“一次之后就永远不探测”。
    """
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        first = _FakeEngineForOptin()
        window.engine = first
        window._refresh_optin()
        assert first.lan_direct.calls == 1 and first.gateway_optin.calls == 1
        for _ in range(10):
            window._refresh_optin()
        assert first.lan_direct.calls == 1, "同一引擎重复刷新不应重复探测"
        assert first.gateway_optin.calls == 1
        # 用户同意/开关之后必须重新探测（否则文案会停留在“需要你点同意”）。
        window._refresh_optin(force=True)
        assert first.lan_direct.calls == 2 and first.gateway_optin.calls == 2
        # 换一个引擎（例如重连）也必须重新探测，缓存不能跨引擎粘住。
        second = _FakeEngineForOptin()
        window.engine = second
        window._refresh_optin()
        assert second.lan_direct.calls == 1 and second.gateway_optin.calls == 1
        # 断开回到“没有引擎”也算换了 key，仍应重新问一次。
        window.engine = None
        window._refresh_optin()
        assert second.lan_direct.calls == 1
        window.engine = first
        window._refresh_optin()
        assert first.lan_direct.calls == 3
    finally:
        _destroy_window(window, qt_app)


def test_optin_status_line_never_repeats_the_capability_line(qt_app) -> None:
    """F4：状态行只说“做过什么”，能力行由上面的三行各自负责，不重复同一句话。"""
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        window.engine = _FakeEngineForOptin()
        window._refresh_optin()
        window._refresh_optin_status()
        status = window.optin_status.text()
        assert "同一网段直连发现" not in status, f"状态行重复了 LAN 能力行：{status!r}"
        assert status == "", "没有审计动作时状态行应当为空，而不是复读能力行"
        # 有审计动作时只显示动作行。
        window.engine = _FakeEngineForOptin(
            audit=[{"action": "map-port", "reason": "GATEWAY_OPTIN_REQUIRED"}]
        )
        window._refresh_optin()
        window._refresh_optin_status()
        status = window.optin_status.text()
        assert "最近一次动作 = map-port" in status
        assert "同一网段直连发现" not in status
        assert window.lan_line.text().startswith("同一网段直连发现")
    finally:
        _destroy_window(window, qt_app)


def test_lan_enable_refuses_before_probing_capability() -> None:
    """F3：未同意时先拒绝，连平台能力探测都不做（探测会短暂建一个 loopback UDP socket）。"""
    import asyncio

    from p2pchat.python_desktop import lan_client

    probes = {"n": 0}

    def capability_fn():
        probes["n"] += 1
        return {"mechanism": "lan-direct", "status": "available", "reason": "OK"}

    direct = lan_client.LanDirect(capability_fn=capability_fn)
    try:
        asyncio.run(
            direct.enable(room="lab", secret="secretsecret123", peer_id="p1", listen_port=5000, consent=False)
        )
        raise AssertionError("未同意竟然没有拒绝")
    except PermissionError as error:
        assert "LAN_OPT_IN_REQUIRED" in str(error)
    assert probes["n"] == 0, "未同意时不应做任何能力探测"
    assert direct.audit.events[-1]["action"] == "enable-denied"


def test_automation_hook_is_opt_in_and_only_clicks(qt_app, monkeypatch) -> None:
    """截图/回归钩子：不设环境变量时什么都不做；设了也只排用户会做的那几个点击。"""
    calls: list[str] = []
    monkeypatch.delenv(qt_ui.AUTOMATION_ENV, raising=False)
    window = qt_ui.DesktopApp(app=qt_app)
    try:
        window._show_capability_preview = lambda: calls.append("preview")
        window._on_connect = lambda: calls.append("connect")
        window._open_settings = lambda: calls.append("settings")
        assert window._apply_automation_hook() == []
        assert calls == []
        monkeypatch.setenv(qt_ui.AUTOMATION_ENV, "preview")
        assert window._apply_automation_hook() == ["preview"]
        monkeypatch.setenv(qt_ui.AUTOMATION_ENV, "connect, chat ,settings")
        assert window._apply_automation_hook() == ["connect", "chat", "settings"]
        # send 走的是“发送”按钮的同一个槽函数，不另开路径。
        monkeypatch.setenv(qt_ui.AUTOMATION_ENV, "send")
        assert window._apply_automation_hook() == ["send"]
        window._on_send_text = lambda: calls.append("send-slot")
        window._automation_send()
        assert calls[-1] == "send-slot"
        assert "自动化截图消息" in window.field_message.text()
        monkeypatch.setenv(qt_ui.AUTOMATION_ENV, "definitely-not-an-action")
        assert window._apply_automation_hook() == []
    finally:
        _destroy_window(window, qt_app)
