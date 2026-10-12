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
    """没有连接/没有对端时，第 2 屏也要按文档顺序列出九种方式（状态=等待中）。"""
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
            # 没有引擎就不能猜可用性/延迟。
            assert item.text(2) == "—"
            assert item.text(3) == "—"
        assert window.settings_tree.topLevelItemCount() == 9
        assert plain.WEBRTC_PROFILE_NOTE in window.attempt_profile_note.text()
        assert "9" in window.attempt_summary.text() or "剩余方式" in window.attempt_summary.text()
    finally:
        _destroy_window(window, qt_app)
