"""The Tkinter three-screen flow and the settings panel.

Structural checks always run; the real ``tk.Tk()`` instantiation only runs when a
display is available (this host has ``DISPLAY=:0``), and it is skipped — never
faked — on a headless runner.
"""
from __future__ import annotations

import inspect
import os

import pytest

from p2pchat.python_desktop import methods as plain
from p2pchat.python_desktop import ui

SCREENS = ("connect_frame", "attempt_frame", "chat_frame")


def test_three_screens_and_settings_exist() -> None:
    source = inspect.getsource(ui)
    for builder in ("_build_connect", "_build_attempt", "_build_chat", "_build_settings", "_show"):
        assert f"def {builder}" in source, builder
    # Screen headings describe the required order.
    assert "1 / 3 · 连接服务器" in source
    assert "2 / 3 · 逐条尝试打洞" in source
    assert "3 / 3 · 聊天" in source


def test_connect_screen_collects_all_four_fields() -> None:
    source = inspect.getsource(ui.DesktopApp._build_connect)
    for field in ("服务器地址", "房间", "你的名字", "房间密码"):
        assert field in source, field
    assert "var_server" in source and "var_room" in source and "var_name" in source and "var_secret" in source


def test_attempt_screen_renders_plain_wording_and_latency() -> None:
    source = inspect.getsource(ui.DesktopApp._refresh_paths) + inspect.getsource(ui.DesktopApp._build_attempt)
    assert "实测延迟" in source
    assert "状态" in source
    assert 'row["title"]' in source and 'row["explain"]' in source
    assert "仅探测，不传内容" in source
    # The screen the user asked for: one row per method, in the documented order.
    assert plain.METHODS[0]["title"] == "双栈直连"


def test_settings_panel_exposes_remaining_availability_latency_and_speed() -> None:
    source = inspect.getsource(ui.DesktopApp._build_settings) + inspect.getsource(ui.DesktopApp._refresh_paths)
    assert "剩余方式" in source
    assert "可用性" in source
    assert "实测延迟" in source
    assert "测当前连接的速度" in source
    # Speed test wording must state the measurement boundary.
    assert "应用层速度" in source and "不是线路带宽" in source


def test_chat_screen_supports_text_image_file_and_voice() -> None:
    source = inspect.getsource(ui.DesktopApp._build_chat)
    for control in ("发送", "图片", "文件", "录音"):
        assert control in source, control
    assert "32 MiB" in source
    assert "不进行实时通话" in source
    audio = inspect.getsource(ui.DesktopApp._finish_recording)
    assert 'audio/wav' in audio


def test_settings_button_is_top_right_and_enabled_in_chat_only() -> None:
    source = inspect.getsource(ui.DesktopApp._build_chat)
    assert 'text="设置"' in source
    assert ".pack(side=\"right\"" in source
    show = inspect.getsource(ui.DesktopApp._show)
    assert 'state="normal" if name == "chat" else "disabled"' in show


def test_no_screen_promises_a_relay_or_invents_a_number() -> None:
    source = inspect.getsource(ui)
    assert "没有中继、没有 TURN" in source
    assert "不会偷偷改走服务器" in source
    # Latency is never rendered as zero when unmeasured.
    assert 'return "—" if value is None' in inspect.getsource(ui._fmt_latency)


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="需要图形显示才能实例化 Tk 窗口")
def test_gui_starts_and_shows_three_screens() -> None:
    import tkinter as tk

    root = tk.Tk()
    root.withdraw()
    try:
        app = ui.DesktopApp(root)
        assert app.current_screen == "connect"
        for name in SCREENS:
            assert getattr(app, name) is not None
        # Screen two lists every documented method with its plain-language title.
        app.selected_target = None
        app.engine = None
        assert len(plain.METHODS) == 9
        for method in plain.METHODS:
            assert method["title"] and method["explain"]
        app.engine_thread.stop()
    finally:
        root.destroy()


def test_both_screens_share_one_telemetry_renderer() -> None:
    """R1：诊断暂停时面板必须说「已暂停」，两个渲染点必须走同一个入口。"""
    assert "def _apply_telemetry" in inspect.getsource(ui.DesktopApp)
    render = inspect.getsource(ui.DesktopApp._render)
    refresh = inspect.getsource(ui.DesktopApp._refresh_paths)
    assert "_apply_telemetry" in render
    assert "_apply_telemetry" in refresh
    apply_source = inspect.getsource(ui.DesktopApp._apply_telemetry)
    # 暂停（uploadEnabled False）必须优先判断，并给出暂停文案。
    assert "uploadEnabled" in apply_source
    assert apply_source.index("uploadEnabled") < apply_source.index("TELEMETRY_ON_TEXT")


@pytest.mark.skipif(not os.environ.get("DISPLAY"), reason="需要图形显示才能实例化 Tk 窗口")
def test_panel_says_paused_never_running() -> None:
    import tkinter as tk

    from p2pchat.python_desktop import methods as plain

    root = tk.Tk()
    root.withdraw()
    try:
        app = ui.DesktopApp(root)
        # 暂停且本地队列已空：中心那份其实是完整的。
        app._apply_telemetry({"uploadEnabled": False, "paused": True, "complete": True,
                              "note": "", "text": plain.TELEMETRY_PAUSED_TEXT})
        text = app.telemetry_status.cget("text")
        assert "已暂停" in text, text
        assert "已开启" not in text, text
        assert app.var_upload_logs.get() is False
        # 暂停且有未上传记录：文案变成「中心记录不完整」，仍不能说「已开启」。
        app._apply_telemetry({"uploadEnabled": False, "paused": True, "complete": False,
                              "note": plain.TELEMETRY_NOTE, "text": plain.TELEMETRY_NOTE})
        text = app.telemetry_status.cget("text")
        assert "中心记录不完整" in text
        assert "已开启" not in text, text
        # 恢复：只有这时才能说「已开启」。
        app._apply_telemetry({"uploadEnabled": True, "paused": False, "complete": True,
                              "note": "", "text": plain.TELEMETRY_ON_TEXT})
        text = app.telemetry_status.cget("text")
        assert "已开启" in text and "已暂停" not in text
        assert app.var_upload_logs.get() is True
        app.engine_thread.stop()
    finally:
        root.destroy()
