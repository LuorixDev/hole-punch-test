"""Qt (PySide6) desktop client: three screens plus a settings dialog.

Screen 1 连接服务器  — server address, room, name, shared secret
Screen 2 逐条尝试    — every method in plain language, with status and measured latency
Screen 3 聊天        — text, image, file and recorded voice messages
Settings (top right) — remaining methods, availability, latency, speed test

Why Qt and not Tkinter: the Tk runtime shipped on this host is not linked against
Xft, so ``font families`` came back as ``('fixed',)`` and ``measure('中文') == 0`` —
Chinese text rendered as blanks. Qt probes fontconfig through its own font stack,
so CJK text renders without any fallback hack. See docs/DESKTOP-PYTHON.md.

This module is the *only* place that imports a GUI toolkit. Everything it needs
(engine, methods, summary/rows fields, opt-in controllers) already exists in the
interface-agnostic layer; the Qt code renders those fields and never re-derives
them.
"""
from __future__ import annotations

import asyncio
import os
import queue
import sys
import threading
import time

from PySide6 import QtCore, QtGui, QtWidgets

from . import methods as plain
from .gateway_optin import GatewayOptIn
from .lan_client import LanDirect
from .audio import Recorder, recorder_status
from .engine import DesktopEngine, EngineConfig
from .version import PRODUCT, VERSION, capability_lines

BG = "#101418"
PANEL = "#171d23"
FG = "#e8eef4"
MUTED = "#93a3b1"
ACCENT = "#3ea6ff"
OK = "#39c46a"
WARN = "#e0a032"
BAD = "#e05a5a"

MAX_MESSAGE_BYTES = 16384
PUMP_INTERVAL_MS = 150

# Families Qt can pick when it has to render 中文. The list is tried in order and
# every candidate is *measured* (inFontUcs4) before it is used.
CJK_FONT_CANDIDATES = (
    "Noto Sans CJK SC",
    "Noto Sans CJK JP",
    "Source Han Sans SC",
    "WenQuanYi Zen Hei",
    "WenQuanYi Micro Hei",
    "Microsoft YaHei",
    "PingFang SC",
    "Hiragino Sans GB",
    "Droid Sans Fallback",
    "DejaVu Sans",
    "Noto Sans",
)
CJK_PROBE = "中文渲染"
MISSING_CJK_FONT_TEXT = (
    "⚠ 本机没有找到能渲染中文的字体：界面文字可能显示为空白方块。"
    "请安装中文字体（例如 fonts-noto-cjk / fonts-wqy-zenhei）后重新启动。"
)


def _fmt_latency(value) -> str:
    return "—" if value is None else f"{value:.1f} ms"


def pick_cjk_font(families=None, probe: str = CJK_PROBE) -> str | None:
    """Return a family that can actually draw ``probe``, or None.

    Measuring beats name-matching: a family may exist but still lack CJK glyphs.
    """
    available = list(families if families is not None else QtGui.QFontDatabase.families())
    lookup = set(available)
    ordered = [name for name in CJK_FONT_CANDIDATES if name in lookup]
    ordered += [name for name in available if name not in set(CJK_FONT_CANDIDATES)]
    for name in ordered:
        font = QtGui.QFont(name)
        metrics = QtGui.QFontMetrics(font)
        if all(metrics.inFontUcs4(ord(char)) for char in probe):
            return name
    return None


class EngineThread:
    """Owns one asyncio loop in a daemon thread; the UI talks through a queue."""

    def __init__(self):
        self.loop = asyncio.new_event_loop()
        self.engine: DesktopEngine | None = None
        self.events: asyncio.Queue | None = None
        self.thread = threading.Thread(target=self._run, name="p2p-engine", daemon=True)
        self.ready = threading.Event()

    def _run(self):
        asyncio.set_event_loop(self.loop)
        self.events = asyncio.Queue(maxsize=4096)
        self.ready.set()
        self.loop.run_forever()

    def start(self):
        if self.thread.is_alive():
            return
        self.thread.start()
        self.ready.wait(5)

    def submit(self, coroutine):
        return asyncio.run_coroutine_threadsafe(coroutine, self.loop)

    def stop(self):
        engine = self.engine
        if engine is not None:
            try:
                self.submit(engine.close()).result(20)
            except Exception:
                pass
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        # Join deterministically: a loop thread still running while the process
        # tears down makes Qt's own teardown crash-prone at exit.
        if self.thread.is_alive() and threading.current_thread() is not self.thread:
            self.thread.join(10)


class DesktopApp(QtWidgets.QMainWindow):
    def __init__(self, config: EngineConfig | None = None, app: QtWidgets.QApplication | None = None):
        super().__init__()
        self.app = app or QtWidgets.QApplication.instance()
        self.setWindowTitle(f"{PRODUCT} {VERSION}")
        self.resize(1120, 780)
        self.setMinimumSize(940, 660)
        self.engine_thread = EngineThread()
        self.engine: DesktopEngine | None = None
        self.selected_target: str | None = None
        self.peer_keys: list[str] = []
        self.chat_entered = False
        self.current_screen = "connect"
        self.recorder = Recorder()
        self.recording = False
        self._images: list = []
        self._optin_refreshed_at = 0.0

        self.font_family = self._install_fonts()
        self._build_style()
        central = QtWidgets.QWidget(self)
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        self.stack = QtWidgets.QStackedWidget()
        layout.addWidget(self.stack, 1)
        self.beacon = QtWidgets.QLabel("正在准备…")
        self.beacon.setWordWrap(True)
        self.beacon.setContentsMargins(18, 6, 18, 6)
        layout.addWidget(self.beacon, 0)

        self._build_connect()
        self._build_attempt()
        self._build_chat()
        self._build_settings()
        self._show("connect")
        self._pump_timer = QtCore.QTimer(self)
        self._pump_timer.timeout.connect(self._pump)
        self._pump_timer.start(PUMP_INTERVAL_MS)
        if config is not None:
            self._prefill(config)

    # ------------------------------------------------------------------ scaffolding
    def _install_fonts(self) -> str | None:
        family = pick_cjk_font()
        if family:
            font = QtGui.QFont(family)
            font.setPointSize(10)
            QtWidgets.QApplication.setFont(font)
            self.missing_font_warning = None
            return family
        # No measurable CJK font: say so instead of showing blank boxes silently.
        self.missing_font_warning = MISSING_CJK_FONT_TEXT
        return None

    def _build_style(self):
        self.setStyleSheet(
            f"""
            QWidget {{ background: {BG}; color: {FG}; }}
            QLabel {{ background: transparent; }}
            QLabel#step {{ color: {ACCENT}; font-size: 12px; font-weight: bold; }}
            QLabel#title {{ font-size: 22px; font-weight: bold; }}
            QLabel#muted {{ color: {MUTED}; font-size: 12px; }}
            QLabel#panel {{ background: {PANEL}; }}
            QFrame#panel, QWidget#panel {{ background: {PANEL}; border-radius: 6px; }}
            QPushButton {{ background: #222b33; border: 1px solid #2d3841; padding: 6px 12px; border-radius: 4px; }}
            QPushButton:hover {{ background: #2a353f; }}
            QPushButton:disabled {{ color: {MUTED}; background: #1b2228; }}
            QPushButton#primary {{ background: {ACCENT}; color: #06121c; font-weight: bold; padding: 8px 14px; }}
            QLineEdit, QPlainTextEdit, QTextEdit, QListWidget, QTreeWidget {{
                background: {PANEL}; border: 1px solid #2a343d; border-radius: 4px; padding: 4px;
            }}
            QHeaderView::section {{ background: #1d252c; padding: 4px; border: 0; }}
            QTreeWidget::item {{ padding: 3px; }}
            """
        )

    def _header(self, parent_layout, step: str, title: str, subtitle: str):
        box = QtWidgets.QVBoxLayout()
        step_label = QtWidgets.QLabel(step)
        step_label.setObjectName("step")
        title_label = QtWidgets.QLabel(title)
        title_label.setObjectName("title")
        subtitle_label = QtWidgets.QLabel(subtitle)
        subtitle_label.setObjectName("muted")
        subtitle_label.setWordWrap(True)
        box.addWidget(step_label)
        box.addWidget(title_label)
        box.addWidget(subtitle_label)
        parent_layout.addLayout(box)
        return box

    def _panel(self):
        frame = QtWidgets.QFrame()
        frame.setObjectName("panel")
        return frame

    def _show(self, name: str):
        self.current_screen = name
        page = {"connect": self.connect_frame, "attempt": self.attempt_frame, "chat": self.chat_frame}[name]
        self.stack.setCurrentWidget(page)
        self.settings_button.setEnabled(name == "chat")
        self._set_beacon(self._beacon_text, self._beacon_colour)

    # ------------------------------------------------------------------- beacon
    _beacon_text = "正在准备…"
    _beacon_colour = MUTED

    def _set_beacon(self, text: str, colour: str = MUTED):
        self._beacon_text = text
        self._beacon_colour = colour
        self.beacon.setText(text)
        self.beacon.setStyleSheet(f"color: {colour}; background: {BG};")

    # ---------------------------------------------------------------- screen one
    def _build_connect(self):
        page = QtWidgets.QWidget()
        self.connect_frame = page
        layout = QtWidgets.QVBoxLayout(page)
        self._header(
            layout,
            "1 / 3 · 连接服务器",
            "连接服务器",
            "服务器帮你找到同房间的人；文字、图片、文件和录音只在你们之间直传。",
        )
        panel = self._panel()
        form = QtWidgets.QGridLayout(panel)
        form.setContentsMargins(14, 12, 14, 12)
        self.field_server = QtWidgets.QLineEdit("ws://127.0.0.1:8088/ws")
        self.field_room = QtWidgets.QLineEdit("lab")
        self.field_name = QtWidgets.QLineEdit("Explorer")
        self.field_secret = QtWidgets.QLineEdit()
        self.field_secret.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        rows = [
            ("服务器地址", self.field_server, "ws:// 或 wss:// 的信令地址"),
            ("房间", self.field_room, "和对方填同一个房间名"),
            ("你的名字", self.field_name, "只用于在房间里互相辨认"),
            ("房间密码", self.field_secret, "和对方使用相同密码，至少 8 个字符"),
        ]
        for index, (label, widget, hint) in enumerate(rows):
            form.addWidget(QtWidgets.QLabel(label), index * 2, 0, QtCore.Qt.AlignmentFlag.AlignLeft)
            form.addWidget(widget, index * 2, 1)
            hint_label = QtWidgets.QLabel(hint)
            hint_label.setObjectName("muted")
            form.addWidget(hint_label, index * 2 + 1, 1)
        form.setColumnStretch(1, 1)
        self.connect_button = QtWidgets.QPushButton("连接并寻找对方")
        self.connect_button.setObjectName("primary")
        self.connect_button.clicked.connect(self._on_connect)
        form.addWidget(self.connect_button, len(rows) * 2, 0, 1, 2)
        note = QtWidgets.QLabel(
            "点击连接即确认这个服务器，并自动汇集不含聊天内容的诊断记录。\n"
            "本客户端没有中继、没有 TURN，也不会把聊天内容交给服务器转发。"
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        form.addWidget(note, len(rows) * 2 + 1, 0, 1, 2)
        self.check_plaintext = QtWidgets.QCheckBox("这条连接允许未加密的 ws://（仅限你自己的可信服务器）")
        form.addWidget(self.check_plaintext, len(rows) * 2 + 2, 0, 1, 2)
        plain_note = QtWidgets.QLabel(
            "默认拒绝：公网服务器必须用加密的 wss://，只有本机地址才允许 ws://。\n"
            "勾选后连接未加密地址，会话期间会一直显示未加密提示。"
        )
        plain_note.setObjectName("muted")
        plain_note.setWordWrap(True)
        form.addWidget(plain_note, len(rows) * 2 + 3, 0, 1, 2)
        layout.addWidget(panel)
        self.connect_error = QtWidgets.QLabel("")
        self.connect_error.setWordWrap(True)
        self.connect_error.setStyleSheet(f"color: {BAD};")
        layout.addWidget(self.connect_error)
        layout.addStretch(1)
        self.stack.addWidget(page)

    # ---------------------------------------------------------------- screen two
    def _build_attempt(self):
        page = QtWidgets.QWidget()
        self.attempt_frame = page
        layout = QtWidgets.QVBoxLayout(page)
        self._header(
            layout,
            "2 / 3 · 逐条尝试打洞",
            "试着连接对方",
            "按固定顺序一条条试；任何一条打通就能聊天，其余方式仍在后台继续尝试。",
        )
        self.attempt_summary = QtWidgets.QLabel("")
        self.attempt_summary.setObjectName("muted")
        self.attempt_summary.setWordWrap(True)
        layout.addWidget(self.attempt_summary)
        self.attempt_tree = QtWidgets.QTreeWidget()
        self.attempt_tree.setColumnCount(4)
        self.attempt_tree.setHeaderLabels(["方式与人话说明", "状态", "可用性", "实测延迟"])
        self.attempt_tree.setRootIsDecorated(False)
        self.attempt_tree.setAlternatingRowColors(True)
        self.attempt_tree.setColumnWidth(0, 640)
        self.attempt_tree.setColumnWidth(1, 190)
        self.attempt_tree.setColumnWidth(2, 100)
        self.attempt_tree.setColumnWidth(3, 110)
        layout.addWidget(self.attempt_tree, 1)
        # METHODS-PLAIN.md/M3: one shared sentence for the three address-family rows.
        self.attempt_profile_note = QtWidgets.QLabel("")
        self.attempt_profile_note.setWordWrap(True)
        self.attempt_profile_note.setStyleSheet(f"color: {ACCENT};")
        layout.addWidget(self.attempt_profile_note)
        bar = QtWidgets.QHBoxLayout()
        enter = QtWidgets.QPushButton("进入聊天")
        enter.setObjectName("primary")
        enter.clicked.connect(lambda: self._show("chat"))
        bar.addWidget(enter)
        details = QtWidgets.QPushButton("连接详情与设置（右上角）")
        details.clicked.connect(self._open_settings)
        bar.addWidget(details)
        back = QtWidgets.QPushButton("返回连接页")
        back.clicked.connect(lambda: self._show("connect"))
        bar.addWidget(back)
        bar.addStretch(1)
        layout.addLayout(bar)
        self.attempt_note = QtWidgets.QLabel(
            "列表顺序不代表启动顺序：基础方式先试，需要额外条件的后试。任何一种成功都可以立刻聊天，"
            "其余方式继续在后台尝试；失败不会改走服务器转发。"
        )
        self.attempt_note.setObjectName("muted")
        self.attempt_note.setWordWrap(True)
        layout.addWidget(self.attempt_note)
        self.stack.addWidget(page)

    # --------------------------------------------------------------- screen three
    def _build_chat(self):
        page = QtWidgets.QWidget()
        self.chat_frame = page
        layout = QtWidgets.QVBoxLayout(page)
        head = QtWidgets.QHBoxLayout()
        titles = QtWidgets.QVBoxLayout()
        step = QtWidgets.QLabel("3 / 3 · 聊天")
        step.setObjectName("step")
        title = QtWidgets.QLabel("直连聊天")
        title.setObjectName("title")
        subtitle = QtWidgets.QLabel("只走已经确认的直接连接；没有直连时不会偷偷改走服务器。")
        subtitle.setObjectName("muted")
        titles.addWidget(step)
        titles.addWidget(title)
        titles.addWidget(subtitle)
        head.addLayout(titles)
        head.addStretch(1)
        self.settings_button = QtWidgets.QPushButton("设置")
        self.settings_button.clicked.connect(self._open_settings)
        head.addWidget(self.settings_button)
        self.disconnect_button = QtWidgets.QPushButton("断开连接")
        self.disconnect_button.clicked.connect(self._on_disconnect)
        head.addWidget(self.disconnect_button)
        layout.addLayout(head)

        body = QtWidgets.QHBoxLayout()
        aside = self._panel()
        aside_layout = QtWidgets.QVBoxLayout(aside)
        aside_layout.addWidget(QtWidgets.QLabel("房间成员"))
        self.peer_list = QtWidgets.QListWidget()
        self.peer_list.setFixedWidth(210)
        self.peer_list.currentRowChanged.connect(self._on_peer_selected)
        aside_layout.addWidget(self.peer_list, 1)
        legend = QtWidgets.QLabel("● 已打通　… 仍在尝试　○ 尚不可用")
        legend.setObjectName("muted")
        aside_layout.addWidget(legend)
        pick = QtWidgets.QLabel("选中谁就发给谁；未打通的连接不能发送。")
        pick.setObjectName("muted")
        pick.setWordWrap(True)
        aside_layout.addWidget(pick)
        body.addWidget(aside)
        chat = self._panel()
        chat_layout = QtWidgets.QVBoxLayout(chat)
        self.chat_title = QtWidgets.QLabel("请先在左侧选择聊天对象")
        chat_layout.addWidget(self.chat_title)
        self.chat_path = QtWidgets.QLabel("连接尚未打通")
        self.chat_path.setObjectName("muted")
        chat_layout.addWidget(self.chat_path)
        self.messages = QtWidgets.QTextEdit()
        self.messages.setReadOnly(True)
        chat_layout.addWidget(self.messages, 1)
        compose = QtWidgets.QHBoxLayout()
        self.field_message = QtWidgets.QLineEdit()
        self.field_message.returnPressed.connect(self._on_send_text)
        compose.addWidget(self.field_message, 1)
        send = QtWidgets.QPushButton("发送")
        send.setObjectName("primary")
        send.clicked.connect(self._on_send_text)
        compose.addWidget(send)
        image = QtWidgets.QPushButton("图片")
        image.clicked.connect(lambda: self._on_send_file("image"))
        compose.addWidget(image)
        attachment = QtWidgets.QPushButton("文件")
        attachment.clicked.connect(lambda: self._on_send_file("file"))
        compose.addWidget(attachment)
        self.record_button = QtWidgets.QPushButton("录音")
        self.record_button.clicked.connect(self._on_record_toggle)
        compose.addWidget(self.record_button)
        chat_layout.addLayout(compose)
        self.transfer_status = QtWidgets.QLabel("")
        self.transfer_status.setObjectName("muted")
        self.transfer_status.setWordWrap(True)
        chat_layout.addWidget(self.transfer_status)
        limit = QtWidgets.QLabel(
            "单文件最多 32 MiB；录音由你手动开始，最多 60 秒，结束后作为语音文件发送，不进行实时通话。"
        )
        limit.setObjectName("muted")
        limit.setWordWrap(True)
        chat_layout.addWidget(limit)
        body.addWidget(chat, 1)
        layout.addLayout(body, 1)
        self.stack.addWidget(page)

    # ------------------------------------------------------------------ settings
    def _build_settings(self):
        self.settings = QtWidgets.QDialog(self)
        self.settings.setWindowTitle("连接与设置")
        self.settings.resize(1000, 720)
        layout = QtWidgets.QVBoxLayout(self.settings)
        intro = QtWidgets.QLabel("连接不会因打开设置而中断")
        intro.setObjectName("step")
        layout.addWidget(intro)
        title = QtWidgets.QLabel("连接与设置")
        title.setObjectName("title")
        layout.addWidget(title)
        bar = QtWidgets.QHBoxLayout()
        rediscover = QtWidgets.QPushButton("重新寻找可用连接")
        rediscover.clicked.connect(self._on_rediscover)
        bar.addWidget(rediscover)
        self.speed_button = QtWidgets.QPushButton("测当前连接的速度")
        self.speed_button.clicked.connect(self._on_benchmark)
        bar.addWidget(self.speed_button)
        self.observe_button = QtWidgets.QPushButton("查看我这台机器的出口地址")
        self.observe_button.clicked.connect(self._on_observe)
        bar.addWidget(self.observe_button)
        capabilities = QtWidgets.QPushButton("本机支持哪些功能")
        capabilities.clicked.connect(self._show_capabilities)
        bar.addWidget(capabilities)
        bar.addStretch(1)
        layout.addLayout(bar)
        self.speed_result = QtWidgets.QLabel(
            "尚未测速。测速在独立通道上进行，最多 5 秒或 32 MiB；速度是应用层速度，不是线路带宽。"
        )
        self.speed_result.setObjectName("muted")
        self.speed_result.setWordWrap(True)
        layout.addWidget(self.speed_result)
        self.settings_tree = QtWidgets.QTreeWidget()
        self.settings_tree.setColumnCount(6)
        self.settings_tree.setHeaderLabels(["方式", "状态", "实测延迟", "可用性", "什么网络下可行", "说明"])
        self.settings_tree.setRootIsDecorated(False)
        self.settings_tree.setAlternatingRowColors(True)
        for column, width in enumerate((190, 105, 130, 130, 230, 280)):
            self.settings_tree.setColumnWidth(column, width)
        layout.addWidget(self.settings_tree, 1)
        self.settings_profile_note = QtWidgets.QLabel("")
        self.settings_profile_note.setWordWrap(True)
        self.settings_profile_note.setStyleSheet(f"color: {ACCENT};")
        layout.addWidget(self.settings_profile_note)
        self.settings_remaining = QtWidgets.QLabel("")
        self.settings_remaining.setObjectName("muted")
        self.settings_remaining.setWordWrap(True)
        layout.addWidget(self.settings_remaining)

        telemetry = self._panel()
        telemetry_layout = QtWidgets.QVBoxLayout(telemetry)
        self.check_upload_logs = QtWidgets.QCheckBox("自动汇集脱敏诊断到已连接中心（可随时暂停）")
        self.check_upload_logs.setChecked(True)
        self.check_upload_logs.toggled.connect(self._on_telemetry_toggle)
        telemetry_layout.addWidget(self.check_upload_logs)
        self.telemetry_status = QtWidgets.QLabel("")
        self.telemetry_status.setWordWrap(True)
        telemetry_layout.addWidget(self.telemetry_status)
        layout.addWidget(telemetry)

        # 需要单独同意的三件事：默认都不做；标题用人话，协议名只在“技术详情”里。
        optin = self._panel()
        optin_layout = QtWidgets.QVBoxLayout(optin)
        optin_title = QtWidgets.QLabel("需要你单独同意的三件事（默认都不做）")
        optin_layout.addWidget(optin_title)
        self.gateway_line = QtWidgets.QLabel("")
        self.gateway_line.setWordWrap(True)
        optin_layout.addWidget(self.gateway_line)
        gateway_bar = QtWidgets.QHBoxLayout()
        gateway_open = QtWidgets.QPushButton("让路由器开一个端口")
        gateway_open.clicked.connect(self._on_gateway_open)
        gateway_bar.addWidget(gateway_open)
        gateway_close = QtWidgets.QPushButton("撤销已开的端口")
        gateway_close.clicked.connect(self._on_gateway_close)
        gateway_bar.addWidget(gateway_close)
        gateway_detail = QtWidgets.QPushButton("技术详情")
        gateway_detail.clicked.connect(self._show_gateway_detail)
        gateway_bar.addWidget(gateway_detail)
        gateway_bar.addStretch(1)
        optin_layout.addLayout(gateway_bar)
        self.lan_line = QtWidgets.QLabel("")
        self.lan_line.setWordWrap(True)
        optin_layout.addWidget(self.lan_line)
        lan_bar = QtWidgets.QHBoxLayout()
        lan_enable = QtWidgets.QPushButton("开启同网段直连发现")
        lan_enable.clicked.connect(self._on_lan_enable)
        lan_bar.addWidget(lan_enable)
        lan_disable = QtWidgets.QPushButton("关闭同网段直连发现")
        lan_disable.clicked.connect(self._on_lan_disable)
        lan_bar.addWidget(lan_disable)
        lan_bar.addStretch(1)
        optin_layout.addLayout(lan_bar)
        self.prediction_line = QtWidgets.QLabel("")
        self.prediction_line.setWordWrap(True)
        optin_layout.addWidget(self.prediction_line)
        prediction_bar = QtWidgets.QHBoxLayout()
        prediction_enable = QtWidgets.QPushButton("开启对称 NAT 端口预测")
        prediction_enable.clicked.connect(self._on_prediction_enable)
        prediction_bar.addWidget(prediction_enable)
        prediction_disable = QtWidgets.QPushButton("关闭端口预测")
        prediction_disable.clicked.connect(self._on_prediction_disable)
        prediction_bar.addWidget(prediction_disable)
        prediction_bar.addStretch(1)
        optin_layout.addLayout(prediction_bar)
        self.optin_status = QtWidgets.QLabel("")
        self.optin_status.setObjectName("muted")
        self.optin_status.setWordWrap(True)
        optin_layout.addWidget(self.optin_status)
        layout.addWidget(optin)
        self._refresh_optin()

    # ------------------------------------------------------------------- actions
    def _prefill(self, config: EngineConfig):
        self.field_server.setText(config.url)
        self.field_room.setText(config.room)
        self.field_name.setText(config.name)
        self.field_secret.setText(config.secret)

    def _on_connect(self):
        url = self.field_server.text().strip()
        room = self.field_room.text().strip()
        name = self.field_name.text().strip() or "Explorer"
        secret = self.field_secret.text()
        if not url or not room:
            self.connect_error.setText("请填写服务器地址和房间名。")
            return
        if len(secret.encode()) < 8:
            self.connect_error.setText("房间密码至少 8 个字符，并和对方保持一致。")
            return
        self.connect_error.setText("")
        self.connect_button.setEnabled(False)
        self.connect_button.setText("正在连接…")
        config = EngineConfig(
            url=url,
            room=room,
            secret=secret,
            name=name,
            data_dir=os.path.join(os.path.expanduser("~"), ".p2pchat-desktop"),
            allow_native=True,
            allow_plaintext=bool(self.check_plaintext.isChecked()),
        )
        self.engine_thread.start()
        events = self.engine_thread.events
        assert events is not None
        self.engine = DesktopEngine(config, events=events)
        self.engine_thread.engine = self.engine
        self.engine_thread.submit(self._guard_start())
        self._show("attempt")
        self.attempt_summary.setText("已连接服务器，正在等待对方加入并交换连接信息…")

    async def _guard_start(self):
        """Surface a refused endpoint (and any other start failure) to the operator."""
        try:
            await self.engine.start()
        except Exception as error:
            code = str(error.args[0]) if error.args else type(error).__name__
            text = plain.reason(code) if code in plain.REASONS else None
            if code == "PLAINTEXT_REFUSED":
                text = (
                    "已拒绝这次连接：这是未加密的 ws:// 且不是本机地址。"
                    "公网服务器必须用 wss://；确实要继续请勾选上面的确认框，会话期间会一直显示未加密提示。"
                )
            self.engine._emit("engine.error", code=code, text=text or str(error))
            self.engine._emit("engine.start_failed", code=code)

    def _on_disconnect(self):
        if self.engine is None:
            return
        try:
            self.engine_thread.submit(self.engine.close()).result(20)
        except Exception:
            pass
        self.engine = None
        self.engine_thread.engine = None
        self.selected_target = None
        self.peer_keys = []
        self.chat_entered = False
        self.peer_list.clear()
        self._append_message("meta", "已断开。聊天连接与房间成员都已清空。")
        self.connect_button.setEnabled(True)
        self.connect_button.setText("连接并寻找对方")
        self._show("connect")
        self._set_beacon("已断开连接。", MUTED)

    def _on_peer_selected(self, index: int):
        if index < 0 or self.engine is None or index >= len(self.peer_keys):
            return
        self.selected_target = self.peer_keys[index]
        self.engine_thread.submit(self.engine.select(self.selected_target))
        target = self.engine.targets.get(self.selected_target)
        self.chat_title.setText(f"正在和 {target.name if target else '对方'} 聊天")
        self._refresh_paths()

    def _require_target(self) -> str | None:
        if self.engine is None:
            self._info("还没有连接", "请先在第一个屏幕连接服务器。")
            return None
        if not self.selected_target:
            self._info("还没选人", "请在左侧选择聊天对象。")
            return None
        return self.selected_target

    def _on_send_text(self):
        key = self._require_target()
        if key is None:
            return
        text = self.field_message.text()
        if not text.strip():
            return
        if len(text.encode()) > MAX_MESSAGE_BYTES:
            self._warn("文字太长", "请分成几条发送。")
            return
        self.field_message.setText("")
        self.engine_thread.submit(self._send_text(key, text))

    async def _send_text(self, key: str, text: str):
        try:
            await self.engine.select(key)
            await self.engine.send_text(text)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self.engine._emit("send.failed", code=code)

    def _on_send_file(self, kind: str):
        key = self._require_target()
        if key is None:
            return
        if kind == "image":
            path, _ = QtWidgets.QFileDialog.getOpenFileName(
                self, "选择图片", "", "图片 (*.png *.jpg *.jpeg *.gif *.webp);;所有文件 (*)"
            )
            mime = "image/png"
        else:
            path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "选择文件", "", "所有文件 (*)")
            mime = "application/octet-stream"
        if not path:
            return
        size = os.path.getsize(path)
        if size > 32 * 1024 * 1024:
            self._warn("文件太大", "单文件最多 32 MiB。")
            return
        self.transfer_status.setText(f"正在发送 {os.path.basename(path)}（{size} 字节）…")
        self.engine_thread.submit(self._send_file(key, path, mime))

    async def _send_file(self, key: str, path: str, mime: str):
        try:
            await self.engine.select(key)
            await self.engine.send_file(path, os.path.basename(path), mime)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self.engine._emit("send.failed", code=code)

    def _on_record_toggle(self):
        key = self._require_target()
        if key is None:
            return
        if self.recording:
            self._stop_recording(key)
        else:
            self._start_recording()

    def _start_recording(self):
        if recorder_status() != "available":
            self._warn("录音不可用", plain.reason("RECORDING_UNAVAILABLE"))
            return
        try:
            self.engine_thread.submit(self.recorder.start()).result(5)
        except Exception as error:
            code = str(error.args[0]) if error.args else "RECORDING_FAILED"
            self._warn("录音失败", plain.reason(code))
            return
        self.recording = True
        self.record_button.setText("停止录音")
        self.transfer_status.setText("正在录音；再点一次「停止录音」结束。最多 60 秒。")

    def _stop_recording(self, key: str):
        self.record_button.setText("录音")
        self.recording = False
        self.transfer_status.setText("正在整理录音…")
        self.engine_thread.submit(self._finish_recording(key))

    async def _finish_recording(self, key: str):
        try:
            payload, info = await self.recorder.stop()
        except Exception as error:
            code = str(error.args[0]) if error.args else "RECORDING_FAILED"
            self.engine._emit("send.failed", code=code)
            return
        name = f"voice-{time.strftime('%H%M%S')}.wav"
        directory = os.path.join(os.path.expanduser("~"), ".p2pchat-desktop", "voice")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, name)
        with open(path, "wb") as handle:
            handle.write(payload)
        self.engine._emit("recording.saved", path=path, seconds=info.get("seconds"))
        try:
            await self.engine.select(key)
            await self.engine.send_file(path, name, "audio/wav")
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self.engine._emit("send.failed", code=code)

    def _on_rediscover(self):
        if self.engine is not None:
            self.engine_thread.submit(self.engine._discover_all())

    def _on_observe(self):
        if self.engine is None or not self.selected_target:
            self._info("还没选人", "请先选择聊天对象。")
            return
        self.engine_thread.submit(self.engine.observe(self.selected_target))

    def _on_benchmark(self):
        key = self._require_target()
        if key is None:
            return
        self.speed_button.setEnabled(False)
        self.speed_button.setText("测速中…")
        self.speed_result.setText("正在独立通道上测速，最多 5 秒或 32 MiB；以对方确认收到多少计算。")
        self.engine_thread.submit(self._benchmark(key))

    async def _benchmark(self, key: str):
        try:
            result = await self.engine.benchmark(key, seconds=5.0)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self.engine._emit("benchmark.done", ok=False, code=code)
            return
        self.engine._emit("benchmark.done", **result)

    # -------------------------------------------------------------------- pump
    def _pump(self):
        """Drain engine events on the GUI thread, then refresh derived views."""
        engine = self.engine
        if engine is not None:
            while True:
                try:
                    event = engine.events.get_nowait()
                except (queue.Empty, Exception):
                    break
                self._render(event)
        self._refresh()
        self._refresh_optin_throttled()
        if self.missing_font_warning:
            # Persistent: a missing CJK font must not look like "blank UI".
            self._set_beacon(self.missing_font_warning, BAD)

    def _render(self, event: dict):
        kind = event.get("kind")
        if kind == "engine.error":
            self._set_beacon(f"提示：{event.get('text') or plain.reason(event.get('code'))}", WARN)
        elif kind == "optin":
            self.optin_status.setText(event.get("text", ""))
            self._refresh_optin()
        elif kind == "session.welcome":
            if self.engine is not None and self.engine.plaintext_warning:
                self._set_beacon("⚠ 未加密连接：" + self.engine.plaintext_warning, BAD)
            else:
                self._set_beacon("已加入房间，正在等待对方。", MUTED)
        elif kind == "engine.warning":
            self._set_beacon("⚠ " + str(event.get("text") or ""), BAD)
        elif kind == "engine.start_failed":
            self.engine = None
            self.engine_thread.engine = None
            self.connect_button.setEnabled(True)
            self.connect_button.setText("连接并寻找对方")
            self._show("connect")
            self.connect_error.setText(str(event.get("text") or plain.reason(event.get("code"))))
        elif kind == "message":
            message = event.get("message")
            who = "我" if message.direction == "out" else self._target_name(message.peer)
            tag = "me" if message.direction == "out" else "them"
            kind_label = {"text": "文字", "file": "文件"}.get(message.kind, message.kind)
            body = message.text if message.kind == "text" else (message.name or f"{message.bytes} 字节")
            self._append_message(tag, f"[{who}·{kind_label}·{message.mechanism}] {body}")
            if message.kind == "file" and message.data:
                self._preview_image(message)
        elif kind == "send.failed":
            self._set_beacon(f"发送未完成：{plain.reason(event.get('code'))}", BAD)
        elif kind == "benchmark.done":
            self.speed_button.setEnabled(True)
            self.speed_button.setText("测当前连接的速度")
            if event.get("ok"):
                self.speed_result.setText(
                    f"测得 {event.get('bytes')} 字节 / {event.get('elapsedMs')} 毫秒 ≈ {event.get('mbps')} Mbps"
                    "（应用层速度，不是线路带宽）。"
                )
            else:
                self.speed_result.setText(
                    f"测速未完成：{event.get('reason') or plain.reason(event.get('code'))}；"
                    f"已发送 {event.get('bytes', 0)} 字节但没有得到对方确认，因此不报告速度。"
                )
        elif kind == "transfer.sent":
            self.transfer_status.setText(f"已发送 {event.get('bytes')} 字节（{event.get('mechanism')}）。")
        elif kind == "transfer.ack":
            self.transfer_status.setText("对方已确认收到。" if event.get("ok") else "对方拒绝了这次传输。")
        elif kind == "transfer.progress":
            self.transfer_status.setText(f"传输进度：已确认 {event.get('bytes')} 字节。")
        elif kind == "observation":
            if event.get("ok"):
                self._set_beacon(f"观测到的出口地址：{event.get('address')}:{event.get('port')}（只观测，不转发）", MUTED)
            else:
                self._set_beacon("没能观测到出口地址。", WARN)
        elif kind == "recording.saved":
            self._set_beacon(f"录音已保存到本地并作为文件发送（{event.get('seconds')} 秒）。", MUTED)
        elif kind == "telemetry":
            self._apply_telemetry(event)

    def _apply_telemetry(self, telemetry: dict):
        """面板上"自动汇集"的唯一渲染点（_render 与 _refresh_paths 都走这里）。

        优先级由数据层决定：先看 uploadEnabled，暂停时绝不显示「已开启」；暂停且
        本机还有没上传的记录时显示「中心记录不完整」。
        """
        telemetry = telemetry or {}
        enabled = telemetry.get("uploadEnabled", True)
        text = telemetry.get("text") or ""
        if self.check_upload_logs.isChecked() != bool(enabled):
            blocker = QtCore.QSignalBlocker(self.check_upload_logs)
            self.check_upload_logs.setChecked(bool(enabled))
            del blocker
        if enabled is False:
            # 暂停优先：本机还有没上传的记录 → 中心记录不完整；队列已空 → 只说已暂停。
            if telemetry.get("complete", True) is False:
                text = text or telemetry.get("note") or plain.TELEMETRY_NOTE
            else:
                text = text or plain.TELEMETRY_PAUSED_TEXT
            self.telemetry_status.setText(text)
            self.telemetry_status.setStyleSheet(f"color: {WARN};")
            return
        self.telemetry_status.setText(text or plain.TELEMETRY_ON_TEXT)
        self.telemetry_status.setStyleSheet(f"color: {MUTED};")

    def _target_name(self, key: str) -> str:
        if self.engine is not None and key in self.engine.targets:
            return self.engine.targets[key].name or key[:6]
        return key[:6]

    def _append_message(self, tag: str, text: str):
        colour = {"me": ACCENT, "them": OK, "meta": MUTED}.get(tag, FG)
        cursor = self.messages.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        fmt = QtGui.QTextCharFormat()
        fmt.setForeground(QtGui.QColor(colour))
        cursor.insertText(text + "\n", fmt)
        self.messages.setTextCursor(cursor)
        self.messages.ensureCursorVisible()

    def _preview_image(self, message):
        suffix = os.path.splitext(message.name or "")[1].lower()
        if suffix not in {".png", ".gif"}:
            return
        image = QtGui.QImage.fromData(message.data)
        if image.isNull():
            return
        name = f"mem-image-{len(self._images)}"
        document = self.messages.document()
        document.addResource(QtGui.QTextDocument.ResourceType.ImageResource, QtCore.QUrl(name), image)
        cursor = self.messages.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.End)
        fmt = QtGui.QTextImageFormat()
        fmt.setName(name)
        fmt.setWidth(min(420, image.width()))
        cursor.insertImage(fmt)
        cursor.insertText("\n")
        self.messages.setTextCursor(cursor)
        self.messages.ensureCursorVisible()
        self._images.append(image)

    def _refresh(self):
        if self.engine is None:
            return
        self._refresh_peers()
        self._refresh_paths()
        # Persistent while connected: never let the unencrypted state scroll away.
        if self.engine.plaintext_warning:
            self._set_beacon("⚠ 未加密连接：" + self.engine.plaintext_warning, BAD)

    def _refresh_peers(self):
        if self.engine is None:
            return
        keys = [key for key, target in self.engine.targets.items() if target.webrtc_id or target.native_id]
        if keys != self.peer_keys:
            self.peer_keys = keys
            self.peer_list.clear()
            for key in keys:
                target = self.engine.targets[key]
                summary = self.engine.summary(key)
                mark = "●" if summary["canSend"] else ("…" if summary["remaining"] else "○")
                self.peer_list.addItem(f"{mark} {target.name or key[:6]}")
            if keys and self.selected_target not in keys:
                self.selected_target = keys[0]
                self.peer_list.setCurrentRow(0)
                self.engine_thread.submit(self.engine.select(keys[0]))
                self.chat_title.setText(f"正在和 {self.engine.targets[keys[0]].name or '对方'} 聊天")
        self._maybe_enter_chat()

    def _maybe_enter_chat(self):
        if self.engine is None or self.chat_entered or not self.selected_target:
            return
        if self.engine.summary(self.selected_target)["canSend"]:
            self.chat_entered = True
            self._show("chat")
            self._set_beacon("已有一条直接连接可用，可以开始聊天；其余方式仍在后台继续尝试。", OK)

    def _preview_summary(self) -> dict:
        """连接前的第 2 屏：九种方式按文档顺序列出，状态=等待中，不谎报可用性/延迟。"""
        rows = [
            {
                "id": method["id"],
                "title": method["title"],
                "explain": method["explain"],
                "works": method["works"],
                "failureHint": method["failure"],
                "status": "等待中",
                "state": "pending",
                "latency": None,
                "availability": "—",
                "availabilityNote": "",
                "detail": "",
                "probeRtt": None,
                "probeOnly": bool(method.get("probe_only")),
                "canMessage": False,
                "consentRequired": bool(method.get("opt_in")),
                "consented": False,
                "capabilityLine": "",
            }
            for method in plain.METHODS
        ]
        return {
            "rows": rows,
            "remaining": [method["title"] for method in plain.METHODS],
            "direct": [],
            "latency": None,
            "probeOnly": [],
            "probeRtt": None,
            "canSend": False,
            "webRtcProfileNote": plain.WEBRTC_PROFILE_NOTE,
            "telemetry": self.engine.telemetry_status() if self.engine is not None else {},
        }

    def _refresh_paths(self):
        if self.engine is None:
            # 还没连服务器：仍然把九种方式逐条摆出来（可用性/延迟留空，不猜）。
            self._render_rows(self._preview_summary(), key=None)
            return
        key = self.selected_target
        if key is not None and key in self.engine.targets:
            summary = self.engine.summary(key)
        else:
            # 还没有选中对端时也逐条列出文档里的九种方式：用 engine 的"没有结果"
            # 视图（同一个 rows()/summary() 数据源），可用性仍来自平台能力。
            summary = self.engine.summary("")
        rows = summary["rows"]
        self._render_rows(summary, key=key)

    def _render_rows(self, summary: dict, key: str | None):
        rows = summary["rows"]
        self.attempt_tree.clear()
        for row in rows:
            label = row["title"]
            if row["probeOnly"]:
                label += "（仅探测，不传内容）"
            label += "  —  " + row["explain"]
            if row.get("works"):
                label += "  ·  可行网络：" + row["works"]
            if row.get("probeRtt") is not None:
                # Measured, but explicitly not the chat latency.
                label += f"  ·  探测/观测往返：{row['probeRtt']:.1f} ms（不是聊天延迟）"
            if row["detail"]:
                label += "  ·  " + row["detail"]
            item = QtWidgets.QTreeWidgetItem([label, row["status"], row["availability"], _fmt_latency(row["latency"])])
            self._colour_item(item, row["state"])
            self.attempt_tree.addTopLevelItem(item)
        if rows:
            self.attempt_profile_note.setText(summary.get("webRtcProfileNote") or "")
            latency_text = _fmt_latency(summary["latency"])
            if summary["latency"] is None:
                latency_text = "—（还没有可聊天的直连，所以不报延迟）"
            self.attempt_summary.setText(
                f"已打通：{'、'.join(summary['direct']) if summary['direct'] else '暂无'}　|　"
                f"实测延迟：{latency_text}　|　剩余方式：{len(summary['remaining'])} 条"
            )
        self.settings_tree.clear()
        for row in rows:
            availability = row["availability"] + (f"（{row['availabilityNote']}）" if row.get("availabilityNote") else "")
            latency = (
                _fmt_latency(row["latency"])
                if row.get("probeRtt") is None
                else f"{row['probeRtt']:.1f} ms（仅探测/观测）"
            )
            item = QtWidgets.QTreeWidgetItem(
                [
                    row["title"],
                    row["status"],
                    latency,
                    availability,
                    row.get("works", ""),
                    row["detail"] or row["failureHint"],
                ]
            )
            self._colour_item(item, row["state"])
            self.settings_tree.addTopLevelItem(item)
        self.settings_profile_note.setText(summary.get("webRtcProfileNote") or "")
        remaining = summary["remaining"]
        self.settings_remaining.setText(
            f"剩余方式（还没成功、仍在后台尝试）：{'、'.join(remaining) if remaining else '无'}\n"
            f"已打通：{'、'.join(summary['direct']) if summary['direct'] else '暂无'}"
            f"　|　实测延迟：{'尚未测到（不会用 0 代替）' if summary['latency'] is None else _fmt_latency(summary['latency'])}\n"
            f"仅探测、不传内容：{'、'.join(summary['probeOnly']) if summary['probeOnly'] else '无'}"
            f"　|　探测/观测往返时间：{_fmt_latency(summary.get('probeRtt'))}（不是聊天延迟）\n"
            "不可用/不支持：见上表说明。路由器放行默认关闭，必须由操作者显式授权；本界面不会自动修改路由器。\n"
            "整个产品没有中继、没有 TURN，也不通过服务器转发聊天：直连不成功就是失败。"
        )
        # 与 _render 的 "telemetry" 事件走同一个渲染点，避免两处文案说反话。
        telemetry = summary.get("telemetry")
        if not telemetry and self.engine is not None:
            telemetry = self.engine.telemetry_status()
        self._apply_telemetry(telemetry or {})
        if key and self.engine is not None and key in self.engine.targets:
            self.chat_path.setText(f"可用直连：{'、'.join(summary['direct']) if summary['direct'] else '连接尚未打通'}")

    @staticmethod
    def _colour_item(item: QtWidgets.QTreeWidgetItem, state: str):
        colour = {"direct": OK, "observed": OK, "unavailable": BAD, "unsupported": WARN}.get(state)
        if colour is None:
            return
        brush = QtGui.QBrush(QtGui.QColor(colour))
        for column in range(item.columnCount()):
            item.setForeground(column, brush)

    def _on_telemetry_toggle(self, _checked: bool):
        if self.engine is None:
            return
        paused = not bool(self.check_upload_logs.isChecked())
        self.engine_thread.submit(self._set_telemetry(paused))

    async def _set_telemetry(self, paused: bool):
        status = self.engine.set_telemetry_paused(paused)
        self.engine._emit("telemetry", **status)

    # -------------------------------- 需要单独同意的三件事（路由器放行 / 同网段 / 端口预测）
    def _gateway_controller(self):
        engine = self.engine
        if engine is not None and getattr(engine, "gateway_optin", None) is not None:
            return engine.gateway_optin
        return GatewayOptIn()

    def _lan_controller(self):
        engine = self.engine
        if engine is not None and getattr(engine, "lan_direct", None) is not None:
            return engine.lan_direct
        return LanDirect()

    def _refresh_optin(self):
        try:
            self.gateway_line.setText(self._gateway_controller().capability_line())
            self.lan_line.setText(self._lan_controller().capability_line())
            self.prediction_line.setText(self._prediction_line_text())
        except Exception as error:  # 能力读取失败也要说出来，不静默
            self.optin_status.setText(f"读取能力失败：{type(error).__name__}")

    def _prediction_line_text(self) -> str:
        engine = self.engine
        if engine is None:
            return (
                "对称 NAT 端口预测：默认关闭；连上服务器后由你单独同意才开启。它只对已信令的对端地址做少量认证探测，"
                "不会扫描第三方。优先顺序：IPv6 直连 > 网关注册放行 > 端口预测。"
            )
        capability = engine.prediction_capability()
        note = engine.prediction_hit_rate_note()
        status = capability.get("status")
        if status == "available":
            return (
                f"对称 NAT 端口预测：已开启（观测点 {capability.get('observationPoints', 0)} 个）——"
                f"只对已信令的对端地址做少量认证探测。{note}"
            )
        if status == "disabled":
            return (
                "对称 NAT 端口预测：默认关闭，需要你点“开启对称 NAT 端口预测”并确认才会开启。"
                "它不会扫描第三方，也不保证成功：" + note
            )
        return f"对称 NAT 端口预测：暂不可用（{capability.get('reason')}）。{note}"

    def _on_prediction_enable(self):
        engine = self.engine
        if engine is None:
            self._warn("还没连接", "先在连接屏连上服务器，再决定要不要开启端口预测。")
            return
        capability = engine.prediction_capability()
        if capability.get("status") == "unavailable" and capability.get("reason") == "OBSERVATION_POINTS_REQUIRED":
            self._warn(
                "缺少观测点",
                "端口预测需要你显式配置至少两个 STUN 观测点（IP:端口），它不会自动找服务器，也不会扫描网段。",
            )
            return
        if not self._ask("开启对称 NAT 端口预测", engine.prediction_consent_text()):
            return
        self.engine_thread.submit(self._prediction_enable_async())

    async def _prediction_enable_async(self):
        try:
            status = await self.engine.prediction_enable(consent=True)
            self.engine._emit("optin", text=f"端口预测：{status.get('status')}")
        except Exception as error:
            self.engine._emit("optin", text=f"端口预测开启失败：{type(error).__name__}")

    def _on_prediction_disable(self):
        if self.engine is None:
            return
        self.engine_thread.submit(self._prediction_disable_async())

    async def _prediction_disable_async(self):
        try:
            await self.engine.prediction_disable()
            self.engine._emit("optin", text="端口预测：已关闭")
        except Exception as error:
            self.engine._emit("optin", text=f"端口预测关闭失败：{type(error).__name__}")

    def _refresh_optin_throttled(self):
        now = time.time()
        if now - self._optin_refreshed_at < 0.5:
            return
        self._optin_refreshed_at = now
        if not self.settings.isVisible():
            return
        self._refresh_optin()
        self.optin_status.setText(self._optin_status_text())

    def _optin_status_text(self) -> str:
        parts = []
        engine = self.engine
        if engine is not None and hasattr(engine, "gateway_audit"):
            audit = engine.gateway_audit()
            if audit:
                last = audit[-1]
                text = f"路由器放行：最近一次动作 = {last.get('action')}"
                reason = last.get("reason")
                if reason:
                    text += "（" + engine.gateway_failure_hint(str(reason).split(",", 1)[0]) + "）"
                parts.append(text)
        controller = self._lan_controller()
        line = controller.capability_line()
        if controller.peers:
            line += f"；已发现 {len(controller.peers)} 个同网段设备"
        parts.append(line)
        return "\n".join(parts)

    def _refresh_optin_status(self):
        self.optin_status.setText(self._optin_status_text())

    def _on_gateway_open(self):
        controller = self._gateway_controller()
        if self.engine is None:
            self.optin_status.setText("请先连接服务器：端口放行要指向一条真实在听的直连端口。")
            return
        if not self._ask("让路由器开一个端口", controller.consent_text()):
            self.optin_status.setText("已取消：没有去动路由器。")
            return
        self.optin_status.setText("已同意，正在尝试让路由器开端口…（失败会说明原因，不会当作成功）")
        self.engine_thread.submit(self._gateway_open_async())

    async def _gateway_open_async(self):
        engine = self.engine
        try:
            await engine.gateway_consent("ui")
            result = await engine.gateway_open_port()
            engine._emit(
                "optin",
                text=f"路由器已开端口 {result.get('externalPort')}"
                f"（外部对端确认：{'已完成' if result.get('verified') else '还没有'}）",
            )
        except Exception as error:
            engine._emit("optin", text="端口放行没有成功：" + engine.gateway_failure_hint(str(error).split(",", 1)[0]))

    def _on_gateway_close(self):
        if self.engine is None:
            self.optin_status.setText("还没有连接，没有需要撤销的端口。")
            return
        self.optin_status.setText("正在撤销路由器上的端口映射…")
        self.engine_thread.submit(self._gateway_close_async())

    async def _gateway_close_async(self):
        engine = self.engine
        try:
            result = await engine.gateway_close_port()
            failures = result.get("failures", [])
            engine._emit(
                "optin",
                text=f"已撤销 {len(result.get('released', []))} 条映射"
                + (f"，{len(failures)} 条没撤销成功" if failures else ""),
            )
        except Exception as error:
            engine._emit("optin", text=f"撤销端口失败：{type(error).__name__}")

    def _on_lan_enable(self):
        controller = self._lan_controller()
        if self.engine is None:
            self.optin_status.setText("请先连接服务器：同网段发现要广播一个真实在听的端口。")
            return
        if not self._ask("在同网段里互相发现", controller.consent_text()):
            self.optin_status.setText("已取消：没有开始组播。")
            return
        self.engine_thread.submit(self._lan_enable_async())

    async def _lan_enable_async(self):
        engine = self.engine
        try:
            status = await engine.lan_enable(consent=True)
            engine._emit(
                "optin",
                text="同网段直连发现已开启"
                + ("（测试模式：回环，不算局域网证据）" if status.get("restrictedLocal") else ""),
            )
        except Exception as error:
            code = str(error) or type(error).__name__
            plain_text = {
                "NO_LOCAL_DATA_PORT": "还没有一条已建立的直连路径可以广播；先在第二条屏幕等到有可用路径，再回来开启。",
                "LAN_OPT_IN_REQUIRED": "没有同意，所以没有开始组播。",
                "NO_LAN_INTERFACE": "没有找到可用的局域网网卡地址（可能只连着回环）。",
                "NO_UDP_MULTICAST_API": "这台设备的系统不支持 UDP 组播。",
            }.get(code, code)
            engine._emit("optin", text="同一网段发现没有开启：" + plain_text)

    def _on_lan_disable(self):
        if self.engine is None:
            self.optin_status.setText("还没有连接，没有在跑的组播。")
            return
        self.engine_thread.submit(self._lan_disable_async())

    async def _lan_disable_async(self):
        engine = self.engine
        result = await engine.lan_disable()
        engine._emit("optin", text=f"同网段直连发现已关闭（之前发现 {result.get('peersFound', 0)} 个设备）")

    def _show_gateway_detail(self):
        self._info(
            "技术详情",
            self._gateway_controller().technical_detail() + "\n\n" + self._lan_controller().technical_detail(),
        )

    def _open_settings(self):
        if self.engine is not None and self.selected_target:
            self._refresh_paths()
        self._refresh_optin_status()
        self.settings.show()
        self.settings.raise_()
        self.settings.activateWindow()

    def _close_settings(self):
        self.settings.hide()

    def _show_capabilities(self):
        self._info("本机支持哪些功能", "\n".join(capability_lines()))

    # ------------------------------------------------------------- dialogs/close
    def _info(self, title: str, text: str):
        QtWidgets.QMessageBox.information(self, title, text)

    def _warn(self, title: str, text: str):
        QtWidgets.QMessageBox.warning(self, title, text)

    def _ask(self, title: str, text: str) -> bool:
        answer = QtWidgets.QMessageBox.question(
            self,
            title,
            text,
            QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.No,
            QtWidgets.QMessageBox.StandardButton.No,
        )
        return answer == QtWidgets.QMessageBox.StandardButton.Yes

    def closeEvent(self, event):  # noqa: N802 - Qt naming
        self._on_close()
        event.accept()

    def _on_close(self):
        self._pump_timer.stop()
        try:
            self.engine_thread.stop()
        finally:
            if self.app is not None:
                self.app.quit()


def _has_display() -> bool:
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY") or os.environ.get("QT_QPA_PLATFORM"))


def run(config: EngineConfig | None = None) -> int:
    if not _has_display():
        print("无法启动图形界面：没有可用的显示（DISPLAY/WAYLAND_DISPLAY 都为空）。", file=sys.stderr)
        print("请在有图形显示的会话中运行，或使用 --self-test 做无界面自检。", file=sys.stderr)
        return 2
    try:
        app = QtWidgets.QApplication.instance() or QtWidgets.QApplication(sys.argv[:1])
    except Exception as error:  # Qt aborts hard when the platform plugin cannot load
        print(f"无法启动图形界面：{error}", file=sys.stderr)
        print("请在有图形显示的会话中运行，或使用 --self-test 做无界面自检。", file=sys.stderr)
        return 2
    window = DesktopApp(config, app=app)
    window.show()
    return app.exec()
