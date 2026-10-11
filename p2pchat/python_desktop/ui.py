"""Tkinter desktop client: three screens plus a settings panel.

Screen 1 连接服务器  — server address, room, name, shared secret
Screen 2 逐条尝试    — every method in plain language, with status and measured latency
Screen 3 聊天        — text, image, file and recorded voice messages
Settings (top right) — remaining methods, availability, latency, speed test

The asyncio engine owns every socket; Tkinter only renders. Nothing here starts,
authenticates or cancels a transport on its own, and no screen claims a path is
usable before the engine has authenticated it.
"""
from __future__ import annotations

import base64
import os
import queue
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import asyncio

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


def _fmt_latency(value) -> str:
    return "—" if value is None else f"{value:.1f} ms"


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


class DesktopApp:
    def __init__(self, root: tk.Tk, config: EngineConfig | None = None):
        self.root = root
        self.root.title(f"{PRODUCT} {VERSION}")
        self.root.geometry("1080x740")
        self.root.minsize(900, 640)
        self.root.configure(bg=BG)
        self.engine_thread = EngineThread()
        self.engine: DesktopEngine | None = None
        self.selected_target: str | None = None
        self.peer_keys: list[str] = []
        self.chat_entered = False
        self.current_screen = "connect"
        self.recorder = Recorder()
        self.recording = False
        self._images: list = []
        self.beacon = tk.Label(self.root, text="正在准备…", bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=1020)
        self._build_style()
        self._build_connect()
        self._build_attempt()
        self._build_chat()
        self._build_settings()
        self._show("connect")
        self.beacon.pack(fill="x", side="bottom", padx=18, pady=6)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self._pump()
        if config is not None:
            self._prefill(config)

    # ------------------------------------------------------------------ scaffolding
    def _build_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TFrame", background=BG)
        style.configure("Panel.TFrame", background=PANEL)
        style.configure("TLabel", background=BG, foreground=FG, font=("Noto Sans CJK SC", 10))
        style.configure("Muted.TLabel", background=BG, foreground=MUTED, font=("Noto Sans CJK SC", 9))
        style.configure("Panel.TLabel", background=PANEL, foreground=FG, font=("Noto Sans CJK SC", 10))
        style.configure("Title.TLabel", background=BG, foreground=FG, font=("Noto Sans CJK SC", 18, "bold"))
        style.configure("Step.TLabel", background=BG, foreground=ACCENT, font=("Noto Sans CJK SC", 9, "bold"))
        style.configure("TButton", font=("Noto Sans CJK SC", 10), padding=6)
        style.configure("Primary.TButton", font=("Noto Sans CJK SC", 11, "bold"), padding=8)
        style.configure("Treeview", background=PANEL, fieldbackground=PANEL, foreground=FG, rowheight=28, font=("Noto Sans CJK SC", 9))
        style.configure("Treeview.Heading", font=("Noto Sans CJK SC", 9, "bold"))
        style.map("Treeview", background=[("selected", "#20435f")])

    def _header(self, parent, step: str, title: str, subtitle: str):
        bar = ttk.Frame(parent)
        bar.pack(fill="x", padx=18, pady=(14, 4))
        ttk.Label(bar, text=step, style="Step.TLabel").pack(anchor="w")
        ttk.Label(bar, text=title, style="Title.TLabel").pack(anchor="w")
        ttk.Label(bar, text=subtitle, style="Muted.TLabel").pack(anchor="w", pady=(2, 0))
        return bar

    def _show(self, name: str):
        for screen in (self.connect_frame, self.attempt_frame, self.chat_frame):
            screen.pack_forget()
        self.current_screen = name
        frame = {"connect": self.connect_frame, "attempt": self.attempt_frame, "chat": self.chat_frame}[name]
        frame.pack(fill="both", expand=True)
        self.beacon.pack(fill="x", side="bottom", padx=18, pady=6)
        self.settings_button.configure(state="normal" if name == "chat" else "disabled")

    # ---------------------------------------------------------------- screen one
    def _build_connect(self):
        frame = ttk.Frame(self.root)
        self.connect_frame = frame
        self._header(frame, "1 / 3 · 连接服务器", "连接服务器", "服务器帮你找到同房间的人；文字、图片、文件和录音只在你们之间直传。")
        panel = ttk.Frame(frame, style="Panel.TFrame")
        panel.pack(fill="x", padx=18, pady=10, ipady=10)
        self.var_server = tk.StringVar(value="ws://127.0.0.1:8088/ws")
        self.var_room = tk.StringVar(value="lab")
        self.var_name = tk.StringVar(value="Explorer")
        self.var_secret = tk.StringVar()
        rows = [
            ("服务器地址", self.var_server, False, "ws:// 或 wss:// 的信令地址"),
            ("房间", self.var_room, False, "和对方填同一个房间名"),
            ("你的名字", self.var_name, False, "只用于在房间里互相辨认"),
            ("房间密码", self.var_secret, True, "和对方使用相同密码，至少 8 个字符"),
        ]
        for index, (label, variable, secret, hint) in enumerate(rows):
            ttk.Label(panel, text=label, style="Panel.TLabel").grid(row=index * 2, column=0, sticky="w", padx=14, pady=(10 if index == 0 else 4, 0))
            entry = ttk.Entry(panel, textvariable=variable, width=64, show="*" if secret else "")
            entry.grid(row=index * 2, column=1, sticky="ew", padx=10, pady=(10 if index == 0 else 4, 0))
            ttk.Label(panel, text=hint, style="Muted.TLabel").grid(row=index * 2 + 1, column=1, sticky="w", padx=12)
            panel.columnconfigure(1, weight=1)
        self.connect_button = ttk.Button(panel, text="连接并寻找对方", style="Primary.TButton", command=self._on_connect)
        self.connect_button.grid(row=len(rows) * 2, column=0, columnspan=2, sticky="ew", padx=14, pady=12)
        ttk.Label(
            panel,
            text="点击连接即确认这个服务器，并自动汇集不含聊天内容的诊断记录。\n本客户端没有中继、没有 TURN，也不会把聊天内容交给服务器转发。",
            style="Muted.TLabel",
        ).grid(row=len(rows) * 2 + 1, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 4))
        self.var_allow_plaintext = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            panel,
            text="这条连接允许未加密的 ws://（仅限你自己的可信服务器）",
            variable=self.var_allow_plaintext,
        ).grid(row=len(rows) * 2 + 2, column=0, columnspan=2, sticky="w", padx=14)
        ttk.Label(
            panel,
            text="默认拒绝：公网服务器必须用加密的 wss://，只有本机地址才允许 ws://。\n勾选后连接未加密地址，会话期间会一直显示未加密提示。",
            style="Muted.TLabel",
        ).grid(row=len(rows) * 2 + 3, column=0, columnspan=2, sticky="w", padx=14, pady=(0, 8))
        self.connect_error = tk.Label(frame, text="", bg=BG, fg=BAD, anchor="w", justify="left", wraplength=1000)
        self.connect_error.pack(fill="x", padx=18)

    # ---------------------------------------------------------------- screen two
    def _build_attempt(self):
        frame = ttk.Frame(self.root)
        self.attempt_frame = frame
        self._header(frame, "2 / 3 · 逐条尝试打洞", "试着连接对方", "按固定顺序一条条试；任何一条打通就能聊天，其余方式仍在后台继续尝试。")
        self.attempt_summary = tk.Label(frame, text="", bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=1010)
        self.attempt_summary.pack(fill="x", padx=18, pady=(0, 6))
        columns = ("status", "availability", "latency")
        self.attempt_tree = ttk.Treeview(frame, columns=columns, show="tree headings", height=9)
        self.attempt_tree.heading("#0", text="方式与人话说明")
        self.attempt_tree.heading("status", text="状态")
        self.attempt_tree.heading("availability", text="可用性")
        self.attempt_tree.heading("latency", text="实测延迟")
        self.attempt_tree.column("#0", width=560, stretch=True)
        self.attempt_tree.column("status", width=190, stretch=False)
        self.attempt_tree.column("availability", width=90, stretch=False)
        self.attempt_tree.column("latency", width=110, stretch=False)
        for state, colour in (("direct", OK), ("observed", OK), ("unavailable", BAD), ("unsupported", WARN)):
            self.attempt_tree.tag_configure(state, foreground=colour)
        self.attempt_tree.pack(fill="both", expand=True, padx=18, pady=4)
        # METHODS-PLAIN.md/M3: one shared sentence for the three address-family rows.
        self.attempt_profile_note = tk.Label(
            frame,
            text="",
            bg=BG,
            fg=ACCENT,
            anchor="w",
            justify="left",
            wraplength=1010,
        )
        self.attempt_profile_note.pack(fill="x", padx=18, pady=(0, 2))
        bar = ttk.Frame(frame)
        bar.pack(fill="x", padx=18, pady=8)
        ttk.Button(bar, text="进入聊天", style="Primary.TButton", command=lambda: self._show("chat")).pack(side="left")
        ttk.Button(bar, text="连接详情与设置（右上角）", command=self._open_settings).pack(side="left", padx=8)
        ttk.Button(bar, text="返回连接页", command=lambda: self._show("connect")).pack(side="left")
        self.attempt_note = tk.Label(
            frame,
            text="列表顺序不代表启动顺序：基础方式先试，需要额外条件的后试。任何一种成功都可以立刻聊天，其余方式继续在后台尝试；失败不会改走服务器转发。",
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=1010,
        )
        self.attempt_note.pack(fill="x", padx=18, pady=(0, 8))

    # --------------------------------------------------------------- screen three
    def _build_chat(self):
        frame = ttk.Frame(self.root)
        self.chat_frame = frame
        head = ttk.Frame(frame)
        head.pack(fill="x", padx=18, pady=(14, 4))
        left = ttk.Frame(head)
        left.pack(side="left", fill="x", expand=True)
        ttk.Label(left, text="3 / 3 · 聊天", style="Step.TLabel").pack(anchor="w")
        ttk.Label(left, text="直连聊天", style="Title.TLabel").pack(anchor="w")
        ttk.Label(left, text="只走已经确认的直接连接；没有直连时不会偷偷改走服务器。", style="Muted.TLabel").pack(anchor="w")
        self.settings_button = ttk.Button(head, text="设置", command=self._open_settings)
        self.settings_button.pack(side="right", padx=(8, 0))
        self.disconnect_button = ttk.Button(head, text="断开连接", command=self._on_disconnect)
        self.disconnect_button.pack(side="right")
        body = ttk.Frame(frame)
        body.pack(fill="both", expand=True, padx=18, pady=6)
        aside = ttk.Frame(body, style="Panel.TFrame")
        aside.pack(side="left", fill="y", padx=(0, 10))
        ttk.Label(aside, text="房间成员", style="Panel.TLabel").pack(anchor="w", padx=10, pady=(10, 2))
        self.peer_list = tk.Listbox(aside, height=14, width=22, bg=PANEL, fg=FG, selectbackground="#20435f", highlightthickness=0, bd=0)
        self.peer_list.pack(fill="y", expand=True, padx=10, pady=6)
        self.peer_list.bind("<<ListboxSelect>>", self._on_peer_selected)
        ttk.Label(aside, text="● 已打通　… 仍在尝试　○ 尚不可用", style="Muted.TLabel").pack(anchor="w", padx=10)
        ttk.Label(aside, text="选中谁就发给谁；未打通的连接不能发送。", style="Muted.TLabel", wraplength=180, justify="left").pack(anchor="w", padx=10, pady=(2, 10))
        chat = ttk.Frame(body, style="Panel.TFrame")
        chat.pack(side="left", fill="both", expand=True)
        self.chat_title = ttk.Label(chat, text="请先在左侧选择聊天对象", style="Panel.TLabel")
        self.chat_title.pack(anchor="w", padx=10, pady=(10, 0))
        self.chat_path = ttk.Label(chat, text="连接尚未打通", style="Muted.TLabel")
        self.chat_path.pack(anchor="w", padx=10)
        self.messages = tk.Text(chat, bg="#0d1116", fg=FG, insertbackground=FG, wrap="word", height=18, bd=0, state="disabled")
        self.messages.pack(fill="both", expand=True, padx=10, pady=8)
        self.messages.tag_configure("me", foreground=ACCENT)
        self.messages.tag_configure("them", foreground=OK)
        self.messages.tag_configure("meta", foreground=MUTED)
        compose = ttk.Frame(chat, style="Panel.TFrame")
        compose.pack(fill="x", padx=10, pady=(0, 8))
        self.var_message = tk.StringVar()
        entry = ttk.Entry(compose, textvariable=self.var_message)
        entry.pack(side="left", fill="x", expand=True)
        entry.bind("<Return>", lambda _event: self._on_send_text())
        ttk.Button(compose, text="发送", style="Primary.TButton", command=self._on_send_text).pack(side="left", padx=6)
        ttk.Button(compose, text="图片", command=lambda: self._on_send_file("image")).pack(side="left", padx=(0, 6))
        ttk.Button(compose, text="文件", command=lambda: self._on_send_file("file")).pack(side="left", padx=(0, 6))
        self.record_button = ttk.Button(compose, text="录音", command=self._on_record_toggle)
        self.record_button.pack(side="left")
        self.transfer_status = tk.Label(chat, text="", bg=PANEL, fg=MUTED, anchor="w", justify="left", wraplength=700)
        self.transfer_status.pack(fill="x", padx=10, pady=(0, 10))
        ttk.Label(
            chat,
            text="单文件最多 32 MiB；录音由你手动开始，最多 60 秒，结束后作为语音文件发送，不进行实时通话。",
            style="Muted.TLabel",
        ).pack(anchor="w", padx=10, pady=(0, 10))

    # ------------------------------------------------------------------ settings
    def _build_settings(self):
        self.settings = tk.Toplevel(self.root)
        self.settings.title("连接与设置")
        self.settings.geometry("940x660")
        self.settings.configure(bg=BG)
        self.settings.withdraw()
        self.settings.protocol("WM_DELETE_WINDOW", self._close_settings)
        head = ttk.Frame(self.settings)
        head.pack(fill="x", padx=16, pady=(12, 4))
        ttk.Label(head, text="连接不会因打开设置而中断", style="Step.TLabel").pack(anchor="w")
        ttk.Label(head, text="连接与设置", style="Title.TLabel").pack(anchor="w")
        bar = ttk.Frame(self.settings)
        bar.pack(fill="x", padx=16, pady=6)
        ttk.Button(bar, text="重新寻找可用连接", command=self._on_rediscover).pack(side="left")
        self.speed_button = ttk.Button(bar, text="测当前连接的速度", command=self._on_benchmark)
        self.speed_button.pack(side="left", padx=8)
        self.observe_button = ttk.Button(bar, text="查看我这台机器的出口地址", command=self._on_observe)
        self.observe_button.pack(side="left")
        ttk.Button(bar, text="本机支持哪些功能", command=self._show_capabilities).pack(side="left", padx=8)
        self.speed_result = tk.Label(
            self.settings,
            text="尚未测速。测速在独立通道上进行，最多 5 秒或 32 MiB；速度是应用层速度，不是线路带宽。",
            bg=BG,
            fg=MUTED,
            anchor="w",
            justify="left",
            wraplength=900,
        )
        self.speed_result.pack(fill="x", padx=16, pady=(2, 6))
        frame = ttk.Frame(self.settings)
        frame.pack(fill="both", expand=True, padx=16, pady=4)
        columns = ("status", "latency", "availability", "works", "detail")
        self.settings_tree = ttk.Treeview(frame, columns=columns, show="tree headings")
        self.settings_tree.heading("#0", text="方式")
        self.settings_tree.heading("status", text="状态")
        self.settings_tree.heading("latency", text="实测延迟")
        self.settings_tree.heading("availability", text="可用性")
        self.settings_tree.heading("works", text="什么网络下可行")
        self.settings_tree.heading("detail", text="说明")
        self.settings_tree.column("#0", width=190)
        self.settings_tree.column("status", width=105, anchor="center")
        self.settings_tree.column("latency", width=85, anchor="center")
        self.settings_tree.column("availability", width=120, anchor="center")
        self.settings_tree.column("works", width=230)
        self.settings_tree.column("detail", width=280)
        for state, colour in (("direct", OK), ("observed", OK), ("unavailable", BAD), ("unsupported", WARN)):
            self.settings_tree.tag_configure(state, foreground=colour)
        self.settings_tree.pack(fill="both", expand=True)
        self.settings_profile_note = tk.Label(self.settings, text="", bg=BG, fg=ACCENT, anchor="w", justify="left", wraplength=900)
        self.settings_profile_note.pack(fill="x", padx=16, pady=(4, 0))
        self.settings_remaining = tk.Label(self.settings, text="", bg=BG, fg=MUTED, anchor="w", justify="left", wraplength=900)
        self.settings_remaining.pack(fill="x", padx=16, pady=(6, 4))
        # Automatic central diagnostic collection: on by default, pausable.
        telemetry = ttk.Frame(self.settings, style="Panel.TFrame")
        telemetry.pack(fill="x", padx=16, pady=(0, 10))
        self.var_upload_logs = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            telemetry,
            text="自动汇集脱敏诊断到已连接中心（可随时暂停）",
            variable=self.var_upload_logs,
            command=self._on_telemetry_toggle,
        ).pack(anchor="w", padx=8, pady=(6, 0))
        self.telemetry_status = tk.Label(telemetry, text="", bg=PANEL, fg=MUTED, anchor="w", justify="left", wraplength=880)
        self.telemetry_status.pack(fill="x", padx=8, pady=(2, 6))

        # 需要单独同意的两件事：默认都不做；标题用人话，协议名只在“技术详情”里。
        optin = ttk.Frame(self.settings, style="Panel.TFrame")
        optin.pack(fill="x", padx=16, pady=(0, 10))
        ttk.Label(optin, text="需要你单独同意的三件事（默认都不做）", style="Panel.TLabel").pack(anchor="w", padx=10, pady=(8, 2))
        self.gateway_line = tk.Label(optin, text="", bg=PANEL, fg=FG, anchor="w", justify="left", wraplength=880)
        self.gateway_line.pack(fill="x", padx=10)
        gateway_bar = ttk.Frame(optin, style="Panel.TFrame")
        gateway_bar.pack(fill="x", padx=10, pady=4)
        ttk.Button(gateway_bar, text="让路由器开一个端口", command=self._on_gateway_open).pack(side="left")
        ttk.Button(gateway_bar, text="撤销已开的端口", command=self._on_gateway_close).pack(side="left", padx=8)
        ttk.Button(gateway_bar, text="技术详情", command=self._show_gateway_detail).pack(side="left")
        self.lan_line = tk.Label(optin, text="", bg=PANEL, fg=FG, anchor="w", justify="left", wraplength=880)
        self.lan_line.pack(fill="x", padx=10, pady=(6, 0))
        lan_bar = ttk.Frame(optin, style="Panel.TFrame")
        lan_bar.pack(fill="x", padx=10, pady=(2, 8))
        ttk.Button(lan_bar, text="开启同网段直连发现", command=self._on_lan_enable).pack(side="left")
        ttk.Button(lan_bar, text="关闭同网段直连发现", command=self._on_lan_disable).pack(side="left", padx=8)
        self.prediction_line = tk.Label(optin, text="", bg=PANEL, fg=FG, anchor="w", justify="left", wraplength=880)
        self.prediction_line.pack(fill="x", padx=10, pady=(6, 0))
        prediction_bar = ttk.Frame(optin, style="Panel.TFrame")
        prediction_bar.pack(fill="x", padx=10, pady=(2, 8))
        ttk.Button(prediction_bar, text="开启对称 NAT 端口预测", command=self._on_prediction_enable).pack(side="left")
        ttk.Button(prediction_bar, text="关闭端口预测", command=self._on_prediction_disable).pack(side="left", padx=8)
        self.optin_status = tk.Label(optin, text="", bg=PANEL, fg=MUTED, anchor="w", justify="left", wraplength=880)
        self.optin_status.pack(fill="x", padx=10, pady=(0, 8))
        self._refresh_optin()

    # ------------------------------------------------------------------- actions
    def _prefill(self, config: EngineConfig):
        self.var_server.set(config.url)
        self.var_room.set(config.room)
        self.var_name.set(config.name)
        self.var_secret.set(config.secret)

    def _on_connect(self):
        url = self.var_server.get().strip()
        room = self.var_room.get().strip()
        name = self.var_name.get().strip() or "Explorer"
        secret = self.var_secret.get()
        if not url or not room:
            self.connect_error.configure(text="请填写服务器地址和房间名。")
            return
        if len(secret.encode()) < 8:
            self.connect_error.configure(text="房间密码至少 8 个字符，并和对方保持一致。")
            return
        self.connect_error.configure(text="")
        self.connect_button.configure(state="disabled", text="正在连接…")
        config = EngineConfig(
            url=url,
            room=room,
            secret=secret,
            name=name,
            data_dir=os.path.join(os.path.expanduser("~"), ".p2pchat-desktop"),
            allow_native=True,
            allow_plaintext=bool(self.var_allow_plaintext.get()),
        )
        self.engine_thread.start()
        events = self.engine_thread.events
        assert events is not None
        self.engine = DesktopEngine(config, events=events)
        self.engine_thread.engine = self.engine
        self.engine_thread.submit(self._guard_start())
        self._show("attempt")
        self.attempt_summary.configure(text="已连接服务器，正在等待对方加入并交换连接信息…")

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
        self.peer_list.delete(0, "end")
        self._append_message("meta", "已断开。聊天连接与房间成员都已清空。")
        self.connect_button.configure(state="normal", text="连接并寻找对方")
        self._show("connect")
        self.beacon.configure(text="已断开连接。", fg=MUTED)

    def _on_peer_selected(self, _event=None):
        selection = self.peer_list.curselection()
        if not selection or self.engine is None or selection[0] >= len(self.peer_keys):
            return
        self.selected_target = self.peer_keys[selection[0]]
        self.engine_thread.submit(self.engine.select(self.selected_target))
        target = self.engine.targets.get(self.selected_target)
        self.chat_title.configure(text=f"正在和 {target.name if target else '对方'} 聊天")
        self._refresh_paths()

    def _require_target(self) -> str | None:
        if self.engine is None:
            messagebox.showinfo("还没有连接", "请先在第一个屏幕连接服务器。")
            return None
        if not self.selected_target:
            messagebox.showinfo("还没选人", "请在左侧选择聊天对象。")
            return None
        return self.selected_target

    def _on_send_text(self):
        key = self._require_target()
        if key is None:
            return
        text = self.var_message.get()
        if not text.strip():
            return
        if len(text.encode()) > MAX_MESSAGE_BYTES:
            messagebox.showwarning("文字太长", "请分成几条发送。")
            return
        self.var_message.set("")
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
            path = filedialog.askopenfilename(title="选择图片", filetypes=[("图片", "*.png *.jpg *.jpeg *.gif *.webp"), ("所有文件", "*.*")])
            mime = "image/png"
        else:
            path = filedialog.askopenfilename(title="选择文件")
            mime = "application/octet-stream"
        if not path:
            return
        size = os.path.getsize(path)
        if size > 32 * 1024 * 1024:
            messagebox.showwarning("文件太大", "单文件最多 32 MiB。")
            return
        self.transfer_status.configure(text=f"正在发送 {os.path.basename(path)}（{size} 字节）…")
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
            messagebox.showwarning("录音不可用", plain.reason("RECORDING_UNAVAILABLE"))
            return
        try:
            self.engine_thread.submit(self.recorder.start()).result(5)
        except Exception as error:
            code = str(error.args[0]) if error.args else "RECORDING_FAILED"
            messagebox.showwarning("录音失败", plain.reason(code))
            return
        self.recording = True
        self.record_button.configure(text="停止录音")
        self.transfer_status.configure(text="正在录音；再点一次「停止录音」结束。最多 60 秒。")

    def _stop_recording(self, key: str):
        self.record_button.configure(text="录音")
        self.recording = False
        self.transfer_status.configure(text="正在整理录音…")
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
            messagebox.showinfo("还没选人", "请先选择聊天对象。")
            return
        self.engine_thread.submit(self.engine.observe(self.selected_target))

    def _on_benchmark(self):
        key = self._require_target()
        if key is None:
            return
        self.speed_button.configure(state="disabled", text="测速中…")
        self.speed_result.configure(text="正在独立通道上测速，最多 5 秒或 32 MiB；以对方确认收到多少计算。")
        self.engine_thread.submit(self._benchmark(key))

    async def _benchmark(self, key: str):
        try:
            result = await self.engine.benchmark(key, seconds=5.0)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            self.engine._emit("benchmark.done", ok=False, code=code)
            return
        self.engine._emit("benchmark.done", **result)

    def _pump(self):
        """Drain engine events on the Tk thread, then refresh derived views."""
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
        self.root.after(150, self._pump)

    def _render(self, event: dict):
        kind = event.get("kind")
        if kind == "engine.error":
            self.beacon.configure(text=f"提示：{event.get('text') or plain.reason(event.get('code'))}", fg=WARN)
        elif kind == "optin":
            self.optin_status.configure(text=event.get("text", ""))
            self._refresh_optin()
        elif kind == "session.welcome":
            if self.engine is not None and self.engine.plaintext_warning:
                self.beacon.configure(text="⚠ 未加密连接：" + self.engine.plaintext_warning, fg=BAD)
            else:
                self.beacon.configure(text="已加入房间，正在等待对方。", fg=MUTED)
        elif kind == "engine.warning":
            self.beacon.configure(text="⚠ " + str(event.get("text") or ""), fg=BAD)
        elif kind == "engine.start_failed":
            self.engine = None
            self.engine_thread.engine = None
            self.connect_button.configure(state="normal", text="连接并寻找对方")
            self._show("connect")
            self.connect_error.configure(text=str(event.get("text") or plain.reason(event.get("code"))))
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
            self.beacon.configure(text=f"发送未完成：{plain.reason(event.get('code'))}", fg=BAD)
        elif kind == "benchmark.done":
            self.speed_button.configure(state="normal", text="测当前连接的速度")
            if event.get("ok"):
                self.speed_result.configure(
                    text=f"测得 {event.get('bytes')} 字节 / {event.get('elapsedMs')} 毫秒 ≈ {event.get('mbps')} Mbps（应用层速度，不是线路带宽）。"
                )
            else:
                self.speed_result.configure(
                    text=f"测速未完成：{event.get('reason') or plain.reason(event.get('code'))}；已发送 {event.get('bytes', 0)} 字节但没有得到对方确认，因此不报告速度。"
                )
        elif kind == "transfer.sent":
            self.transfer_status.configure(text=f"已发送 {event.get('bytes')} 字节（{event.get('mechanism')}）。")
        elif kind == "transfer.ack":
            self.transfer_status.configure(text="对方已确认收到。" if event.get("ok") else "对方拒绝了这次传输。")
        elif kind == "transfer.progress":
            self.transfer_status.configure(text=f"传输进度：已确认 {event.get('bytes')} 字节。")
        elif kind == "observation":
            if event.get("ok"):
                self.beacon.configure(text=f"观测到的出口地址：{event.get('address')}:{event.get('port')}（只观测，不转发）", fg=MUTED)
            else:
                self.beacon.configure(text="没能观测到出口地址。", fg=WARN)
        elif kind == "recording.saved":
            self.beacon.configure(text=f"录音已保存到本地并作为文件发送（{event.get('seconds')} 秒）。", fg=MUTED)
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
        if self.var_upload_logs.get() != bool(enabled):
            self.var_upload_logs.set(bool(enabled))
        if enabled is False:
            # 暂停优先：本机还有没上传的记录 → 中心记录不完整；队列已空 → 只说已暂停。
            if telemetry.get("complete", True) is False:
                text = text or telemetry.get("note") or plain.TELEMETRY_NOTE
            else:
                text = text or plain.TELEMETRY_PAUSED_TEXT
            self.telemetry_status.configure(text=text, fg=WARN)
            return
        self.telemetry_status.configure(text=text or plain.TELEMETRY_ON_TEXT, fg=MUTED)

    def _target_name(self, key: str) -> str:
        if self.engine is not None and key in self.engine.targets:
            return self.engine.targets[key].name or key[:6]
        return key[:6]

    def _append_message(self, tag: str, text: str):
        self.messages.configure(state="normal")
        self.messages.insert("end", text + "\n", tag)
        self.messages.see("end")
        self.messages.configure(state="disabled")

    def _preview_image(self, message):
        suffix = os.path.splitext(message.name or "")[1].lower()
        if suffix not in {".png", ".gif"}:
            return
        try:
            image = tk.PhotoImage(data=base64.b64encode(message.data).decode())
        except tk.TclError:
            return
        self.messages.configure(state="normal")
        self.messages.image_create("end", image=image)
        self.messages.insert("end", "\n")
        self.messages.configure(state="disabled")
        self._images.append(image)

    def _refresh(self):
        if self.engine is None:
            return
        self._refresh_peers()
        self._refresh_paths()
        # Persistent while connected: never let the unencrypted state scroll away.
        if self.engine.plaintext_warning:
            self.beacon.configure(text="⚠ 未加密连接：" + self.engine.plaintext_warning, fg=BAD)

    def _refresh_peers(self):
        if self.engine is None:
            return
        keys = [key for key, target in self.engine.targets.items() if target.webrtc_id or target.native_id]
        if keys != self.peer_keys:
            self.peer_keys = keys
            self.peer_list.delete(0, "end")
            for key in keys:
                target = self.engine.targets[key]
                summary = self.engine.summary(key)
                mark = "●" if summary["canSend"] else ("…" if summary["remaining"] else "○")
                self.peer_list.insert("end", f"{mark} {target.name or key[:6]}")
            if keys and self.selected_target not in keys:
                self.selected_target = keys[0]
                self.peer_list.selection_set(0)
                self.engine_thread.submit(self.engine.select(keys[0]))
                self.chat_title.configure(text=f"正在和 {self.engine.targets[keys[0]].name or '对方'} 聊天")
        self._maybe_enter_chat()

    def _maybe_enter_chat(self):
        if self.engine is None or self.chat_entered or not self.selected_target:
            return
        if self.engine.summary(self.selected_target)["canSend"]:
            self.chat_entered = True
            self._show("chat")
            self.beacon.configure(text="已有一条直接连接可用，可以开始聊天；其余方式仍在后台继续尝试。", fg=OK)

    def _refresh_paths(self):
        if self.engine is None:
            return
        key = self.selected_target
        if key is None or key not in self.engine.targets:
            rows = []
            summary = {"remaining": [], "direct": [], "latency": None, "probeOnly": [], "unavailable": [], "canSend": False}
        else:
            summary = self.engine.summary(key)
            rows = summary["rows"]
        self.attempt_tree.delete(*self.attempt_tree.get_children())
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
            self.attempt_tree.insert(
                "",
                "end",
                text=label,
                values=(row["status"], row["availability"], _fmt_latency(row["latency"])),
                tags=(row["state"],),
            )
        if rows:
            self.attempt_profile_note.configure(text=summary.get("webRtcProfileNote") or "")
            latency_text = _fmt_latency(summary["latency"])
            if summary["latency"] is None:
                latency_text = "—（还没有可聊天的直连，所以不报延迟）"
            self.attempt_summary.configure(
                text=f"已打通：{'、'.join(summary['direct']) if summary['direct'] else '暂无'}　|　实测延迟：{latency_text}　|　剩余方式：{len(summary['remaining'])} 条"
            )
        self.settings_tree.delete(*self.settings_tree.get_children())
        for row in rows:
            self.settings_tree.insert(
                "",
                "end",
                text=row["title"],
                values=(
                    row["status"],
                    _fmt_latency(row["latency"]) if row.get("probeRtt") is None else f"{row['probeRtt']:.1f} ms（仅探测/观测）",
                    row["availability"] + (f"（{row['availabilityNote']}）" if row.get("availabilityNote") else ""),
                    row.get("works", ""),
                    row["detail"] or row["failureHint"],
                ),
                tags=(row["state"],),
            )
        self.settings_profile_note.configure(text=summary.get("webRtcProfileNote") or "")
        remaining = summary["remaining"]
        self.settings_remaining.configure(
            text=(
                f"剩余方式（还没成功、仍在后台尝试）：{'、'.join(remaining) if remaining else '无'}\n"
                f"已打通：{'、'.join(summary['direct']) if summary['direct'] else '暂无'}"
                f"　|　实测延迟：{'尚未测到（不会用 0 代替）' if summary['latency'] is None else _fmt_latency(summary['latency'])}\n"
                f"仅探测、不传内容：{'、'.join(summary['probeOnly']) if summary['probeOnly'] else '无'}"
                f"　|　探测/观测往返时间：{_fmt_latency(summary.get('probeRtt'))}（不是聊天延迟）\n"
                "不可用/不支持：见上表说明。路由器放行默认关闭，必须由操作者显式授权；本界面不会自动修改路由器。\n"
                "整个产品没有中继、没有 TURN，也不通过服务器转发聊天：直连不成功就是失败。"
            )
        )
        # 与 _render 的 "telemetry" 事件走同一个渲染点，避免两处文案说反话。
        telemetry = summary.get("telemetry")
        if not telemetry and self.engine is not None:
            telemetry = self.engine.telemetry_status()
        self._apply_telemetry(telemetry or {})
        if key and key in self.engine.targets:
            self.chat_path.configure(text=f"可用直连：{'、'.join(summary['direct']) if summary['direct'] else '连接尚未打通'}")

    def _on_telemetry_toggle(self):
        if self.engine is None:
            return
        paused = not bool(self.var_upload_logs.get())
        self.engine_thread.submit(self._set_telemetry(paused))

    async def _set_telemetry(self, paused: bool):
        status = self.engine.set_telemetry_paused(paused)
        self.engine._emit("telemetry", **status)

    # ------------------------------------ 需要单独同意的两件事（路由器放行 / 同网段直连）
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
            self.gateway_line.configure(text=self._gateway_controller().capability_line())
            self.lan_line.configure(text=self._lan_controller().capability_line())
            self.prediction_line.configure(text=self._prediction_line_text())
        except Exception as error:  # 能力读取失败也要说出来，不静默
            self.optin_status.configure(text=f"读取能力失败：{type(error).__name__}")

    def _prediction_line_text(self) -> str:
        engine = self.engine
        if engine is None:
            return ("对称 NAT 端口预测：默认关闭；连上服务器后由你单独同意才开启。它只对已信令的对端地址做少量认证探测，"
                    "不会扫描第三方。优先顺序：IPv6 直连 > 网关注册放行 > 端口预测。")
        capability = engine.prediction_capability()
        note = engine.prediction_hit_rate_note()
        status = capability.get("status")
        if status == "available":
            return (f"对称 NAT 端口预测：已开启（观测点 {capability.get('observationPoints', 0)} 个）——"
                    f"只对已信令的对端地址做少量认证探测。{note}")
        if status == "disabled":
            return ("对称 NAT 端口预测：默认关闭，需要你点“开启对称 NAT 端口预测”并确认才会开启。"
                    "它不会扫描第三方，也不保证成功：" + note)
        return f"对称 NAT 端口预测：暂不可用（{capability.get('reason')}）。{note}"

    def _on_prediction_enable(self):
        engine = self.engine
        if engine is None:
            messagebox.showwarning("还没连接", "先在连接屏连上服务器，再决定要不要开启端口预测。")
            return
        capability = engine.prediction_capability()
        if capability.get("status") == "unavailable" and capability.get("reason") == "OBSERVATION_POINTS_REQUIRED":
            messagebox.showwarning(
                "缺少观测点",
                "端口预测需要你显式配置至少两个 STUN 观测点（IP:端口），它不会自动找服务器，也不会扫描网段。",
            )
            return
        if not messagebox.askyesno("开启对称 NAT 端口预测", engine.prediction_consent_text()):
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
        if now - getattr(self, "_optin_refreshed_at", 0.0) < 0.5:
            return
        self._optin_refreshed_at = now
        try:
            if self.settings.winfo_viewable():
                self._refresh_optin()
        except Exception:
            return

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
        self.optin_status.configure(text=self._optin_status_text())

    def _on_gateway_open(self):
        controller = self._gateway_controller()
        if self.engine is None:
            self.optin_status.configure(text="请先连接服务器：端口放行要指向一条真实在听的直连端口。")
            return
        if not messagebox.askyesno("让路由器开一个端口", controller.consent_text()):
            self.optin_status.configure(text="已取消：没有去动路由器。")
            return
        self.optin_status.configure(text="已同意，正在尝试让路由器开端口…（失败会说明原因，不会当作成功）")
        self.engine_thread.submit(self._gateway_open_async())

    async def _gateway_open_async(self):
        engine = self.engine
        try:
            await engine.gateway_consent("ui")
            result = await engine.gateway_open_port()
            engine._emit("optin", text=f"路由器已开端口 {result.get('externalPort')}"
                                       f"（外部对端确认：{'已完成' if result.get('verified') else '还没有'}）")
        except Exception as error:
            engine._emit("optin", text="端口放行没有成功：" + engine.gateway_failure_hint(str(error).split(",", 1)[0]))

    def _on_gateway_close(self):
        if self.engine is None:
            self.optin_status.configure(text="还没有连接，没有需要撤销的端口。")
            return
        self.optin_status.configure(text="正在撤销路由器上的端口映射…")
        self.engine_thread.submit(self._gateway_close_async())

    async def _gateway_close_async(self):
        engine = self.engine
        try:
            result = await engine.gateway_close_port()
            failures = result.get("failures", [])
            engine._emit("optin", text=f"已撤销 {len(result.get('released', []))} 条映射"
                                       + (f"，{len(failures)} 条没撤销成功" if failures else ""))
        except Exception as error:
            engine._emit("optin", text=f"撤销端口失败：{type(error).__name__}")

    def _on_lan_enable(self):
        controller = self._lan_controller()
        if self.engine is None:
            self.optin_status.configure(text="请先连接服务器：同网段发现要广播一个真实在听的端口。")
            return
        if not messagebox.askyesno("在同网段里互相发现", controller.consent_text()):
            self.optin_status.configure(text="已取消：没有开始组播。")
            return
        self.engine_thread.submit(self._lan_enable_async())

    async def _lan_enable_async(self):
        engine = self.engine
        try:
            status = await engine.lan_enable(consent=True)
            engine._emit("optin", text="同网段直连发现已开启"
                                       + ("（测试模式：回环，不算局域网证据）" if status.get("restrictedLocal") else ""))
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
            self.optin_status.configure(text="还没有连接，没有在跑的组播。")
            return
        self.engine_thread.submit(self._lan_disable_async())

    async def _lan_disable_async(self):
        engine = self.engine
        result = await engine.lan_disable()
        engine._emit("optin", text=f"同网段直连发现已关闭（之前发现 {result.get('peersFound', 0)} 个设备）")

    def _show_gateway_detail(self):
        messagebox.showinfo("技术详情", self._gateway_controller().technical_detail()
                            + "\n\n" + self._lan_controller().technical_detail())

    def _open_settings(self):
        if self.engine is not None and self.selected_target:
            self._refresh_paths()
        self.settings.deiconify()
        self.settings.lift()

    def _close_settings(self):
        self.settings.withdraw()

    def _show_capabilities(self):
        messagebox.showinfo("本机支持哪些功能", "\n".join(capability_lines()))

    def _on_close(self):
        try:
            self.engine_thread.stop()
        finally:
            self.root.destroy()


def run(config: EngineConfig | None = None) -> int:
    try:
        root = tk.Tk()
    except tk.TclError as error:
        print(f"无法启动图形界面：{error}", file=sys.stderr)
        print("请在有图形显示的会话中运行，或使用 --self-test 做无界面自检。", file=sys.stderr)
        return 2
    DesktopApp(root, config)
    root.mainloop()
    return 0
