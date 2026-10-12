"""网关放行接线：未授权零请求；授权后受控 mock 走完 map/renew/close；非 Linux 明确不可用。"""
from __future__ import annotations

import asyncio
import json
import sys

from p2pchat.native import adapter as adapter_module
from p2pchat.native.adapter import NativeAdapter, gateway_platform_capability
from p2pchat.python_desktop.gateway_optin import GatewayOptIn


class FakeAdapter:
    """受控 mock：记录每次调用，不碰网络。"""

    def __init__(self, status="available", reason="EXPLICIT_OPT_IN_REQUIRED", fail=None):
        self.calls = []
        self.status, self.reason, self.fail = status, reason, fail

    def gateway_capability(self):
        return {"v": 1, "status": self.status, "reason": self.reason, "platform": "linux",
                "gateway": "10.0.0.1", "consentRequired": True, "mechanisms": ["pcp", "natpmp", "upnp"],
                "limits": {"maxMappings": 8, "maxLifetimeSeconds": 7200}}

    async def gateway_map(self, params):
        self.calls.append(("map", params))
        if self.fail:
            raise self.fail
        return {"protocol": "pcp", "internalPort": params["internalPort"], "externalPort": 41234,
                "externalAddress": "203.0.113.7", "lifetimeSeconds": params["lifetimeSeconds"], "verified": True}

    async def gateway_renew(self, params):
        self.calls.append(("renew", params))
        return {"protocol": params.get("protocol") or "pcp", "internalPort": 40000, "externalPort": 41234,
                "lifetimeSeconds": params["lifetimeSeconds"], "verified": True}

    async def gateway_release(self, params):
        self.calls.append(("release", params))
        return {"released": ["pcp"], "failures": []}


def test_unauthorized_makes_zero_requests_and_records_denial() -> None:
    fake = FakeAdapter()
    controller = GatewayOptIn(adapter=fake)
    try:
        asyncio.run(controller.map_port(40000))
        raise AssertionError("没有同意时必须拒绝")
    except PermissionError as error:
        assert str(error) == "GATEWAY_OPT_IN_REQUIRED"
    assert fake.calls == [], "未授权时不得调用适配器"
    assert controller.audit.events[-1]["action"] == "mapping-denied"
    assert controller.audit.events[-1]["reason"] == "GATEWAY_OPT_IN_REQUIRED"
    assert controller.capability()["consented"] is False


def test_real_adapter_consent_gate_never_opens_a_socket(monkeypatch) -> None:
    """把适配器里的 socket 模块换成记录器：未同意时连一次 socket() 都不该发生。

    只替换 ``p2pchat.native.adapter`` 引用的那份模块，不动全局 socket（否则会拆掉
    asyncio 自己的 self-pipe）。
    """
    adapter = NativeAdapter()
    real_socket = adapter_module.socket

    class Recorder:
        def __init__(self):
            self.calls = []

        def socket(self, *args, **kwargs):  # pragma: no cover - 只有越界时才会执行
            self.calls.append((args, kwargs))
            raise AssertionError("未同意时不应该创建任何 socket")

        def __getattr__(self, name):
            return getattr(real_socket, name)

    recorder = Recorder()
    monkeypatch.setattr(adapter_module, "socket", recorder)
    try:
        asyncio.run(adapter.gateway_map({"consent": False, "internalPort": 40000}))
        raise AssertionError("没有同意时必须拒绝")
    except PermissionError as error:
        assert str(error) == "GATEWAY_OPT_IN_REQUIRED"
    assert recorder.calls == [], "未同意时不得创建 socket"


def test_non_linux_reports_unsupported_without_silent_fallback(monkeypatch) -> None:
    assert gateway_platform_capability("win32")["status"] == "unsupported"
    assert gateway_platform_capability("darwin")["reason"] == "PLATFORM_VALIDATION_UNAVAILABLE"
    assert gateway_platform_capability("linux", route_path="/nonexistent/route")["reason"] == "NO_LOCAL_ROUTING_TABLE"

    monkeypatch.setattr(adapter_module, "gateway_platform_capability",
                        lambda platform=None, route_path=None: {"status": "unsupported",
                                                                "reason": "PLATFORM_VALIDATION_UNAVAILABLE",
                                                                "platform": platform or "win32"})
    adapter = NativeAdapter()
    capability = adapter.gateway_capability()
    assert capability["status"] == "unsupported"
    assert capability["consentRequired"] is True
    entries = asyncio.run(adapter.capabilities())["methods"]
    gateway_entries = [entry for entry in entries if entry["mechanism"] in {"upnp", "pcp", "natpmp"}]
    assert gateway_entries and all(entry["status"] == "unsupported" for entry in gateway_entries)
    assert all(entry["reason"] == "PLATFORM_VALIDATION_UNAVAILABLE" for entry in gateway_entries)
    assert all(entry["canMessage"] is False for entry in gateway_entries)
    try:
        asyncio.run(adapter.gateway_map({"consent": True, "internalPort": 40000}))
        raise AssertionError("平台不可用时应拒绝而不是静默降级")
    except NotImplementedError as error:
        assert str(error) == "PLATFORM_VALIDATION_UNAVAILABLE"


# 平台真实原因码：Linux 只读路由表可用 / 无路由表 / 无默认网关；其它平台核对未实现。
# 不能用假的“不可用”糊弄，也不能把某个平台的原因码当成所有平台都必须出现的值。
REAL_PLATFORM_REASONS = {"EXPLICIT_OPT_IN_REQUIRED", "PLATFORM_VALIDATION_UNAVAILABLE",
                         "NO_LOCAL_ROUTING_TABLE", "NO_DEFAULT_GATEWAY"}


def test_linux_reports_available_and_still_requires_consent() -> None:
    adapter = NativeAdapter()
    capability = adapter.gateway_capability()
    entries = asyncio.run(adapter.capabilities())["methods"]
    gateway_entries = [entry for entry in entries if entry["mechanism"] in {"upnp", "pcp", "natpmp"}]
    assert gateway_entries, "网关方式必须如实出现在能力表里"
    assert capability["consentRequired"] is True
    assert capability["reason"] in REAL_PLATFORM_REASONS and capability["reason"], capability
    if capability["status"] == "available":
        # Linux 的只读路由表核对可用：仍然必须显式同意才会去请求映射。
        assert sys.platform.startswith("linux"), "只有 Linux 的只读路由表核对被验证过"
        assert capability["gateway"], "Linux 上应该能读只读路由表拿到默认网关"
        assert all(entry["status"] == "available" and entry["requiresExplicitConsent"] for entry in gateway_entries)
        assert all(entry["reason"] == "EXPLICIT_OPT_IN_REQUIRED" for entry in gateway_entries)
    else:
        # Linux 无路由表 / Windows / macOS：如实报不支持，原因码必须是平台真实原因。
        if not sys.platform.startswith("linux"):
            assert capability["reason"] == "PLATFORM_VALIDATION_UNAVAILABLE", capability
        else:
            assert capability["reason"] in {"NO_LOCAL_ROUTING_TABLE", "NO_DEFAULT_GATEWAY"}, capability
        assert all(entry["status"] == "unsupported" and entry["canMessage"] is False for entry in gateway_entries)
        assert all(entry["reason"] == capability["reason"] for entry in gateway_entries)


def test_authorized_mock_completes_map_renew_close_lifecycle() -> None:
    fake = FakeAdapter()
    controller = GatewayOptIn(adapter=fake)
    controller.grant_consent("test")

    async def scenario():
        mapped = await controller.map_port(40000, lifetime_seconds=120)
        renewed = await controller.renew(lifetime_seconds=180)
        released = await controller.close()
        return mapped, renewed, released

    mapped, renewed, released = asyncio.run(scenario())
    assert mapped["externalPort"] == 41234 and mapped["verified"] is True
    assert renewed["lifetimeSeconds"] == 180
    assert released == {"released": ["pcp"], "failures": []}
    assert [name for name, _ in fake.calls] == ["map", "renew", "release"]
    assert all(params.get("consent") is True for _, params in fake.calls)
    actions = [event["action"] for event in controller.audit.events]
    assert actions[:2] == ["consent-granted", "mapping-requested"]
    assert "mapping-established" in actions and "renew-ok" in actions and "release-ok" in actions
    blob = json.dumps(controller.audit.events, ensure_ascii=False).lower()
    for forbidden in ("secret", "privatekey", "password", "room_key"):
        assert forbidden not in blob, f"审计记录里不应出现 {forbidden}"


def test_failure_is_recorded_with_a_plain_language_reason() -> None:
    fake = FakeAdapter(fail=TimeoutError("GATEWAY_TIMEOUT"))
    controller = GatewayOptIn(adapter=fake)
    controller.grant_consent("test")
    try:
        asyncio.run(controller.map_port(40000))
        raise AssertionError("失败必须抛出")
    except TimeoutError:
        pass
    last = controller.audit.events[-1]
    assert last["action"] == "mapping-failed"
    assert "路由器" in last["plain"], "失败原因要用人话说明（例如路由器关掉了该功能）"


def test_close_without_any_mapping_is_recorded_as_skipped() -> None:
    controller = GatewayOptIn(adapter=FakeAdapter())
    assert asyncio.run(controller.close()) == {"released": [], "failures": []}
    assert controller.audit.events[-1]["action"] == "release-skipped"


def test_capability_text_matches_the_real_status() -> None:
    """界面文案必须来自同一份能力数据：可用/不可用不能各说各话。"""
    available = GatewayOptIn(adapter=FakeAdapter())
    line = available.capability_line()
    assert "不可用" not in line and "需要你点同意" in line
    available.grant_consent("test")
    assert "已同意" in available.capability_line()

    unsupported = GatewayOptIn(adapter=FakeAdapter(status="unsupported", reason="PLATFORM_VALIDATION_UNAVAILABLE"))
    assert unsupported.capability_line().startswith("不可用：")
    assert "这个系统" in unsupported.capability_line(), "不可用时必须给人话原因"
    assert "10.0.0.1" in unsupported.technical_detail()
    assert "PLATFORM_VALIDATION_UNAVAILABLE" in unsupported.technical_detail()


def test_capabilities_reports_gateway_honestly_without_pretending() -> None:
    """能力报告必须与平台事实一致：可用就说可用（但仍需同意），不可用就给人话原因。"""
    adapter = NativeAdapter()
    capability = adapter.gateway_capability()
    entries = asyncio.run(adapter.capabilities())["methods"]
    gateway_entries = [entry for entry in entries if entry["mechanism"] in {"upnp", "pcp", "natpmp"}]
    assert gateway_entries and all(entry["canMessage"] is False for entry in gateway_entries)
    assert all(entry["requiresExplicitConsent"] is True for entry in gateway_entries), "网关放行必须逐次显式同意"
    if capability["status"] == "available":
        assert capability["gateway"], "Linux 上应能只读路由表读出默认网关"
        assert all(entry["status"] == "available" for entry in gateway_entries)
        assert all(entry["reason"] == "EXPLICIT_OPT_IN_REQUIRED" for entry in gateway_entries)
    else:
        assert capability["reason"] in {"PLATFORM_VALIDATION_UNAVAILABLE", "NO_LOCAL_ROUTING_TABLE", "NO_DEFAULT_GATEWAY"}
        assert all(entry["status"] == "unsupported" for entry in gateway_entries)
        assert all(entry["reason"] == capability["reason"] for entry in gateway_entries)
    udp = next(entry for entry in entries if entry["mechanism"] == "udp-probe")
    assert udp["canMessage"] is False, "UDP 探测只能探测，不能传内容"


# ---------------------------------------------------------------- 与界面库无关

from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]  # p2pchat/ 包目录；下面路径相对它

# 纯逻辑模块：不允许出现任何界面库导入，也不允许构造控件。
LOGIC_MODULES = (
    "python_desktop/gateway_optin.py",
    "python_desktop/lan_client.py",
    "python_desktop/engine.py",
    "python_desktop/signal_session.py",
    "python_desktop/native_session.py",
    "native/adapter.py",
)

GUI_TOOLKIT_IMPORTS = (
    "import tkinter", "from tkinter", "import _tkinter",
    "import PySide6", "from PySide6", "import PyQt", "from PyQt",
)
WIDGET_CONSTRUCTION = (
    "QtWidgets.Q", "QApplication(", "QDialog(", "QLabel(", "QMainWindow(",
    "Tk(", "tk.Label", "ttk.",
)

# Qt 迁移后的薄界面层：只有它可以 import 界面库并构造控件。
UI_MODULE = "python_desktop/qt_ui.py"
UI_MODULE_IMPORT = "from PySide6 import QtCore"
OLD_TK_MODULE = "python_desktop/ui.py"
# 例外：version.py 允许在函数体里做“本机能力探测”式导入（必须缩进，不能顶格 import）。
RUNTIME_PROBE_ALLOWLIST = {"version.py"}


def test_logic_layer_is_free_of_gui_toolkits() -> None:
    """逻辑层（能力查询 / opt-in 状态机 / native 调用）不依赖任何界面库。"""
    offenders = []
    for relative in LOGIC_MODULES:
        source = (ROOT / relative).read_text(encoding="utf-8")
        for marker in GUI_TOOLKIT_IMPORTS + WIDGET_CONSTRUCTION:
            if marker in source:
                offenders.append(f"{relative}: {marker}")
    assert offenders == [], f"逻辑层不应依赖界面库：{offenders}"


def test_ui_layer_is_the_only_place_that_imports_the_toolkit() -> None:
    """界面库只允许出现在薄界面层；旧的 Tk 模块必须已经移除。"""
    ui = ROOT / UI_MODULE
    assert ui.is_file(), f"薄界面层应当是 {UI_MODULE}"
    assert UI_MODULE_IMPORT in ui.read_text(encoding="utf-8"), "qt_ui.py 应当 import Qt 控件层"
    assert not (ROOT / OLD_TK_MODULE).exists(), "旧的 Tk 界面模块必须移除"

    offenders = []
    for path in sorted((ROOT / "python_desktop").glob("*.py")):
        if path.name == Path(UI_MODULE).name:
            continue
        text = path.read_text(encoding="utf-8")
        for marker in GUI_TOOLKIT_IMPORTS:
            if marker not in text:
                continue
            indented = all(line[:1].isspace() or not line.strip()
                           for line in text.splitlines() if marker in line)
            if path.name in RUNTIME_PROBE_ALLOWLIST and indented:
                continue  # 运行时能力探测：只在函数体里 import，不参与界面渲染
            offenders.append(f"{path.name}: {marker}")
    assert offenders == [], f"界面库只应出现在 {UI_MODULE}：{offenders}"


def test_only_the_thin_ui_layer_builds_widgets() -> None:
    offenders = []
    for path in sorted((ROOT / "python_desktop").glob("*.py")):
        if path.name == Path(UI_MODULE).name:
            continue
        text = path.read_text(encoding="utf-8")
        found = [marker for marker in WIDGET_CONSTRUCTION if marker in text]
        if found:
            offenders.append(f"{path.name}: {found}")
    assert offenders == [], f"只有 {UI_MODULE} 可以构造控件：{offenders}"
