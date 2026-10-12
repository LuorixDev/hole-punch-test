"""Single source of truth for the desktop version and its capability list."""
from __future__ import annotations

import platform
import sys

VERSION = "0.2.0"
PRODUCT = "直连聊天 · 桌面版"

# Every mechanism this client can start on its own. Gateway methods
# (UPnP / PCP / NAT-PMP / IPv6 pinhole) are **not** in this list because they are
# never started automatically: they are off by default and only behave after the
# operator gives explicit consent (see gateway_optin.py and docs/GATEWAY-OPTIN.md).
# Their availability is still reported truthfully by _gateway_capability_line():
# 可用（但需要你点同意）on platforms whose routing table can be verified read-only,
# 不支持 elsewhere — being opt-in is not the same as being unsupported.
NATIVE_MECHANISMS = ("udp-probe", "quic", "tcp", "tcp-simopen")
WEBRTC_PROFILES = ("ice-dual", "ice-v6", "ice-v4")


def capabilities_report() -> dict:
    """Import-checked capability list; never claims an untested network result."""
    report = {
        "version": VERSION,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.machine()}",
        "webrtc": None,
        "native": {},
        "audio": None,
        "gui": None,
    }
    try:
        import aiortc  # noqa: F401

        report["webrtc"] = "available"
    except Exception:
        report["webrtc"] = "unsupported"
    for module, label in (("aioquic", "quic"), ("cryptography", None)):
        if label is None:
            continue
        try:
            __import__(module)
            report["native"][label] = "available"
        except Exception:
            report["native"][label] = "unsupported"
    report["native"]["udp-probe"] = report["native"].get("quic", "unsupported")
    report["native"]["tcp"] = "available"
    report["native"]["tcp-simopen"] = "available"
    # GUI toolkit: Qt via PySide6 (the Tkinter shell was replaced because this Tk
    # runtime is not linked against Xft and rendered 中文 as blanks). Probe without
    # importing the toolkit: this module is part of the logic layer and must stay
    # free of GUI imports.
    from importlib import metadata, util

    if util.find_spec("PySide6") is None:
        report["gui"] = "unsupported"
        report["guiToolkit"] = "unsupported"
    else:
        report["gui"] = "available"
        versions = []
        for distribution in ("PySide6-Essentials", "PySide6", "shiboken6"):
            try:
                versions.append(f"{distribution} {metadata.version(distribution)}")
            except Exception:
                continue
        report["guiToolkit"] = " / ".join(versions) or "PySide6（版本未知）"
    from .audio import recorder_status

    report["audio"] = recorder_status()
    return report


def _gateway_capability_line() -> str:
    """如实报告路由器放行的平台能力（默认关闭不等于不支持）。"""
    try:
        from .gateway_optin import GatewayOptIn

        capability = GatewayOptIn().capability()
    except Exception as error:  # 读能力失败也说出来，不假装可用
        return f"路由器放行（自动开一个端口）：暂不可用（读取能力失败：{type(error).__name__}）"
    if capability.get("status") == "available":
        return "路由器放行（自动开一个端口）：可用（默认关闭，需要你单独点同意后才尝试一次，本客户端不会自动改路由器）"
    return f"路由器放行（自动开一个端口）：不支持（{capability.get('reason')}；默认关闭）"


def _lan_capability_line() -> str:
    try:
        from .lan_client import LanDirect

        capability = LanDirect().capability()
        consent = "需要你单独同意" if capability.get("consentRequired", True) else "无需同意"
        return f"同网段直连发现：{capability.get('status')}（默认关闭，{consent}；生产模式拒绝回环）"
    except Exception as error:
        return f"同网段直连发现：暂不可用（读取能力失败：{type(error).__name__}）"


def capability_lines() -> list[str]:
    report = capabilities_report()
    lines = [
        f"版本：{report['version']}",
        f"运行环境：{report['platform']} / Python {report['python']}",
        f"图形界面（Qt / PySide6）：{report['gui']}（{report.get('guiToolkit')}）",
        f"浏览器直连（WebRTC / ICE）：{report['webrtc']}",
        f"UDP 探测：{report['native'].get('udp-probe')}",
        f"QUIC 加密直连：{report['native'].get('quic')}",
        f"TCP 加密直连：{report['native'].get('tcp')}",
        f"TCP 同时打开：{report['native'].get('tcp-simopen')}",
        f"录音（麦克风）：{report['audio']}",
        _gateway_capability_line(),
        _lan_capability_line(),
        "明文 ws:// 连接：默认拒绝非回环地址，只有显式确认后才放行，并在会话期间持续提示未加密",
    ]
    return lines
