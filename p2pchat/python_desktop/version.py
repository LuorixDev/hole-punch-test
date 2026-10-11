"""Single source of truth for the desktop version and its capability list."""
from __future__ import annotations

import platform
import sys

VERSION = "0.2.0"
PRODUCT = "直连聊天 · 桌面版"

# Every mechanism this client can actually start in this process. Gateway
# methods (UPnP / PCP / NAT-PMP / IPv6 pinhole) are deliberately absent: the
# adapter reports them unsupported unless an operator opts in out of band.
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
    try:
        import tkinter  # noqa: F401

        report["gui"] = "available"
    except Exception:
        report["gui"] = "unsupported"
    from .audio import recorder_status

    report["audio"] = recorder_status()
    return report


def capability_lines() -> list[str]:
    report = capabilities_report()
    lines = [
        f"版本：{report['version']}",
        f"运行环境：{report['platform']} / Python {report['python']}",
        f"图形界面（Tkinter）：{report['gui']}",
        f"浏览器直连（WebRTC / ICE）：{report['webrtc']}",
        f"UDP 探测：{report['native'].get('udp-probe')}",
        f"QUIC 加密直连：{report['native'].get('quic')}",
        f"TCP 加密直连：{report['native'].get('tcp')}",
        f"TCP 同时打开：{report['native'].get('tcp-simopen')}",
        f"录音（麦克风）：{report['audio']}",
        "路由器放行（自动开一个端口）：不支持（需要操作者显式授权，本客户端不自动修改路由器）",
        "明文 ws:// 连接：默认拒绝非回环地址，只有显式确认后才放行，并在会话期间持续提示未加密",
    ]
    return lines
