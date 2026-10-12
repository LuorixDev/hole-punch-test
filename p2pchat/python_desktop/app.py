"""Desktop client entry point.

    python -m p2pchat.python_desktop.app                 # Qt (PySide6) client
    python -m p2pchat.python_desktop.app --self-test     # headless verification
    python -m p2pchat.python_desktop.app --capabilities  # version + capability list

The GUI starts on the server-address screen; nothing connects until the operator
fills the form and presses connect.
"""
from __future__ import annotations

import argparse
import json
import sys


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="直连聊天 · 纯 Python + Qt(PySide6) 桌面客户端")
    parser.add_argument("--self-test", action="store_true", help="无界面自检：启动服务端+回声+客户端做一次真实 P2P 握手")
    parser.add_argument("--capabilities", action="store_true", help="输出版本与本机能力清单后退出")
    parser.add_argument("--json", action="store_true", help="自检或能力清单以 JSON 输出")
    parser.add_argument("--no-native", action="store_true", help="自检时只验证浏览器直连方式")
    parser.add_argument("--timeout", type=float, default=60.0, help="自检等待握手的最长秒数")
    parser.add_argument("--server", help="预填服务器地址（仅预填，不会自动连接）")
    parser.add_argument("--room", help="预填房间名")
    parser.add_argument("--name", help="预填昵称")
    parser.add_argument("--secret-file", help="从文件读取房间密码（不落在命令行里）")
    parser.add_argument("--data-dir", help="本机诊断日志目录")
    parser.add_argument("--origin", help="操作者批准的 WSS Origin；不是身份凭据")
    parser.add_argument(
        "--allow-plaintext",
        action="store_true",
        help="显式确认允许未加密的 ws://（仅限你自己的可信服务器；默认拒绝非回环明文）",
    )
    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    if args.capabilities:
        from .version import VERSION, capabilities_report, capability_lines

        if args.json:
            print(json.dumps({"version": VERSION, **capabilities_report()}, ensure_ascii=False, indent=2))
        else:
            print("直连聊天 · 桌面版")
            for line in capability_lines():
                print(f"  {line}")
        return 0

    if args.self_test:
        from .selftest import self_test

        import asyncio

        return asyncio.run(self_test(native=not args.no_native, timeout=args.timeout, as_json=args.json))

    import os

    from .engine import EngineConfig
    from .qt_ui import run

    secret = ""
    if args.secret_file:
        with open(args.secret_file, "r", encoding="utf-8") as handle:
            secret = handle.read().strip()
    config = EngineConfig(
        url=args.server or "ws://127.0.0.1:8088/ws",
        room=args.room or "lab",
        secret=secret or "change-me-please",
        name=args.name or "Explorer",
        data_dir=args.data_dir or os.path.join(os.path.expanduser("~"), ".p2pchat-desktop"),
        origin=args.origin,
        allow_plaintext=bool(args.allow_plaintext),
    )
    if not (args.server or args.room or args.name or args.secret_file or args.data_dir):
        # Nothing prefilled: start on a blank-ish form, but keep the local default
        # so the text fields still show something usable.
        config.secret = ""
    return run(config)


if __name__ == "__main__":
    sys.exit(main())
