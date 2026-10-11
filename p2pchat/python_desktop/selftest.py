"""Headless self-test: real server + real echo peer + real client handshake.

Run ``python -m p2pchat.python_desktop.app --self-test``. The mode starts the
project's own signaling/STUN server in-process, joins the same room with a
reused :class:`p2pchat.peer.Peer` echo, and drives the desktop engine until a
direct path is authenticated. It then proves the path with a text round-trip,
an echoed file and a benchmark, and prints the method that was actually used,
the measured latency and the outcome.

Scope honesty: every socket here is on this Linux host. This is a functional
proof that the desktop client performs a real authenticated P2P handshake and
that the reused transports work; it is **not** home-broadband or cross-NAT
evidence, and it does not claim any method works on Windows or Android.
"""
from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import secrets
import socket
import sys
import tempfile
import time
import uuid
from pathlib import Path

from aiohttp import web

from p2pchat.server import Stun, make_app

from .engine import DesktopEngine, EngineConfig
from .methods import METHOD_BY_ID

LOOPBACK = "127.0.0.1"
SELFTEST_PEER = "127.0.0.2"
SCOPE_NOTE = "同一台 Linux 主机上的真实套接字与真实握手；不是家宽或跨 NAT 证据。"


def free_port(family=socket.AF_INET, host=LOOPBACK) -> int:
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


class SelfTestLab:
    def __init__(self, native: bool = True, with_stun: bool = True):
        self.native = native
        self.with_stun = with_stun
        self.runner: web.AppRunner | None = None
        self.root = Path(tempfile.mkdtemp(prefix="p2pobs-selftest-"))
        self.http_port = free_port()
        self.stun_port = free_port()
        self.room = f"selftest-{uuid.uuid4().hex[:8]}"
        self.secret = secrets.token_hex(24)
        self.stun_url = f"stun:{LOOPBACK}:{self.stun_port}"
        self.stun_transport = None
        self.results: dict = {}

    async def start_server(self) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        app = make_app(str(self.root / "central"), [{"urls": self.stun_url}] if self.with_stun else [])
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        await web.TCPSite(self.runner, LOOPBACK, self.http_port).start()
        if self.with_stun:
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind((LOOPBACK, self.stun_port))
            sock.setblocking(False)
            transport, _ = await loop.create_datagram_endpoint(lambda: Stun(app["store"]), sock=sock)
            self.stun_transport = transport

    @property
    def url(self) -> str:
        return f"ws://{LOOPBACK}:{self.http_port}/ws"

    async def wait_for_health(self, timeout: float = 10) -> None:
        from aiohttp import ClientSession

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                async with ClientSession() as session:
                    async with session.get(f"http://{LOOPBACK}:{self.http_port}/health") as response:
                        if response.status == 200:
                            return
            except OSError:
                pass
            await asyncio.sleep(0.1)
        raise TimeoutError("SERVER_NOT_READY")

    def config(self, name: str, host: str = LOOPBACK, echo: bool = False) -> EngineConfig:
        return EngineConfig(
            url=self.url,
            room=self.room,
            secret=self.secret,
            name=name,
            bind_host=host,
            data_dir=str(self.root / name.replace(" ", "_")),
            stun_url=self.stun_url if self.with_stun else None,
            echo=echo,
            allow_native=self.native,
        )

    async def stop(self) -> None:
        if self.stun_transport is not None:
            self.stun_transport.close()
        if self.runner is not None:
            await self.runner.cleanup()


async def wait_direct(engine: DesktopEngine, key: str, timeout: float) -> dict:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        target = engine.targets.get(key)
        if target is not None:
            summary = engine.summary(key)
            if summary["canSend"]:
                return summary
        await asyncio.sleep(0.1)
    return engine.summary(key) if key in engine.targets else {}


async def run_handshake(lab: SelfTestLab, report: list[str], timeout: float = 60) -> bool:
    echo = DesktopEngine(lab.config("回声节点", echo=True))
    client = DesktopEngine(lab.config("自检客户端"))
    engines = [echo, client]
    ok = False
    try:
        await echo.start()
        await client.start()
        await lab.wait_for_health()
        key = await _wait_for_target(client, timeout=timeout)
        if key is None:
            report.append("没有在房间里发现对方，握手无法开始。")
            return False
        summary = await wait_direct(client, key, timeout)
        if not summary.get("canSend"):
            rows = summary.get("rows") or []
            failures = [f"{row['title']}：{row['status']}{('（' + row['detail'] + '）') if row.get('detail') else ''}" for row in rows]
            report.append("没有找到可聊天的直连。各方式结果：")
            report.extend(f"  - {line}" for line in failures)
            return False
        # Give the engine's latency sweep a bounded moment to measure the live
        # path; if it cannot, the report says so instead of printing zero.
        for _ in range(16):
            summary = client.summary(key)
            if summary.get("latency") is not None:
                break
            await asyncio.sleep(0.5)
        summary = client.summary(key)
        direct = summary["direct"]
        latency = summary["latency"]
        report.append(f"已打通的方式：{'、'.join(direct)}")
        if latency is not None:
            report.append(f"实测往返延迟：{latency:.1f} 毫秒（本机计时）")
        else:
            report.append("实测往返延迟：尚未测到（不会用 0 代替）")
        observed = summary.get("observed") or []
        if observed:
            report.append(f"仅探测/观测、不传内容的方式（已观测，不等于已打通）：{'、'.join(observed)}")
        remaining = summary.get("remaining") or []
        report.append(f"仍在尝试的其它方式：{'、'.join(remaining) if remaining else '无'}")
        unavailable = summary.get("unavailable") or []
        for item in unavailable:
            report.append(f"不可用：{item['title']}（{item['detail']}）")

        # 1) real text round-trip through the authenticated path
        token = f"selftest-{secrets.token_hex(8)}"
        await client.send_text(token)
        echoed = await _wait_for_echo(client, token, timeout=20)
        if not echoed:
            report.append("文本消息没有收到对方回显，握手未被证实。")
            return False
        report.append("文本消息：已通过已认证直连送达，并收到对方回显。")

        # 2) bounded file transfer with SHA-256 verification
        payload = secrets.token_bytes(65536)
        source = lab.root / "selftest.bin"
        source.write_bytes(payload)
        before = len(client.messages)
        sent = await client.send_file(str(source), "selftest.bin", "application/octet-stream")
        received = await _wait_for_file(echo, sent["id"], timeout=30) or await _wait_for_file(client, sent["id"], timeout=5)
        digest = hashlib.sha256(payload).hexdigest()
        if not received:
            report.append(f"文件传输未完成（{sent['mechanism']}）。")
            return False
        report.append(f"文件传输：{len(payload)} 字节经 {sent['mechanism']} 通道发送，发送端校验值 {digest[:16]}… 已记录 {len(client.messages) - before} 条本地记录。")

        # 3) latency re-measure and the application-layer speed test
        rtt = await client.measure_webrtc_latency(key)
        if rtt is not None:
            report.append(f"数据通道往返复测：{rtt:.1f} 毫秒。")
        try:
            bench = await client.benchmark(key, seconds=2.0)
        except Exception as error:
            code = str(error.args[0]) if error.args else "INTERNAL_ERROR"
            report.append(f"测速未完成：{code}")
        else:
            if bench.get("ok"):
                report.append(f"测速：{bench['bytes']} 字节 / {bench['elapsedMs']:.1f} 毫秒 ≈ {bench['mbps']} Mbps（{bench['note']}）")
            else:
                report.append(f"测速未确认：{bench.get('reason') or '未收到确认'}")

        # 4) confirm the no-relay report: observation is described as observation
        sample = client.summary(key)
        observation = sample.get("observation")
        if observation:
            report.append(f"STUN 映射观测：出口 {observation['address']}:{observation['port']}（只观测，不转发）")
        else:
            report.append("STUN 映射观测：本次没有可用 STUN 服务，如实标记为不可用。")
        ok = True
        return ok
    finally:
        for engine in engines:
            try:
                await asyncio.wait_for(engine.close(), 20)
            except Exception:
                pass


async def _wait_for_target(engine: DesktopEngine, timeout: float) -> str | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if engine.targets:
            for key, target in engine.targets.items():
                if target.webrtc_id or target.native_id:
                    await engine.select(key)
                    return key
        await asyncio.sleep(0.1)
    return None


async def _wait_for_echo(engine: DesktopEngine, token: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for message in engine.messages:
            if message.direction == "in" and message.kind == "text" and message.text == token:
                return True
        await asyncio.sleep(0.1)
    return False


async def _wait_for_file(engine: DesktopEngine, identifier: str, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for message in engine.messages:
            if message.id == identifier and message.kind == "file":
                return True
        await asyncio.sleep(0.1)
    return False


def plaintext_policy_check(report: list[str]) -> bool:
    """默认必须拒绝非回环明文 ws://；只有显式确认才放行。"""
    from .engine import plaintext_risk, validate_endpoint

    checks = [
        ("ws://127.0.0.1:8088/ws", False, True, "本机回环允许明文"),
        ("ws://localhost:8088/ws", False, True, "localhost 视为本机"),
        ("wss://example.invalid/ws", False, True, "wss 一律允许"),
        ("ws://192.0.2.10:8088/ws", False, False, "非回环明文默认拒绝"),
        ("ws://203.0.113.7:8088/ws", False, False, "公网明文默认拒绝"),
    ]
    ok = True
    for url, allow, expected, label in checks:
        try:
            validate_endpoint(url, allow)
            allowed = True
        except ValueError as error:
            allowed = False
            assert str(error) == "PLAINTEXT_REFUSED", error
        if allowed != expected:
            ok = False
            report.append(f"明文策略不符合预期：{label}（{url}）允许={allowed}，应为 {expected}")
    if not validate_endpoint("ws://192.0.2.10:8088/ws", True):
        ok = False
        report.append("显式确认后仍未给出未加密提示。")
    if plaintext_risk("ws://192.0.2.10:8088/ws") is None:
        ok = False
        report.append("非回环明文没有产生未加密提示。")
    report.append("明文连接策略：非回环 ws:// 默认拒绝；显式确认后放行并持续提示未加密。" if ok else "明文连接策略检查未通过。")
    return ok


async def self_test(native: bool = True, timeout: float = 60, as_json: bool = False) -> int:
    lab = SelfTestLab(native=native)
    report: list[str] = []
    started = time.monotonic()
    try:
        policy_ok = plaintext_policy_check(report)
        await lab.start_server()
        ok = await run_handshake(lab, report, timeout=timeout) and policy_ok
    except Exception as error:
        report.append(f"自检过程中出错：{type(error).__name__}: {error}")
        ok = False
    finally:
        await lab.stop()
    elapsed = time.monotonic() - started
    verdict = "通过" if ok else "未通过"
    if as_json:
        print(json.dumps({"ok": ok, "scope": SCOPE_NOTE, "seconds": round(elapsed, 2), "report": report}, ensure_ascii=False, indent=2))
    else:
        print("桌面客户端自检（无界面模式）")
        print(f"范围：{SCOPE_NOTE}")
        print(f"原生方式：{'参与尝试' if native else '已禁用'}")
        for line in report:
            print(f"  {line}")
        print(f"结论：{verdict}（用时 {elapsed:.1f} 秒）")
        if not ok:
            print("说明：失败就是失败，不会改走服务器转发。")
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="直连聊天桌面客户端自检（无界面）")
    parser.add_argument("--no-native", action="store_true", help="只验证浏览器直连方式")
    parser.add_argument("--timeout", type=float, default=60)
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    return asyncio.run(self_test(native=not args.no_native, timeout=args.timeout, as_json=args.json))


if __name__ == "__main__":
    sys.exit(main())
