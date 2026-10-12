#!/usr/bin/env python3
"""对**真实 p2pchat.server** 做一次 v2 加入（算法与 Kotlin `JoinProof.kt` 完全同一套）。

为什么要这个：本机跑不了 Kotlin（JDK 25 / 无 Android SDK），但「加不进房间」这个风险点可以用
协议层证据覆盖 —— 用 Kotlin 里同一套 HKDF/HMAC/字段名/分隔符去加入真实服务器：

  1) 起一个真的 `p2pchat.server`（127.0.0.1，随机端口，临时数据目录）；
  2) POST `/signal/join/challenge` 拿一次性 nonce；
  3) 用 `joinKey = HKDF-SHA256(secret, salt=room, info=<从 JoinProof.kt 读到的 info>)` 与
     `proof = HMAC-SHA256(joinKey, room\\0nonce\\0clientSessionId)` 构造 join 报文（带 verifier）；
  4) 断言服务器接受、报文里**没有** `secret` 字段；再复用同一个 nonce 重放一次，断言被拒（一次性生效）。

诚实边界：这是**协议层**证据（Python 重实现同一算法），不是 Kotlin 二进制在真机上的运行证据。
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]  # 仓库根
KOTLIN = Path(__file__).resolve().parents[1] / "app/src/main/java/dev/p2pobservatory/nativeprobe/JoinProof.kt"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def kotlin_info() -> bytes:
    text = KOTLIN.read_text(encoding="utf-8")
    match = re.search(r'INFO = "([^"]+)"\.toByteArray', text)
    version = re.search(r"JOIN_VERSION = (\d+)", text)
    if not match or not version or version.group(1) != "2":
        raise SystemExit("FAIL cannot read join info/version from JoinProof.kt")
    return match.group(1).encode()


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def post(url: str, payload: dict, origin: str) -> tuple[int, dict]:
    body = json.dumps(payload, ensure_ascii=False).encode()
    request = urllib.request.Request(url, data=body, headers={
        "Content-Type": "application/json", "Origin": origin})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, json.loads(response.read().decode() or "{}")
    except urllib.error.HTTPError as error:  # type: ignore[attr-defined]
        body = error.read().decode(errors="replace")
        try:
            return error.code, json.loads(body or "{}")
        except json.JSONDecodeError:
            return error.code, {"raw": body[:400]}


def main() -> int:
    info = kotlin_info()
    port = free_port()
    base = f"http://127.0.0.1:{port}"
    origin = f"http://127.0.0.1:{port}"
    data_dir = Path(os.environ.get("TMPDIR", "/tmp")) / f"t46-join-{os.getpid()}"
    data_dir.mkdir(parents=True, exist_ok=True)
    server = subprocess.Popen(
        [sys.executable, "-m", "p2pchat.server", "--host", "127.0.0.1", "--port", str(port),
         "--data", str(data_dir), "--stun-port", str(free_port())],
        cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    try:
        deadline = time.time() + 25
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{base}/health", timeout=2) as response:
                    if response.status == 200:
                        break
            except Exception:
                time.sleep(0.3)
        else:
            print("FAIL server did not become healthy")
            return 1

        room, secret = "测试房间", "correct horse battery staple"
        session = "7f3c1d5e-9a2b-4c6d-8e0f-1234567890ab"
        status, challenge = post(f"{base}/signal/join/challenge",
                                 {"v": 1, "type": "join_challenge", "room": room, "clientSessionId": session}, origin)
        nonce = challenge.get("nonce", "")
        print(f"challenge status={status} nonce_len={len(nonce)}")
        if status != 200 or len(nonce) != 48:
            print(f"FAIL no usable nonce: {challenge}")
            return 1

        join_key = hkdf_sha256(secret.encode(), room.encode(), info)
        proof = hmac.new(join_key, (room + "\0" + nonce + "\0" + session).encode(), hashlib.sha256).hexdigest()
        message = {"v": 1, "type": "join", "joinVersion": 2, "room": room, "name": "android-probe",
                   "clientSessionId": session, "capabilities": ["webrtc"],
                   "nonce": nonce, "proof": proof, "verifier": join_key.hex()}
        if "secret" in json.dumps(message):
            print("FAIL join message mentions secret")
            return 1
        status, reply = post(f"{base}/signal/join", message, origin)
        print(f"join status={status} reply={json.dumps(reply, ensure_ascii=False)[:160]}")
        accepted = status in (200, 201) and reply.get("type") != "error"
        if not accepted:
            print("FAIL real server rejected the v2 join")
            return 1
        status, replay = post(f"{base}/signal/join", message, origin)
        replayed = status >= 400 or replay.get("type") == "error"
        print(f"replay status={status} rejected={replayed} code={replay.get('code')}")
        print(f"NATIVE_JOIN_PROBE accepted=true replay_rejected={replayed}")
        return 0 if replayed else 1
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()


if __name__ == "__main__":
    sys.exit(main())
