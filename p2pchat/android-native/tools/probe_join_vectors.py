#!/usr/bin/env python3
"""加入证明 v2 的测试向量：**独立实现一遍 HKDF + HMAC**，再和 Kotlin 里的常量对比。

kotlin 侧 `JoinProof.SELF_CHECK_VECTORS` 在应用启动时自检；这个脚本在构建机上再独立算一次，
两边不一致就说明算法/分隔符/域分隔串有人改了（例如把 info 写成别的字符串）。

只用标准库（hashlib/hmac），不依赖 cryptography：这样向量本身就是对实现的独立复核。
"""
from __future__ import annotations

import hashlib
import hmac
import re
import sys
from pathlib import Path

JOIN_KEY_INFO = b"p2pchat/join-key/v2"
KOTLIN = Path(__file__).resolve().parents[1] / "app/src/main/java/dev/p2pobservatory/nativeprobe/JoinProof.kt"
SERVER = Path(__file__).resolve().parents[2] / "server.py"


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()[:length]


def join_key_hex(secret: str, room: str) -> str:
    return hkdf_sha256(secret.encode(), room.encode(), JOIN_KEY_INFO).hex()


def join_proof_hex(join_key: bytes, room: str, nonce: str, session: str) -> str:
    return hmac.new(join_key, (room + "\0" + nonce + "\0" + session).encode(), hashlib.sha256).hexdigest()


def kotlin_vectors(text: str) -> list[dict[str, str]]:
    pattern = re.compile(
        r'Vector\(\s*secret = "([^"]*)",\s*room = "([^"]*)",\s*nonce = "([^"]*)",\s*session = "([^"]*)",'
        r'\s*joinKeyHex = "([0-9a-f]{64})",\s*proofHex = "([0-9a-f]{64})",',
        re.MULTILINE | re.DOTALL)
    return [dict(zip(("secret", "room", "nonce", "session", "joinKeyHex", "proofHex"), m.groups()))
            for m in pattern.finditer(text)]


def main() -> int:
    # 1) Kotlin 里的常量必须和服务端声明的算法/域分隔串一致
    server = SERVER.read_text(encoding="utf-8")
    info = re.search(r"JOIN_KEY_INFO\s*=\s*b'([^']+)'", server)
    if not info or info.group(1).encode() != JOIN_KEY_INFO:
        print(f"FAIL join-key-info mismatch: server={info.group(1) if info else None} kotlin={JOIN_KEY_INFO!r}")
        return 1
    print(f"OK  server JOIN_KEY_INFO == kotlin info == {JOIN_KEY_INFO.decode()}")

    kotlin = KOTLIN.read_text(encoding="utf-8")
    vectors = kotlin_vectors(kotlin)
    if not vectors:
        print("FAIL no vectors found in JoinProof.kt")
        return 1

    failures = 0
    for vector in vectors:
        key = join_key_hex(vector["secret"], vector["room"])
        proof = join_proof_hex(bytes.fromhex(key), vector["room"], vector["nonce"], vector["session"])
        if key != vector["joinKeyHex"]:
            print(f"FAIL joinKey room={vector['room']} script={key} kotlin={vector['joinKeyHex']}")
            failures += 1
        elif proof != vector["proofHex"]:
            print(f"FAIL proof room={vector['room']} script={proof} kotlin={vector['proofHex']}")
            failures += 1
        else:
            print(f"OK  vector room={vector['room']} joinKey={key[:16]}… proof={proof[:16]}…")
    print(f"JOIN_VECTORS checked={len(vectors)} failures={failures}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
