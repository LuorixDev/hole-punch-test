import asyncio
import base64
import hashlib
import json
import os
import socket
import sys
import uuid

import pytest
from p2pchat.native.adapter import Budget, NativeAdapter, validate_candidate
from p2pchat.native.auth import Auth


def params(mechanism, role, cid, aid):
    local, remote = ("a", "b") if role == "offerer" else ("b", "a")
    return dict(connectionId=cid, attemptId=aid, peerId=remote, mechanism=mechanism,
                profile="loopback-test", role=role, timeoutMs=3000,
                auth=dict(room="test", localPeerId=local, secret="test-secret-128-bit"))


# --------------------------------------------------------------- native CLI I/O
#
# The native CLI speaks JSON-lines over pipes. On Windows a piped stdout uses the
# ANSI code page (cp1252/cp936), which cannot encode the capability text, and the
# bridge's writer used to die silently: the parent then saw *no* output at all.
# One explicit UTF-8 contract for both ends is the cross-platform fix; a missing or
# empty stream is reported as a failure with context instead of crashing on None.

CLI_ENCODING = "utf-8"


def cli_env():
    """Force UTF-8 stdio for the child on every platform (never the ANSI code page)."""
    return {**os.environ, "PYTHONIOENCODING": CLI_ENCODING, "PYTHONUTF8": "1"}


def run_bridge(args=(), requests=()):
    import subprocess

    payload = "".join(json.dumps(request) + "\n" for request in requests)
    return subprocess.run([sys.executable, "-m", "p2pchat.native.bridge", *args],
                          input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          encoding=CLI_ENCODING, env=cli_env(), timeout=30)


def bridge_frames(result):
    """Decoded JSON-lines frames; fails loudly when the CLI produced nothing."""
    assert result.returncode == 0, (result.returncode, result.stderr)
    assert result.stdout is not None, f"原生 CLI 没有 stdout（返回码 {result.returncode}）"
    assert result.stdout.strip(), (f"原生 CLI 没有产出任何输出（返回码 {result.returncode}，"
                                   f"stderr={result.stderr!r}）")
    return [json.loads(line) for line in result.stdout.splitlines() if line.strip()]


async def pair(mechanism, host="127.0.0.1", bad_secret=False, budget=None):
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    a, b = NativeAdapter(host, budget=budget), NativeAdapter(host, budget=budget)
    events_a, events_b = [], []
    a.subscribe(lambda kind, data: events_a.append((kind, data)))
    b.subscribe(lambda kind, data: events_b.append((kind, data)))
    await a.start(params(mechanism, "offerer", cid, aid))
    p = params(mechanism, "answerer", cid, aid)
    if bad_secret:
        p["auth"]["secret"] = "different-secret"
    await b.start(p)
    for target, events, sender in [(a, events_b, "b"), (b, events_a, "a")]:
        for kind, event in list(events):
            if kind == "candidate":
                await target.signal({**event, "from": sender})
    return a, b, aid, events_a, events_b


async def wait_states(a, b, aid, timeout=5):
    async with asyncio.timeout(timeout):
        while True:
            states = [(await x.stats({"attemptId": aid}))["state"] for x in [a, b]]
            if all(s in {"direct", "failed", "timeout", "unsupported"} for s in states):
                return states
            await asyncio.sleep(.02)


@pytest.mark.asyncio
@pytest.mark.parametrize("mechanism", ["udp-probe", "quic", "tcp", "tcp-simopen"])
@pytest.mark.parametrize("host", ["127.0.0.1", "::1"])
async def test_two_endpoint_integrity(mechanism, host):
    a, b, aid, ea, eb = await pair(mechanism, host)
    try:
        states = await wait_states(a, b, aid)
        if mechanism == "tcp-simopen" and states != ["direct", "direct"]:
            # Zero-delay loopback may reset before the other active-open. Real
            # success is a separate namespace test with modeled propagation.
            assert states == ["failed", "failed"]
            for x in [a, b]:
                assert (await x.stats({"attemptId": aid}))["failureCode"] == "TCP_SIMOPEN_UNAVAILABLE"
            return
        assert states == ["direct", "direct"], [(await x.stats({"attemptId": aid})) for x in [a, b]]
        if mechanism == "udp-probe":
            with pytest.raises(ValueError, match="NOT_MESSAGE_CAPABLE"):
                await a.send(dict(attemptId=aid, lane="chat", data=b"no plaintext chat"))
            return
        payload = os.urandom(65536)
        for src in [a, b]:
            await src.send(dict(attemptId=aid, lane="chat", data=payload))
        async with asyncio.timeout(3):
            while not all(any(kind == "data" for kind, _ in events) for events in [ea, eb]):
                await asyncio.sleep(.01)
        for events in [ea, eb]:
            data = next(e for k, e in events if k == "data")
            assert hashlib.sha256(base64.b64decode(data["dataB64"])).digest() == hashlib.sha256(payload).digest()
        if mechanism == "quic":
            for x in [a, b]:
                candidate = x.attempts[aid].candidate
                assert candidate["port"] == x.attempts[aid].sock.getsockname()[1]
                assert x.attempts[aid].quic.configuration.verify_mode != 0
            await a.send(dict(attemptId=aid, lane="benchmark", data=b"separate stream"))
        else:
            with pytest.raises(ValueError, match="BENCHMARK_UNSUPPORTED"):
                await a.send(dict(attemptId=aid, lane="benchmark", data=b"busy"))
    finally:
        await a.shutdown()
        await b.shutdown()
    assert not a.attempts and not b.attempts


@pytest.mark.asyncio
async def test_bad_auth_never_direct():
    a, b, aid, ea, eb = await pair("udp-probe", bad_secret=True)
    try:
        assert await wait_states(a, b, aid) == ["timeout", "timeout"]
    finally:
        await a.shutdown()
        await b.shutdown()


def test_nonce_binding_and_candidate_validation():
    a = Auth("room", "secret", "c", "a", "one", "two")
    b = Auth("room", "secret", "c", "a", "two", "one")
    response = b.receive(a.frame())
    a.receive(b.frame())
    a.receive(response)
    assert a.direct
    b.nonce = "0" * 64
    with pytest.raises(ValueError, match="NONCE_REPLAY"):
        a.receive(b.frame())
    for address in ["224.0.0.1", "255.255.255.255", "0.0.0.0", "169.254.1.2"]:
        with pytest.raises(ValueError):
            validate_candidate(dict(id="x", family=4, transport="udp", address=address, port=1, kind="host", socketId="x"))


@pytest.mark.asyncio
async def test_close_network_change_and_replay():
    a, b, aid, _, _ = await pair("quic")
    try:
        assert await wait_states(a, b, aid) == ["direct", "direct"]
        await a.network_changed()
        assert not a.attempts
        with pytest.raises(ValueError, match="ATTEMPT_REPLAY"):
            await a.start(params("quic", "offerer", str(uuid.uuid4()), aid))
    finally:
        await a.shutdown()
        await b.shutdown()


def test_stdio_subprocess():
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    requests = [dict(v=1, id=1, method="capabilities", params={}),
                dict(v=1, id=2, method="start", params=params("unknown", "offerer", cid, aid)),
                dict(v=1, id=3, method="execute", params={})]
    result = run_bridge(requests=requests)
    frames = bridge_frames(result)
    assert [f["id"] for f in frames if "id" in f] == [1, 2, 3]
    assert any(f.get("event") == "state" and f["params"]["state"] == "unsupported" for f in frames)
    assert frames[-1]["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert "test-secret" not in result.stdout + result.stderr
    # 能力文案含中文：必须原样往返。Windows 代码页无法编码它时，桥的写端曾静默死掉，
    # 父进程一个字节都拿不到（本测试现在会以“没有产出”明确失败，而不是 None 崩溃）。
    capability = next(f for f in frames if f.get("id") == 1)["result"]
    note = (capability.get("prediction") or {}).get("hitRateNote", "")
    assert note, "能力报告必须包含人话说明"
    assert not note.isascii(), "中文说明必须原样往返，不能被代码页吞掉"


@pytest.mark.asyncio
async def test_quic_burst_is_not_aborted_by_a_momentary_full_buffer():
    """Same burst/budget that b56f507 aborted with BACKPRESSURE after one frame.

    No caller-side sleep: the adapter itself must wait (boundedly) for ACK-driven
    drain. Linux loopback ACKs between awaits; Windows needs the wait.
    """
    budget = Budget(queued_bytes=16 * 1024, drain_timeout=2.0)
    a, b, aid, _, _ = await pair("quic", budget=budget)
    try:
        assert await wait_states(a, b, aid) == ["direct", "direct"]
        for _ in range(8):
            await a.send(dict(attemptId=aid, lane="chat", data=b"x" * 8192))
        assert (await a.stats({"attemptId": aid}))["txBytes"] >= 8 * 8192
    finally:
        await a.shutdown()
        await b.shutdown()


@pytest.mark.asyncio
async def test_quic_send_waits_for_drain_and_fails_bounded_when_acks_stop(monkeypatch):
    """A momentarily full QUIC buffer waits for the peer; a silent peer still fails loudly."""
    from p2pchat.native import adapter as adapter_module

    budget = Budget(queued_bytes=16 * 1024, drain_timeout=1.0)
    a, b, aid, _, _ = await pair("quic", budget=budget)
    try:
        assert await wait_states(a, b, aid) == ["direct", "direct"]
        stall, gate = {"on": True}, asyncio.Event()
        real = adapter_module.receive_udp_retry

        async def slow_peer(sock, limit):
            if stall["on"] and sock is b.attempts[aid].sock:
                await gate.wait()  # peer stops reading: no ACKs, exactly the Windows symptom
            return await real(sock, limit)

        monkeypatch.setattr(adapter_module, "receive_udp_retry", slow_peer)
        started = asyncio.get_running_loop().time()
        with pytest.raises(ValueError, match="BACKPRESSURE"):
            for _ in range(32):
                await a.send(dict(attemptId=aid, lane="chat", data=b"x" * 8192))
        waited = asyncio.get_running_loop().time() - started
        assert waited >= 0.5, f"必须先有界等待再失败，而不是立刻抛错（{waited:.3f}s）"
        assert waited < 10, f"等待必须有界（{waited:.3f}s）"

        stall["on"] = False
        gate.set()  # peer resumes: drain is ACK-driven, so the next send must go through
        async with asyncio.timeout(5):
            while await a.attempts[aid].quic_pending_bytes() > 0:
                await asyncio.sleep(.01)
        await a.send(dict(attemptId=aid, lane="chat", data=b"y" * 8192))
    finally:
        await a.shutdown()
        await b.shutdown()
