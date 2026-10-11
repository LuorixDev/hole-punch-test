import asyncio
import base64
import hashlib
import json
import os
import socket
import sys
import uuid

import pytest
from p2pchat.native.adapter import NativeAdapter, validate_candidate
from p2pchat.native.auth import Auth


def params(mechanism, role, cid, aid):
    local, remote = ("a", "b") if role == "offerer" else ("b", "a")
    return dict(connectionId=cid, attemptId=aid, peerId=remote, mechanism=mechanism,
                profile="loopback-test", role=role, timeoutMs=3000,
                auth=dict(room="test", localPeerId=local, secret="test-secret-128-bit"))


async def pair(mechanism, host="127.0.0.1", bad_secret=False):
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    a, b = NativeAdapter(host), NativeAdapter(host)
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
    import subprocess
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    requests = [dict(v=1, id=1, method="capabilities", params={}),
                dict(v=1, id=2, method="start", params=params("unknown", "offerer", cid, aid)),
                dict(v=1, id=3, method="execute", params={})]
    result = subprocess.run([sys.executable, "-m", "p2pchat.native.bridge"],
                            input="\n".join(json.dumps(r) for r in requests)+"\n", capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    frames = [json.loads(line) for line in result.stdout.splitlines()]
    assert [f["id"] for f in frames if "id" in f] == [1, 2, 3]
    assert any(f.get("event") == "state" and f["params"]["state"] == "unsupported" for f in frames)
    assert frames[-1]["error"]["code"] == "METHOD_NOT_ALLOWED"
    assert "test-secret" not in result.stdout + result.stderr
