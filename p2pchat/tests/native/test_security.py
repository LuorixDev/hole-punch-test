import asyncio
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid
import pytest
from p2pchat.native.adapter import NativeAdapter, Budget, certificate
from cryptography.hazmat.primitives import serialization
from .test_transport import pair, wait_states, params


@pytest.mark.asyncio
async def test_parallel_paths_remain_independent_and_bounded():
    pairs = await asyncio.gather(*(pair(m) for m in ["udp-probe", "quic", "tcp"]))
    try:
        states = await asyncio.gather(*(wait_states(a, b, aid) for a, b, aid, _, _ in pairs))
        assert states == [["direct", "direct"]] * 3
        assert len({aid for _, _, aid, _, _ in pairs}) == 3
        await pairs[0][0].shutdown()
        for a, b, aid, _, _ in pairs[1:]:
            assert (await a.stats({"attemptId": aid}))["state"] == "direct"
        a = pairs[1][0]
        aid = pairs[1][2]
        a.budget.queued_bytes = 2
        with pytest.raises(ValueError, match="BACKPRESSURE"):
            await a.send(dict(attemptId=aid, lane="chat", data=b"larger"))
    finally:
        for a, b, *_ in pairs:
            await a.shutdown()
            await b.shutdown()
    constrained = NativeAdapter(budget=Budget(attempts=0))
    with pytest.raises(ValueError, match="RESOURCE_LIMIT"):
        await constrained.start(params("tcp", "offerer", str(uuid.uuid4()), str(uuid.uuid4())))


@pytest.mark.asyncio
async def test_certificate_tampering_and_wrong_signal_identity():
    a = NativeAdapter()
    cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
    await a.start(params("quic", "offerer", cid, aid))
    key, cert = certificate()
    candidate = dict(a.attempts[aid].candidate)
    candidate["certificateFingerprint"] = "0" * 64
    try:
        with pytest.raises(ValueError, match="SIGNAL_IDENTITY_MISMATCH"):
            await a.signal(dict(connectionId=cid, attemptId=aid, **{"from": "evil"}, nativeCandidate=candidate))
        await a.signal(dict(connectionId=cid, attemptId=aid, **{"from": "b"}, nativeCandidate=candidate))
        with pytest.raises(ValueError, match="CERTIFICATE_FINGERPRINT_MISMATCH"):
            await a.signal(dict(connectionId=cid, attemptId=aid, **{"from": "b"},
                description=dict(type="answer", sdp=cert.public_bytes(serialization.Encoding.PEM).decode())))
        assert a.attempts[aid].state != "direct"
    finally:
        await a.shutdown()


@pytest.mark.asyncio
async def test_quic_rejects_wrong_presented_client_certificate():
    a, b, aid, _, _ = await pair("quic")
    # Signal has passed; simulate a mismatched expected server-side peer pin.
    # UDP shared-key proof alone MUST NOT bypass actual TLS certificate binding.
    b.attempts[aid].remote_candidate["certificateFingerprint"] = "0" * 64
    try:
        async with asyncio.timeout(5):
            while b.attempts[aid].state not in {"failed", "timeout"}:
                await asyncio.sleep(.01)
        assert b.attempts[aid].failure == "CERTIFICATE_FINGERPRINT_MISMATCH"
    finally:
        await a.shutdown()
        await b.shutdown()


@pytest.mark.asyncio
async def test_scheduler_parallel_network_rebuild():
    from p2pchat.native.scheduler import Discovery
    adapter = NativeAdapter()
    discovery = Discovery(adapter)
    cid = str(uuid.uuid4())
    requests = [params(method, "offerer", cid, str(uuid.uuid4())) for method in ["udp-probe", "quic", "tcp"]]
    old_ids = {p["attemptId"] for p in requests}
    announcements = []
    async def announce(request, retry):
        announcements.append((request["attemptId"], retry))
    try:
        result = await discovery.start_all(requests)
        assert len(result) == 3
        await discovery.network_changed("::1", announce)
        assert len(announcements) == 3
        assert old_ids.isdisjoint(adapter.attempts)
        assert all(a.candidate["family"] == 6 for a in adapter.attempts.values())
    finally:
        await discovery.close()
    assert not discovery.starts and not adapter.attempts


def test_stdio_malformed_and_oversize():
    for data in ["not json\n", "x" * 131073 + "\n"]:
        result = subprocess.run([sys.executable, "-m", "p2pchat.native.bridge"], input=data,
                                text=True, encoding="utf-8", capture_output=True, timeout=10)
        assert result.returncode == 0
        output = json.loads(result.stdout)
        assert output["error"]["code"] in {"LINE_LIMIT", "INVALID_REQUEST"}
        assert len(result.stdout) < 256


def test_isolated_simultaneous_open_positive():
    if sys.platform != "linux" or any(shutil.which(tool) is None for tool in ["unshare", "nsenter", "ip", "tc", "ping"]):
        pytest.skip("isolated netns tooling unavailable; not simultaneous-open positive evidence")
    check = subprocess.run(["unshare", "-Urn", "true"], capture_output=True)
    if check.returncode:
        pytest.skip("user/network namespaces forbidden; not simultaneous-open positive evidence")
    script = Path(__file__).with_name("netns_simopen.py")
    result = subprocess.run(["unshare", "-Urn", sys.executable, str(script)], capture_output=True, text=True, encoding="utf-8", timeout=40)
    assert result.returncode == 0, result.stderr
    evidence = json.loads(result.stdout)
    assert evidence["listeningFallback"] is False
    assert evidence["verifiedBytesEachDirection"] == [65536, 65536]
    assert [s["state"] for s in evidence["states"]] == ["direct", "direct"]
