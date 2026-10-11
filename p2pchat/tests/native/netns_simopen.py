"""Authorized isolated positive simultaneous-open experiment; no host route/firewall changes.
Run: unshare -Urn .venv/bin/python p2pchat/tests/native/netns_simopen.py
Two child network namespaces + veth, 80ms queue delay models network propagation
so both active-open SYNs are outstanding. NO listening sockets / RST suppression.
"""
import asyncio
import base64
import hashlib
import json
import os
import subprocess
import sys
import uuid


def run(*args):
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f"{' '.join(args)}: {result.returncode}: {result.stderr.strip()}")
    return result.stdout


async def main():
    # Safety assertion: refuse initial host namespace, including accidental direct invocation.
    from pathlib import Path
    uid_map = Path('/proc/self/uid_map').read_text().split()
    if len(uid_map) != 3 or uid_map[0] != '0' or uid_map[1] == '0' or uid_map[2] != '1':
        raise RuntimeError("ISOLATED_USER_NAMESPACE_REQUIRED")
    # unshare -Ur without -n cannot gain CAP_NET_ADMIN over the host netns;
    # kernel ownership further prevents accidental host interface mutation.
    workers = []
    try:
        for ip in ["10.231.0.1", "10.231.0.2"]:
            worker = await asyncio.create_subprocess_exec("unshare", "-n", sys.executable, "-m", "p2pchat.native.bridge", "--bind", ip,
                stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, limit=131072)
            workers.append(worker)
        # Wait for unshare exec completion using a bounded namespace-identity check.
        async with asyncio.timeout(3):
            for w in workers:
                while os.readlink(f'/proc/{w.pid}/ns/net') == os.readlink('/proc/self/ns/net'):
                    await asyncio.sleep(.01)
        run("ip", "link", "add", "obs-a", "type", "veth", "peer", "name", "obs-b")
        for w, name, ip in zip(workers, ["obs-a", "obs-b"], ["10.231.0.1", "10.231.0.2"]):
            run("ip", "link", "set", name, "netns", str(w.pid))
            prefix = ("nsenter", "-t", str(w.pid), "-n")
            run(*prefix, "ip", "link", "set", "lo", "up")
            run(*prefix, "ip", "addr", "add", ip + "/24", "dev", name)
            run(*prefix, "ip", "link", "set", name, "up")
            run(*prefix, "tc", "qdisc", "add", "dev", name, "root", "netem", "delay", "80ms")
        # Prewarm neighbor caches before opening the sockets.
        run("nsenter", "-t", str(workers[0].pid), "-n", "ping", "-c", "1", "-W", "2", "10.231.0.2")
        cid, aid = str(uuid.uuid4()), str(uuid.uuid4())
        async def write(w, ident, method, params):
            w.stdin.write((json.dumps(dict(v=1, id=ident, method=method, params=params))+"\n").encode())
            await w.stdin.drain()
        async def until_response(w, ident):
            events = []
            async with asyncio.timeout(10):
                while True:
                    line = await w.stdout.readline()
                    if not line:
                        raise RuntimeError("SIDECAR_EXIT")
                    frame = json.loads(line)
                    if frame.get("id") == ident:
                        if "error" in frame:
                            raise RuntimeError(frame["error"])
                        return frame["result"], events
                    events.append(frame)
        for i, w in enumerate(workers):
            await write(w, 1, "start", dict(connectionId=cid, attemptId=aid, peerId="b" if i == 0 else "a",
                mechanism="tcp-simopen", profile="direct", role="offerer" if i == 0 else "answerer", timeoutMs=10000,
                auth=dict(room="isolated", localPeerId="a" if i == 0 else "b", secret="isolated-test-secret")))
        initial = await asyncio.gather(*(until_response(w, 1) for w in workers))
        candidates = [[f["params"] for f in events if f.get("event") == "candidate"] for _, events in initial]
        for i, w in enumerate(workers):
            for seq, candidate in enumerate(candidates[1-i]):
                await write(w, 2+seq, "signal", dict(**candidate, **{"from": "b" if i == 0 else "a"}))
        observed = [[], []]
        async def direct(i, w):
            async with asyncio.timeout(15):
                while True:
                    frame = json.loads(await w.stdout.readline())
                    observed[i].append(frame)
                    if frame.get("event") == "state":
                        state = frame["params"]["state"]
                        if state == "direct":
                            return frame["params"]
                        if state in {"failed", "timeout"}:
                            raise RuntimeError(frame["params"])
        states = await asyncio.gather(*(direct(i, w) for i, w in enumerate(workers)))
        payload = os.urandom(65536)
        for w in workers:
            await write(w, 8, "send", dict(attemptId=aid, lane="chat", dataB64=base64.b64encode(payload).decode()))
        async def received(w):
            async with asyncio.timeout(10):
                while True:
                    frame = json.loads(await w.stdout.readline())
                    if frame.get("event") == "data":
                        data = base64.b64decode(frame["params"]["dataB64"])
                        assert hashlib.sha256(data).digest() == hashlib.sha256(payload).digest()
                        return len(data)
        sizes = await asyncio.gather(*(received(w) for w in workers))
        print(json.dumps({"scope": "isolated-user-netns-veth", "delayMs": 80, "mechanism": "tcp-simopen",
                          "listeningFallback": False, "states": states, "verifiedBytesEachDirection": sizes}))
    finally:
        for w in workers:
            if w.stdin:
                w.stdin.close()
            try:
                await asyncio.wait_for(w.wait(), 3)
            except asyncio.TimeoutError:
                w.kill()
                await w.wait()


if __name__ == "__main__":
    asyncio.run(main())
