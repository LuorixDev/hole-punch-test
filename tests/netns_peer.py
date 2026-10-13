"""Internal worker for the isolated, simulated IPv6 CPE test; not a deployment client."""

import asyncio
import json
import sys
from pathlib import Path

from p2plab.client import Client
from p2plab.udp import UdpAttempt


async def run(directory, name, mode):
    root = Path(directory)
    other = "b" if name == "a" else "a"
    addresses = {"a": "2001:db8:a::2", "b": "2001:db8:b::2"}
    client = Client(
        {
            "data_dir": str(root / name),
            "experiment": {"timeout": 3, "gateway": False, "diagnostics": False, "stun": []},
        },
        "namespace",
        console=False,
    )
    client.peer_id = {
        "a": "00000000-0000-0000-0000-000000000001",
        "b": "00000000-0000-0000-0000-000000000002",
    }[name]
    client.pair = "00000000-0000-0000-0000-000000000003"
    temporary = root / (name + ".tmp")
    temporary.write_text(
        json.dumps(
            {
                "id": client.peer_id,
                "name": name,
                "public": client.identity.public,
                "certificate": client.identity.cert_pem,
            }
        )
    )
    temporary.replace(root / (name + ".json"))
    try:
        async with asyncio.timeout(5):
            while not (root / (other + ".json")).exists():
                await asyncio.sleep(0.02)
        client.peer = json.loads((root / (other + ".json")).read_text())
        spec = {
            "attempt": "isolated-cpe-" + mode,
            "profile": "balanced",
            "bind_port": 9999,
            "initiator": name == "a",
        }
        udp = UdpAttempt(client, spec, addresses[name])
        try:
            await udp.open()
            udp.set_candidates([[addresses[other], 9999]])
            try:
                await udp.punch(3)
                evidence = await udp.mtu()
                report = {"peer": name, "state": "authenticated", "mtu": evidence}
            except TimeoutError:
                report = {"peer": name, "state": "timeout-not-authenticated"}
            (root / (name + "-result.json")).write_text(json.dumps(report))
        finally:
            await udp.close()
    finally:
        client.identity.close()
        client.log.close()


if __name__ == "__main__":
    asyncio.run(run(*sys.argv[1:]))
