"""Run only inside unshare -Urn. No host network/firewall configuration is modified."""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def run():
    if os.geteuid() != 0 or len(sys.argv) != 2 or os.readlink("/proc/self/ns/net") == sys.argv[1]:
        raise RuntimeError("ISOLATED_USER_AND_NETWORK_NAMESPACE_REQUIRED")
    keepers = {}

    def command(args, namespace=None, text=None):
        prefix = ["nsenter", "-t", str(keepers[namespace].pid), "-n"] if namespace else []
        return subprocess.run(
            prefix + args,
            input=text,
            text=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=5,
        ).stdout

    def pair(left, right, left_name, right_name, left_address, right_address):
        temp_left, temp_right = "x" + left_name + (left or "core"), "x" + right_name + (right or "core")
        command(["ip", "link", "add", temp_left, "type", "veth", "peer", "name", temp_right])
        for namespace, temporary, name, address in (
            (left, temp_left, left_name, left_address),
            (right, temp_right, right_name, right_address),
        ):
            if namespace:
                command(["ip", "link", "set", temporary, "netns", str(keepers[namespace].pid)])
            command(["ip", "link", "set", temporary, "name", name], namespace)
            command(["ip", "link", "set", name, "up"], namespace)
            command(["ip", "-6", "address", "add", address + "/64", "dev", name, "nodad"], namespace)

    try:
        for name in ("ra", "rb", "a", "b"):
            process = subprocess.Popen(["unshare", "-n", "sleep", "180"])
            keepers[name] = process
            deadline = time.monotonic() + 2
            while os.readlink(f"/proc/{process.pid}/ns/net") == os.readlink("/proc/self/ns/net"):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("CHILD_NAMESPACE_SETUP_FAILED")
                time.sleep(0.01)
            command(["ip", "link", "set", "lo", "up"], name)
        command(["ip", "link", "set", "lo", "up"])
        pair(None, "ra", "ca", "wan", "2001:db8:100::1", "2001:db8:100::2")
        pair(None, "rb", "cb", "wan", "2001:db8:200::1", "2001:db8:200::2")
        pair("ra", "a", "lan", "eth", "2001:db8:a::1", "2001:db8:a::2")
        pair("rb", "b", "lan", "eth", "2001:db8:b::1", "2001:db8:b::2")
        for namespace in (None, "ra", "rb"):
            command(["sysctl", "-q", "-w", "net.ipv6.conf.all.forwarding=1"], namespace)
        for destination, via in (("a", "100"), ("b", "200")):
            command(["ip", "-6", "route", "add", f"2001:db8:{destination}::/64", "via", f"2001:db8:{via}::2"])
        for namespace, via in (("ra", "100"), ("rb", "200")):
            command(
                ["ip", "-6", "route", "add", "default", "via", f"2001:db8:{via}::1", "dev", "wan"], namespace
            )
        for namespace in ("a", "b"):
            command(
                ["ip", "-6", "route", "add", "default", "via", f"2001:db8:{namespace}::1", "dev", "eth"],
                namespace,
            )
        rules = """table inet p2plab {
          chain forward {
            type filter hook forward priority 0; policy drop;
            ct state established,related counter accept
            iifname "lan" oifname "wan" counter accept
            counter drop
          }
        }
        """
        for router in ("ra", "rb"):
            command(["nft", "-f", "-"], router, rules)
        results = []
        with tempfile.TemporaryDirectory(prefix="p2plab-netns-") as directory:
            for mode in ("stateful", "stateful-small-mtu", "static-block"):
                if mode == "stateful-small-mtu":
                    for namespace, interfaces in (
                        (None, ("ca", "cb")),
                        ("ra", ("wan", "lan")),
                        ("rb", ("wan", "lan")),
                        ("a", ("eth",)),
                        ("b", ("eth",)),
                    ):
                        for interface in interfaces:
                            command(["ip", "link", "set", interface, "mtu", "1280"], namespace)
                if mode == "static-block":
                    command(
                        [
                            "nft",
                            "insert",
                            "rule",
                            "inet",
                            "p2plab",
                            "forward",
                            "iifname",
                            "wan",
                            "udp",
                            "dport",
                            "9999",
                            "counter",
                            "drop",
                        ],
                        "rb",
                    )
                target = Path(directory) / mode
                target.mkdir()
                children = []
                try:
                    for name in ("a", "b"):
                        children.append(
                            subprocess.Popen(
                                [
                                    "nsenter",
                                    "-t",
                                    str(keepers[name].pid),
                                    "-n",
                                    sys.executable,
                                    "tests/netns_peer.py",
                                    str(target),
                                    name,
                                    mode,
                                ],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True,
                            )
                        )
                    for child in children:
                        out, err = child.communicate(timeout=15)
                        if child.returncode:
                            raise RuntimeError(out + err)
                    peers = [
                        json.loads((target / (name + "-result.json")).read_text()) for name in ("a", "b")
                    ]
                    expected = "timeout-not-authenticated" if mode == "static-block" else "authenticated"
                    if any(peer["state"] != expected for peer in peers):
                        raise AssertionError({"mode": mode, "peers": peers})
                    if mode == "stateful-small-mtu":
                        for peer in peers:
                            evidence = {item["udp_payload_bytes"]: item["confirmed"] for item in peer["mtu"]}
                            if evidence[1200] != 2 or evidence[1400] != 0:
                                raise AssertionError({"mode": mode, "unexpected_mtu": peer})
                    counters = {
                        router: json.loads(command(["nft", "-j", "list", "table", "inet", "p2plab"], router))
                        for router in ("ra", "rb")
                    }
                    results.append({"mode": mode, "peers": peers, "firewall_counters": counters})
                finally:
                    for child in children:
                        if child.poll() is None:
                            child.kill()
                            child.wait()
        print(
            json.dumps(
                {"evidence": "isolated-linux-nftables-simulated-cpe-not-real-home-router", "results": results}
            )
        )
    finally:
        for process in keepers.values():
            process.terminate()
        for process in keepers.values():
            process.wait(timeout=3)


if __name__ == "__main__":
    run()
