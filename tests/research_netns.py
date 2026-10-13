"""Additional native/raw/translation tests, only inside an isolated network namespace."""
import os
import subprocess
import sys


def main():
    if os.geteuid() != 0 or len(sys.argv) != 2 or os.readlink("/proc/self/ns/net") == sys.argv[1]:
        raise RuntimeError("ISOLATED_USER_AND_NETWORK_NAMESPACE_REQUIRED")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    subprocess.run(["ip", "-6", "address", "add", "64:ff9b::7f00:2/128", "dev", "lo", "nodad"], check=True)
    # Inbound naked SYNs are dropped after packet capture; crafted SYNACKs may reach the stack.
    subprocess.run(["nft", "-f", "-"], check=True, text=True, input="""
table inet p2plab_raw {
  chain input {
    type filter hook input priority 0; policy accept;
    tcp flags & (syn | ack) == syn drop
  }
}
""")
    env = {**os.environ, "P2PLAB_RAW_TEST": "isolated"}
    return subprocess.call([sys.executable, "-m", "pytest", "tests/test_research.py", "-q", "-k",
                            "raw_namespace or translated_namespace", "--junitxml=data/verification/junit-raw-netns.xml"],
                           env=env)


if __name__ == "__main__":
    raise SystemExit(main())
