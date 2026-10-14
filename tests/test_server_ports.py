import sys

import pytest

from p2plab import server


@pytest.mark.parametrize("flags,ports", [
    ([], (8443, 8443, 8443)),
    (["--port", "9000"], (9000, 9000, 9000)),
    (["--port", "65535"], (65535, 65535, 65535)),
    (["--port", "9000", "--stun-port", "3478"], (9000, 3478, 9000)),
    (["--port", "9000", "--tcp-port", "3479"], (9000, 9000, 3479)),
    (["--stun-port", "3478", "--tcp-port", "3479"], (8443, 3478, 3479)),
])
def test_server_ports_follow_main_port_unless_explicitly_overridden(monkeypatch, flags, ports):
    captured = []

    async def capture(args):
        captured.append(args)

    monkeypatch.setattr(sys, "argv", ["server.py", *flags])
    monkeypatch.setattr(server, "serve", capture)
    server.main()
    assert len(captured) == 1
    args = captured[0]
    assert (args.port, args.stun_port, args.tcp_port) == ports


def test_external_port_and_forwarded_mode_do_not_change_listen_ports(monkeypatch):
    captured = []

    async def capture(args):
        captured.append(args)

    monkeypatch.setattr(sys, "argv", ["server.py", "--port", "8443", "--public-port", "57878", "--forwarded"])
    monkeypatch.setattr(server, "serve", capture)
    server.main()
    args = captured[0]
    assert (args.port, args.stun_port, args.tcp_port) == (8443, 8443, 8443)
    assert args.public_port == 57878 and args.forwarded


@pytest.mark.parametrize("flags", [
    ["--port", "0"], ["--port", "65536"], ["--stun-port", "-1"],
    ["--tcp-port", "65536"],
    ["--public-port", "0"], ["--public-port", "65536"],
    ["--public-port", "9000", "--stun-host", "127.0.0.1", "--stun-alt-ip", "127.0.0.2"],
    ["--port", "65535", "--stun-host", "127.0.0.1", "--stun-alt-ip", "127.0.0.2"],
    ["--stun-alt-ip", "127.0.0.2"],
    ["--stun-host", "0.0.0.0", "--stun-alt-ip", "127.0.0.2"],
])
def test_server_rejects_invalid_ports_before_startup(monkeypatch, flags):
    monkeypatch.setattr(sys, "argv", ["server.py", *flags])
    with pytest.raises(SystemExit) as raised:
        server.main()
    assert raised.value.code == 2
