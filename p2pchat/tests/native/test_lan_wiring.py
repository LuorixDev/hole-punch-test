"""局域网直连发现接线：默认关闭、显式同意、候选不放宽，以及一次受控的『发现→直连』。

注意：这里用 ``restricted_local=True`` 的回环模式，只证明**接线可用**，
**不是**局域网/家宽证据（候选会被标记 testOnly）。
"""
from __future__ import annotations

import asyncio
import socket
import time

from p2pchat.python_desktop.lan_client import LanDirect

SECRET = "lan-test-secret-1234"


def test_default_is_off_and_unsigned_consent_is_refused() -> None:
    created = []

    def factory(policy):
        created.append(policy)
        raise AssertionError("没有同意时不应该创建发现实例")

    controller = LanDirect(discovery_factory=factory, interface_resolver=lambda: "127.0.0.1")
    assert controller.enabled is False
    assert controller.capability()["enabled"] is False
    line = controller.capability_line()
    assert "默认关闭" in line or "不可用" in line
    try:
        asyncio.run(controller.enable(room="lab", secret=SECRET, peer_id="a", listen_port=40404, consent=False))
        raise AssertionError("没有同意时必须拒绝")
    except PermissionError as error:
        assert str(error) == "LAN_OPT_IN_REQUIRED"
    assert created == []
    assert controller.audit.events[-1]["action"] == "enable-denied"


def test_production_refuses_loopback_interface_and_candidates() -> None:
    controller = LanDirect(interface_resolver=lambda: "127.0.0.1")
    try:
        asyncio.run(controller.enable(room="lab", secret=SECRET, peer_id="a", listen_port=40404, consent=True))
        raise AssertionError("生产路径上不允许回环接口")
    except ValueError as error:
        assert str(error) == "NO_LAN_INTERFACE"
    loopback_candidate = {"id": "x", "family": 4, "transport": "udp", "address": "127.0.0.1", "port": 40404,
                          "kind": "host", "socketId": "a" * 16}
    ok, reason = controller.accept_candidate(loopback_candidate)
    assert ok is False and reason == "LOOPBACK_NOT_ALLOWED_IN_PRODUCTION"
    multicast = dict(loopback_candidate, address="239.255.42.99")
    ok, reason = controller.accept_candidate(multicast)
    assert ok is False and reason == "INVALID_CANDIDATE"


def test_candidate_rules_are_not_loosened(monkeypatch) -> None:
    """同一份 validate_candidate 仍然生效：伪造字段/非法端口一律拒绝。"""
    controller = LanDirect(interface_resolver=lambda: "127.0.0.1")
    controller.restricted_local = True  # 即使是测试模式，字段校验也不能放宽
    for broken in ({"id": "x", "family": 4, "transport": "udp", "address": "10.0.0.5", "port": 0, "kind": "host"},
                   {"id": "x", "family": 6, "transport": "udp", "address": "10.0.0.5", "port": 40404, "kind": "host"},
                   {"id": "x", "family": 4, "transport": "smtp", "address": "10.0.0.5", "port": 40404, "kind": "host"},
                   {"id": "x", "family": 4, "transport": "udp", "address": "10.0.0.5", "port": 40404, "kind": "host",
                    "injected": "y"}):
        ok, reason = controller.accept_candidate(broken)
        assert ok is False and reason == "INVALID_CANDIDATE", broken


def test_capability_text_matches_the_real_status() -> None:
    """界面文案与真实能力同源：可用时说“默认关闭”，不可用时给人话原因。"""
    controller = LanDirect(interface_resolver=lambda: "127.0.0.1")
    capability = controller.capability()
    line = controller.capability_line()
    if capability["status"] == "available":
        assert "默认关闭" in line or "已开启" in line
    else:
        assert "不可用" in line and capability["reason"] in {"NO_UDP_MULTICAST_API"}
    assert capability["mechanism"] == "lan-direct"
    assert "lan-direct" in controller.technical_detail()


def test_controlled_multicast_discover_then_direct_datagram() -> None:
    """受控组播：两个实例互相发现，然后用发现到的候选真的发一个数据报过去。"""

    async def scenario():
        listener_a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)   # A 真正在听的端口
        listener_a.bind(("127.0.0.1", 0))
        listener_a.setblocking(False)
        port_a = listener_a.getsockname()[1]
        sender_b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)     # B 侧发数据的套接字
        sender_b.bind(("127.0.0.1", 0))
        port_b = sender_b.getsockname()[1]

        a = LanDirect(interface_resolver=lambda: "127.0.0.1")
        b = LanDirect(interface_resolver=lambda: "127.0.0.1")
        await a.enable(room="lab", secret=SECRET, peer_id="a", listen_port=port_a,
                       consent=True, restricted_local=True)
        await b.enable(room="lab", secret=SECRET, peer_id="b", listen_port=port_b,
                       consent=True, restricted_local=True)
        loop = asyncio.get_running_loop()
        deadline = time.time() + 12
        while time.time() < deadline and not (a.peers and b.peers):
            await asyncio.sleep(0.2)
        assert b.peers, "B 应该发现 A（受控组播）"
        candidates = b.candidates()
        assert candidates and candidates[0]["address"] == "127.0.0.1"
        assert candidates[0]["port"] == port_a, "候选应指向 A 广告的监听端口"
        # 直连：B 把数据发到发现到的候选端口，A 的监听端口必须真的收到
        sender_b.sendto(b"discover-then-direct", ("127.0.0.1", candidates[0]["port"]))
        payload, _ = await asyncio.wait_for(loop.sock_recvfrom(listener_a, 64), 3)
        await a.disable()
        await b.disable()
        listener_a.close()
        sender_b.close()
        return candidates, payload, a, b

    candidates, payload, a, b = asyncio.run(scenario())
    assert payload == b"discover-then-direct"
    assert candidates[0].get("testOnly") is True, "回环候选必须标成测试模式，绝不当局域网证据"
    actions = [event["action"] for event in b.audit.events]
    assert "enable-requested" in actions and "enabled" in actions and "peer-found" in actions and "disabled" in actions
    assert a.enabled is False and b.enabled is False, "关闭后不应再跑组播"
