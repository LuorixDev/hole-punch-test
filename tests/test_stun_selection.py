import asyncio
import socket
from types import SimpleNamespace

import pytest
import pytest_asyncio

from p2plab.common import new_socket
from p2plab.experiments import Experiments
from p2plab.nat64 import Nat64Attempt, synthesize
from p2plab.native_ice import NativeIceAttempt
from p2plab.research import SocketPoolAttempt
from p2plab.rtc import RtcAttempt
from p2plab.stun import StunServer, select_ice_observer
from p2plab.udp import UdpAttempt
from tests.test_transports import specs

SECOND_LOOPBACK = "127.0.0.2"


def second_loopback_available():
    """Report whether this host has a second address inside 127.0.0.0/8.

    Linux makes the whole range local, so 127.0.0.2 is bindable there. macOS and Windows configure
    only 127.0.0.1, and a changed-source observer cannot be simulated without a second local address.
    """
    probe = socket.socket()
    try:
        probe.bind((SECOND_LOOPBACK, 0))
        return True
    except OSError:
        return False
    finally:
        probe.close()


requires_second_loopback = pytest.mark.skipif(
    not second_loopback_available(),
    reason=f"{SECOND_LOOPBACK} is not a local address on this platform",
)


@pytest_asyncio.fixture
async def observer_pair(peers):
    import socket

    loop = asyncio.get_running_loop()
    sock = new_socket("127.0.0.1", socket.SOCK_DGRAM)
    target = sock.getsockname()[:2]
    live, _ = await loop.create_datagram_endpoint(
        lambda: StunServer(peers[0].log, {}, target, None), sock=sock)
    silent, _ = await loop.create_datagram_endpoint(asyncio.DatagramProtocol, local_addr=("127.0.0.1", 0))
    dead_target = silent.get_extra_info("sockname")[:2]
    try:
        yield [f"{ip}:{port}" for ip, port in (dead_target, target)], list(target), list(dead_target)
    finally:
        live.close()
        silent.close()


@requires_second_loopback
async def test_real_health_falls_back_and_cache_is_source_specific(peers, observer_pair):
    client, _ = peers
    observers, target, _ = observer_pair
    selector = client.stun_selector
    selected = await selector.select(observers, ["127.0.0.1"], attempt="health")
    assert selected["observer"] == observers[1] and selected["target"] == target
    def events():
        return [r for r in client.log.query() if r["event"] == "stun.health"]

    assert len(events()) == 2
    assert await selector.select(observers, ["127.0.0.1"], attempt="cached") == selected
    assert len(events()) == 2
    assert await selector.select(observers[1:], ["127.0.0.2"], attempt="new-source")
    assert len(events()) == 3
    assert "mapped" not in selected


async def test_health_cache_expires_failures_and_cancellation_leaves_no_entry(peers, monkeypatch):
    client, _ = peers
    selector = client.stun_selector
    calls = []
    release = asyncio.Event()

    async def blocked(observer, source):
        calls.append(observer)
        await release.wait()
        return {"state": "failed", "observer": observer, "source": source}

    monkeypatch.setattr(selector, "probe", blocked)
    task = asyncio.create_task(selector.select(["test:1"], ["127.0.0.1"], attempt="cancel"))
    while not calls:
        await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert not selector.cache
    release.set()
    assert await selector.select(["test:1"], ["127.0.0.1"], attempt="failed") is None
    key = next(iter(selector.cache))
    selector.cache[key] = (0, [])
    assert await selector.select(["test:1"], ["127.0.0.1"], attempt="retry") is None
    assert len(calls) == 3


async def test_route_change_during_health_check_cannot_restore_stale_cache(peers, monkeypatch):
    client, _ = peers
    entered, release = asyncio.Event(), asyncio.Event()

    async def probe(observer, source):
        entered.set()
        await release.wait()
        return {"observer": observer, "source": source, "state": "reachable", "target": ["127.0.0.1", 3478]}

    monkeypatch.setattr(client.stun_selector, "probe", probe)
    task = asyncio.create_task(client.stun_selector.select(["test:3478"], ["127.0.0.1"], attempt="old-route"))
    await entered.wait()
    client.stun_selector.invalidate()
    release.set()
    await task
    assert not client.stun_selector.cache


async def test_ice_tries_other_selected_nic_and_bounds_probe_concurrency(peers, monkeypatch):
    client, _ = peers
    client.loopback = False
    client.observers = [f"observer{i}:3478" for i in range(4)]
    client.network = {"addresses": [{"address": f"192.168.{i}.2", "family": 4} for i in range(8)]}
    active, peak = 0, 0

    async def probe(observer, source):
        nonlocal active, peak
        active += 1
        peak = max(peak, active)
        try:
            await asyncio.sleep(0.001)
            return {"state": "reachable" if source == "192.168.1.2" else "failed",
                    "observer": observer, "source": source, "target": ["127.0.0.1", 3478]}
        finally:
            active -= 1

    monkeypatch.setattr(client.stun_selector, "probe", probe)
    selected = await select_ice_observer(client, "4", "multi-nic")
    assert selected["source"] == "192.168.1.2"
    assert peak <= 8 and active == 0
    assert len([r for r in client.log.query() if r["event"] == "stun.health"]) == 32


async def test_same_socket_mapping_tries_second_dns_target(peers, observer_pair, monkeypatch):
    client, _ = peers
    _, target, dead_target = observer_pair

    async def resolve(observer, family):
        return [tuple(dead_target), tuple(target)]

    monkeypatch.setattr("p2plab.udp.resolve_observers", resolve)
    spec, _ = specs("quic", "127.0.0.1")
    udp = UdpAttempt(client, spec, "127.0.0.1")
    try:
        await udp.open()
        bound = list(udp.candidates[0])
        samples = await udp.observe(["multi.example:3478"])
        assert len(samples) == 2
        assert all(s["mapped"] == bound and s["local"] == bound and s["observer"] == tuple(target) for s in samples)
        assert udp.stun_failures[0]["target"] == dead_target
        assert udp.candidate_evidence()["stun_observations"] == samples
    finally:
        await udp.close()


async def test_health_dns_fallback_retains_failure_without_mislabeling_success(peers, observer_pair, monkeypatch):
    client, _ = peers
    _, target, dead_target = observer_pair

    async def resolve(*args):
        return [tuple(dead_target), tuple(target)]

    monkeypatch.setattr("p2plab.stun.resolve_observers", resolve)
    result = await client.stun_selector.probe("multi.example:3478", "127.0.0.1")
    assert result["state"] == "reachable" and result["target"] == target
    assert "reason" not in result
    assert result["failures"][0]["target"] == dead_target


async def test_pool_uses_reachable_observer_beyond_first_two(peers, observer_pair):
    client, _ = peers
    observers, target, _ = observer_pair
    client.observers = [observers[0], observers[0], observers[1]]
    spec, _ = specs("udp-birthday", "127.0.0.1", socket_count=2, hard_side="a")
    pool = SocketPoolAttempt(client, spec, "127.0.0.1")
    try:
        await pool.open()
        mappings = [r for r in client.log.query() if r["event"] == "pool.mapping"]
        assert len(mappings) == 2
        assert all(r["fields"]["observer"] == target for r in mappings)
        assert all(r["fields"]["local"] == r["fields"]["mapped"] for r in mappings)
    finally:
        await pool.close()


async def test_nat64_tries_second_dns_target_and_retains_evidence(peers, monkeypatch):
    client, _ = peers
    prefix = "64:ff9b::/96"
    client.config.setdefault("experiment", {})["nat64_prefixes"] = [prefix]
    spec, _ = specs("nat64", "::1")
    nat = Nat64Attempt(client, spec, "::1")
    nat.candidates = [["::1", 12345]]
    calls = []

    async def resolve(*args):
        return [("192.0.2.1", 3478), ("192.0.2.2", 3478)]

    async def binding(target, **kwargs):
        calls.append(target)
        if target[0] == synthesize(prefix, "192.0.2.1"):
            raise TimeoutError("STUN_TIMEOUT")
        return {"mapped": ("125.111.10.112", 12345)}

    monkeypatch.setattr("p2plab.nat64.resolve_observers", resolve)
    monkeypatch.setattr(nat, "binding", binding)
    samples = await nat.observe(["multi.example:3478"])
    assert len(calls) == 2 and len(samples) == 1
    assert nat.candidate_evidence()["stun_observations"] == samples
    assert len(nat.stun_failures) == 1


async def test_webrtc_uses_live_observer_and_retains_host_mode_when_all_fail(peers, observer_pair):
    client, _ = peers
    observers, target, _ = observer_pair
    client.loopback = False
    client.observers = observers
    client.network = {"addresses": [{"address": "127.0.0.1", "family": 4}]}
    spec, _ = specs("webrtc", "127.0.0.1", profile="4")
    rtc = RtcAttempt(client, spec)
    try:
        rtc.pc.createDataChannel("chat")
        await rtc.configure_stun()
        connection = rtc.pc.sctp.transport.transport.iceGatherer._connection
        assert connection.stun_server == tuple(target)
        client.observers = observers[:1]
        rtc.stun_configured = False
        await rtc.configure_stun()
        assert connection.stun_server is None
    finally:
        await rtc.close()


async def test_native_ice_selects_second_live_observer(peers, observer_pair):
    client, _ = peers
    observers, target, _ = observer_pair
    client.loopback = False
    client.observers = observers
    client.network = {"addresses": [{"address": "127.0.0.1", "family": 4}]}
    native = NativeIceAttempt.__new__(NativeIceAttempt)
    native.owner, native.spec, native.attempt = client, {"profile": "4"}, "native-fallback"
    native.agent, native.stream = None, 0
    native.libs = SimpleNamespace(nice=SimpleNamespace(nice_agent_gather_candidates=lambda *args: False))
    properties = {}
    native.property = properties.__setitem__
    with pytest.raises(ValueError, match="LIBNICE_GATHER_UNAVAILABLE"):
        await native.connect()
    assert properties == {"stun-server": target[0], "stun-server-port": target[1]}


async def test_timeout_result_and_done_signal_retain_real_candidate_evidence(peers, observer_pair):
    client, _ = peers
    _, _, target = observer_pair
    client.timeout = 0.05
    manager = Experiments(client)
    spec, _ = specs("quic", "127.0.0.1", phase="baseline")
    sent = []

    async def signal(data):
        sent.append(data)
        if data["kind"] == "candidate":
            manager.attempts[spec["attempt"]].set_candidates([target])

    client.signal = signal
    try:
        result = await manager.execute(spec, 0)
        assert result["state"] == "failed"
        evidence = result["candidate_evidence"]
        assert evidence["remote_candidates"] == [target]
        assert evidence["local_candidates"][0][0] == "127.0.0.1"
        assert evidence["probe_sends"] > 0 and evidence["received_probes"] == 0
        done = next(data for data in sent if data["kind"] == "done")
        assert done["result"]["candidate_evidence"] == evidence
        event = next(r for r in client.log.query() if r["event"] == "udp.punch_started")
        assert event["fields"]["remote_candidates"] == [target]
    finally:
        await manager.close()


def test_missing_public_mapping_is_distinct_from_public_punch_failure(peers):
    client, _ = peers
    client.loopback = False
    spec, _ = specs("quic", "192.168.1.22")
    udp = UdpAttempt(client, spec, spec["host"])
    udp.candidates, udp.remote_candidates = [["192.168.1.22", 12345]], [["125.111.10.112", 47629]]
    assert udp.candidate_evidence()["diagnosis"] == "LOCAL_PUBLIC_UDP_MAPPING_MISSING"
    udp.candidates.append(["120.225.12.142", 12345])
    assert udp.candidate_evidence()["diagnosis"] == "PUBLIC_UDP_CANDIDATES_PRESENT"
    udp.remote_candidates = [["192.168.1.233", 47629]]
    assert udp.candidate_evidence()["diagnosis"] == "PEER_PUBLIC_UDP_CANDIDATE_MISSING"
