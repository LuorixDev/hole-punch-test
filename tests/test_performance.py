import asyncio
import copy
import statistics
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from p2plab.performance import BenchProbe, bottleneck_assessment, darwin_udp_errors, udp_errors
from p2plab.quic_timer import QuicTimer


def measurement():
    probe = {"samples": 40, "event_loop_core_fraction": .2, "event_loop_lag_p95_ms": 1,
             "transport": {}, "udp_buffer_errors": {}}
    return {"seconds": 2, "mbps": 100, "sender_runtime": copy.deepcopy(probe),
            "receiver_runtime": copy.deepcopy(probe)}


def test_low_speed_is_not_automatically_implementation_or_network_limit():
    result = measurement()
    assert bottleneck_assessment(result, {"mbps": 1000, "basis": "configured"})["state"] == "unknown"
    assert bottleneck_assessment({"seconds": 2, "mbps": 20})["state"] == "unknown"
    result["seconds"] = .9
    result["sender_runtime"]["event_loop_core_fraction"] = 1
    assert bottleneck_assessment(result)["state"] == "unknown"


@pytest.mark.parametrize("role", ["sender_runtime", "receiver_runtime"])
def test_either_endpoint_cpu_or_loop_can_indicate_implementation_limit(role):
    result = measurement()
    result[role]["event_loop_core_fraction"] = .92
    verdict = bottleneck_assessment(result)
    assert verdict["state"] == "implementation" and verdict["confidence"] == "probable"
    result[role]["event_loop_core_fraction"] = .2
    result[role]["event_loop_lag_p95_ms"] = 15
    assert bottleneck_assessment(result)["state"] == "implementation"


def test_pacing_and_namespace_buffer_drops_are_not_marked_network_limits():
    result = measurement()
    result["sender_runtime"]["transport"] = {"pacing_fires": 100, "pacing_requested_seconds": .03,
                                              "pacing_late_seconds": .6}
    assert bottleneck_assessment(result)["state"] == "implementation"
    result["sender_runtime"]["transport"] = {}
    result["receiver_runtime"]["udp_buffer_errors"] = {"RcvbufErrors": 1}
    assert bottleneck_assessment(result)["state"] == "unknown"


def test_congestion_constraint_requires_both_quiet_endpoints_and_repeated_recovery():
    result = measurement()
    result["sender_runtime"]["transport"] = {"congestion_reductions_observed": 3,
        "inflight_fraction_median": .9, "cwnd_rtt_mbps_median": 120}
    assert bottleneck_assessment(result)["state"] == "network"
    result["sender_runtime"]["transport"]["congestion_reductions_observed"] = 0
    assert bottleneck_assessment(result)["state"] == "unknown"
    result["sender_runtime"]["transport"]["congestion_reductions_observed"] = 3
    result["receiver_runtime"]["event_loop_core_fraction"] = .7
    assert bottleneck_assessment(result)["state"] == "unknown"


def test_normal_requires_valid_reference_and_runtime_and_contended_samples_stay_unknown():
    result = measurement()
    reference = {"mbps": 110, "basis": "measured"}
    assert bottleneck_assessment(result, reference)["state"] == "normal"
    assert bottleneck_assessment(result, reference, competing=True)["state"] == "unknown"
    result["receiver_runtime"]["competing_work"] = True
    assert bottleneck_assessment(result, reference)["state"] == "unknown"
    result["receiver_runtime"]["competing_work"] = False
    result["receiver_runtime"]["event_loop_core_fraction"] = float("nan")
    assert bottleneck_assessment(result, reference)["state"] == "unknown"


@pytest.mark.parametrize("precise", [True, False])
async def test_timer_rearm_disarm_and_close_do_not_fire_stale_callbacks(precise):
    fired = []
    timer = QuicTimer(fired.append, precise=precise)
    try:
        deadline = time.monotonic() + .01
        timer.arm(deadline)
        timer.arm(deadline)
        timer.arm(None)
        await asyncio.sleep(.03)
        assert not fired
        event = asyncio.Event()
        timer.callback = lambda deadline: (fired.append(deadline), event.set())
        deadline = time.monotonic() + .002
        timer.arm(deadline)
        await asyncio.wait_for(event.wait(), 1)
        assert fired == [deadline]
        timer.arm(time.monotonic() + .001)
        timer.close()
        timer.close()
        await asyncio.sleep(.02)
        assert fired == [deadline] and timer.fd is None
    finally:
        timer.close()


async def test_probe_is_bounded_cancelable_and_samples_without_transport():
    path = SimpleNamespace(owner=SimpleNamespace(managers=[], transfers=SimpleNamespace(records={})))
    probe = BenchProbe(path)
    await asyncio.sleep(.12)
    result = probe.finish()
    assert result["samples"] >= 1 and result["transport"] == {}
    assert result["event_loop_core_fraction"] >= 0
    assert probe.handle.cancelled()


async def test_timerfd_settime_failure_falls_back_and_keeps_deadline():
    event = asyncio.Event()
    timer = QuicTimer(lambda deadline: event.set())
    try:
        if timer.fd is None:
            pytest.skip("timerfd unavailable")
        timer.settime = lambda *args: -1
        timer.arm(time.monotonic() + .002)
        assert timer.fd is None and timer.backend == "asyncio-fallback"
        await asyncio.wait_for(event.wait(), 1)
    finally:
        timer.close()


async def _median_lateness(precise, delay=.01, samples=15):
    """Median (observed - requested) wakeup delay, re-arming one timer to exercise the hot path."""
    loop = asyncio.get_running_loop()
    state = {"fut": None, "errors": []}

    def callback(deadline):
        state["errors"].append(time.monotonic() - deadline)
        fut = state["fut"]
        if fut is not None and not fut.done():
            fut.set_result(None)

    timer = QuicTimer(callback, precise=precise)
    try:
        for _ in range(samples):
            state["fut"] = loop.create_future()
            timer.arm(time.monotonic() + delay)
            await asyncio.wait_for(state["fut"], 1)
        return statistics.median(state["errors"]), timer.backend
    finally:
        timer.close()


async def test_imprecise_timer_never_starts_a_poller_thread():
    before = threading.active_count()
    timer = QuicTimer(lambda deadline: None, precise=False)
    try:
        assert timer.backend == "asyncio" and threading.active_count() == before
    finally:
        timer.close()


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires an actual macOS host")
async def test_darwin_precise_timer_uses_kqueue_and_beats_timer_coalescing():
    kqueue_lateness, kqueue_backend = await _median_lateness(precise=True)
    asyncio_lateness, asyncio_backend = await _median_lateness(precise=False)
    assert kqueue_backend == "darwin-kqueue"
    assert asyncio_backend == "asyncio"
    # macOS coalesces kevent select() timeouts to roughly a millisecond, so the plain asyncio
    # fallback wakes ~1000us late where a NOTE_CRITICAL kernel timer wakes ~30us late.
    assert kqueue_lateness < asyncio_lateness / 2


@pytest.mark.skipif(sys.platform != "darwin", reason="Requires an actual macOS host")
async def test_darwin_timer_close_stops_its_poller_thread():
    before = threading.active_count()
    timer = QuicTimer(lambda deadline: None, precise=True)
    assert timer.backend == "darwin-kqueue" and threading.active_count() == before + 1
    timer.close()
    for _ in range(200):
        if threading.active_count() == before:
            break
        await asyncio.sleep(.01)
    assert threading.active_count() == before


@pytest.mark.parametrize("mutation", [
    lambda r: r["sender_runtime"].update(samples="bad"),
    lambda r: r["receiver_runtime"].update(udp_buffer_errors="bad"),
    lambda r: r["sender_runtime"].update(transport="bad"),
])
def test_malformed_optional_peer_diagnostics_do_not_crash_classification(mutation):
    result = measurement()
    mutation(result)
    assert bottleneck_assessment(result)["state"] == "unknown"


# Captured from `netstat -s -p udp` on macOS 26 (arm64). The two-tab rows are sub-items of the
# row above them, so only the named counters must be picked up.
NETSTAT_UDP = """
udp:
\t5431061 datagrams received
\t\t0 with incomplete header
\t\t0 with bad data length field
\t\t0 with bad checksum
\t\t615126 with no checksum
\t\t2838 checksummed in software
\t\t\t323 datagrams (61655 bytes) over IPv4
\t\t\t2515 datagrams (629219 bytes) over IPv6
\t\t49147 dropped due to no socket
\t\t85421 broadcast/multicast datagrams undelivered
\t\t19 IPv6 multicast datagrams undelivered
\t\t0 time multicast source filter matched
\t\t200299 dropped due to full socket buffers
\t\t0 not for hashed pcb
\t\t5096194 delivered
\t3272488 datagrams output
\t\t1122203 checksummed in software
\t\t\t1064401 datagrams (112880051 bytes) over IPv4
\t\t\t57802 datagrams (18799003 bytes) over IPv6
\t51 open UDP sockets
"""

DARWIN_UDP_DROPS = {
    "with_bad_checksum": 0,
    "dropped_due_to_no_socket": 49147,
    "broadcast_multicast_undelivered": 85421,
    "dropped_due_to_full_socket_buffers": 200299,
}


def test_darwin_udp_errors_reads_only_the_named_counters():
    assert darwin_udp_errors(NETSTAT_UDP) == DARWIN_UDP_DROPS


def test_udp_errors_reads_netstat_on_darwin(monkeypatch):
    monkeypatch.setattr("p2plab.performance.platform.system", lambda: "Darwin")
    monkeypatch.setattr("p2plab.performance.darwin_netstat_udp", lambda: NETSTAT_UDP)
    assert udp_errors() == DARWIN_UDP_DROPS


def test_udp_errors_is_empty_when_netstat_cannot_be_read(monkeypatch):
    """Missing telemetry must stay absent rather than become zeros people mistake for evidence."""
    monkeypatch.setattr("p2plab.performance.platform.system", lambda: "Darwin")
    monkeypatch.setattr("p2plab.performance.darwin_netstat_udp", lambda: "")
    assert udp_errors() == {}


def test_udp_errors_still_reads_proc_on_linux(monkeypatch):
    files = {
        "/proc/net/snmp": (
            "Udp: InDatagrams NoPorts InErrors OutDatagrams RcvbufErrors SndbufErrors InCsumErrors\n"
            "Udp: 100 0 0 100 7 9 0\n"
        ),
        "/proc/net/snmp6": "Udp6RcvbufErrors 3\nUdp6SndbufErrors 4\n",
    }

    class FakePath:
        def __init__(self, name):
            self.name = name

        def read_text(self):
            return files[self.name]

    monkeypatch.setattr("p2plab.performance.platform.system", lambda: "Linux")
    monkeypatch.setattr("p2plab.performance.Path", FakePath)
    assert udp_errors() == {
        "RcvbufErrors": 7,
        "SndbufErrors": 9,
        "Udp6RcvbufErrors": 3,
        "Udp6SndbufErrors": 4,
    }
