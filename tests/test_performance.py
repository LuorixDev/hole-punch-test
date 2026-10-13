import asyncio
import copy
import time
from types import SimpleNamespace

import pytest

from p2plab.performance import BenchProbe, bottleneck_assessment
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


@pytest.mark.parametrize("mutation", [
    lambda r: r["sender_runtime"].update(samples="bad"),
    lambda r: r["receiver_runtime"].update(udp_buffer_errors="bad"),
    lambda r: r["sender_runtime"].update(transport="bad"),
])
def test_malformed_optional_peer_diagnostics_do_not_crash_classification(mutation):
    result = measurement()
    mutation(result)
    assert bottleneck_assessment(result)["state"] == "unknown"
