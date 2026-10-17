import asyncio
from types import SimpleNamespace

from p2plab.experiments import (
    MAX_CONCURRENT_ATTEMPTS,
    Experiments,
    attempt_resource_keys,
)


def test_attempt_resources_separate_transport_families_and_exclude_risky_work():
    def spec(method, host="192.0.2.10", **fields):
        return {"method": method, "host": host, "phase": "baseline", **fields}

    assert attempt_resource_keys(spec("udp")) == attempt_resource_keys(spec("quic"))
    assert attempt_resource_keys(spec("udp")) != attempt_resource_keys(spec("tcp"))
    assert attempt_resource_keys(spec("udp")) != attempt_resource_keys(spec("udp", "2001:db8::10"))
    assert attempt_resource_keys(spec("webrtc", profile="dual")) == frozenset({
        ("network", 4, "udp"), ("network", 6, "udp")
    })
    assert attempt_resource_keys(spec("udp-birthday")) == frozenset({"exclusive"})
    assert attempt_resource_keys(spec("upnp", phase="gateway")) == frozenset({"exclusive"})


async def test_scheduler_bounds_parallel_lanes_and_places_exclusive_attempts_at_barriers():
    class Log:
        def event(self, *args, **kwargs):
            pass

    owner = SimpleNamespace(leader=True, log=Log(), paths=[])

    async def park_idle_paths():
        pass

    owner.park_idle_paths = park_idle_paths
    manager = Experiments(owner)
    manager.plan = [
        {"attempt": "udp4-a", "method": "udp", "a_host": "192.0.2.1", "leader_initiator": True,
         "phase": "baseline"},
        {"attempt": "quic4-same-lane", "method": "quic", "a_host": "192.0.2.1",
         "leader_initiator": True, "phase": "baseline"},
        {"attempt": "tcp4", "method": "tcp", "a_host": "192.0.2.1", "leader_initiator": True,
         "phase": "baseline"},
        {"attempt": "udp6", "method": "udp", "a_host": "2001:db8::1", "leader_initiator": True,
         "phase": "baseline"},
        {"attempt": "tcp6", "method": "tcp", "a_host": "2001:db8::1", "leader_initiator": True,
         "phase": "baseline"},
        {"attempt": "port-pool", "method": "udp-birthday", "a_host": "192.0.2.1",
         "leader_initiator": True, "phase": "baseline"},
        {"attempt": "tcp4-after", "method": "tcp", "a_host": "192.0.2.1", "leader_initiator": True,
         "phase": "baseline"},
    ]
    active_keys = set()
    active_count = 0
    peak = 0
    exclusive_overlap = []

    async def execute(spec, index):
        nonlocal active_count, peak
        keys = attempt_resource_keys(spec)
        if "exclusive" in keys:
            exclusive_overlap.append(active_count)
        else:
            assert keys.isdisjoint(active_keys)
        active_keys.update(keys)
        active_count += 1
        peak = max(peak, active_count)
        try:
            await asyncio.sleep(0.01 if index % 2 else 0.02)
            result = {"attempt": spec["attempt"], "state": "failed", "data_path": False}
            manager.results.append(result)
            manager.remote_done_events.setdefault(spec["attempt"], asyncio.Event()).set()
            manager.remote_done[spec["attempt"]] = {}
            return result
        finally:
            active_count -= 1
            active_keys.difference_update(keys)

    manager.execute = execute
    await asyncio.wait_for(manager.run_plan(), timeout=2)

    assert peak == 4
    assert peak <= MAX_CONCURRENT_ATTEMPTS
    assert exclusive_overlap == [0]
    assert len(manager.results) == len(manager.plan)


async def test_paired_schedulers_preserve_overlapping_order_after_asymmetric_completions(peers, task_scheduling):
    plan = [
        {"attempt": "pre4", "method": "udp", "profile": "fast", "a_host": "127.0.0.1"},
        {"attempt": "pre6", "method": "udp", "profile": "fast", "a_host": "::1"},
        {"attempt": "dual", "method": "webrtc", "profile": "dual", "a_host": None},
        {"attempt": "single4", "method": "webrtc", "profile": "4", "a_host": None},
        {"attempt": "single6", "method": "webrtc", "profile": "6", "a_host": None},
        {"attempt": "tcp-independent", "method": "tcp", "profile": "fast", "a_host": "127.0.0.1"},
    ]
    plan = [{**spec, "b_host": spec["a_host"], "phase": "baseline", "leader_initiator": True}
            for spec in plan]
    started = {(side, spec["attempt"]): asyncio.Event() for side in (0, 1) for spec in plan}
    launches = [[], []]
    managers = []

    async def park():
        pass

    for side, peer in enumerate(peers):
        owner = SimpleNamespace(leader=side == 0, log=peer.log, paths=[], park_idle_paths=park)
        manager = Experiments(owner)
        manager.plan = plan

        async def run_attempt(spec, index, side=side, manager=manager):
            attempt = spec["attempt"]
            launches[side].append(attempt)
            started[side, attempt].set()
            if attempt.startswith("pre"):
                # One peer releases only IPv4 first; the other releases both lanes together.
                await asyncio.sleep(0.04 if side == 0 and attempt == "pre6" else 0.01)
            else:
                await started[1 - side, attempt].wait()
            result = {"attempt": attempt, "state": "failed", "data_path": False}
            manager.results.append(result)
            return result, result

        manager.run_attempt = run_attempt
        managers.append(manager)

    await asyncio.wait_for(asyncio.gather(*(m.run_plan() for m in managers)), 2)
    for order in launches:
        assert order.index("tcp-independent") < order.index("dual")
        assert order.index("dual") < order.index("single4")
        assert order.index("dual") < order.index("single6")
        assert len(order) == len(plan)
