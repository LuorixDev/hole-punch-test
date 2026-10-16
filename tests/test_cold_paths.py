import asyncio
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from p2plab.client import Client
from p2plab.experiments import Experiments
from p2plab.tui import P2PApp
from tests.test_reconnect import wait_for
from tests.test_server import cleanup_hub, start_hub


async def test_failed_reopen_attempt_keeps_request_pending_until_coordinator_decides(peers):
    owner, _ = peers
    request = "retry-request"
    future = asyncio.get_running_loop().create_future()
    owner.reopen_futures[request] = future
    ready = asyncio.Event()
    ready.set()
    manager = SimpleNamespace(
        reopen_start=ready, plan=[{"attempt": "failed-wake", "leader_initiator": True,
                                  "a_host": "127.0.0.1", "b_host": "127.0.0.1"}],
        execute=AsyncMock(return_value={"data_path": False}),
        remote_done_events={"failed-wake": ready}, remote_done={"failed-wake": {"data_path": False}},
        close=AsyncMock(),
    )
    try:
        with pytest.raises(ConnectionError, match="REOPEN_FAILED"):
            await owner.run_reopen(manager, None, {"attempt": "failed-wake", "source": "source",
                                                  "request": request, "mode": "measure"})
        assert not future.done()
        manager.close.assert_awaited_once()
    finally:
        owner.reopen_futures.pop(request)
        future.cancel()


@pytest.mark.parametrize("succeed", [False, True])
async def test_simopen_coordinator_retries_fresh_attempt_and_only_reports_final_failure(peers, monkeypatch, succeed):
    owner, _ = peers
    request = "retry-request"
    future = asyncio.get_running_loop().create_future()
    owner.reopen_futures[request] = future
    monkeypatch.setattr(owner, "reopen_source", lambda source: (None, {"method": "tcp-simopen"}))
    monkeypatch.setattr(owner, "signal", AsyncMock())
    attempts = []

    def start(data):
        attempts.append(data)
        owner.reopen_managers[data["attempt"]] = SimpleNamespace(reopen_start=asyncio.Event())

        async def execute():
            assert not future.done()
            if len(attempts) == 2 and succeed:
                future.set_result("verified-path")
                return
            raise ConnectionError("REOPEN_FAILED")

        return asyncio.create_task(execute())

    monkeypatch.setattr(owner, "start_reopen", start)
    try:
        await owner.coordinate_reopen("original-source", request, "measure")
        assert len(attempts) == 2 and attempts[0]["attempt"] != attempts[1]["attempt"]
        assert all(data["source"] == "original-source" for data in attempts)
        if succeed:
            assert future.result() == "verified-path"
            assert not any(call.args[0]["kind"] == "path_reopen_reject" for call in owner.signal.call_args_list)
        else:
            with pytest.raises(ConnectionError, match="REOPEN_FAILED"):
                await future
            assert owner.signal.call_args_list[-1].args[0]["kind"] == "path_reopen_reject"
    finally:
        owner.reopen_futures.pop(request)


async def cold_pair(peers, monkeypatch, method="tcp"):
    a, b = peers
    plan = [
        {"attempt": f"cold-test-{i:03d}-{method}", "method": method,
         "a_host": "127.0.0.1", "b_host": "127.0.0.1", "leader_initiator": True,
         "phase": "baseline", "profile": "fast", "datagram_size": 1200}
        for i in range(2)
    ]
    monkeypatch.setattr("p2plab.experiments.build_plan", lambda *args, **kwargs: plan)
    for owner in peers:
        owner.cold_paths_supported = True
        owner.connected.set()
        owner.paired.set()
        owner.network = {"addresses": [{"address": "127.0.0.1", "family": 4}]}
        owner.network_ready.set()
        owner.manager = Experiments(owner)
        owner.managers.append(owner.manager)

    async def from_a(data):
        await b.handle_control({"type": "signal", "pair": a.pair, "data": data})

    async def from_b(data):
        await a.handle_control({"type": "signal", "pair": b.pair, "data": data})

    a.signal, b.signal = from_a, from_b
    await asyncio.gather(a.manager.start(), b.manager.start())
    await asyncio.wait_for(asyncio.gather(a.manager.task, b.manager.task), 40)
    await wait_for(lambda: all(len(p.paths) == 2 and sum(not q.closed for q in p.paths) == 1 for p in peers))
    return a, b


async def cleanup(peers):
    for owner in peers:
        owner.stop.set()
    for owner in peers:
        for manager in owner.managers:
            await manager.close()
        for path in owner.paths:
            await path.close()
        for task in tuple(owner.tasks):
            task.cancel()
        await asyncio.gather(*tuple(owner.tasks), return_exceptions=True)


@pytest.mark.parametrize("method", ["tcp", "quic"])
async def test_verified_standbys_release_backends_and_reopen_fresh_on_use(peers, monkeypatch, method, task_scheduling):
    a, b = await cold_pair(peers, monkeypatch, method)
    try:
        originals = [p.paths[1] for p in peers]
        for owner in peers:
            assert all(r["data_path"] and r["state"] == "success" for r in owner.manager.results)
            assert owner.paths[1].closed and owner.can_reopen(owner.paths[1])
            assert all(p.keepalive_task is None for p in owner.paths)
            assert owner.paths[1].attempt not in owner.manager.attempts
            assert getattr(owner.paths[1]._send, "__self__", None) is None
            assert sum(t.get_name() == "path-maintenance" for t in owner.tasks) == 1
        await b.command("/use 1")
        await wait_for(lambda: all(p.active_path is p.paths[1] and not p.paths[1].closed
                                  and p.paths[0].closed for p in peers))
        for owner, old in zip(peers, originals):
            assert len(owner.paths) == 2
            assert owner.paths[1] is not old
            assert owner.paths[1].attempt != old.attempt
            assert owner.paths[1].source_attempt == old.attempt
            assert owner.paths[0].closed
            assert any(r["event"] == "path.reopen_verified" for r in owner.log.query())
        await a.chat("cold standby rebuilt")
        assert any(r["event"] == "chat.received" for r in b.log.query())
        app = P2PApp(client=a, start_backend=False)
        assert app.attempt_label(a.paths[1].attempt).startswith("#002")
        assert "重建" in app.attempt_label(a.paths[1].attempt)
    finally:
        await cleanup(peers)


async def test_cold_batch_speed_rebuilds_serially_preserves_primary_and_chat(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    primary = a.active_path
    try:
        task = asyncio.create_task(a.command("/speed-all 1"))
        await a.chat("chat remains on primary")
        await asyncio.wait_for(task, 25)
        await wait_for(lambda: all(sum(not q.closed for q in p.paths) == 1 for p in peers))
        assert a.active_path is primary and not primary.closed
        assert a.batch_speed_state["completed"] == 2 and a.batch_speed_state["failed"] == 0
        for path in a.paths:
            assert set(path.latest_speed) == {"local-to-peer", "peer-to-local"}
        assert a.paths[1].closed and a.can_reopen(a.paths[1])
        assert not any(r["event"] == "path.rtt_sample" for r in a.log.query())
    finally:
        await cleanup(peers)


async def test_no_automatic_rtt_even_on_visible_tab_and_primary_idle_keepalive_is_not_a_sample(peers, monkeypatch):
    a, _ = await cold_pair(peers, monkeypatch)
    try:
        a.link_monitor_active = True
        path = a.active_path
        old_rtt, old_stamp = path.last_rtt, path.rtt_measured_at
        path.last_rx = path.last_tx = time.monotonic() - 13
        previous = path.last_liveness
        await wait_for(lambda: path.last_liveness != previous, timeout=3)
        assert not path.closed
        assert (path.last_rtt, path.rtt_measured_at) == (old_rtt, old_stamp)
        assert not any(r["event"] == "path.rtt_sample" for r in a.log.query())
        a.rtt_monitor_enabled = True
        path.last_liveness = time.monotonic() - 3
        await wait_for(lambda: path.rtt_measured_at != old_stamp, timeout=3)
        samples = [r for r in a.log.query() if r["event"] == "path.rtt_sample"]
        assert samples and all(r["fields"]["attempt"] == path.attempt for r in samples)
        assert a.paths[1].closed
        a.link_monitor_active = False
        stamp = path.rtt_measured_at
        path.last_liveness = time.monotonic() - 3
        await asyncio.sleep(1.2)
        assert path.rtt_measured_at == stamp
    finally:
        await cleanup(peers)


async def test_benchmark_suppresses_opt_in_periodic_rtt(peers, monkeypatch):
    a, _ = await cold_pair(peers, monkeypatch)
    try:
        a.link_monitor_active = a.rtt_monitor_enabled = True
        path = a.active_path
        stamp = path.rtt_measured_at
        async with a.speed_lock:
            path.last_liveness = time.monotonic() - 10
            path.last_rx = path.last_tx = time.monotonic() - 13
            previous = path.last_liveness
            await wait_for(lambda: path.last_liveness != previous, timeout=3)
            assert not path.closed
            assert path.rtt_measured_at == stamp
        await wait_for(lambda: path.rtt_measured_at != stamp, timeout=3)
    finally:
        await cleanup(peers)


async def test_busy_transfer_path_is_not_parked_on_switch_and_releases_when_done(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    primary = a.active_path
    try:
        for owner in peers:
            owner.transfers.outgoing["busy-test"] = {"path": owner.active_path, "queue": asyncio.Queue(1)}
        await a.command("/use 1")
        assert a.active_path is a.paths[1]
        assert a.path_busy(primary) and not primary.closed
        for owner in peers:
            owner.transfers.outgoing.pop("busy-test")
        await a.park_idle_paths()
        assert primary.closed
    finally:
        for owner in peers:
            owner.transfers.outgoing.pop("busy-test", None)
        await cleanup(peers)


async def test_peer_only_busy_standby_refuses_park_without_losing_transfer(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    try:
        temporary = await a.ensure_path(a.paths[1])
        await wait_for(lambda: not b.paths[1].closed)
        b.transfers.outgoing["peer-busy"] = {"path": b.paths[1], "queue": asyncio.Queue(1)}
        temporary.lifecycle_pins = 0
        await a.park_idle_paths()
        assert not temporary.closed and not b.paths[1].closed
        b.transfers.outgoing.pop("peer-busy")
        await a.park_idle_paths()
        await wait_for(lambda: temporary.closed and b.paths[1].closed)
    finally:
        b.transfers.outgoing.pop("peer-busy", None)
        await cleanup(peers)


async def test_reopen_offline_or_unknown_source_fails_without_claiming_connection(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    try:
        cold = a.paths[1]
        a.connected.clear()
        with pytest.raises(ConnectionError, match="REOPEN_REQUIRES_SIGNALING"):
            await a.ensure_path(cold)
        assert cold.closed
        a.connected.set()
        with pytest.raises(ValueError, match="SOURCE_UNKNOWN"):
            a.reopen_source("not-a-verified-attempt")
        assert len(a.paths) == len(b.paths) == 2
    finally:
        await cleanup(peers)


async def test_current_link_loss_rebuilds_known_cold_path_for_chat(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    try:
        await asyncio.gather(*(p.active_path.close("TEST_PRIMARY_LOST") for p in peers))
        assert all(not any(not q.closed for q in p.paths) for p in peers)
        await a.chat("on-demand failover after primary loss")
        assert not a.active_path.closed
        assert a.active_path.attempt not in ("cold-test-000-tcp", "cold-test-001-tcp")
        assert any(r["event"] == "path.reopen_verified" for r in a.log.query())
        assert any(r["event"] == "chat.received" for r in b.log.query())
    finally:
        await cleanup(peers)


async def test_concurrent_chat_after_primary_loss_rebuilds_cold_path_once(peers, monkeypatch):
    a, b = await cold_pair(peers, monkeypatch)
    try:
        await asyncio.gather(*(p.active_path.close("TEST_PRIMARY_LOST") for p in peers))
        await asyncio.gather(a.chat("first after loss"), a.chat("second after loss"))
        reopened = [r for r in a.log.query() if r["event"] == "path.reopen_verified"]
        assert len(reopened) == 1
        assert sum(r["event"] == "chat.delivered" for r in a.log.query()) == 2
        assert not a.active_path.closed and a.active_path.lifecycle_pins == 1
        assert any(r["event"] == "chat.received" for r in b.log.query())
    finally:
        await cleanup(peers)


async def test_cold_path_protocol_over_real_signaling_server_and_central_logs(tmp_path, monkeypatch):
    plan = [
        {"attempt": f"wire-cold-{i:03d}-tcp", "method": "tcp", "a_host": "127.0.0.1",
         "b_host": "127.0.0.1", "leader_initiator": True, "phase": "baseline", "profile": "fast"}
        for i in range(2)
    ]
    monkeypatch.setattr("p2plab.experiments.build_plan", lambda *args, **kwargs: plan)
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    peers = [Client({"server": url, "data_dir": str(tmp_path / name), "loopback": True,
                     "logs": {"upload_interval": 0.1, "retry_interval": 0.2},
                     "experiment": {"gateway": False, "diagnostics": False, "stun": [], "timeout": 2},
                     "wan": {"enabled": False}}, "wire-cold", console=False) for name in ("a", "b")]
    tasks = [asyncio.create_task(p.run(interactive=False)) for p in peers]
    try:
        await wait_for(lambda: all(p.manager and p.manager.task and p.manager.task.done() for p in peers), timeout=15)
        assert all(len(p.paths) == 2 and sum(not q.closed for q in p.paths) == 1 for p in peers)
        await peers[1].command("/use 1")
        await wait_for(lambda: all(p.active_path is p.paths[1] and p.paths[0].closed for p in peers))
        await peers[0].ensure_path(peers[0].paths[0])
        await wait_for(lambda: all(not p.paths[0].closed and p.paths[0].pool_managed for p in peers))
        await asyncio.wait_for(peers[0].command("/use 0"), 3)
        await wait_for(lambda: all(p.active_path is p.paths[0] and p.paths[1].closed for p in peers), timeout=3)
        await peers[0].chat("real server cold-path switch")
        await wait_for(lambda: not any(p.log.pending() for p in peers), timeout=5)
        records = journal.query(room="wire-cold")
        assert sum(r["event"] == "path.reopen_verified" for r in records) == 4
        assert any(r["event"] == "chat.delivered" for r in records)
        assert not any(r["event"] == "signaling.error" for r in journal.query())
    finally:
        for peer in peers:
            peer.stop.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        await cleanup_hub(journal, runner, transport, tcp)
