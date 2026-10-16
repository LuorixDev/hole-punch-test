import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from textual.widgets import Button, DataTable, Input, Select, Static, TabbedContent

from p2plab.client import Client
from p2plab.experiments import scheme_explanation
from p2plab.journal import Journal
from p2plab.tui import DetailScreen, JoinScreen, LogReader, P2PApp
from tests.test_server import cleanup_hub, start_hub


def save_preview(app, name):
    destination = os.environ.get("P2PLAB_TUI_ARTIFACTS")
    if destination:
        Path(destination).mkdir(parents=True, exist_ok=True)
        app.save_screenshot(filename=name + ".svg", path=destination)


def session_diagnostics(app, peer):
    def recent_events(client):
        with client.log.lock:
            cursor = client.log.db.execute("SELECT COALESCE(MAX(seq),0) FROM events").fetchone()[0]
        return client.log.query(after=max(0, cursor - 60), limit=60)

    return json.dumps({name: {
        "batch_state": client.batch_speed_state,
        "matrix_results": client.manager.results[-4:] if client.manager else [],
        "matrix_count": len(client.manager.results) if client.manager else 0,
        "matrix_total": len(client.manager.plan) if client.manager else 0,
        "paths": [{"attempt": p.attempt, "closed": p.closed,
                   "speed_state": getattr(p, "speed_state", None)} for p in client.paths],
        "recent_events": recent_events(client),
        "failures": [event for event in client.log.query(limit=1000)
                     if event["event"] in ("speed.batch_path_failed", "path.reopen_failed", "runtime.asyncio_error")],
    } for name, client in (("tui", app.client), ("peer", peer))}, ensure_ascii=False, default=str)


def test_readonly_logs_filter_page_and_reassemble_without_losing_fields(tmp_path):
    journal = Journal(tmp_path / "journal.db", role="client", console=False)
    for index in range(205):
        journal.event("sample", index=index)
    record = journal.event("network.large", "大记录", payload="地址参数" * 20000, token="secret")
    reader = LogReader(tmp_path / "journal.db")
    try:
        newest = reader.browse(limit=100)
        older = reader.browse(before=min(r["cursor"] for r in newest), limit=100)
        assert len(newest) == len(older) == 100
        assert {r["cursor"] for r in newest}.isdisjoint(r["cursor"] for r in older)
        fragment = next(r for r in newest if r["event"] == "journal.fragment")
        full = reader.detail(fragment["cursor"])
        assert full["fields"] == record["fields"]
        assert full["fields"]["token"] == "[redacted]"
        assert full["reassembled_fragments"] > 1
        assert len(reader.browse(search='"index":17', limit=1000)) >= 1
        assert reader.browse(level="ERROR") == []
        assert reader.stats()["pending"] == reader.stats()["total"]
        with pytest.raises(Exception, match="readonly"):
            reader.db.execute("DELETE FROM events")
        journal.close()
        assert reader.detail(fragment["cursor"])["fields"] == record["fields"]
    finally:
        reader.close()
        if not journal.closed:
            journal.close()


async def test_activity_history_survives_hidden_writes_resize_and_repeated_tab_changes(peers):
    from p2plab.tui import HistoryLog

    client, _ = peers
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=(112, 34)) as pilot:
        client.log.event("signaling.connected", "历史消息-A")
        app.refresh_state()
        await pilot.pause()
        sidebar = app.query_one("#activity", HistoryLog)
        async with asyncio.timeout(5):
            while "历史消息-A" not in "".join(s.text for s in sidebar.lines):
                await pilot.pause(0.05)
        assert "历史消息-A" in "".join(s.text for s in sidebar.lines)
        app.action_tab("matrix")
        await pilot.pause()
        for i in range(120):
            client.log.event(
                "experiment.result",
                "后台记录-" + str(i),
                attempt="matrix-001-quic",
                state="success",
                method="quic",
                a_host="2001:4860::1",
            )
        app.refresh_state()
        await pilot.pause()
        assert len(sidebar.history) >= 121
        assert "历史消息-A" in "".join(s.text for s in sidebar.lines)
        app.receive_chat("对端", "隐藏页面收到的聊天")
        for tab in ("network", "paths", "settings", "chat"):
            app.action_tab(tab)
            await pilot.pause()
        rendered = "".join(s.text for s in sidebar.lines)
        assert "历史消息-A" in rendered and "后台记录-119" in rendered
        assert "IPv6 QUIC打洞" in rendered
        assert "隐藏页面收到的聊天" in "".join(s.text for s in app.query_one("#chat-log", HistoryLog).lines)
        await pilot.resize_terminal(80, 24)
        await pilot.pause()
        await pilot.resize_terminal(112, 34)
        await pilot.pause()
        assert "历史消息-A" in "".join(s.text for s in sidebar.lines)
        save_preview(app, "activity-history-restored")


async def test_activity_rollover_renders_only_new_entries_and_keeps_wrapped_history(monkeypatch):
    from rich.text import Text
    from textual.app import App
    from textual.widgets import RichLog

    from p2plab.tui import HistoryLog

    class LogApp(App):
        def compose(self):
            yield HistoryLog(id="history", wrap=True, min_width=1, history_limit=20)

    writes = []
    original = RichLog.write

    def write(widget, content, **kwargs):
        writes.append(content.plain)
        return original(widget, content, **kwargs)

    monkeypatch.setattr(RichLog, "write", write)
    app = LogApp()
    async with app.run_test(size=(60, 12)) as pilot:
        log = app.query_one(HistoryLog)
        for index in range(20):
            log.append_entry(Text(f"entry-{index:03d}\n" + "中文测试" * 30))
        log.flush_history()
        await pilot.pause()
        assert "entry-000" in log._render_line(0, 0, 60).text
        log.scroll_to(y=10, animate=False, immediate=True)
        await pilot.pause()
        removed_lines = log.rendered_entries[0][1] if log.rendered_entries else 0
        writes.clear()
        log.append_entry(Text("entry-020\nnew-tail"))
        log.flush_history()
        await pilot.pause()
        assert len(writes) == 1, "Rollover must not rerender the retained history"
        rendered = "\n".join(strip.text for strip in log.lines)
        assert "entry-000" not in rendered
        assert "entry-001" in rendered and "entry-020" in rendered
        assert "entry-001" in log._render_line(0, 0, 60).text
        assert log.scroll_y == max(0, 10 - removed_lines)
        await pilot.resize_terminal(45, 12)
        await pilot.pause()
        rendered = "\n".join(strip.text for strip in log.lines)
        assert "entry-000" not in rendered and "entry-001" in rendered and "new-tail" in rendered
        log.display = False
        await pilot.pause()
        for index in range(21, 66):
            log.append_entry(Text(f"entry-{index:03d}\nhidden-tail"))
        log.flush_history()
        log.display = True
        await pilot.pause()
        rendered = "\n".join(strip.text for strip in log.lines)
        assert "entry-020" not in rendered and "entry-045" not in rendered
        assert "entry-046" in rendered and "entry-065" in rendered
        assert len(log.rendered_entries) == 20
        assert sum(count for _, count in log.rendered_entries) == len(log.lines)


@pytest.mark.parametrize("size", [(80, 24), (140, 40)])
async def test_matrix_distinguishes_bind_addresses_and_missing_public_candidates(peers, size):
    client, _ = peers
    spec = {"attempt": "missing-mapping", "method": "quic", "a_host": "192.168.67.1",
            "b_host": "192.168.1.233", "leader_initiator": True, "phase": "baseline", "profile": "fast"}
    evidence = {"local_candidates": [["192.168.67.1", 56422]],
                "remote_candidates": [["125.111.10.112", 47629]],
                "diagnosis": "LOCAL_PUBLIC_UDP_MAPPING_MISSING"}
    result = {"attempt": spec["attempt"], "state": "failed", "data_path": False,
              "reason": "TimeoutError:UDP_AUTHENTICATED_PUNCH_TIMEOUT", "candidate_evidence": evidence}
    client.manager = SimpleNamespace(plan=[spec], results=[result], remote_done={})
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=size) as pilot:
        app.action_tab("matrix")
        await pilot.pause()
        table = app.query_one("#attempts", DataTable)
        assert "本端未获取公网 UDP 映射" in table.get_row(spec["attempt"])[-1].plain
        table.focus()
        table.move_cursor(row=0)
        await pilot.pause()
        selection = app.query_one("#matrix-selection", Static)
        text = str(selection.content)
        assert "绑定：协调端 192.168.67.1" in text
        assert "对端候选：[125.111.10.112]:47629" in text
        assert selection.content.no_wrap
        assert selection.region.bottom <= size[1]
        save_preview(app, f"matrix-candidate-evidence-{size[0]}")


async def test_banner_displays_both_peers_addresses_and_honest_http_inbound_state(peers):
    from datetime import datetime, timedelta, timezone

    from p2plab.status import utcnow
    from tests.test_status_wan import status

    client, _ = peers
    client.network = {
        "address_inventory": [
            {
                "address": "2001:4860::1",
                "family": 6,
                "interface": "eth0",
                "state": "preferred",
                "type": "temporary",
            },
            {"address": "192.168.1.2", "family": 4, "interface": "eth0", "state": "preferred"},
        ]
    }
    client.server_observed_ipv4 = "8.8.8.8"
    client.inbound_results = {
        "2001:4860::1": {
            "address": "2001:4860::1",
            "code": "REACHABLE",
            "listener_received": True,
            "tested_at": utcnow(),
        },
        "2001:4860::2": {
            "address": "2001:4860::2",
            "code": "TIMEOUT_INCONCLUSIVE",
            "listener_received": False,
            "tested_at": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        },
    }
    client.peer_network = status(family=6)
    client.peer_network["nat"] = {
        "state": "classified",
        "level": 4,
        "label": "NAT4 目的相关映射",
        "evidence": ["同 socket 不同目标映射不同"],
        "tested_at": utcnow(),
    }
    client.nat_probe = {
        "attempt": "nat-local",
        "local": ["192.168.1.2", 49000],
        "mapping": "endpoint-independent-observed",
        "filtering": "endpoint-independent-observed",
        "samples": [],
        "tested_at": utcnow(),
    }
    client.peer_network["inbound"] = [
        {
            "address": "2001:4860::1",
            "code": "TIMEOUT_INCONCLUSIVE",
            "listener_received": False,
            "tested_at": utcnow(),
        }
    ]
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=(112, 34)) as pilot:
        await pilot.pause()
        banner = str(app.query_one("#network-banner", Static).content)
        assert all(value in banner for value in ("本机", "对端", "192.168.1.2", "8.8.8.8", "2001:4860::1"))
        assert "临时·HTTP可达" in banner
        assert "稳定·未确认" in banner
        assert "入站：IPv4 未测 / IPv6 HTTP可达" in banner
        assert "入站：IPv4 未测 / IPv6 已探测·未确认" in banner
        assert "NAT2 完全锥形" in banner and "NAT4 目的相关映射" in banner
        assert "阻止" not in banner and "防火墙关闭" not in banner
        assert app.query_one("#network-banner", Static).content.no_wrap is True
        assert "2001:4860::1" in str(app.query_one("#network-banner", Static).tooltip)


async def test_path_rows_mark_directional_ninety_percent_and_remove_stale_marks(peers):
    from tests.test_status_wan import status

    client, _ = peers
    client.network = {
        "address_inventory": [
            {
                "address": "2001:4860::1",
                "family": 6,
                "state": "preferred",
                "interface": "eth0",
                "type": "stable",
            }
        ]
    }
    client.wan_options = {"upload_mbps": 100, "download_mbps": 1000}
    client.peer_network = status(upload=50, download=80, basis="configured")
    ready = asyncio.Event()
    ready.set()
    path = SimpleNamespace(
        attempt="speed-ui",
        family=6,
        mechanism="quic",
        ready=ready,
        closed=False,
        last_rtt=None,
        rtt_measured_at=None,
        rtt_state="not-measured",
        peer={},
        speed_state="success",
        speed_run="one",
        latest_speed={
            "local-to-peer": {"mbps": 72, "seconds": 2, "measurement_run": "one"},
            "peer-to-local": {"mbps": 46, "seconds": 2, "measurement_run": "one"},
        },
    )
    client.paths = [path]
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=(112, 34)) as pilot:
        app.action_tab("paths")
        await pilot.pause()
        table = app.query_one("#path-table", DataTable)
        assert "≥90%上限" in table.get_row("0")[7].plain
        assert "≥90%上限" in table.get_row("0")[8].plain
        assert "速度瓶颈" in str(table.columns)
        assert "未确定" in table.get_row("0")[9].plain
        from tests.test_performance import measurement
        path.latest_speed["local-to-peer"].update(measurement())
        path.latest_speed["local-to-peer"]["sender_runtime"]["event_loop_core_fraction"] = .95
        path.latest_speed["local-to-peer"]["mbps"] = 72
        app.refresh_state()
        assert "实现限制" in table.get_row("0")[9].plain
        assert "speed_bottlenecks" in app.details["path-table"]["0"]
        path.latest_speed["local-to-peer"]["short_sample"] = True
        app.refresh_state()
        assert "≥90%" not in table.get_row("0")[7].plain
        path.latest_speed["peer-to-local"]["measurement_run"] = "previous"
        app.refresh_state()
        assert "旧" in table.get_row("0")[8].plain and "≥90%" not in table.get_row("0")[8].plain
        client.peer_network["updated_at"] = "2000-01-01T00:00:00+00:00"
        app.refresh_state()
        assert "≥90%" not in table.get_row("0")[7].plain
        save_preview(app, "directional-wan-reference")


@pytest.mark.parametrize("size", [(112, 34), (80, 24), (60, 24), (160, 48)])
async def test_chinese_tabs_resize_and_full_record_inspection(peers, size):
    client, _ = peers
    spec = {
        "attempt": "ui-attempt",
        "method": "quic",
        "profile": "fast",
        "phase": "baseline",
        "leader_initiator": True,
        "datagram_size": 1400,
        "a_host": "2001:db9:a::2",
        "b_host": "2001:db9:b::2",
    }
    client.manager = SimpleNamespace(plan=[spec], results=[], remote_done={}, task=None)
    client.network = {
        "address_inventory": [
            {
                "address": "2001:db9:a::2",
                "family": 6,
                "interface": "eth0",
                "type": "temporary",
                "state": "preferred",
                "mtu": 1280,
                "preferred_lifetime": 300,
                "valid_lifetime": 600,
            }
        ],
        "addresses": [],
    }
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        assert app.query_one("#message", Input).region.bottom <= size[1]
        assert app.query_one("#message", Input).region.width > 10
        for name in ("ping", "speed", "net", "retry", "quit"):
            assert app.query_one("#" + name).region.right <= size[0]
        save_preview(app, f"layout-{size[0]}x{size[1]}")
        app.action_tab("matrix")
        await pilot.pause()
        assert app.query_one("#attempts", DataTable).row_count == 1
        table = app.query_one("#attempts", DataTable)
        assert [column.label.plain for column in table.ordered_columns][-2:] == ["方案解释", "原因"]
        assert "IPv6 入站打洞" in table.get_row("ui-attempt")[-2].plain
        table.focus()
        await pilot.press("enter")
        await pilot.pause()
        assert isinstance(app.screen, DetailScreen)
        assert app.screen.document["尝试参数"]["datagram_size"] == 1400
        assert "QUIC" in app.screen.document["方案解释"]
        assert "2001:db9:a::2" in str(app.screen.query_one("#detail-body", Static).content)
        await pilot.pause(0.6)
        save_preview(app, f"detail-{size[0]}x{size[1]}")
        await pilot.press("escape")
        for tab in ("chat", "network", "paths", "logs", "settings"):
            app.action_tab(tab)
            await pilot.pause()
            assert app.query_one("#views", TabbedContent).active == tab
        assert app.query_one("#settings-table", DataTable).row_count >= 20
        assert app.query_one("#addresses", DataTable).row_count == 1


@pytest.mark.parametrize("size", [(60, 24), (80, 24), (160, 48)])
async def test_measurement_controls_belong_to_their_tabs_and_live_rtt_is_enabled(peers, size):
    client, _ = peers
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=size) as pilot:
        await pilot.pause()
        assert app.query_one("#toolbar").is_on_screen
        app.action_tab("matrix")
        await pilot.pause()
        for name in ("ping", "speed", "net", "retry", "quit", "message"):
            assert not app.query_one("#" + name).is_on_screen
        app.action_tab("paths")
        await pilot.pause()
        assert client.link_monitor_active
        assert not client.rtt_monitor_enabled
        await pilot.click("#path-rtt-monitor")
        assert client.rtt_monitor_enabled
        assert str(app.query_one("#speed-all", Button).label) == "批量测速"
        for name in ("speed-all", "use-path", "path-speed-size"):
            widget = app.query_one("#" + name)
            assert widget.is_on_screen and widget.region.right <= size[0] and widget.region.bottom <= size[1]
        app.action_tab("chat")
        await pilot.pause()
        assert not client.link_monitor_active
        assert app.query_one("#ping").is_on_screen


async def test_both_speed_directions_and_live_log_order_survive_one_refresh(peers):
    client, _ = peers
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test() as pilot:
        client.log.event("speed.result", direction="local-to-peer", mbps=12.5)
        client.log.event("speed.result", direction="peer-to-local", mbps=25.5)
        client.log.event("ping.result", mean_ms=2.25, min_ms=1.5, max_ms=3)
        app.refresh_state()
        assert app.latest["speed.local-to-peer"]["fields"]["mbps"] == 12.5
        assert app.latest["speed.peer-to-local"]["fields"]["mbps"] == 25.5
        assert "25.50" in str(app.query_one("#measurements", Static).content)
        client.log.event("last.event")
        app.refresh_state()
        table = app.query_one("#log-table", DataTable)
        assert table.ordered_rows[0].key.value == str(app.reader.stats()["cursor"])
        app.action_tab("logs")
        app.query_one("#log-search", Input).value = "ping.result"
        await pilot.pause()
        assert len(app.log_rows) == 1
        assert app.log_rows[0]["event"] == "ping.result"
        app.query_one("#log-level", Select).value = "ERROR"
        await pilot.pause()
        assert app.log_rows == []


async def test_chat_content_stays_p2p_only_and_command_errors_are_durable(peers):
    client, _ = peers
    commands = []

    async def command(text):
        commands.append(text)
        if text == "/ping":
            raise ConnectionError("NO_AUTHENTICATED_P2P_DATA_PATH_YET")

    client.command = command
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test() as pilot:
        app.query_one("#message", Input).value = "秘密聊天 [bold] \x1b payload"
        await pilot.press("enter")
        await pilot.pause()
        assert commands == ["秘密聊天 [bold] \x1b payload"]
        assert app.query_one("#message", Input).value == ""
        app.submit_command("/ping")
        await pilot.pause()
        records = client.log.query()
        assert any(r["event"] == "terminal.command_failed" for r in records)
        assert "秘密聊天" not in json.dumps(records, ensure_ascii=False)
        assert "chat" not in app.busy and "/ping" not in app.busy


async def test_room_form_validates_and_cancels_without_backend():
    app = P2PApp({"server": "ws://127.0.0.1:8443/ws"})
    async with app.run_test(size=(80, 24)) as pilot:
        await pilot.pause()
        assert isinstance(app.screen, JoinScreen)
        await pilot.press("enter")
        assert app.client is None
        assert "1–64" in str(app.screen.query_one("#join-error", Static).content)
        await pilot.click("#cancel-join")


async def test_busy_chat_keeps_unsent_input_and_history_page_does_not_jump(peers):
    client, _ = peers
    for index in range(205):
        client.log.event("page.sample", index=index)
    current = client.log.run
    client.log.run = "past-run"
    client.log.event("past.event")
    client.log.run = current
    app = P2PApp(client=client, start_backend=False)
    async with app.run_test(size=(112, 34)) as pilot:
        await pilot.pause()
        app.busy.add("chat")
        app.query_one("#message", Input).value = "等待发送的消息"
        await pilot.press("enter")
        assert app.query_one("#message", Input).value == "等待发送的消息"
        app.busy.clear()
        app.action_tab("logs")
        await pilot.pause()
        assert await pilot.click("#log-older")
        async with asyncio.timeout(5):
            while app.page_before is None:
                await pilot.pause(0.05)
        frozen = [r["cursor"] for r in app.log_rows]
        assert app.page_before is not None
        client.log.event("later.event")
        app.refresh_state()
        assert [r["cursor"] for r in app.log_rows] == frozen
        assert await pilot.click("#log-newer")
        async with asyncio.timeout(5):
            while app.page_before is not None:
                await pilot.pause(0.05)
        assert app.page_before is None
        assert app.log_rows[0]["event"] == "later.event"
        app.query_one("#log-run", Select).value = "all"
        app.query_one("#log-search", Input).value = "past.event"
        await pilot.pause()
        assert len(app.log_rows) == 1 and app.log_rows[0]["run"] == "past-run"


async def test_tui_real_client_waiting_shutdown_and_central_log_ack(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    config = {
        "server": url,
        "data_dir": str(tmp_path / "client"),
        "loopback": True,
        "experiment": {"diagnostics": False, "gateway": False, "stun": [], "timeout": 1},
    }
    app = P2PApp(config, room="tui-live")
    try:
        async with app.run_test(size=(112, 34)) as pilot:
            async with asyncio.timeout(10):
                while not app.client or not app.client.connected.is_set():
                    await pilot.pause(0.05)
            await pilot.pause()
            app.refresh_state()
            assert "在线" in str(app.query_one("#status", Static).content)
            assert app.client.chat_display is not None
            assert app.client.log.console is False
            app.action_quit()
            await asyncio.wait_for(app.backend_task, 10)
        assert app.client.closed
        records = journal.query(room="tui-live")
        assert any(r["event"] == "client.started" for r in records)
        assert any(r["event"] == "client.stopped" for r in records)
        reader = LogReader(tmp_path / "client/client.sqlite3")
        pending = reader.db.execute("SELECT journal_json(document) FROM events WHERE acked=0").fetchall()
        # The in-process test hub may emit its access log after the final drain.
        assert all(json.loads(doc)["event"] == "runtime.log" for (doc,) in pending)
        reader.close()
    finally:
        await cleanup_hub(journal, runner, transport, tcp)


async def test_tui_real_p2p_chat_ping_and_bidirectional_speed(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    config = {
        "server": url,
        "loopback": True,
        "experiment": {
            "diagnostics": False,
            "gateway": False,
            "stun": [],
            "timeout": 1,
            "profiles": ["fast"],
            "max_pairs": 1,
            "port_prediction": False,
        },
    }
    peer = Client({**config, "name": "B", "data_dir": str(tmp_path / "b")}, "tui-p2p", console=False)
    app = P2PApp({**config, "name": "A", "data_dir": str(tmp_path / "a")}, room="tui-p2p")
    peer_task = asyncio.create_task(peer.run(interactive=False))
    try:
        async with app.run_test(size=(112, 34)) as pilot:
            async with asyncio.timeout(30):
                while not app.client or not app.client.paths:
                    await pilot.pause(0.1)
            app.submit_command("真实 TUI P2P 消息")
            app.submit_command("/ping")
            async with asyncio.timeout(30):
                while app.busy:
                    await pilot.pause(0.1)
            async with asyncio.timeout(30):
                while (
                    not app.client.manager
                    or not app.client.manager.task.done()
                    or not peer.manager
                    or not peer.manager.task.done()
                ):
                    await pilot.pause(0.1)
            app.submit_command("/speed 1")
            async with asyncio.timeout(30):
                while "/speed" in app.busy:
                    await pilot.pause(0.1)
            app.refresh_state()
            assert "ping.result" in app.latest
            assert app.latest["speed.local-to-peer"]["fields"]["bytes"] == 1024 * 1024
            assert app.latest["speed.peer-to-local"]["fields"]["bytes"] == 1024 * 1024
            assert app.query_one("#path-table", DataTable).row_count >= 1
            assert any(r["event"] == "chat.received" for r in peer.log.query())
            attachment = tmp_path / "private-file.txt"
            attachment.write_bytes(b"PRIVATE_FILE_CONTENT_NO_CENTRAL_RELAY")
            app.submit_command("/file " + str(attachment))
            async with asyncio.timeout(10):
                while "/file" in app.busy:
                    await pilot.pause(0.05)
            sent = next(iter(app.client.transfers.records.values()))
            assert sent["state"] == "completed"
            received = peer.transfers.records[sent["id"]]
            assert Path(received["saved_path"]).read_bytes() == attachment.read_bytes()
            assert sent["received_at"] == received["received_at"]
            async with asyncio.timeout(10):
                while not {"file.received", "file.delivered"} <= {r["event"] for r in journal.query()}:
                    await pilot.pause(0.1)
            central = json.dumps(journal.query(), ensure_ascii=False)
            assert "PRIVATE_FILE_CONTENT_NO_CENTRAL_RELAY" not in central
            assert "file.delivered" in central
            assert "receiver_seconds" in central and "received_at" in central
            try:
                async with asyncio.timeout(180):
                    while not app.client.manager.results or len(app.client.manager.results) < len(
                        app.client.manager.plan
                    ):
                        await pilot.pause(0.1)
            except TimeoutError:
                pytest.fail(session_diagnostics(app, peer))
            results = app.client.manager.results
            assert any(r["method"] == "quic" and r["data_path"] for r in results)
            assert any(
                r["method"] == "webrtc" and r["parameters"]["profile"] == "4" and r["data_path"]
                for r in results
            )
            assert all(r["scheme_explanation"] for r in results)
            active = app.client.active_path
            app.action_tab("paths")
            await pilot.pause()
            app.submit_command("/speed-all 1")
            try:
                async with asyncio.timeout(180):
                    while "/speed-all" in app.busy:
                        await pilot.pause(0.1)
            except TimeoutError:
                pytest.fail(session_diagnostics(app, peer))
            assert app.client.active_path is active
            assert app.client.batch_speed_state["completed"] == app.client.batch_speed_state["total"]
            assert app.client.batch_speed_state["failed"] == 0, session_diagnostics(app, peer)
            assert all("peer-to-local" in p.latest_speed for p in app.client.paths if not p.closed)
            app.refresh_state()
            save_preview(app, "live-batch-speed")
            records = app.client.log.query(limit=1000) + peer.log.query(limit=1000)
            assert not any(
                r["event"]
                in (
                    "quic.application_failed",
                    "webrtc.application_failed",
                    "experiment.signal_failed",
                    "runtime.asyncio_error",
                )
                for r in records
            )
            assert "真实 TUI P2P 消息" not in json.dumps(journal.query(), ensure_ascii=False)
            save_preview(app, "live-chat")
            for tab in ("matrix", "network", "paths", "logs", "settings"):
                app.action_tab(tab)
                await pilot.pause()
                save_preview(app, "live-" + tab)
            app.action_quit()
            await asyncio.wait_for(app.backend_task, 10)
    finally:
        peer.stop.set()
        await asyncio.wait_for(peer_task, 10)
        await cleanup_hub(journal, runner, transport, tcp)


@pytest.mark.parametrize(
    "method,family,profile,expected",
    [
        ("udp", 6, "fast", "仅认证探测"),
        ("udp", 4, "fast", "NAT 映射与过滤行为"),
        ("quic", 6, "fast", "QUIC 加密可靠流"),
        ("quic", 4, "fast", "IPv4 NAT 打洞"),
        ("tcp", 6, "fast", "未主动打开双向入站状态"),
        ("tcp", 4, "fast", "IPv4 TCP 直连"),
        ("tcp-simopen", 6, "fast", "双方从各自绑定端口主动发 SYN"),
        ("tcp-simopen", 4, "fast", "不是普通单向直连"),
        ("prediction", 4, "fast", "有限预测"),
        ("webrtc", 4, "dual", "IPv4/IPv6 双栈"),
        ("webrtc", 4, "4", "IPv4 WebRTC"),
        ("webrtc", 6, "6", "IPv6 WebRTC"),
        ("pinhole", 6, "fast", "IPv6 UPnP 防火墙开孔"),
        ("upnp", 4, "fast", "IPv4 UPnP 端口映射"),
        ("natpmp", 4, "fast", "IPv4 NAT-PMP 端口映射"),
        ("pcp", 4, "fast", "IPv4 PCP 端口映射"),
        ("pcp", 6, "fast", "IPv6 PCP 入站放行"),
    ],
)
def test_scheme_explanations_distinguish_address_family_and_mechanism(method, family, profile, expected):
    spec = {"method": method, "profile": profile, "a_host": "2001:db8::1" if family == 6 else "192.0.2.1"}
    explanation = scheme_explanation(spec)
    assert expected in explanation
    assert "全锥型" not in explanation and "对称型" not in explanation
