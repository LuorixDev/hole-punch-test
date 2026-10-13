import asyncio
from pathlib import Path

import pytest
from rich.console import Console
from textual.widgets import Button, DataTable, Input

from p2plab.transfers import receipt
from p2plab.tui import AttachmentScreen, HistoryLog, P2PApp, message_metrics_text
from tests.test_transfers import connected
from tests.test_tui import save_preview


def test_receipt_labels_gray_italic_and_numbers_colored_italic():
    text = message_metrics_text(receipt(1024, 0.1, received_at="2026-10-13T10:11:12.345+00:00"))
    segments = list(Console().render(text))
    labels = [s for s in segments if "接收" in s.text or "均速" in s.text or "耗时" in s.text]
    assert labels and all(s.style.italic and s.style.color.triplet.hex == "#859096" for s in labels)
    numbers = [s for s in segments if any(c.isdigit() for c in s.text)]
    assert numbers and all(s.style.italic for s in numbers)
    assert {s.style.color.triplet.hex for s in numbers} == {"#79b8ff", "#e5c46d", "#7dd7bc"}
    assert "10-13" in text.plain and "Mbps" in text.plain and "ms" in text.plain


@pytest.mark.parametrize("size", [(60, 24), (80, 24), (112, 34), (160, 48)])
async def test_picker_transfers_metrics_history_and_layout(peers, tmp_path, size):
    a, b = peers
    source = tmp_path / "attachment with spaces.txt"
    source.write_bytes(b"test attachment")
    async with connected(peers):
        app = P2PApp(client=a, start_backend=False)
        async with app.run_test(size=size) as pilot:
            await pilot.pause()
            for name in ("message", "attach-file", "attach-image", "send"):
                widget = app.query_one("#" + name)
                assert (
                    widget.is_on_screen and widget.region.right <= size[0] and widget.region.bottom <= size[1]
                )
            await pilot.click("#attach-file")
            await pilot.pause()
            assert isinstance(app.screen, AttachmentScreen)
            app.screen.query_one("#attachment-path", Input).value = str(source)
            await pilot.click("#attachment-confirm")
            await pilot.pause()
            assert not isinstance(app.screen, AttachmentScreen)
            async with asyncio.timeout(5):
                while not any(r["state"] == "completed" for r in a.transfers.records.values()):
                    await pilot.pause(0.02)
            saved = next(iter(b.transfers.records.values()))
            assert Path(saved["saved_path"]).read_bytes() == source.read_bytes()
            await pilot.press("ctrl+7")
            await pilot.pause()
            app.refresh_state()
            assert app.query_one("#transfer-table", DataTable).row_count == 1
            for name in (
                "transfer-accept",
                "transfer-reject",
                "transfer-cancel",
                "transfer-view",
                "transfer-directory",
            ):
                widget = app.query_one("#" + name)
                assert (
                    widget.is_on_screen and widget.region.right <= size[0] and widget.region.bottom <= size[1]
                )
            app.receive_chat("对端", "后台收到的带统计消息", receipt(1024, 0.1))
            app.action_tab("chat")
            await pilot.pause()
            history = app.query_one("#chat-log", HistoryLog)
            rendered = "".join(s.text for s in history.lines)
            assert "后台收到的带统计消息" in rendered and "Mbps" in rendered and "attachment" in rendered
            assert app.effective_settings()["transfer"]["download_dir"] == str(a.transfers.directory)
            save_preview(app, f"attachments-chat-{size[0]}x{size[1]}")


async def test_receiver_table_accept_and_view_image(peers, tmp_path, monkeypatch):
    a, b = peers
    b.transfers.auto_accept = False
    source = tmp_path / "image.png"
    source.write_bytes(b"\x89PNG\r\n\x1a\n" + bytes(32))
    opened = []

    async def desktop(target):
        opened.append(target)

    monkeypatch.setattr(b, "open_desktop", desktop)
    async with connected(peers) as (pa, _):
        app = P2PApp(client=b, start_backend=False)
        async with app.run_test(size=(112, 34)) as pilot:
            sending = asyncio.create_task(a.transfers.send(pa, source, image=True))
            async with asyncio.timeout(5):
                while not b.transfers.incoming:
                    await pilot.pause(0.02)
            app.action_tab("transfers")
            app.refresh_state()
            await pilot.pause()
            assert not app.query_one("#transfer-accept", Button).disabled
            await pilot.click("#transfer-accept")
            await asyncio.wait_for(sending, 5)
            app.refresh_state()
            await pilot.pause()
            assert not app.query_one("#transfer-view", Button).disabled
            assert app.query_one("#transfer-cancel", Button).disabled
            save_preview(app, "received-image-transfer-table")
            await pilot.click("#transfer-view")
            await pilot.pause()
            assert opened and opened[0].suffix == ".png"
            app.action_tab("chat")
            await pilot.pause()
            assert "[图片]" in "".join(s.text for s in app.query_one("#chat-log", HistoryLog).lines)
