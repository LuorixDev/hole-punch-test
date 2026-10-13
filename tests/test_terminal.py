import asyncio
import os
import sys
from types import SimpleNamespace

import pytest

from p2plab.client import Client
from p2plab.journal import Journal


@pytest.mark.asyncio
async def test_pty_input_does_not_make_shared_terminal_output_nonblocking(monkeypatch):
    master, slave = os.openpty()
    source = os.fdopen(slave, "rb", buffering=0)
    ready, stop = asyncio.Event(), asyncio.Event()
    received = []

    def event(name, *args, **kwargs):
        if name == "terminal.ready":
            ready.set()

    async def command(text):
        received.append(text)
        stop.set()

    client = SimpleNamespace(stop=stop, log=SimpleNamespace(event=event), terminal_command=command)
    monkeypatch.setattr(sys, "stdin", source)
    task = asyncio.create_task(Client.terminal(client))
    try:
        await asyncio.wait_for(ready.wait(), 3)
        assert os.get_blocking(slave)
        os.write(master, b"hello from PTY\n")
        await asyncio.wait_for(task, 3)
        assert received == ["hello from PTY\n"]
        assert not source.closed
        assert os.get_blocking(slave)
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        source.close()
        os.close(master)


@pytest.mark.parametrize("error", [BlockingIOError(11, "busy"), BrokenPipeError(32, "closed")])
def test_console_error_cannot_abort_durable_logging(tmp_path, monkeypatch, error):
    journal = Journal(tmp_path / "journal.sqlite3", role="client")

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr("builtins.print", fail)
    try:
        result = journal.event("experiment.started")
        journal.event("experiment.completed")
        assert result["event"] == "experiment.started"
        assert [record["event"] for record in journal.pending()] == [
            "experiment.started",
            "terminal.output_failed",
            "experiment.completed",
        ]
        assert journal.console is False
    finally:
        journal.close()
