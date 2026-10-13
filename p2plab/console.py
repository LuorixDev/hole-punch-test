"""Bounded Windows console input without asyncio's unsupported TTY pipe transport."""

import asyncio
import threading


class ConsoleReader:
    def __init__(self, source):
        self.source = source
        self.loop = asyncio.get_running_loop()
        self.queue = asyncio.Queue(maxsize=16)
        self.stopped = threading.Event()
        self.pending = None

    def start(self):
        # A blocked console read must not keep asyncio's default executor alive on exit.
        threading.Thread(target=self.read, name="console-input", daemon=True).start()

    def read(self):
        while not self.stopped.is_set():
            try:
                line = self.source.readline(65537)
                if isinstance(line, str):
                    line = line.encode("utf-8")
                if len(line) > 65536:
                    raise ValueError("TERMINAL_LINE_LIMIT")
            except Exception as exc:
                line = exc
            if self.stopped.is_set():
                return
            delivery = self.queue.put(line)
            try:
                self.pending = asyncio.run_coroutine_threadsafe(delivery, self.loop)
            except RuntimeError:
                delivery.close()
                return
            try:
                self.pending.result()
            except Exception:
                return
            if not line or isinstance(line, Exception):
                return

    async def readline(self):
        line = await self.queue.get()
        if isinstance(line, Exception):
            raise line
        return line

    def close(self):
        self.stopped.set()
        if self.pending:
            self.pending.cancel()
