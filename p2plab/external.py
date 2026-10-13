from __future__ import annotations

import asyncio

from .research import Synchronizer


class ExternalAttempt:
    """Optional native/raw backends, never a signaling-server data tunnel."""

    def __init__(self, owner, spec):
        self.owner, self.spec, self.attempt = owner, spec, spec["attempt"]
        if spec["method"] == "utp":
            from .native_utp import UtpAttempt

            self.backend = UtpAttempt(owner, spec, spec["host"])
        else:
            from .raw_probes import IcmpAttempt, NatBlasterAttempt

            cls = IcmpAttempt if spec["method"] == "pwnat" else NatBlasterAttempt
            self.backend = cls(owner, spec, spec["host"])
        self.sync = Synchronizer(owner, self.attempt)
        self._path = None

    @property
    def path(self):
        return self._path or getattr(self.backend, "path", None) or (
            self.backend.quic.path if getattr(self.backend, "quic", None) else None)

    @path.setter
    def path(self, value):
        self._path = value

    def set_candidates(self, candidates):
        self.backend.set_candidates(candidates)

    async def handle(self, data):
        if data["kind"] == "sync" and self.spec["method"] == "utp":
            await self.sync.handle(data)
        else:
            await self.backend.handle(data)

    async def connect(self):
        if self.spec["method"] == "natblaster":
            await self.backend.prepare()
        else:
            await self.backend.open()
            await self.backend.observe(self.owner.observers)
        await self.owner.signal({"kind": "candidate", "attempt": self.attempt,
                                 "candidates": self.backend.candidates})
        await asyncio.wait_for(self.backend.candidates_ready.wait(), self.owner.timeout + 10)
        if self.spec["method"] == "natblaster":
            self.path = await self.backend.connect()
        else:
            if self.spec["method"] == "pwnat":
                await self.backend.warmup()
            await self.backend.punch(self.owner.timeout)
            if self.spec["method"] == "utp":
                await self.sync.synchronize(self.owner.timeout + 10)
                self.path = await self.backend.connect_stream()
            else:
                self.path = await self.backend.start_quic()
        self.path.mechanism = self.spec["method"]
        return self.path

    async def close(self):
        await self.backend.close()
