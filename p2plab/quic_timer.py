"""One reusable QUIC deadline, with sub-millisecond Linux wakeups and no polling."""

from __future__ import annotations

import asyncio
import ctypes
import os
import sys
import time


class Timespec(ctypes.Structure):
    _fields_ = [("seconds", ctypes.c_long), ("nanoseconds", ctypes.c_long)]


class Itimerspec(ctypes.Structure):
    _fields_ = [("interval", Timespec), ("value", Timespec)]


class QuicTimer:
    def __init__(self, callback, *, precise=True):
        self.loop = asyncio.get_running_loop()
        self.callback = callback
        self.deadline = None
        self.handle = None
        self.fd = None
        self.closed = False
        self.backend = "asyncio"
        if precise and sys.platform.startswith("linux"):
            try:
                libc = ctypes.CDLL(None, use_errno=True)
                create = libc.timerfd_create
                create.argtypes, create.restype = [ctypes.c_int, ctypes.c_int], ctypes.c_int
                self.settime = libc.timerfd_settime
                self.settime.argtypes = [ctypes.c_int, ctypes.c_int, ctypes.POINTER(Itimerspec), ctypes.c_void_p]
                self.settime.restype = ctypes.c_int
                fd = create(time.CLOCK_MONOTONIC, os.O_NONBLOCK | os.O_CLOEXEC)
                if fd < 0:
                    raise OSError(ctypes.get_errno(), "timerfd_create")
                self.fd = fd
                self.loop.add_reader(fd, self.expire)
                self.backend = "linux-timerfd"
            except (AttributeError, OSError, NotImplementedError):
                self.release_fd()

    def release_fd(self):
        if self.fd is not None:
            fd = self.fd
            self.fd = None
            try:
                self.loop.remove_reader(fd)
            except (OSError, NotImplementedError):
                pass
            finally:
                os.close(fd)

    def arm(self, deadline):
        if self.closed or deadline == self.deadline:
            return
        if self.handle:
            self.handle.cancel()
            self.handle = None
        self.deadline = deadline
        if self.fd is not None:
            spec = Itimerspec()
            if deadline is not None:
                # Zero disarms timerfd; an expired nonzero absolute time fires immediately.
                nanos = max(1, int(deadline * 1_000_000_000))
                spec.value.seconds, spec.value.nanoseconds = divmod(nanos, 1_000_000_000)
            if self.settime(self.fd, 1, ctypes.byref(spec), None) == 0:
                return
            self.release_fd()
            self.backend = "asyncio-fallback"
        if deadline is not None:
            self.handle = self.loop.call_later(max(0, deadline - time.monotonic()), self.expire)

    def expire(self):
        if self.closed:
            return
        if self.fd is not None:
            try:
                os.read(self.fd, 8)
            except BlockingIOError:
                return
        deadline = self.deadline
        self.deadline = None
        self.handle = None
        if deadline is not None:
            self.callback(deadline)

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.handle:
            self.handle.cancel()
        self.release_fd()
