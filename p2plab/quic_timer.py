"""One reusable QUIC deadline, with sub-millisecond wakeups and no polling.

Linux uses timerfd (the kernel timer wakes the loop directly) and macOS uses a NOTE_CRITICAL
kqueue timer. macOS coalesces an asyncio selector timeout to roughly a millisecond, so the plain
call_later fallback cannot honour a sub-millisecond deadline; NOTE_CRITICAL opts the kernel timer
out of that coalescing and brings the wakeup error down to tens of microseconds.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import select
import socket
import sys
import threading
import time

# Darwin's <sys/event.h> timer units and coalescing hint (Python does not export either).
DARWIN_NOTE_NSECONDS = 0x00000004
DARWIN_NOTE_CRITICAL = 0x00000020
DARWIN_TIMER_IDENT = 1


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
        self.kq = None
        self.wake = None
        self.programmed = None
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
        elif precise and sys.platform == "darwin":
            try:
                self.start_kqueue_poller()
            except (AttributeError, OSError):
                self.discard_kqueue()

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

    def start_kqueue_poller(self):
        """Darwin: own the deadline with a NOTE_CRITICAL kqueue timer on a background thread.

        A kqueue fd cannot be handed to loop.add_reader, because KqueueSelector derives its mask
        from the event filter: an EVFILT_TIMER wakeup surfaces with a zero mask and is dropped, so
        the poller thread hands expiry back to the loop with call_soon_threadsafe instead.
        """
        self.kq = select.kqueue()
        self.wake = socket.socketpair()
        for sock in self.wake:
            sock.setblocking(False)
        threading.Thread(target=self.poll, name="p2plab-quic-timer", daemon=True).start()
        self.backend = "darwin-kqueue"

    def discard_kqueue(self):
        """Close kqueue resources directly, for a poller thread that never started."""
        for sock in self.wake or ():
            try:
                sock.close()
            except OSError:
                pass
        if self.kq is not None:
            try:
                self.kq.close()
            except OSError:
                pass
        self.kq = self.wake = None

    def release_kqueue(self):
        """Ask the poller to exit; the thread itself closes the kqueue and the socketpair."""
        wake = self.wake
        if wake is None:
            return
        self.wake = None
        try:
            wake[1].send(b"\0")
        except OSError:
            pass

    def nudge(self):
        """Wake the poller so it re-reads the deadline after arm() changed it."""
        wake = self.wake
        if wake is None:
            return
        try:
            wake[1].send(b"\0")
        except OSError:
            pass

    def programme_timer(self, deadline):
        """Re-arm the kernel timer for `deadline`. Only ever called from the poller thread.

        `programmed` deliberately keeps the armed deadline after the one-shot timer fires, so an
        expiry that has not been consumed by the loop yet cannot be re-armed and fire twice.
        """
        if deadline == self.programmed:
            return
        kq = self.kq
        if kq is None:
            return
        if self.programmed is not None:
            try:
                kq.control(
                    [select.kevent(DARWIN_TIMER_IDENT, select.KQ_FILTER_TIMER, select.KQ_EV_DELETE)], 0, 0
                )
            except OSError:
                pass
        self.programmed = None
        if deadline is None:
            return
        kevent = select.kevent(
            DARWIN_TIMER_IDENT,
            filter=select.KQ_FILTER_TIMER,
            flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
            fflags=DARWIN_NOTE_NSECONDS | DARWIN_NOTE_CRITICAL,
            data=max(1, int((deadline - time.monotonic()) * 1e9)),
        )
        kq.control([kevent], 0, 0)
        self.programmed = deadline

    def fire(self, deadline):
        """Fire only while `deadline` is still current, so a superseded timer stays silent."""
        if self.closed or self.deadline != deadline:
            return
        self.deadline = None
        self.handle = None
        self.callback(deadline)

    def poll(self):
        kq, wake = self.kq, self.wake
        if kq is None or wake is None:
            return
        try:
            kq.control(
                [
                    select.kevent(
                        wake[0].fileno(),
                        select.KQ_FILTER_READ,
                        select.KQ_EV_ADD | select.KQ_EV_ENABLE | select.KQ_EV_CLEAR,
                    )
                ],
                0,
                0,
            )
            while not self.closed:
                try:
                    self.programme_timer(self.deadline)
                    events = kq.control(None, 4, None)
                except OSError:
                    break
                for event in events:
                    if event.filter == select.KQ_FILTER_READ:
                        try:
                            wake[0].recv(4096)
                        except OSError:
                            pass
                    elif event.filter == select.KQ_FILTER_TIMER:
                        try:
                            self.loop.call_soon_threadsafe(self.fire, self.programmed)
                        except RuntimeError:
                            return
        except OSError:
            pass
        finally:
            for sock in wake:
                try:
                    sock.close()
                except OSError:
                    pass
            try:
                kq.close()
            except OSError:
                pass
            self.kq = self.wake = None

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
        elif self.wake is not None:
            # The poller thread owns the kernel timer on macOS, so nudging it is enough.
            self.nudge()
            return
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
        self.release_kqueue()
