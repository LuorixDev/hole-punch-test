from __future__ import annotations

import asyncio
import ctypes as C
import ctypes.util
import ipaddress
import os
import socket
import struct
from collections import deque
from pathlib import Path

from .encrypted_stream import EncryptedStream
from .udp import MAGIC, UdpAttempt


class Value(C.Union):
    _fields_ = [("address", C.c_void_p), ("state", C.c_int)]


class Arguments(C.Structure):
    _fields_ = [("context", C.c_void_p), ("socket", C.c_void_p), ("length", C.c_size_t),
               ("flags", C.c_uint32), ("kind", C.c_int), ("buffer", C.c_void_p),
               ("value", Value), ("address_length", C.c_uint32)]


CALLBACK = C.CFUNCTYPE(C.c_uint64, C.POINTER(Arguments))


def library_path():
    return os.environ.get("P2PLAB_LIBUTP") or ctypes.util.find_library("utp") or str(
        Path(__file__).resolve().parents[1] / "data/native/libutp.so")


def address_buffer(target):
    address, port = target
    if ":" in address:
        raw = struct.pack("=H", socket.AF_INET6) + struct.pack("!H", port) + bytes(4)
        raw += socket.inet_pton(socket.AF_INET6, address) + bytes(4)
    else:
        raw = struct.pack("=H", socket.AF_INET) + struct.pack("!H", port) + socket.inet_aton(address) + bytes(8)
    return C.create_string_buffer(raw), len(raw)


class UtpAttempt(UdpAttempt):
    def __init__(self, owner, spec, host):
        super().__init__(owner, spec, host)
        try:
            self.lib = C.CDLL(library_path())
            for name, result, args in (
                ("utp_init", C.c_void_p, [C.c_int]),
                ("utp_destroy", None, [C.c_void_p]),
                ("utp_set_callback", None, [C.c_void_p, C.c_int, CALLBACK]),
                ("utp_create_socket", C.c_void_p, [C.c_void_p]),
                ("utp_connect", C.c_int, [C.c_void_p, C.c_void_p, C.c_uint32]),
                ("utp_process_udp", C.c_int, [C.c_void_p, C.c_void_p, C.c_size_t, C.c_void_p, C.c_uint32]),
                ("utp_write", C.c_ssize_t, [C.c_void_p, C.c_void_p, C.c_size_t]),
                ("utp_close", None, [C.c_void_p]),
                ("utp_read_drained", None, [C.c_void_p]),
                ("utp_check_timeouts", None, [C.c_void_p]),
                ("utp_issue_deferred_acks", None, [C.c_void_p]),
            ):
                function = getattr(self.lib, name)
                function.restype, function.argtypes = result, args
        except (OSError, AttributeError) as exc:
            raise ValueError("LIBUTP_BACKEND_UNAVAILABLE;RUN_tools/install_libutp.py") from exc
        self.context = self.lib.utp_init(2)
        if not self.context:
            raise ValueError("LIBUTP_CONTEXT_UNAVAILABLE")
        self.callback = CALLBACK(self.on_callback)
        for kind in (0, 1, 3, 4, 6, 7, 9, 15):
            self.lib.utp_set_callback(self.context, kind, self.callback)
        self.utp_socket = None
        self.native_connected, self.writable = asyncio.Event(), asyncio.Event()
        self.failure = None
        self.tls = self.path = self.pump_task = None
        self.early = deque()
        self.socket_buffers = {}

    async def open(self):
        await super().open()
        sock = self.transport.get_extra_info("socket")
        if sock is None:
            return
        for name, option in (("receive", socket.SO_RCVBUF), ("send", socket.SO_SNDBUF)):
            try:
                sock.setsockopt(socket.SOL_SOCKET, option, 4 * 1024 * 1024)
                self.socket_buffers[name + "_bytes"] = sock.getsockopt(socket.SOL_SOCKET, option)
            except OSError as exc:
                self.owner.log.event("native.utp_buffer_tuning_failed", str(exc), "WARNING",
                                     attempt=self.attempt, direction=name)
        self.owner.log.event("native.utp_socket_buffers", attempt=self.attempt,
                             requested_bytes=4 * 1024 * 1024, actual=self.socket_buffers,
                             scope="per-socket;no-system-sysctl-change")

    def on_callback(self, pointer):
        try:
            arg = pointer.contents
            if arg.kind == 0:
                return int(self.spec["initiator"] or self.utp_socket is not None)
            if arg.kind == 1:
                self.utp_socket = arg.socket
                self.native_connected.set()
                self.writable.set()
            elif arg.kind == 3:
                self.fail("LIBUTP_ERROR_" + str(arg.value.state))
            elif arg.kind == 4:
                data = C.string_at(arg.buffer, arg.length)
                if self.tls:
                    self.tls.feed(data)
                elif len(self.early) < 128:
                    self.early.append(data)
                else:
                    self.fail("LIBUTP_RECEIVE_QUEUE_OVERFLOW")
                self.lib.utp_read_drained(arg.socket)
            elif arg.kind == 6:
                state = arg.value.state
                if state in (1, 2):
                    self.native_connected.set()
                    self.writable.set()
                elif state in (3, 4):
                    if state == 4:
                        self.utp_socket = None
                    self.fail("LIBUTP_CLOSED_BY_PEER")
            elif arg.kind == 7:
                return sum(map(len, self.early)) + (self.tls.queue.qsize() * 16384 if self.tls else 0)
            elif arg.kind == 9:
                return 1200  # Conservative payload ceiling for the experiment.
            elif arg.kind == 15 and not self.closed:
                raw = C.string_at(arg.value.address, arg.address_length)
                family = struct.unpack_from("=H", raw)[0]
                address = socket.inet_ntop(family, raw[8:24] if family == socket.AF_INET6 else raw[4:8])
                target = (address, struct.unpack_from("!H", raw, 2)[0])
                if target == self.remote:
                    self.transport.sendto(C.string_at(arg.buffer, arg.length), target)
        except Exception as exc:
            self.fail(type(exc).__name__ + ":" + str(exc))
        return 0

    def fail(self, reason):
        if self.closed:
            return
        self.failure = reason
        self.native_connected.set()
        self.writable.set()
        self.owner.log.event("native.utp_failed", reason, "WARNING", attempt=self.attempt)
        if self.path:
            self.owner.spawn(self.path.close(reason), "utp-close")

    def datagram_received(self, data, source):
        if data.startswith(MAGIC) or self.receive_stun(data, source):
            return super().datagram_received(data, source)
        if self.context and not self.closed and tuple(source[:2]) == self.remote:
            address, length = address_buffer(self.remote)
            self.lib.utp_process_udp(self.context, C.c_char_p(data), len(data), address, length)

    async def pump(self):
        ticks = 0
        while not self.closed:
            self.lib.utp_issue_deferred_acks(self.context)
            if ticks % 10 == 0:
                self.lib.utp_check_timeouts(self.context)
            ticks += 1
            await asyncio.sleep(0.02)

    async def send_raw(self, data):
        offset = 0
        async with asyncio.timeout(15):
            while offset < len(data):
                if self.closed or self.failure or not self.utp_socket:
                    raise ConnectionError(self.failure or "LIBUTP_NOT_CONNECTED")
                self.writable.clear()
                block = data[offset:offset + 16384]
                count = self.lib.utp_write(self.utp_socket, C.c_char_p(block), len(block))
                if count < 0:
                    raise ConnectionError("LIBUTP_WRITE_FAILED")
                offset += count
                if not count:
                    await self.writable.wait()

    async def connect_stream(self):
        self.pump_task = asyncio.create_task(self.pump(), name="libutp:" + self.attempt)
        if self.spec["initiator"]:
            self.utp_socket = self.lib.utp_create_socket(self.context)
            if not self.utp_socket:
                raise ValueError("LIBUTP_SOCKET_UNAVAILABLE")
            address, length = address_buffer(self.remote)
            if self.lib.utp_connect(self.utp_socket, address, length) < 0:
                raise ValueError("LIBUTP_CONNECT_FAILED")
        await asyncio.wait_for(self.native_connected.wait(), self.owner.timeout + 10)
        if self.failure:
            raise ConnectionError(self.failure)
        self.owner.log.event("native.utp_connected", attempt=self.attempt, remote=self.remote,
                             evidence="libutp-v2-reliable-stream;not-application-auth-yet")
        self.tls = EncryptedStream(self.owner, self.spec, self.send_raw, self.close,
                                  ipaddress.ip_address(self.host).version)
        self.path = self.tls.path
        for data in self.early:
            self.tls.feed(data)
        self.early.clear()
        return await self.tls.start(self.owner.timeout + 10)

    async def close(self):
        if self.closed:
            return
        # Close TLS before disposing its native send/receive resources.
        self.closed = True
        if self.pump_task and self.pump_task is not asyncio.current_task():
            self.pump_task.cancel()
            await asyncio.gather(self.pump_task, return_exceptions=True)
        if self.path and not self.path.closed:
            await self.path.close("LIBUTP_ATTEMPT_CLOSED")
        if self.tls:
            await self.tls.close()
        if self.context:
            self.lib.utp_destroy(self.context)
            self.context = None
            self.utp_socket = None
        self.closed = False
        await super().close()
