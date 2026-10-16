from __future__ import annotations

import asyncio
import ctypes as C
import ipaddress
from collections import deque

from .encrypted_stream import EncryptedStream
from .native_loader import load_library
from .rtc import filter_sdp
from .stun import select_ice_observer

PTR, UINT, INT = C.c_void_p, C.c_uint, C.c_int
RECV = C.CFUNCTYPE(None, PTR, UINT, UINT, UINT, PTR, PTR)
GATHER = C.CFUNCTYPE(None, PTR, UINT, PTR)
STATE = C.CFUNCTYPE(None, PTR, UINT, UINT, UINT, PTR)
WRITABLE = C.CFUNCTYPE(None, PTR, UINT, UINT, PTR)


class Libraries:
    def __init__(self):
        try:
            self.nice = load_library("nice")
            self.glib = load_library("glib-2.0")
            self.obj = load_library("gobject-2.0")
            for lib, name, result, args in (
                (self.glib, "g_main_context_new", PTR, []),
                (self.glib, "g_main_context_iteration", INT, [PTR, INT]),
                (self.glib, "g_main_context_unref", None, [PTR]),
                (self.glib, "g_free", None, [PTR]),
                (self.obj, "g_object_unref", None, [PTR]),
                (self.obj, "g_signal_connect_data", C.c_ulong, [PTR, C.c_char_p, PTR, PTR, PTR, UINT]),
                (self.nice, "nice_agent_new_full", PTR, [PTR, INT, UINT]),
                (self.nice, "nice_agent_add_stream", UINT, [PTR, UINT]),
                (self.nice, "nice_agent_set_stream_name", INT, [PTR, UINT, C.c_char_p]),
                (self.nice, "nice_agent_gather_candidates", INT, [PTR, UINT]),
                (self.nice, "nice_agent_attach_recv", INT, [PTR, UINT, UINT, PTR, PTR, PTR]),
                (self.nice, "nice_agent_generate_local_sdp", PTR, [PTR]),
                (self.nice, "nice_agent_parse_remote_sdp", INT, [PTR, C.c_char_p]),
                (self.nice, "nice_agent_send", INT, [PTR, UINT, UINT, UINT, PTR]),
                (self.nice, "nice_agent_get_selected_pair", INT, [PTR, UINT, UINT, C.POINTER(PTR), C.POINTER(PTR)]),
                (self.nice, "nice_agent_generate_local_candidate_sdp", PTR, [PTR, PTR]),
                (self.nice, "nice_address_new", PTR, []),
                (self.nice, "nice_address_set_from_string", INT, [PTR, C.c_char_p]),
                (self.nice, "nice_address_free", None, [PTR]),
                (self.nice, "nice_agent_add_local_address", INT, [PTR, PTR]),
                (self.nice, "nice_agent_remove_stream", None, [PTR, UINT]),
            ):
                function = getattr(lib, name)
                function.restype, function.argtypes = result, args
            self.obj.g_object_set.argtypes = [PTR, C.c_char_p]
            self.obj.g_object_set.restype = None
        except (OSError, AttributeError) as exc:
            raise ValueError("LIBNICE_BACKEND_UNAVAILABLE") from exc

    def string(self, pointer):
        if not pointer:
            return ""
        try:
            return C.string_at(pointer).decode()
        finally:
            self.glib.g_free(pointer)


class NativeIceAttempt:
    def __init__(self, owner, spec):
        self.owner, self.spec, self.attempt = owner, spec, spec["attempt"]
        self.libs = Libraries()
        self.context = self.libs.glib.g_main_context_new()
        self.agent = self.libs.nice.nice_agent_new_full(self.context, 0, 1 | 2 | 32 | 64)
        if not self.agent:
            self.libs.glib.g_main_context_unref(self.context)
            raise ValueError("LIBNICE_AGENT_UNAVAILABLE")
        self.closed = False
        self.path = self.tls = None
        self.gathered, self.connected, self.writable = asyncio.Event(), asyncio.Event(), asyncio.Event()
        self.early = deque(maxlen=128)
        self.callbacks = []
        self.remote_sdp = None
        self.failure = None
        self.pump_task = None
        self.stream = 0
        try:
            self.property("upnp", False)
            self.property("controlling-mode", spec["initiator"])
            if spec["method"] == "ice-tcp":
                self.property("ice-tcp", True)
                self.property("ice-udp", False)
            else:
                self.property("ice-udp", True)
                self.property("ice-tcp", False)
            records = owner.network.get("addresses", [])
            addresses = [r["address"] for r in records]
            if owner.loopback and not addresses:
                addresses = ["127.0.0.1", "::1"]
            added = 0
            for host in addresses:
                if spec["profile"] != "dual" and (":" in host) != (spec["profile"] == "6"):
                    continue
                address = self.libs.nice.nice_address_new()
                try:
                    if self.libs.nice.nice_address_set_from_string(address, host.encode()):
                        added += bool(self.libs.nice.nice_agent_add_local_address(self.agent, address))
                finally:
                    self.libs.nice.nice_address_free(address)
            if not added:
                raise ValueError("LIBNICE_PROFILE_NO_CANDIDATES")
            self.stream = self.libs.nice.nice_agent_add_stream(self.agent, 1)
            if not self.stream:
                raise ValueError("LIBNICE_STREAM_UNAVAILABLE")
            self.libs.nice.nice_agent_set_stream_name(self.agent, self.stream, b"application")
            self.attach("candidate-gathering-done", GATHER, lambda agent, stream, data: self.gathered.set())
            self.attach("component-state-changed", STATE, self.state)
            self.attach("reliable-transport-writable", WRITABLE, lambda *args: self.writable.set())
            receive = RECV(self.received)
            self.callbacks.append(receive)
            if not self.libs.nice.nice_agent_attach_recv(self.agent, self.stream, 1, self.context, C.cast(receive, PTR), None):
                raise ValueError("LIBNICE_RECEIVER_UNAVAILABLE")
            self.pump_task = asyncio.create_task(self.pump(), name="libnice:" + self.attempt)
        except BaseException:
            self.dispose()
            raise

    def property(self, name, value):
        wire = C.c_int(int(value)) if isinstance(value, (bool, int)) else C.c_char_p(value.encode())
        self.libs.obj.g_object_set(self.agent, name.encode(), wire, C.c_void_p(0))

    def attach(self, name, callback_type, function):
        callback = callback_type(function)
        self.callbacks.append(callback)
        self.libs.obj.g_signal_connect_data(self.agent, name.encode(), C.cast(callback, PTR), None, None, 0)

    def state(self, agent, stream, component, state, data):
        if self.closed:
            return
        self.owner.log.event("native.ice_state", attempt=self.attempt, method=self.spec["method"], state=state)
        if state == 4:
            self.connected.set()
            self.writable.set()
        elif state == 5 and self.path:
            self.owner.spawn(self.path.close("LIBNICE_ICE_FAILED"), "libnice-failed")

    def received(self, agent, stream, component, length, pointer, data):
        if self.closed:
            return
        raw = C.string_at(pointer, length)
        if self.tls:
            self.tls.feed(raw)
        elif len(self.early) < self.early.maxlen:
            self.early.append(raw)
        else:
            self.failure = "LIBNICE_RECEIVE_QUEUE_OVERFLOW"
            self.owner.log.event("native.ice_overflow", attempt=self.attempt, level="ERROR")
            self.connected.set()

    async def pump(self):
        while not self.closed:
            for _ in range(64):
                if not self.libs.glib.g_main_context_iteration(self.context, False):
                    break
            await asyncio.sleep(0.002)

    def permitted_sdp(self, sdp):
        sdp = filter_sdp(sdp, self.spec["profile"], allow_loopback=self.owner.loopback)
        protocol = "tcp" if self.spec["method"] == "ice-tcp" else "udp"
        lines = [line for line in sdp.splitlines() if not line.startswith("a=candidate:") or line.split()[2].lower() == protocol]
        if not any(line.startswith("a=candidate:") for line in lines):
            raise ValueError("LIBNICE_PROFILE_NO_CANDIDATES")
        # libnice's SDP parser splits on LF without stripping CR from credentials/types.
        return "\n".join(lines) + "\n"

    async def handle(self, data):
        if self.closed:
            return
        if data.get("kind") != "native_ice" or not isinstance(data.get("sdp"), str) or len(data["sdp"]) > 65536:
            raise ValueError("LIBNICE_SIGNAL_SCHEMA")
        self.remote_sdp = self.permitted_sdp(data["sdp"])
        if self.gathered.is_set():
            self.apply_remote()

    def apply_remote(self):
        if self.libs.nice.nice_agent_parse_remote_sdp(self.agent, self.remote_sdp.encode()) < 0:
            raise ValueError("LIBNICE_REMOTE_SDP_INVALID")

    async def send(self, raw):
        offset = 0
        async with asyncio.timeout(10):
            while offset < len(raw):
                if self.closed:
                    raise ConnectionError("LIBNICE_CLOSED")
                self.writable.clear()
                block = raw[offset:offset + 16 * 1024]
                count = self.libs.nice.nice_agent_send(self.agent, self.stream, 1, len(block), C.c_char_p(block))
                if count > 0:
                    offset += count
                else:
                    await self.writable.wait()

    async def connect(self):
        selection = await select_ice_observer(self.owner, self.spec["profile"], self.attempt)
        if selection:
            host, port = selection["target"]
            self.property("stun-server", host)
            self.property("stun-server-port", port)
        if not self.libs.nice.nice_agent_gather_candidates(self.agent, self.stream):
            raise ValueError("LIBNICE_GATHER_UNAVAILABLE")
        await asyncio.wait_for(self.gathered.wait(), self.owner.timeout + 10)
        if self.remote_sdp:
            self.apply_remote()
        sdp = self.permitted_sdp(self.libs.string(self.libs.nice.nice_agent_generate_local_sdp(self.agent)))
        await self.owner.signal({"kind": "native_ice", "attempt": self.attempt, "sdp": sdp})
        await asyncio.wait_for(self.connected.wait(), self.owner.timeout + 15)
        if self.failure:
            raise ConnectionError(self.failure)
        local, remote = PTR(), PTR()
        if not self.libs.nice.nice_agent_get_selected_pair(self.agent, self.stream, 1, C.byref(local), C.byref(remote)):
            raise ValueError("LIBNICE_SELECTED_PAIR_UNAVAILABLE")
        selected = [self.libs.string(self.libs.nice.nice_agent_generate_local_candidate_sdp(self.agent, pointer))
                    for pointer in (local, remote)]
        if any(" typ relay" in candidate for candidate in selected):
            raise ValueError("LIBNICE_RELAY_FORBIDDEN")
        self.owner.log.event("native.ice_selected", attempt=self.attempt, method=self.spec["method"],
                             candidates=selected, evidence="libnice-no-TURN;selected-candidates-not-application-auth-yet")
        self.tls = EncryptedStream(self.owner, self.spec, self.send, self.close,
                                  ipaddress.ip_address(selected[0].split()[4]).version)
        self.path = self.tls.path
        hosts = []
        for candidate in selected:
            bits = candidate.split()
            hosts.append(bits[bits.index("raddr") + 1] if "raddr" in bits else bits[4])
        self.path.local_host, self.path.peer_host = hosts
        for raw in self.early:
            self.tls.feed(raw)
        self.early.clear()
        return await self.tls.start(self.owner.timeout + 10)

    def dispose(self):
        if self.agent:
            if self.stream:
                self.libs.nice.nice_agent_attach_recv(self.agent, self.stream, 1, self.context, None, None)
                self.libs.nice.nice_agent_remove_stream(self.agent, self.stream)
            self.libs.obj.g_object_unref(self.agent)
            self.agent = None
        if self.context:
            self.libs.glib.g_main_context_unref(self.context)
            self.context = None

    async def close(self):
        if self.closed:
            return
        self.closed = True
        if self.pump_task and self.pump_task is not asyncio.current_task():
            self.pump_task.cancel()
            await asyncio.gather(self.pump_task, return_exceptions=True)
        if self.path and not self.path.closed:
            await self.path.close("LIBNICE_ATTEMPT_CLOSED")
        if self.tls:
            await self.tls.close()
        self.dispose()
