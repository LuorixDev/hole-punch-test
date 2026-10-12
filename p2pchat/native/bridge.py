"""Bounded JSON-lines RPC. Run: python -m p2pchat.native.bridge [--bind ADDRESS] [capabilities].

Transport contract (unchanged): one JSON request per line on stdin, one JSON frame per
line on stdout, bounded sizes, explicit enumerated errors, no relay of chat content.
Input accepts either ``\n`` or ``\r\n`` terminators (JSON treats the trailing CR as
whitespace, and the line-length bound counts the bytes that arrived).

Output contract (t31/t40): stdout/stderr are pinned to UTF-8 with canonical ``\n``
line endings whatever the parent's code page or text mode is (Windows text mode would
otherwise rewrite every frame as CRLF and break byte-level consumers), and a failed
local write is surfaced as a non-zero exit with a bounded reason on stderr instead of
silently exiting 0 with no output.
"""
import argparse
import asyncio
import base64
import contextlib
import ipaddress
import json
import os
import sys
from .adapter import NativeAdapter, MAX_FRAME

MAX_LINE = 128 * 1024
METHODS = {"capabilities", "start", "signal", "send", "stats", "close"}
OUTPUT_ENCODING = "utf-8"
# The frame separator is part of the wire contract, so it is canonical on every
# platform rather than whatever the local text mode would translate "\n" into.
LINE_ENDING = "\n"
# Data output is strict: never replace a character with "?" or "\ufffd" and call it done.
STDOUT_ERRORS = "strict"
# Diagnostics must never crash or print "?" while reporting a problem.
STDERR_ERRORS = "backslashreplace"
_STOPPED = object()


class BridgeOutputError(RuntimeError):
    """The local output stream failed; it must reach the caller as a non-zero exit."""


def force_utf8_streams():
    """Pin stdout/stderr to UTF-8 with canonical ``\n`` regardless of the parent.

    ``PYTHONIOENCODING`` only influences interpreter startup, so an explicitly
    hostile parent (``PYTHONIOENCODING=cp1252``) would otherwise reconfigure our
    pipe back to a code page that cannot encode the capability text. ``newline="\\n"``
    disables newline translation, so Windows text mode cannot turn frames into CRLF.
    Streams that are not real text files (embedded callers, some test harnesses) are
    left alone; ``write_frame`` still guarantees the bytes on the wire.
    """
    for stream, errors in ((sys.stdout, STDOUT_ERRORS), (sys.stderr, STDERR_ERRORS)):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        with contextlib.suppress(ValueError, OSError, AttributeError):
            reconfigure(encoding=OUTPUT_ENCODING, errors=errors, newline=LINE_ENDING)


def write_frame(output, text):
    """Write one frame as canonical UTF-8 bytes, ignoring text-mode translation.

    Prefers the underlying binary buffer: the bytes on the wire are exactly the frame
    plus ``\\n``, so a Windows text stream (``newline=None``) cannot rewrite them as
    CRLF. Injected writers without a buffer keep the text path. Either way the stream
    is flushed here, so a failure is visible to the caller instead of being lost at
    interpreter shutdown, and encoding stays strict (no silent "?" substitution).
    """
    buffer = getattr(output, "buffer", None)
    if buffer is not None:
        buffer.write(text.encode(OUTPUT_ENCODING))
        buffer.flush()
        return
    output.write(text)
    output.flush()


def describe_output_error(error):
    """Bounded, payload-free reason code for a failed writer; never echoes content."""
    if isinstance(error, UnicodeEncodeError):
        return "OUTPUT_ENCODING_FAILED"
    if isinstance(error, BrokenPipeError):
        return "OUTPUT_CLOSED"
    code = str(error)
    if code in {"OUTPUT_BACKPRESSURE", "OUTPUT_FAILED"}:
        return code
    if isinstance(error, ValueError):  # e.g. "I/O operation on closed file"
        return "OUTPUT_CLOSED"
    if isinstance(error, OSError):
        return "OUTPUT_IO_ERROR"
    return "OUTPUT_FAILED"


async def _readline_or_stop(reader, state):
    """Read one line, but stop as soon as the writer has died.

    Without the race a dead writer plus an idle parent would hang forever instead
    of exiting non-zero, which is the silent-truncation failure mode t31 fixes.
    """
    if state["error"] is not None:
        return _STOPPED
    read = asyncio.ensure_future(reader.readline())
    stop = asyncio.ensure_future(state["stopped"].wait())
    try:
        done, _ = await asyncio.wait({read, stop}, return_when=asyncio.FIRST_COMPLETED)
        if read in done:
            return read.result()
        return _STOPPED
    finally:
        for task in (read, stop):
            if not task.done():
                task.cancel()
        await asyncio.gather(read, stop, return_exceptions=True)


async def serve(adapter=None, reader=None, output=None):
    adapter = adapter or NativeAdapter()
    output = output or sys.stdout
    if reader is None:
        class StdioReader:
            async def readline(self):
                # Portable across Windows anonymous pipes and POSIX; bounded even
                # without a newline. Parent closes stdin during lifecycle shutdown.
                return await asyncio.to_thread(sys.stdin.buffer.readline, MAX_LINE + 1)
        reader = StdioReader()
    queue = asyncio.Queue(maxsize=128)
    state = {"error": None, "stopped": asyncio.Event()}

    def emit(frame):
        try:
            queue.put_nowait(frame)
        except asyncio.QueueFull:
            # Slow/dead local UI must not grow memory or become a network relay.
            raise RuntimeError("OUTPUT_BACKPRESSURE")

    async def drain():
        try:
            while True:
                frame = await queue.get()
                try:
                    text = json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + LINE_ENDING
                    await asyncio.to_thread(write_frame, output, text)
                finally:
                    queue.task_done()
        except asyncio.CancelledError:
            raise
        except BaseException as error:  # recorded and re-raised: never a silent writer death
            state["error"] = error
            state["stopped"].set()
            raise

    writer = asyncio.create_task(drain())
    unsubscribe = adapter.subscribe(lambda event, params: emit({"v": 1, "event": event, "params": params}))
    try:
        while state["error"] is None:
            try:
                line = await _readline_or_stop(reader, state)
            except (ValueError, asyncio.LimitOverrunError):
                emit({"v": 1, "id": None, "error": {"code": "LINE_LIMIT", "message": "LINE_LIMIT"}})
                break
            if line is _STOPPED or not line:
                break
            request_id = None
            try:
                if len(line) > MAX_LINE:
                    emit({"v": 1, "id": None, "error": {"code": "LINE_LIMIT", "message": "LINE_LIMIT"}})
                    break
                req = json.loads(line)
                if not isinstance(req, dict) or set(req) != {"v", "id", "method", "params"} or req["v"] != 1:
                    raise ValueError("INVALID_REQUEST")
                if not isinstance(req["id"], (str, int)) or isinstance(req["id"], bool) or len(str(req["id"])) > 100:
                    raise ValueError("INVALID_ID")
                request_id = req["id"]
                if req["method"] not in METHODS or not isinstance(req["params"], dict):
                    raise ValueError("METHOD_NOT_ALLOWED")
                params = req["params"]
                if req["method"] == "send":
                    params = dict(params)
                    params["data"] = base64.b64decode(params.pop("dataB64"), validate=True)
                    if len(params["data"]) > MAX_FRAME:
                        raise ValueError("FRAME_LIMIT")
                method = getattr(adapter, req["method"])
                result = await method() if req["method"] == "capabilities" else await method(params)
                emit({"v": 1, "id": request_id, "result": result})
            except Exception as exc:
                # Only stable enumerated errors, never echo user input, auth, endpoint or data.
                code = str(exc)
                if not code or len(code) > 64 or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ_" for ch in code):
                    code = "INVALID_REQUEST"
                emit({"v": 1, "id": request_id, "error": {"code": code, "message": code}})
    finally:
        unsubscribe()
        await adapter.shutdown()
        try:
            await asyncio.wait_for(queue.join(), 2)
        except asyncio.TimeoutError:
            pass
        writer.cancel()
        for result in await asyncio.gather(writer, return_exceptions=True):
            if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                state["error"] = state["error"] or result
        failed = state["error"]
        # Do not mask a real protocol error that is already propagating; either way the
        # process must not exit 0 after a failed write.
        if failed is not None and sys.exc_info()[0] is None:
            raise BridgeOutputError(describe_output_error(failed)) from None


def write_stdout_once(text):
    """Write one frame to the real stdout; any failure becomes a BridgeOutputError."""
    try:
        write_frame(sys.stdout, text)
    except (UnicodeError, OSError, ValueError, AttributeError) as error:
        raise BridgeOutputError(describe_output_error(error)) from None


def stun_config(address=None, port=None):
    """Trusted CLI configuration only; one explicit numeric IPv4 STUN endpoint."""
    if address is None and port is None:
        return None
    try:
        ip = ipaddress.IPv4Address(address)
        if ip.is_multicast or ip.is_unspecified or ip.is_link_local or str(ip) == "255.255.255.255":
            raise ValueError
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            raise ValueError
    except (ValueError, TypeError, ipaddress.AddressValueError):
        raise ValueError("INVALID_STUN_CONFIG") from None
    return str(ip), port


def main():
    force_utf8_streams()
    parser = argparse.ArgumentParser(description="Direct P2P native stdio adapter; no relay")
    parser.add_argument("command", nargs="?", choices=("capabilities",),
                        help="One-shot helper: print the capability JSON (UTF-8) and exit")
    parser.add_argument("--bind", default="127.0.0.1", help="Explicit local numeric IP; no wildcard bind")
    parser.add_argument("--stun-address", help="Explicitly authorized numeric IPv4 STUN server; disabled by default")
    parser.add_argument("--stun-port", type=int, help="Authorized STUN UDP port (1..65535)")
    args = parser.parse_args()
    try:
        server = stun_config(args.stun_address, args.stun_port)
    except ValueError:
        parser.error("INVALID_STUN_CONFIG")
    adapter = NativeAdapter(bind_host=args.bind, stun_server=server)
    try:
        if args.command == "capabilities":
            payload = asyncio.run(adapter.capabilities())
            write_stdout_once(json.dumps(payload, ensure_ascii=False, separators=(",", ":")) + LINE_ENDING)
            return
        asyncio.run(serve(adapter))
    except BridgeOutputError as error:
        # Bounded reason on stderr; never a payload, never exit 0 with truncated output.
        print(f"native bridge: {error}", file=sys.stderr)
        # The output pipe is already broken: point stdout at an inert stream so the
        # interpreter's final flush cannot downgrade the status or add noise.
        with contextlib.suppress(Exception):
            sys.stdout = open(os.devnull, "w", encoding=OUTPUT_ENCODING)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
