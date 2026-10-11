"""Bounded JSON-lines RPC. Run: python -m p2pchat.native.bridge [--bind ADDRESS]."""
import argparse
import asyncio
import base64
import json
import ipaddress
import sys
from .adapter import NativeAdapter, MAX_FRAME

MAX_LINE = 128 * 1024
METHODS = {"capabilities", "start", "signal", "send", "stats", "close"}


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

    def emit(frame):
        try:
            queue.put_nowait(frame)
        except asyncio.QueueFull:
            # Slow/dead local UI must not grow memory or become a network relay.
            raise RuntimeError("OUTPUT_BACKPRESSURE")

    async def drain():
        while True:
            frame = await queue.get()
            try:
                text = json.dumps(frame, ensure_ascii=False, separators=(",", ":")) + "\n"
                await asyncio.to_thread(output.write, text)
                await asyncio.to_thread(output.flush)
            finally:
                queue.task_done()

    writer = asyncio.create_task(drain())
    unsubscribe = adapter.subscribe(lambda event, params: emit({"v": 1, "event": event, "params": params}))
    try:
        while True:
            try:
                line = await reader.readline()
            except (ValueError, asyncio.LimitOverrunError):
                emit({"v": 1, "id": None, "error": {"code": "LINE_LIMIT", "message": "LINE_LIMIT"}})
                break
            if not line:
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
        await asyncio.gather(writer, return_exceptions=True)


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
    parser = argparse.ArgumentParser(description="Direct P2P native stdio adapter; no relay")
    parser.add_argument("--bind", default="127.0.0.1", help="Explicit local numeric IP; no wildcard bind")
    parser.add_argument("--stun-address", help="Explicitly authorized numeric IPv4 STUN server; disabled by default")
    parser.add_argument("--stun-port", type=int, help="Authorized STUN UDP port (1..65535)")
    args = parser.parse_args()
    try:
        server = stun_config(args.stun_address, args.stun_port)
    except ValueError:
        parser.error("INVALID_STUN_CONFIG")
    asyncio.run(serve(NativeAdapter(bind_host=args.bind, stun_server=server)))


if __name__ == "__main__":
    main()
