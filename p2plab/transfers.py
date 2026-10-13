from __future__ import annotations

import asyncio
import contextlib
import datetime as dt
import hashlib
import math
import os
import secrets
import shutil
import stat
import time
from collections import OrderedDict
from pathlib import Path

from .common import BENCH_CHUNK

FILE_CAPABILITY = "file-binary-v1"
RECEIPT_CAPABILITY = "chat-receipt-v1"
FILE_WINDOW = 4 * 1024 * 1024
FILE_ACK_BYTES = 256 * 1024
IO_BLOCK = 1024 * 1024
IDLE_SECONDS = 30


def receipt(size, seconds=None, *, received_at=None):
    return {
        "bytes": size,
        "received_at": received_at or dt.datetime.now(dt.timezone.utc).isoformat(),
        "receiver_seconds": seconds,
        "mbps": size * 8 / max(seconds, 1e-6) / 1e6 if seconds is not None else None,
    }


def validate_receipt(value, size):
    if not isinstance(value, dict) or type(value.get("bytes")) is not int or value["bytes"] != size:
        raise ValueError("RECEIPT_SIZE_MISMATCH")
    stamp = value.get("received_at")
    if not isinstance(stamp, str) or len(stamp) > 64 or dt.datetime.fromisoformat(stamp).tzinfo is None:
        raise ValueError("RECEIPT_TIME_INVALID")
    seconds = value.get("receiver_seconds")
    if (
        isinstance(seconds, bool)
        or not isinstance(seconds, (int, float))
        or not math.isfinite(seconds)
        or seconds < 0
    ):
        raise ValueError("RECEIPT_DURATION_INVALID")
    return receipt(size, seconds, received_at=stamp)


def image_format(data):
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "png"
    if data.startswith(b"\xff\xd8\xff"):
        return "jpeg"
    if data.startswith((b"GIF87a", b"GIF89a")):
        return "gif"
    if data.startswith(b"RIFF") and data[8:12] == b"WEBP":
        return "webp"
    if data.startswith(b"BM"):
        return "bmp"
    return None


def safe_filename(name):
    if not isinstance(name, str) or not name or len(name.encode()) > 1024:
        raise ValueError("FILE_NAME_INVALID")
    name = name.replace("\\", "/").rsplit("/", 1)[-1]
    name = "".join(c for c in name if c.isprintable() and c not in "/\\")
    name = name.strip(" .") or "attachment"
    while len(name.encode()) > 220:
        name = name[:-1]
    return name


async def disk_call(function, *args, cleanup=None):
    # Finish an in-flight filesystem operation before cancellation closes its file handle.
    task = asyncio.create_task(asyncio.to_thread(function, *args))
    try:
        return await asyncio.shield(task)
    except asyncio.CancelledError:
        result = await task
        if cleanup:
            await asyncio.to_thread(cleanup, result)
        raise


def open_source(path, image):
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    stream = os.fdopen(fd, "rb")
    try:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("FILE_NOT_REGULAR")
        prefix = stream.read(32)
        stream.seek(0)
        if image and not image_format(prefix):
            raise ValueError("IMAGE_FORMAT_UNSUPPORTED")
        return stream, info
    except BaseException:
        stream.close()
        raise


def commit_file(item):
    stream = item["stream"]
    stream.flush()
    os.fsync(stream.fileno())
    stream.close()
    # Atomic no-overwrite commit; partial and final live on the same filesystem.
    os.link(item["partial"], item["destination"])
    item["partial"].unlink()


def open_partial(path):
    return os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb")


def discard_partial(stream, path):
    stream.close()
    path.unlink(missing_ok=True)


class TransferManager:
    def __init__(self, owner):
        self.owner = owner
        options = owner.config.get("transfer", {})
        self.directory = Path(options.get("download_dir", owner.data / "downloads")).expanduser().absolute()
        self.max_bytes = int(options.get("max_mib", 10240)) * 1024 * 1024
        if not 1024 * 1024 <= self.max_bytes <= 1024**4:
            raise ValueError("TRANSFER_LIMIT_MUST_BE_1_TO_1048576_MIB")
        self.auto_accept = bool(options.get("auto_accept", True))
        self.records = OrderedDict()
        self.incoming = {}
        self.outgoing = {}
        self.accept_lock = asyncio.Lock()
        self.send_lock = asyncio.Lock()
        self.closed = False

    def record(self, tid, **fields):
        item = self.records.setdefault(tid, {"id": tid})
        item.update(fields)
        while len(self.records) > 200:
            removable = next(
                (k for k in self.records if k not in self.incoming and k not in self.outgoing), None
            )
            if removable is None:
                break
            del self.records[removable]
        return item

    def progress(self, tid, size):
        item = self.records[tid]
        item["completed"] = size
        now = time.monotonic()
        if now - item.get("last_log", 0) >= 1 or size == item["bytes"]:
            item["last_log"] = now
            self.owner.log.event(
                "file.progress",
                transfer_id=tid,
                direction=item["direction"],
                bytes=size,
                total_bytes=item["bytes"],
                attempt=item["attempt"],
            )

    async def send(self, path, source, *, image=False):
        if self.closed or FILE_CAPABILITY not in path.remote_capabilities:
            raise ValueError("PEER_FILE_TRANSFER_UNSUPPORTED")
        source = Path(source).expanduser().absolute()
        name = safe_filename(source.name)
        async with self.send_lock:
            if self.closed or len(self.outgoing) >= 2:
                raise ValueError("FILE_SEND_BUSY")
            stream, original = await disk_call(
                open_source, source, image, cleanup=lambda result: result[0].close()
            )
            if self.closed or path.closed:
                await disk_call(stream.close)
                raise ConnectionError("CLIENT_OR_PATH_CLOSED")
            tid, queue = secrets.token_hex(8), asyncio.Queue(maxsize=128)
            item = {"path": path, "queue": queue, "task": asyncio.current_task(), "stream": stream}
            self.outgoing[tid] = item
        self.record(
            tid,
            name=name,
            bytes=original.st_size,
            completed=0,
            media="image" if image else "file",
            direction="send",
            state="offered",
            attempt=path.attempt,
        )
        self.owner.log.event(
            "file.offered",
            transfer_id=tid,
            name=source.name,
            bytes=original.st_size,
            media="image" if image else "file",
            attempt=path.attempt,
        )
        completed = False
        try:
            if original.st_size > self.max_bytes:
                raise ValueError("FILE_SIZE_LIMIT")
            await path.send(
                {
                    "kind": "file_offer",
                    "id": tid,
                    "name": source.name,
                    "bytes": original.st_size,
                    "media": "image" if image else "file",
                }
            )
            ready = await asyncio.wait_for(queue.get(), 120)
            self.check_error(ready)
            if ready["kind"] != "file_ready":
                raise ValueError("FILE_READY_REQUIRED")
            self.record(tid, state="sending")
            digest, sent, acknowledged, seq = hashlib.sha256(), 0, 0, 0

            async def wait_ack():
                nonlocal acknowledged
                reply = await asyncio.wait_for(queue.get(), IDLE_SECONDS)
                self.check_error(reply)
                size = reply.get("bytes")
                if (
                    reply.get("kind") != "file_ack"
                    or isinstance(size, bool)
                    or not isinstance(size, int)
                    or not acknowledged <= size <= sent
                ):
                    raise ValueError("FILE_ACK_INVALID")
                acknowledged = size
                self.progress(tid, size)

            while sent < original.st_size:
                block = await disk_call(stream.read, min(IO_BLOCK, original.st_size - sent))
                if not block:
                    raise ValueError("FILE_CHANGED_DURING_SEND")
                digest.update(block)
                for offset in range(0, len(block), BENCH_CHUNK):
                    data = block[offset : offset + BENCH_CHUNK]
                    while sent + len(data) - acknowledged > FILE_WINDOW:
                        await wait_ack()
                    if item.get("cancelled"):
                        raise ConnectionError("FILE_CANCELLED")
                    await path.send({"kind": "file_chunk", "id": tid, "seq": seq, "data": data})
                    sent += len(data)
                    seq += 1
            # Bulk and control streams may be independently ordered (QUIC/WebRTC).
            while acknowledged < sent:
                await wait_ack()
            current = await disk_call(os.fstat, stream.fileno())
            if (current.st_size, current.st_mtime_ns, current.st_ctime_ns) != (
                original.st_size,
                original.st_mtime_ns,
                original.st_ctime_ns,
            ):
                raise ValueError("FILE_CHANGED_DURING_SEND")
            await path.send({"kind": "file_end", "id": tid, "sha256": digest.hexdigest()})
            while True:
                result = await asyncio.wait_for(queue.get(), IDLE_SECONDS)
                self.check_error(result)
                if result["kind"] != "file_ack":
                    break
            if result["kind"] != "file_result" or result.get("sha256") != digest.hexdigest():
                raise ValueError("FILE_RECEIPT_INVALID")
            metrics = validate_receipt(result, sent)
            self.record(tid, state="completed", completed=sent, **metrics)
            self.owner.log.event(
                "file.delivered", transfer_id=tid, sha256=digest.hexdigest(), attempt=path.attempt, **metrics
            )
            self.owner.display_chat("我 · 已送达", self.description(tid), metrics)
            completed = True
            return {**metrics, "id": tid, "sha256": digest.hexdigest()}
        except BaseException as exc:
            reason = "FILE_CANCELLED" if isinstance(exc, asyncio.CancelledError) else str(exc)
            self.record(tid, state="cancelled" if "CANCEL" in reason else "failed", reason=reason)
            self.owner.log.event("file.failed", reason, "WARNING", transfer_id=tid, attempt=path.attempt)
            raise
        finally:
            self.outgoing.pop(tid, None)
            await disk_call(stream.close)
            if not completed and not path.closed:
                with contextlib.suppress(ConnectionError, TimeoutError, OSError):
                    await path.send({"kind": "file_cancel", "id": tid})

    @staticmethod
    def check_error(reply):
        if reply.get("kind") == "file_error":
            raise ConnectionError(reply.get("reason", "FILE_TRANSFER_FAILED"))

    def description(self, tid):
        item = self.records[tid]
        kind = "图片" if item["media"] == "image" else "文件"
        text = f"[{kind}] {item['name']}  ({item['bytes']:,} 字节)"
        if item.get("saved_path"):
            text += "\n" + item["saved_path"]
        return text

    async def handle(self, path, body):
        tid = body.get("id")
        if not isinstance(tid, str) or len(tid) != 16:
            raise ValueError("FILE_ID_INVALID")
        try:
            if bytes.fromhex(tid).hex() != tid:
                raise ValueError("FILE_ID_INVALID")
        except ValueError as exc:
            raise ValueError("FILE_ID_INVALID") from exc
        if body["kind"] in ("file_ready", "file_ack", "file_result", "file_error"):
            item = self.outgoing.get(tid)
            if item and item["path"] is path:
                if item["queue"].full():
                    item["cancelled"] = True
                    item["queue"].get_nowait()
                    body = {"kind": "file_error", "reason": "FILE_REPLY_QUEUE_LIMIT"}
                item["queue"].put_nowait(body)
            return
        if body["kind"] == "file_offer":
            await self.offer(path, body)
            return
        item = self.incoming.get(tid)
        if not item or item["path"] is not path:
            # A cancelled transfer can have already queued chunks on its bulk stream.
            return
        if body["kind"] == "file_cancel":
            await self.abort(tid, "FILE_CANCELLED", notify=False)
            return
        async with item["lock"]:
            if self.incoming.get(tid) is not item:
                return
            try:
                if body["kind"] == "file_chunk":
                    await self.chunk(tid, body)
                elif body["kind"] == "file_end":
                    await self.finish(tid, body)
                else:
                    raise ValueError("UNKNOWN_FILE_FRAME")
            except (OSError, ValueError) as exc:
                await self._abort(tid, str(exc))

    async def offer(self, path, body):
        tid = body["id"]
        size = body.get("bytes")
        if tid in self.records:
            await path.send({"kind": "file_error", "id": tid, "reason": "FILE_DUPLICATE_ID"})
            return
        try:
            name = safe_filename(body.get("name"))
        except ValueError:
            await path.send({"kind": "file_error", "id": tid, "reason": "FILE_NAME_INVALID"})
            self.owner.log.event("file.rejected", "FILE_NAME_INVALID", "WARNING", transfer_id=tid)
            return
        reason = None
        if isinstance(size, bool) or not isinstance(size, int) or not 0 <= size <= self.max_bytes:
            reason = "FILE_SIZE_LIMIT"
        elif body.get("media") not in ("image", "file"):
            reason = "FILE_MEDIA_INVALID"
        elif self.closed or len(self.incoming) >= 2:
            reason = "FILE_RECEIVE_BUSY"
        if reason:
            await path.send({"kind": "file_error", "id": tid, "reason": reason})
            self.owner.log.event("file.rejected", reason, "WARNING", transfer_id=tid)
            return
        self.record(
            tid,
            name=name,
            bytes=size,
            completed=0,
            media=body["media"],
            direction="receive",
            state="offered",
            attempt=path.attempt,
        )
        self.incoming[tid] = {
            "path": path,
            "expected": size,
            "seq": 0,
            "bytes": 0,
            "stream": None,
            "buffer": bytearray(),
            "digest": hashlib.sha256(),
            "started": None,
            "progress": time.monotonic(),
            "next_ack": FILE_ACK_BYTES,
            "prefix": bytearray(),
            "lock": asyncio.Lock(),
        }
        self.owner.log.event(
            "file.incoming", transfer_id=tid, name=name, bytes=size, media=body["media"], attempt=path.attempt
        )
        if self.auto_accept:
            await self.accept(tid)

    async def accept(self, tid):
        item = self.incoming.get(tid)
        if not item:
            raise ValueError("FILE_NOT_WAITING_FOR_ACCEPT")
        async with item["lock"]:
            if self.incoming.get(tid) is not item:
                raise ValueError("FILE_NOT_WAITING_FOR_ACCEPT")
            await self._accept(tid)

    async def _accept(self, tid):
        async with self.accept_lock:
            item = self.incoming.get(tid)
            if not item or item["stream"] is not None:
                raise ValueError("FILE_NOT_WAITING_FOR_ACCEPT")
            try:
                await disk_call(self.directory.mkdir, 0o700, True, True)
                free = (await disk_call(shutil.disk_usage, self.directory)).free
                reserved = sum(i["expected"] - i["bytes"] for i in self.incoming.values() if i is not item)
                if free < item["expected"] + reserved + 64 * 1024 * 1024:
                    raise OSError("FILE_NOT_ENOUGH_SPACE")
                item["partial"] = self.directory / (tid + ".part")
                item["destination"] = self.directory / (tid + "-" + self.records[tid]["name"])
                item["stream"] = await disk_call(
                    open_partial,
                    item["partial"],
                    cleanup=lambda stream: discard_partial(stream, item["partial"]),
                )
                item["partial_owned"] = True
                item["progress"] = time.monotonic()
                self.record(tid, state="receiving")
                await item["path"].send({"kind": "file_ready", "id": tid})
            except (OSError, ConnectionError) as exc:
                await self._abort(tid, str(exc))

    async def chunk(self, tid, body):
        item = self.incoming[tid]
        raw, seq = body.get("data"), body.get("seq")
        if (
            not item["stream"]
            or not isinstance(raw, bytes)
            or not 1 <= len(raw) <= BENCH_CHUNK
            or isinstance(seq, bool)
            or not isinstance(seq, int)
            or seq != item["seq"]
            or item["bytes"] + len(raw) > item["expected"]
        ):
            raise ValueError("FILE_CHUNK_INVALID")
        if item["started"] is None:
            item["started"] = time.monotonic()
        item["prefix"].extend(raw[: max(0, 32 - len(item["prefix"]))])
        item["digest"].update(raw)
        item["buffer"].extend(raw)
        item["bytes"] += len(raw)
        item["seq"] += 1
        item["progress"] = time.monotonic()
        if len(item["buffer"]) >= IO_BLOCK or item["bytes"] == item["expected"]:
            await disk_call(item["stream"].write, bytes(item["buffer"]))
            item["buffer"].clear()
        self.progress(tid, item["bytes"])
        if item["bytes"] >= item["next_ack"] or item["bytes"] == item["expected"]:
            await item["path"].send({"kind": "file_ack", "id": tid, "bytes": item["bytes"]})
            item["next_ack"] = item["bytes"] + FILE_ACK_BYTES

    async def finish(self, tid, body):
        item = self.incoming[tid]
        if not item["stream"] or item["bytes"] != item["expected"]:
            raise ValueError("FILE_INCOMPLETE")
        digest = item["digest"].hexdigest()
        if body.get("sha256") != digest:
            raise ValueError("FILE_CHECKSUM_MISMATCH")
        if self.records[tid]["media"] == "image":
            extension = image_format(item["prefix"])
            if not extension:
                raise ValueError("IMAGE_FORMAT_UNSUPPORTED")
            if item["destination"].suffix.lower() != "." + extension:
                item["destination"] = item["destination"].with_name(
                    item["destination"].name + "." + extension
                )
        await disk_call(commit_file, item)
        metrics = receipt(item["bytes"], time.monotonic() - (item["started"] or item["progress"]))
        self.record(
            tid, state="completed", completed=item["bytes"], saved_path=str(item["destination"]), **metrics
        )
        self.incoming.pop(tid)
        self.owner.log.event(
            "file.received",
            transfer_id=tid,
            sha256=digest,
            saved_path=str(item["destination"]),
            attempt=item["path"].attempt,
            **metrics,
        )
        self.owner.display_chat(item["path"].peer["name"], self.description(tid), metrics)
        await item["path"].send({"kind": "file_result", "id": tid, "sha256": digest, **metrics})

    async def abort(self, tid, reason, *, notify=True):
        item = self.incoming.get(tid)
        if not item:
            return
        async with item["lock"]:
            await self._abort(tid, reason, notify=notify)

    async def _abort(self, tid, reason, *, notify=True):
        item = self.incoming.pop(tid, None)
        if not item:
            return
        if item["stream"]:
            try:
                await disk_call(item["stream"].close)
            except OSError as exc:
                self.owner.log.event(
                    "file.cleanup_failed", str(exc), "WARNING", transfer_id=tid, operation="close"
                )
        partial = item.get("partial")
        if partial and item.get("partial_owned"):
            try:
                await disk_call(partial.unlink, True)
            except OSError as exc:
                self.owner.log.event(
                    "file.cleanup_failed", str(exc), "WARNING", transfer_id=tid, operation="unlink"
                )
        self.record(tid, state="cancelled" if "CANCEL" in reason else "failed", reason=reason)
        self.owner.log.event("file.failed", reason, "WARNING", transfer_id=tid, attempt=item["path"].attempt)
        if notify and not item["path"].closed:
            with contextlib.suppress(ConnectionError, TimeoutError, OSError):
                await item["path"].send({"kind": "file_error", "id": tid, "reason": reason[:160]})

    async def cancel(self, tid):
        if tid in self.incoming:
            await self.abort(tid, "FILE_CANCELLED")
        elif tid in self.outgoing:
            item = self.outgoing[tid]
            item["cancelled"] = True
            item["task"].cancel()
            if item["task"] is not asyncio.current_task():
                await asyncio.gather(item["task"], return_exceptions=True)
        else:
            raise ValueError("FILE_TRANSFER_NOT_ACTIVE")

    async def expire(self, path):
        now = time.monotonic()
        for tid, item in tuple(self.incoming.items()):
            budget = IDLE_SECONDS if item["stream"] else 120
            if item["path"] is path and now - item["progress"] > budget:
                await self.abort(tid, "FILE_RECEIVE_TIMEOUT")

    async def path_closed(self, path, reason):
        for tid, item in tuple(self.incoming.items()):
            if item["path"] is path:
                await self.abort(tid, reason, notify=False)
        for item in self.outgoing.values():
            if item["path"] is path and not item["queue"].full():
                item["cancelled"] = True
                item["queue"].put_nowait({"kind": "file_error", "reason": reason})

    async def close(self):
        self.closed = True
        for tid in tuple(self.incoming):
            await self.abort(tid, "CLIENT_SHUTDOWN", notify=False)
        for tid in tuple(self.outgoing):
            await self.cancel(tid)
