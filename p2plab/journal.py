from __future__ import annotations

import datetime as dt
import json
import logging
import re
import sqlite3
import sys
import threading
import traceback
import uuid
from pathlib import Path

from .common import packed
from .logcodec import (
    MAX_BATCH_BYTES,
    MAX_BATCH_EVENTS,
    MAX_RECORD_BYTES,
    document_text,
    load_document,
    store_document,
)

SENSITIVE = re.compile(
    r"^(signature|proof|nonce|private_key|secret|password|token|observation_token|authorization|credential|ice_pwd|sdp)$",
    re.I,
)


def redact(value):
    if isinstance(value, dict):
        return {str(k): "[redacted]" if SENSITIVE.match(str(k)) else redact(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact(v) for v in value]
    if isinstance(value, str):
        value = re.sub(r"(?i)(authorization\s*[:=]\s*|bearer\s+)[^\s,\"']+", r"\1[redacted]", value)
        value = re.sub(r"(?i)([?&](?:token|secret|password|key)=)[^&\s\"']+", r"\1[redacted]", value)
        value = re.sub(r"(https?://|wss?://)[^/@\s]+:[^/@\s]+@", r"\1[redacted]@", value)
        return value
    return value


class Journal:
    """Commit before upload; only a server commit ACK marks a local event delivered."""

    def __init__(self, path: Path, *, role: str, room: str = "", console: bool = True):
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = sqlite3.connect(path, check_same_thread=False)
        path.chmod(0o600)
        self.lock = threading.RLock()
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.create_function("journal_json", 1, document_text, deterministic=True)
        self.db.executescript("""
          CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
          CREATE TABLE IF NOT EXISTS events (
            seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
            client TEXT NOT NULL, room TEXT NOT NULL, document BLOB NOT NULL, acked INTEGER NOT NULL DEFAULT 0
          );
          CREATE INDEX IF NOT EXISTS events_filter ON events(room, client, seq);
          CREATE INDEX IF NOT EXISTS pending ON events(acked, seq);
        """)
        try:
            self._migrate()
        except BaseException:
            self.db.close()
            raise
        row = self.db.execute("SELECT value FROM meta WHERE key='client'").fetchone()
        self.client = row[0] if row else str(uuid.uuid4())
        self.db.execute("INSERT OR IGNORE INTO meta VALUES ('client',?)", (self.client,))
        self.db.commit()
        self.role, self.room, self.console = role, room, console
        self.run = str(uuid.uuid4())
        self.closed = False
        self.previous_hook = None
        self.handler = None

    @staticmethod
    def _metadata(record):
        fields = record.get("fields")
        fields = fields if isinstance(fields, dict) else {}
        fragment = record.get("event") == "journal.fragment"
        return (
            str(record.get("run", "")), str(record.get("level", "")),
            str(fields.get("original_id", "")) if fragment else None,
            fields.get("index") if fragment and type(fields.get("index")) is int else None,
        )

    def _migrate(self):
        """Resumable startup migration; never replace IDs, cursors or ACK state."""
        columns = {row[1] for row in self.db.execute("PRAGMA table_info(events)")}
        with self.db:
            for name, kind in (("run", "TEXT"), ("level", "TEXT"),
                               ("original_id", "TEXT"), ("fragment_index", "INTEGER")):
                if name not in columns:
                    self.db.execute(f"ALTER TABLE events ADD COLUMN {name} {kind}")
        cursor = 0
        while True:
            rows = self.db.execute(
                "SELECT seq,document FROM events WHERE seq>? "
                "AND (typeof(document)='text' OR run IS NULL) ORDER BY seq LIMIT 1000", (cursor,)
            ).fetchall()
            if not rows:
                break
            with self.db:
                for seq, document in rows:
                    record = load_document(document)
                    self.db.execute(
                        "UPDATE events SET document=?,run=?,level=?,original_id=?,fragment_index=? WHERE seq=?",
                        (store_document(record), *self._metadata(record), seq),
                    )
                self.db.execute("INSERT OR REPLACE INTO meta VALUES ('log_compaction_pending','1')")
            cursor = rows[-1][0]
        self.db.executescript("""
            CREATE INDEX IF NOT EXISTS events_run ON events(run,seq);
            CREATE INDEX IF NOT EXISTS events_fragments ON events(original_id,fragment_index)
              WHERE original_id IS NOT NULL;
        """)
        if self.db.execute("SELECT 1 FROM meta WHERE key='log_compaction_pending'").fetchone():
            # Compression alone leaves free pages in the old file; reclaim them once.
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self.db.execute("VACUUM")
            with self.db:
                self.db.execute("DELETE FROM meta WHERE key='log_compaction_pending'")
            self.db.execute("PRAGMA wal_checkpoint(TRUNCATE)")

    def event(self, event: str, message: str = "", level: str = "INFO", **fields):
        record = {
            "id": str(uuid.uuid4()),
            "client": self.client,
            "run": self.run,
            "room": fields.get("room", self.room),
            "role": self.role,
            "time": dt.datetime.now(dt.timezone.utc).isoformat(),
            "level": level,
            "event": event,
            "message": message,
            "fields": fields,
        }
        record = redact(record)
        document = packed(record).decode()
        records = [record]
        if len(document.encode()) > 64_000:
            parts = [document[start : start + 24_000] for start in range(0, len(document), 24_000)]
            records = [
                {
                    **record,
                    "id": str(uuid.uuid4()),
                    "event": "journal.fragment",
                    "message": "Lossless large-event fragment",
                    "fields": {
                        "original_id": record["id"],
                        "original_event": event,
                        "index": index,
                        "parts": len(parts),
                        "json_part": part,
                    },
                }
                for index, part in enumerate(parts)
            ]
        with self.lock:
            if self.closed:
                return
            with self.db:
                self.db.executemany(
                    "INSERT INTO events(id,client,room,document,acked,run,level,original_id,fragment_index) "
                    "VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        (
                            row["id"],
                            self.client,
                            row["room"],
                            store_document(row),
                            int(self.role == "server"),
                            *self._metadata(row),
                        )
                        for row in records
                    ),
                )
        if self.console:
            stamp = dt.datetime.now().astimezone().strftime("%H:%M:%S")
            details = " " + json.dumps(record["fields"], ensure_ascii=False) if fields else ""
            try:
                print(f"[{stamp}] {level:<7} {event}: {record['message']}{details}", flush=True)
            except OSError as exc:
                self.console = False
                self.event(
                    "terminal.output_failed",
                    str(exc),
                    "ERROR",
                    original_event=event,
                    exception=type(exc).__name__,
                )
        return record

    def exception(self, event: str, exc: BaseException, **fields):
        return self.event(
            event,
            str(exc),
            "ERROR",
            exception=type(exc).__name__,
            traceback="".join(traceback.format_exception(exc)),
            **fields,
        )

    def pending(self, limit: int = 64, max_bytes: int = 220_000) -> list[dict]:
        result, size = [], 0
        with self.lock:
            rows = self.db.execute(
                "SELECT document FROM events WHERE acked=0 ORDER BY seq LIMIT ?",
                (min(max(limit, 1), MAX_BATCH_EVENTS),),
            )
            try:
                for (document,) in rows:
                    document = document_text(document)
                    encoded_size = len(document.encode())
                    if result and size + encoded_size > max_bytes:
                        break
                    result.append(json.loads(document))
                    size += encoded_size
            finally:
                rows.close()
        return result

    def ack(self, ids: list[str]):
        with self.lock:
            self.db.executemany("UPDATE events SET acked=1 WHERE id=?", ((i,) for i in ids))
            self.db.commit()

    def bind_client(self, client: str, public: str):
        import hmac

        key = "identity:" + client
        with self.lock, self.db:
            row = self.db.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
            if row and not hmac.compare_digest(row[0], public):
                raise ValueError("CLIENT_IDENTITY_CHANGED")
            self.db.execute("INSERT OR IGNORE INTO meta VALUES (?,?)", (key, public))

    def ingest(self, records: list[dict], client: str) -> list[str]:
        if not isinstance(records, list) or len(records) > MAX_BATCH_EVENTS:
            raise ValueError("LOG_BATCH_LIMIT")
        if len(packed(records)) > MAX_BATCH_BYTES:
            raise ValueError("LOG_BATCH_BYTES_LIMIT")
        ids = []
        with self.lock, self.db:
            for record in records:
                if not isinstance(record, dict) or record.get("client") != client:
                    raise ValueError("LOG_CLIENT_MISMATCH")
                uuid.UUID(record["id"])
                if len(packed(record)) > MAX_RECORD_BYTES:
                    raise ValueError("LOG_RECORD_LIMIT")
                record = redact(record)
                self.db.execute(
                    "INSERT OR IGNORE INTO events(id,client,room,document,acked,run,level,original_id,fragment_index) "
                    "VALUES (?,?,?,?,1,?,?,?,?)",
                    (record["id"], client, str(record.get("room", ""))[:64],
                     store_document(record), *self._metadata(record)),
                )
                ids.append(record["id"])
        return ids

    def query(self, *, after=0, room=None, client=None, limit=1000):
        sql, args = "SELECT seq,document FROM events WHERE seq>?", [after]
        for key, value in (("room", room), ("client", client)):
            if value is not None:
                sql += f" AND {key}=?"
                args.append(value)
        sql += " ORDER BY seq LIMIT ?"
        args.append(min(max(limit, 1), 1000))
        with self.lock:
            return [{"cursor": seq, **load_document(doc)} for seq, doc in self.db.execute(sql, args)]

    def install(self):
        journal = self

        class Handler(logging.Handler):
            def emit(self, record):
                try:
                    fields = {"logger": record.name}
                    if record.exc_info:
                        fields["traceback"] = "".join(traceback.format_exception(*record.exc_info))
                    journal.event("runtime.log", self.format(record), record.levelname, **fields)
                except Exception:
                    self.handleError(record)

        self.handler = Handler()
        logging.getLogger().addHandler(self.handler)
        logging.getLogger().setLevel(logging.INFO)
        self.previous_hook = sys.excepthook

        def hook(kind, value, tb):
            self.exception("runtime.fatal", value)
            self.previous_hook(kind, value, tb)

        sys.excepthook = hook

    def close(self):
        if self.handler:
            logging.getLogger().removeHandler(self.handler)
        if self.previous_hook:
            sys.excepthook = self.previous_hook
        with self.lock:
            self.closed = True
            self.db.close()
