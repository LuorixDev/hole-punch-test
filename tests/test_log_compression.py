import asyncio
import base64
import gzip
import hashlib
import json
import os
import sqlite3
import time
import uuid
import zlib
from argparse import Namespace

import aiohttp
import pytest

from p2plab.client import Client
from p2plab.common import packed
from p2plab.export import download
from p2plab.journal import Journal
from p2plab.logcodec import (
    CODEC,
    LEGACY_MAGIC,
    MAGIC,
    MAX_BATCH_BYTES,
    MAX_BATCH_EVENTS,
    decode_batch,
    document_text,
    encode_batch,
    inflate,
    load_document,
)
from p2plab.tui import LogReader
from tests.test_reconnect import wait_for
from tests.test_server import cleanup_hub, join, start_hub


def test_storage_and_batch_roundtrip_compression_and_redaction(tmp_path):
    log = Journal(tmp_path / "local.db", role="client", room="压缩房间", console=False)
    try:
        for i in range(1024):
            log.event("path.rtt_sample", attempt="matrix-017-quic", rtt_ms=12.345,
                      index=i, token="never-upload", description="中文参数")
        records = log.pending(limit=1024, max_bytes=MAX_BATCH_BYTES - 4096)
        assert len(records) == 1024
        documents = log.db.execute("SELECT document FROM events").fetchall()
        assert all(isinstance(doc, bytes) and doc.startswith(MAGIC) for (doc,) in documents)
        assert [load_document(doc) for (doc,) in documents] == records
        assert sum(len(doc) for (doc,) in documents) < len(packed(records)) * 0.7
        batch = encode_batch(records)
        assert decode_batch(batch) == records
        assert len(packed(batch)) < len(packed(records)) * 0.15
        assert "never-upload" not in document_text(documents[0][0])
    finally:
        log.close()


def legacy_database(path, count=1205):
    client = str(uuid.uuid4())
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE meta(key TEXT PRIMARY KEY,value TEXT NOT NULL);
            CREATE TABLE events(seq INTEGER PRIMARY KEY AUTOINCREMENT,id TEXT NOT NULL UNIQUE,
              client TEXT NOT NULL,room TEXT NOT NULL,document TEXT NOT NULL,acked INTEGER NOT NULL DEFAULT 0);
        """)
        db.execute("INSERT INTO meta VALUES('client',?)", (client,))
        for seq in range(1, count + 1):
            record = {"id": str(uuid.uuid4()), "client": client, "room": "legacy", "run": "old-run",
                      "level": "INFO", "event": "old.event", "fields": {"index": seq, "data": "x" * 600}}
            db.execute("INSERT INTO events VALUES(?,?,?,?,?,?)",
                       (seq, record["id"], client, "legacy", packed(record).decode(), int(seq % 2 == 0)))
    return client


def snapshot_rows(db):
    return [(seq, event_id, client, room, load_document(doc), acked)
            for seq, event_id, client, room, doc, acked in db.execute(
                "SELECT seq,id,client,room,document,acked FROM events ORDER BY seq")]


def test_legacy_migration_preserves_all_records_ids_cursors_ack_identity_and_search(tmp_path):
    path = tmp_path / "legacy.db"
    client = legacy_database(path)
    with sqlite3.connect(path) as db:
        before = snapshot_rows(db)
    original_bytes = path.stat().st_size
    old_reader = LogReader(path)
    assert old_reader.browse(run="old-run", search='"index":17')[0]["event"] == "old.event"
    old_reader.close()
    log = Journal(path, role="client", console=False)
    try:
        assert log.client == client
        assert snapshot_rows(log.db) == before
        assert log.db.execute("SELECT COUNT(*) FROM events WHERE typeof(document)='blob'").fetchone()[0] == 1205
        assert path.stat().st_size < original_bytes * 0.7
        assert log.event("new.event")["client"] == client
        assert log.query(after=1205)[0]["cursor"] == 1206
        reader = LogReader(path)
        try:
            assert len(reader.browse(run="old-run", limit=1000)) == 1000
            assert reader.browse(after=16, before=18, search='"index":17')[0]["cursor"] == 17
            assert reader.stats()["total"] == 1206
        finally:
            reader.close()
    finally:
        log.close()
    log = Journal(path, role="client", console=False)
    try:
        assert snapshot_rows(log.db)[:1205] == before
    finally:
        log.close()


def test_interrupted_migration_resumes_mixed_rows_and_pending_compaction(tmp_path, monkeypatch):
    path = tmp_path / "legacy.db"
    legacy_database(path)
    with sqlite3.connect(path) as db:
        before = snapshot_rows(db)
    from p2plab import journal

    real_store = journal.store_document
    calls = 0

    def interrupt(record):
        nonlocal calls
        calls += 1
        if calls == 1010:
            raise RuntimeError("simulated crash")
        return real_store(record)

    monkeypatch.setattr(journal, "store_document", interrupt)
    with pytest.raises(RuntimeError, match="simulated crash"):
        Journal(path, role="client", console=False)
    with sqlite3.connect(path) as db:
        assert snapshot_rows(db) == before
        assert db.execute("SELECT COUNT(*) FROM events WHERE typeof(document)='blob'").fetchone()[0] == 1000
    monkeypatch.setattr(journal, "store_document", real_store)
    log = Journal(path, role="client", console=False)
    try:
        assert snapshot_rows(log.db) == before
        assert not log.db.execute("SELECT 1 FROM meta WHERE key='log_compaction_pending'").fetchone()
    finally:
        log.close()


@pytest.mark.parametrize("mutation,error", [
    ({"encoding": "unknown"}, "LOG_ENCODING_UNSUPPORTED"),
    ({"count": True}, "LOG_BATCH_LIMIT"),
    ({"count": MAX_BATCH_EVENTS + 1}, "LOG_BATCH_LIMIT"),
    ({"raw_bytes": MAX_BATCH_BYTES + 1}, "LOG_BATCH_BYTES_LIMIT"),
    ({"data": "%invalid%"}, "LOG_COMPRESSED_INVALID"),
    ({"data": "x" * 300_000}, "LOG_COMPRESSED_LIMIT"),
    ({"data": base64.b64encode(zlib.compress(b"[{}]") + b"trailing").decode()}, "LOG_COMPRESSED_INVALID"),
    ({"data": base64.b64encode(zlib.compress(b"[{}]")[:-2]).decode()}, "LOG_COMPRESSED_INVALID"),
    ({"raw_bytes": 100}, "LOG_BATCH_SIZE_MISMATCH"),
    ({"count": 2}, "LOG_BATCH_COUNT_MISMATCH"),
])
def test_wire_rejects_corruption_or_invalid_limits(mutation, error):
    body = encode_batch([{}])
    body.update(mutation)
    with pytest.raises(ValueError, match=error):
        decode_batch(body)


def test_decompression_bomb_is_bounded_and_storage_corruption_fails():
    with pytest.raises(ValueError, match="LOG_DECOMPRESSED_LIMIT"):
        inflate(zlib.compress(b"x" * 2_000_000), 100)
    with pytest.raises(ValueError, match="LOG_STORAGE_FORMAT"):
        document_text(b"unknown")
    with pytest.raises(ValueError, match="LOG_COMPRESSED_INVALID"):
        document_text(MAGIC + b"broken")
    legacy = packed({"event": "legacy.compressed", "message": "旧格式"})
    assert document_text(LEGACY_MAGIC + zlib.compress(legacy)) == legacy.decode()


@pytest.mark.parametrize("options,error", [
    ({"upload_interval": 0}, "LOG_UPLOAD_INTERVAL"),
    ({"upload_interval": float("nan")}, "LOG_UPLOAD_INTERVAL"),
    ({"retry_interval": 2}, "LOG_RETRY_INTERVAL"),
    ({"batch_events": True}, "LOG_BATCH_EVENTS"),
    ({"batch_events": 1025}, "LOG_BATCH_EVENTS"),
])
def test_upload_settings_are_bounded(tmp_path, options, error):
    with pytest.raises(ValueError, match=error):
        Client({"data_dir": str(tmp_path), "logs": options}, "settings", console=False)


async def test_legacy_server_fallback_preserves_small_batches_and_shutdown_spool(tmp_path):
    client = Client({"data_dir": str(tmp_path), "logs": {"batch_events": 1024}}, "legacy", console=False)
    for i in range(200):
        client.log.event("legacy.pending", index=i)
    body, ids = client.prepare_log_upload()
    assert "encoding" not in body
    assert len(body["events"]) == len(ids) == 64
    assert len(client.log.pending(limit=1024, max_bytes=MAX_BATCH_BYTES)) == 200
    persistent = client.log.client
    await client.close()
    reopened = Journal(tmp_path / "client.sqlite3", role="client", console=False)
    try:
        assert reopened.client == persistent
        assert len(reopened.pending(limit=1024, max_bytes=MAX_BATCH_BYTES)) == 202
    finally:
        reopened.close()


def test_incompressible_batches_shrink_without_losing_any_pending_events(tmp_path):
    client = Client({"data_dir": str(tmp_path), "logs": {"batch_events": 1024}}, "noise", console=False)
    client.log_encoding = CODEC
    original = [client.log.event("noise", payload=base64.b64encode(os.urandom(40_000)).decode())
                for _ in range(25)]
    delivered = []
    try:
        while True:
            body, ids = client.prepare_log_upload()
            if not ids:
                break
            assert len(ids) < len(original)
            delivered.extend(record["id"] for record in decode_batch(body))
            client.log.ack(list(ids))
        assert delivered == [e["id"] for e in original]
    finally:
        client.identity.close()
        client.log.close()


async def test_compressed_upload_retry_dedup_atomic_commit_and_legacy_compatibility(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    local = Journal(tmp_path / "local.db", role="client", room="batch", console=False)
    try:
        async with aiohttp.ClientSession() as session:
            ws, welcome = await join(session, url, tmp_path / "identity", room="batch", client=local.client)
            assert CODEC in welcome["log_encodings"]
            await ws.receive_json()
            for i in range(800):
                local.event("batch.event", index=i)
            batch = local.pending(limit=1024, max_bytes=MAX_BATCH_BYTES - 4096)
            body = {"v": 1, **encode_batch(batch)}
            for _ in range(2):
                await ws.send_json(body)
                ack = await ws.receive_json()
                assert ack["ids"] == [e["id"] for e in batch]
            received = [r for r in journal.query(room="batch") if r["event"] == "batch.event"]
            assert len(received) == 800
            local.ack(ack["ids"])
            assert local.pending() == []
            legacy = local.event("legacy.event")
            await ws.send_json({"v": 1, "type": "logs", "events": [legacy]})
            assert (await ws.receive_json())["ids"] == [legacy["id"]]
            first = local.event("should.rollback")
            bad = {**first, "id": str(uuid.uuid4()), "client": str(uuid.uuid4())}
            await ws.send_json({"v": 1, **encode_batch([first, bad])})
            assert (await ws.receive_json())["code"] == "LOG_CLIENT_MISMATCH"
            assert not any(r["id"] == first["id"] for r in journal.query(room="batch"))
            await ws.close()
    finally:
        local.close()
        await cleanup_hub(journal, runner, transport, tcp)


async def test_upload_cadence_keeps_every_entry_and_retries_only_after_timeout(tmp_path):
    client = Client({"data_dir": str(tmp_path), "logs": {"upload_interval": 0.3, "retry_interval": 0.6}},
                    "cadence", console=False)
    client.log_encoding = CODEC
    client.ws = Namespace(closed=False)
    client.connected.set()
    sent = []

    async def send(body):
        sent.append((time.monotonic(), decode_batch(body)))
        if len(sent) > 1:
            await client.handle_control({"type": "logs_ack", "ids": [r["id"] for r in sent[-1][1]]})

    client.send_control = send
    client.log.event("first")
    task = asyncio.create_task(client.uploader())
    try:
        await wait_for(lambda: len(sent) == 1)
        second = client.log.event("second")
        await asyncio.sleep(0.35)
        assert len(sent) == 1
        assert len(client.log.pending()) == 2
        await wait_for(lambda: len(sent) >= 2)
        assert sent[1][0] - sent[0][0] >= 0.6
        assert second["id"] in {r["id"] for r in sent[1][1]}
        third = client.log.event("third")
        await asyncio.sleep(0.15)
        assert len(sent) == 2
        await wait_for(lambda: len(sent) >= 3)
        assert sent[2][0] - sent[1][0] >= 0.3
        assert third["id"] in {r["id"] for r in sent[2][1]}
        assert client.log.pending() == []
    finally:
        client.stop.set()
        await task
        client.identity.close()
        client.log.close()


async def test_large_offline_spool_uploads_compressed_after_reconnect(tmp_path):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    client = Client({"server": url, "data_dir": str(tmp_path / "client"),
                     "logs": {"upload_interval": 0.1, "retry_interval": 0.2},
                     "experiment": {"diagnostics": False, "gateway": False, "stun": []}},
                    "spool", console=False)
    original = [client.log.event("offline.event", index=i) for i in range(2300)]
    tasks = [asyncio.create_task(client.signaling()), asyncio.create_task(client.uploader())]
    try:
        await wait_for(lambda: client.connected.is_set())
        await wait_for(lambda: not client.log.pending(), timeout=10)
        ids = []
        cursor = 0
        while rows := journal.query(after=cursor, room="spool"):
            cursor = rows[-1]["cursor"]
            ids.extend(r["id"] for r in rows if r["event"] == "offline.event")
        assert ids == [r["id"] for r in original]
        commits = []
        cursor = 0
        while rows := journal.query(after=cursor, room="spool"):
            cursor = rows[-1]["cursor"]
            commits.extend(r for r in rows if r["event"] == "logs.committed")
        assert commits and all(r["fields"]["encoding"] == CODEC for r in commits)
    finally:
        await client.close()
        await asyncio.gather(*tasks, return_exceptions=True)
        await cleanup_hub(journal, runner, transport, tcp)


async def test_compressed_http_and_gzip_paginated_export_with_incremental_append(tmp_path, capsys):
    hub, journal, runner, transport, tcp, url = await start_hub(tmp_path)
    token = tmp_path / "admin.token"
    token.write_text("admin")
    output = tmp_path / "events.jsonl.gz"
    for i in range(1105):
        journal.event("export.event", room="export", index=i, payload="中文" * 50)
    args = Namespace(server=url.replace("ws://", "http://").removesuffix("/ws"),
                     token_file=str(token), ca_file=None, output=str(output), after=0,
                     room="export", client=None)
    try:
        async with aiohttp.ClientSession(auto_decompress=False) as session:
            async with session.get(args.server + "/logs", params={"room": "export"},
                                   headers={"Authorization": "Bearer admin", "Accept-Encoding": "gzip"}) as response:
                assert response.headers["Content-Encoding"] == "gzip"
                raw = gzip.decompress(await response.read())
                assert len(json.loads(raw)["events"]) == 1000
        await download(args)
        with gzip.open(output, "rt", encoding="utf-8") as f:
            first = [json.loads(line) for line in f]
        originals = [r for r in first if r["event"] == "export.event"]
        assert len(originals) == 1105
        assert [r["fields"]["index"] for r in originals] == list(range(1105))
        assert output.stat().st_mode & 0o777 == 0o600
        args.after = first[-1]["cursor"]
        new = journal.event("export.new", room="export")
        await download(args)
        with gzip.open(output, "rt", encoding="utf-8") as f:
            appended = [json.loads(line) for line in f]
        assert appended[:len(first)] == first
        assert sum(r["id"] == new["id"] for r in appended) == 1
        assert output.stat().st_size < len(packed(appended)) * 0.2
        assert hashlib.sha256(packed(first)).digest() == hashlib.sha256(packed(appended[:len(first)])).digest()
        assert "Exported through cursor" in capsys.readouterr().out
    finally:
        await cleanup_hub(journal, runner, transport, tcp)
