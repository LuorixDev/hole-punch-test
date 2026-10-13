"""Lossless log codecs, with bounded decompression on both disk and wire."""

from __future__ import annotations

import base64
import binascii
import json
import zlib

from .common import packed

CODEC = "zlib-json-v1"
MAGIC = b"P2PLOG2\0"
LEGACY_MAGIC = b"P2PLOG1\0"
# Immutable v2 dictionary: common public schema, never user data or credentials.
STORAGE_DICTIONARY = (
    b'journal.fragment original_id original_event index parts json_part '
    b'logs.committed count encoding raw_bytes encoded_bytes zlib-json-v1 '
    b'signaling.connected path.opened path.verified WARNING ERROR DEBUG server '
    b'{"client":"","event":"path.rtt_sample","fields":{"attempt":"",'
    b'"interval_seconds":2,"rtt_ms":0},"id":"","level":"INFO","message":"",'
    b'"role":"client","room":"","run":"","time":""}'
)
MAX_RECORD_BYTES = 128_000
MAX_BATCH_EVENTS = 1024
MAX_BATCH_BYTES = 2_000_000
MAX_COMPRESSED_BYTES = 200_000


def inflate(data: bytes, limit: int, *, dictionary: bytes = b"") -> bytes:
    try:
        decoder = zlib.decompressobj(zdict=dictionary)
        raw = decoder.decompress(data, limit + 1)
        if len(raw) > limit or decoder.unconsumed_tail:
            raise ValueError("LOG_DECOMPRESSED_LIMIT")
        if not decoder.eof or decoder.unused_data:
            raise ValueError("LOG_COMPRESSED_INVALID")
        return raw
    except zlib.error as exc:
        raise ValueError("LOG_COMPRESSED_INVALID") from exc


def store_document(record: dict) -> bytes:
    encoder = zlib.compressobj(level=1, zdict=STORAGE_DICTIONARY)
    return MAGIC + encoder.compress(packed(record)) + encoder.flush()


def document_text(document: str | bytes) -> str:
    if isinstance(document, str):
        return document  # Legacy SQLite TEXT rows remain readable during migration.
    if document.startswith(LEGACY_MAGIC):
        return inflate(document[len(LEGACY_MAGIC):], MAX_RECORD_BYTES).decode("utf-8")
    if not document.startswith(MAGIC):
        raise ValueError("LOG_STORAGE_FORMAT")
    return inflate(document[len(MAGIC):], MAX_RECORD_BYTES, dictionary=STORAGE_DICTIONARY).decode("utf-8")


def load_document(document: str | bytes) -> dict:
    return json.loads(document_text(document))


def encode_batch(records: list[dict]) -> dict:
    if not records or len(records) > MAX_BATCH_EVENTS:
        raise ValueError("LOG_BATCH_LIMIT")
    raw = packed(records)
    if len(raw) > MAX_BATCH_BYTES:
        raise ValueError("LOG_BATCH_BYTES_LIMIT")
    compressed = zlib.compress(raw, level=3)
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("LOG_COMPRESSED_LIMIT")
    return {
        "type": "logs", "encoding": CODEC, "count": len(records),
        "raw_bytes": len(raw), "data": base64.b64encode(compressed).decode("ascii"),
    }


def decode_batch(body: dict) -> list[dict]:
    if body.get("encoding") != CODEC:
        raise ValueError("LOG_ENCODING_UNSUPPORTED")
    count, size, data = body.get("count"), body.get("raw_bytes"), body.get("data")
    if type(count) is not int or not 1 <= count <= MAX_BATCH_EVENTS:
        raise ValueError("LOG_BATCH_LIMIT")
    if type(size) is not int or not 1 <= size <= MAX_BATCH_BYTES:
        raise ValueError("LOG_BATCH_BYTES_LIMIT")
    if not isinstance(data, str) or len(data) > ((MAX_COMPRESSED_BYTES + 2) // 3) * 4:
        raise ValueError("LOG_COMPRESSED_LIMIT")
    try:
        compressed = base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("LOG_COMPRESSED_INVALID") from exc
    if len(compressed) > MAX_COMPRESSED_BYTES:
        raise ValueError("LOG_COMPRESSED_LIMIT")
    raw = inflate(compressed, size)
    if len(raw) != size:
        raise ValueError("LOG_BATCH_SIZE_MISMATCH")
    try:
        records = json.loads(raw)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise ValueError("LOG_BATCH_JSON_INVALID") from exc
    if not isinstance(records, list) or len(records) != count:
        raise ValueError("LOG_BATCH_COUNT_MISMATCH")
    return records
