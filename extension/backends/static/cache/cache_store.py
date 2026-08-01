# SPDX-License-Identifier: AGPL-3.0-only
"""Bounded SQLite-only store for heterogeneous static-analysis cache payloads."""

from __future__ import annotations

import json
import os
import sqlite3
import time
from pathlib import Path
from typing import Any

DB_NAME = "static-cache.sqlite3"
MAX_PAYLOAD_BYTES = 16 * 1024 * 1024
MAX_TOTAL_BYTES = 256 * 1024 * 1024
MAX_ENTRIES = 4_096

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cache_entries (
    namespace TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    variant TEXT NOT NULL DEFAULT '',
    binary_path TEXT NOT NULL DEFAULT '',
    binary_mtime_ms REAL NOT NULL DEFAULT 0,
    binary_size INTEGER NOT NULL DEFAULT 0,
    payload_json TEXT NOT NULL,
    payload_bytes INTEGER NOT NULL,
    created_at_ms REAL NOT NULL,
    accessed_at_ms REAL NOT NULL,
    PRIMARY KEY(namespace, cache_key, variant)
);
CREATE INDEX IF NOT EXISTS idx_cache_binary ON cache_entries(binary_path);
CREATE INDEX IF NOT EXISTS idx_cache_accessed ON cache_entries(accessed_at_ms);
"""


def resolve_db_path(root_or_db: str | os.PathLike[str]) -> Path:
    path = Path(root_or_db)
    return path if path.suffix in {".db", ".sqlite", ".sqlite3"} else path / DB_NAME


def _open(root_or_db: str | os.PathLike[str]) -> sqlite3.Connection:
    db_path = resolve_db_path(root_or_db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(db_path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA journal_mode = WAL")
    connection.executescript(SCHEMA_SQL)
    return connection


def get_payload(
    root_or_db: str | os.PathLike[str],
    namespace: str,
    cache_key: str,
    variant: str = "",
) -> Any | None:
    if not resolve_db_path(root_or_db).is_file():
        return None
    with _open(root_or_db) as connection:
        row = connection.execute(
            "SELECT payload_json FROM cache_entries WHERE namespace=? AND cache_key=? AND variant=?",
            (namespace, cache_key, variant),
        ).fetchone()
        if not row:
            return None
        connection.execute(
            "UPDATE cache_entries SET accessed_at_ms=? WHERE namespace=? AND cache_key=? AND variant=?",
            (time.time() * 1000, namespace, cache_key, variant),
        )
        try:
            return json.loads(row["payload_json"])
        except (TypeError, json.JSONDecodeError):
            connection.execute(
                "DELETE FROM cache_entries WHERE namespace=? AND cache_key=? AND variant=?",
                (namespace, cache_key, variant),
            )
            return None


def put_payload(
    root_or_db: str | os.PathLike[str],
    namespace: str,
    cache_key: str,
    payload: Any,
    *,
    variant: str = "",
    binary_path: str = "",
    binary_mtime_ms: float = 0,
    binary_size: int = 0,
) -> int:
    serialized = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    payload_bytes = len(serialized.encode("utf-8"))
    if payload_bytes > MAX_PAYLOAD_BYTES:
        raise ValueError(f"Cache payload exceeds {MAX_PAYLOAD_BYTES} bytes")
    now = time.time() * 1000
    with _open(root_or_db) as connection:
        connection.execute(
            """INSERT INTO cache_entries(
                namespace, cache_key, variant, binary_path, binary_mtime_ms, binary_size,
                payload_json, payload_bytes, created_at_ms, accessed_at_ms
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(namespace, cache_key, variant) DO UPDATE SET
                binary_path=excluded.binary_path, binary_mtime_ms=excluded.binary_mtime_ms,
                binary_size=excluded.binary_size, payload_json=excluded.payload_json,
                payload_bytes=excluded.payload_bytes, accessed_at_ms=excluded.accessed_at_ms""",
            (
                namespace,
                cache_key,
                variant,
                str(Path(binary_path).resolve()) if binary_path else "",
                float(binary_mtime_ms),
                int(binary_size),
                serialized,
                payload_bytes,
                now,
                now,
            ),
        )
        _enforce_limits(connection)
    return payload_bytes


def _enforce_limits(connection: sqlite3.Connection) -> None:
    row = connection.execute(
        "SELECT COUNT(*) AS entries, COALESCE(SUM(payload_bytes), 0) AS bytes FROM cache_entries"
    ).fetchone()
    overflow_entries = max(0, int(row["entries"]) - MAX_ENTRIES)
    total_bytes = int(row["bytes"])
    while overflow_entries > 0 or total_bytes > MAX_TOTAL_BYTES:
        oldest = connection.execute(
            "SELECT namespace, cache_key, variant, payload_bytes FROM cache_entries ORDER BY accessed_at_ms ASC LIMIT 1"
        ).fetchone()
        if not oldest:
            break
        connection.execute(
            "DELETE FROM cache_entries WHERE namespace=? AND cache_key=? AND variant=?",
            (oldest["namespace"], oldest["cache_key"], oldest["variant"]),
        )
        overflow_entries = max(0, overflow_entries - 1)
        total_bytes -= int(oldest["payload_bytes"])


def list_entries(root_or_db: str | os.PathLike[str]) -> list[dict[str, Any]]:
    if not resolve_db_path(root_or_db).is_file():
        return []
    with _open(root_or_db) as connection:
        rows = connection.execute(
            """SELECT cache_key, binary_path, binary_mtime_ms, binary_size,
                      GROUP_CONCAT(DISTINCT namespace) AS namespaces,
                      SUM(payload_bytes) AS size, COUNT(*) AS file_count,
                      MAX(accessed_at_ms) AS mtime
               FROM cache_entries GROUP BY cache_key, binary_path, binary_mtime_ms, binary_size
               ORDER BY mtime DESC"""
        ).fetchall()
    return [_list_entry(row) for row in rows]


def _list_entry(row: sqlite3.Row) -> dict[str, Any]:
    binary_path = str(row["binary_path"] or "")
    binary_exists = bool(binary_path and os.path.isfile(binary_path))
    status = "missing"
    if binary_exists:
        stat = os.stat(binary_path)
        mtime_ms = stat.st_mtime_ns / 1_000_000
        status = (
            "ok"
            if abs(mtime_ms - float(row["binary_mtime_ms"])) <= 0.001
            and stat.st_size == int(row["binary_size"])
            else "stale"
        )
    return {
        "key": row["cache_key"],
        "path": binary_path,
        "binaryPath": binary_path,
        "binaryExists": binary_exists,
        "status": status,
        "size": int(row["size"] or 0),
        "mtime": float(row["mtime"] or 0),
        "cacheTypes": sorted(filter(None, str(row["namespaces"] or "").split(","))),
        "fileCount": int(row["file_count"] or 0),
    }


def prune_entries(root_or_db: str | os.PathLike[str]) -> int:
    entries = list_entries(root_or_db)
    stale_keys = [
        (item["key"], item["binaryPath"]) for item in entries if item["status"] != "ok"
    ]
    if not stale_keys:
        return 0
    with _open(root_or_db) as connection:
        before = connection.total_changes
        connection.executemany(
            "DELETE FROM cache_entries WHERE cache_key=? AND binary_path=?", stale_keys
        )
        return connection.total_changes - before


def delete_binary(root_or_db: str | os.PathLike[str], binary_path: str) -> int:
    if not resolve_db_path(root_or_db).is_file():
        return 0
    with _open(root_or_db) as connection:
        cursor = connection.execute(
            "DELETE FROM cache_entries WHERE binary_path=?",
            (str(Path(binary_path).resolve()),),
        )
        return cursor.rowcount


def clear_entries(root_or_db: str | os.PathLike[str]) -> int:
    if not resolve_db_path(root_or_db).is_file():
        return 0
    with _open(root_or_db) as connection:
        count = connection.execute("SELECT COUNT(*) FROM cache_entries").fetchone()[0]
        connection.execute("DELETE FROM cache_entries")
        return int(count)
