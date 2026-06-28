# SPDX-License-Identifier: AGPL-3.0-only
"""Index SQLite pour le cache statique de l'extension.

Cette base ne remplace pas les payloads JSON du cache UI : elle sert de
catalogue professionnel pour inventorier, purger et préparer des workflows
multi-session sans rescanner toute la filesystem.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS cache_entries (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    workspace_root   TEXT NOT NULL,
    cache_key        TEXT NOT NULL,
    binary_path      TEXT NOT NULL,
    cache_type       TEXT NOT NULL,
    cache_file       TEXT NOT NULL,
    cache_path       TEXT NOT NULL,
    cache_dir        TEXT NOT NULL,
    payload_bytes    INTEGER NOT NULL DEFAULT 0,
    binary_mtime_ms  REAL NOT NULL DEFAULT 0,
    binary_size      INTEGER NOT NULL DEFAULT 0,
    updated_at_ms    REAL NOT NULL DEFAULT 0
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_cache_entries_unique
ON cache_entries(workspace_root, cache_key, cache_file);
CREATE INDEX IF NOT EXISTS idx_cache_entries_workspace
ON cache_entries(workspace_root, cache_key);
"""


def _open(db_path: str) -> sqlite3.Connection:
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA_SQL)
    conn.commit()
    return conn


def upsert_entry(
    db_path: str,
    *,
    workspace_root: str,
    cache_key: str,
    binary_path: str,
    cache_type: str,
    cache_file: str,
    cache_path: str,
    cache_dir: str,
    payload_bytes: int,
    binary_mtime_ms: float,
    binary_size: int,
    updated_at_ms: float,
) -> None:
    with _open(db_path) as conn:
        conn.execute(
            """
            INSERT INTO cache_entries (
                workspace_root, cache_key, binary_path, cache_type, cache_file,
                cache_path, cache_dir, payload_bytes, binary_mtime_ms, binary_size, updated_at_ms
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(workspace_root, cache_key, cache_file) DO UPDATE SET
                binary_path=excluded.binary_path,
                cache_type=excluded.cache_type,
                cache_path=excluded.cache_path,
                cache_dir=excluded.cache_dir,
                payload_bytes=excluded.payload_bytes,
                binary_mtime_ms=excluded.binary_mtime_ms,
                binary_size=excluded.binary_size,
                updated_at_ms=excluded.updated_at_ms
            """,
            (
                workspace_root,
                cache_key,
                binary_path,
                cache_type,
                cache_file,
                cache_path,
                cache_dir,
                int(payload_bytes),
                float(binary_mtime_ms),
                int(binary_size),
                float(updated_at_ms),
            ),
        )
        conn.commit()


def _entry_status(
    binary_path: str,
    binary_mtime_ms: float,
    binary_size: int,
    cache_dir: str,
    cache_paths: list[str],
) -> tuple[str, bool]:
    if not os.path.isdir(cache_dir):
        return ("missing", False)
    if any(not os.path.isfile(cache_path) for cache_path in cache_paths):
        return ("stale", True)
    if not os.path.exists(binary_path):
        return ("missing", False)
    try:
        stat = os.stat(binary_path)
    except OSError:
        return ("missing", False)
    current_mtime_ms = (
        float(getattr(stat, "st_mtime_ns", 0) / 1_000_000)
        if getattr(stat, "st_mtime_ns", None)
        else float(stat.st_mtime * 1000.0)
    )
    current_size = int(stat.st_size)
    if abs(current_mtime_ms - float(binary_mtime_ms)) > 0.001 or current_size != int(
        binary_size
    ):
        return ("stale", True)
    return ("ok", True)


def list_entries(db_path: str, *, workspace_root: str) -> list[dict[str, Any]]:
    if not os.path.exists(db_path):
        return []
    with _open(db_path) as conn:
        rows = conn.execute(
            """
            SELECT workspace_root, cache_key, binary_path, cache_type, cache_file,
                   cache_path, cache_dir, payload_bytes, binary_mtime_ms, binary_size, updated_at_ms
            FROM cache_entries
            WHERE workspace_root = ?
            ORDER BY updated_at_ms DESC, cache_file ASC
            """,
            (workspace_root,),
        ).fetchall()
    grouped: dict[tuple[str, str, str], dict[str, Any]] = {}
    for row in rows:
        key = (row["workspace_root"], row["cache_key"], row["binary_path"])
        entry = grouped.get(key)
        if entry is None:
            entry = {
                "key": row["cache_key"],
                "path": row["cache_dir"],
                "binaryPath": row["binary_path"],
                "size": 0,
                "mtime": 0,
                "binaryMtimeMs": row["binary_mtime_ms"],
                "binarySize": row["binary_size"],
                "cacheTypes": set(),
                "fileCount": 0,
                "_cache_paths": [],
            }
            grouped[key] = entry
        entry["size"] += int(row["payload_bytes"] or 0)
        entry["mtime"] = max(float(entry["mtime"]), float(row["updated_at_ms"] or 0))
        entry["cacheTypes"].add(str(row["cache_type"] or "").strip())
        entry["fileCount"] += 1
        entry["_cache_paths"].append(str(row["cache_path"] or ""))
    result = []
    for entry in grouped.values():
        status, binary_exists = _entry_status(
            str(entry["binaryPath"] or ""),
            float(entry["binaryMtimeMs"] or 0),
            int(entry["binarySize"] or 0),
            str(entry["path"] or ""),
            [p for p in entry["_cache_paths"] if p],
        )
        result.append(
            {
                "key": entry["key"],
                "path": entry["path"],
                "binaryPath": entry["binaryPath"],
                "binaryExists": binary_exists,
                "status": status,
                "size": entry["size"],
                "mtime": entry["mtime"],
                "binaryMtimeMs": entry["binaryMtimeMs"],
                "binarySize": entry["binarySize"],
                "cacheTypes": sorted(t for t in entry["cacheTypes"] if t),
                "fileCount": entry["fileCount"],
            }
        )
    result.sort(key=lambda item: float(item.get("mtime") or 0), reverse=True)
    return result


def prune_entries(db_path: str, *, workspace_root: str) -> int:
    if not os.path.exists(db_path):
        return 0
    with _open(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, binary_path, binary_mtime_ms, binary_size, cache_dir, cache_path
            FROM cache_entries
            WHERE workspace_root = ?
            """,
            (workspace_root,),
        ).fetchall()
        to_delete: list[int] = []
        for row in rows:
            status, _ = _entry_status(
                str(row["binary_path"] or ""),
                float(row["binary_mtime_ms"] or 0),
                int(row["binary_size"] or 0),
                str(row["cache_dir"] or ""),
                [str(row["cache_path"] or "")],
            )
            if status != "ok":
                to_delete.append(int(row["id"]))
        if to_delete:
            conn.executemany(
                "DELETE FROM cache_entries WHERE id = ?",
                [(row_id,) for row_id in to_delete],
            )
            conn.commit()
        return len(to_delete)


def clear_entries(db_path: str, *, workspace_root: str) -> int:
    if not os.path.exists(db_path):
        return 0
    with _open(db_path) as conn:
        before = conn.execute(
            "SELECT COUNT(*) AS n FROM cache_entries WHERE workspace_root = ?",
            (workspace_root,),
        ).fetchone()
        conn.execute(
            "DELETE FROM cache_entries WHERE workspace_root = ?", (workspace_root,)
        )
        conn.commit()
        return int(before["n"] if before else 0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Manage static cache index for the VS Code extension"
    )
    parser.add_argument("--db", required=True, help="SQLite path for the cache index")
    sub = parser.add_subparsers(dest="command", required=True)

    p_upsert = sub.add_parser("upsert", help="Insert or update one cache payload entry")
    p_upsert.add_argument("--workspace-root", required=True)
    p_upsert.add_argument("--cache-key", required=True)
    p_upsert.add_argument("--binary-path", required=True)
    p_upsert.add_argument("--cache-type", required=True)
    p_upsert.add_argument("--cache-file", required=True)
    p_upsert.add_argument("--cache-path", required=True)
    p_upsert.add_argument("--cache-dir", required=True)
    p_upsert.add_argument("--payload-bytes", type=int, required=True)
    p_upsert.add_argument("--binary-mtime-ms", type=float, required=True)
    p_upsert.add_argument("--binary-size", type=int, required=True)
    p_upsert.add_argument("--updated-at-ms", type=float, required=True)

    p_list = sub.add_parser("list", help="List cache entries for one workspace")
    p_list.add_argument("--workspace-root", required=True)

    p_prune = sub.add_parser("prune", help="Delete obsolete rows for one workspace")
    p_prune.add_argument("--workspace-root", required=True)

    p_clear = sub.add_parser("clear", help="Delete every row for one workspace")
    p_clear.add_argument("--workspace-root", required=True)

    args = parser.parse_args()

    if args.command == "upsert":
        upsert_entry(
            args.db,
            workspace_root=args.workspace_root,
            cache_key=args.cache_key,
            binary_path=args.binary_path,
            cache_type=args.cache_type,
            cache_file=args.cache_file,
            cache_path=args.cache_path,
            cache_dir=args.cache_dir,
            payload_bytes=args.payload_bytes,
            binary_mtime_ms=args.binary_mtime_ms,
            binary_size=args.binary_size,
            updated_at_ms=args.updated_at_ms,
        )
        print(json.dumps({"ok": True}))
        return 0
    if args.command == "list":
        print(
            json.dumps(
                {"entries": list_entries(args.db, workspace_root=args.workspace_root)},
                ensure_ascii=False,
            )
        )
        return 0
    if args.command == "prune":
        removed = prune_entries(args.db, workspace_root=args.workspace_root)
        print(json.dumps({"removed": removed}))
        return 0
    if args.command == "clear":
        removed = clear_entries(args.db, workspace_root=args.workspace_root)
        print(json.dumps({"removed": removed}))
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
