# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite source of truth for persistent binary patch history."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path
from typing import Any

MAX_PATCHES_PER_BINARY = 4096
MAX_PATCH_BYTES = 1024 * 1024
MAX_COMMENT_CHARS = 2000


def default_db_path() -> Path:
    override = os.environ.get("POF_PATCHES_DB", "").strip()
    return Path(override) if override else Path.home() / ".pile-ou-face" / "patches.db"


class PatchDb:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS patch_binaries (
                binary_path TEXT PRIMARY KEY,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS binary_patches (
                binary_path TEXT NOT NULL REFERENCES patch_binaries(binary_path) ON DELETE CASCADE,
                patch_id TEXT NOT NULL,
                state TEXT NOT NULL CHECK(state IN ('active', 'redo')),
                ordinal INTEGER NOT NULL,
                offset INTEGER NOT NULL CHECK(offset >= 0),
                original_bytes BLOB NOT NULL,
                patched_bytes BLOB NOT NULL,
                timestamp TEXT NOT NULL,
                comment TEXT NOT NULL DEFAULT '',
                PRIMARY KEY (binary_path, patch_id),
                UNIQUE (binary_path, state, ordinal)
            );
            CREATE INDEX IF NOT EXISTS idx_binary_patches_state
                ON binary_patches(binary_path, state, ordinal);
            """
        )
        self._conn.commit()

    @staticmethod
    def _empty(binary_path: str) -> dict[str, Any]:
        return {
            "binary": os.path.abspath(binary_path),
            "patches": [],
            "redo_patches": [],
        }

    @staticmethod
    def _row_to_patch(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "id": row["patch_id"],
            "offset": row["offset"],
            "original_bytes": bytes(row["original_bytes"]).hex(" "),
            "patched_bytes": bytes(row["patched_bytes"]).hex(" "),
            "timestamp": row["timestamp"],
            "comment": row["comment"],
        }

    def load(self, binary_path: str) -> dict[str, Any]:
        binary_abs = os.path.abspath(binary_path)
        result = self._empty(binary_abs)
        rows = self._conn.execute(
            """
            SELECT patch_id, state, ordinal, offset, original_bytes, patched_bytes,
                   timestamp, comment
            FROM binary_patches
            WHERE binary_path = ?
            ORDER BY state, ordinal
            """,
            (binary_abs,),
        ).fetchall()
        for row in rows:
            target = "patches" if row["state"] == "active" else "redo_patches"
            result[target].append(self._row_to_patch(row))
        return result

    def save(self, binary_path: str, data: dict[str, Any]) -> None:
        binary_abs = os.path.abspath(binary_path)
        active = list(data.get("patches") or [])
        redo = list(data.get("redo_patches") or [])
        if len(active) + len(redo) > MAX_PATCHES_PER_BINARY:
            raise ValueError(f"Patch history limit exceeded ({MAX_PATCHES_PER_BINARY})")
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO patch_binaries(binary_path, updated_at)
                VALUES (?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
                ON CONFLICT(binary_path) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (binary_abs,),
            )
            self._conn.execute(
                "DELETE FROM binary_patches WHERE binary_path = ?", (binary_abs,)
            )
            for state, entries in (("active", active), ("redo", redo)):
                for ordinal, entry in enumerate(entries):
                    original = bytes.fromhex(str(entry.get("original_bytes") or ""))
                    patched = bytes.fromhex(str(entry.get("patched_bytes") or ""))
                    if (
                        not original
                        or not patched
                        or len(original) > MAX_PATCH_BYTES
                        or len(patched) > MAX_PATCH_BYTES
                    ):
                        raise ValueError("Invalid or oversized patch bytes")
                    self._conn.execute(
                        """
                        INSERT INTO binary_patches(
                            binary_path, patch_id, state, ordinal, offset, original_bytes,
                            patched_bytes, timestamp, comment
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            binary_abs,
                            str(entry.get("id") or "")[:128],
                            state,
                            ordinal,
                            int(entry.get("offset") or 0),
                            original,
                            patched,
                            str(entry.get("timestamp") or "")[:64],
                            str(entry.get("comment") or "")[:MAX_COMMENT_CHARS],
                        ),
                    )

    def delete(self, binary_path: str) -> int:
        with self._conn:
            cursor = self._conn.execute(
                "DELETE FROM patch_binaries WHERE binary_path = ?",
                (os.path.abspath(binary_path),),
            )
        return max(0, cursor.rowcount)

    def purge_missing(self, workspace_root: str) -> int:
        root = os.path.abspath(workspace_root)
        removed = 0
        paths = [
            row[0]
            for row in self._conn.execute("SELECT binary_path FROM patch_binaries")
        ]
        for binary_path in paths:
            try:
                in_workspace = os.path.commonpath((root, binary_path)) == root
            except ValueError:
                in_workspace = False
            if in_workspace and not os.path.exists(binary_path):
                removed += self.delete(binary_path)
        return removed

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> PatchDb:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
