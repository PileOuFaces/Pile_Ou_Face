# SPDX-License-Identifier: AGPL-3.0-only
"""Dedicated SQLite store for binary annotations (comments, renames,
bookmarks, review-status, ...), keyed by the sha256 of the binary's content.

This store lives at a fixed location under the user's home directory so
that it is independently resolvable both by the VS Code extension (Node/TS
side) and by a standalone MCP server process that has no access to VS Code
internals.
"""

import hashlib
import sqlite3
from pathlib import Path


def default_db_path() -> Path:
    """Return the default location of the annotations database."""
    return Path.home() / ".pile-ou-face" / "annotations.db"


def hash_binary_content(binary_path: str) -> str:
    """Return the sha256 hex digest of the file at ``binary_path``.

    Reads the file in chunks so large binaries aren't loaded fully into
    memory.
    """
    sha256 = hashlib.sha256()
    with open(binary_path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


class AnnotationDb:
    """SQLite-backed store for annotations on binary addresses."""

    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS binaries (
                sha256 TEXT PRIMARY KEY,
                first_seen_path TEXT,
                indexed_at INTEGER
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS annotations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                binary_sha256 TEXT NOT NULL REFERENCES binaries(sha256) ON DELETE CASCADE,
                addr TEXT NOT NULL,
                kind TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                UNIQUE(binary_sha256, addr, kind)
            )
            """
        )
        self._conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_annotations_binary_sha256 "
            "ON annotations(binary_sha256)"
        )
        self._conn.commit()

    def _ensure_binary(self, sha256: str, binary_path: str) -> None:
        self._conn.execute(
            """
            INSERT OR IGNORE INTO binaries (sha256, first_seen_path, indexed_at)
            VALUES (?, ?, strftime('%s', 'now'))
            """,
            (sha256, binary_path),
        )

    def get_annotations(self, binary_path: str, addr: str | None = None) -> list:
        sha256 = hash_binary_content(binary_path)
        if addr is None:
            cur = self._conn.execute(
                "SELECT addr, kind, value, updated_at FROM annotations "
                "WHERE binary_sha256 = ? ORDER BY addr, kind",
                (sha256,),
            )
        else:
            cur = self._conn.execute(
                "SELECT addr, kind, value, updated_at FROM annotations "
                "WHERE binary_sha256 = ? AND addr = ? ORDER BY kind",
                (sha256, addr),
            )
        return [dict(row) for row in cur.fetchall()]

    def save_annotation(
        self, binary_path: str, addr: str, kind: str, value: str
    ) -> None:
        sha256 = hash_binary_content(binary_path)
        self._ensure_binary(sha256, binary_path)
        self._conn.execute(
            "DELETE FROM annotations WHERE binary_sha256 = ? AND addr = ? AND kind = ?",
            (sha256, addr, kind),
        )
        self._conn.execute(
            """
            INSERT INTO annotations (binary_sha256, addr, kind, value, updated_at)
            VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
            """,
            (sha256, addr, kind, value),
        )
        self._conn.commit()

    def delete_annotation(
        self, binary_path: str, addr: str, kind: str | None = None
    ) -> int:
        sha256 = hash_binary_content(binary_path)
        if kind is None:
            cur = self._conn.execute(
                "DELETE FROM annotations WHERE binary_sha256 = ? AND addr = ?",
                (sha256, addr),
            )
        else:
            cur = self._conn.execute(
                "DELETE FROM annotations WHERE binary_sha256 = ? AND addr = ? AND kind = ?",
                (sha256, addr, kind),
            )
        self._conn.commit()
        return cur.rowcount

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "AnnotationDb":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.close()
