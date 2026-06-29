# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.cache.cache_index."""

from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from backends.static.cache.cache_index import list_entries, prune_entries, upsert_entry


class TestStaticCacheIndex(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.db_path = self.root / "cache-index.sqlite3"
        self.workspace_root = str(self.root / "workspace")
        Path(self.workspace_root).mkdir(parents=True, exist_ok=True)
        self.binary = Path(self.workspace_root) / "demo.elf"
        self.binary.write_bytes(b"\x7fELFdemo")
        self.cache_dir = (
            Path(self.workspace_root)
            / ".pile-ou-face"
            / "static_cache"
            / "deadbeefcafebabe"
        )
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.cache_file = self.cache_dir / "info.json"
        self.cache_file.write_text('{"ok":true}', encoding="utf-8")

    def _upsert_info(self) -> None:
        stat = self.binary.stat()
        payload_stat = self.cache_file.stat()
        upsert_entry(
            str(self.db_path),
            workspace_root=self.workspace_root,
            cache_key="deadbeefcafebabe",
            binary_path=str(self.binary),
            cache_type="info",
            cache_file=self.cache_file.name,
            cache_path=str(self.cache_file),
            cache_dir=str(self.cache_dir),
            payload_bytes=payload_stat.st_size,
            binary_mtime_ms=stat.st_mtime_ns / 1_000_000,
            binary_size=stat.st_size,
            updated_at_ms=payload_stat.st_mtime_ns / 1_000_000,
        )

    def test_list_entries_reports_ok_status(self):
        self._upsert_info()
        entries = list_entries(str(self.db_path), workspace_root=self.workspace_root)
        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["cacheTypes"], ["info"])
        self.assertEqual(entry["fileCount"], 1)
        self.assertTrue(entry["binaryExists"])

    def test_list_entries_reports_stale_when_binary_changes(self):
        self._upsert_info()
        time.sleep(0.02)
        self.binary.write_bytes(b"\x7fELFdemo-changed")
        entries = list_entries(str(self.db_path), workspace_root=self.workspace_root)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["status"], "stale")
        self.assertTrue(entries[0]["binaryExists"])

    def test_prune_entries_removes_missing_or_stale_rows(self):
        self._upsert_info()
        self.cache_file.unlink()
        removed = prune_entries(str(self.db_path), workspace_root=self.workspace_root)
        self.assertGreaterEqual(removed, 1)
        entries = list_entries(str(self.db_path), workspace_root=self.workspace_root)
        self.assertEqual(entries, [])


if __name__ == "__main__":
    unittest.main()
