# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the bounded SQLite-only static cache store."""

from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from backends.static.cache import cache_store


class TestStaticCacheStore(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / "static_cache"
        self.binary = Path(self.tmp.name) / "demo.elf"
        self.binary.write_bytes(b"\x7fELFdemo")
        stat = self.binary.stat()
        self.meta = {
            "binary_path": str(self.binary.resolve()),
            "binary_mtime_ms": stat.st_mtime_ns / 1_000_000,
            "binary_size": stat.st_size,
        }

    def put(self, key="deadbeef", namespace="info", payload=None, variant=""):
        return cache_store.put_payload(
            self.root,
            namespace,
            key,
            payload or {"ok": True},
            variant=variant,
            **self.meta,
        )

    def test_missing_read_does_not_create_database(self):
        self.assertIsNone(cache_store.get_payload(self.root, "info", "missing"))
        self.assertFalse(cache_store.resolve_db_path(self.root).exists())

    def test_round_trip_and_variants(self):
        self.put(payload={"value": "default"})
        self.put(payload={"value": "wide"}, variant="utf16")
        self.assertEqual(
            cache_store.get_payload(self.root, "info", "deadbeef"), {"value": "default"}
        )
        self.assertEqual(
            cache_store.get_payload(self.root, "info", "deadbeef", "utf16"),
            {"value": "wide"},
        )

    def test_list_reports_grouped_valid_entry(self):
        self.put(namespace="info")
        self.put(namespace="symbols")
        entry = cache_store.list_entries(self.root)[0]
        self.assertEqual(entry["status"], "ok")
        self.assertEqual(entry["cacheTypes"], ["info", "symbols"])
        self.assertEqual(entry["fileCount"], 2)

    def test_changed_binary_is_stale_and_pruned(self):
        self.put()
        time.sleep(0.002)
        self.binary.write_bytes(b"changed payload")
        self.assertEqual(cache_store.list_entries(self.root)[0]["status"], "stale")
        self.assertEqual(cache_store.prune_entries(self.root), 1)
        self.assertEqual(cache_store.list_entries(self.root), [])

    def test_delete_binary_and_clear(self):
        self.put("one")
        self.put("two")
        self.assertEqual(cache_store.delete_binary(self.root, str(self.binary)), 2)
        self.put("three")
        self.assertEqual(cache_store.clear_entries(self.root), 1)

    def test_rejects_oversized_payload(self):
        with mock.patch.object(cache_store, "MAX_PAYLOAD_BYTES", 4):
            with self.assertRaises(ValueError):
                self.put(payload={"too": "large"})

    def test_lru_evicts_oldest_entry(self):
        with mock.patch.object(cache_store, "MAX_ENTRIES", 1):
            self.put("old")
            self.put("new")
        self.assertIsNone(cache_store.get_payload(self.root, "info", "old"))
        self.assertEqual(
            cache_store.get_payload(self.root, "info", "new"), {"ok": True}
        )

    def test_corrupt_payload_is_removed(self):
        self.put()
        with sqlite3.connect(cache_store.resolve_db_path(self.root)) as connection:
            connection.execute(
                "UPDATE cache_entries SET payload_json='{' WHERE cache_key='deadbeef'"
            )
        self.assertIsNone(cache_store.get_payload(self.root, "info", "deadbeef"))
        self.assertEqual(cache_store.list_entries(self.root), [])


if __name__ == "__main__":
    unittest.main()
