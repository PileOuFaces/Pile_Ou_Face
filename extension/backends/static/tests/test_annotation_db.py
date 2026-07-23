# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.exceptions import BinaryNotFoundError
from backends.static.annotations.annotation_db import (
    AnnotationDb,
    default_db_path,
    hash_binary_content,
)


class TestHashBinaryContent(unittest.TestCase):
    def test_matches_sha256_of_bytes(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello world")
            path = f.name
        try:
            expected = hashlib.sha256(b"hello world").hexdigest()
            self.assertEqual(hash_binary_content(path), expected)
        finally:
            Path(path).unlink()

    def test_same_content_same_hash_regardless_of_path(self):
        with tempfile.NamedTemporaryFile(delete=False) as f1:
            f1.write(b"identical bytes")
            path1 = f1.name
        with tempfile.NamedTemporaryFile(delete=False) as f2:
            f2.write(b"identical bytes")
            path2 = f2.name
        try:
            self.assertEqual(hash_binary_content(path1), hash_binary_content(path2))
        finally:
            Path(path1).unlink()
            Path(path2).unlink()


class TestDefaultDbPath(unittest.TestCase):
    def test_lives_under_home_pile_ou_face(self):
        p = default_db_path()
        self.assertEqual(p, Path.home() / ".pile-ou-face" / "annotations.db")


class TestAnnotationDb(unittest.TestCase):
    def setUp(self):
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._db_path = self._db_file.name
        self._db_file.close()
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def test_get_returns_empty_list_for_unknown_binary(self):
        with AnnotationDb(self._db_path) as db:
            result = db.get_annotations(self._binary_path)
        self.assertEqual(result, [])

    def test_save_and_get_roundtrip(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "entry point")
            result = db.get_annotations(self._binary_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x401000")
        self.assertEqual(result[0]["kind"], "comment")
        self.assertEqual(result[0]["value"], "entry point")
        self.assertIn("updated_at", result[0])

    def test_save_replaces_same_addr_kind(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "old")
            db.save_annotation(self._binary_path, "0x401000", "comment", "new")
            result = db.get_annotations(self._binary_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "new")

    def test_delete_specific_kind(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "c")
            db.save_annotation(self._binary_path, "0x401000", "rename", "r")
            n = db.delete_annotation(self._binary_path, "0x401000", kind="comment")
            remaining = db.get_annotations(self._binary_path)
        self.assertEqual(n, 1)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["kind"], "rename")

    def test_delete_all_kinds_for_addr(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "c")
            db.save_annotation(self._binary_path, "0x401000", "rename", "r")
            n = db.delete_annotation(self._binary_path, "0x401000")
            remaining = db.get_annotations(self._binary_path)
        self.assertEqual(n, 2)
        self.assertEqual(remaining, [])

    def test_two_binaries_with_different_content_are_isolated(self):
        bin2 = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        bin2.write(b"different content")
        bin2.flush()
        bin2.close()
        try:
            with AnnotationDb(self._db_path) as db:
                db.save_annotation(self._binary_path, "0x1000", "comment", "A")
                db.save_annotation(bin2.name, "0x1000", "comment", "B")
                result_a = db.get_annotations(self._binary_path)
                result_b = db.get_annotations(bin2.name)
            self.assertEqual(result_a[0]["value"], "A")
            self.assertEqual(result_b[0]["value"], "B")
        finally:
            Path(bin2.name).unlink(missing_ok=True)

    def test_persists_across_instances(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "persisted")
        with AnnotationDb(self._db_path) as db:
            result = db.get_annotations(self._binary_path)
        self.assertEqual(result[0]["value"], "persisted")

    def test_wal_mode_enabled(self):
        with AnnotationDb(self._db_path) as db:
            mode = db._conn.execute("PRAGMA journal_mode").fetchone()[0]
        self.assertEqual(mode.lower(), "wal")

    def test_deleting_binary_cascades_to_annotations(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "c")
            sha256 = hash_binary_content(self._binary_path)
            # Directly delete the parent row to exercise ON DELETE CASCADE.
            db._conn.execute("DELETE FROM binaries WHERE sha256 = ?", (sha256,))
            db._conn.commit()
            remaining = db._conn.execute(
                "SELECT * FROM annotations WHERE binary_sha256 = ?", (sha256,)
            ).fetchall()
        self.assertEqual(remaining, [])

    def test_hash_binary_content_raises_for_missing_file(self):
        missing_path = str(Path(self._binary_path).with_suffix(".missing"))
        with self.assertRaises(BinaryNotFoundError):
            hash_binary_content(missing_path)

    def test_get_annotations_raises_for_missing_binary(self):
        missing_path = str(Path(self._binary_path).with_suffix(".missing"))
        with AnnotationDb(self._db_path) as db:
            with self.assertRaises(BinaryNotFoundError):
                db.get_annotations(missing_path)

    def test_save_annotation_defaults_source_to_user(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "c")
            result = db.get_annotations(self._binary_path)
        self.assertEqual(result[0]["source"], "user")

    def test_save_annotation_accepts_explicit_source(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(
                self._binary_path, "0x401000", "comment", "c", source="ai"
            )
            result = db.get_annotations(self._binary_path)
        self.assertEqual(result[0]["source"], "ai")

    def test_migration_adds_source_column_to_legacy_db(self):
        # Simulate a pre-existing DB created before the `source` column existed.
        import sqlite3

        conn = sqlite3.connect(self._db_path)
        conn.execute(
            """
            CREATE TABLE binaries (
                sha256 TEXT PRIMARY KEY,
                first_seen_path TEXT,
                indexed_at INTEGER
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE annotations (
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
        sha256 = hash_binary_content(self._binary_path)
        conn.execute(
            "INSERT INTO binaries (sha256, first_seen_path, indexed_at) VALUES (?, ?, 0)",
            (sha256, self._binary_path),
        )
        conn.execute(
            "INSERT INTO annotations (binary_sha256, addr, kind, value, updated_at) "
            "VALUES (?, '0x1000', 'comment', 'legacy', '2026-01-01T00:00:00.000Z')",
            (sha256,),
        )
        conn.commit()
        conn.close()

        with AnnotationDb(self._db_path) as db:
            result = db.get_annotations(self._binary_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "legacy")
        self.assertEqual(result[0]["source"], "user")

    def test_save_ai_annotation_writes_when_slot_empty(self):
        with AnnotationDb(self._db_path) as db:
            written = db.save_ai_annotation(
                self._binary_path, "0x401000", "comment", "ai guess"
            )
            result = db.get_annotations(self._binary_path)
        self.assertTrue(written)
        self.assertEqual(result[0]["value"], "ai guess")
        self.assertEqual(result[0]["source"], "ai")

    def test_save_ai_annotation_never_overwrites_user_annotation(self):
        with AnnotationDb(self._db_path) as db:
            db.save_annotation(self._binary_path, "0x401000", "comment", "human note")
            written = db.save_ai_annotation(
                self._binary_path, "0x401000", "comment", "ai guess"
            )
            result = db.get_annotations(self._binary_path)
        self.assertFalse(written)
        self.assertEqual(result[0]["value"], "human note")
        self.assertEqual(result[0]["source"], "user")

    def test_save_ai_annotation_can_replace_earlier_ai_annotation(self):
        with AnnotationDb(self._db_path) as db:
            db.save_ai_annotation(
                self._binary_path, "0x401000", "comment", "first guess"
            )
            written = db.save_ai_annotation(
                self._binary_path, "0x401000", "comment", "refined guess"
            )
            result = db.get_annotations(self._binary_path)
        self.assertTrue(written)
        self.assertEqual(result[0]["value"], "refined guess")


if __name__ == "__main__":
    unittest.main()
