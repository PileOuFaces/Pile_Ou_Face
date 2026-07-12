# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

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


if __name__ == "__main__":
    unittest.main()
