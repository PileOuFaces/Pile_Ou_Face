# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.annotations.annotations."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.annotations.annotations import AnnotationStore, KIND_COMMENT, KIND_RENAME


class TestAnnotationStore(unittest.TestCase):
    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def _store(self) -> AnnotationStore:
        return AnnotationStore(self._binary_path, cache_path=self._db_path)

    def test_list_empty_on_fresh_store(self):
        with self._store() as store:
            result = store.list()
        self.assertEqual(result, [])

    def test_comment_and_retrieve(self):
        with self._store() as store:
            store.comment("0x401000", "entry point")
            result = store.get_comment("0x401000")
        self.assertEqual(result, "entry point")

    def test_rename_and_retrieve(self):
        with self._store() as store:
            store.rename("0x401000", "my_main")
            result = store.get_name("0x401000")
        self.assertEqual(result, "my_main")

    def test_get_returns_all_kinds(self):
        with self._store() as store:
            store.comment("0x401000", "init func")
            store.rename("0x401000", "init")
            result = store.get("0x401000")
        self.assertEqual(len(result), 2)
        kinds = {r["kind"] for r in result}
        self.assertIn(KIND_COMMENT, kinds)
        self.assertIn(KIND_RENAME, kinds)

    def test_replace_comment(self):
        with self._store() as store:
            store.comment("0x401000", "old comment")
            store.comment("0x401000", "new comment")
            result = store.get_comment("0x401000")
        self.assertEqual(result, "new comment")

    def test_delete_specific_kind(self):
        with self._store() as store:
            store.comment("0x401000", "test")
            store.rename("0x401000", "foo")
            n = store.delete("0x401000", kind=KIND_COMMENT)
            remaining = store.list(addr="0x401000")
        self.assertEqual(n, 1)
        self.assertEqual(len(remaining), 1)
        self.assertEqual(remaining[0]["kind"], KIND_RENAME)

    def test_delete_all_for_addr(self):
        with self._store() as store:
            store.comment("0x401000", "c")
            store.rename("0x401000", "r")
            n = store.delete("0x401000")
            result = store.list(addr="0x401000")
        self.assertEqual(n, 2)
        self.assertEqual(result, [])

    def test_list_filters_by_addr(self):
        with self._store() as store:
            store.comment("0x401000", "A")
            store.comment("0x401010", "B")
            result = store.list(addr="0x401000")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "A")

    def test_get_comment_returns_none_when_absent(self):
        with self._store() as store:
            result = store.get_comment("0xdeadbeef")
        self.assertIsNone(result)

    def test_get_name_returns_none_when_absent(self):
        with self._store() as store:
            result = store.get_name("0xdeadbeef")
        self.assertIsNone(result)

    def test_export_json_returns_list(self):
        with self._store() as store:
            store.comment("0x401000", "c1")
            store.rename("0x401010", "func_foo")
            data = store.export_json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)

    def test_persistent_across_instances(self):
        """Les annotations survivent entre deux instances du store."""
        with self._store() as store:
            store.comment("0x401000", "persistent comment")
        with self._store() as store:
            result = store.get_comment("0x401000")
        self.assertEqual(result, "persistent comment")


if __name__ == "__main__":
    unittest.main()
