# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.cache.cache_admin."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.cache.cache import DisasmCache
from backends.static.cache.cache_admin import db_stats, list_binaries, purge_binary


class TestCacheAdmin(unittest.TestCase):
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

    def _populate(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(
                self._binary_path,
                [
                    {"addr": "0x401000", "line": 1, "text": "push rbp"},
                ],
            )
            cache.save_symbols(
                self._binary_path,
                [
                    {"name": "_main", "addr": "0x401000", "type": "T"},
                ],
            )

    # list_binaries
    def test_list_empty_db(self):
        """DB vide → liste vide."""
        # Créer le schéma en ouvrant le cache une fois
        with DisasmCache(self._db_path):
            pass
        result = list_binaries(self._db_path)
        self.assertEqual(result, [])

    def test_list_nonexistent_db(self):
        self.assertEqual(list_binaries("/nonexistent/path.pfdb"), [])

    def test_list_one_binary(self):
        self._populate()
        result = list_binaries(self._db_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["path"], self._binary_path)
        self.assertEqual(result[0]["disasm_lines"], 1)
        self.assertEqual(result[0]["symbols"], 1)

    # db_stats
    def test_stats_nonexistent(self):
        stats = db_stats("/nonexistent/path.pfdb")
        self.assertIn("error", stats)

    def test_stats_empty(self):
        with DisasmCache(self._db_path):
            pass
        stats = db_stats(self._db_path)
        self.assertEqual(stats["binaries"], 0)
        self.assertEqual(stats["total_disasm_lines"], 0)
        self.assertIn("size_human", stats)
        self.assertIn("schema_version", stats)

    def test_stats_populated(self):
        self._populate()
        stats = db_stats(self._db_path)
        self.assertEqual(stats["binaries"], 1)
        self.assertEqual(stats["total_disasm_lines"], 1)
        self.assertEqual(stats["total_symbols"], 1)

    # purge_binary
    def test_purge_nonexistent_db(self):
        n = purge_binary("/nonexistent/path.pfdb")
        self.assertEqual(n, 0)

    def test_purge_all(self):
        self._populate()
        n = purge_binary(self._db_path)
        self.assertEqual(n, 1)
        result = list_binaries(self._db_path)
        self.assertEqual(result, [])

    def test_purge_specific_binary(self):
        self._populate()
        n = purge_binary(self._db_path, binary_path=self._binary_path)
        self.assertEqual(n, 1)
        result = list_binaries(self._db_path)
        self.assertEqual(result, [])

    def test_purge_unknown_binary_returns_zero(self):
        self._populate()
        n = purge_binary(self._db_path, binary_path="/nonexistent/binary")
        self.assertEqual(n, 0)
        # Le binaire original est toujours là
        result = list_binaries(self._db_path)
        self.assertEqual(len(result), 1)


if __name__ == "__main__":
    unittest.main()
