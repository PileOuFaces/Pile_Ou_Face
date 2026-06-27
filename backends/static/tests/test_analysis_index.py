# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.analysis.analysis_index."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.analysis.analysis_index import build_analysis_index
from backends.static.cache.cache import DisasmCache
from backends.static.tests.util import compile_minimal_elf

try:
    import lief as _lief
    import capstone as _capstone

    _DISASM_AVAILABLE = True
except ImportError:
    _DISASM_AVAILABLE = False


@unittest.skipUnless(_DISASM_AVAILABLE, "lief/capstone not installed")
class TestAnalysisIndex(unittest.TestCase):
    def test_build_analysis_index_returns_stats(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            cache_db = tmp_path / "analysis.pfdb"
            result = build_analysis_index(str(binary), cache_db=str(cache_db), force=True)

            self.assertEqual(result["binary"], str(binary))
            self.assertEqual(result["cache_db"], str(cache_db))
            self.assertGreater(result["stats"]["instructions"], 0)
            self.assertGreaterEqual(result["stats"]["blocks"], 1)
            self.assertTrue(cache_db.exists())

            with DisasmCache(str(cache_db)) as cache:
                self.assertIsNotNone(cache.get_cfg(str(binary)))
                if result["stats"]["xref_targets"] > 0:
                    self.assertIsNotNone(cache.get_xref_map(str(binary)))
                if not result["errors"].get("imports"):
                    self.assertIsNotNone(cache.get_imports_analysis(str(binary)))


if __name__ == "__main__":
    unittest.main()
