# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.symbols."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.symbols import extract_symbols
from backends.static.tests.util import compile_minimal_elf


class TestExtractSymbols(unittest.TestCase):
    """Tests de extract_symbols avec lief."""

    def test_real_binary(self):
        """Teste l'extraction de symboles sur un vrai binaire."""
        import backends.static.binary.symbols as _sym_mod

        if _sym_mod.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            symbols = extract_symbols(str(binary))
            self.assertIsInstance(symbols, list)
            self.assertGreater(len(symbols), 0)

            # Vérifier le format
            for sym in symbols:
                self.assertIn("name", sym)
                self.assertIn("addr", sym)
                self.assertIn("type", sym)
                self.assertTrue(sym["name"])  # Non vide

    def test_pe_symbols_no_crash(self):
        """extract_symbols() sur un PE sans exports ne plante pas."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            result = extract_symbols(pe_path)
            self.assertIsInstance(result, list)
            # PE minimal sans exports → liste vide ou quelques imports
        finally:
            os.unlink(pe_path)

    def test_raw_blob_fallback_symbol_candidates(self):
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00sub_401000\x00main\x00plainword\x00_start\x00")
            raw_path = f.name
        try:
            symbols = extract_symbols(raw_path)
            names = {sym["name"] for sym in symbols}
            self.assertIn("sub_401000", names)
            self.assertIn("main", names)
            self.assertIn("_start", names)
            self.assertNotIn("plainword", names)
            self.assertTrue(
                all(sym.get("source") == "string-reference" for sym in symbols)
            )
        finally:
            os.unlink(raw_path)

    def test_symbols_have_size_field(self):
        """Chaque symbole doit avoir un champ size (int ou None)."""
        import backends.static.binary.symbols as _sym_mod

        if _sym_mod.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            symbols = extract_symbols(str(binary))
            self.assertGreater(len(symbols), 0)
            for sym in symbols:
                self.assertIn("size", sym, f"Missing 'size' in {sym}")
                self.assertTrue(sym["size"] is None or isinstance(sym["size"], int))


if __name__ == "__main__":
    unittest.main()
