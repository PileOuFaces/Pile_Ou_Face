# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.headers."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.headers import extract_binary_info
from backends.static.tests.util import compile_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


@unittest.skipUnless(_LIEF_AVAILABLE, "lief not installed")
class TestExtractBinaryInfo(unittest.TestCase):
    """Tests de extract_binary_info avec lief."""

    def test_real_binary(self):
        """Teste l'extraction d'infos sur un vrai binaire."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            info = extract_binary_info(str(binary))
            self.assertIsInstance(info, dict)
            self.assertIn("format", info)
            self.assertIn("machine", info)
            self.assertIn("entry", info)
            self.assertIn("bits", info)
            self.assertIn("arch", info)
            self.assertIn("endianness", info)
            self.assertIn("packer_analysis", info)
            self.assertNotIn("error", info)

            # Vérifier que les valeurs sont non vides
            self.assertTrue(info["format"])
            self.assertTrue(info["machine"])
            self.assertTrue(info["entry"])
            self.assertIn(info["bits"], ["32", "64"])
            self.assertIn("summary", info["packer_analysis"])

    def test_hash_fields_present(self):
        """extract_binary_info() retourne md5 et sha256."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")
            info = extract_binary_info(str(binary))
            self.assertIn("md5", info)
            self.assertIn("sha256", info)
            self.assertRegex(info["md5"], r"^[0-9a-f]{32}$")
            self.assertRegex(info["sha256"], r"^[0-9a-f]{64}$")

    def test_pe_binary_info(self):
        """Vérifie que extract_binary_info() fonctionne sur un PE64 minimal."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            result = extract_binary_info(pe_path)
            self.assertNotIn("error", result, result.get("error", ""))
            self.assertIn(
                "PE", result.get("format", ""), f"format={result.get('format')}"
            )
            self.assertEqual(result.get("bits"), "64")
            self.assertIn("x86", result.get("arch", ""), f"arch={result.get('arch')}")
            entry = result.get("entry", "")
            self.assertTrue(entry.startswith("0x"), f"entry={entry}")
            self.assertRegex(result.get("md5", ""), r"^[0-9a-f]{32}$")
            self.assertRegex(result.get("sha256", ""), r"^[0-9a-f]{64}$")
            # imphash peut être vide pour un PE sans imports
            self.assertIn("imphash", result)
        finally:
            os.unlink(pe_path)
if __name__ == "__main__":
    unittest.main()
