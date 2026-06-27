# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.sections."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.sections import extract_sections, get_section_file_ranges
from backends.static.tests.util import compile_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


class TestExtractSections(unittest.TestCase):
    """Tests de extract_sections avec lief."""

    def test_real_binary(self):
        """Teste l'extraction de sections sur un vrai binaire."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            sections = extract_sections(str(binary))
            self.assertIsInstance(sections, list)
            self.assertGreater(len(sections), 0)

            # Vérifier le format
            for sec in sections:
                self.assertIn("name", sec)
                self.assertIn("size", sec)
                self.assertIn("vma", sec)
                self.assertIn("type", sec)


class TestGetSectionFileRanges(unittest.TestCase):
    """Tests de get_section_file_ranges avec lief."""

    def test_real_binary(self):
        """Teste l'extraction de ranges sur un vrai binaire."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            ranges = get_section_file_ranges(str(binary))
            self.assertIsInstance(ranges, list)
            self.assertGreater(len(ranges), 0)

            # Vérifier le format (name, start, end)
            for r in ranges:
                self.assertIsInstance(r, tuple)
                self.assertEqual(len(r), 3)
                name, start, end = r
                self.assertIsInstance(name, str)
                self.assertIsInstance(start, int)
                self.assertIsInstance(end, int)
                self.assertGreaterEqual(end, start)

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief not installed")
    def test_pe_sections(self):
        """Vérifie extract_sections() sur un PE64."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            sections = extract_sections(pe_path)
            self.assertIsInstance(sections, list)
            self.assertGreater(len(sections), 0)
            names = [s["name"] for s in sections]
            self.assertIn(".text", names)
            text = next(s for s in sections if s["name"] == ".text")
            self.assertEqual(text["type"], "TEXT")
            self.assertIn("vma", text)
        finally:
            os.unlink(pe_path)

    def test_raw_file_fallback_section(self):
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"hello raw")
            raw_path = f.name
        try:
            sections = extract_sections(raw_path)
            self.assertEqual(len(sections), 1)
            self.assertEqual(sections[0]["name"], "raw")
            self.assertEqual(sections[0]["type"], "RAW")
            self.assertEqual(sections[0]["size"], 9)
        finally:
            os.unlink(raw_path)

    def test_raw_file_fallback_range(self):
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"abc")
            raw_path = f.name
        try:
            self.assertEqual(get_section_file_ranges(raw_path), [("raw", 0, 3)])
        finally:
            os.unlink(raw_path)


if __name__ == "__main__":
    unittest.main()
