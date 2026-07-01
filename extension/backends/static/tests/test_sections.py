# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.sections."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

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


class TestGetSectionFileRangesMocked(unittest.TestCase):
    """Tests unitaires de get_section_file_ranges via mocks lief — vérifient que
    les offsets fichier (pas les VAs/RVAs) sont utilisés pour ELF et PE."""

    def _make_elf_section(self, name, file_offset, virtual_address, size):
        sec = MagicMock()
        sec.name = name
        sec.file_offset = file_offset
        sec.virtual_address = virtual_address
        sec.size = size
        return sec

    def _make_pe_section(self, name, offset, virtual_address, size):
        sec = MagicMock()
        sec.name = name
        sec.offset = offset  # file offset
        sec.virtual_address = virtual_address  # RVA — must NOT be used
        sec.size = size
        return sec

    def _make_macho_section(self, name, offset, virtual_address, size):
        sec = MagicMock()
        sec.name = name
        sec.offset = offset
        sec.virtual_address = virtual_address
        sec.size = size
        return sec

    def test_elf_uses_file_offset_not_virtual_address(self):
        """ELF : range calculé depuis file_offset, pas virtual_address."""
        import lief

        mock_sec = self._make_elf_section(
            ".rodata",
            file_offset=0x100,  # offset fichier = 256
            virtual_address=0x401000,  # VA absolue — ne doit PAS être utilisée
            size=64,
        )
        mock_binary = MagicMock(spec=lief.ELF.Binary)
        mock_binary.sections = [mock_sec]

        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.return_value = mock_binary
            mock_lief.ELF.Binary = lief.ELF.Binary
            mock_lief.MachO = lief.MachO
            mock_lief.PE = lief.PE

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "elf"
                f.write_bytes(b"\x00" * 512)
                ranges = get_section_file_ranges(str(f))

        self.assertEqual(len(ranges), 1)
        name, start, end = ranges[0]
        self.assertEqual(name, ".rodata")
        self.assertEqual(start, 0x100)  # file_offset utilisé
        self.assertEqual(end, 0x100 + 64)
        self.assertNotEqual(start, 0x401000)  # VA absolue non utilisée

    def test_pe_uses_file_offset_not_rva(self):
        """PE : range calculé depuis sec.offset (file offset), pas virtual_address (RVA)."""
        import lief

        mock_sec = self._make_pe_section(
            ".rdata",
            offset=0x200,  # file offset = 512
            virtual_address=0x1000,  # RVA — ne doit PAS être utilisée
            size=128,
        )
        mock_binary = MagicMock(spec=lief.PE.Binary)
        mock_binary.sections = [mock_sec]

        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.return_value = mock_binary
            mock_lief.ELF.Binary = lief.ELF.Binary
            mock_lief.MachO = lief.MachO
            mock_lief.PE = lief.PE
            mock_lief.PE.Binary = lief.PE.Binary

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "pe.exe"
                f.write_bytes(b"\x00" * 1024)
                ranges = get_section_file_ranges(str(f))

        self.assertEqual(len(ranges), 1)
        name, start, end = ranges[0]
        self.assertEqual(name, ".rdata")
        self.assertEqual(start, 0x200)  # file offset utilisé
        self.assertEqual(end, 0x200 + 128)
        self.assertNotEqual(start, 0x1000)  # RVA non utilisée

    def test_macho_uses_offset_not_virtual_address(self):
        """Mach-O : range calculé depuis sec.offset (file offset), pas virtual_address."""
        import lief

        mock_sec = self._make_macho_section(
            "__cstring",
            offset=0x300,
            virtual_address=0x100003000,
            size=32,
        )
        mock_binary = MagicMock(spec=lief.MachO.Binary)
        mock_binary.sections = [mock_sec]

        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.return_value = mock_binary
            mock_lief.ELF.Binary = lief.ELF.Binary
            mock_lief.MachO = lief.MachO
            mock_lief.MachO.Binary = lief.MachO.Binary
            mock_lief.PE = lief.PE

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "macho"
                f.write_bytes(b"\x00" * 2048)
                ranges = get_section_file_ranges(str(f))

        self.assertEqual(len(ranges), 1)
        name, start, end = ranges[0]
        self.assertEqual(name, "__cstring")
        self.assertEqual(start, 0x300)
        self.assertEqual(end, 0x300 + 32)

    def test_nonexistent_file_returns_empty(self):
        """Fichier inexistant → []."""
        result = get_section_file_ranges("/nonexistent/path/to/binary")
        self.assertEqual(result, [])

    def test_lief_parse_returns_none_falls_back_to_raw(self):
        """lief.parse() → None → fallback raw (taille du fichier)."""
        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.return_value = None

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"X" * 42)
                result = get_section_file_ranges(str(f))

        self.assertEqual(result, [("raw", 0, 42)])

    def test_lief_parse_exception_falls_back_to_raw(self):
        """lief.parse() lève une exception → fallback raw."""
        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.side_effect = RuntimeError("lief error")

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"Y" * 20)
                result = get_section_file_ranges(str(f))

        self.assertEqual(result, [("raw", 0, 20)])

    def test_multiple_sections_all_returned(self):
        """Plusieurs sections ELF → toutes retournées avec leurs offsets fichier."""
        import lief

        sections = [
            self._make_elf_section(
                ".text", file_offset=64, virtual_address=0x401040, size=100
            ),
            self._make_elf_section(
                ".rodata", file_offset=164, virtual_address=0x4020A4, size=50
            ),
            self._make_elf_section(
                ".data", file_offset=214, virtual_address=0x403000, size=30
            ),
        ]
        mock_binary = MagicMock(spec=lief.ELF.Binary)
        mock_binary.sections = sections

        with patch("backends.static.binary.sections.lief") as mock_lief:
            mock_lief.parse.return_value = mock_binary
            mock_lief.ELF.Binary = lief.ELF.Binary
            mock_lief.MachO = lief.MachO
            mock_lief.PE = lief.PE

            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "elf"
                f.write_bytes(b"\x00" * 300)
                ranges = get_section_file_ranges(str(f))

        self.assertEqual(len(ranges), 3)
        by_name = {name: (start, end) for name, start, end in ranges}
        self.assertEqual(by_name[".text"], (64, 164))
        self.assertEqual(by_name[".rodata"], (164, 214))
        self.assertEqual(by_name[".data"], (214, 244))


if __name__ == "__main__":
    unittest.main()
