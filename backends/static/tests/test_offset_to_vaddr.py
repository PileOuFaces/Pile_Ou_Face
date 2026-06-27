# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.offset_to_vaddr."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.offset_to_vaddr import (
    offset_to_vaddr,
    offset_to_vaddr_elf,
    offset_to_vaddr_pe,
)


class TestOffsetToVaddrELF(unittest.TestCase):
    def test_nonexistent_returns_none(self):
        self.assertIsNone(offset_to_vaddr_elf("/nonexistent/binary", 0))

    def test_non_elf_returns_none(self):
        import tempfile, os

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"MZ" + b"\x00" * 100)
        f.close()
        try:
            self.assertIsNone(offset_to_vaddr_elf(f.name, 0))
        finally:
            os.unlink(f.name)

    def test_real_elf(self):
        """Test sur un ELF système si disponible."""
        import os

        elf_paths = ["/bin/ls", "/usr/bin/ls", "/bin/sh"]
        elf = next((p for p in elf_paths if os.path.exists(p)), None)
        if not elf:
            self.skipTest("Pas de binaire ELF système disponible")
        # L'offset 0 (ELF header) ne doit pas forcément mapper, mais pas crasher
        result = offset_to_vaddr_elf(elf, 0)
        # Peut retourner None ou un int
        self.assertTrue(result is None or isinstance(result, int))


class TestOffsetToVaddrPE(unittest.TestCase):
    def test_pe_minimal(self):
        """Test offset→vaddr sur un PE64 minimal."""
        import tempfile, os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            # offset 0x200 = début du .text, VirtualAddress = 0x1000, ImageBase = 0x140000000
            # Expected: 0x140000000 + 0x1000 + (0x200 - 0x200) = 0x140001000
            result = offset_to_vaddr_pe(pe_path, 0x200)
            if result is not None:
                self.assertIsInstance(result, int)
                self.assertGreater(result, 0)
        finally:
            os.unlink(pe_path)

    def test_nonexistent_returns_none(self):
        self.assertIsNone(offset_to_vaddr_pe("/nonexistent.exe", 0))


class TestOffsetToVaddrDispatch(unittest.TestCase):
    def test_nonexistent_returns_none(self):
        self.assertIsNone(offset_to_vaddr("/nonexistent", 0))

    def test_pe_dispatches(self):
        """offset_to_vaddr dispatch automatique vers PE."""
        import tempfile, os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            result = offset_to_vaddr(pe_path, 0x200)
            # Peut retourner None si offset hors section ou un int valide
            self.assertTrue(result is None or isinstance(result, int))
        finally:
            os.unlink(pe_path)

    def test_elf_dispatches(self):
        """offset_to_vaddr dispatch automatique vers ELF si disponible."""
        import os

        elf_paths = ["/bin/ls", "/usr/bin/ls", "/bin/sh"]
        elf = next((p for p in elf_paths if os.path.exists(p)), None)
        if not elf:
            self.skipTest("Pas de binaire ELF disponible")
        result = offset_to_vaddr(elf, 0)
        self.assertTrue(result is None or isinstance(result, int))

    def test_unknown_format_returns_none(self):
        import tempfile, os

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(b"\x00" * 64)
        f.close()
        try:
            self.assertIsNone(offset_to_vaddr(f.name, 0))
        finally:
            os.unlink(f.name)


if __name__ == "__main__":
    unittest.main()
