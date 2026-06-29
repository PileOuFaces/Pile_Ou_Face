# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_exception_handlers.py
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)
from backends.static.tests.fixtures.make_elf import make_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


def run_eh(binary):
    r = subprocess.run(
        [sys.executable, "backends/static/exception_handlers.py", "--binary", binary],
        capture_output=True,
        text=True,
        cwd=ROOT,
    )
    return json.loads(r.stdout)


class TestExceptionHandlers(unittest.TestCase):
    def test_error_on_missing(self):
        result = run_eh("/nonexistent/binary")
        self.assertIsNotNone(result.get("error"))

    def test_output_shape_on_elf(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            self.assertIn("format", result)
            self.assertIn("entries", result)
            self.assertIn("count", result)
            self.assertIsInstance(result["entries"], list)

    def test_each_entry_has_required_fields(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            for entry in result.get("entries", []):
                self.assertIn("handler_type", entry)
                self.assertIn("func_start", entry)

    def test_elf_format_reported(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_eh(elf)
            self.assertEqual(result.get("format"), "ELF")

    def test_shape_on_direct_call(self):
        from backends.static.exception_handlers import get_exception_handlers

        self.assertTrue(callable(get_exception_handlers))
        result = get_exception_handlers("/nonexistent/binary")
        self.assertIsInstance(result, dict)
        self.assertIn("format", result)
        self.assertIn("arch", result)
        self.assertIn("entries", result)
        self.assertIn("count", result)

    def test_elf_dwarf32_fde_is_parsed_from_eh_frame(self):
        from backends.static.exception_handlers import _elf_dwarf_exceptions

        cie = (4).to_bytes(4, "little") + (0).to_bytes(4, "little")
        fde = (
            (12).to_bytes(4, "little")
            + (4).to_bytes(4, "little")
            + (0x10).to_bytes(4, "little", signed=True)
            + (0x20).to_bytes(4, "little")
        )
        fake_binary = SimpleNamespace(
            sections=[
                SimpleNamespace(name=".text", content=[], virtual_address=0),
                SimpleNamespace(
                    name=".eh_frame", content=cie + fde, virtual_address=0x1000
                ),
            ]
        )

        result = _elf_dwarf_exceptions(fake_binary)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["func_start"], "0x1020")
        self.assertEqual(result[0]["func_end"], "0x1040")
        self.assertEqual(result[0]["handler_type"], "DWARF FDE")
        self.assertEqual(result[0]["unwind_flags"], [])

    def test_elf_dwarf64_fde_is_parsed_from_eh_frame(self):
        from backends.static.exception_handlers import _elf_dwarf_exceptions

        cie = (4).to_bytes(4, "little") + (0).to_bytes(4, "little")
        fde64 = (
            (0xFFFFFFFF).to_bytes(4, "little")
            + (24).to_bytes(8, "little")
            + (8).to_bytes(8, "little")
            + (0x20).to_bytes(8, "little", signed=True)
            + (0x30).to_bytes(8, "little")
        )
        fake_binary = SimpleNamespace(
            sections=[
                SimpleNamespace(
                    name=".eh_frame", content=cie + fde64, virtual_address=0x400000
                )
            ]
        )

        result = _elf_dwarf_exceptions(fake_binary)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["func_start"], "0x40003c")
        self.assertEqual(result[0]["func_end"], "0x40006c")
        self.assertEqual(result[0]["handler_type"], "DWARF FDE")
        self.assertEqual(result[0]["unwind_flags"], ["DWARF64"])

    def test_elf_dwarf64_truncated_record_is_ignored(self):
        from backends.static.exception_handlers import _elf_dwarf_exceptions

        fake_binary = SimpleNamespace(
            sections=[
                SimpleNamespace(
                    name=".eh_frame",
                    content=(0xFFFFFFFF).to_bytes(4, "little")
                    + (24).to_bytes(8, "little"),
                    virtual_address=0x400000,
                )
            ]
        )

        self.assertEqual(_elf_dwarf_exceptions(fake_binary), [])

    def test_macho_metadata_entry_is_explicitly_global(self):
        from backends.static.exception_handlers import _macho_exceptions

        fake_binary = SimpleNamespace(
            sections=[
                SimpleNamespace(name="__text"),
                SimpleNamespace(name="__unwind_info"),
            ]
        )
        result = _macho_exceptions(fake_binary)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handler_type"], "Mach-O unwind metadata")
        self.assertIn("note", result[0])
        self.assertIn("sans résolution par fonction", result[0]["note"])

    def test_macho_compact_unwind_entries_are_resolved_per_function(self):
        from backends.static.exception_handlers import _macho_exceptions

        record = (
            (0x1000).to_bytes(4, "little")
            + (0x40).to_bytes(4, "little")
            + (0x02000000).to_bytes(4, "little")
            + (0x2000).to_bytes(4, "little")
            + (0x3000).to_bytes(4, "little")
        )
        fake_binary = SimpleNamespace(
            imagebase=0x100000000,
            sections=[SimpleNamespace(name="__compact_unwind", content=record)],
        )

        result = _macho_exceptions(fake_binary)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handler_type"], "Mach-O compact unwind")
        self.assertEqual(result[0]["func_start"], "0x100001000")
        self.assertEqual(result[0]["func_end"], "0x100001040")
        self.assertEqual(result[0]["handler"], "0x100002000")
        self.assertIn("encoding=0x2000000", result[0]["unwind_flags"])
        self.assertIn("lsda=0x100003000", result[0]["unwind_flags"])

    def test_macho_compact_unwind_zero_length_records_are_ignored(self):
        from backends.static.exception_handlers import _macho_exceptions

        record = (
            (0x1000).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0x02000000).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
        )
        fake_binary = SimpleNamespace(
            imagebase=0x100000000,
            sections=[
                SimpleNamespace(name="__compact_unwind", content=record),
                SimpleNamespace(name="__unwind_info"),
            ],
        )

        result = _macho_exceptions(fake_binary)

        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["handler_type"], "Mach-O unwind metadata")


if __name__ == "__main__":
    unittest.main()
