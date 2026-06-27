"""Tests for the normalized binary metadata aggregation layer."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.binary_metadata_model import (
    build_binary_metadata_model,
    dumps_binary_metadata,
)
from backends.static.binary.adapters import lief_adapter
from backends.static.tests.util import compile_minimal_elf


FAKE_BINARY = {
    "path": "/tmp/challenge",
    "format": "ELF",
    "arch": "x86_64",
    "bits": 64,
    "entry": "0x401050",
    "base": "0x400000",
    "pie": False,
    "stripped": False,
    "source": "LIEF",
}


FAKE_SECTIONS = [
    {"name": ".text", "vma": "0x401000", "size": 512, "offset": 4096, "type": "TEXT"},
    {"name": ".data", "vma": "0x404000", "size": 32, "offset": 16384, "type": "DATA"},
]


FAKE_SYMBOLS = [
    {"name": "main", "addr": "0x401136", "size": 74, "kind": "FUNC", "binding": "GLOBAL", "section": ".text", "source": "LIEF/symtab"},
    {"name": "challenge", "addr": "0x4011c0", "size": 120, "kind": "FUNC", "binding": "GLOBAL", "section": ".text", "source": "LIEF/symtab"},
    {"name": "global_counter", "addr": "0x404010", "size": 4, "kind": "OBJECT", "binding": "GLOBAL", "section": ".data", "source": "LIEF/symtab"},
]


def build_mocked_model(binary=None, dwarf=None, dwarf_error=None, plt=None):
    with patch("backends.static.binary.binary_metadata_model.Path.exists", return_value=True), \
            patch("backends.static.binary.binary_metadata_model.load_binary_facts", return_value=binary or FAKE_BINARY), \
            patch("backends.static.binary.binary_metadata_model.extract_sections", return_value=FAKE_SECTIONS), \
            patch("backends.static.binary.binary_metadata_model.section_flags_by_name", return_value={".text": ["READ", "EXEC"], ".data": ["READ", "WRITE"]}), \
            patch("backends.static.binary.binary_metadata_model.load_symbols", return_value=FAKE_SYMBOLS), \
            patch("backends.static.binary.binary_metadata_model.load_dwarf_functions", return_value=(dwarf or [], dwarf_error)), \
            patch("backends.static.binary.binary_metadata_model.load_plt_entries", return_value=plt or [{"name": "printf", "plt_addr": "0x401040", "got_addr": "0x404000", "source": "LIEF/PLT"}]):
        return build_binary_metadata_model("/tmp/challenge")


class TestBinaryMetadataModel(unittest.TestCase):
    def test_section_symbol_plt_and_source_provenance_fields(self):
        model = build_mocked_model()

        self.assertEqual(model["binary"]["format"], "ELF")
        self.assertEqual(model["sections"][0]["name"], ".text")
        self.assertEqual(model["sections"][0]["flags"], ["READ", "EXEC"])
        self.assertEqual(model["sections"][0]["source"], "LIEF")
        self.assertEqual(model["symbols"][0]["name"], "main")
        self.assertEqual(model["symbols"][0]["source"], "LIEF/symtab")
        self.assertEqual(model["plt"][0]["name"], "printf")
        self.assertEqual(model["plt"][0]["source"], "LIEF/PLT")

    def test_function_ranges_keep_main_and_challenge_distinct(self):
        model = build_mocked_model()
        by_name = {fn["name"]: fn for fn in model["functions"]}

        self.assertEqual(by_name["main"]["start"], "0x401136")
        self.assertEqual(by_name["main"]["end"], "0x401180")
        self.assertEqual(by_name["challenge"]["start"], "0x4011c0")
        self.assertEqual(by_name["challenge"]["end"], "0x401238")

    def test_pie_vs_non_pie_runtime_fields(self):
        pie_binary = {**FAKE_BINARY, "base": "0x0", "pie": True, "entry": "0x1050"}
        model = build_mocked_model(binary=pie_binary)

        self.assertTrue(model["binary"]["pie"])
        self.assertEqual(model["runtime"], {"base": "0x0", "entry": "0x1050", "pie": True})

    def test_stripped_binary_still_has_stable_shape(self):
        stripped = {**FAKE_BINARY, "stripped": True}
        with patch("backends.static.binary.binary_metadata_model.Path.exists", return_value=True), \
                patch("backends.static.binary.binary_metadata_model.load_binary_facts", return_value=stripped), \
                patch("backends.static.binary.binary_metadata_model.extract_sections", return_value=FAKE_SECTIONS), \
                patch("backends.static.binary.binary_metadata_model.section_flags_by_name", return_value={}), \
                patch("backends.static.binary.binary_metadata_model.load_symbols", return_value=[]), \
                patch("backends.static.binary.binary_metadata_model.load_dwarf_functions", return_value=([], "Aucune info DWARF")), \
                patch("backends.static.binary.binary_metadata_model.load_plt_entries", return_value=[]):
            model = build_binary_metadata_model("/tmp/stripped")

        self.assertTrue(model["binary"]["stripped"])
        self.assertEqual(model["symbols"], [])
        self.assertEqual(model["functions"], [])
        self.assertTrue(any(d["source"] == "DWARF" for d in model["diagnostics"]))

    def test_missing_dwarf_is_diagnostic_not_failure(self):
        model = build_mocked_model(dwarf_error="Aucune info DWARF dans ce binaire")

        self.assertTrue(any("DWARF" == d["source"] for d in model["diagnostics"]))
        self.assertTrue(model["functions"])

    def test_deterministic_json_output(self):
        model = build_mocked_model()

        first = dumps_binary_metadata(model)
        second = dumps_binary_metadata(model)

        self.assertEqual(first, second)
        parsed = json.loads(first)
        self.assertEqual(list(parsed.keys()), ["binary", "sections", "symbols", "functions", "plt", "runtime", "diagnostics"])

    def test_malformed_incomplete_binary_returns_diagnostics(self):
        fixture = ROOT / "backends/static/tests/fixtures/binary_metadata_malformed.bin"
        model = build_binary_metadata_model(str(fixture))

        self.assertEqual(model["binary"]["format"], "UNKNOWN")
        self.assertEqual(model["sections"], [{"name": "raw", "vaddr": "0x0", "size": 11, "offset": "0x0", "kind": "RAW", "flags": [], "source": "LIEF"}])
        self.assertTrue(any(d["source"] == "LIEF" for d in model["diagnostics"]))

    def test_real_fixture_elf_if_toolchain_available(self):
        if lief_adapter.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")

            model = build_binary_metadata_model(str(binary))

        self.assertEqual(model["binary"]["format"], "ELF")
        self.assertIn(model["binary"]["bits"], (32, 64))
        self.assertTrue(any(section["name"] == ".text" for section in model["sections"]))
        self.assertTrue(any(symbol["name"] == "main" for symbol in model["symbols"]))

    def test_cli_outputs_valid_json(self):
        if lief_adapter.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            script = ROOT / "backends/static/binary/build_binary_metadata.py"
            result = subprocess.run(
                [sys.executable, str(script), str(binary)],
                cwd=str(ROOT),
                capture_output=True,
                text=True,
                timeout=30,
            )

        self.assertEqual(result.returncode, 0, result.stderr)
        parsed = json.loads(result.stdout)
        self.assertEqual(parsed["binary"]["format"], "ELF")


if __name__ == "__main__":
    unittest.main()
