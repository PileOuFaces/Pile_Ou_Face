# SPDX-License-Identifier: AGPL-3.0-only
"""Tests d'intégration E2E — pipeline complet d'analyse statique.

Couvre le chemin :
    lignes désassemblage → CFG (complet + par fonction)
    → export DOT + CSV + JSON
    → AnnotationStore (commenter, renommer, lister)
    → DisasmCache (symboles, strings, annotations)
    → cache_admin (stats, list, purge)

Ces tests utilisent uniquement des données synthétiques (pas de vrai binaire).
"""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.annotations.annotations import AnnotationStore
from backends.static.cache.cache import DisasmCache
from backends.static.disasm.cfg import build_cfg, build_cfg_for_function
from backends.static.export.export import (
    export_cfg_dot,
    export_strings_csv,
    export_symbols_csv,
    export_xrefs_json,
)
from backends.static.cache.cache_admin import db_stats, list_binaries, purge_binary
from backends.static.disasm.xrefs import build_xref_map

# ---------------------------------------------------------------------------
# Fixtures réutilisables
# ---------------------------------------------------------------------------

DISASM_LINES = [
    # Entrée principale : appelle les deux fonctions
    {"addr": "0x400000", "text": "call\t0x401000", "line": 1},
    {"addr": "0x400005", "text": "call\t0x402000", "line": 2},
    {"addr": "0x40000a", "text": "ret", "line": 3},
    # Fonction A : 0x401000 — simple if/else
    {"addr": "0x401000", "text": "push rbp", "line": 4},
    {"addr": "0x401001", "text": "mov rbp, rsp", "line": 5},
    {"addr": "0x401004", "text": "cmp rdi, 0", "line": 6},
    {"addr": "0x401008", "text": "jne\t0x401020", "line": 7},
    {"addr": "0x40100a", "text": "xor eax, eax", "line": 8},
    {"addr": "0x40100c", "text": "ret", "line": 9},
    # Bloc "else" de func_a
    {"addr": "0x401020", "text": "mov eax, 1", "line": 10},
    {"addr": "0x401025", "text": "ret", "line": 11},
    # Fonction B : 0x402000 — appelle func_a
    {"addr": "0x402000", "text": "push rbp", "line": 12},
    {"addr": "0x402001", "text": "call\t0x401000", "line": 13},
    {"addr": "0x402006", "text": "ret", "line": 14},
]

SYMBOLS = [
    {"name": "func_a", "addr": "0x401000", "type": "T"},
    {"name": "func_b", "addr": "0x402000", "type": "T"},
]

STRINGS = [
    {"addr": "0x403000", "value": "hello world", "length": 11},
    {"addr": "0x403020", "value": "error: bad arg", "length": 14},
]

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


class TestCfgPipeline(unittest.TestCase):
    """Pipeline : lignes → CFG complet → CFG par fonction → DOT."""

    def test_full_cfg_has_func_a_blocks(self):
        """Le CFG complet contient les blocs de func_a (if et else)."""
        cfg = build_cfg(DISASM_LINES)
        addrs = {b["addr"] for b in cfg["blocks"]}
        self.assertIn("0x401000", addrs)
        self.assertIn("0x401020", addrs)

    def test_full_cfg_has_func_b_blocks(self):
        """0x402000 est atteignable via call 0x402000 depuis 0x403000."""
        cfg = build_cfg(DISASM_LINES)
        addrs = {b["addr"] for b in cfg["blocks"]}
        self.assertIn("0x402000", addrs)

    def test_func_a_cfg_excludes_callee(self):
        """Le CFG de func_a ne traverse pas les callees (0x402000)."""
        cfg_a = build_cfg_for_function(DISASM_LINES, "0x401000")
        addrs = {b["addr"] for b in cfg_a["blocks"]}
        self.assertIn("0x401000", addrs)
        self.assertIn("0x401020", addrs)
        # func_b et le stub ne doivent pas être traversés (edges call)
        self.assertNotIn("0x402000", addrs)
        self.assertNotIn("0x403000", addrs)

    def test_func_b_cfg_has_own_blocks(self):
        """Le CFG de func_b contient ses propres blocs sans func_a."""
        cfg_b = build_cfg_for_function(DISASM_LINES, "0x402000")
        addrs = {b["addr"] for b in cfg_b["blocks"]}
        self.assertIn("0x402000", addrs)
        # func_a est un callee → non traversée
        self.assertNotIn("0x401000", addrs)

    def test_export_cfg_dot_round_trip(self):
        cfg_a = build_cfg_for_function(DISASM_LINES, "0x401000")
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            dot_path = f.name
        try:
            n = export_cfg_dot(cfg_a, dot_path, graph_name="func_a")
            self.assertGreater(n, 0)
            content = Path(dot_path).read_text(encoding="utf-8")
            self.assertIn("func_a", content)
            self.assertIn("0x401000", content)
            self.assertIn("->", content)
        finally:
            Path(dot_path).unlink(missing_ok=True)


class TestXrefPipeline(unittest.TestCase):
    """Pipeline : lignes → xref_map → export JSON."""

    def test_xref_map_detects_call(self):
        xref_map = build_xref_map(DISASM_LINES)
        # 0x401000 est appelé depuis 0x400000 et 0x402001
        self.assertIn("0x401000", xref_map)
        calls = [r for r in xref_map["0x401000"] if r["type"] == "call"]
        self.assertGreaterEqual(len(calls), 1)
        callers = {c["from_addr"] for c in calls}
        self.assertIn("0x400000", callers)

    def test_export_xrefs_json(self):
        xref_map = build_xref_map(DISASM_LINES)
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            n = export_xrefs_json(xref_map, json_path)
            self.assertGreater(n, 0)
            with open(json_path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("0x401000", data)
        finally:
            Path(json_path).unlink(missing_ok=True)


class TestExportPipeline(unittest.TestCase):
    """Pipeline : symboles/strings → CSV."""

    def test_symbols_csv_round_trip(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            csv_path = f.name
        try:
            n = export_symbols_csv(SYMBOLS, csv_path)
            self.assertEqual(n, 2)
            with open(csv_path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            names = [r["name"] for r in rows]
            self.assertIn("func_a", names)
            self.assertIn("func_b", names)
        finally:
            Path(csv_path).unlink(missing_ok=True)

    def test_strings_csv_round_trip(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            csv_path = f.name
        try:
            n = export_strings_csv(STRINGS, csv_path)
            self.assertEqual(n, 2)
            with open(csv_path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
            values = [r["value"] for r in rows]
            self.assertIn("hello world", values)
        finally:
            Path(csv_path).unlink(missing_ok=True)


class TestCachePipeline(unittest.TestCase):
    """Pipeline : cache désassemblage + symboles + strings + annotations."""

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

    def test_full_cache_pipeline(self):
        """Toutes les tables remplies et récupérées correctement."""
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(self._binary_path, DISASM_LINES)
            cache.save_symbols(self._binary_path, SYMBOLS)
            cache.save_strings(self._binary_path, STRINGS)
            cache.save_annotation(self._binary_path, "0x401000", "comment", "entry of func_a")
            cache.save_annotation(self._binary_path, "0x401000", "rename", "func_a")

            disasm = cache.get_disasm(self._binary_path)
            syms = cache.get_symbols(self._binary_path)
            strs = cache.get_strings(self._binary_path)
            anns = cache.get_annotations(self._binary_path)

        self.assertIsNotNone(disasm)
        self.assertEqual(len(disasm[1]), len(DISASM_LINES))  # type: ignore
        self.assertEqual(len(syms), 2)  # type: ignore
        self.assertEqual(len(strs), 2)  # type: ignore
        self.assertEqual(len(anns), 2)

    def test_cache_admin_stats_after_populate(self):
        """cache_admin.stats reflète le contenu réel du cache."""
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(self._binary_path, DISASM_LINES)
            cache.save_symbols(self._binary_path, SYMBOLS)

        stats = db_stats(self._db_path)
        self.assertEqual(stats["binaries"], 1)
        self.assertEqual(stats["total_disasm_lines"], len(DISASM_LINES))
        self.assertEqual(stats["total_symbols"], len(SYMBOLS))

    def test_cache_admin_list_and_purge(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(self._binary_path, DISASM_LINES)

        binaries = list_binaries(self._db_path)
        self.assertEqual(len(binaries), 1)
        self.assertEqual(binaries[0]["path"], self._binary_path)

        n = purge_binary(self._db_path)
        self.assertEqual(n, 1)
        self.assertEqual(list_binaries(self._db_path), [])


class TestAnnotationPipeline(unittest.TestCase):
    """Pipeline : AnnotationStore + export JSON + persistence."""

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

    def test_annotation_workflow(self):
        """Annoter, renommer, lister, exporter, puis vérifier persistence."""
        with AnnotationStore(self._binary_path, cache_path=self._db_path) as store:
            store.comment("0x401000", "entry point — vérifie argc")
            store.rename("0x401000", "check_args")
            store.comment("0x401020", "else branch — argc != 0")

            # Vérification en session
            self.assertEqual(store.get_comment("0x401000"), "entry point — vérifie argc")
            self.assertEqual(store.get_name("0x401000"), "check_args")
            self.assertEqual(len(store.list()), 3)

            exported = store.export_json()

        # Persistence : rouvrir et vérifier
        with AnnotationStore(self._binary_path, cache_path=self._db_path) as store2:
            self.assertEqual(store2.get_name("0x401000"), "check_args")
            all_ann = store2.list()

        self.assertEqual(len(exported), 3)
        self.assertEqual(len(all_ann), 3)

        # Export vers JSON fichier
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            json_path = f.name
        try:
            with open(json_path, "w", encoding="utf-8") as f:
                json.dump(exported, f, indent=2)
            with open(json_path, encoding="utf-8") as f:
                loaded = json.load(f)
            self.assertEqual(len(loaded), 3)
            kinds = {a["kind"] for a in loaded}
            self.assertIn("comment", kinds)
            self.assertIn("rename", kinds)
        finally:
            Path(json_path).unlink(missing_ok=True)


@unittest.skipUnless(_LIEF_AVAILABLE, "lief not installed")
class TestE2EPEPipeline(unittest.TestCase):
    """Tests E2E sur un vrai PE64 minimal."""

    def test_e2e_pe_pipeline(self):
        """Pipeline complet sur un PE64 : headers → sections → symbols → disasm."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)

            from backends.static.binary.headers import extract_binary_info

            info = extract_binary_info(pe_path)
            self.assertIn("PE", info.get("format", ""))

            from backends.static.binary.sections import extract_sections

            sects = extract_sections(pe_path)
            self.assertTrue(any(s["name"] == ".text" for s in sects))

            from backends.static.binary.symbols import extract_symbols

            syms = extract_symbols(pe_path)
            self.assertIsInstance(syms, list)

            from backends.static.disasm.disasm import disassemble_with_capstone

            lines = disassemble_with_capstone(pe_path)
            self.assertGreater(len(lines), 0)
        finally:
            os.unlink(pe_path)


if __name__ == "__main__":
    unittest.main()
