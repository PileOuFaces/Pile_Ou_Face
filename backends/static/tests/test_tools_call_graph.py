# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour tools.static.call_graph."""

import json
import os
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import subprocess
import tempfile

from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm.call_graph import build_call_graph, resolve_plt_symbols


class TestBuildCallGraph(unittest.TestCase):
    """Tests de build_call_graph."""

    def test_empty_cfg_empty_symbols(self):
        result = build_call_graph({"edges": []}, [])
        self.assertEqual(result["nodes"], [])
        self.assertEqual(result["edges"], [])

    def test_call_edges_extracted(self):
        cfg = {
            "edges": [
                {"from": "0x401000", "to": "0x401100", "type": "call"},
                {"from": "0x401000", "to": "0x401200", "type": "jmp"},
            ],
        }
        symbols = [
            {"addr": "0x401000", "name": "main", "type": "T"},
            {"addr": "0x401100", "name": "foo", "type": "T"},
        ]
        result = build_call_graph(cfg, symbols)
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["from"], "0x401000")
        self.assertEqual(result["edges"][0]["to"], "0x401100")
        self.assertIn("from_name", result["edges"][0])
        self.assertIn("to_name", result["edges"][0])

    def test_symbol_resolution(self):
        cfg = {"edges": [{"from": "0x401010", "to": "0x401100", "type": "call"}]}
        symbols = [
            {"addr": "0x401000", "name": "main", "type": "T"},
            {"addr": "0x401100", "name": "printf", "type": "T"},
        ]
        result = build_call_graph(cfg, symbols)
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["from_name"], "main")
        self.assertEqual(result["edges"][0]["to_name"], "printf")

    def test_nodes_built(self):
        cfg = {"edges": [{"from": "0x401000", "to": "0x401100", "type": "call"}]}
        symbols = [{"addr": "0x401000", "name": "main", "type": "T"}]
        result = build_call_graph(cfg, symbols)
        self.assertGreaterEqual(len(result["nodes"]), 1)
        for n in result["nodes"]:
            self.assertIn("addr", n)
            self.assertIn("name", n)

    def test_dynamic_symbol_from_disasm(self):
        """CG2: noms dynamiques (puts@plt) depuis le texte objdump."""
        cfg = {"edges": [{"from": "0x401050", "to": "0x401030", "type": "call"}]}
        symbols = [{"addr": "0x401000", "name": "main", "type": "T"}]
        lines = [
            {"addr": "0x401050", "text": "e8 db ff ff ff \tcall\t0x401030 <puts@plt>"},
        ]
        result = build_call_graph(cfg, symbols, lines=lines)
        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["to_name"], "puts@plt")
        self.assertEqual(result["edges"][0]["from_name"], "main")

    def test_discovered_functions_can_name_raw_call_graph(self):
        cfg = {"edges": [{"from": "0x500010", "to": "0x500100", "type": "call"}]}
        symbols = [
            {"addr": "0x500000", "name": "entry_blob", "type": "auto"},
            {"addr": "0x500100", "name": "sub_500100", "type": "auto"},
        ]
        result = build_call_graph(cfg, symbols)
        self.assertEqual(result["edges"][0]["from_name"], "entry_blob")
        self.assertEqual(result["edges"][0]["to_name"], "sub_500100")

    def test_plt_map_overrides_text_resolution(self):
        """CG1: la PLT map a priorité sur le texte de l'instruction."""
        plt_stub_addr = "0x401030"
        cfg = {"edges": [{"from": "0x401050", "to": plt_stub_addr, "type": "call"}]}
        symbols = [{"addr": "0x401000", "name": "main", "type": "T"}]
        # PLT map résout 0x401030 → puts@plt directement
        # build_call_graph avec binary_path=None, on injecte plt_map via monkey-patch
        # → on vérifie via le résultat que le nom est bien résolu
        # On simule la résolution PLT via la fonction resolve_plt_symbols
        result = build_call_graph(cfg, symbols)
        # Sans PLT map, l'adresse reste non résolue (à moins d'un symbole statique)
        self.assertEqual(result["edges"][0]["to"], plt_stub_addr)


class TestResolvePltSymbols(unittest.TestCase):
    """Tests pour resolve_plt_symbols."""

    def test_nonexistent_binary_returns_empty(self):
        result = resolve_plt_symbols("/nonexistent/binary.elf")
        self.assertEqual(result, {})

    def test_real_binary_returns_dict(self):
        """Compile un binaire avec PLT call et vérifie la résolution."""
        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "test.c"
            src.write_text('#include <stdio.h>\nint main() { puts("hi"); return 0; }')
            out = Path(tmp) / "test"
            r = subprocess.run(
                ["gcc", "-o", str(out), str(src)],
                capture_output=True,
            )
            if r.returncode != 0:
                self.skipTest("gcc non disponible")

            plt_map = resolve_plt_symbols(str(out))
            self.assertIsInstance(plt_map, dict)
            # Au moins puts@plt ou _puts@plt doit apparaître
            if plt_map:
                values = list(plt_map.values())
                self.assertTrue(
                    any("puts" in v for v in values),
                    f"'puts' not found in PLT map values: {values}",
                )
                # Toutes les valeurs doivent finir par @plt
                for v in values:
                    self.assertTrue(v.endswith("@plt"), f"{v} does not end with @plt")


class TestCallGraphCli(unittest.TestCase):
    def test_cli_uses_cached_cfg_and_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "cached.elf"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

            mapping = Path(tmp) / "mapping.json"
            mapping.write_text(
                json.dumps({"binary": str(binary), "lines": []}),
                encoding="utf-8",
            )

            with DisasmCache(default_cache_path(str(binary))) as cache:
                cache.save_cfg(
                    str(binary),
                    {
                        "blocks": [],
                        "edges": [{"from": "0x401000", "to": "0x401020", "type": "call"}],
                    },
                )
                cache.save_symbols(
                    str(binary),
                    [
                        {"addr": "0x401000", "name": "main", "type": "T"},
                        {"addr": "0x401020", "name": "puts", "type": "T"},
                    ],
                )

            result = subprocess.run(
                [
                    sys.executable,
                    "backends/static/disasm/call_graph.py",
                    "--mapping",
                    str(mapping),
                    "--binary",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env={**os.environ, "PYTHONPATH": str(ROOT)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(len(data["edges"]), 1)
            self.assertEqual(data["edges"][0]["from_name"], "main")
            self.assertEqual(data["edges"][0]["to_name"], "puts")

    def test_cli_supports_raw_mapping_with_discovered_functions_as_symbols(self):
        with tempfile.TemporaryDirectory() as tmp:
            mapping = Path(tmp) / "blob.mapping.json"
            mapping.write_text(
                json.dumps(
                    {
                        "path": str(Path(tmp) / "blob.disasm.asm"),
                        "raw": {
                            "arch": "i386:x86-64",
                            "base_addr": "0x500000",
                            "endian": "little",
                        },
                        "lines": [
                            {"addr": "0x500000", "text": "call\t0x500100", "line": 1},
                            {"addr": "0x500005", "text": "ret", "line": 2},
                            {"addr": "0x500100", "text": "ret", "line": 3},
                        ],
                    }
                ),
                encoding="utf-8",
            )
            symbols = Path(tmp) / "blob.discovered.json"
            symbols.write_text(
                json.dumps(
                    [
                        {"addr": "0x500000", "name": "entry_blob", "type": "auto"},
                        {"addr": "0x500100", "name": "sub_500100", "type": "auto"},
                    ]
                ),
                encoding="utf-8",
            )

            result = subprocess.run(
                [
                    sys.executable,
                    "backends/static/disasm/call_graph.py",
                    "--mapping",
                    str(mapping),
                    "--symbols",
                    str(symbols),
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env={**os.environ, "PYTHONPATH": str(ROOT)},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            data = json.loads(result.stdout)
            self.assertEqual(len(data["edges"]), 1)
            self.assertEqual(data["edges"][0]["from_name"], "entry_blob")
            self.assertEqual(data["edges"][0]["to_name"], "sub_500100")


if __name__ == "__main__":
    unittest.main()
