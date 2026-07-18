# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.disasm."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.exceptions import BinaryNotFoundError
from backends.static.disasm.disasm import (
    _augment_context_with_discovered_functions,
    _write_disasm_outputs,
    disassemble,
    disassemble_with_capstone,
)
from backends.static.disasm.mapping_db import query_window
from backends.static.tests.util import compile_minimal_elf

try:
    import capstone as _capstone
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


@unittest.skipUnless(_LIEF_AVAILABLE, "lief/capstone not installed")
def _db_lines(out_map):
    """Lit les lignes du mapping depuis le SQLite associé au JSON allégé."""
    lines, _total = query_window(str(out_map)[: -len(".json")] + ".db", None, 100000)
    return lines


class TestDisassembleWithCapstone(unittest.TestCase):
    """Tests de disassemble_with_capstone."""

    def test_nonexistent_binary_raises(self):
        """Binaire inexistant lève BinaryNotFoundError."""
        with self.assertRaises(BinaryNotFoundError):
            disassemble_with_capstone("/nonexistent/binary.elf")

    def test_real_binary(self):
        """Désassemble un binaire réel avec capstone + lief."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            lines = disassemble_with_capstone(str(binary))
            self.assertIsNotNone(lines)
            self.assertGreater(len(lines), 0)

            # Vérifier le format de sortie
            for line in lines:
                self.assertIn("addr", line)
                self.assertIn("text", line)
                self.assertIn("bytes", line)
                self.assertIn("mnemonic", line)
                self.assertIn("operands", line)
                # Vérifier que l'adresse est au format 0xhex
                self.assertTrue(line["addr"].startswith("0x"))

    def test_raw_multi_arch_branch_mnemonics(self):
        cases = [
            {
                "label": "riscv32",
                "arch": "riscv32",
                "base": "0x1200",
                "endian": "little",
                "blob": bytes.fromhex("6384000067800000"),
                "expected_mnemonics": ("beqz", "ret"),
            },
            {
                "label": "riscv64",
                "arch": "riscv64",
                "base": "0x1000",
                "endian": "little",
                "blob": bytes.fromhex("6384000067800000"),
                "expected_mnemonics": ("beqz", "ret"),
            },
            {
                "label": "sparc",
                "arch": "sparc",
                "base": "0x2000",
                "endian": "big",
                "blob": bytes.fromhex("108000020100000081c3e00801000000"),
                "expected_mnemonics": ("ba", "nop", "retl", "nop"),
            },
            {
                "label": "bpf",
                "arch": "bpf",
                "base": "0x0",
                "endian": "little",
                "blob": bytes.fromhex("85000000010000009500000000000000"),
                "expected_mnemonics": ("call", "exit"),
            },
            {
                "label": "wasm",
                "arch": "wasm",
                "base": "0x0",
                "endian": "little",
                "blob": bytes.fromhex("10000c000d000f0b"),
                "expected_mnemonics": ("call", "br", "br_if", "return", "end"),
            },
        ]
        for case in cases:
            with (
                self.subTest(arch=case["label"]),
                tempfile.NamedTemporaryFile(delete=False) as blob_file,
            ):
                blob_file.write(case["blob"])
                blob_path = blob_file.name
            try:
                lines = disassemble_with_capstone(
                    blob_path,
                    raw_arch=case["arch"],
                    raw_base_addr=case["base"],
                    raw_endian=case["endian"],
                )
                self.assertIsNotNone(lines)
                mnemonics = tuple(line["mnemonic"] for line in lines)
                self.assertEqual(mnemonics, case["expected_mnemonics"])
            finally:
                os.unlink(blob_path)


@unittest.skipUnless(_LIEF_AVAILABLE, "lief/capstone not installed")
class TestDisassemble(unittest.TestCase):
    """Tests de disassemble (fonction principale)."""

    def test_nonexistent_binary_raises(self):
        """Binaire inexistant lève BinaryNotFoundError."""
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BinaryNotFoundError):
                disassemble(
                    str(Path(tmp) / "nonexistent.elf"),
                    str(Path(tmp) / "out.asm"),
                )

    def test_real_binary(self):
        """Compile un binaire minimal, désassemble, vérifie la sortie."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            out_asm = tmp_path / "out.asm"
            out_map = tmp_path / "out.json"

            result = disassemble(
                str(binary),
                str(out_asm),
                output_mapping=str(out_map),
            )

            self.assertIsNotNone(result)
            self.assertEqual(result["path"], str(out_asm))
            self.assertIn("lines", result)
            self.assertGreater(len(result["lines"]), 0)

            # Vérifier que les fichiers sont créés
            self.assertTrue(out_asm.exists())
            self.assertTrue(out_map.exists())

            # Vérifier le format des lignes
            for line in result["lines"]:
                self.assertIn("addr", line)
                self.assertIn("text", line)
                self.assertIn("line", line)
                # Vérifier que l'adresse est au format 0xhex
                self.assertTrue(line["addr"].startswith("0x"))
                # Vérifier que line est un numéro de ligne valide
                self.assertIsInstance(line["line"], int)
                self.assertGreater(line["line"], 0)

    def test_intel_syntax(self):
        """Teste la syntaxe Intel (par défaut)."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            out_asm = tmp_path / "out.asm"

            result = disassemble(
                str(binary),
                str(out_asm),
                syntax="intel",
            )

            self.assertIsNotNone(result)
            self.assertGreater(len(result["lines"]), 0)

    def test_pe_disassembly(self):
        """Désassemble le .text d'un PE64 (nop;ret)."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            lines = disassemble_with_capstone(pe_path)
            self.assertIsInstance(lines, list)
            self.assertGreater(len(lines), 0)
            first = lines[0]
            self.assertIn("mnemonic", first)
            self.assertIn(first["mnemonic"].lower(), ("nop", "ret"))
        finally:
            os.unlink(pe_path)

    def test_cli_cache_hit_rebuilds_identical_asm(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            out1 = tmp_path / "out1.asm"
            map1 = tmp_path / "out1.json"
            out2 = tmp_path / "out2.asm"
            map2 = tmp_path / "out2.json"

            env = {**os.environ, "PYTHONPATH": str(ROOT)}
            cmd = [
                sys.executable,
                "backends/static/disasm/disasm.py",
                "--binary",
                str(binary),
                "--cache-db",
                "auto",
            ]

            r1 = subprocess.run(
                cmd + ["--output", str(out1), "--output-mapping", str(map1)],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env=env,
            )
            self.assertEqual(r1.returncode, 0, msg=r1.stderr)

            r2 = subprocess.run(
                cmd + ["--output", str(out2), "--output-mapping", str(map2)],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
                env=env,
            )
            self.assertEqual(r2.returncode, 0, msg=r2.stderr)
            self.assertIn("[cached]", r2.stdout)
            self.assertEqual(
                out1.read_text(encoding="utf-8"), out2.read_text(encoding="utf-8")
            )

    def test_raw_blob_disassembly(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            blob = tmp_path / "blob.bin"
            out_asm = tmp_path / "blob.asm"
            out_map = tmp_path / "blob.json"
            blob.write_bytes(bytes.fromhex("554889e5c3"))  # push rbp; mov rbp, rsp; ret

            result = disassemble(
                str(blob),
                str(out_asm),
                output_mapping=str(out_map),
                raw_arch="i386:x86-64",
                raw_base_addr="0x401000",
                raw_endian="little",
            )

            self.assertIsNotNone(result)
            self.assertTrue(out_asm.exists())
            self.assertTrue(out_map.exists())
            self.assertGreater(len(result["lines"]), 0)
            self.assertEqual(result["lines"][0]["addr"], "0x401000")

            mapping = json.loads(out_map.read_text(encoding="utf-8"))
            self.assertEqual(mapping["raw"]["arch"], "i386:x86-64")
            self.assertEqual(mapping["raw"]["base_addr"], "0x401000")
            self.assertEqual(mapping["raw"]["endian"], "little")
            self.assertEqual(mapping["arch"]["key"], "x86_64")
            self.assertEqual(mapping["arch"]["support"]["cfg"]["level"], "full")


class TestDisasmEnrichmentFormatting(unittest.TestCase):
    def test_write_outputs_include_function_banner_comment_and_stack_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            out_map = Path(tmp) / "out.json"
            lines = [
                {
                    "addr": "0x401000",
                    "text": "55                   push     rbp",
                    "bytes": "55",
                    "mnemonic": "push",
                    "operands": "rbp",
                },
                {
                    "addr": "0x401004",
                    "text": "48 89 44 24 18       mov      qword ptr [rsp + 0x18], rax",
                    "bytes": "48 89 44 24 18",
                    "mnemonic": "mov",
                    "operands": "qword ptr [rsp + 0x18], rax",
                },
            ]
            mapping = _write_disasm_outputs(
                lines,
                "/tmp/fake.bin",
                str(out_asm),
                str(out_map),
                label_map={0x401000: "entry_main"},
                comment_map={0x401000: "bootstrap"},
                function_ranges=[
                    (
                        0x401000,
                        0x401020,
                        {"addr": "0x401000", "name": "entry_main", "size": 0x20},
                    )
                ],
                stack_frames={
                    "0x401000": {
                        "args": [],
                        "vars": [
                            {
                                "name": "saved_tmp",
                                "location": "[rsp+0x18]",
                                "source": "auto",
                            }
                        ],
                    }
                },
            )

            asm = out_asm.read_text(encoding="utf-8")
            saved_lines = _db_lines(out_map)

            self.assertIn("; ===== Function entry_main @ 0x401000 =====", asm)
            self.assertIn("entry_main:", asm)
            self.assertIn("bootstrap", asm)
            self.assertIn("var saved_tmp @ [rsp+0x18]", asm)
            self.assertEqual(mapping["functions"][0]["name"], "entry_main")
            first_line = saved_lines[0]
            second_line = saved_lines[1]
            self.assertEqual(first_line["function_name"], "entry_main")
            self.assertEqual(second_line["function_addr"], "0x401000")
            self.assertEqual(second_line["stack_hints"][0]["name"], "saved_tmp")

    def test_write_outputs_include_register_arg_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            out_map = Path(tmp) / "out.json"
            lines = [
                {
                    "addr": "0x401000",
                    "text": "89 c7                mov      edi, eax",
                    "bytes": "89 c7",
                    "mnemonic": "mov",
                    "operands": "edi, eax",
                },
            ]
            _write_disasm_outputs(
                lines,
                "/tmp/fake.bin",
                str(out_asm),
                str(out_map),
                function_ranges=[
                    (
                        0x401000,
                        0x401010,
                        {"addr": "0x401000", "name": "entry_main", "size": 0x10},
                    )
                ],
                stack_frames={
                    "0x401000": {
                        "args": [
                            {
                                "name": "arg_rdi",
                                "location": "rdi",
                                "source": "abi",
                            }
                        ],
                        "vars": [],
                    }
                },
            )

            asm = out_asm.read_text(encoding="utf-8")
            saved_lines = _db_lines(out_map)

            self.assertIn("arg arg_rdi @ rdi", asm)
            self.assertEqual(saved_lines[0]["stack_hints"][0]["name"], "arg_rdi")
            self.assertEqual(saved_lines[0]["stack_hints"][0]["kind"], "arg")

    def test_generic_macho_header_symbol_falls_back_to_discovered_functions(self):
        lines = [
            {
                "addr": "0x100000978",
                "text": "55                   push     rbp",
                "bytes": "55",
                "mnemonic": "push",
                "operands": "rbp",
            },
            {
                "addr": "0x100000979",
                "text": "48 89 e5             mov      rbp, rsp",
                "bytes": "48 89 e5",
                "mnemonic": "mov",
                "operands": "rbp, rsp",
            },
            {
                "addr": "0x10000097c",
                "text": "c3                   ret",
                "bytes": "c3",
                "mnemonic": "ret",
                "operands": "",
            },
        ]
        context = {
            "label_map": {},
            "comment_map": {},
            "function_ranges": [],
            "stack_frames": {},
            "typed_struct_index": {},
        }
        with mock.patch(
            "backends.static.disasm.disasm.extract_symbols",
            return_value=[
                {
                    "name": "__mh_execute_header",
                    "addr": "0x100000000",
                    "type": "T",
                    "size": None,
                }
            ],
        ):
            enriched = _augment_context_with_discovered_functions(
                context,
                lines,
                "/tmp/ls",
            )

        ranges = enriched["function_ranges"]
        self.assertEqual(len(ranges), 1)
        self.assertEqual(ranges[0][2]["addr"], "0x100000978")
        self.assertNotEqual(ranges[0][2]["name"], "__mh_execute_header")

    def test_write_outputs_include_typed_struct_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            out_map = Path(tmp) / "out.json"
            lines = [
                {
                    "addr": "0x401000",
                    "text": "mov      eax, 0x402000",
                    "bytes": "b8 00 20 40 00",
                    "mnemonic": "mov",
                    "operands": "eax, 0x402000",
                },
            ]
            _write_disasm_outputs(
                lines,
                "/tmp/fake.bin",
                str(out_asm),
                str(out_map),
                typed_struct_index={
                    "exact_by_addr": {
                        "0x402000": {
                            "kind": "field",
                            "label": "Demo.magic",
                            "comment": "struct Demo • champ magic • uint32_t",
                            "addr": "0x402000",
                            "struct_name": "Demo",
                            "field_name": "magic",
                            "field_type": "uint32_t",
                        }
                    }
                },
            )

            asm = out_asm.read_text(encoding="utf-8")
            saved_lines = _db_lines(out_map)
            self.assertIn("struct Demo.magic", asm)
            self.assertEqual(
                saved_lines[0]["typed_struct_hints"][0]["label"], "Demo.magic"
            )

    def test_write_outputs_match_arm_memory_stack_hints(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            out_map = Path(tmp) / "out.json"
            lines = [
                {
                    "addr": "0x500000",
                    "text": "f9 40 0b a9          ldr      x0, [x29, #0x10]",
                    "bytes": "f9 40 0b a9",
                    "mnemonic": "ldr",
                    "operands": "x0, [x29, #0x10]",
                },
                {
                    "addr": "0x600000",
                    "text": "e5 9b 40 08          ldr      r4, [fp, #0x8]",
                    "bytes": "e5 9b 40 08",
                    "mnemonic": "ldr",
                    "operands": "r4, [fp, #0x8]",
                },
            ]
            _write_disasm_outputs(
                lines,
                "/tmp/fake.bin",
                str(out_asm),
                str(out_map),
                function_ranges=[
                    (
                        0x500000,
                        0x500010,
                        {"addr": "0x500000", "name": "sub_500000", "size": 0x10},
                    ),
                    (
                        0x600000,
                        0x600010,
                        {"addr": "0x600000", "name": "sub_600000", "size": 0x10},
                    ),
                ],
                stack_frames={
                    "0x500000": {
                        "args": [
                            {
                                "name": "arg_saved",
                                "location": "[x29+0x10]",
                                "source": "auto",
                            }
                        ],
                        "vars": [],
                    },
                    "0x600000": {
                        "args": [
                            {
                                "name": "arg_fp",
                                "location": "[r11+0x8]",
                                "source": "auto",
                            }
                        ],
                        "vars": [],
                    },
                },
            )

            asm = out_asm.read_text(encoding="utf-8")
            saved_lines = _db_lines(out_map)

            self.assertIn("arg arg_saved @ [x29+0x10]", asm)
            self.assertIn("arg arg_fp @ [r11+0x8]", asm)
            self.assertEqual(saved_lines[0]["stack_hints"][0]["name"], "arg_saved")
            self.assertEqual(saved_lines[1]["stack_hints"][0]["name"], "arg_fp")

    def test_write_outputs_replaces_non_x86_branch_targets(self):
        with tempfile.TemporaryDirectory() as tmp:
            out_asm = Path(tmp) / "out.asm"
            out_map = Path(tmp) / "out.json"
            lines = [
                {
                    "addr": "0x1000",
                    "text": "63 14 a5 00          bnez     a0, 0x1010",
                    "bytes": "63 14 a5 00",
                    "mnemonic": "bnez",
                    "operands": "0x1010",
                },
                {
                    "addr": "0x1010",
                    "text": "82 80                ret",
                    "bytes": "82 80",
                    "mnemonic": "ret",
                    "operands": "",
                },
            ]
            _write_disasm_outputs(
                lines,
                "/tmp/fake.bin",
                str(out_asm),
                str(out_map),
                label_map={0x1010: "done"},
            )

            asm = out_asm.read_text(encoding="utf-8")
            self.assertIn("bnez     a0, done", asm)


if __name__ == "__main__":
    unittest.main()
