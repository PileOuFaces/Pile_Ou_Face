# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.xrefs."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.disasm.xrefs import (
    extract_xrefs,
    extract_xrefs_from_addr,
    build_xref_map,
    _describe_source_context,
    _is_store_ref,
    _classify_data_ref,
    _location_matches_text,
)


class TestExtractXrefs(unittest.TestCase):
    """Tests de extract_xrefs."""

    def test_empty_lines(self):
        self.assertEqual(extract_xrefs([], "0x401000"), [])

    def test_call_to_target(self):
        lines = [
            {"addr": "0x401000", "text": "call\t0x401100", "line": 1},
            {"addr": "0x401100", "text": "ret", "line": 2},
        ]
        refs = extract_xrefs(lines, "0x401100")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["from_addr"], "0x401000")
        self.assertEqual(refs[0]["type"], "call")

    def test_jmp_to_target(self):
        lines = [
            {"addr": "0x401000", "text": "jmp\t0x401050", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401050")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "jmp")

    def test_data_ref_load(self):
        lines = [
            {"addr": "0x401000", "text": "mov	rax, [0x401200]", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401200")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "load")
        self.assertEqual(refs[0]["from_addr"], "0x401000")

    def test_data_ref_lea(self):
        lines = [
            {"addr": "0x401010", "text": "lea	rdi, [0x401300]", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401300")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "lea")

    def test_data_ref_rip_relative_lea(self):
        lines = [
            {
                "addr": "0x401010",
                "text": "48 8d 3d 79 0a 00 00 lea      rdi, [rip + 0xa79]",
                "operands": "rdi, [rip + 0xa79]",
                "bytes": "48 8d 3d 79 0a 00 00",
                "line": 1,
            },
        ]
        refs = extract_xrefs(lines, "0x401a90")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "lea")
        self.assertEqual(refs[0]["from_addr"], "0x401010")

    def test_data_ref_store(self):
        """mov [addr], src doit être classifié store."""
        lines = [
            {"addr": "0x401020", "text": "mov\t[0x601050], rax", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x601050")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "store")

    def test_jcc_to_target(self):
        lines = [
            {"addr": "0x401005", "text": "jne\t0x401020", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401020")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "jcc")

    def test_arm64_call_to_target(self):
        lines = [
            {"addr": "0x500000", "text": "bl\t0x500100", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x500100")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "call")

    def test_no_data_ref_without_bracket(self):
        """mov rax, 0x401234 sans brackets ne doit pas être une data ref."""
        lines = [
            {"addr": "0x401000", "text": "mov\trax, 0x401234", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401234")
        self.assertEqual(refs, [])

    def test_include_data_false(self):
        lines = [
            {"addr": "0x401000", "text": "mov\trax, [0x401200]", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x401200", include_data=False)
        self.assertEqual(refs, [])

    def test_arm64_store_is_classified_as_store(self):
        lines = [
            {"addr": "0x500010", "text": "str\tx0, [0x601000]", "line": 1},
        ]
        refs = extract_xrefs(lines, "0x601000")
        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["type"], "store")

    def test_multi_arch_riscv_and_mips_code_refs(self):
        lines = [
            {"addr": "0x800000", "text": "000000ef jal 0x800020", "line": 1},
            {"addr": "0x800004", "text": "11000003 beq t0, zero, 0x800018", "line": 2},
        ]
        call_refs = extract_xrefs(lines, "0x800020")
        branch_refs = extract_xrefs(lines, "0x800018")
        self.assertEqual(call_refs[0]["type"], "call")
        self.assertEqual(branch_refs[0]["type"], "jcc")


class TestStoreDetection(unittest.TestCase):
    """Tests pour _is_store_ref et _classify_data_ref."""

    def test_is_store_bracket_first(self):
        self.assertTrue(_is_store_ref("mov\t[0x601050], rax"))

    def test_is_load_bracket_second(self):
        self.assertFalse(_is_store_ref("mov\trax, [0x601050]"))

    def test_classify_lea(self):
        self.assertEqual(_classify_data_ref("lea", "lea\trdi, [0x401300]"), "lea")

    def test_classify_store(self):
        self.assertEqual(_classify_data_ref("mov", "mov\t[0x601050], rax"), "store")

    def test_classify_load(self):
        self.assertEqual(_classify_data_ref("mov", "mov\trax, [0x601050]"), "load")

    def test_classify_arm64_store(self):
        self.assertEqual(_classify_data_ref("str", "str\tx0, [0x601050]"), "store")

    def test_classify_arm64_load(self):
        self.assertEqual(_classify_data_ref("ldr", "ldr\tx0, [0x601050]"), "load")

    def test_classify_mips_ppc_load_store(self):
        self.assertEqual(_classify_data_ref("lw", "lw a0, 8(sp)"), "load")
        self.assertEqual(_classify_data_ref("sw", "sw a0, 8(sp)"), "store")
        self.assertEqual(_classify_data_ref("std", "std r3, 16(r1)"), "store")

    def test_matches_offset_base_memory_locations(self):
        self.assertTrue(_location_matches_text("[sp+0x8]", "lw a0, 8(sp)"))
        self.assertTrue(_location_matches_text("[sp+0x10]", "ld r3, 16(r1)"))
        self.assertTrue(_location_matches_text("[r11-0x8]", "ld [%fp - 0x8], %l0"))


class TestBuildXrefMap(unittest.TestCase):
    """Tests pour build_xref_map."""

    def test_empty_returns_empty(self):
        self.assertEqual(build_xref_map([]), {})

    def test_call_appears_in_map(self):
        lines = [
            {"addr": "0x401000", "text": "call\t0x401100", "line": 1},
            {"addr": "0x401100", "text": "ret", "line": 2},
        ]
        xmap = build_xref_map(lines)
        self.assertIn("0x401100", xmap)
        self.assertEqual(xmap["0x401100"][0]["type"], "call")
        self.assertEqual(xmap["0x401100"][0]["from_addr"], "0x401000")

    def test_multiple_callers_aggregated(self):
        lines = [
            {"addr": "0x401000", "text": "call\t0x401500", "line": 1},
            {"addr": "0x401010", "text": "call\t0x401500", "line": 2},
        ]
        xmap = build_xref_map(lines)
        self.assertEqual(len(xmap["0x401500"]), 2)

    def test_data_ref_in_map(self):
        lines = [
            {"addr": "0x401000", "text": "mov\trax, [0x601000]", "line": 1},
        ]
        xmap = build_xref_map(lines)
        self.assertIn("0x601000", xmap)
        self.assertEqual(xmap["0x601000"][0]["type"], "load")

    def test_rip_relative_data_ref_in_map(self):
        lines = [
            {
                "addr": "0x401010",
                "text": "48 8d 3d 79 0a 00 00 lea      rdi, [rip + 0xa79]",
                "operands": "rdi, [rip + 0xa79]",
                "bytes": "48 8d 3d 79 0a 00 00",
                "line": 1,
            },
        ]
        xmap = build_xref_map(lines)
        self.assertIn("0x401a90", xmap)
        self.assertEqual(xmap["0x401a90"][0]["type"], "lea")

    def test_multi_arch_data_ref_in_map(self):
        lines = [
            {"addr": "0x900000", "text": "8d280000 lw t0, [0x900100]", "line": 1},
        ]
        xmap = build_xref_map(lines)
        self.assertIn("0x900100", xmap)
        self.assertEqual(xmap["0x900100"][0]["type"], "load")

    def test_include_data_false_excludes_data_refs(self):
        lines = [
            {"addr": "0x401000", "text": "mov\trax, [0x601000]", "line": 1},
            {"addr": "0x401010", "text": "call\t0x401100", "line": 2},
        ]
        xmap = build_xref_map(lines, include_data=False)
        self.assertNotIn("0x601000", xmap)
        self.assertIn("0x401100", xmap)


class TestExtractXrefsFromAddr(unittest.TestCase):
    """Tests de extract_xrefs_from_addr."""

    def test_empty_lines(self):
        self.assertEqual(extract_xrefs_from_addr([], "0x401000"), [])

    def test_call_returns_target(self):
        lines = [
            {"addr": "0x401000", "text": "call\t0x401100", "line": 1},
        ]
        targets = extract_xrefs_from_addr(lines, "0x401000")
        self.assertEqual(targets, ["0x401100"])

    def test_nop_returns_empty(self):
        lines = [
            {"addr": "0x401000", "text": "nop", "line": 1},
        ]
        self.assertEqual(extract_xrefs_from_addr(lines, "0x401000"), [])

    def test_data_ref_returns_target(self):
        """mov rax, [addr] doit retourner addr comme cible."""
        lines = [
            {"addr": "0x401000", "text": "mov\trax, [0x601000]", "line": 1},
        ]
        targets = extract_xrefs_from_addr(lines, "0x401000")
        self.assertIn("0x601000", targets)


class TestBuildXrefMapTypeInfo(unittest.TestCase):
    """Vérifie que les entrées xref ont un champ type_info."""

    def test_build_xref_map_has_type_info_key(self):
        """build_xref_map() retourne des entrées avec clé type_info (peut être None)."""
        lines = [
            {"addr": "0x401000", "text": "call\t0x401100", "line": 1},
        ]
        xmap = build_xref_map(lines)
        self.assertTrue(len(xmap) > 0, "xref map should not be empty for 'call' instruction")
        for refs in xmap.values():
            for ref in refs:
                self.assertIn("type_info", ref)


class TestXrefBinaryContext(unittest.TestCase):
    def _fake_cache(self):
        class FakeCache:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get_functions(self, _binary_path):
                return [{"addr": "0x401000", "name": "sub_401000", "size": 0x40}]

            def get_symbols(self, _binary_path):
                return []

            def get_annotations(self, _binary_path):
                return [{"addr": "0x401000", "kind": "rename", "value": "entry_main"}]

            def get_stack_frame(self, _binary_path, _func_addr):
                return {
                    "args": [],
                    "vars": [
                        {
                            "name": "saved_tmp",
                            "offset": -16,
                            "location": "[rsp+0x18]",
                            "source": "auto",
                        }
                    ],
                }

        return FakeCache()

    def test_extract_xrefs_enriches_function_and_stack_context(self):
        lines = [
            {
                "addr": "0x401010",
                "text": "mov qword ptr [rsp + 0x18], 0x601000",
                "line": 1,
            }
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=self._fake_cache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
        ):
            refs = extract_xrefs(lines, "0x601000", binary_path=tmp.name)

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["function_name"], "entry_main")
        self.assertEqual(refs[0]["function_addr"], "0x401000")
        self.assertEqual(refs[0]["stack_hints"][0]["name"], "saved_tmp")

    def test_extract_xrefs_enriches_typed_struct_context(self):
        lines = [
            {
                "addr": "0x401010",
                "text": "mov qword ptr [rsp + 0x18], 0x601000",
                "line": 1,
            }
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=self._fake_cache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
            mock.patch(
                "backends.static.disasm.xrefs.build_typed_struct_index",
                return_value={
                    "exact_by_addr": {
                        "0x601000": {
                            "kind": "field",
                            "label": "Demo.magic",
                            "addr": "0x601000",
                            "struct_name": "Demo",
                            "field_name": "magic",
                            "field_type": "uint32_t",
                        }
                    }
                },
            ),
        ):
            refs = extract_xrefs(lines, "0x601000", binary_path=tmp.name)

        self.assertEqual(refs[0]["typed_struct_hints"][0]["label"], "Demo.magic")

    def test_extract_xrefs_enriches_register_arg_context(self):
        class FakeCache:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get_functions(self, _binary_path):
                return [{"addr": "0x401000", "name": "sub_401000", "size": 0x40}]

            def get_symbols(self, _binary_path):
                return []

            def get_annotations(self, _binary_path):
                return []

            def get_stack_frame(self, _binary_path, _func_addr):
                return {
                    "args": [
                        {
                            "name": "arg_rdi",
                            "offset": None,
                            "location": "rdi",
                            "source": "abi",
                        }
                    ],
                    "vars": [],
                }

        lines = [
            {
                "addr": "0x401010",
                "text": "mov dword ptr [0x601000], edi",
                "line": 1,
            }
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=FakeCache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
        ):
            refs = extract_xrefs(lines, "0x601000", binary_path=tmp.name)

        self.assertEqual(len(refs), 1)
        self.assertTrue(
            any(h["name"] == "arg_rdi" and h["kind"] == "arg" for h in refs[0]["stack_hints"])
        )

    def test_extract_xrefs_matches_arm_memory_stack_context(self):
        class FakeCache:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get_functions(self, _binary_path):
                return [
                    {"addr": "0x500000", "name": "sub_500000", "size": 0x40},
                    {"addr": "0x600000", "name": "sub_600000", "size": 0x40},
                ]

            def get_symbols(self, _binary_path):
                return []

            def get_annotations(self, _binary_path):
                return []

            def get_stack_frame(self, _binary_path, func_addr):
                if func_addr == "0x500000":
                    return {
                        "args": [{"name": "arg_saved", "location": "[x29+0x10]", "source": "auto"}],
                        "vars": [],
                    }
                return {
                    "args": [{"name": "arg_fp", "location": "[r11+0x8]", "source": "auto"}],
                    "vars": [],
                }

        lines = [
            {
                "addr": "0x500010",
                "text": "ldr x0, [x29, #0x10] ; 0x601000",
                "line": 1,
            },
            {
                "addr": "0x600010",
                "text": "ldr r4, [fp, #0x8] ; 0x602000",
                "line": 2,
            },
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=FakeCache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
        ):
            refs_arm64 = extract_xrefs(lines, "0x601000", binary_path=tmp.name)
            refs_arm32 = extract_xrefs(lines, "0x602000", binary_path=tmp.name)

        self.assertEqual(len(refs_arm64), 1)
        self.assertEqual(len(refs_arm32), 1)
        self.assertTrue(
            any(
                h["name"] == "arg_saved" and h["kind"] == "arg"
                for h in refs_arm64[0]["stack_hints"]
            )
        )
        self.assertTrue(
            any(h["name"] == "arg_fp" and h["kind"] == "arg" for h in refs_arm32[0]["stack_hints"])
        )

    def test_extract_xrefs_matches_offset_base_stack_context(self):
        class FakeCache:
            def __enter__(self):
                return self

            def __exit__(self, exc_type, exc, tb):
                return False

            def get_functions(self, _binary_path):
                return [{"addr": "0x800000", "name": "sub_800000", "size": 0x40}]

            def get_symbols(self, _binary_path):
                return []

            def get_annotations(self, _binary_path):
                return []

            def get_stack_frame(self, _binary_path, _func_addr):
                return {
                    "args": [],
                    "vars": [{"name": "saved_ra", "location": "[sp+0x8]", "source": "auto"}],
                }

        lines = [
            {
                "addr": "0x800010",
                "text": "lw ra, 8(sp) ; 0x900100",
                "line": 1,
            },
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=FakeCache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
        ):
            refs = extract_xrefs(lines, "0x900100", binary_path=tmp.name)

        self.assertEqual(len(refs), 1)
        self.assertTrue(
            any(h["name"] == "saved_ra" and h["kind"] == "var" for h in refs[0]["stack_hints"])
        )

    def test_extract_xrefs_can_enrich_from_functions_without_binary(self):
        lines = [
            {
                "addr": "0x500010",
                "text": "str x0, [0x601000]",
                "line": 1,
            }
        ]
        refs = extract_xrefs(
            lines,
            "0x601000",
            binary_path=None,
            functions=[{"addr": "0x500000", "name": "sub_500000", "size": 0x40}],
        )

        self.assertEqual(len(refs), 1)
        self.assertEqual(refs[0]["function_addr"], "0x500000")
        self.assertEqual(refs[0]["function_name"], "sub_500000")

    def test_describe_source_context_enriches_function_name(self):
        lines = [
            {"addr": "0x401010", "text": "call 0x401100", "line": 3},
        ]
        with (
            tempfile.NamedTemporaryFile() as tmp,
            mock.patch("backends.static.disasm.xrefs.DisasmCache", return_value=self._fake_cache()),
            mock.patch("backends.static.disasm.xrefs.default_cache_path", return_value=tmp.name),
        ):
            source = _describe_source_context(lines, "0x401010", binary_path=tmp.name)

        self.assertIsNotNone(source)
        self.assertEqual(source["function_name"], "entry_main")
        self.assertEqual(source["line"], 3)

    def test_describe_source_context_can_use_functions_without_binary(self):
        lines = [
            {"addr": "0x500020", "text": "bl 0x500100", "line": 7},
        ]
        source = _describe_source_context(
            lines,
            "0x500020",
            functions=[{"addr": "0x500000", "name": "entry_blob", "size": 0x80}],
        )

        self.assertIsNotNone(source)
        self.assertEqual(source["function_name"], "entry_blob")
        self.assertEqual(source["function_addr"], "0x500000")


if __name__ == "__main__":
    unittest.main()
