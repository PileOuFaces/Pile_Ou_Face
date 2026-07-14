# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.cfg."""

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.utils import normalize_addr as _normalize_addr
from backends.static.disasm.cfg import (
    _detect_switch_max_case,
    _extract_jump_table_base,
    _extract_jump_target,
    _get_mnemonic,
    _is_branch,
    _is_jump_table,
    _is_valid_code_addr,
    _read_jump_table_entries,
    _resolve_rip_relative_table,
    _section_is_exec,
    build_cfg,
    build_cfg_for_function,
    find_function_entry_for_addr,
)


class TestCfgHelpers(unittest.TestCase):
    def test_get_mnemonic_with_tab(self):
        self.assertEqual(_get_mnemonic("e8 56 00 00 00\tcall\t0x1000004d8"), "call")
        self.assertEqual(_get_mnemonic("75 07\tjne\t0x1000004be"), "jne")

    def test_extract_jump_target(self):
        self.assertEqual(
            _extract_jump_target("call\t0x1000004d8 <_printf+0x1000004d8>"),
            "0x1000004d8",
        )
        self.assertEqual(
            _extract_jump_target("jne\t0x1000004be <_main+0x2e>"), "0x1000004be"
        )

    def test_extract_jump_target_ignores_leading_instruction_bytes(self):
        self.assertEqual(_extract_jump_target("0c200008 jal 0x800020"), "0x800020")
        self.assertIsNone(_extract_jump_target("03e00008 jr ra"))

    def test_normalize_addr(self):
        self.assertEqual(_normalize_addr("0x401000"), "0x401000")
        self.assertEqual(_normalize_addr("401000"), "0x401000")

    def test_operand_based_returns_are_branches_without_targets(self):
        cases = [
            "03e00008 jr ra",
            "e12fff1e bx lr",
            "pop {r4, pc}",
        ]
        for text in cases:
            with self.subTest(text=text):
                is_branch, is_call, target = _is_branch(text)
                self.assertTrue(is_branch)
                self.assertFalse(is_call)
                self.assertIsNone(target)


class TestJumpTableDetection(unittest.TestCase):
    """Tests pour la détection de jump tables."""

    def test_is_jump_table_x86_indirect_jmp(self):
        """Détecte jmp indirect avec indexation."""
        # x86-64: jmp qword ptr [rip+rax*8+offset]
        self.assertTrue(_is_jump_table("jmp\tqword ptr [rip+rax*8+0x2004]"))
        self.assertTrue(_is_jump_table("jmp\tdword ptr [eax*4+0x401000]"))
        self.assertTrue(_is_jump_table("jmp\tqword ptr [r12+rbx*8]"))

    def test_is_jump_table_not_detected_for_direct_jmp(self):
        """Ne détecte pas les sauts directs."""
        self.assertFalse(_is_jump_table("jmp\t0x401000"))
        self.assertFalse(_is_jump_table("jmp\t0x1000004d8 <_main>"))

    def test_is_jump_table_arm64_br(self):
        """Détecte br (branch register) sur ARM64."""
        self.assertTrue(_is_jump_table("br\tx8"))
        self.assertTrue(_is_jump_table("br\tx10"))

    def test_is_jump_table_multi_arch_register_indirect(self):
        """Détecte aussi les patterns registre exotiques hors x86/ARM64."""
        self.assertTrue(_is_jump_table("03e00008 jr t9"))
        self.assertFalse(_is_jump_table("03e00008 jr ra"))
        self.assertTrue(_is_jump_table("jalr zero, t0, 0"))
        self.assertTrue(_is_jump_table("bctr"))

    def test_is_jump_table_not_detected_for_normal_branch(self):
        """Ne détecte pas les branches normales."""
        self.assertFalse(_is_jump_table("b\t0x1000004e8"))
        self.assertFalse(_is_jump_table("bl\t0x100000584"))

    def test_extract_jump_table_base_rip_relative(self):
        """Extrait l'offset RIP-relatif."""
        addr = _extract_jump_table_base("jmp\tqword ptr [rip+rax*8+0x2004]")
        self.assertEqual(addr, "0x2004")

    def test_extract_jump_table_base_absolute(self):
        """Extrait l'adresse absolue."""
        addr = _extract_jump_table_base("jmp\tdword ptr [0x401234+rax*8]")
        self.assertEqual(addr, "0x401234")

    def test_extract_jump_table_base_no_address(self):
        """Retourne None si pas d'adresse."""
        addr = _extract_jump_table_base("br\tx8")
        self.assertIsNone(addr)


class TestBuildCfg(unittest.TestCase):
    def test_empty_returns_empty(self):
        cfg = build_cfg([])
        self.assertEqual(cfg["blocks"], [])
        self.assertEqual(cfg["edges"], [])
        self.assertEqual(cfg["support_level"], "unsupported")

    def test_single_line_no_branch(self):
        lines = [{"addr": "0x401000", "text": "push rbp", "line": 1}]
        cfg = build_cfg(lines)
        self.assertEqual(len(cfg["blocks"]), 1)
        self.assertEqual(cfg["blocks"][0]["addr"], "0x401000")
        self.assertEqual(cfg["blocks"][0]["successors"], [])

    def test_jmp_creates_blocks(self):
        lines = [
            {"addr": "0x401000", "text": "jmp\t0x401010", "line": 1},
            {"addr": "0x401005", "text": "nop", "line": 2},
            {"addr": "0x401010", "text": "ret", "line": 3},
        ]
        cfg = build_cfg(lines)
        self.assertGreater(len(cfg["blocks"]), 0)
        self.assertGreater(len(cfg["edges"]), 0)

    def test_push_ret_creates_jmp_edge(self):
        """push+ret = jmp : la cible du push devient un successeur."""
        lines = [
            {"addr": "0x401000", "text": "push\t0x401020", "line": 1},
            {"addr": "0x401005", "text": "ret", "line": 2},
            {"addr": "0x401010", "text": "nop", "line": 3},
            {"addr": "0x401020", "text": "ret", "line": 4},
        ]
        cfg = build_cfg(lines)
        self.assertIn("0x401000", [b["addr"] for b in cfg["blocks"]])
        jmp_to_4020 = [
            e for e in cfg["edges"] if e["from"] == "0x401000" and e["to"] == "0x401020"
        ]
        self.assertEqual(len(jmp_to_4020), 1)
        self.assertEqual(jmp_to_4020[0]["type"], "jmp")

    def test_push_nop_ret_creates_jmp_edge(self):
        """push; nop; ret = jmp : cible du push même avec nops entre les deux."""
        lines = [
            {"addr": "0x401000", "text": "push\t0x401030", "line": 1},
            {"addr": "0x401005", "text": "nop", "line": 2},
            {"addr": "0x401006", "text": "ret", "line": 3},
            {"addr": "0x401030", "text": "ret", "line": 4},
        ]
        cfg = build_cfg(lines)
        jmp_to_4030 = [
            e for e in cfg["edges"] if e["from"] == "0x401000" and e["to"] == "0x401030"
        ]
        self.assertEqual(len(jmp_to_4030), 1)

    def test_preserves_line_metadata_for_cfg_views(self):
        lines = [
            {
                "addr": "0x401000",
                "text": "mov\trax, [rsp+0x18]",
                "line": 1,
                "comment": "saved value",
                "label": "entry_label",
                "function_name": "entry_main",
                "stack_hints": [
                    {"kind": "var", "name": "saved_tmp", "location": "[rsp+0x18]"}
                ],
            },
            {"addr": "0x401005", "text": "ret", "line": 2},
        ]
        cfg = build_cfg(lines)
        self.assertEqual(len(cfg["blocks"]), 1)
        block_line = cfg["blocks"][0]["lines"][0]
        self.assertEqual(block_line["comment"], "saved value")
        self.assertEqual(block_line["label"], "entry_label")
        self.assertEqual(block_line["function_name"], "entry_main")
        self.assertEqual(block_line["stack_hints"][0]["name"], "saved_tmp")

    def test_multi_arch_mips_call_and_branch_mnemonics(self):
        lines = [
            {"addr": "0x800000", "text": "27bdfff0 addiu sp, sp, -0x10", "line": 1},
            {"addr": "0x800004", "text": "0c200008 jal 0x800020", "line": 2},
            {"addr": "0x800008", "text": "11000003 beq t0, zero, 0x800018", "line": 3},
            {"addr": "0x80000c", "text": "08000008 j 0x800020", "line": 4},
            {"addr": "0x800018", "text": "00000000 nop", "line": 5},
            {"addr": "0x800020", "text": "03e00008 jr ra", "line": 6},
        ]
        cfg = build_cfg(lines)
        self.assertTrue(
            any(
                edge["type"] == "call" and edge["to"] == "0x800020"
                for edge in cfg["edges"]
            )
        )
        self.assertTrue(
            any(
                edge["type"] == "jmp" and edge["to"] == "0x800018"
                for edge in cfg["edges"]
            )
        )
        self.assertFalse(any(edge["to"] == "0x03e00008" for edge in cfg["edges"]))
        self.assertIn(cfg["support_level"], {"full", "partial"})

    def test_systemz_call_branch_and_return_mnemonics(self):
        lines = [
            {"addr": "0x1000", "text": "stmg %r14, %r15, 112(%r15)", "line": 1},
            {"addr": "0x1006", "text": "brasl %r14, 0x1020", "line": 2},
            {"addr": "0x100c", "text": "jne 0x1018", "line": 3},
            {"addr": "0x1012", "text": "j 0x1020", "line": 4},
            {"addr": "0x1018", "text": "br %r14", "line": 5},
            {"addr": "0x1020", "text": "br %r14", "line": 6},
        ]

        cfg = build_cfg(lines, arch_hint="sysz")

        self.assertTrue(
            any(
                edge["type"] == "call" and edge["to"] == "0x1020"
                for edge in cfg["edges"]
            )
        )
        self.assertTrue(
            any(
                edge["type"] == "jmp" and edge["to"] == "0x1018"
                for edge in cfg["edges"]
            )
        )
        self.assertEqual(cfg["support_level"], "partial")

    def test_arm_pop_pc_terminates_block_without_fallthrough(self):
        lines = [
            {"addr": "0x1000", "text": "push {r4, lr}", "line": 1},
            {"addr": "0x1004", "text": "pop {r4, pc}", "line": 2},
            {"addr": "0x1008", "text": "mov r0, r0", "line": 3},
        ]
        cfg = build_cfg(lines)
        block = next(b for b in cfg["blocks"] if b["addr"] == "0x1000")
        self.assertEqual(block["successors"], [])


class TestBuildCfgForFunction(unittest.TestCase):
    """Tests pour build_cfg_for_function."""

    def _make_lines(self, instructions: list[tuple]) -> list[dict]:
        """Construit une liste de lignes [{addr, text, line}, ...]."""
        return [
            {"addr": addr, "text": text, "line": i + 1}
            for i, (addr, text) in enumerate(instructions)
        ]

    def test_unknown_addr_returns_empty(self):
        """Adresse inconnue → blocs vides."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "ret"),
            ]
        )
        result = build_cfg_for_function(lines, "0x999999")
        self.assertEqual(result["blocks"], [])
        self.assertEqual(result["edges"], [])
        self.assertEqual(result["func_addr"], "0x999999")

    def test_empty_lines_returns_empty(self):
        """Lignes vides → résultat vide."""
        result = build_cfg_for_function([], "0x401000")
        self.assertEqual(result["blocks"], [])

    def test_single_block_linear(self):
        """Fonction simple sans branchement."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "mov rbp, rsp"),
                ("0x401003", "ret"),
            ]
        )
        result = build_cfg_for_function(lines, "0x401000")
        self.assertEqual(result["func_addr"], "0x401000")
        self.assertEqual(len(result["blocks"]), 1)
        self.assertEqual(result["blocks"][0]["addr"], "0x401000")

    def test_function_with_branch(self):
        """Fonction avec branchement conditionnel — 3 blocs (entry, true, false)."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "jne\t0x401010"),
                ("0x401003", "nop"),
                ("0x401004", "ret"),
                ("0x401010", "mov rax, 0"),
                ("0x401013", "ret"),
            ]
        )
        result = build_cfg_for_function(lines, "0x401000")
        addrs = {b["addr"] for b in result["blocks"]}
        self.assertIn("0x401000", addrs)
        self.assertIn("0x401010", addrs)
        self.assertGreaterEqual(len(result["blocks"]), 2)

    def test_excludes_callee_blocks(self):
        """Les blocs appelés (call) ne sont pas inclus dans le CFG de la fonction."""
        lines = self._make_lines(
            [
                # Fonction A : 0x401000
                ("0x401000", "push rbp"),
                ("0x401001", "call\t0x402000"),
                ("0x401006", "ret"),
                # Fonction B (appelée) : 0x402000
                ("0x402000", "push rbp"),
                ("0x402001", "mov rax, 1"),
                ("0x402003", "ret"),
            ]
        )
        result = build_cfg_for_function(lines, "0x401000")
        addrs = {b["addr"] for b in result["blocks"]}
        # Le bloc 0x402000 ne doit pas être inclus (c'est un callee)
        self.assertNotIn("0x402000", addrs)
        self.assertIn("0x401000", addrs)

    def test_func_addr_normalization(self):
        """L'adresse est normalisée (avec/sans 0x)."""
        lines = self._make_lines(
            [
                ("0x401000", "nop"),
                ("0x401001", "ret"),
            ]
        )
        r1 = build_cfg_for_function(lines, "0x401000")
        r2 = build_cfg_for_function(lines, "401000")
        self.assertEqual(r1["func_addr"], r2["func_addr"])
        self.assertEqual(len(r1["blocks"]), len(r2["blocks"]))


class TestSwitchHelpers(unittest.TestCase):
    """Tests des helpers de detection switch/jump-table.

    lief n'etant pas installe dans cet environnement, on teste via deux axes :
    - chemin "lief absent" : patch backends.static.disasm.cfg.lief = None → fallback
    - chemin "lief present" : on construit de vraies classes ELFBinary/section via
      type() pour que isinstance() fonctionne, et on patche lief dans cfg.
    """

    # --- helpers de construction de mocks ---

    @staticmethod
    def _make_elf_fixture(vaddr, size, executable=True):
        """Cree un triplet (lief_mod, binary, sec) compatible avec isinstance().

        On cree dynamiquement ELFBinaryClass et ELFSectionFlagClass pour que
        isinstance(binary, lief_mod.ELF.Binary) == True.
        """
        EXECINSTR = object()
        WRITE = object()

        # Classes dynamiques pour que isinstance fonctionne
        ELFBinaryClass = type("Binary", (), {})
        binary = ELFBinaryClass()

        sec = MagicMock()
        sec.virtual_address = vaddr
        sec.size = size
        sec.file_offset = 0
        sec.flags_list = [EXECINSTR] if executable else [WRITE]

        binary.sections = [sec]

        # Module lief factice
        lief_mod = MagicMock()
        lief_mod.ELF.Binary = ELFBinaryClass
        lief_mod.ELF.Section.FLAGS.EXECINSTR = EXECINSTR
        lief_mod.ELF.Section.FLAGS.WRITE = WRITE
        # PE et MachO sont des classes differentes → isinstance retournera False
        lief_mod.PE.Binary = type("PEBinary", (), {})
        lief_mod.MachO.Binary = type("MachOBinary", (), {})

        return lief_mod, binary, sec

    # --- tests _section_is_exec ---

    def test_section_is_exec_elf_executable(self):
        lief_mod, binary, sec = self._make_elf_fixture(
            0x401000, 0x1000, executable=True
        )
        with patch("backends.static.disasm.cfg.lief", lief_mod):
            self.assertTrue(_section_is_exec(sec, binary))

    def test_section_is_exec_elf_not_executable(self):
        lief_mod, binary, sec = self._make_elf_fixture(
            0x601000, 0x1000, executable=False
        )
        with patch("backends.static.disasm.cfg.lief", lief_mod):
            self.assertFalse(_section_is_exec(sec, binary))

    # --- tests _is_valid_code_addr ---

    def test_is_valid_code_addr_in_exec(self):
        lief_mod, binary, _ = self._make_elf_fixture(0x401000, 0x1000, executable=True)
        with patch("backends.static.disasm.cfg.lief", lief_mod):
            self.assertTrue(_is_valid_code_addr(0x401500, binary))

    def test_is_valid_code_addr_outside_sections(self):
        lief_mod, binary, _ = self._make_elf_fixture(0x401000, 0x1000, executable=True)
        with patch("backends.static.disasm.cfg.lief", lief_mod):
            self.assertFalse(_is_valid_code_addr(0x500000, binary))

    def test_is_valid_code_addr_in_non_exec(self):
        lief_mod, binary, _ = self._make_elf_fixture(0x601000, 0x1000, executable=False)
        with patch("backends.static.disasm.cfg.lief", lief_mod):
            self.assertFalse(_is_valid_code_addr(0x601500, binary))

    # --- tests _resolve_rip_relative_table ---

    def test_resolve_rip_relative_fallback_no_capstone(self):
        with patch("backends.static.disasm.cfg._capstone", None):
            result = _resolve_rip_relative_table(0x401000, 0x2000, object(), True)
        self.assertEqual(result, 0x401000 + 6 + 0x2000)

    def test_detect_switch_max_case_accepts_arm_immediate(self):
        lines = [
            {"addr": "0x401000", "text": "cmp w0, #0x3"},
            {"addr": "0x401004", "text": "br x11"},
        ]
        self.assertEqual(_detect_switch_max_case(lines), 4)


class TestJumpTableIntegration(unittest.TestCase):
    def test_read_jump_table_stops_at_zero(self):
        """La lecture s'arrête à la première entrée 0x0.

        Les constantes file_offset=0 et virtual_address=0x402000 fonctionnent ensemble
        car offset_in_section = table_addr - virtual_address = 0x402000 - 0x402000 = 0,
        donc la lecture commence exactement au début du fichier temporaire (offset 0).
        """
        import os
        import struct
        import tempfile

        from backends.static.disasm.cfg import _read_jump_table_entries

        addrs = [0x401000, 0x401050, 0]
        data = struct.pack("<QQQ", *addrs)

        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch("backends.static.disasm.cfg._is_valid_code_addr", return_value=True),
        ):
            mock_sec = MagicMock()
            mock_sec.virtual_address = 0x402000
            mock_sec.size = len(data) + 0x100
            mock_sec.file_offset = 0

            mock_bin = MagicMock()
            mock_bin.sections = [mock_sec]
            mock_bin.header.identity_class = "CLASS.ELF64"
            mock_lief.parse.return_value = mock_bin
            mock_lief.ELF.Binary = type(mock_bin)
            mock_lief.MachO.Binary = type(None)
            mock_lief.PE.Binary = type(None)
            mock_lief.ELF.Header.CLASS.ELF64 = "CLASS.ELF64"

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(data)
                fname = f.name
            mock_bin.name = fname

            try:
                entries = _read_jump_table_entries(fname, 0x402000)
                self.assertIn("0x401000", entries)
                self.assertIn("0x401050", entries)
                self.assertEqual(len(entries), 2)
            finally:
                os.unlink(fname)

    def test_read_relative_jump_table_entries(self):
        """Les tables relatives signées sont résolues depuis l'adresse de base."""
        import os
        import struct
        import tempfile

        rels = [0x100, 0x120, -0x20]
        data = struct.pack("<iii", *rels)

        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch("backends.static.disasm.cfg._is_valid_code_addr", return_value=True),
        ):
            mock_sec = MagicMock()
            mock_sec.virtual_address = 0x402000
            mock_sec.size = len(data) + 0x100
            mock_sec.file_offset = 0

            mock_bin = MagicMock()
            mock_bin.sections = [mock_sec]
            mock_bin.header.identity_class = "CLASS.ELF64"
            mock_lief.parse.return_value = mock_bin
            mock_lief.ELF.Binary = type(mock_bin)
            mock_lief.MachO.Binary = type(None)
            mock_lief.PE.Binary = type(None)
            mock_lief.ELF.Header.CLASS.ELF64 = "CLASS.ELF64"

            with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
                f.write(data)
                fname = f.name
            mock_bin.name = fname

            try:
                entries = _read_jump_table_entries(
                    fname,
                    0x402000,
                    max_entries=3,
                    entry_mode="relative",
                    base_addr=0x402000,
                    entry_size=4,
                    parsed_binary=mock_bin,
                )
                self.assertEqual(entries, ["0x402100", "0x402120", "0x401fe0"])
            finally:
                os.unlink(fname)

    def test_build_cfg_rip_relative_uses_resolve(self):
        """build_cfg utilise _resolve_rip_relative_table pour les offsets < 0x10000."""
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x1000]"},
        ]
        with (
            patch("backends.static.disasm.cfg._is_jump_table", return_value=True),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x1000",
            ),
            patch(
                "backends.static.disasm.cfg._resolve_rip_relative_table",
                return_value=0x403000,
            ) as mock_resolve,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401020"],
            ) as mock_read,
            patch("backends.static.disasm.cfg.lief") as mock_lief,
        ):
            mock_lief.parse.return_value = MagicMock(name="binary")
            build_cfg(lines, binary_path="/fake/binary")

        mock_resolve.assert_called_once()
        mock_read.assert_called_once()
        # Vérifier que _read_jump_table_entries a été appelé avec 0x403000 comme table_addr
        self.assertEqual(mock_read.call_args[0][1], 0x403000)

    def test_build_cfg_rip_relative_fallback_no_lief(self):
        """Sans lief, build_cfg tombe en fallback addr+6+offset."""
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x1000]"},
        ]
        with (
            patch("backends.static.disasm.cfg._is_jump_table", return_value=True),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x1000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010"],
            ),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path="/fake/binary")

        # Pas de crash, le CFG est construit
        self.assertIn("blocks", result)

    def test_build_cfg_register_switch_pattern_uses_relative_jump_table(self):
        """Détecte un switch PIC classique via lea + movsxd + add + jmp reg."""
        lines = [
            {"addr": "0x401000", "text": "lea rdx, [rip+0x2000]"},
            {"addr": "0x401007", "text": "movsxd rax, dword ptr [rdx+rax*4]"},
            {"addr": "0x40100b", "text": "add rax, rdx"},
            {"addr": "0x40100e", "text": "jmp rax"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._resolve_table_addr_from_lea",
                return_value=0x403000,
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401100", "0x401120"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/binary")

        self.assertEqual(len(result["blocks"]), 1)
        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(
            block.get("switch_cases"),
            [
                {"case": 0, "target": "0x401100"},
                {"case": 1, "target": "0x401120"},
            ],
        )
        mock_read.assert_called_once()
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/binary", 0x403000))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "relative")
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 4)
        jt_edges = [e for e in result["edges"] if e["type"] == "jumptable"]
        self.assertEqual([e["case_label"] for e in jt_edges], [0, 1])

    def test_build_cfg_arm64_absolute_switch_pattern_uses_absolute_jump_table(self):
        """Détecte un switch ARM64 absolu via adrp/add + ldr + br."""
        lines = [
            {"addr": "0x401000", "text": "cmp w0, #0x1"},
            {"addr": "0x401004", "text": "adrp x10, 0x403000"},
            {"addr": "0x401008", "text": "add x10, x10, #0x40"},
            {"addr": "0x40100c", "text": "ldr x11, [x10, x0, lsl #3]"},
            {"addr": "0x401010", "text": "br x11"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401100", "0x401180"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/binary")

        self.assertEqual(len(result["blocks"]), 1)
        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(
            block.get("switch_cases"),
            [
                {"case": 0, "target": "0x401100"},
                {"case": 1, "target": "0x401180"},
            ],
        )
        mock_read.assert_called_once()
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/binary", 0x403040))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "absolute")
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 8)
        jt_edges = [e for e in result["edges"] if e["type"] == "jumptable"]
        self.assertEqual([e["case_label"] for e in jt_edges], [0, 1])

    def test_build_cfg_arm64_relative_switch_pattern_uses_relative_jump_table(self):
        """Détecte un switch ARM64 relatif via ldrsw + add + br."""
        lines = [
            {"addr": "0x401000", "text": "cmp w0, #0x1"},
            {"addr": "0x401004", "text": "adrp x10, 0x403000"},
            {"addr": "0x401008", "text": "add x10, x10, #0x40"},
            {"addr": "0x40100c", "text": "ldrsw x11, [x10, w0, uxtw #2]"},
            {"addr": "0x401010", "text": "add x11, x11, x10"},
            {"addr": "0x401014", "text": "br x11"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401220", "0x401260"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/binary")

        self.assertEqual(len(result["blocks"]), 1)
        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(
            block.get("switch_cases"),
            [
                {"case": 0, "target": "0x401220"},
                {"case": 1, "target": "0x401260"},
            ],
        )
        mock_read.assert_called_once()
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/binary", 0x403040))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "relative")
        self.assertEqual(mock_read.call_args.kwargs.get("base_addr"), 0x403040)
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 4)
        jt_edges = [e for e in result["edges"] if e["type"] == "jumptable"]
        self.assertEqual([e["case_label"] for e in jt_edges], [0, 1])

    def test_build_cfg_mips_absolute_switch_pattern_uses_absolute_jump_table(self):
        """Détecte un switch MIPS absolu via lui/addiu + lw + jr."""
        lines = [
            {"addr": "0x800000", "text": "lui t1, 0x40"},
            {"addr": "0x800004", "text": "addiu t1, t1, 0x3000"},
            {"addr": "0x800008", "text": "sll t0, t0, 2"},
            {"addr": "0x80000c", "text": "addu t1, t1, t0"},
            {"addr": "0x800010", "text": "lw t9, 0(t1)"},
            {"addr": "0x800014", "text": "jr t9"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x800100", "0x800140"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/mips.bin", arch_hint="mips")

        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(block.get("successors"), ["0x800100", "0x800140"])
        self.assertFalse(any(edge["type"] == "fallthrough" for edge in result["edges"]))
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/mips.bin", 0x403000))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "absolute")
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 4)

    def test_build_cfg_riscv_relative_switch_pattern_uses_relative_jump_table(self):
        """Détecte un switch RISC-V relatif via add + jalr sans fallthrough."""
        lines = [
            {"addr": "0x401000", "text": "lui a1, 0x403"},
            {"addr": "0x401004", "text": "addi a1, a1, 0x40"},
            {"addr": "0x401008", "text": "slli a0, a0, 2"},
            {"addr": "0x40100c", "text": "add a1, a1, a0"},
            {"addr": "0x401010", "text": "lw t0, 0(a1)"},
            {"addr": "0x401014", "text": "add t0, t0, a1"},
            {"addr": "0x401018", "text": "jalr zero, t0, 0"},
            {"addr": "0x40101c", "text": "addi a0, a0, 1"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401100", "0x401180"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/riscv.bin", arch_hint="riscv")

        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(block.get("successors"), ["0x401100", "0x401180"])
        self.assertFalse(any(edge["type"] == "fallthrough" for edge in result["edges"]))
        self.assertFalse(result["blocks"][1].get("is_switch"))
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/riscv.bin", 0x403040))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "relative")
        self.assertEqual(mock_read.call_args.kwargs.get("base_addr"), 0x403040)
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 4)

    def test_build_cfg_ppc_absolute_switch_pattern_uses_absolute_jump_table(self):
        """Détecte un switch PPC absolu via lis/addi + lwzx + mtctr/bctr."""
        lines = [
            {"addr": "0x1000", "text": "lis r11, 0x40"},
            {"addr": "0x1004", "text": "addi r11, r11, 0x3000"},
            {"addr": "0x1008", "text": "slwi r3, r3, 2"},
            {"addr": "0x100c", "text": "lwzx r12, r11, r3"},
            {"addr": "0x1010", "text": "mtctr r12"},
            {"addr": "0x1014", "text": "bctr"},
            {"addr": "0x1018", "text": "addi r3, r3, 1"},
        ]
        fake_binary = MagicMock(name="binary")
        with (
            patch("backends.static.disasm.cfg.lief") as mock_lief,
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x1100", "0x1180"],
            ) as mock_read,
        ):
            mock_lief.parse.return_value = fake_binary
            result = build_cfg(lines, binary_path="/fake/ppc.bin", arch_hint="ppc")

        block = result["blocks"][0]
        self.assertTrue(block.get("is_switch"))
        self.assertEqual(block.get("successors"), ["0x1100", "0x1180"])
        self.assertFalse(any(edge["type"] == "fallthrough" for edge in result["edges"]))
        self.assertEqual(mock_read.call_args.args[:2], ("/fake/ppc.bin", 0x403000))
        self.assertEqual(mock_read.call_args.kwargs.get("entry_mode"), "absolute")
        self.assertEqual(mock_read.call_args.kwargs.get("entry_size"), 4)


class TestFindFunctionEntryForAddr(unittest.TestCase):
    """Tests pour find_function_entry_for_addr (reverse BFS sur le CFG complet)."""

    def _make_lines(self, instructions: list[tuple]) -> list[dict]:
        return [
            {"addr": addr, "text": text, "line": i + 1}
            for i, (addr, text) in enumerate(instructions)
        ]

    def test_returns_none_for_unknown_addr(self):
        """Adresse absente du CFG → None."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "ret"),
            ]
        )
        self.assertIsNone(find_function_entry_for_addr(lines, "0x999999"))

    def test_returns_none_for_empty_lines(self):
        """Mapping vide → None."""
        self.assertIsNone(find_function_entry_for_addr([], "0x401000"))

    def test_entry_block_addr_returns_itself(self):
        """Addr = début du seul bloc → retourne cette même adresse."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "mov rbp, rsp"),
                ("0x401003", "ret"),
            ]
        )
        result = find_function_entry_for_addr(lines, "0x401000")
        self.assertEqual(result, "0x401000")

    def test_finds_entry_from_inner_instruction(self):
        """Addr = instruction à l'intérieur d'un bloc → retourne l'entrée de la fonction."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "mov rbp, rsp"),  # addr inside the entry block
                ("0x401003", "ret"),
            ]
        )
        result = find_function_entry_for_addr(lines, "0x401001")
        self.assertEqual(result, "0x401000")

    def test_finds_entry_from_non_entry_block(self):
        """Addr dans un bloc non-entry → remonte via reverse BFS jusqu'à l'entrée."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "jne\t0x401010"),
                ("0x401003", "nop"),
                ("0x401004", "ret"),
                ("0x401010", "mov rax, 0"),  # non-entry block
                ("0x401013", "ret"),
            ]
        )
        result = find_function_entry_for_addr(lines, "0x401010")
        self.assertEqual(result, "0x401000")

    def test_does_not_cross_call_edges(self):
        """Deux fonctions séparées par un call — reverse BFS ne traverse pas les call edges."""
        lines = self._make_lines(
            [
                ("0x401000", "push rbp"),
                ("0x401001", "call\t0x401020"),
                ("0x401006", "ret"),
                ("0x401020", "push rbp"),  # start of second function
                ("0x401021", "xor eax, eax"),
                ("0x401023", "ret"),
            ]
        )
        # Addr inside the callee must resolve to callee's entry, not caller's
        result = find_function_entry_for_addr(lines, "0x401021")
        self.assertEqual(result, "0x401020")

    def test_finds_entry_from_branch_target(self):
        """Addr = bloc cible d'un saut conditionnel → remonte au bloc source."""
        lines = self._make_lines(
            [
                ("0x401000", "test eax, eax"),
                ("0x401002", "jne\t0x40100a"),
                ("0x401004", "xor eax, eax"),
                ("0x401006", "ret"),
                ("0x40100a", "mov eax, 1"),  # branch target block
                ("0x40100f", "ret"),
            ]
        )
        result = find_function_entry_for_addr(lines, "0x40100a")
        self.assertEqual(result, "0x401000")


class TestCfgSwitchSerialization(unittest.TestCase):
    def test_switch_block_has_is_switch_and_switch_cases(self):
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x602000]"},
        ]
        with (
            patch("backends.static.disasm.cfg._is_jump_table", return_value=True),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x602000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401020", "0x401030"],
            ),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path=None)

        blks = {b["addr"]: b for b in result["blocks"]}
        blk_key = None
        for k in blks:
            if k in ("0x401000", "401000"):
                blk_key = k
                break
        self.assertIsNotNone(blk_key, "Bloc 0x401000 introuvable")
        assert blk_key is not None  # narrowing explicite pour Pyright
        blk = blks[blk_key]
        self.assertTrue(blk.get("is_switch"), "is_switch manquant ou False")
        cases = blk.get("switch_cases", [])
        self.assertGreater(len(cases), 0, "switch_cases vide")
        targets = [c["target"] for c in cases]
        self.assertIn("0x401010", targets)

    def test_jumptable_edges_have_case_label(self):
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x602000]"},
        ]
        with (
            patch(
                "backends.static.disasm.cfg._is_jump_table",
                side_effect=lambda text: "jmp" in text.lower(),
            ),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x602000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401020"],
            ),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path=None)

        jt_edges = [e for e in result["edges"] if e["type"] == "jumptable"]
        self.assertGreater(len(jt_edges), 0, "Aucun arc jumptable généré")
        for e in jt_edges:
            self.assertIn("case_label", e, f"case_label manquant sur {e}")
            self.assertIsNotNone(e["case_label"])
        # Vérifier que les labels sont 0 et 1 (index des 2 entrées)
        labels = sorted(
            e["case_label"] for e in jt_edges if isinstance(e.get("case_label"), int)
        )
        self.assertEqual(labels, [0, 1])

    def test_switch_target_blocks_receive_incoming_case_labels(self):
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x1"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x602000]"},
            {"addr": "0x401010", "text": "mov eax, 0x1"},
            {"addr": "0x401015", "text": "ret"},
            {"addr": "0x401020", "text": "mov eax, 0x2"},
            {"addr": "0x401025", "text": "ret"},
        ]
        with (
            patch(
                "backends.static.disasm.cfg._is_jump_table",
                side_effect=lambda text: "jmp" in text.lower(),
            ),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x602000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401020"],
            ),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path=None)

        blocks = {b["addr"]: b for b in result["blocks"]}
        self.assertEqual(blocks["0x401010"].get("incoming_case_labels"), [0])
        self.assertEqual(blocks["0x401020"].get("incoming_case_labels"), [1])
        self.assertEqual(
            blocks["0x401010"].get("incoming_switch_cases"),
            [{"from": "0x401000", "case": 0}],
        )

    def test_switch_target_block_merges_multiple_case_labels(self):
        from backends.static.disasm.cfg import build_cfg

        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x602000]"},
            {"addr": "0x401010", "text": "nop"},
            {"addr": "0x401011", "text": "ret"},
            {"addr": "0x401020", "text": "nop"},
            {"addr": "0x401021", "text": "ret"},
        ]
        with (
            patch(
                "backends.static.disasm.cfg._is_jump_table",
                side_effect=lambda text: "jmp" in text.lower(),
            ),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x602000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401010", "0x401020"],
            ),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path=None)

        blocks = {b["addr"]: b for b in result["blocks"]}
        self.assertEqual(blocks["0x401010"].get("incoming_case_labels"), [0, 1])
        self.assertEqual(
            blocks["0x401010"].get("incoming_switch_cases"),
            [
                {"from": "0x401000", "case": 0},
                {"from": "0x401000", "case": 1},
            ],
        )
        source_edges = [
            edge
            for edge in result["edges"]
            if edge["from"] == "0x401000" and edge["type"] == "jumptable"
        ]
        self.assertEqual(len(source_edges), 2)
        first_edge = next(edge for edge in source_edges if edge["to"] == "0x401010")
        second_edge = next(edge for edge in source_edges if edge["to"] == "0x401020")
        self.assertEqual(first_edge.get("case_label"), 0)
        self.assertEqual(first_edge.get("case_labels"), [0, 1])
        self.assertEqual(second_edge.get("case_label"), 2)

    def test_unresolved_default_flagged_when_no_successor(self):
        """Un default orphelin sans successeur correspondant garde unresolved_default=True."""
        from backends.static.disasm.cfg import build_cfg

        # cmp eax, 0x2 → max_cases=3 ; jump table has 2 entries ; no 3rd successor
        lines = [
            {"addr": "0x401000", "text": "cmp eax, 0x2"},
            {"addr": "0x401003", "text": "jmp qword ptr [rax*8+0x602000]"},
            {"addr": "0x401010", "text": "nop"},
            {"addr": "0x401011", "text": "ret"},
            {"addr": "0x401020", "text": "nop"},
            {"addr": "0x401021", "text": "ret"},
        ]
        with (
            patch(
                "backends.static.disasm.cfg._is_jump_table",
                side_effect=lambda text: "jmp" in text.lower(),
            ),
            patch(
                "backends.static.disasm.cfg._extract_jump_table_base",
                return_value="0x602000",
            ),
            patch(
                "backends.static.disasm.cfg._read_jump_table_entries",
                return_value=["0x401010", "0x401020"],
            ),
            patch("backends.static.disasm.cfg._detect_switch_max_case", return_value=3),
            patch("backends.static.disasm.cfg.lief", None),
        ):
            result = build_cfg(lines, binary_path=None)

        blocks = {b["addr"]: b for b in result["blocks"]}
        self.assertIn("0x401000", blocks)
        switch_block = blocks["0x401000"]
        self.assertTrue(
            switch_block.get("unresolved_default"),
            "Le bloc doit être marqué unresolved_default quand default target=None reste",
        )

    def test_large_jump_table_fallback_is_256(self):
        """Sans cmp détecté, le fallback max_entries est 256 (non plus 64)."""
        import inspect

        import backends.static.disasm.cfg as cfg_mod

        # _detect_switch_max_case returns None when no cmp is found
        block_lines = [{"addr": "0x401000", "text": "jmp qword ptr [rax*8+0x602000]"}]
        result = _detect_switch_max_case(block_lines)
        self.assertIsNone(
            result, "Sans cmp, _detect_switch_max_case doit retourner None"
        )
        # Verify the fallback 256 is present in _resolve_register_jump_table
        src_resolve = inspect.getsource(cfg_mod._resolve_register_jump_table)
        self.assertIn(
            "or 256",
            src_resolve,
            "Le fallback max_entries doit être 256 dans _resolve_register_jump_table",
        )
        # Verify build_cfg also uses 256 for its inline _read_jump_table_entries call
        src_build = inspect.getsource(cfg_mod.build_cfg)
        self.assertIn(
            "or 256", src_build, "Le fallback max_entries doit être 256 dans build_cfg"
        )


if __name__ == "__main__":
    unittest.main()
