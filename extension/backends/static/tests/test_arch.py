# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour la couche centralisee backends.static.binary.arch."""

from __future__ import annotations

import sys
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary import arch as arch_module

try:
    import capstone as _capstone

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


class TestRawArchInfo(unittest.TestCase):
    def test_raw_alias_x86_64(self):
        info = arch_module.get_raw_arch_info("amd64")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "x86_64")
        self.assertEqual(info.raw_name, "i386:x86-64")
        self.assertEqual(info.ptr_size, 8)
        self.assertEqual(info.abi, "sysv64")

    def test_raw_alias_arm64(self):
        info = arch_module.get_raw_arch_info("arm64")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "arm64")
        self.assertEqual(info.raw_name, "aarch64")
        self.assertEqual(info.ptr_size, 8)
        self.assertEqual(info.abi, "aapcs64")

    def test_raw_arm_big_endian_is_preserved(self):
        info = arch_module.get_raw_arch_info("arm", "big")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "arm32")
        self.assertEqual(info.adapter.key, "arm32")
        self.assertEqual(info.endian, "big")

    def test_raw_thumb_profile_is_preserved(self):
        info = arch_module.get_raw_arch_info("thumb", "little")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "arm32")
        self.assertEqual(info.raw_name, "thumb")
        self.assertEqual(info.machine, "thumb")
        self.assertEqual(info.ptr_size, 4)
        self.assertEqual(info.endian, "little")

    def test_raw_x86_forces_little_endian(self):
        info = arch_module.get_raw_arch_info("i386:x86-64", "big")
        self.assertIsNotNone(info)
        self.assertEqual(info.key, "x86_64")
        self.assertEqual(info.endian, "little")

    @unittest.skipUnless(_CAPSTONE_AVAILABLE, "capstone not installed")
    def test_raw_capstone_architecture_aliases(self):
        cases = {
            "mips64": ("mips64", 8),
            "ppc": ("ppc32", 4),
            "sparc64": ("sparcv9", 8),
            "sysz": ("sysz", 8),
            "s390x": ("sysz", 8),
            "m68k": ("m68k", 4),
            "wasm": ("wasm", 4),
            "bpf": ("bpf", 8),
            "riscv32": ("riscv32", 4),
            "tricore": ("tricore", 4),
        }
        for raw_arch, (expected_key, expected_ptr_size) in cases.items():
            with self.subTest(raw_arch=raw_arch):
                info = arch_module.get_raw_arch_info(raw_arch)
                self.assertIsNotNone(info)
                self.assertEqual(info.key, expected_key)
                self.assertEqual(info.ptr_size, expected_ptr_size)
                self.assertIsNotNone(info.capstone_tuple)


class TestArchAdapters(unittest.TestCase):
    def test_x86_adapter_classifies_branches_and_prologue(self):
        adapter = arch_module.X86_ADAPTER
        self.assertEqual(adapter.classify_code_ref_mnemonic("call"), "call")
        self.assertEqual(adapter.classify_code_ref_mnemonic("jne"), "jcc")
        self.assertEqual(adapter.classify_code_ref_mnemonic("jmp"), "jmp")
        self.assertEqual(adapter.classify_code_ref_mnemonic("ret"), "ret")
        self.assertEqual(adapter.matches_prologue("55 push rbp"), "push rbp")

    def test_arm64_adapter_classifies_branches_and_prologue(self):
        adapter = arch_module.ARM64_ADAPTER
        self.assertEqual(adapter.classify_code_ref_mnemonic("bl"), "call")
        self.assertEqual(adapter.classify_code_ref_mnemonic("cbz"), "jcc")
        self.assertEqual(adapter.classify_code_ref_mnemonic("br"), "jmp")
        self.assertEqual(adapter.classify_code_ref_mnemonic("ret"), "ret")
        self.assertEqual(
            adapter.matches_prologue("a9bf7bfd stp x29, x30, [sp, #-16]!"),
            "stp",
        )

    def test_extended_adapters_classify_common_control_flow(self):
        cases = [
            (arch_module.MIPS_ADAPTER, "jal", "beq", "j", "eret"),
            (arch_module.PPC_ADAPTER, "bl", "bne", "b", "blr"),
            (arch_module.SPARC_ADAPTER, "call", "be", "ba", "retl"),
            (arch_module.RISCV_ADAPTER, "jal", "bne", "j", "ret"),
            (arch_module.BPF_ADAPTER, "call", "jeq", "ja", "exit"),
            (arch_module.WASM_ADAPTER, "call", "br_if", "br", "return"),
            (arch_module.M68K_ADAPTER, "jsr", "bne", "bra", "rts"),
            (arch_module.SH_ADAPTER, "bsr", "bt", "bra", "rts"),
            (arch_module.TRICORE_ADAPTER, "call", "jne", "j", "ret"),
        ]
        for adapter, call, jcc, jmp, ret in cases:
            with self.subTest(adapter=adapter.key):
                self.assertEqual(adapter.classify_code_ref_mnemonic(call), "call")
                self.assertEqual(adapter.classify_code_ref_mnemonic(jcc), "jcc")
                self.assertEqual(adapter.classify_code_ref_mnemonic(jmp), "jmp")
                self.assertEqual(adapter.classify_code_ref_mnemonic(ret), "ret")
        self.assertEqual(
            arch_module.SYSZ_ADAPTER.classify_code_ref_mnemonic("brasl"), "call"
        )
        self.assertEqual(
            arch_module.SYSZ_ADAPTER.classify_code_ref_mnemonic("jne"), "jcc"
        )
        self.assertEqual(
            arch_module.SYSZ_ADAPTER.classify_code_ref_mnemonic("j"), "jmp"
        )

    def test_extended_adapters_recognize_operand_based_returns(self):
        self.assertTrue(arch_module.ARM32_ADAPTER.is_return_instruction("bx", "lr"))
        self.assertTrue(
            arch_module.ARM32_ADAPTER.is_return_instruction("pop", "{r4, pc}")
        )
        self.assertTrue(
            arch_module.ARM32_ADAPTER.is_return_instruction("ldmia", "sp!, {r4, pc}")
        )
        self.assertTrue(arch_module.MIPS_ADAPTER.is_return_instruction("jr", "$ra"))
        self.assertFalse(arch_module.MIPS_ADAPTER.is_return_instruction("jr", "$t9"))
        self.assertTrue(arch_module.SYSZ_ADAPTER.is_return_instruction("br", "%r14"))
        self.assertFalse(arch_module.SYSZ_ADAPTER.is_return_instruction("br", "%r1"))

    def test_extended_prologue_patterns_accept_hex_immediates(self):
        cases = [
            (arch_module.MIPS_ADAPTER, "27bdfff0 addiu sp, sp, -0x10", "addiu sp"),
            (arch_module.PPC_ADAPTER, "stwu r1, -0x20(r1)", "stwu r1"),
            (arch_module.RISCV_ADAPTER, "addi sp, sp, -0x20", "addi sp"),
        ]
        for adapter, text, expected in cases:
            with self.subTest(adapter=adapter.key):
                self.assertEqual(adapter.matches_prologue(text), expected)

    def test_feature_support_matrix_exposes_levels(self):
        matrix = arch_module.get_feature_support_matrix()
        self.assertEqual(matrix["x86"]["cfg"]["level"], "full")
        self.assertEqual(matrix["arm64"]["stack_frame"]["level"], "full")
        self.assertEqual(matrix["mips"]["cfg"]["level"], "partial")
        self.assertEqual(matrix["sysz"]["cfg"]["level"], "partial")
        self.assertEqual(matrix["wasm"]["stack_frame"]["level"], "partial")
        self.assertEqual(matrix["mips"]["calling_convention"]["level"], "partial")
        self.assertNotIn("taint", matrix["riscv"])
        self.assertNotIn("string_deobfuscate", matrix["sparc"])
        self.assertNotIn("generic", matrix)

    def test_generic_raw_adapters_do_not_claim_semantic_cfg(self):
        adapter = arch_module._generic_adapter("xcore", "XCore")

        self.assertEqual(adapter.support_for("disasm").level, "disasm-only")
        self.assertEqual(adapter.support_for("cfg").level, "unsupported")
        self.assertEqual(adapter.support_for("call_graph").level, "unsupported")


class TestDetectBinaryArch(unittest.TestCase):
    def _fake_capstone(self):
        return types.SimpleNamespace(
            CS_ARCH_X86=1,
            CS_ARCH_ARM=2,
            CS_ARCH_ARM64=3,
            CS_ARCH_BPF=4,
            CS_MODE_32=32,
            CS_MODE_64=64,
            CS_MODE_ARM=128,
            CS_MODE_BPF_EXTENDED=256,
            CS_MODE_LITTLE_ENDIAN=0,
        )

    def _fake_lief(self):
        ELFBinary = type("ELFBinary", (), {})
        PEBinary = type("PEBinary", (), {})
        MachOBinary = type("MachOBinary", (), {})
        return types.SimpleNamespace(
            ELF=types.SimpleNamespace(
                Binary=ELFBinary,
                ARCH=types.SimpleNamespace(
                    X86_64="ELF_X86_64",
                    X86="ELF_X86",
                    I386="ELF_I386",
                    AARCH64="ELF_AARCH64",
                    ARM="ELF_ARM",
                    BPF="ELF_BPF",
                ),
            ),
            PE=types.SimpleNamespace(
                Binary=PEBinary,
                Header=types.SimpleNamespace(
                    MACHINE_TYPES=types.SimpleNamespace(
                        AMD64="PE_AMD64",
                        I386="PE_I386",
                        ARM64="PE_ARM64",
                        ARM="PE_ARM",
                    )
                ),
            ),
            MachO=types.SimpleNamespace(Binary=MachOBinary),
        )

    def test_detect_binary_arch_elf_sysv64(self):
        fake_lief = self._fake_lief()
        fake_capstone = self._fake_capstone()
        binary = fake_lief.ELF.Binary()
        binary.header = types.SimpleNamespace(machine_type=fake_lief.ELF.ARCH.X86_64)

        with (
            mock.patch.object(arch_module, "lief", fake_lief),
            mock.patch.object(arch_module, "capstone", fake_capstone),
        ):
            info = arch_module.detect_binary_arch(binary)

        self.assertIsNotNone(info)
        self.assertEqual(info.key, "x86_64")
        self.assertEqual(info.abi, "sysv64")
        self.assertEqual(info.raw_name, "i386:x86-64")

    def test_detect_binary_arch_pe_win64(self):
        fake_lief = self._fake_lief()
        fake_capstone = self._fake_capstone()
        binary = fake_lief.PE.Binary()
        binary.header = types.SimpleNamespace(
            machine=fake_lief.PE.Header.MACHINE_TYPES.AMD64
        )

        with (
            mock.patch.object(arch_module, "lief", fake_lief),
            mock.patch.object(arch_module, "capstone", fake_capstone),
        ):
            info = arch_module.detect_binary_arch(binary)

        self.assertIsNotNone(info)
        self.assertEqual(info.key, "x86_64")
        self.assertEqual(info.abi, "win64")
        self.assertEqual(info.ptr_size, 8)

    def test_detect_binary_arch_elf_capstone_fallback(self):
        fake_lief = self._fake_lief()
        fake_capstone = self._fake_capstone()
        binary = fake_lief.ELF.Binary()
        binary.header = types.SimpleNamespace(machine_type=fake_lief.ELF.ARCH.BPF)

        with (
            mock.patch.object(arch_module, "lief", fake_lief),
            mock.patch.object(arch_module, "capstone", fake_capstone),
        ):
            info = arch_module.detect_binary_arch(binary)

        self.assertIsNotNone(info)
        self.assertEqual(info.key, "bpf")
        self.assertEqual(info.raw_name, "BPF")
        self.assertEqual(info.format_kind, "elf")


if __name__ == "__main__":
    unittest.main()
