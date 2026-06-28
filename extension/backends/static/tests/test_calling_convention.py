# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)
from backends.static.binary.arch import get_raw_arch_info
from backends.static.disasm.calling_convention import (
    _analyze_function,
    _known_abi_convention,
)
from backends.static.tests.util import compile_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False

try:
    import capstone as _capstone

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


def run_cc(binary, addrs=None):
    args = [
        sys.executable,
        "backends/static/disasm/calling_convention.py",
        "--binary",
        binary,
    ]
    if addrs:
        args += ["--addrs", ",".join(addrs)]
    env = {**os.environ, "PYTHONPATH": ROOT}
    r = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, env=env)
    return json.loads(r.stdout)


import unittest


class TestCallingConvention(unittest.TestCase):
    def test_output_shape(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            result = run_cc(str(binary))
            self.assertIn("arch", result)
            self.assertIn("conventions", result)
            self.assertIsInstance(result["conventions"], dict)

    def test_each_entry_has_convention_and_confidence(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            result = run_cc(str(binary))
            for _addr, info in result["conventions"].items():
                self.assertIn("convention", info)
                self.assertIn("confidence", info)
                self.assertIsInstance(info["confidence"], float)

    def test_invalid_binary_returns_error(self):
        result = run_cc("/nonexistent/binary")
        self.assertIn("error", result)

    def test_empty_addrs_returns_all_functions(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            result = run_cc(str(binary))
            self.assertGreater(len(result["conventions"]), 0)

    @unittest.skipUnless(_CAPSTONE_AVAILABLE, "capstone not installed")
    def test_known_multi_arch_abi_conventions(self):
        cases = {
            "mips32": ("MIPS o32", ("a0", "a1", "a2", "a3")),
            "mips64": ("MIPS n64", ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7")),
            "ppc32": (
                "PowerPC SysV",
                ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
            ),
            "ppc64": (
                "PowerPC ELFv2",
                ("r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10"),
            ),
            "sparc": ("SPARC ABI", ("o0", "o1", "o2", "o3", "o4", "o5")),
            "riscv64": (
                "RISC-V psABI",
                ("a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"),
            ),
            "sysz": ("System V s390x", ("r2", "r3", "r4", "r5", "r6")),
        }
        for raw_arch, (expected_name, expected_regs) in cases.items():
            with self.subTest(raw_arch=raw_arch):
                info = get_raw_arch_info(raw_arch)
                self.assertIsNotNone(info)
                convention, confidence = _known_abi_convention(info)
                self.assertEqual(convention, expected_name)
                self.assertGreater(confidence, 0.0)
                self.assertEqual(info.arg_registers, expected_regs)

    @unittest.skipUnless(_CAPSTONE_AVAILABLE, "capstone not installed")
    def test_multi_arch_abi_survives_missing_function_bytes(self):
        info = get_raw_arch_info("riscv64")
        self.assertIsNotNone(info)

        class EmptyBinary:
            def get_content_from_virtual_address(self, addr, size):
                return None

        result = _analyze_function(EmptyBinary(), object(), info, 0x1000)

        self.assertEqual(result["convention"], "RISC-V psABI")
        self.assertEqual(result["source"], "abi")
        self.assertEqual(
            result["arg_registers"], ["a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7"]
        )

    def test_x86_still_requires_instruction_bytes_for_heuristic(self):
        info = get_raw_arch_info("i386:x86-64")
        self.assertIsNotNone(info)

        class EmptyBinary:
            def get_content_from_virtual_address(self, addr, size):
                return None

        result = _analyze_function(EmptyBinary(), object(), info, 0x1000)

        self.assertIsNone(result["convention"])
        self.assertEqual(result["source"], "heuristic")


if __name__ == "__main__":
    unittest.main()
