# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.stack_frame."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm import stack_frame as stack_frame_module


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def run(args):
    r = subprocess.run(
        [sys.executable, "backends/static/disasm/stack_frame.py"] + args,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(f"stack_frame.py failed:\n{r.stderr}")
    return json.loads(r.stdout)


def _lief_available() -> bool:
    try:
        import lief  # noqa: F401

        return True
    except ImportError:
        return False


def _capstone_available() -> bool:
    try:
        import capstone  # noqa: F401

        return True
    except ImportError:
        return False


@unittest.skipUnless(
    _lief_available() and _capstone_available(), "lief et capstone requis"
)
class TestStackFrame(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = str(Path(self.tmp) / "test.elf")
        make_minimal_elf(self.binary)

    def test_output_schema(self):
        """Output must have func_addr, frame_size, vars, args keys."""
        data = run(["--binary", self.binary, "--addr", "0x0"])
        self.assertIn("func_addr", data)
        self.assertIn("frame_size", data)
        self.assertIn("vars", data)
        self.assertIn("args", data)
        self.assertIn("abi", data)
        self.assertIsInstance(data["vars"], list)
        self.assertIsInstance(data["args"], list)

    def test_var_schema(self):
        """Each var must have name, offset, size, source."""
        data = run(["--binary", self.binary, "--addr", "0x0"])
        for v in data["vars"]:
            self.assertIn("name", v)
            self.assertIn("offset", v)
            self.assertIn("size", v)
            self.assertIn("source", v)
            self.assertIn(v["source"], ("auto", "dwarf"))

    def test_binary_not_found(self):
        """Missing binary exits non-zero."""
        r = subprocess.run(
            [
                sys.executable,
                "backends/static/stack_frame.py",
                "--binary",
                "/nonexistent/binary",
                "--addr",
                "0x0",
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            env={**os.environ, "PYTHONPATH": str(ROOT)},
        )
        self.assertNotEqual(r.returncode, 0)

    def test_auto_naming_negative_offset(self):
        """Negative rbp offsets produce var_N names."""
        data = run(["--binary", self.binary, "--addr", "0x0"])
        for v in data["vars"]:
            if v["offset"] < 0 and v["source"] == "auto":
                self.assertTrue(v["name"].startswith("var_"), v)

    def test_auto_naming_positive_offset(self):
        """Positive rbp offsets >= 0x10 produce arg_N names."""
        data = run(["--binary", self.binary, "--addr", "0x0"])
        for v in data["args"]:
            if v["source"] == "auto":
                self.assertTrue(v["name"].startswith("arg_"), v)

    def test_cached_stack_frame_is_returned_first(self):
        cached = {
            "version": stack_frame_module.STACK_FRAME_CACHE_VERSION,
            "func_addr": "0x1234",
            "frame_size": 48,
            "abi": "win64",
            "vars": [{"name": "cached_var", "offset": -8, "size": 8, "source": "auto"}],
            "args": [],
        }
        with DisasmCache(default_cache_path(self.binary)) as cache:
            cache.save_stack_frame(self.binary, cached)

        with (
            mock.patch.object(stack_frame_module, "lief", None),
            mock.patch.object(stack_frame_module, "capstone", None),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x1234)

        self.assertEqual(data, cached)

    def test_rsp_based_locals_and_stack_args_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("push", "rbx"),
            FakeInstr("sub", "rsp, 0x20"),
            FakeInstr("mov", "qword ptr [rsp + 0x18], rax"),
            FakeInstr("mov", "qword ptr [rsp + 0x30], rcx"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "sysv64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 32, 0x401000),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401000)

        self.assertEqual(data["frame_size"], 40)
        self.assertTrue(
            any(
                v["location"] == "[rsp+0x18]" and v["offset"] == -16
                for v in data["vars"]
            )
        )
        self.assertTrue(
            any(
                a["location"] == "[rsp+0x30]" and a["offset"] == 16
                for a in data["args"]
            )
        )

    def test_x86_stack_realignment_keeps_rsp_locals_usable(self):
        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            SimpleNamespace(mnemonic="push", op_str="rbp"),
            SimpleNamespace(mnemonic="mov", op_str="rbp, rsp"),
            SimpleNamespace(mnemonic="sub", op_str="rsp, 0x28"),
            SimpleNamespace(mnemonic="and", op_str="rsp, -0x10"),
            SimpleNamespace(mnemonic="mov", op_str="qword ptr [rsp + 0x10], rax"),
            SimpleNamespace(mnemonic="ret", op_str=""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "sysv64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 40, 0x401040),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401040)

        self.assertEqual(data["frame_size"], 48)
        self.assertTrue(
            any(
                v["location"] == "[rsp+0x10]" and v["offset"] == -32
                for v in data["vars"]
            )
        )

    def test_x86_dynamic_alloca_suppresses_ambiguous_rsp_accesses(self):
        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            SimpleNamespace(mnemonic="push", op_str="rbp"),
            SimpleNamespace(mnemonic="mov", op_str="rbp, rsp"),
            SimpleNamespace(mnemonic="sub", op_str="rsp, 0x20"),
            SimpleNamespace(mnemonic="sub", op_str="rsp, rax"),
            SimpleNamespace(mnemonic="mov", op_str="qword ptr [rsp + 0x18], rcx"),
            SimpleNamespace(mnemonic="mov", op_str="qword ptr [rbp - 0x8], rdx"),
            SimpleNamespace(mnemonic="ret", op_str=""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "sysv64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 48, 0x401060),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401060)

        self.assertFalse(any(v["location"] == "[rsp+0x18]" for v in data["vars"]))
        self.assertFalse(any(a["location"] == "[rsp+0x18]" for a in data["args"]))
        self.assertTrue(
            any(
                v["location"] == "[rbp-0x8]" and v["offset"] == -8 for v in data["vars"]
            )
        )

    def test_x86_static_lea_stack_adjustment_is_tracked(self):
        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            SimpleNamespace(mnemonic="lea", op_str="rsp, [rsp - 0x30]"),
            SimpleNamespace(mnemonic="mov", op_str="qword ptr [rsp + 0x20], rax"),
            SimpleNamespace(mnemonic="ret", op_str=""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "sysv64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 32, 0x401080),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401080)

        self.assertEqual(data["frame_size"], 0x30)
        self.assertTrue(
            any(
                v["location"] == "[rsp+0x20]" and v["offset"] == -0x10
                for v in data["vars"]
            )
        )

    def test_win64_shadow_space_is_not_treated_as_stack_args(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("sub", "rsp, 0x20"),
            FakeInstr("mov", "qword ptr [rsp + 0x20], rcx"),
            FakeInstr("mov", "qword ptr [rsp + 0x48], rax"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "win64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 32, 0x401020),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401020)

        self.assertFalse(any(a["location"] == "[rsp+0x20]" for a in data["args"]))
        self.assertTrue(
            any(
                a["location"] == "[rsp+0x48]" and a["offset"] == 0x30
                for a in data["args"]
            )
        )

    def test_cdecl32_frame_pointer_args_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("push", "ebp"),
            FakeInstr("mov", "ebp, esp"),
            FakeInstr("mov", "eax, dword ptr [ebp + 0x8]"),
            FakeInstr("mov", "edx, dword ptr [ebp + 0xc]"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 4, "cdecl32")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 24, 0x402000),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x402000)

        self.assertTrue(
            any(a["location"] == "[ebp+0x8]" and a["offset"] == 8 for a in data["args"])
        )
        self.assertTrue(
            any(
                a["location"] == "[ebp+0xc]" and a["offset"] == 12 for a in data["args"]
            )
        )

    def test_sysv64_register_aliases_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("mov", "edi, 1"),
            FakeInstr("add", "esi, eax"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("x86", 8, "sysv64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 16, 0x401100),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x401100)

        self.assertTrue(
            any(a["location"] == "rdi" and a["source"] == "abi" for a in data["args"])
        )
        self.assertTrue(
            any(a["location"] == "rsi" and a["source"] == "abi" for a in data["args"])
        )

    def test_arm64_register_args_and_sp_locals_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("stp", "x29, x30, [sp, #-0x20]!"),
            FakeInstr("mov", "x29, sp"),
            FakeInstr("sub", "sp, sp, #0x40"),
            FakeInstr("str", "x19, [sp, #0x18]"),
            FakeInstr("add", "x0, x0, #1"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm64", 8, "aapcs64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 32, 0x500000),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x500000)

        self.assertEqual(data["arch"], "arm64")
        self.assertEqual(data["abi"], "aapcs64")
        self.assertEqual(data["frame_size"], 96)
        self.assertTrue(
            any(
                v["location"] == "[sp+0x18]" and v["offset"] == -72
                for v in data["vars"]
            )
        )
        self.assertTrue(
            any(a["location"] == "x0" and a["source"] == "abi" for a in data["args"])
        )

    def test_arm64_dynamic_alloca_suppresses_ambiguous_sp_accesses(self):
        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            SimpleNamespace(mnemonic="stp", op_str="x29, x30, [sp, #-0x20]!"),
            SimpleNamespace(mnemonic="mov", op_str="x29, sp"),
            SimpleNamespace(mnemonic="sub", op_str="sp, sp, #0x30"),
            SimpleNamespace(mnemonic="sub", op_str="sp, sp, x0"),
            SimpleNamespace(mnemonic="str", op_str="x1, [sp, #0x18]"),
            SimpleNamespace(mnemonic="str", op_str="x2, [x29, #-0x8]"),
            SimpleNamespace(mnemonic="ret", op_str=""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm64", 8, "aapcs64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 48, 0x500040),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x500040)

        self.assertEqual(data["frame_size"], 0x50)
        self.assertFalse(any(v["location"] == "[sp+0x18]" for v in data["vars"]))
        self.assertFalse(any(a["location"] == "[sp+0x18]" for a in data["args"]))
        self.assertTrue(
            any(
                v["location"] == "[x29-0x8]" and v["offset"] == -8 for v in data["vars"]
            )
        )

    def test_arm64_restoring_sp_from_frame_pointer_recovers_known_state(self):
        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            SimpleNamespace(mnemonic="stp", op_str="x29, x30, [sp, #-0x20]!"),
            SimpleNamespace(mnemonic="mov", op_str="x29, sp"),
            SimpleNamespace(mnemonic="sub", op_str="sp, sp, x0"),
            SimpleNamespace(mnemonic="mov", op_str="sp, x29"),
            SimpleNamespace(mnemonic="sub", op_str="sp, sp, #0x20"),
            SimpleNamespace(mnemonic="str", op_str="x3, [sp, #0x8]"),
            SimpleNamespace(mnemonic="ret", op_str=""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm64", 8, "aapcs64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 48, 0x500060),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x500060)

        self.assertEqual(data["frame_size"], 0x20)
        self.assertTrue(
            any(
                v["location"] == "[sp+0x8]" and v["offset"] == -0x18
                for v in data["vars"]
            )
        )

    def test_arm64_w_register_aliases_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("add", "w0, w0, #1"),
            FakeInstr("mov", "w1, wzr"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm64", 8, "aapcs64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 16, 0x500100),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x500100)

        self.assertTrue(
            any(a["location"] == "x0" and a["source"] == "abi" for a in data["args"])
        )
        self.assertTrue(
            any(a["location"] == "x1" and a["source"] == "abi" for a in data["args"])
        )

    def test_arm32_register_args_and_sp_locals_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("push", "{r4, lr}"),
            FakeInstr("sub", "sp, sp, #0x20"),
            FakeInstr("str", "r4, [sp, #0x8]"),
            FakeInstr("add", "r0, r0, #1"),
            FakeInstr("bx", "lr"),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm", 4, "aapcs32")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 24, 0x600000),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x600000)

        self.assertEqual(data["arch"], "arm")
        self.assertEqual(data["abi"], "aapcs32")
        self.assertEqual(data["frame_size"], 40)
        self.assertTrue(
            any(
                v["location"] == "[sp+0x8]" and v["offset"] == -32 for v in data["vars"]
            )
        )
        self.assertTrue(
            any(a["location"] == "r0" and a["source"] == "abi" for a in data["args"])
        )

    def test_arm32_frame_pointer_args_are_detected(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("push", "{r11, lr}"),
            FakeInstr("add", "r11, sp, #0"),
            FakeInstr("ldr", "r4, [r11, #0x8]"),
            FakeInstr("ldr", "r5, [r11, #0xc]"),
            FakeInstr("bx", "lr"),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm", 4, "aapcs32")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 24, 0x600100),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x600100)

        self.assertTrue(
            any(a["location"] == "[r11+0x8]" and a["offset"] == 8 for a in data["args"])
        )
        self.assertTrue(
            any(
                a["location"] == "[r11+0xc]" and a["offset"] == 12 for a in data["args"]
            )
        )

    def test_arm64_frame_pointer_anchor_tracks_saved_area_size(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("stp", "x29, x30, [sp, #-0x20]!"),
            FakeInstr("mov", "x29, sp"),
            FakeInstr("ldr", "x0, [x29, #0x18]"),
            FakeInstr("ldr", "x1, [x29, #0x20]"),
            FakeInstr("ret", ""),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm64", 8, "aapcs64")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 32, 0x700000),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x700000)

        self.assertFalse(any(a["location"] == "[x29+0x18]" for a in data["args"]))
        self.assertTrue(
            any(
                a["location"] == "[x29+0x20]" and a["offset"] == 0x20
                for a in data["args"]
            )
        )

    def test_arm32_frame_pointer_anchor_tracks_bias_from_fp_setup(self):
        class FakeInstr:
            def __init__(self, mnemonic, op_str):
                self.mnemonic = mnemonic
                self.op_str = op_str

        class FakeDisasm:
            def __init__(self, instrs):
                self.detail = False
                self._instrs = instrs

            def disasm(self, _code, _base):
                return iter(self._instrs)

        instrs = [
            FakeInstr("push", "{r11, lr}"),
            FakeInstr("add", "fp, sp, #0x4"),
            FakeInstr("ldr", "r0, [fp, #0x4]"),
            FakeInstr("ldr", "r1, [fp, #0x8]"),
            FakeInstr("bx", "lr"),
        ]

        with (
            mock.patch.object(
                stack_frame_module, "_get_arch_mode", return_value=(1, 1)
            ),
            mock.patch.object(
                stack_frame_module, "_detect_abi", return_value=("arm", 4, "aapcs32")
            ),
            mock.patch.object(
                stack_frame_module,
                "_get_code_bytes",
                return_value=(b"\x90" * 24, 0x700100),
            ),
            mock.patch.object(
                stack_frame_module,
                "lief",
                mock.Mock(parse=mock.Mock(return_value=object())),
            ),
            mock.patch.object(
                stack_frame_module,
                "capstone",
                mock.Mock(Cs=mock.Mock(return_value=FakeDisasm(instrs))),
            ),
        ):
            data = stack_frame_module.analyse_stack_frame(self.binary, 0x700100)

        self.assertTrue(
            any(a["location"] == "[r11+0x4]" and a["offset"] == 4 for a in data["args"])
        )
        self.assertTrue(
            any(a["location"] == "[r11+0x8]" and a["offset"] == 8 for a in data["args"])
        )

    def test_extended_stack_access_forms_are_parsed(self):
        cases = [
            ("sd ra, 8(sp)", "riscv", ("sp", 8, "[sp+0x8]")),
            ("sw $ra, 0x1c($sp)", "mips", ("sp", 0x1C, "[sp+0x1c]")),
            ("stw r31, -4(r1)", "ppc", ("sp", -4, "[sp-0x4]")),
            ("ld [%fp - 0x8], %o0", "sparc", ("r11", -8, "[r11-0x8]")),
        ]
        for op_str, family, expected in cases:
            with self.subTest(family=family):
                self.assertEqual(
                    stack_frame_module._parse_stack_access(op_str, family), expected
                )

    def test_extended_stack_adjust_patterns_are_tracked(self):
        cases = [
            (
                SimpleNamespace(mnemonic="addi", op_str="sp, sp, -0x20"),
                "riscv",
                8,
                0x20,
            ),
            (SimpleNamespace(mnemonic="addiu", op_str="$sp, $sp, -32"), "mips", 4, 32),
            (SimpleNamespace(mnemonic="stwu", op_str="r1, -0x30(r1)"), "ppc", 4, 0x30),
            (
                SimpleNamespace(mnemonic="save", op_str="%sp, -0x60, %sp"),
                "sparc",
                4,
                0x60,
            ),
        ]
        for ins, family, ptr_size, expected in cases:
            with self.subTest(family=family):
                self.assertEqual(
                    stack_frame_module._update_stack_adjust(0, ins, family, ptr_size),
                    expected,
                )


if __name__ == "__main__":
    unittest.main()
