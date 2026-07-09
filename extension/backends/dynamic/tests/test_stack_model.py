# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the dynamic semantic stack model."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.stack_model import (
    StaticTraceResolver,
    _guess_buffer_region,
    _overflow_summary,
    build_dynamic_analysis,
)


def _hex_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


class TestDynamicStackModel(unittest.TestCase):
    def test_compat_imports_reexport_moved_symbols(self):
        from backends.dynamic.engine.unicorn.config import TraceConfig
        from backends.dynamic.run_pipeline import TraceConfig as pipeline_compat_config
        from backends.dynamic.stack_model import build_dynamic_analysis as compat_build

        self.assertIs(compat_build, build_dynamic_analysis)
        self.assertIs(pipeline_compat_config, TraceConfig)

    def test_guess_buffer_region_prefers_static_var_when_trace_offset_disagrees(self):
        bp = 0x1000
        frame = {
            "vars": [
                {"name": "buffer", "offset": -0x50, "size": 64, "source": "auto"},
                {"name": "modified", "offset": -4, "size": 4, "source": "auto"},
            ]
        }
        meta = {
            "buffer_offset": -0x40,
            "buffer_size": 64,
        }

        region = _guess_buffer_region(frame, bp, meta)

        self.assertIsNotNone(region)
        self.assertEqual(region["start"], bp - 0x50)
        self.assertEqual(region["end"], bp - 0x10)
        self.assertEqual(region["label"], "buffer")
        self.assertEqual(region["source"], "heuristic")

    def test_runtime_write_infers_buffer_and_detects_control_overwrite(self):
        word = 8
        rbp = 0x1000
        rsp = 0x0FB8
        window_start = 0x0FB8
        buffer_start = 0x0FC0
        write_size = 80
        payload = b"A" * write_size
        window = bytearray(b"\x00" * 0x60)
        write_offset = buffer_start - window_start
        window[write_offset : write_offset + write_size] = payload

        snapshot = {
            "step": 1,
            "instr": "call 0x401030",
            "instruction": {
                "address": "0x401020",
                "size": 5,
                "bytes": "e8 0b 00 00 00",
                "mnemonic": "call",
                "operands": "0x401030",
                "text": "call 0x401030",
            },
            "cpu": {
                "arch": "x86_64",
                "word_size": word,
                "endian": "little",
                "aliases": {
                    "sp": "rsp",
                    "bp": "rbp",
                    "fp": "rbp",
                    "ip": "rip",
                    "lr": None,
                },
                "before": {
                    "registers": {
                        "rsp": hex(rsp),
                        "rbp": hex(rbp),
                        "rip": "0x401020",
                    }
                },
                "after": {
                    "registers": {
                        "rsp": hex(rsp),
                        "rbp": hex(rbp),
                        "rip": "0x401025",
                    }
                },
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [
                    {
                        "addr": hex(buffer_start),
                        "size": write_size,
                        "bytes": _hex_bytes(payload),
                        "source": "external",
                    }
                ],
                "reads": [],
            },
            "effects": {
                "kind": "call",
                "call_target": "0x401030",
                "external_simulated": True,
                "external_symbol": "strcpy",
            },
            "registers": [
                {"name": "rbp", "value": hex(rbp), "pos": 0},
                {"name": "rsp", "value": hex(rsp), "pos": 1},
                {"name": "rip", "value": "0x401020", "pos": 2},
            ],
            "stack": [],
        }
        meta = {
            "arch_bits": 64,
            "word_size": word,
            "stack_base": hex(0x0F00),
            "stack_size": 0x200,
            "binary": str(__file__),
        }
        disasm = [
            {"addr": "0x401020", "text": "call 0x401030"},
            {"addr": "0x401030", "text": "ret"},
        ]

        analysis = build_dynamic_analysis([snapshot], meta, str(__file__), disasm)
        step = analysis["1"]

        self.assertEqual(step["buffer"]["start"], hex(buffer_start))
        self.assertEqual(step["buffer"]["size"], rbp - buffer_start)
        # A size inferred purely from an observed runtime write span is never
        # proof of the object's true declared size -- must not be reported
        # as exact.
        self.assertFalse(step["buffer"]["size_exact"])
        self.assertTrue(step["overflow"]["active"])
        self.assertEqual(step["overflow"]["controlRisk"], "return_address")
        self.assertIn("saved_bp", step["overflow"]["reached"])
        self.assertIn("return_address", step["overflow"]["reached"])
        self.assertTrue(
            any("Overflow:" in bullet for bullet in step["explanationBullets"])
        )

    def test_frame_allocation_gating_buffer84_example(self):
        """buffer84 (buffer_offset=-0x60): locals/buffers must not appear
        before this invocation's own frame is fully set up. At step 1
        (`push rbp`), rbp still holds the *caller's* frame pointer. At
        step 2 (`mov rbp, rsp`), rbp becomes this call's own frame base,
        but nothing has been reserved for locals/buffers yet -- only once
        `sub rsp, N` executes (step 3) may the buffer be shown. Mid-
        function/unresolved traces (no push rbp ever observed) keep the
        historical permissive default -- see
        test_runtime_write_infers_buffer_and_detects_control_overwrite."""
        word = 8
        rbp_new = 0x1000
        rbp_caller = 0x1100
        window_start = 0x0F00
        window = bytearray(b"\x00" * 0x400)

        def _snap(step, text, mnemonic, operands, rsp_before, rbp_before, rsp_after, rbp_after):
            return {
                "step": step,
                "func": "main",
                "instr": text,
                "instruction": {
                    "address": hex(0x401000 + step),
                    "size": 1,
                    "bytes": "00",
                    "mnemonic": mnemonic,
                    "operands": operands,
                    "text": text,
                },
                "cpu": {
                    "arch": "x86_64",
                    "word_size": word,
                    "endian": "little",
                    "aliases": {"sp": "rsp", "bp": "rbp", "fp": "rbp", "ip": "rip", "lr": None},
                    "before": {
                        "registers": {
                            "rsp": hex(rsp_before),
                            "rbp": hex(rbp_before),
                            "rip": hex(0x401000 + step),
                        }
                    },
                    "after": {
                        "registers": {
                            "rsp": hex(rsp_after),
                            "rbp": hex(rbp_after),
                            "rip": hex(0x401001 + step),
                        }
                    },
                },
                "memory": {
                    "window_start": hex(window_start),
                    "window_bytes": _hex_bytes(window),
                    "writes": [],
                    "reads": [],
                },
                "effects": {"kind": "write"},
                "registers": [],
                "stack": [],
            }

        # push rbp: rbp unchanged (still the caller's), rsp decrements one word.
        snap_push = _snap(
            1, "push rbp", "push", "rbp",
            rsp_before=rbp_new + word, rbp_before=rbp_caller,
            rsp_after=rbp_new, rbp_after=rbp_caller,
        )
        # mov rbp, rsp: rbp becomes this call's own frame base, nothing reserved yet.
        snap_mov = _snap(
            2, "mov rbp, rsp", "mov", "rbp, rsp",
            rsp_before=rbp_new, rbp_before=rbp_caller,
            rsp_after=rbp_new, rbp_after=rbp_new,
        )
        # sub rsp, 0x70: locals/buffers now have reserved storage.
        snap_sub = _snap(
            3, "sub rsp, 0x70", "sub", "rsp, 0x70",
            rsp_before=rbp_new, rbp_before=rbp_new,
            rsp_after=rbp_new - 0x70, rbp_after=rbp_new,
        )

        meta = {
            "arch_bits": 64,
            "word_size": word,
            "stack_base": hex(0x0F00),
            "stack_size": 0x400,
            "binary": str(__file__),
            "buffer_offset": -0x60,
            "buffer_size": 0x60,
        }
        disasm = [{"addr": "0x401000", "text": "nop"}]

        analysis = build_dynamic_analysis([snap_push, snap_mov, snap_sub], meta, str(__file__), disasm)

        step1 = analysis["1"]
        self.assertIsNone(step1["buffer"])
        self.assertNotIn("buffer", {slot["role"] for slot in step1["frame"]["slots"]})

        # mov rbp, rsp: frame pointer established, but nothing reserved yet.
        step2 = analysis["2"]
        self.assertIsNone(step2["buffer"])
        self.assertNotIn("buffer", {slot["role"] for slot in step2["frame"]["slots"]})
        self.assertNotIn("local", {slot["role"] for slot in step2["frame"]["slots"]})

        # sub rsp, 0x70: locals/buffers are now reserved and may be shown.
        step3 = analysis["3"]
        self.assertIsNotNone(step3["buffer"])
        self.assertEqual(step3["buffer"]["start"], hex(rbp_new - 0x60))
        # Config-declared (meta.buffer_offset/buffer_size): a real, proven
        # size -- an observed runtime write must never be allowed to
        # override it downstream (frontend guard, ported separately).
        self.assertTrue(step3["buffer"]["size_exact"])
        buffer_slot = next(
            slot for slot in step3["frame"]["slots"] if slot["role"] == "buffer"
        )
        self.assertTrue(buffer_slot["size_exact"])

    def test_leave_keeps_frame_control_addresses_on_last_valid_bp(self):
        word = 4
        ebp = 0x1000
        esp = 0x0FC0
        window_start = 0x0FA0
        window = bytearray(b"\x00" * 0x80)
        buffer_start = ebp - 0x40
        write_offset = buffer_start - window_start
        window[write_offset : write_offset + 64] = b"A" * 64
        saved_bp_offset = ebp - window_start
        window[saved_bp_offset : saved_bp_offset + 4] = b"BBBB"
        ret_offset = (ebp + 4) - window_start
        window[ret_offset : ret_offset + 4] = b"CCCC"
        arg_offset = (ebp + 8) - window_start
        window[arg_offset : arg_offset + 4] = b"\x96\x91\x04\x08"

        step1 = {
            "step": 1,
            "func": "main",
            "instr": "mov eax, 0",
            "instruction": {
                "address": "0x401000",
                "size": 3,
                "bytes": "b8 00 00",
                "mnemonic": "mov",
                "operands": "eax, 0",
                "text": "mov eax, 0",
            },
            "cpu": {
                "arch": "x86",
                "word_size": word,
                "endian": "little",
                "aliases": {
                    "sp": "esp",
                    "bp": "ebp",
                    "fp": "ebp",
                    "ip": "eip",
                    "lr": None,
                },
                "before": {
                    "registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401000"}
                },
                "after": {
                    "registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401003"}
                },
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [],
                "reads": [],
            },
            "effects": {"kind": "write"},
            "registers": [],
            "stack": [],
        }

        step2 = {
            "step": 2,
            "func": "main",
            "instr": "leave",
            "instruction": {
                "address": "0x401003",
                "size": 1,
                "bytes": "c9",
                "mnemonic": "leave",
                "operands": "",
                "text": "leave",
            },
            "cpu": {
                "arch": "x86",
                "word_size": word,
                "endian": "little",
                "aliases": {
                    "sp": "esp",
                    "bp": "ebp",
                    "fp": "ebp",
                    "ip": "eip",
                    "lr": None,
                },
                "before": {
                    "registers": {"esp": hex(esp), "ebp": hex(ebp), "eip": "0x401003"}
                },
                "after": {
                    "registers": {
                        "esp": hex(ebp + 4),
                        "ebp": "0x42424242",
                        "eip": "0x401004",
                    }
                },
            },
            "memory": {
                "window_start": hex(window_start),
                "window_bytes": _hex_bytes(window),
                "writes": [],
                "reads": [],
            },
            "effects": {"kind": "write"},
            "registers": [],
            "stack": [],
        }

        meta = {
            "arch_bits": 32,
            "word_size": word,
            "stack_base": hex(0x0F00),
            "stack_size": 0x400,
            "buffer_offset": -0x40,
            "buffer_size": 64,
            "binary": str(__file__),
        }
        disasm = [
            {"addr": "0x401000", "text": "mov eax, 0"},
            {"addr": "0x401003", "text": "leave"},
            {"addr": "0x401004", "text": "ret"},
        ]

        analysis = build_dynamic_analysis([step1, step2], meta, str(__file__), disasm)
        leave_step = analysis["2"]

        self.assertEqual(leave_step["frame"]["basePointer"], hex(ebp))
        self.assertEqual(leave_step["frame"]["registerBasePointer"], "0x42424242")
        self.assertEqual(leave_step["control"]["savedBpAddr"], hex(ebp))
        self.assertEqual(leave_step["control"]["retAddrAddr"], hex(ebp + word))
        self.assertEqual(leave_step["control"]["retValue"], "0x43434343")

    def test_overflow_summary_ignores_control_flags_without_crossing_write(self):
        analysis = {
            "buffer": {
                "name": "buffer",
                "start": "0xfc0",
                "end": "0x1000",
                "size": 64,
            },
            "control": {
                "savedBpAddr": "0x1000",
                "retAddrAddr": "0x1008",
            },
            "frame": {
                "slots": [
                    {
                        "role": "buffer",
                        "start": "0xfc0",
                        "end": "0x1000",
                        "recentWrite": True,
                        "changed": True,
                    },
                    {
                        "role": "saved_bp",
                        "start": "0x1000",
                        "end": "0x1008",
                        "corrupted": True,
                    },
                    {
                        "role": "return_address",
                        "start": "0x1008",
                        "end": "0x1010",
                        "corrupted": True,
                    },
                ]
            },
            "delta": {
                "writes": [
                    {"addr": "0xfc0", "size": 25, "bytes": _hex_bytes(b"A" * 25)}
                ]
            },
        }

        overflow = _overflow_summary(analysis)

        self.assertIsNotNone(overflow)
        self.assertFalse(overflow["active"])
        self.assertEqual(overflow["progressBytes"], 0)


class TestResolveFunction(unittest.TestCase):
    """Regression tests for PIE address normalization in resolve_function.

    login-leakage-hard: base=0x400000, main at ELF offset 0x1d4d,
    _fini at ELF offset 0x1e58 (no size).  Before the fix, any rebased
    address (0x401d4d) was larger than every PIE-relative symbol end, so
    _fini (end=None) always won the range scan.
    """

    # Minimal symbol table mirroring login-leakage-hard's .text section.
    SYMBOLS = [
        {"name": "win", "addr": "0x1aae", "size": 263, "type": "T"},
        {"name": "challenge", "addr": "0x1bb5", "size": 408, "type": "T"},
        {"name": "main", "addr": "0x1d4d", "size": 141, "type": "T"},
        {"name": "__libc_csu_init", "addr": "0x1de0", "size": 101, "type": "T"},
        {"name": "__libc_csu_fini", "addr": "0x1e50", "size": 5, "type": "T"},
        {"name": "_fini", "addr": "0x1e58", "size": None, "type": "T"},
    ]
    META_PIE = {"base": "0x400000", "stack_base": "0x7fff0000", "stack_size": 0x10000}
    META_NOPIE = {"base": "0x0", "stack_base": "0x7fff0000", "stack_size": 0x10000}

    def _make_resolver(self, meta: dict) -> StaticTraceResolver:
        resolver = StaticTraceResolver.__new__(StaticTraceResolver)
        resolver.binary_path = "/fake/binary"
        resolver.meta = meta
        resolver._symbols = None
        resolver._function_ranges = None
        resolver._stack_frames = {}
        resolver._conventions = {}
        resolver._annotation_names = None
        resolver._annotation_comments = None
        resolver.code_min = None
        resolver.code_max = None
        resolver.stack_base = None
        resolver.stack_end = None
        from backends.dynamic.pipeline.stack_model import _parse_int

        resolver.load_base = _parse_int(meta.get("base")) or 0
        resolver._symbols = self.SYMBOLS
        return resolver

    def test_rebased_main_address_resolves_to_main_not_fini(self):
        """0x401d4d is main rebased. Must return 'main', never '_fini'."""
        resolver = self._make_resolver(self.META_PIE)
        result = resolver.resolve_function(0x401D4D)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "main")

    def test_rebased_challenge_address_resolves_to_challenge(self):
        """0x401bb5 is challenge rebased."""
        resolver = self._make_resolver(self.META_PIE)
        result = resolver.resolve_function(0x401BB5)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "challenge")

    def test_rebased_address_inside_challenge_resolves_to_challenge(self):
        """0x401c00 is inside challenge (0x1bb5 + 0x4b offset)."""
        resolver = self._make_resolver(self.META_PIE)
        result = resolver.resolve_function(0x401C00)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "challenge")

    def test_fini_with_no_end_does_not_swallow_main(self):
        """_fini (end=None) must never be returned for addresses in main."""
        resolver = self._make_resolver(self.META_PIE)
        for offset in range(0, 141, 4):
            addr = 0x400000 + 0x1D4D + offset
            result = resolver.resolve_function(addr)
            self.assertIsNotNone(result, f"no function for 0x{addr:x}")
            self.assertNotEqual(
                result["name"], "_fini", f"0x{addr:x} resolved to _fini instead of main"
            )

    def test_libc_csu_fini_does_not_swallow_user_functions(self):
        """__libc_csu_fini must not be returned for challenge or main addresses."""
        resolver = self._make_resolver(self.META_PIE)
        for func, base_offset, size in [
            ("main", 0x1D4D, 141),
            ("challenge", 0x1BB5, 408),
        ]:
            for offset in range(0, size, max(1, size // 8)):
                addr = 0x400000 + base_offset + offset
                result = resolver.resolve_function(addr)
                self.assertIsNotNone(result, f"no function for 0x{addr:x}")
                self.assertNotIn(
                    result["name"],
                    ("_fini", "__libc_csu_fini"),
                    f"0x{addr:x} ({func}+{offset}) resolved to {result['name']}",
                )

    def test_pie_relative_address_still_works_when_base_zero(self):
        """When base=0x0 (non-PIE or already normalized), ELF-relative lookup works."""
        resolver = self._make_resolver(self.META_NOPIE)
        result = resolver.resolve_function(0x1D4D)
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "main")

    def test_build_dynamic_analysis_pie_trace_all_steps_resolve_main(self):
        """build_dynamic_analysis must return 'main' for all main-body steps."""
        base = 0x400000
        main_start = 0x1D4D
        snapshots = [
            {
                "step": i + 1,
                "rip": hex(base + main_start + i * 4),
                "func": "main",
                "instr": "nop",
                "registers": {},
                "stack": [],
                "effects": {},
            }
            for i in range(5)
        ]
        meta = {
            "base": hex(base),
            "arch_bits": 64,
            "word_size": 8,
            "stack_base": "0x7fff0000",
            "stack_size": 0x10000,
        }
        analysis = build_dynamic_analysis(snapshots, meta, binary_path=None)
        for step_key, entry in analysis.items():
            fn_name = entry.get("function", {}).get("name")
            self.assertNotEqual(
                fn_name,
                "_fini",
                f"step {step_key}: function.name is '_fini', expected 'main' or None",
            )


if __name__ == "__main__":
    unittest.main()
