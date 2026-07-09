# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for dynamic crash/error diagnostics."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.diagnostics import build_diagnostics
from backends.dynamic.pipeline.run_pipeline import _build_crash_report


def _hex_bytes(data: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


def _snapshot(step=1, instr="call 0x401030", mnemonic="call", after_rip="0x401015"):
    return {
        "step": step,
        "func": "main",
        "instr": instr,
        "instruction": {
            "address": "0x401010",
            "mnemonic": mnemonic,
            "operands": "0x401030" if mnemonic == "call" else "",
            "text": instr,
        },
        "cpu": {
            "before": {
                "registers": {
                    "rip": "0x401010",
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                }
            },
            "after": {
                "registers": {
                    "rip": after_rip,
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                }
            },
        },
        "effects": {
            "external_simulated": True,
            "external_symbol": "strcpy",
        },
        "memory": {
            "writes": [],
            "reads": [],
        },
    }


def _base_analysis(ret_value="0x401080"):
    return {
        "function": {"name": "main", "addr": "0x401000"},
        "buffer": {
            "name": "buffer",
            "start": "0x7fffffffdfc0",
            "end": "0x7fffffffe000",
            "size": 64,
        },
        "control": {
            "savedBpAddr": "0x7fffffffe000",
            "retAddrAddr": "0x7fffffffe008",
            "savedBpValue": "0x7fffffffe030",
            "retValue": ret_value,
        },
        "frame": {
            "slots": [
                {
                    "role": "buffer",
                    "start": "0x7fffffffdfc0",
                    "end": "0x7fffffffe000",
                    "size": 64,
                    "bytesHex": _hex_bytes(b"A" * 8),
                    "recentWrite": True,
                    "changed": True,
                },
                {
                    "role": "saved_bp",
                    "start": "0x7fffffffe000",
                    "end": "0x7fffffffe008",
                    "size": 8,
                    "valueHex": "0x7fffffffe030",
                    "bytesHex": "30 e0 ff ff ff 7f 00 00",
                },
                {
                    "role": "return_address",
                    "start": "0x7fffffffe008",
                    "end": "0x7fffffffe010",
                    "size": 8,
                    "valueHex": ret_value,
                    "bytesHex": "80 10 40 00 00 00 00 00",
                    "pointerKind": "code",
                },
            ]
        },
        "delta": {"writes": [], "reads": []},
        "overflow": {"active": False, "reached": []},
    }


class TestDynamicDiagnostics(unittest.TestCase):
    def test_overflow_argv_overwrites_return_address(self):
        payload = b"A" * 72 + b"C" * 8
        analysis = _base_analysis("0x4343434343434343")
        analysis["frame"]["slots"][1].update(
            {
                "valueHex": "0x4141414141414141",
                "bytesHex": _hex_bytes(b"A" * 8),
                "recentWrite": True,
                "changed": True,
                "flags": ["corrupted"],
            }
        )
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x4343434343434343",
                "bytesHex": _hex_bytes(b"C" * 8),
                "recentWrite": True,
                "changed": True,
                "flags": ["corrupted"],
                "pointerKind": "unknown",
            }
        )
        analysis["delta"]["writes"] = [
            {
                "addr": "0x7fffffffdfc0",
                "size": len(payload),
                "bytes": _hex_bytes(payload),
                "source": "external",
            }
        ]
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": ["saved_bp", "return_address"],
            "frontier": "0x7fffffffe010",
            "controlRisk": "return_address",
        }
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": payload.hex(),
            "payload_target": "argv1",
        }

        diagnostics = build_diagnostics(
            [_snapshot()],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        kinds = {diag["kind"] for diag in diagnostics}
        self.assertIn("buffer_overflow", kinds)
        self.assertIn("return_address_corrupted", kinds)
        ret_diag = next(
            diag for diag in diagnostics if diag["kind"] == "return_address_corrupted"
        )
        self.assertEqual(ret_diag["severity"], "error")
        self.assertEqual(ret_diag["slot"]["kind"], "return_address")
        self.assertEqual(ret_diag["probableSource"], "argv[1]")
        self.assertEqual(ret_diag["payloadOffset"], 72)
        self.assertTrue(analysis["diagnostics"])

    def test_overflow_only_local_warns_without_control_corruption(self):
        payload = b"A" * 68
        analysis = _base_analysis()
        analysis["delta"]["writes"] = [
            {
                "addr": "0x7fffffffdfc0",
                "size": len(payload),
                "bytes": _hex_bytes(payload),
            }
        ]
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": [],
            "frontier": "0x7fffffffe004",
        }
        meta = {"arch_bits": 64, "word_size": 8, "payload_hex": _hex_bytes(payload)}

        diagnostics = build_diagnostics(
            [_snapshot()],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        self.assertEqual([diag["kind"] for diag in diagnostics], ["buffer_overflow"])
        self.assertEqual(diagnostics[0]["severity"], "warning")

    def test_invalid_ret_to_pattern_address(self):
        analysis = _base_analysis("0x41414141")
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x41414141",
                "bytesHex": "41 41 41 41 00 00 00 00",
                "pointerKind": "unknown",
            }
        )
        snap = _snapshot(step=3, instr="ret", mnemonic="ret", after_rip="0x41414141")
        snap["instruction"]["address"] = "0x401050"
        snap["cpu"]["before"]["registers"]["rip"] = "0x401050"
        meta = {"arch_bits": 64, "word_size": 8, "payload_hex": _hex_bytes(b"A" * 80)}

        diagnostics = build_diagnostics(
            [snap],
            {"3": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        invalid = [diag for diag in diagnostics if diag["kind"] == "fatal_crash"]
        self.assertEqual(len(invalid), 1)
        self.assertEqual(invalid[0]["after"], "0x41414141")
        self.assertEqual(invalid[0]["severity"], "error")

    def test_crash_report_marks_suspect_return_slot(self):
        payload = b"A" * 72 + b"C" * 8
        analysis = _base_analysis("0x4343434343434343")
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x4343434343434343",
                "bytesHex": _hex_bytes(b"C" * 8),
                "pointerKind": "unknown",
            }
        )
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": payload.hex(),
            "payload_target": "argv1",
        }
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401050",
                "instructionText": "ret",
                "registers": {
                    "rip": "0x4343434343434343",
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                },
                "rip": "0x4343434343434343",
                "rsp": "0x7fffffffdf80",
                "rbp": "0x7fffffffe000",
                "faultAddress": "0x4343434343434343",
                "reason": "Retour vers une adresse non executable ou non mappee.",
            },
            [
                _snapshot(
                    step=1, instr="ret", mnemonic="ret", after_rip="0x4343434343434343"
                )
            ],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        self.assertEqual(crash["suspectOverwrittenSlot"]["kind"], "return_address")
        self.assertEqual(crash["payloadOffset"], 72)
        self.assertEqual(crash["probableSource"], "argv[1]")

    def test_crash_report_ignores_normal_main_return_to_sentinel(self):
        analysis = _base_analysis("0x0")
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x0",
                "bytesHex": "00 00 00 00 00 00 00 00",
                "pointerKind": "unknown",
            }
        )
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x4011f3",
                "instructionText": "ret",
                "registers": {
                    "rip": "0x0",
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                },
                "rip": "0x0",
                "faultAddress": "0x0",
                "reason": "Retour vers une adresse non executable ou non mappee.",
            },
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x0")],
            {"1": analysis},
            {"arch_bits": 64, "word_size": 8, "payload_hex": "41" * 264},
            [{"addr": "0x401000"}, {"addr": "0x401200"}],
        )

        self.assertIsNone(crash)

    def test_crash_block_adds_runtime_crash_diagnostic(self):
        analysis = _base_analysis()
        snap = _snapshot(
            step=1,
            instr="mov dword ptr [eax], ebx",
            mnemonic="mov",
            after_rip="0x401012",
        )
        meta = {"arch_bits": 32, "word_size": 4}

        diagnostics = build_diagnostics(
            [snap],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
            crash={
                "type": "unmapped_write",
                "step": 1,
                "function": "main",
                "instructionAddress": "0x401010",
                "instructionText": "mov dword ptr [eax], ebx",
                "registers": {
                    "eip": "0x401010",
                    "esp": "0xbffff000",
                    "ebp": "0xbffff100",
                },
                "eip": "0x401010",
                "esp": "0xbffff000",
                "ebp": "0xbffff100",
                "memoryAddress": "0x0",
                "reason": "Ecriture sur une adresse non mappee pendant l'execution.",
                "probableSource": "stdin",
            },
        )

        runtime = next(diag for diag in diagnostics if diag["kind"] == "runtime_crash")
        self.assertEqual(runtime["severity"], "error")
        self.assertEqual(runtime["instructionAddress"], "0x401010")
        self.assertEqual(runtime["probableSource"], "stdin")

    def test_control_slots_without_current_write_do_not_raise_corruption(self):
        analysis = _base_analysis("0x0")
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x0",
                "bytesHex": "00 00 00 00 00 00 00 00",
                "flags": ["corrupted"],
                "pointerKind": "unknown",
            }
        )
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": ["return_address"],
            "frontier": "0x7fffffffe010",
            "progressBytes": 0,
        }
        snap = _snapshot(
            step=2, instr="mov eax, eax", mnemonic="mov", after_rip="0x401011"
        )
        meta = {"arch_bits": 64, "word_size": 8}

        diagnostics = build_diagnostics(
            [snap],
            {"2": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        self.assertEqual(diagnostics, [])

    def test_normal_trace_has_no_diagnostics(self):
        analysis = _base_analysis("0x401080")
        snap = _snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x401080")
        snap["instruction"]["address"] = "0x401050"
        snap["cpu"]["before"]["registers"]["rip"] = "0x401050"
        meta = {"arch_bits": 64, "word_size": 8}

        diagnostics = build_diagnostics(
            [snap],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )

        self.assertEqual(diagnostics, [])


class TestCrashClassification(unittest.TestCase):
    def _make_overflow_analysis(self, ret_value):
        analysis = _base_analysis(ret_value)
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": ret_value,
                "bytesHex": _hex_bytes(
                    bytes.fromhex(ret_value.replace("0x", "").zfill(16))[::-1]
                ),
                "recentWrite": True,
                "changed": True,
                "flags": ["corrupted"],
                "pointerKind": "unknown",
            }
        )
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": ["saved_bp", "return_address"],
            "frontier": "0x7fffffffe010",
            "controlRisk": "return_address",
        }
        analysis["delta"]["writes"] = [
            {
                "addr": "0x7fffffffdfc0",
                "size": 80,
                "bytes": _hex_bytes(b"A" * 80),
                "source": "external",
            }
        ]
        return analysis

    def test_fatal_crash_aaaa_payload(self):
        analysis = self._make_overflow_analysis("0x4141414141414141")
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": _hex_bytes(b"A" * 80),
            "payload_target": "stdin",
            "functions": [],
        }
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401050",
                "instructionText": "ret",
                "registers": {
                    "rip": "0x4141414141414141",
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                },
                "rip": "0x4141414141414141",
                "faultAddress": "0x4141414141414141",
                "reason": "Retour vers une adresse non mappee.",
            },
            [
                _snapshot(
                    step=1, instr="ret", mnemonic="ret", after_rip="0x4141414141414141"
                )
            ],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        self.assertIsNotNone(crash)
        self.assertEqual(crash["classification"], "fatal_crash")

    def test_control_hijack_code_address(self):
        # Return address overwritten to a code address (not a win symbol)
        analysis = self._make_overflow_analysis("0x401050")
        analysis["frame"]["slots"][2]["pointerKind"] = "code"
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": _hex_bytes(b"A" * 72 + b"\x50\x10\x40\x00\x00\x00\x00\x00"),
            "payload_target": "stdin",
            "functions": [
                {"name": "helper", "addr": "0x401050", "type": "T", "size": "0x30"}
            ],
        }
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401020",
                "instructionText": "ret",
                "registers": {
                    "rip": "0x401050",
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                },
                "rip": "0x401050",
                "faultAddress": "0x401050",
                "reason": "Retour vers une zone executable.",
            },
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x401050")],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        self.assertIsNotNone(crash)
        self.assertEqual(crash["classification"], "control_hijack")

    def test_ret2win_success_classification(self):
        win_addr = "0x401234"
        analysis = self._make_overflow_analysis(win_addr)
        analysis["frame"]["slots"][2]["pointerKind"] = "code"
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": _hex_bytes(b"A" * 72 + b"\x34\x12\x40\x00\x00\x00\x00\x00"),
            "payload_target": "stdin",
            "functions": [
                {"name": "win", "addr": win_addr, "type": "T", "size": "0x20"}
            ],
        }
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401020",
                "instructionText": "ret",
                "registers": {
                    "rip": win_addr,
                    "rsp": "0x7fffffffdf80",
                    "rbp": "0x7fffffffe000",
                },
                "rip": win_addr,
                "faultAddress": win_addr,
                "reason": "Retour vers win().",
            },
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip=win_addr)],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401300"}],
        )
        self.assertIsNotNone(crash)
        self.assertEqual(crash["classification"], "ret2win_success")
        self.assertEqual(crash["retTarget"], win_addr)

    def test_ret2win_diagnostic_severity_is_success(self):
        win_addr = "0x401234"
        analysis = self._make_overflow_analysis(win_addr)
        analysis["frame"]["slots"][2]["pointerKind"] = "code"
        snap = _snapshot(step=1, instr="ret", mnemonic="ret", after_rip=win_addr)
        snap["instruction"]["address"] = "0x401020"
        snap["cpu"]["before"]["registers"]["rip"] = "0x401020"
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": _hex_bytes(b"A" * 72 + b"\x34\x12\x40\x00\x00\x00\x00\x00"),
            "payload_target": "stdin",
            "functions": [
                {"name": "win", "addr": win_addr, "type": "T", "size": "0x20"}
            ],
        }
        diagnostics = build_diagnostics(
            [snap],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401300"}],
        )
        success_diags = [d for d in diagnostics if d.get("kind") == "ret2win_success"]
        self.assertTrue(len(success_diags) >= 1)
        self.assertEqual(success_diags[0]["severity"], "success")

    def test_control_hijack_diagnostic_severity_is_warning(self):
        target_addr = "0x401050"
        analysis = self._make_overflow_analysis(target_addr)
        analysis["frame"]["slots"][2]["pointerKind"] = "code"
        snap = _snapshot(step=1, instr="ret", mnemonic="ret", after_rip=target_addr)
        snap["instruction"]["address"] = "0x401020"
        snap["cpu"]["before"]["registers"]["rip"] = "0x401020"
        meta = {
            "arch_bits": 64,
            "word_size": 8,
            "payload_hex": _hex_bytes(b"A" * 72 + b"\x50\x10\x40\x00\x00\x00\x00\x00"),
            "payload_target": "stdin",
            "functions": [
                {"name": "helper", "addr": target_addr, "type": "T", "size": "0x30"}
            ],
        }
        diagnostics = build_diagnostics(
            [snap],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        hijack_diags = [d for d in diagnostics if d.get("kind") == "control_hijack"]
        self.assertTrue(len(hijack_diags) >= 1)
        self.assertEqual(hijack_diags[0]["severity"], "warning")


class TestBenignTerminationClassification(unittest.TestCase):
    """A crash must never be reported as a vulnerability without real
    evidence: an overflow reaching a control slot, a flagged write on one, or
    the faulting bytes matching a configured payload. Plain hello-world /
    printf-only binaries hit this exact shape when `main` returns into
    un-emulated libc (a real, but unmapped-in-this-trace, return address) --
    that's the emulator running out of road, not a corrupted return address.
    """

    def _no_evidence_analysis(self, ret_value: str) -> dict:
        analysis = _base_analysis(ret_value)
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": ret_value,
                "bytesHex": _hex_bytes(bytes.fromhex(ret_value.replace("0x", "").zfill(16))[::-1]),
                # No recentWrite/changed/flags: this slot was never touched.
            }
        )
        analysis["overflow"] = {"active": False, "reached": []}
        analysis["delta"] = {"writes": [], "reads": []}
        return analysis

    def test_hello_world_ret_to_unmapped_libc_is_not_fatal_payload_crash(self):
        # A hello-world's `main` returns to its real (but here unmapped,
        # since libc isn't loaded) caller address -- not literal 0, which is
        # why the narrow zero-address guard alone doesn't catch this shape.
        libc_return_addr = "0x7ffff7a52083"
        analysis = self._no_evidence_analysis(libc_return_addr)
        meta = {"arch_bits": 64, "word_size": 8, "functions": []}  # no payload configured at all
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401050",
                "instructionText": "ret",
                "registers": {"rip": libc_return_addr, "rsp": "0x7fffffffdf80", "rbp": "0x7fffffffe000"},
                "rip": libc_return_addr,
                "faultAddress": libc_return_addr,
                "reason": "Retour vers une adresse non mappee.",
            },
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip=libc_return_addr)],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        self.assertIsNotNone(crash)
        self.assertEqual(crash["classification"], "benign_termination")
        self.assertIsNone(crash["probableSource"])
        self.assertIsNone(crash["payloadOffset"])

        diagnostics = build_diagnostics(
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip=libc_return_addr)],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
            crash=crash,
        )
        kinds = {diag["kind"] for diag in diagnostics}
        self.assertNotIn("fatal_crash", kinds)
        self.assertNotIn("return_address_corrupted", kinds)
        self.assertIn("benign_termination", kinds)
        benign = next(diag for diag in diagnostics if diag["kind"] == "benign_termination")
        self.assertEqual(benign["severity"], "info")
        self.assertIsNone(benign.get("probableSource"))

    def test_printf_only_ret_after_call_is_not_flagged_vulnerable(self):
        # Same shape as hello-world, but the last user instruction before the
        # crashing return is a (simulated) call to printf -- printf-only
        # binaries must not be flagged as vulnerable either.
        unmapped_addr = "0x7ffff7a1a1b9"
        analysis = self._no_evidence_analysis(unmapped_addr)
        snap = _snapshot(step=2, instr="ret", mnemonic="ret", after_rip=unmapped_addr)
        snap["effects"] = {"external_simulated": True, "external_symbol": "printf"}
        meta = {"arch_bits": 64, "word_size": 8, "functions": []}
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 2,
                "instructionAddress": "0x401060",
                "instructionText": "ret",
                "registers": {"rip": unmapped_addr, "rsp": "0x7fffffffdf80", "rbp": "0x7fffffffe000"},
                "rip": unmapped_addr,
                "faultAddress": unmapped_addr,
                "reason": "Retour vers une adresse non mappee.",
            },
            [snap],
            {"2": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        diagnostics = build_diagnostics([snap], {"2": analysis}, meta, [{"addr": "0x401000"}, {"addr": "0x401100"}], crash=crash)
        kinds = {diag["kind"] for diag in diagnostics}
        self.assertEqual(kinds & {"fatal_crash", "buffer_overflow", "return_address_corrupted", "control_hijack"}, set())

    def test_retaddr_overwrite_stays_fatal_with_evidence(self):
        # Regression: real evidence (overflow reaching return_address + a
        # payload match) must keep the crash strong, never downgraded.
        analysis = _base_analysis("0x4141414141414141")
        analysis["frame"]["slots"][2].update(
            {
                "valueHex": "0x4141414141414141",
                "bytesHex": _hex_bytes(b"A" * 8),
                "recentWrite": True,
                "changed": True,
                "flags": ["corrupted"],
                "pointerKind": "unknown",
            }
        )
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": ["return_address"],
            "frontier": "0x7fffffffe010",
        }
        analysis["delta"]["writes"] = [
            {"addr": "0x7fffffffdfc0", "size": 80, "bytes": _hex_bytes(b"A" * 80), "source": "external"}
        ]
        meta = {"arch_bits": 64, "word_size": 8, "payload_hex": _hex_bytes(b"A" * 80), "payload_target": "stdin", "functions": []}
        crash = _build_crash_report(
            {
                "type": "unmapped_fetch",
                "step": 1,
                "instructionAddress": "0x401050",
                "instructionText": "ret",
                "registers": {"rip": "0x4141414141414141", "rsp": "0x7fffffffdf80", "rbp": "0x7fffffffe000"},
                "rip": "0x4141414141414141",
                "faultAddress": "0x4141414141414141",
                "reason": "Retour vers une adresse non mappee.",
            },
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x4141414141414141")],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        self.assertEqual(crash["classification"], "fatal_crash")
        self.assertIsNotNone(crash["probableSource"])

        diagnostics = build_diagnostics(
            [_snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x4141414141414141")],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
            crash=crash,
        )
        fatal = next(diag for diag in diagnostics if diag["kind"] == "fatal_crash")
        self.assertEqual(fatal["severity"], "error")

    def test_saved_bp_overwrite_corruption_is_conserved(self):
        # Regression: saved-bp corruption with real write evidence must keep
        # raising saved_bp_corrupted, independent of the benign-termination gate.
        analysis = _base_analysis("0x401080")
        analysis["frame"]["slots"][1].update(
            {
                "valueHex": "0x4242424242424242",
                "bytesHex": _hex_bytes(b"B" * 8),
                "recentWrite": True,
                "changed": True,
                "flags": ["corrupted"],
            }
        )
        analysis["overflow"] = {
            "active": True,
            "bufferName": "buffer",
            "reached": ["saved_bp"],
            "frontier": "0x7fffffffe008",
        }
        analysis["delta"]["writes"] = [
            {"addr": "0x7fffffffdfc0", "size": 72, "bytes": _hex_bytes(b"B" * 72), "source": "external"}
        ]
        meta = {"arch_bits": 64, "word_size": 8, "payload_hex": _hex_bytes(b"B" * 72), "payload_target": "stdin"}

        diagnostics = build_diagnostics(
            [_snapshot()],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
        )
        kinds = {diag["kind"] for diag in diagnostics}
        self.assertIn("saved_bp_corrupted", kinds)
        saved_bp = next(diag for diag in diagnostics if diag["kind"] == "saved_bp_corrupted")
        self.assertEqual(saved_bp["severity"], "warning")

    def test_max_steps_reached_produces_clear_diagnostic_without_crash(self):
        snap = _snapshot(step=500, instr="mov eax, ebx", mnemonic="mov", after_rip="0x401200")
        analysis = _base_analysis()
        meta = {"arch_bits": 64, "word_size": 8}

        diagnostics = build_diagnostics(
            [snap],
            {"500": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401300"}],
            crash=None,
            max_steps_reached=True,
        )
        self.assertEqual([diag["kind"] for diag in diagnostics], ["max_steps_reached"])
        self.assertEqual(diagnostics[0]["severity"], "info")

    def test_max_steps_reached_is_suppressed_when_a_real_crash_exists(self):
        analysis = self._no_evidence_analysis("0x0")
        snap = _snapshot(step=1, instr="ret", mnemonic="ret", after_rip="0x0")
        meta = {"arch_bits": 64, "word_size": 8}
        crash = {
            "type": "unmapped_fetch",
            "step": 1,
            "instructionText": "ret",
            "registers": {},
            "classification": "benign_termination",
        }

        diagnostics = build_diagnostics(
            [snap],
            {"1": analysis},
            meta,
            [{"addr": "0x401000"}, {"addr": "0x401100"}],
            crash=crash,
            max_steps_reached=True,
        )
        self.assertNotIn("max_steps_reached", {diag["kind"] for diag in diagnostics})


if __name__ == "__main__":
    unittest.main()
