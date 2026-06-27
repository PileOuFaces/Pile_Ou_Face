# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.discover_functions."""

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.disasm.discover_functions import (
    _estimate_function_bounds,
    _matches_prologue,
    _normalize_addr,
    _addr_to_int,
    discover_functions,
    evaluate_function_discovery,
)


class TestHelpers(unittest.TestCase):
    """Tests des helpers."""

    def test_normalize_addr(self):
        self.assertEqual(_normalize_addr("0x401000"), "0x401000")
        self.assertEqual(_normalize_addr("401000"), "0x401000")
        self.assertEqual(_normalize_addr("0XDEADBEEF"), "0xdeadbeef")

    def test_addr_to_int(self):
        self.assertEqual(_addr_to_int("0x401000"), 0x401000)
        self.assertEqual(_addr_to_int("401000"), 0x401000)


class TestMatchesPrologue(unittest.TestCase):
    """Tests de _matches_prologue."""

    def test_push_rbp(self):
        self.assertIsNotNone(_matches_prologue("55\tpush\trbp"))
        self.assertIsNotNone(_matches_prologue("push rbp"))

    def test_push_ebp(self):
        self.assertIsNotNone(_matches_prologue("push\tebp"))

    def test_sub_rsp(self):
        self.assertIsNotNone(_matches_prologue("48 83 ec 10\tsub\trsp, 0x10"))
        self.assertIsNotNone(_matches_prologue("sub rsp, 0x20"))

    def test_endbr64(self):
        self.assertIsNotNone(_matches_prologue("f3 0f 1e fa\tendbr64"))

    def test_arm64_stp(self):
        self.assertIsNotNone(_matches_prologue("a9bf7bfd\tstp\tx29, x30, [sp, #-16]!"))

    def test_arm64_sub_sp(self):
        self.assertIsNotNone(_matches_prologue("d101c3ff\tsub\tsp, sp, #0x70"))

    def test_arm32_push_lr(self):
        self.assertIsNotNone(_matches_prologue("00 48 2d e9\tpush\t{fp, lr}"))

    def test_nop_not_prologue(self):
        self.assertIsNone(_matches_prologue("nop"))
        self.assertIsNone(_matches_prologue("ret"))


class TestDiscoverFunctions(unittest.TestCase):
    """Tests de discover_functions."""

    def test_empty_lines(self):
        self.assertEqual(discover_functions([], set()), [])

    def test_known_addrs_excluded(self):
        lines = [
            {"addr": "0x401000", "text": "push rbp", "line": 1},
            {"addr": "0x401001", "text": "mov rbp, rsp", "line": 2},
        ]
        result = discover_functions(lines, {"0x401000"})
        self.assertEqual(len(result), 0)

    def test_prologue_detected(self):
        lines = [
            {"addr": "0x401000", "text": "ret", "line": 1},
            {"addr": "0x401010", "text": "55\tpush\trbp", "line": 2},
            {"addr": "0x401011", "text": "48 89 e5\tmov\trbp, rsp", "line": 3},
        ]
        result = discover_functions(lines, set())
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x401010")
        self.assertIn("sub_", result[0]["name"])
        self.assertIn(
            result[0]["reason"],
            ("push rbp", "endbr64", "sub rsp", "stp", "sub sp", "str preindex"),
        )

    def test_sorted_by_addr(self):
        lines = [
            {"addr": "0x401020", "text": "push rbp", "line": 1},
            {"addr": "0x401010", "text": "ret", "line": 2},
            {"addr": "0x401030", "text": "push rbp", "line": 3},
        ]
        result = discover_functions(lines, set())
        addrs = [_addr_to_int(r["addr"]) for r in result]
        self.assertEqual(addrs, sorted(addrs))

    def test_filler_preserves_terminator(self):
        """ret; nop; nop; push rbp → détecte la fonction après les nops."""
        lines = [
            {"addr": "0x401000", "text": "ret", "line": 1},
            {"addr": "0x401010", "text": "nop", "line": 2},
            {"addr": "0x401011", "text": "nop", "line": 3},
            {"addr": "0x401012", "text": "push rbp", "line": 4},
        ]
        result = discover_functions(lines, set())
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x401012")

    def test_custom_prelude(self):
        """Prelude personnalisé : regex custom détecte une fonction."""
        lines = [
            {"addr": "0x401000", "text": "ret", "line": 1},
            {"addr": "0x401010", "text": "custom_entry x29", "line": 2},
        ]
        custom = [(r"\bcustom_entry\b", "custom")]
        result = discover_functions(lines, set(), custom_preludes=custom)
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(result[0]["reason"], "custom")

    def test_gap_detection(self):
        """Fonction dans un gap entre deux symboles connus."""
        lines = [
            {"addr": "0x401000", "text": "push rbp", "line": 1},  # known
            {"addr": "0x401020", "text": "mov rbp, rsp", "line": 2},  # in gap
            {"addr": "0x401025", "text": "push rbp", "line": 3},  # in gap - prologue
            {"addr": "0x401050", "text": "push rbp", "line": 4},  # known
        ]
        known = {"0x401000", "0x401050"}
        result = discover_functions(lines, known)
        self.assertGreaterEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x401025")

    def test_direct_call_target_detected_without_prologue(self):
        """Une cible d'appel direct doit être reconnue même sans prologue classique."""
        lines = [
            {
                "addr": "0x401000",
                "text": "call 0x401100",
                "mnemonic": "call",
                "operands": "0x401100",
                "line": 1,
            },
            {"addr": "0x401005", "text": "ret", "mnemonic": "ret", "line": 2},
            {
                "addr": "0x401100",
                "text": "mov eax, 1",
                "mnemonic": "mov",
                "operands": "eax, 1",
                "line": 3,
            },
            {"addr": "0x401105", "text": "ret", "mnemonic": "ret", "line": 4},
        ]
        result = discover_functions(lines, set())
        target = next((fn for fn in result if fn["addr"] == "0x401100"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target["reason"], "call_target")
        self.assertIn(target["confidence"], ("medium", "high"))
        self.assertEqual(target["kind"], "function")
        self.assertIn("confidence_score", target)
        self.assertGreaterEqual(target["confidence_score"], 0.72)
        self.assertEqual(target["end_addr"], "0x401106")
        self.assertEqual(target["size"], 6)

    def test_direct_call_target_thunk_detected(self):
        """Une cible d'appel qui saute directement ailleurs doit être marquée comme thunk."""
        lines = [
            {
                "addr": "0x401000",
                "text": "call 0x401020",
                "mnemonic": "call",
                "operands": "0x401020",
                "line": 1,
            },
            {"addr": "0x401005", "text": "ret", "mnemonic": "ret", "line": 2},
            {
                "addr": "0x401020",
                "text": "jmp 0x402000",
                "mnemonic": "jmp",
                "operands": "0x402000",
                "line": 3,
            },
            {"addr": "0x402000", "text": "ret", "mnemonic": "ret", "line": 4},
        ]
        result = discover_functions(lines, set())
        thunk = next((fn for fn in result if fn["addr"] == "0x401020"), None)
        self.assertIsNotNone(thunk)
        self.assertEqual(thunk["reason"], "call_target_thunk")
        self.assertEqual(thunk["confidence"], "high")
        self.assertEqual(thunk["kind"], "thunk")
        self.assertEqual(thunk["target_addr"], "0x402000")
        self.assertGreaterEqual(thunk["confidence_score"], 0.86)

    def test_tail_call_target_detected_after_epilogue(self):
        """Un jmp direct après un épilogue doit promouvoir la cible en fonction."""
        lines = [
            {
                "addr": "0x401000",
                "text": "push rbp",
                "mnemonic": "push",
                "operands": "rbp",
                "line": 1,
            },
            {"addr": "0x401001", "text": "leave", "mnemonic": "leave", "line": 2},
            {
                "addr": "0x401002",
                "text": "jmp 0x401100",
                "mnemonic": "jmp",
                "operands": "0x401100",
                "line": 3,
            },
            {
                "addr": "0x401100",
                "text": "push rbp",
                "mnemonic": "push",
                "operands": "rbp",
                "line": 4,
            },
            {"addr": "0x401101", "text": "ret", "mnemonic": "ret", "line": 5},
        ]
        result = discover_functions(lines, set())
        target = next((fn for fn in result if fn["addr"] == "0x401100"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target["reason"], "tail_call")
        self.assertEqual(target["kind"], "function")
        self.assertIn("end_addr", target)
        self.assertGreaterEqual(target["confidence_score"], 0.8)

    def test_heuristic_thunk_start_has_target_metadata(self):
        """Un thunk découvert heuristiquement doit exposer sa cible finale."""
        lines = [
            {"addr": "0x401000", "text": "ret", "mnemonic": "ret", "line": 1},
            {
                "addr": "0x401010",
                "text": "jmp 0x401020",
                "mnemonic": "jmp",
                "operands": "0x401020",
                "line": 2,
            },
            {
                "addr": "0x401020",
                "text": "jmp 0x402000",
                "mnemonic": "jmp",
                "operands": "0x402000",
                "line": 3,
            },
            {"addr": "0x402000", "text": "ret", "mnemonic": "ret", "line": 4},
        ]
        result = discover_functions(lines, set())
        thunk = next((fn for fn in result if fn["addr"] == "0x401010"), None)
        self.assertIsNotNone(thunk)
        self.assertEqual(thunk["kind"], "thunk")
        self.assertEqual(thunk["target_addr"], "0x402000")
        self.assertIn("confidence_score", thunk)

    def test_endbr64_import_stub_is_classified_as_thunk(self):
        """Un stub PLT/import qui commence par endbr64 doit rester classé thunk."""
        lines = [
            {"addr": "0x401000", "text": "ret", "mnemonic": "ret", "line": 1},
            {"addr": "0x401010", "text": "endbr64", "mnemonic": "endbr64", "line": 2},
            {
                "addr": "0x401014",
                "text": "jmp qword ptr [rip+0x2000]",
                "mnemonic": "jmp",
                "operands": "qword ptr [rip+0x2000]",
                "line": 3,
            },
        ]
        result = discover_functions(lines, set())
        stub = next((fn for fn in result if fn["addr"] == "0x401010"), None)
        self.assertIsNotNone(stub)
        self.assertEqual(stub["reason"], "plt_stub")
        self.assertEqual(stub["kind"], "thunk")
        self.assertEqual(stub["confidence"], "high")
        self.assertGreaterEqual(stub["confidence_score"], 0.88)
        self.assertNotIn("target_addr", stub)

    def test_call_target_endbr64_import_stub_is_thunk(self):
        """Une cible d'appel qui pointe vers un import stub endbr64+jmp doit être un thunk."""
        lines = [
            {
                "addr": "0x401000",
                "text": "call 0x401020",
                "mnemonic": "call",
                "operands": "0x401020",
                "line": 1,
            },
            {"addr": "0x401005", "text": "ret", "mnemonic": "ret", "line": 2},
            {"addr": "0x401020", "text": "endbr64", "mnemonic": "endbr64", "line": 3},
            {
                "addr": "0x401024",
                "text": "jmp qword ptr [rip+0x3000]",
                "mnemonic": "jmp",
                "operands": "qword ptr [rip+0x3000]",
                "line": 4,
            },
        ]
        result = discover_functions(lines, set())
        thunk = next((fn for fn in result if fn["addr"] == "0x401020"), None)
        self.assertIsNotNone(thunk)
        self.assertEqual(thunk["reason"], "call_target_thunk")
        self.assertEqual(thunk["kind"], "thunk")
        self.assertEqual(thunk["confidence"], "high")
        self.assertGreaterEqual(thunk["confidence_score"], 0.86)
        self.assertNotIn("target_addr", thunk)

    def test_binary_hints_can_name_function(self):
        """Les hints binaires (DWARF/entrypoint/etc.) doivent fournir nom et raison."""
        lines = [
            {"addr": "0x401000", "text": "nop", "mnemonic": "nop", "line": 1},
            {
                "addr": "0x401100",
                "text": "mov eax, 1",
                "mnemonic": "mov",
                "operands": "eax, 1",
                "line": 2,
            },
            {"addr": "0x401105", "text": "ret", "mnemonic": "ret", "line": 3},
        ]
        with patch(
            "backends.static.disasm.discover_functions._collect_binary_function_hints",
            return_value=({0x401100: "dwarf"}, {0x401100: "real_name"}),
        ):
            result = discover_functions(lines, set(), binary_path="/tmp/fake")
        target = next((fn for fn in result if fn["addr"] == "0x401100"), None)
        self.assertIsNotNone(target)
        self.assertEqual(target["reason"], "dwarf")
        self.assertEqual(target["name"], "real_name")
        self.assertGreaterEqual(target["confidence_score"], 0.9)

    def test_push_ret_trampoline_is_detected(self):
        """Un push imm; ret doit être détecté comme trampoline."""
        lines = [
            {"addr": "0x401000", "text": "ret", "mnemonic": "ret", "line": 1},
            {
                "addr": "0x401010",
                "text": "push 0x402000",
                "mnemonic": "push",
                "operands": "0x402000",
                "line": 2,
            },
            {"addr": "0x401015", "text": "ret", "mnemonic": "ret", "line": 3},
            {"addr": "0x402000", "text": "ret", "mnemonic": "ret", "line": 4},
        ]
        result = discover_functions(lines, set())
        thunk = next((fn for fn in result if fn["addr"] == "0x401010"), None)
        self.assertIsNotNone(thunk)
        self.assertEqual(thunk["reason"], "trampoline")
        self.assertEqual(thunk["kind"], "thunk")
        self.assertEqual(thunk["target_addr"], "0x402000")
        self.assertEqual(thunk["boundary_reason"], "coverage")

    def test_register_trampoline_is_detected(self):
        """Un mov imm; jmp reg doit être détecté comme trampoline."""
        lines = [
            {"addr": "0x401000", "text": "ret", "mnemonic": "ret", "line": 1},
            {
                "addr": "0x401010",
                "text": "mov eax, 0x402000",
                "mnemonic": "mov",
                "operands": "eax, 0x402000",
                "line": 2,
            },
            {
                "addr": "0x401015",
                "text": "jmp eax",
                "mnemonic": "jmp",
                "operands": "eax",
                "line": 3,
            },
            {"addr": "0x402000", "text": "ret", "mnemonic": "ret", "line": 4},
        ]
        result = discover_functions(lines, set())
        thunk = next((fn for fn in result if fn["addr"] == "0x401010"), None)
        self.assertIsNotNone(thunk)
        self.assertEqual(thunk["reason"], "trampoline")
        self.assertEqual(thunk["kind"], "thunk")
        self.assertEqual(thunk["target_addr"], "0x402000")
        self.assertGreaterEqual(thunk["confidence_score"], 0.84)

    def test_estimate_function_bounds_can_stop_at_next_start(self):
        """L'estimateur doit savoir fermer une fonction au prochain start connu."""
        lines = [
            {
                "addr": "0x401000",
                "text": "push rbp",
                "mnemonic": "push",
                "operands": "rbp",
                "line": 1,
            },
            {
                "addr": "0x401001",
                "text": "mov eax, 1",
                "mnemonic": "mov",
                "operands": "eax, 1",
                "line": 2,
            },
            {
                "addr": "0x401010",
                "text": "push rbp",
                "mnemonic": "push",
                "operands": "rbp",
                "line": 5,
            },
            {"addr": "0x401011", "text": "ret", "mnemonic": "ret", "line": 6},
        ]
        end_addr, size, reason = _estimate_function_bounds(
            lines,
            0x401000,
            [0x401000, 0x401010],
        )
        self.assertEqual(end_addr, 0x401010)
        self.assertEqual(size, 0x10)
        self.assertEqual(reason, "next_start")

    def test_arm32_prologue_is_detected_as_function_start(self):
        """Une entrée ARM32 push/add/bl/pop doit être reconnue comme fonction."""
        lines = [
            {
                "addr": "0x700000",
                "text": "push {fp, lr}",
                "mnemonic": "push",
                "operands": "{fp, lr}",
                "bytes": "00 48 2d e9",
                "line": 1,
            },
            {
                "addr": "0x700004",
                "text": "add fp, sp, #4",
                "mnemonic": "add",
                "operands": "fp, sp, #4",
                "bytes": "04 b0 8d e2",
                "line": 2,
            },
            {
                "addr": "0x700008",
                "text": "bl #0x700010",
                "mnemonic": "bl",
                "operands": "#0x700010",
                "bytes": "00 00 00 eb",
                "line": 3,
            },
            {
                "addr": "0x70000c",
                "text": "pop {fp, pc}",
                "mnemonic": "pop",
                "operands": "{fp, pc}",
                "bytes": "00 88 bd e8",
                "line": 4,
            },
            {
                "addr": "0x700010",
                "text": "bx lr",
                "mnemonic": "bx",
                "operands": "lr",
                "bytes": "1e ff 2f e1",
                "line": 5,
            },
        ]
        result = discover_functions(lines, set())
        entry = next((fn for fn in result if fn["addr"] == "0x700000"), None)
        target = next((fn for fn in result if fn["addr"] == "0x700010"), None)
        self.assertIsNotNone(entry)
        self.assertEqual(entry["reason"], "push lr")
        self.assertEqual(entry["kind"], "function")
        self.assertEqual(entry["end_addr"], "0x700010")
        self.assertEqual(entry["boundary_reason"], "coverage")
        self.assertIsNotNone(target)
        self.assertEqual(target["reason"], "call_target")


class TestDiscoveryMetrics(unittest.TestCase):
    def test_precision_metrics_report_false_positives_and_overlaps(self):
        discovered = [
            {"addr": "0x401000", "end_addr": "0x401010"},
            {"addr": "0x401008", "end_addr": "0x401014"},
            {"addr": "0x401100", "end_addr": "0x401110"},
        ]
        metrics = evaluate_function_discovery(
            discovered,
            {"0x401000", "0x401100"},
        )
        self.assertEqual(metrics["expected_count"], 2)
        self.assertEqual(metrics["discovered_count"], 3)
        self.assertEqual(metrics["true_positive_count"], 2)
        self.assertEqual(metrics["false_positive_count"], 1)
        self.assertEqual(metrics["missed_count"], 0)
        self.assertEqual(metrics["precision"], 0.667)
        self.assertEqual(metrics["recall"], 1.0)
        self.assertEqual(metrics["overlap_count"], 1)
        self.assertEqual(metrics["false_positive"], ["0x401008"])


if __name__ == "__main__":
    unittest.main()
