# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the Evidence stack-slot size model.

These pin down the "buffer84" bug: a slot whose start address is only ever
materialized by `lea rbp-0x60` (no sized ASM access, no source/DWARF, no
runtime write) must never report a fabricated size of 8 -- 8 is the register
width `lea` happened to use, not the size of anything it points to.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.audit.evidence import (
    _attach_runtime_accesses,
    _finalize_function_slot_sizes,
    _score_slot,
    _slot_from_access,
    _slot_from_frame_entry,
)


def _write_snapshot(rbp: int, write_addr: int, size: int, external_symbol: str = "strcpy") -> dict:
    return {
        "func": "main",
        "cpu": {
            "before": {"registers": {"rbp": hex(rbp)}},
            "after": {"registers": {"rbp": hex(rbp)}},
        },
        "effects": {"kind": "call", "external_symbol": external_symbol, "external_simulated": True},
        "memory": {
            "writes": [
                {"addr": hex(write_addr), "size": size, "bytes": "41" * size, "source": "external"},
            ],
            "reads": [],
        },
    }


class TestEvidenceBufferSize(unittest.TestCase):
    def test_source_c_char_array_reports_exact_size(self):
        """buffer84 with enriched C source: char buf[84] must report size=84
        exact, regardless of what the ASM analysis alone would have found."""
        entry = {
            "offset": -0x54,
            "size": 84,
            "size_is_exact": False,
            "source": "source_c",
            "type": "char[84]",
            "name": "buf",
        }
        slot = _slot_from_frame_entry(entry, "probable_local")
        self.assertEqual(slot["size"], 84)
        self.assertEqual(slot["size_source"], "source_c")

        _finalize_function_slot_sizes({slot["key"]: slot})
        self.assertEqual(slot["size"], 84)
        self.assertEqual(slot["size_confidence"], "exact")

    def test_lea_only_slot_keeps_correct_start_without_a_fabricated_size(self):
        """buffer84 without source/DWARF: the only evidence is a `lea
        rbp-0x60` (as `analyse_stack_frame` reports it: size=8/ptr_size,
        size_is_exact=False). The start offset must stay correct while the
        size must NOT default to 8 -- it should fall back to an estimated
        bound (distance to the saved rbp at offset 0), clearly separate from
        a proven size."""
        entry = {"offset": -0x60, "size": 8, "size_is_exact": False, "source": "auto", "name": "var_60"}
        slot = _slot_from_frame_entry(entry, "probable_local")
        self.assertEqual(slot["offset"], -0x60)
        self.assertIsNone(slot["size"])

        _finalize_function_slot_sizes({slot["key"]: slot})
        self.assertIsNone(slot["size"])
        self.assertEqual(slot["size_source"], "unknown")
        self.assertEqual(slot["estimated_bound"], 0x60)

        # Buffer classification (proven via a known-sink call argument) must
        # stay independent of size: proven start + proven sink is enough to
        # call it a buffer, without needing -- or fabricating -- a size.
        slot["passed_as_call_argument"] = [
            {"call_addr": "0x1000", "target": "strcpy", "argument_index": 0, "register": "rdi"}
        ]
        scored = _score_slot(slot, "main", [])
        self.assertEqual(scored["classification"], "buffer")
        self.assertIsNone(scored["size"])

    def test_strcpy_write_reports_observed_size_but_not_as_the_slot_size(self):
        """strcpy(buf, "A"*43) writes 44 bytes (43 + NUL) into a buffer that
        could be much larger (e.g. 84 bytes): observed_write_size must carry
        the 44, but `size` must stay unset -- a partial write is not proof
        of the whole object's size."""
        rbp = 0x7FFF0000
        offset = -0x60
        slot = _slot_from_access({"base": "rbp", "offset": offset, "expression": "[rbp-0x60]"})
        slots = {slot["key"]: slot}

        snapshot = _write_snapshot(rbp, rbp + offset, size=44, external_symbol="strcpy")
        _attach_runtime_accesses("main", [snapshot], slots, [], [])
        _finalize_function_slot_sizes(slots)

        self.assertEqual(slot["observed_write_size"], 44)
        self.assertIsNone(slot["size"])
        self.assertEqual(slot["size_source"], "unknown")

    def test_read_stdin_reports_observed_size_without_claiming_exact_size(self):
        """read(0, buf, 31) writes exactly 31 bytes, no NUL: observed_write_size
        is 31 (distinct from the strcpy+NUL case), but `size` still must not
        be reported as an exact size from a runtime write alone."""
        rbp = 0x7FFF0000
        offset = -0x40
        slot = _slot_from_access({"base": "rbp", "offset": offset, "expression": "[rbp-0x40]"})
        slots = {slot["key"]: slot}

        snapshot = _write_snapshot(rbp, rbp + offset, size=31, external_symbol="read")
        _attach_runtime_accesses("main", [snapshot], slots, [], [])
        _finalize_function_slot_sizes(slots)

        self.assertEqual(slot["observed_write_size"], 31)
        self.assertIsNone(slot["size"])
        self.assertEqual(slot["size_source"], "unknown")


if __name__ == "__main__":
    unittest.main()
