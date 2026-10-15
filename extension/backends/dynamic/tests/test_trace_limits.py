# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for bounded dynamic trace collection and CLI inputs."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.engine.unicorn.config import (
    DEFAULT_MAX_TRACE_BYTES,
    MAX_USER_TRACE_BYTES,
    MAX_USER_TRACE_STEPS,
)
from backends.dynamic.engine.unicorn.hooks import SnapshotCollector
from backends.dynamic.pipeline.run_pipeline import _main


class FakeUnicorn:
    def __init__(self) -> None:
        self.stopped = False

    def emu_stop(self) -> None:
        self.stopped = True


def _collector(limit: int) -> SnapshotCollector:
    collector = SnapshotCollector.__new__(SnapshotCollector)
    collector._config = SimpleNamespace(max_trace_bytes=limit)
    collector.snapshots = []
    collector.trace_bytes = 0
    collector.trace_limit_reached = False
    collector.step = 0
    return collector


class TestTraceLimits(unittest.TestCase):
    def test_default_trace_budget_is_64_mib(self):
        self.assertEqual(DEFAULT_MAX_TRACE_BYTES, 64 * 1024 * 1024)

    def test_snapshot_that_fits_budget_is_retained(self):
        snapshot = {"step": 1, "instr": "nop"}
        limit = SnapshotCollector._serialized_size(snapshot)
        collector = _collector(limit)
        unicorn = FakeUnicorn()

        retained = collector._retain_snapshot(snapshot, unicorn)

        self.assertTrue(retained)
        self.assertEqual(collector.snapshots, [snapshot])
        self.assertEqual(collector.trace_bytes, limit)
        self.assertEqual(collector.step, 1)
        self.assertFalse(collector.trace_limit_reached)
        self.assertFalse(unicorn.stopped)

    def test_snapshot_exceeding_budget_stops_before_append(self):
        snapshot = {"step": 1, "instr": "nop"}
        collector = _collector(SnapshotCollector._serialized_size(snapshot) - 1)
        unicorn = FakeUnicorn()

        retained = collector._retain_snapshot(snapshot, unicorn)

        self.assertFalse(retained)
        self.assertEqual(collector.snapshots, [])
        self.assertEqual(collector.trace_bytes, 0)
        self.assertEqual(collector.step, 0)
        self.assertTrue(collector.trace_limit_reached)
        self.assertTrue(unicorn.stopped)

    def test_cli_rejects_step_limit_outside_public_range(self):
        for value in ("0", str(MAX_USER_TRACE_STEPS + 1)):
            with self.subTest(value=value), self.assertRaises(SystemExit) as raised:
                _main(["--binary", "unused", "--max-steps", value])
            self.assertEqual(raised.exception.code, 2)

    def test_cli_rejects_trace_byte_limit_outside_public_range(self):
        for value in ("0", str(MAX_USER_TRACE_BYTES + 1)):
            with self.subTest(value=value), self.assertRaises(SystemExit) as raised:
                _main(["--binary", "unused", "--max-trace-bytes", value])
            self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
