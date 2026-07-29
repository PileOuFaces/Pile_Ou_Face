# SPDX-License-Identifier: AGPL-3.0-only
"""Privacy-safe Dynamic observability classification tests."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.run_pipeline import _termination_category


class TestDynamicObservability(unittest.TestCase):
    def test_termination_categories_are_bounded_and_ignore_raw_details(self):
        self.assertEqual(
            _termination_category(
                {"termination_category": "canary_failure"},
                {"classification": "fatal_crash", "reason": "/private/payload"},
                False,
            ),
            "canary_failure",
        )
        self.assertEqual(
            _termination_category({}, {"classification": "fatal_crash"}, False),
            "target_crash",
        )
        self.assertEqual(_termination_category({}, None, True), "instruction_limit")
        self.assertEqual(
            _termination_category(
                {"termination_category": "/private/value"},
                {"classification": "arbitrary exception"},
                False,
            ),
            "normal",
        )


if __name__ == "__main__":
    unittest.main()
