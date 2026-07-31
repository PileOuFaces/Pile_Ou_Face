#!/usr/bin/env python3
"""Run the auto-triage backend tests and enforce feature-level coverage."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

from coverage import Coverage


ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

MINIMUM_COVERAGE = 80.0
DATA_FILE = ".coverage.auto-triage"


def main() -> int:
    coverage = Coverage(branch=True, source=["backends/mcp"], data_file=DATA_FILE)
    coverage.erase()
    coverage.start()
    suite = unittest.defaultTestLoader.loadTestsFromName("backends.static.tests.test_auto_triage")
    result = unittest.TextTestRunner(verbosity=1, buffer=True).run(suite)
    coverage.stop()
    coverage.save()
    if not result.wasSuccessful():
        return 1
    total = coverage.report(
        morfs=["backends/mcp/auto_triage.py"],
        show_missing=True,
    )
    return 0 if total >= MINIMUM_COVERAGE else 1


if __name__ == "__main__":
    sys.exit(main())
