# SPDX-License-Identifier: AGPL-3.0-only
"""Tests des reprises ciblées contre le bruit des runners CI."""

import unittest
from unittest.mock import Mock

from tooling.loadtest.__main__ import _confirm_baseline_regression
from tooling.loadtest.report import Baseline, Budget, Result


BUDGET = Budget(2000, 3000, 5.0, 10.0)
BASELINE = Baseline(1000, 1.0)


def result(elapsed_s: float, *, rss: int = 1000) -> Result:
    return Result("sections", "medium", 100, rss, elapsed_s, 0, False)


class TestTargetedRetry(unittest.TestCase):
    def test_does_not_retry_a_passing_measurement(self):
        measure = Mock(return_value=result(1.0))
        final, retries = _confirm_baseline_regression(
            result(1.0), measure, BUDGET, BASELINE, None
        )
        self.assertEqual(final.elapsed_s, 1.0)
        self.assertEqual(retries, 0)
        measure.assert_not_called()

    def test_retries_baseline_failure_and_uses_median(self):
        measure = Mock(side_effect=[result(1.0), result(1.1)])
        final, retries = _confirm_baseline_regression(
            result(1.6), measure, BUDGET, BASELINE, None
        )
        self.assertEqual(final.elapsed_s, 1.1)
        self.assertEqual(retries, 2)
        self.assertEqual(measure.call_count, 2)

    def test_does_not_retry_an_absolute_budget_failure(self):
        measure = Mock(return_value=result(1.0))
        final, retries = _confirm_baseline_regression(
            result(11.0), measure, BUDGET, BASELINE, None
        )
        self.assertEqual(final.elapsed_s, 11.0)
        self.assertEqual(retries, 0)
        measure.assert_not_called()


if __name__ == "__main__":
    unittest.main()
