# SPDX-License-Identifier: AGPL-3.0-only
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loadtest.report import (  # noqa: E402
    Baseline,
    Budget,
    Result,
    all_ok,
    check_threshold,
    evaluate_result,
    format_summary_table,
    to_json,
)

MIB = 1024 * 1024
BUDGETS = {
    "small": Budget(192 * MIB, 256 * MIB, 1.5, 3.0),
    "medium": Budget(256 * MIB, 384 * MIB, 2.0, 5.0),
    "large": Budget(768 * MIB, 1024 * MIB, 10.0, 30.0),
}


def make_result(**overrides):
    values = {
        "scenario": "disasm",
        "fixture": "medium",
        "binary_size_bytes": 20_000_000,
        "peak_rss_bytes": 100 * MIB,
        "elapsed_s": 0.5,
        "returncode": 0,
        "timed_out": False,
    }
    values.update(overrides)
    return Result(**values)


class TestEvaluateResult(unittest.TestCase):
    def test_within_budget_is_ok(self):
        self.assertEqual(evaluate_result(make_result(), BUDGETS["medium"]).status, "ok")

    def test_warning_is_non_blocking_and_keeps_reasons(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=300 * MIB, elapsed_s=3.0),
            BUDGETS["medium"],
        )
        self.assertEqual(evaluation.status, "warning")
        self.assertEqual(evaluation.reasons, ("rss_warn", "duration_warn"))
        self.assertFalse(evaluation.blocking)

    def test_memory_limit_has_priority_and_reports_duration_too(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=400 * MIB, elapsed_s=6.0),
            BUDGETS["medium"],
        )
        self.assertEqual(evaluation.status, "memory_limit")
        self.assertEqual(evaluation.reasons, ("rss_fail", "duration_fail"))
        self.assertTrue(evaluation.blocking)

    def test_duration_limit_is_blocking(self):
        evaluation = evaluate_result(
            make_result(elapsed_s=5.01),
            BUDGETS["medium"],
        )
        self.assertEqual(evaluation.status, "duration_limit")

    def test_exact_fail_limits_are_allowed(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=384 * MIB, elapsed_s=5.0),
            BUDGETS["medium"],
        )
        self.assertEqual(evaluation.status, "warning")

    def test_crash_and_timeout_have_distinct_statuses(self):
        crash = evaluate_result(make_result(returncode=1), BUDGETS["medium"])
        timeout = evaluate_result(
            make_result(returncode=None, timed_out=True), BUDGETS["medium"]
        )
        self.assertEqual(crash.status, "error")
        self.assertEqual(timeout.status, "timeout")

    def test_process_memory_limit_is_distinct_from_crash(self):
        evaluation = evaluate_result(
            make_result(returncode=1, memory_limited=True), BUDGETS["medium"]
        )
        self.assertEqual(evaluation.status, "memory_limit")
        self.assertEqual(evaluation.reasons, ("process_memory_limit",))

    def test_legacy_ratio_remains_an_optional_extra_gate(self):
        result = make_result(binary_size_bytes=1 * MIB, peak_rss_bytes=20 * MIB)
        without_ratio = evaluate_result(result, BUDGETS["medium"])
        with_ratio = evaluate_result(result, BUDGETS["medium"], max_ratio=10.0)
        self.assertEqual(without_ratio.status, "ok")
        self.assertEqual(with_ratio.status, "memory_limit")
        self.assertIn("ratio_fail", with_ratio.reasons)

    def test_legacy_check_threshold_contract(self):
        result = make_result(binary_size_bytes=1 * MIB, peak_rss_bytes=20 * MIB)
        self.assertEqual(check_threshold(result, max_ratio=10.0), "exceeded")

    def test_baseline_warning_at_more_than_twenty_percent(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=121 * MIB, elapsed_s=1.21),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 1.0),
        )
        self.assertEqual(evaluation.status, "warning")
        self.assertEqual(
            evaluation.reasons,
            ("rss_regression_warn", "duration_regression_warn"),
        )

    def test_baseline_failure_at_more_than_thirty_five_percent(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=136 * MIB),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 0.5),
        )
        self.assertEqual(evaluation.status, "regression_limit")
        self.assertEqual(evaluation.reasons, ("rss_regression_fail",))
        self.assertTrue(evaluation.blocking)

    def test_subsecond_duration_jitter_does_not_block(self):
        evaluation = evaluate_result(
            make_result(elapsed_s=0.527),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 0.39),
        )
        self.assertEqual(evaluation.status, "warning")
        self.assertEqual(evaluation.reasons, ("duration_regression_warn",))

    def test_meaningful_duration_regression_still_blocks(self):
        evaluation = evaluate_result(
            make_result(elapsed_s=0.91),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 0.39),
        )
        self.assertEqual(evaluation.status, "regression_limit")
        self.assertEqual(evaluation.reasons, ("duration_regression_fail",))

    def test_short_command_runner_jitter_does_not_block(self):
        evaluation = evaluate_result(
            make_result(elapsed_s=1.17),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 0.81),
        )
        self.assertEqual(evaluation.status, "warning")
        self.assertEqual(evaluation.reasons, ("duration_regression_warn",))

    def test_exact_baseline_limits_are_allowed(self):
        evaluation = evaluate_result(
            make_result(peak_rss_bytes=135 * MIB, elapsed_s=1.35),
            BUDGETS["medium"],
            baseline=Baseline(100 * MIB, 1.0),
        )
        self.assertEqual(evaluation.status, "warning")


class TestAllOk(unittest.TestCase):
    def test_warnings_pass_but_limits_fail(self):
        warning = make_result(peak_rss_bytes=300 * MIB)
        failure = make_result(peak_rss_bytes=400 * MIB)
        self.assertTrue(all_ok([warning], BUDGETS))
        self.assertFalse(all_ok([warning, failure], BUDGETS))

    def test_empty_list_returns_true(self):
        self.assertTrue(all_ok([], BUDGETS))

    def test_scenario_budget_override_is_targeted(self):
        slow_entropy = make_result(scenario="entropy", elapsed_s=6.0)
        slow_disasm = make_result(scenario="disasm", elapsed_s=6.0)
        overrides = {("entropy", "medium"): Budget(256 * MIB, 384 * MIB, 4.0, 8.0)}

        self.assertTrue(all_ok([slow_entropy], BUDGETS, scenario_budgets=overrides))
        self.assertFalse(all_ok([slow_disasm], BUDGETS, scenario_budgets=overrides))

    def test_baseline_regression_is_blocking(self):
        baselines = {("disasm", "medium"): Baseline(100 * MIB, 1.0)}
        self.assertFalse(
            all_ok(
                [make_result(peak_rss_bytes=140 * MIB)],
                BUDGETS,
                baselines=baselines,
            )
        )


class TestFormatting(unittest.TestCase):
    def test_json_contains_metadata_budgets_status_and_ratio(self):
        payload = json.loads(
            to_json(
                [make_result()],
                BUDGETS,
                {"commit": "abc", "python": "3.11"},
            )
        )
        self.assertEqual(payload["schema_version"], 3)
        self.assertEqual(payload["metadata"]["commit"], "abc")
        self.assertEqual(payload["results"][0]["status"], "ok")
        self.assertEqual(payload["results"][0]["budget"]["fail_duration_s"], 5.0)
        self.assertGreater(payload["results"][0]["rss_ratio"], 0)
        self.assertEqual(payload["regression_thresholds"]["warn_ratio"], 1.2)

    def test_summary_table_includes_explicit_status(self):
        table = format_summary_table(
            [make_result(elapsed_s=6.0)],
            BUDGETS,
        )
        self.assertIn("disasm", table)
        self.assertIn("duration_limit", table)

    def test_json_and_summary_use_scenario_override(self):
        result = make_result(scenario="entropy", elapsed_s=6.0)
        overrides = {("entropy", "medium"): Budget(256 * MIB, 384 * MIB, 4.0, 8.0)}

        payload = json.loads(
            to_json(
                [result],
                BUDGETS,
                {},
                scenario_budgets=overrides,
            )
        )
        table = format_summary_table([result], BUDGETS, scenario_budgets=overrides)

        self.assertEqual(payload["results"][0]["budget"]["fail_duration_s"], 8.0)
        self.assertEqual(payload["results"][0]["status"], "warning")
        self.assertIn("warning", table)

    def test_json_exposes_baseline_ratios(self):
        baselines = {("disasm", "medium"): Baseline(100 * MIB, 0.5)}
        payload = json.loads(to_json([make_result()], BUDGETS, {}, baselines=baselines))
        row = payload["results"][0]

        self.assertEqual(row["baseline"]["peak_rss_bytes"], 100 * MIB)
        self.assertEqual(row["baseline_rss_ratio"], 1.0)
        self.assertEqual(row["baseline_duration_ratio"], 1.0)


if __name__ == "__main__":
    unittest.main()
