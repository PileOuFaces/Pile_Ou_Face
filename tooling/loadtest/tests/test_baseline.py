# SPDX-License-Identifier: AGPL-3.0-only
import json
import tempfile
import unittest
from pathlib import Path

from tooling.loadtest.baseline import build_baseline, load_baseline


def make_report(rss: int, elapsed: float, *, machine: str = "x86_64"):
    return {
        "metadata": {"machine": machine, "python": "3.11.15"},
        "results": [
            {
                "scenario": "disasm",
                "fixture": "medium",
                "peak_rss_bytes": rss,
                "elapsed_s": elapsed,
            }
        ],
    }


class TestBuildBaseline(unittest.TestCase):
    def test_builds_median_from_three_equivalent_runs(self):
        payload = build_baseline(
            [make_report(100, 1.0), make_report(300, 3.0), make_report(200, 2.0)]
        )

        self.assertEqual(payload["sample_count"], 3)
        self.assertEqual(payload["results"][0]["peak_rss_bytes"], 200)
        self.assertEqual(payload["results"][0]["elapsed_s"], 2.0)

    def test_rejects_less_than_three_runs(self):
        with self.assertRaisesRegex(ValueError, "au moins 3"):
            build_baseline([make_report(100, 1.0), make_report(110, 1.1)])

    def test_rejects_mixed_environments(self):
        reports = [
            make_report(100, 1.0),
            make_report(110, 1.1),
            make_report(120, 1.2, machine="arm64"),
        ]
        with self.assertRaisesRegex(ValueError, "même environnement"):
            build_baseline(reports)

    def test_rejects_different_scenario_sets(self):
        reports = [make_report(100, 1.0) for _ in range(3)]
        reports[-1]["results"][0]["scenario"] = "strings"
        with self.assertRaisesRegex(ValueError, "mêmes scénarios"):
            build_baseline(reports)

    def test_rejects_failed_report(self):
        reports = [make_report(100, 1.0) for _ in range(3)]
        reports[-1]["results"][0]["returncode"] = 1
        with self.assertRaisesRegex(ValueError, "rapport en échec"):
            build_baseline(reports)


class TestLoadBaseline(unittest.TestCase):
    def test_loads_promoted_baseline(self):
        payload = build_baseline([make_report(100, 1.0) for _ in range(3)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            baseline = load_baseline(path)[("disasm", "medium")]

        self.assertEqual(baseline.peak_rss_bytes, 100)
        self.assertEqual(baseline.elapsed_s, 1.0)

    def test_rejects_unpromoted_baseline(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(
                json.dumps({"schema_version": 1, "sample_count": 1, "results": []}),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "non fiable"):
                load_baseline(path)

    def test_rejects_incompatible_runtime(self):
        payload = build_baseline([make_report(100, 1.0) for _ in range(3)])
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "baseline.json"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "architecture incompatible"):
                load_baseline(path, expected_machine="arm64", expected_python="3.11.9")
            with self.assertRaisesRegex(ValueError, "Python incompatible"):
                load_baseline(path, expected_machine="x86_64", expected_python="3.12.0")


if __name__ == "__main__":
    unittest.main()
