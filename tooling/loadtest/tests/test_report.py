# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loadtest.report import Result, check_threshold, format_summary_table, to_json


class TestCheckThreshold(unittest.TestCase):
    def test_within_threshold_is_ok(self):
        result = Result(scenario="disasm", fixture="small", binary_size_bytes=1_000_000,
                         peak_rss_bytes=5_000_000, elapsed_s=0.5, returncode=0, timed_out=False)
        status = check_threshold(result, max_ratio=10.0)
        self.assertEqual(status, "ok")

    def test_exceeding_threshold_is_flagged(self):
        result = Result(scenario="disasm", fixture="large", binary_size_bytes=1_000_000,
                         peak_rss_bytes=50_000_000, elapsed_s=0.5, returncode=0, timed_out=False)
        status = check_threshold(result, max_ratio=10.0)
        self.assertEqual(status, "exceeded")

    def test_crash_is_flagged_regardless_of_ratio(self):
        result = Result(scenario="disasm", fixture="small", binary_size_bytes=1_000_000,
                         peak_rss_bytes=0, elapsed_s=0.1, returncode=1, timed_out=False)
        status = check_threshold(result, max_ratio=10.0)
        self.assertEqual(status, "error")

    def test_timeout_is_flagged(self):
        result = Result(scenario="disasm", fixture="large", binary_size_bytes=1_000_000,
                         peak_rss_bytes=0, elapsed_s=120.0, returncode=None, timed_out=True)
        status = check_threshold(result, max_ratio=10.0)
        self.assertEqual(status, "timeout")


class TestFormatting(unittest.TestCase):
    def test_json_roundtrip(self):
        result = Result(scenario="strings", fixture="medium", binary_size_bytes=20_000_000,
                         peak_rss_bytes=40_000_000, elapsed_s=1.2, returncode=0, timed_out=False)
        payload = to_json([result])
        self.assertIn("strings", payload)
        self.assertIn("medium", payload)

    def test_summary_table_includes_status_column(self):
        result = Result(scenario="disasm", fixture="small", binary_size_bytes=1_000_000,
                         peak_rss_bytes=5_000_000, elapsed_s=0.5, returncode=0, timed_out=False)
        table = format_summary_table([result], max_ratio=10.0)
        self.assertIn("disasm", table)
        self.assertIn("ok", table)


if __name__ == "__main__":
    unittest.main()
