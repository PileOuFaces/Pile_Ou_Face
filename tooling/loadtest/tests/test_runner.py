# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loadtest.runner import parse_time_output_macos, parse_time_output_linux, run_measured


class TestParseTimeOutput(unittest.TestCase):
    def test_parses_macos_peak_memory_footprint(self):
        sample = (
            "        0.10 real         0.00 user         0.00 sys\n"
            "             1212416  maximum resident set size\n"
            "                   0  average shared memory size\n"
            "              917720  peak memory footprint\n"
        )
        result = parse_time_output_macos(sample)
        self.assertEqual(result["peak_rss_bytes"], 917720)
        self.assertAlmostEqual(result["elapsed_s"], 0.10)

    def test_falls_back_to_max_rss_when_footprint_absent(self):
        sample = (
            "        0.05 real         0.00 user         0.00 sys\n"
            "             500000  maximum resident set size\n"
        )
        result = parse_time_output_macos(sample)
        self.assertEqual(result["peak_rss_bytes"], 500000)

    def test_parses_linux_output_and_converts_kb_to_bytes(self):
        sample = (
            "\tElapsed (wall clock) time (h:mm:ss or m:ss): 0:00.12\n"
            "\tMaximum resident set size (kbytes): 2048\n"
        )
        result = parse_time_output_linux(sample)
        self.assertEqual(result["peak_rss_bytes"], 2048 * 1024)
        self.assertAlmostEqual(result["elapsed_s"], 0.12, places=2)


class TestRunMeasured(unittest.TestCase):
    def test_runs_a_real_command_and_returns_positive_measurements(self):
        result = run_measured([sys.executable, "-c", "x = [0] * 1000000"], timeout_s=30)
        self.assertEqual(result["returncode"], 0)
        self.assertGreater(result["peak_rss_bytes"], 0)
        self.assertGreaterEqual(result["elapsed_s"], 0)

    def test_captures_nonzero_exit_code_without_raising(self):
        result = run_measured([sys.executable, "-c", "import sys; sys.exit(3)"], timeout_s=30)
        self.assertEqual(result["returncode"], 3)

    def test_times_out_gracefully(self):
        result = run_measured([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=1)
        self.assertTrue(result["timed_out"])


if __name__ == "__main__":
    unittest.main()
