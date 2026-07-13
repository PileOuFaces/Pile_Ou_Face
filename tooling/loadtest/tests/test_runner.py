# SPDX-License-Identifier: AGPL-3.0-only
import os
import sys
import tempfile
import time
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
        self.assertGreater(result["peak_rss_bytes"], 5_000_000)
        self.assertGreaterEqual(result["elapsed_s"], 0)

    def test_captures_nonzero_exit_code_without_raising(self):
        result = run_measured([sys.executable, "-c", "import sys; sys.exit(3)"], timeout_s=30)
        self.assertEqual(result["returncode"], 3)

    def test_times_out_gracefully(self):
        result = run_measured([sys.executable, "-c", "import time; time.sleep(5)"], timeout_s=1)
        self.assertTrue(result["timed_out"])

    def test_timeout_actually_kills_the_underlying_process(self):
        # Regression test: run_measured wraps the target command with
        # /usr/bin/time. A naive subprocess.run(timeout=...) only kills the
        # direct child (/usr/bin/time), leaving the actual analyzed command
        # (its grandchild) running in the background after a timeout. This
        # test writes the grandchild's pid to a file immediately, then makes
        # it sleep well past the timeout; if the fix is correct, the whole
        # process group is killed and the pid is dead shortly after
        # run_measured returns.
        with tempfile.TemporaryDirectory() as tmpdir:
            marker = Path(tmpdir) / "marker"
            pidfile = Path(tmpdir) / "pid"
            script = (
                "import os, time\n"
                f"open({str(pidfile)!r}, 'w').write(str(os.getpid()))\n"
                "time.sleep(3)\n"
                f"open({str(marker)!r}, 'w').write('done')\n"
            )
            result = run_measured([sys.executable, "-c", script], timeout_s=1)
            self.assertTrue(result["timed_out"])

            # give the OS a brief moment to finish tearing down the process
            deadline = time.monotonic() + 2
            pid = None
            while time.monotonic() < deadline:
                if pidfile.exists() and pidfile.read_text():
                    pid = int(pidfile.read_text())
                    break
                time.sleep(0.05)
            self.assertIsNotNone(pid, "child process never started")

            deadline = time.monotonic() + 2
            alive = True
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except ProcessLookupError:
                    alive = False
                    break
                time.sleep(0.05)

            self.assertFalse(alive, "underlying process was not killed on timeout")
            # It should not have survived long enough to write the marker.
            self.assertFalse(marker.exists())

    def test_large_stdout_does_not_hang_or_blow_up(self):
        # Regression test: capture_output=True buffered stdout that was
        # never used, holding megabytes of unused data in memory and risking
        # deadlock on large output. stdout should be discarded (DEVNULL) so
        # this completes quickly regardless of output size.
        script = "import sys; sys.stdout.write('x' * (5 * 1024 * 1024))"
        start = time.monotonic()
        result = run_measured([sys.executable, "-c", script], timeout_s=30)
        elapsed = time.monotonic() - start
        self.assertEqual(result["returncode"], 0)
        self.assertLess(elapsed, 10)
        self.assertNotIn("stdout", result)


if __name__ == "__main__":
    unittest.main()
