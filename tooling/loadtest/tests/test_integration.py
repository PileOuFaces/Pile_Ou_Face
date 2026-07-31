# SPDX-License-Identifier: AGPL-3.0-only
"""Test bout-en-bout léger : une seule fixture (small), un seul scénario
(strings, le plus rapide), pour vérifier que le pipeline complet
(génération -> exécution mesurée -> rapport) fonctionne réellement, sans
faire tourner la matrice complète (trop lent pour une suite de tests normale)."""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
HAS_CC = shutil.which("cc") is not None


@unittest.skipUnless(HAS_CC, "cc introuvable")
class TestEndToEnd(unittest.TestCase):
    def test_rejects_non_positive_safety_guards(self):
        for flag in ("--memory-limit-mib", "--timeout-cap-s"):
            with self.subTest(flag=flag):
                result = subprocess.run(
                    [sys.executable, "-m", "tooling.loadtest", flag, "0"],
                    cwd=str(REPO_ROOT),
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 2)
                self.assertIn("strictement positif", result.stderr)

    def test_external_binary_requires_a_budget_profile(self):
        result = subprocess.run(
            [sys.executable, "-m", "tooling.loadtest", "--binary", sys.executable],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("requiert --size", result.stderr)

    def test_external_binary_is_measured_and_identified(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "external.bin"
            binary.write_bytes(b"POF-real-corpus\x00" * 1024)
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tooling.loadtest",
                    "--binary",
                    str(binary),
                    "--scenario",
                    "strings",
                    "--size",
                    "small",
                    "--results-dir",
                    tmp,
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            reports = list(Path(tmp).glob("loadtest_*.json"))
            self.assertEqual(len(reports), 1)
            metadata = json.loads(reports[0].read_text())["metadata"]
            self.assertEqual(metadata["fixture_kind"], "external")
            self.assertEqual(metadata["fixture_name"], "external.bin")
            self.assertEqual(len(metadata["fixture_sha256"]), 64)

    def test_single_scenario_single_fixture_produces_a_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "tooling.loadtest",
                    "--scenario",
                    "strings",
                    "--size",
                    "small",
                    "--results-dir",
                    tmp,
                ],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("strings", result.stdout)
            self.assertIn("small", result.stdout)
            reports = list(Path(tmp).glob("loadtest_*.json"))
            self.assertEqual(len(reports), 1)
            payload = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual(payload["schema_version"], 3)
            self.assertIn(payload["results"][0]["status"], {"ok", "warning"})
            self.assertIn("os", payload["metadata"])


if __name__ == "__main__":
    unittest.main()
