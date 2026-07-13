# SPDX-License-Identifier: AGPL-3.0-only
"""Test bout-en-bout léger : une seule fixture (small), un seul scénario
(strings, le plus rapide), pour vérifier que le pipeline complet
(génération -> exécution mesurée -> rapport) fonctionne réellement, sans
faire tourner la matrice complète (trop lent pour une suite de tests normale)."""
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
    def test_single_scenario_single_fixture_produces_a_result(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = subprocess.run(
                [sys.executable, "-m", "tooling.loadtest", "--scenario", "strings", "--size", "small",
                 "--results-dir", tmp],
                cwd=str(REPO_ROOT),
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("strings", result.stdout)
            self.assertIn("small", result.stdout)


if __name__ == "__main__":
    unittest.main()
