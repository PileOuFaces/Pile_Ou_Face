# SPDX-License-Identifier: AGPL-3.0-only
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from loadtest.scenarios import FIXTURE_PROFILES, SCENARIOS


class TestFixtureProfiles(unittest.TestCase):
    def test_has_small_medium_large(self):
        names = {p.name for p in FIXTURE_PROFILES}
        self.assertEqual(names, {"small", "medium", "large"})

    def test_sizes_strictly_increase(self):
        by_name = {p.name: p for p in FIXTURE_PROFILES}
        self.assertLess(by_name["small"].padding_bytes, by_name["medium"].padding_bytes)
        self.assertLess(by_name["medium"].padding_bytes, by_name["large"].padding_bytes)


class TestScenarioRegistry(unittest.TestCase):
    def test_has_at_least_disasm_and_strings(self):
        names = {s.name for s in SCENARIOS}
        self.assertIn("disasm", names)
        self.assertIn("strings", names)

    def test_each_scenario_builds_args_referencing_the_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary_path = Path(tmp) / "target.bin"
            binary_path.write_bytes(b"\x00")
            out_dir = Path(tmp) / "out"
            out_dir.mkdir()
            for scenario in SCENARIOS:
                args = scenario.build_args(binary_path, out_dir)
                self.assertIn(str(binary_path), args, f"{scenario.name} doit référencer le binaire")
                self.assertTrue(scenario.script, f"{scenario.name} doit avoir un script")


if __name__ == "__main__":
    unittest.main()
