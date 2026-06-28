# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
import os
import subprocess
import sys
import tempfile

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)


def _load_make_elf():
    spec = importlib.util.spec_from_file_location(
        "make_elf", os.path.join(os.path.dirname(__file__), "fixtures", "make_elf.py")
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


make_minimal_elf = _load_make_elf().make_minimal_elf


def run_pm(args):
    import os

    env = {**os.environ, "PYTHONPATH": ROOT}
    r = subprocess.run(
        [sys.executable, "backends/static/patch/patch_manager.py"] + args,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    return json.loads(r.stdout)


import unittest


class TestPatchManager(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = os.path.join(self.tmp, "test.elf")
        make_minimal_elf(self.binary)

    def test_list_empty(self):
        result = run_pm(["list", "--binary", self.binary])
        self.assertEqual(result["patches"], [])
        self.assertEqual(result["redo_patches"], [])

    def test_apply_and_list(self):
        run_pm(["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"])
        result = run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(result["patches"]), 1)
        self.assertEqual(result["patches"][0]["patched_bytes"], "90 90")
        self.assertEqual(result["patches"][0]["offset"], 0)

    def test_revert_restores_bytes(self):
        with open(self.binary, "rb") as f:
            original = f.read(2)
        run_pm(["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"])
        patches = run_pm(["list", "--binary", self.binary])["patches"]
        patch_id = patches[0]["id"]
        run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        with open(self.binary, "rb") as f:
            restored = f.read(2)
        self.assertEqual(original, restored)
        listed = run_pm(["list", "--binary", self.binary])
        self.assertEqual(listed["patches"], [])
        self.assertEqual(len(listed["redo_patches"]), 1)

    def test_redo_reapplies_last_reverted_patch(self):
        with open(self.binary, "rb") as f:
            original = f.read(2)
        run_pm(["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"])
        patch_id = run_pm(["list", "--binary", self.binary])["patches"][0]["id"]
        run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        run_pm(["redo", "--binary", self.binary])
        with open(self.binary, "rb") as f:
            redone = f.read(2)
        self.assertEqual(redone, bytes.fromhex("90 90"))
        listed = run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(listed["patches"]), 1)
        self.assertEqual(listed["redo_patches"], [])
        self.assertNotEqual(redone, original)

    def test_apply_clears_redo_stack(self):
        run_pm(["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"])
        patch_id = run_pm(["list", "--binary", self.binary])["patches"][0]["id"]
        run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        run_pm(["apply", "--binary", self.binary, "--offset", "2", "--bytes", "cc cc"])
        listed = run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(listed["patches"]), 1)
        self.assertEqual(listed["redo_patches"], [])

    def test_revert_all(self):
        with open(self.binary, "rb") as f:
            original = f.read(4)
        run_pm(["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"])
        run_pm(["apply", "--binary", self.binary, "--offset", "2", "--bytes", "cc cc"])
        run_pm(["revert-all", "--binary", self.binary])
        with open(self.binary, "rb") as f:
            restored = f.read(4)
        self.assertEqual(original, restored)
        result = run_pm(["list", "--binary", self.binary])
        self.assertEqual(result["patches"], [])
        self.assertEqual(len(result["redo_patches"]), 2)


if __name__ == "__main__":
    unittest.main()
