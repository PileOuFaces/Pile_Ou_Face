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


def run_pm(args, env_extra=None):
    import os

    env = {**os.environ, "PYTHONPATH": ROOT, **(env_extra or {})}
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
        self.storage = os.path.join(self.tmp, "storage")
        make_minimal_elf(self.binary)

    def run_pm(self, args, *, storage=None):
        return run_pm(
            args,
            {"POF_STORAGE_DIR": storage if storage is not None else self.storage},
        )

    def test_list_empty(self):
        result = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(result["patches"], [])
        self.assertEqual(result["redo_patches"], [])

    def test_apply_and_list(self):
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        result = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(result["patches"]), 1)
        self.assertEqual(result["patches"][0]["patched_bytes"], "90 90")
        self.assertEqual(result["patches"][0]["offset"], 0)

    def test_apply_uses_storage_dir_patches_without_project_pof_dir(self):
        workspace = os.path.join(self.tmp, "workspace")
        nested = os.path.join(workspace, "samples", "bin")
        os.makedirs(nested)
        binary = os.path.join(nested, "nested.elf")
        make_minimal_elf(binary)

        self.run_pm(["apply", "--binary", binary, "--offset", "0", "--bytes", "90 90"])

        patch_dir = os.path.join(self.storage, "patches")
        self.assertTrue(os.path.isdir(patch_dir))
        self.assertEqual(len(os.listdir(patch_dir)), 1)
        self.assertFalse(os.path.exists(os.path.join(workspace, ".pile-ou-face")))
        self.assertFalse(os.path.exists(os.path.join(nested, ".pile-ou-face")))

    def test_apply_without_storage_env_uses_local_patches_dir(self):
        run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"],
            {"POF_STORAGE_DIR": ""},
        )

        patch_dir = os.path.join(self.tmp, "patches")
        self.assertTrue(os.path.isdir(patch_dir))
        self.assertEqual(len(os.listdir(patch_dir)), 1)
        self.assertFalse(os.path.exists(os.path.join(self.tmp, ".pile-ou-face")))

    def test_revert_restores_bytes(self):
        with open(self.binary, "rb") as f:
            original = f.read(2)
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        patches = self.run_pm(["list", "--binary", self.binary])["patches"]
        patch_id = patches[0]["id"]
        self.run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        with open(self.binary, "rb") as f:
            restored = f.read(2)
        self.assertEqual(original, restored)
        listed = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(listed["patches"], [])
        self.assertEqual(len(listed["redo_patches"]), 1)

    def test_redo_reapplies_last_reverted_patch(self):
        with open(self.binary, "rb") as f:
            original = f.read(2)
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        patch_id = self.run_pm(["list", "--binary", self.binary])["patches"][0]["id"]
        self.run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        self.run_pm(["redo", "--binary", self.binary])
        with open(self.binary, "rb") as f:
            redone = f.read(2)
        self.assertEqual(redone, bytes.fromhex("90 90"))
        listed = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(listed["patches"]), 1)
        self.assertEqual(listed["redo_patches"], [])
        self.assertNotEqual(redone, original)

    def test_redo_can_reapply_a_specific_reverted_patch(self):
        with open(self.binary, "rb") as f:
            original = f.read(4)
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "2", "--bytes", "cc cc"]
        )
        patches = self.run_pm(["list", "--binary", self.binary])["patches"]

        self.run_pm(["revert", "--binary", self.binary, "--id", patches[0]["id"]])
        self.run_pm(["revert", "--binary", self.binary, "--id", patches[1]["id"]])
        self.run_pm(["redo", "--binary", self.binary, "--id", patches[0]["id"]])

        with open(self.binary, "rb") as f:
            redone_first = f.read(4)
        self.assertEqual(redone_first[:2], bytes.fromhex("90 90"))
        self.assertEqual(redone_first[2:], original[2:])

        listed = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual([p["id"] for p in listed["patches"]], [patches[0]["id"]])
        self.assertEqual([p["id"] for p in listed["redo_patches"]], [patches[1]["id"]])

    def test_apply_clears_redo_stack(self):
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        patch_id = self.run_pm(["list", "--binary", self.binary])["patches"][0]["id"]
        self.run_pm(["revert", "--binary", self.binary, "--id", patch_id])
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "2", "--bytes", "cc cc"]
        )
        listed = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(listed["patches"]), 1)
        self.assertEqual(listed["redo_patches"], [])

    def test_revert_all(self):
        with open(self.binary, "rb") as f:
            original = f.read(4)
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "2", "--bytes", "cc cc"]
        )
        self.run_pm(["revert-all", "--binary", self.binary])
        with open(self.binary, "rb") as f:
            restored = f.read(4)
        self.assertEqual(original, restored)
        result = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(result["patches"], [])
        self.assertEqual(len(result["redo_patches"]), 2)


if __name__ == "__main__":
    unittest.main()
