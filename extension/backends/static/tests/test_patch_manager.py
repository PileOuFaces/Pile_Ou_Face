# SPDX-License-Identifier: AGPL-3.0-only
import importlib.util
import json
import os
import sqlite3
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
        self.db_path = os.path.join(self.tmp, "patches.db")
        make_minimal_elf(self.binary)

    def run_pm(self, args, *, storage=None):
        return run_pm(
            args,
            {"POF_PATCHES_DB": storage if storage is not None else self.db_path},
        )

    def test_list_empty(self):
        result = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(result["patches"], [])
        self.assertEqual(result["redo_patches"], [])

    def test_apply_rejects_empty_bytes_without_touching_binary(self):
        with open(self.binary, "rb") as binary_file:
            original = binary_file.read()

        result = self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", " "]
        )

        self.assertFalse(result["ok"])
        with open(self.binary, "rb") as binary_file:
            self.assertEqual(binary_file.read(), original)

    def test_apply_and_list(self):
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"]
        )
        result = self.run_pm(["list", "--binary", self.binary])
        self.assertEqual(len(result["patches"]), 1)
        self.assertEqual(result["patches"][0]["patched_bytes"], "90 90")
        self.assertEqual(result["patches"][0]["offset"], 0)

    def test_apply_uses_sqlite_without_project_patch_directory(self):
        workspace = os.path.join(self.tmp, "workspace")
        nested = os.path.join(workspace, "samples", "bin")
        os.makedirs(nested)
        binary = os.path.join(nested, "nested.elf")
        make_minimal_elf(binary)

        self.run_pm(["apply", "--binary", binary, "--offset", "0", "--bytes", "90 90"])

        self.assertTrue(os.path.isfile(self.db_path))
        self.assertFalse(os.path.exists(os.path.join(self.storage, "patches")))
        self.assertFalse(os.path.exists(os.path.join(workspace, ".pile-ou-face")))
        self.assertFalse(os.path.exists(os.path.join(nested, ".pile-ou-face")))

    def test_storage_is_normalized_sqlite(self):
        run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90 90"],
            {"POF_PATCHES_DB": self.db_path},
        )

        with sqlite3.connect(self.db_path) as conn:
            tables = {
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            self.assertIn("patch_binaries", tables)
            self.assertIn("binary_patches", tables)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM binary_patches").fetchone()[0], 1
            )

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

    def test_delete_removes_one_binary_history(self):
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90"]
        )

        result = self.run_pm(["delete", "--binary", self.binary])

        self.assertEqual(result, {"ok": True, "removed": 1})
        self.assertEqual(self.run_pm(["list", "--binary", self.binary])["patches"], [])

    def test_purge_missing_is_scoped_to_workspace(self):
        outside_dir = tempfile.mkdtemp()
        outside_binary = os.path.join(outside_dir, "outside.bin")
        make_minimal_elf(outside_binary)
        self.run_pm(
            ["apply", "--binary", self.binary, "--offset", "0", "--bytes", "90"]
        )
        self.run_pm(
            ["apply", "--binary", outside_binary, "--offset", "0", "--bytes", "90"]
        )
        os.unlink(self.binary)
        os.unlink(outside_binary)

        result = self.run_pm(["purge-missing", "--workspace", self.tmp])

        self.assertEqual(result, {"ok": True, "removed": 1})
        with sqlite3.connect(self.db_path) as conn:
            remaining = conn.execute(
                "SELECT binary_path FROM patch_binaries"
            ).fetchall()
        self.assertEqual(remaining, [(os.path.abspath(outside_binary),)])


if __name__ == "__main__":
    unittest.main()
