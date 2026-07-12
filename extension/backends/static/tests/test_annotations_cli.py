# SPDX-License-Identifier: AGPL-3.0-only
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SCRIPT = ROOT / "backends" / "static" / "annotations" / "annotations.py"


class TestAnnotationsCli(unittest.TestCase):
    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def _run(self, *args):
        env = {**os.environ, "PYTHONPATH": str(ROOT)}
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "--binary",
                self._binary_path,
                "--cache-db",
                self._db_path,
                *args,
            ],
            capture_output=True,
            text=True,
            cwd=str(ROOT),
            env=env,
            check=True,
        )
        return json.loads(result.stdout)

    def test_annotate_returns_grouped_dict(self):
        out = self._run("annotate", "--addr", "0x401000", "--comment", "hi")
        self.assertEqual(out["0x401000"]["comment"], "hi")

    def test_bookmark_then_list_grouped(self):
        self._run(
            "bookmark", "--addr", "0x401000", "--label", "L", "--color", "#123456"
        )
        out = self._run("list", "--grouped")
        self.assertTrue(out["0x401000"]["bookmark"])
        self.assertEqual(out["0x401000"]["bookmarkLabel"], "L")
        self.assertEqual(out["0x401000"]["bookmarkColor"], "#123456")

    def test_delete_bookmark(self):
        self._run("bookmark", "--addr", "0x401000", "--label", "L")
        out = self._run("delete-bookmark", "--addr", "0x401000")
        self.assertNotIn("bookmark", out.get("0x401000", {}))

    def test_review(self):
        out = self._run(
            "review", "--addr", "0x401000", "--status", "reviewed", "--notes", "n"
        )
        self.assertEqual(out["0x401000"]["reviewStatus"], "reviewed")
        self.assertEqual(out["0x401000"]["reviewNotes"], "n")

    def test_clear_bookmarks(self):
        self._run("bookmark", "--addr", "0x401000", "--label", "L")
        self._run("annotate", "--addr", "0x401000", "--comment", "kept")
        out = self._run("clear-bookmarks")
        self.assertNotIn("bookmark", out.get("0x401000", {}))
        self.assertEqual(out["0x401000"]["comment"], "kept")

    def test_delete_annotation_preserves_bookmark_and_review(self):
        self._run("annotate", "--addr", "0x401000", "--comment", "c", "--name", "n")
        self._run(
            "bookmark", "--addr", "0x401000", "--label", "L", "--color", "#123456"
        )
        self._run(
            "review", "--addr", "0x401000", "--status", "reviewed", "--notes", "notes"
        )
        out = self._run("delete-annotation", "--addr", "0x401000")
        entry = out["0x401000"]
        self.assertNotIn("comment", entry)
        self.assertNotIn("name", entry)
        self.assertTrue(entry["bookmark"])
        self.assertEqual(entry["bookmarkLabel"], "L")
        self.assertEqual(entry["reviewStatus"], "reviewed")
        self.assertEqual(entry["reviewNotes"], "notes")

    def test_migrate_legacy(self):
        legacy = {"0x401000": {"comment": "old", "name": "old_name"}}
        out = self._run("migrate-legacy", "--json", json.dumps(legacy))
        self.assertEqual(out["0x401000"]["comment"], "old")
        self.assertEqual(out["0x401000"]["name"], "old_name")


if __name__ == "__main__":
    unittest.main()
