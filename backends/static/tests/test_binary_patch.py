# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for binary_patch.py — patch bytes in binary files."""

import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)


def _load_make_elf():
    here = os.path.dirname(os.path.abspath(__file__))
    spec = importlib.util.spec_from_file_location(
        "make_elf",
        os.path.join(here, "fixtures", "make_elf.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


make_minimal_elf = _load_make_elf().make_minimal_elf


def run_patch(args):
    import os

    env = {**os.environ, "PYTHONPATH": ROOT}
    r = subprocess.run(
        [sys.executable, "backends/static/patch/binary_patch.py"] + args,
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
    )
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(f"binary_patch.py failed:\n{r.stderr}")
    return json.loads(r.stdout)


class TestBinaryPatch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = os.path.join(self.tmp, "test.elf")
        make_minimal_elf(self.binary)

    def test_patch_and_verify(self):
        result = run_patch(["--binary", self.binary, "--offset", "0", "--bytes", "90 90 90 90"])
        self.assertTrue(result.get("ok"), msg=f"Patch failed: {result}")
        with open(self.binary, "rb") as f:
            data = f.read(4)
        self.assertEqual(data, b"\x90\x90\x90\x90")

    def test_patch_out_of_range(self):
        size = os.path.getsize(self.binary)
        result = run_patch(
            [
                "--binary",
                self.binary,
                "--offset",
                str(size + 10),
                "--bytes",
                "ff",
            ]
        )
        self.assertFalse(result.get("ok"), msg=f"Expected failure: {result}")
        self.assertIn("error", result)


if __name__ == "__main__":
    unittest.main()
