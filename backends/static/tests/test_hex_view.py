# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.search.hex_view."""

import importlib.util
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def run(args):
    """Run hex_view.py as a subprocess and return parsed JSON output."""
    import os

    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    r = subprocess.run(
        [sys.executable, "backends/static/search/hex_view.py"] + args,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env=env,
    )
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(f"hex_view.py failed:\n{r.stderr}")
    return json.loads(r.stdout)


class TestHexView(unittest.TestCase):
    """Tests du dump hexadécimal de hex_view.py."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = str(Path(self.tmp) / "test.elf")
        make_minimal_elf(self.binary)

    def test_basic_dump(self):
        """Vérifie la structure de base des lignes de dump."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "64"])
        self.assertIn("rows", data)
        self.assertGreater(len(data["rows"]), 0)
        row = data["rows"][0]
        self.assertIn("offset", row)
        self.assertIn("hex", row)
        self.assertIn("ascii", row)
        self.assertEqual(len(row["hex"].split()), 16)

    def test_ascii_column(self):
        """Vérifie que la colonne ascii contient des caractères valides."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "16"])
        self.assertGreater(len(data["rows"]), 0)
        row = data["rows"][0]
        self.assertTrue("." in row["ascii"] or row["ascii"].isprintable())

    def test_sections(self):
        """Vérifie que la liste de sections est présente et bien formée."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "16"])
        self.assertIn("sections", data)
        self.assertIsInstance(data["sections"], list)

    def test_exposes_layout_metadata(self):
        """Le dump expose endian, ptr_size et bits pour synchroniser les vues."""
        data = run(["--binary", self.binary, "--offset", "0", "--length", "16"])
        self.assertEqual(data.get("endianness"), "little")
        self.assertEqual(data.get("ptr_size"), 8)
        self.assertEqual(data.get("bits"), 64)
        self.assertTrue(data.get("arch"))

    def test_out_of_range(self):
        """Un offset hors limites doit retourner une liste de lignes vide."""
        data = run(["--binary", self.binary, "--offset", "99999999", "--length", "16"])
        self.assertEqual(data["rows"], [])

    def test_raw_profile_exposes_thumb_metadata_even_without_lief_sections(self):
        with tempfile.NamedTemporaryFile(delete=False) as raw:
            raw.write(bytes.fromhex("00b500f005f800bd00bf00bf00bf00bf7047"))
            raw_path = raw.name
        try:
            data = run(
                [
                    "--binary",
                    raw_path,
                    "--offset",
                    "0",
                    "--length",
                    "16",
                    "--raw-base-addr",
                    "0x710000",
                    "--raw-arch",
                    "thumb",
                    "--raw-endian",
                    "little",
                ]
            )
            self.assertEqual(data.get("arch"), "thumb")
            self.assertEqual(data.get("bits"), 32)
            self.assertEqual(data.get("ptr_size"), 4)
            self.assertEqual(data.get("endianness"), "little")
            self.assertEqual(data.get("sections")[0]["name"], "raw")
            self.assertEqual(data.get("sections")[0]["offset"], 0)
            self.assertEqual(data.get("sections")[0]["virtual_address"], 0x710000)
            self.assertGreater(len(data.get("rows", [])), 0)
        finally:
            Path(raw_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
