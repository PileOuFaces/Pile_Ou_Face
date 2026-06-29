# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour tools.static.strings (CLI extraction strings)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.search.strings import main
from backends.static.tests.util import compile_minimal_elf


class TestStringsMain(unittest.TestCase):
    """Tests du CLI extraction strings."""

    def test_nonexistent_binary_returns_zero(self):
        old_argv = sys.argv
        try:
            sys.argv = ["strings", "--binary", "/nonexistent/binary"]
            result = main()
        finally:
            sys.argv = old_argv
        self.assertEqual(result, 0)

    def test_real_binary(self):
        """Compile un binaire minimal, extrait les strings via CLI, supprime à la fin."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            out_json = Path(tmp) / "strings.json"
            old_argv = sys.argv
            try:
                sys.argv = [
                    "strings",
                    "--binary",
                    str(binary),
                    "--output",
                    str(out_json),
                ]
                result = main()
            finally:
                sys.argv = old_argv
            self.assertEqual(result, 0)
            self.assertTrue(out_json.exists())


if __name__ == "__main__":
    unittest.main()
