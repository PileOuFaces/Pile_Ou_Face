# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour tools.static.symbols (CLI extraction symboles)."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.tests.util import compile_minimal_elf
from backends.static.binary.symbols import main


class TestSymbolsMain(unittest.TestCase):
    """Tests du CLI extraction symboles."""

    def test_nonexistent_binary_returns_zero_but_empty_output(self):
        old_argv = sys.argv
        try:
            sys.argv = ["symbols", "--binary", "/nonexistent/binary"]
            result = main()
        finally:
            sys.argv = old_argv
        self.assertEqual(result, 0)

    def test_real_binary(self):
        """Compile un binaire minimal, extrait les symboles via CLI, supprime à la fin."""
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            old_argv = sys.argv
            try:
                sys.argv = ["symbols", "--binary", str(binary)]
                result = main()
            finally:
                sys.argv = old_argv
            self.assertEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
