# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.shared.utils."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.utils import addr_to_int, normalize_addr, validate_addr


class TestNormalizeAddr(unittest.TestCase):
    def test_with_prefix(self):
        self.assertEqual(normalize_addr("0x401000"), "0x401000")

    def test_without_prefix(self):
        self.assertEqual(normalize_addr("401000"), "0x401000")

    def test_uppercase(self):
        self.assertEqual(normalize_addr("0x4010AB"), "0x4010ab")

    def test_strip_spaces(self):
        self.assertEqual(normalize_addr("  0x401000  "), "0x401000")


class TestAddrToInt(unittest.TestCase):
    def test_with_prefix(self):
        self.assertEqual(addr_to_int("0x401000"), 0x401000)

    def test_without_prefix(self):
        self.assertEqual(addr_to_int("401000"), 0x401000)

    def test_zero(self):
        self.assertEqual(addr_to_int("0x0"), 0)


class TestValidateAddr(unittest.TestCase):
    def test_valid_with_prefix(self):
        self.assertEqual(validate_addr("0x401000"), "0x401000")

    def test_valid_without_prefix(self):
        self.assertEqual(validate_addr("401000"), "0x401000")

    def test_uppercase_hex(self):
        self.assertEqual(validate_addr("0x4010AB"), "0x4010ab")

    def test_empty_string(self):
        self.assertIsNone(validate_addr(""))

    def test_only_prefix(self):
        self.assertIsNone(validate_addr("0x"))

    def test_invalid_chars(self):
        self.assertIsNone(validate_addr("not_an_addr"))

    def test_mixed_invalid(self):
        self.assertIsNone(validate_addr("0xGGGG"))

    def test_zero(self):
        self.assertEqual(validate_addr("0x0"), "0x0")

    def test_large_addr(self):
        self.assertEqual(validate_addr("0x7fffffffffff"), "0x7fffffffffff")


if __name__ == "__main__":
    unittest.main()
