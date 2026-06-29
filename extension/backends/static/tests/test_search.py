# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.search.search."""

import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.search.search import search_in_binary


class TestSearchInBinary(unittest.TestCase):
    """Tests de search_in_binary."""

    def test_nonexistent_returns_empty(self):
        self.assertEqual(search_in_binary("/nonexistent/path", "test"), [])

    def test_text_mode(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"hello world\x00foo bar")
            path = f.name
        try:
            result = search_in_binary(path, "hello", mode="text")
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "hello")
            self.assertIn("offset", result[0])
            self.assertIn("offset_hex", result[0])
            self.assertIn("context", result[0])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_text_mode_can_expose_raw_vaddr(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"hello world\x00foo bar")
            path = f.name
        try:
            result = search_in_binary(
                path,
                "hello",
                mode="text",
                raw_base_addr="0x500000",
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["vaddr"], 0x500000)
            self.assertEqual(result[0]["vaddr_hex"], "0x500000")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_text_mode_no_match(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"xxxx")
            path = f.name
        try:
            self.assertEqual(search_in_binary(path, "yyyy", mode="text"), [])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_hex_mode(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x43\x43\x43\x43\x00\x00")  # CCCC
            path = f.name
        try:
            result = search_in_binary(path, "43434343", mode="hex")
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "43434343")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_hex_mode_raw_vaddr_respects_match_offset(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00\x00CCCC\x00")
            path = f.name
        try:
            result = search_in_binary(
                path,
                "43434343",
                mode="hex",
                raw_base_addr=0x600000,
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["offset"], 2)
            self.assertEqual(result[0]["vaddr"], 0x600002)
            self.assertEqual(result[0]["vaddr_hex"], "0x600002")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_hex_mode_invalid_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"xxxx")
            path = f.name
        try:
            self.assertEqual(search_in_binary(path, "zz", mode="hex"), [])
            self.assertEqual(
                search_in_binary(path, "434", mode="hex"), []
            )  # odd length
        finally:
            Path(path).unlink(missing_ok=True)

    def test_empty_pattern_returns_empty(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"hello")
            path = f.name
        try:
            self.assertEqual(search_in_binary(path, "", mode="text"), [])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_max_results_limits_output(self):
        """max_results doit limiter le nombre de résultats retournés."""
        # Créer un fichier avec 5 occurrences
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"AA" * 5)
            path = f.name
        try:
            all_results = search_in_binary(path, "41", mode="hex")
            limited = search_in_binary(path, "41", mode="hex", max_results=2)
            self.assertGreater(len(all_results), 2)
            self.assertEqual(len(limited), 2)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_max_results_none_is_unlimited(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"AA" * 10)
            path = f.name
        try:
            results = search_in_binary(path, "41", mode="hex", max_results=None)
            self.assertGreaterEqual(len(results), 5)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_regex_mode(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"AAAA\x00BBBB\x00CCCC")
            path = f.name
        try:
            result = search_in_binary(path, r"\x41{4}", mode="regex")
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["offset"], 0)
            self.assertIn("value", result[0])
            self.assertEqual(search_in_binary(path, "[invalid", mode="regex"), [])
        finally:
            Path(path).unlink(missing_ok=True)

    def test_regex_mode_raw_vaddr_is_added(self):
        with tempfile.NamedTemporaryFile(suffix=".bin", delete=False) as f:
            f.write(b"\x00AAAA\x00")
            path = f.name
        try:
            result = search_in_binary(
                path,
                r"\x41{4}",
                mode="regex",
                raw_base_addr="0x700000",
            )
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["offset"], 1)
            self.assertEqual(result[0]["vaddr_hex"], "0x700001")
        finally:
            Path(path).unlink(missing_ok=True)


class TestSearchFilters(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
        self.tmp.write(b"\x00" * 0x100)  # padding 256 bytes
        self.tmp.write(b"hello world\x00")  # offset 0x100 (len=11 pour "hello world")
        self.tmp.write(b"HELLO\x00")  # offset 0x10c (len=5)
        self.tmp.write(b"hi\x00")  # offset 0x112 (len=2)
        self.tmp.write(b"\x00" * 0x100)
        self.tmp.close()
        self.binary = self.tmp.name

    def tearDown(self):
        import os

        os.unlink(self.binary)

    def test_result_has_length_field(self):
        results = search_in_binary(self.binary, "hello", mode="text")
        self.assertTrue(any("length" in r for r in results), "Champ 'length' manquant")
        hit = next(r for r in results if r["value"] == "hello")
        self.assertEqual(hit["length"], 5)

    def test_min_length_filters_short_matches(self):
        # regex \w+ matche 'hi' (len=2), 'hello' (len=5), 'world' (len=5), 'HELLO' (len=5)
        results = search_in_binary(self.binary, r"\w+", mode="regex", min_length=3)
        for r in results:
            self.assertGreaterEqual(r["length"], 3, f"Match trop court: {r}")

    def test_max_length_filters_long_matches(self):
        results = search_in_binary(self.binary, r"\w+", mode="regex", max_length=5)
        for r in results:
            self.assertLessEqual(r["length"], 5, f"Match trop long: {r}")

    def test_case_sensitive_by_default(self):
        results = search_in_binary(self.binary, "hello", mode="text")
        values = [r["value"] for r in results]
        self.assertIn("hello", values)
        self.assertNotIn("HELLO", values)

    def test_case_insensitive_flag(self):
        results = search_in_binary(
            self.binary, "hello", mode="text", case_sensitive=False
        )
        # Doit trouver à la fois 'hello' et 'HELLO' (valeurs réelles des bytes)
        offsets = [r["offset"] for r in results]
        self.assertIn(0x100, offsets, "Manque 'hello' à 0x100")
        self.assertIn(0x10C, offsets, "Manque 'HELLO' à 0x10c")
        # value doit contenir les bytes originaux, pas le pattern lowercased
        by_offset = {r["offset"]: r for r in results}
        self.assertEqual(
            by_offset[0x100]["value"], "hello", "value à 0x100 doit être 'hello'"
        )
        self.assertEqual(
            by_offset[0x10C]["value"], "HELLO", "value à 0x10c doit être 'HELLO'"
        )

    def test_offset_start_filters(self):
        results = search_in_binary(
            self.binary, r"\w+", mode="regex", offset_start=0x10C
        )
        for r in results:
            self.assertGreaterEqual(r["offset"], 0x10C)

    def test_offset_end_filters(self):
        results = search_in_binary(self.binary, r"\w+", mode="regex", offset_end=0x10B)
        for r in results:
            self.assertLessEqual(r["offset"], 0x10B)

    def test_regex_case_insensitive(self):
        """case_sensitive=False avec mode regex applique re.IGNORECASE."""
        data = b"Hello World HELLO"
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(data)
            path = f.name
        try:
            results = search_in_binary(
                path, "hello", mode="regex", case_sensitive=False
            )
            self.assertEqual(len(results), 2)  # "Hello" et "HELLO"
        finally:
            os.unlink(path)

    def test_min_length_text_mode(self):
        """min_length filtre en mode text (longueur fixe = len(pattern))."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"AABBCCDDEE" * 10)
            path = f.name
        try:
            results = search_in_binary(path, "AB", mode="text", min_length=10)
            self.assertEqual(results, [])
        finally:
            os.unlink(path)

    def test_min_length_text_mode_pass(self):
        """min_length = len(pattern) ne filtre pas en mode text."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"AABBCCDDEE" * 10)
            path = f.name
        try:
            results = search_in_binary(path, "AB", mode="text", min_length=2)
            self.assertGreater(len(results), 0)
        finally:
            os.unlink(path)

    def test_min_length_hex_mode(self):
        """min_length filtre en mode hex (longueur fixe = len(needle))."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"AABBCCDDEE" * 10)
            path = f.name
        try:
            results = search_in_binary(path, "4142", mode="hex", min_length=10)
            self.assertEqual(results, [])
        finally:
            os.unlink(path)

    def test_max_length_hex_mode(self):
        """max_length filtre en mode hex si max_length < len(needle)."""
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"AABBCCDDEE" * 10)
            path = f.name
        try:
            results = search_in_binary(path, "4142", mode="hex", max_length=1)
            self.assertEqual(results, [])
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
