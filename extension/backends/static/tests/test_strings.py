# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.search.strings."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.search.strings import extract_strings

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


class TestExtractStrings(unittest.TestCase):
    """Tests de extract_strings (implémentation Python pure)."""

    def test_empty_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "empty.bin"
            f.write_bytes(b"")
            self.assertEqual(extract_strings(str(f)), [])

    def test_no_strings_min_len_4(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"\x00\x01\x02\x03\x04\x05")
            self.assertEqual(extract_strings(str(f), min_len=4), [])

    def test_single_string(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"\x00\x00hello\x00\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4)
            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "hello")
            self.assertEqual(result[0]["length"], 5)
            self.assertEqual(result[0]["encoding"], "utf-8")
            self.assertIn("addr", result[0])

    def test_multiple_strings(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"AAAA\x00BBBB\x00CCCC"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4)
            self.assertGreaterEqual(len(result), 2)
            values = [r["value"] for r in result]
            self.assertIn("AAAA", values)
            self.assertIn("BBBB", values)

    def test_min_len_filter(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"abc\x00abcd\x00")
            self.assertEqual(len(extract_strings(str(f), min_len=4)), 1)
            self.assertGreaterEqual(len(extract_strings(str(f), min_len=3)), 1)

    def test_nonexistent_returns_empty(self):
        result = extract_strings("/nonexistent/path/binary")
        self.assertEqual(result, [])

    def test_utf16_le(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"h\x00e\x00l\x00l\x00o\x00\x00\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4, encoding="utf-16-le")
            self.assertGreaterEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "hello")
            self.assertEqual(result[0]["length"], 5)
            self.assertEqual(result[0]["encoding"], "utf-16-le")

    def test_auto_merges_ascii_and_utf16(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"hello\x00\x00W\x00o\x00r\x00l\x00d\x00\x00\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4, encoding="auto")
            values = {(entry["value"], entry["encoding"]) for entry in result}
            self.assertIn(("hello", "utf-8"), values)
            self.assertIn(("World", "utf-16-le"), values)

    def test_auto_keeps_addresses_sorted(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"\x00A\x00B\x00C\x00D\x00\x00hello\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4, encoding="auto")
            addrs = [int(entry["addr"], 16) for entry in result]
            self.assertEqual(addrs, sorted(addrs))

    @unittest.skipUnless(_LIEF_AVAILABLE, "lief not installed")
    def test_section_filter_elf(self):
        binary = Path(__file__).parent.parent.parent.parent / "examples" / "demo_push_ret.elf"
        if not binary.exists():
            self.skipTest("demo_push_ret.elf absent")
        all_s = extract_strings(str(binary), section=None)
        rodata_s = extract_strings(str(binary), section=".rodata")
        self.assertGreater(len(all_s), len(rodata_s))
        self.assertGreater(len(rodata_s), 0)


class TestExtractStringsSystemVaddr(unittest.TestCase):
    """extract_strings_system doit retourner des VAs cohérentes avec extract_strings."""

    def test_system_returns_hex_addresses(self):
        """Toutes les adresses doivent être au format 0x<hex>."""
        import subprocess
        from backends.static.search.strings import extract_strings_system

        # Vérifier que strings est disponible
        try:
            subprocess.run(["strings", "--version"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("commande strings non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"\x00\x00hello world\x00\x00test string\x00")
            result = extract_strings_system(str(f))
            for entry in result:
                addr = entry.get("addr", "")
                self.assertTrue(
                    addr.startswith("0x"), f"addr devrait commencer par '0x', reçu: {addr!r}"
                )
                self.assertEqual(entry.get("encoding"), "utf-8")

    def test_system_and_python_consistent_addresses(self):
        """Sur un binaire avec lief disponible, les VAs doivent être identiques."""
        import subprocess

        try:
            import lief as _lief
        except ImportError:
            self.skipTest("lief non disponible")
        try:
            subprocess.run(["strings", "--version"], capture_output=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            self.skipTest("commande strings non disponible")

        binary = Path(__file__).parent.parent.parent.parent / "examples" / "demo_push_ret.elf"
        if not binary.exists():
            self.skipTest("demo_push_ret.elf absent")

        from backends.static.search.strings import extract_strings, extract_strings_system

        py_strings = extract_strings(str(binary), min_len=4)
        sys_strings = extract_strings_system(str(binary), min_len=4)

        # Construire un set des adresses retournées par chaque méthode
        py_addrs = {e["addr"] for e in py_strings}
        sys_addrs = {e["addr"] for e in sys_strings}

        # Les adresses communes doivent exister (non vide) si le binaire a des strings
        if py_strings and sys_strings:
            common = py_addrs & sys_addrs
            self.assertGreater(
                len(common),
                0,
                "extract_strings et extract_strings_system devraient partager des adresses VA",
            )


if __name__ == "__main__":
    unittest.main()
