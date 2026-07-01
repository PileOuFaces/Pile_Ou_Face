# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.search.strings."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.search.strings import _extract_from_pe_imports, extract_strings

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
        binary = (
            Path(__file__).parent.parent.parent.parent
            / "examples"
            / "demo_push_ret.elf"
        )
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
                    addr.startswith("0x"),
                    f"addr devrait commencer par '0x', reçu: {addr!r}",
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

        binary = (
            Path(__file__).parent.parent.parent.parent
            / "examples"
            / "demo_push_ret.elf"
        )
        if not binary.exists():
            self.skipTest("demo_push_ret.elf absent")

        from backends.static.search.strings import (
            extract_strings,
            extract_strings_system,
        )

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


class TestExtractStringsRigorous(unittest.TestCase):
    """Tests de cas limites pour extract_strings."""

    def test_all_non_printable_returns_empty(self):
        """Données purement non-imprimables → 0 strings."""
        non_printable = bytes([b for b in range(256) if b < 0x20 or b > 0x7E]) * 4
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "noise.bin"
            f.write_bytes(non_printable)
            result = extract_strings(str(f), encoding="utf-8")
            self.assertEqual(result, [])

    def test_min_len_exact_boundary_found(self):
        """String de longueur exactement min_len → trouvée."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"\x00ABCD\x00")  # 4 chars, min_len=4
            result = extract_strings(str(f), min_len=4)
            values = [e["value"] for e in result]
            self.assertIn("ABCD", values)

    def test_min_len_one_below_boundary_not_found(self):
        """String de longueur min_len-1 → non trouvée."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"\x00ABC\x00")  # 3 chars, min_len=4
            result = extract_strings(str(f), min_len=4)
            values = [e["value"] for e in result]
            self.assertNotIn("ABC", values)

    def test_utf16_be_encoding(self):
        """UTF-16 BE est correctement détecté."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            # "hello" en UTF-16 BE : \x00h\x00e\x00l\x00l\x00o
            data = b"\x00h\x00e\x00l\x00l\x00o\x00\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4, encoding="utf-16-be")
            self.assertGreaterEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "hello")
            self.assertEqual(result[0]["encoding"], "utf-16-be")

    def test_auto_mode_finds_utf16_be(self):
        """Le mode auto inclut l'encodage UTF-16 BE."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            data = b"\x00W\x00o\x00r\x00l\x00d\x00\x00"
            f.write_bytes(data)
            result = extract_strings(str(f), min_len=4, encoding="auto")
            encodings = {e["encoding"] for e in result}
            self.assertIn("utf-16-be", encodings)

    def test_all_results_have_hex_addr(self):
        """Toutes les adresses commencent par '0x'."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello world test binary data here\x00")
            result = extract_strings(str(f), min_len=4)
            for entry in result:
                self.assertTrue(
                    str(entry["addr"]).startswith("0x"),
                    f"addr devrait commencer par '0x': {entry['addr']!r}",
                )

    def test_result_contains_required_fields(self):
        """Chaque entrée contient addr, value, length, encoding."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello world\x00")
            result = extract_strings(str(f), min_len=4)
            self.assertGreater(len(result), 0)
            for entry in result:
                self.assertIn("addr", entry)
                self.assertIn("value", entry)
                self.assertIn("length", entry)
                self.assertIn("encoding", entry)

    def test_length_field_matches_value(self):
        """Le champ length correspond à len(value)."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"\x00hello world\x00short\x00verylongstring1234\x00")
            result = extract_strings(str(f), min_len=4)
            for entry in result:
                self.assertEqual(
                    entry["length"],
                    len(entry["value"]),
                    f"length mismatch pour {entry['value']!r}",
                )

    def test_section_nonexistent_returns_empty(self):
        """Filtre de section inexistant → []."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello world this is a test\x00")
            result = extract_strings(str(f), section=".nonexistent_section_xyz")
            self.assertEqual(result, [])

    def test_unsupported_encoding_raises_valueerror(self):
        """Encodage inconnu → ValueError."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello\x00")
            with self.assertRaises(ValueError):
                extract_strings(str(f), encoding="latin-1")

    def test_result_sorted_ascending_by_address(self):
        """Les résultats sont triés par adresse croissante."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            # Plusieurs strings à des offsets différents
            f.write_bytes(b"aaaa\x00bbbb\x00cccc\x00dddd\x00")
            result = extract_strings(str(f), min_len=4, encoding="utf-8")
            addrs = [int(e["addr"], 16) for e in result]
            self.assertEqual(addrs, sorted(addrs))

    def test_min_len_1_finds_every_printable_byte(self):
        """min_len=1 : tout byte imprimable est une string."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"A\x00B\x00C")
            result = extract_strings(str(f), min_len=1)
            values = [e["value"] for e in result]
            self.assertIn("A", values)
            self.assertIn("B", values)
            self.assertIn("C", values)


class TestExtractFromPeImports(unittest.TestCase):
    """Tests pour _extract_from_pe_imports."""

    def test_nonexistent_file_returns_empty(self):
        """Chemin inexistant → [] sans exception."""
        result = _extract_from_pe_imports("/nonexistent/binary.exe")
        self.assertEqual(result, [])

    def test_non_pe_raw_bytes_returns_empty(self):
        """Fichier binaire brut non-PE → []."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "notpe.bin"
            f.write_bytes(b"\x00\x01\x02\x03" * 64)
            result = _extract_from_pe_imports(str(f))
            self.assertEqual(result, [])

    def test_result_has_source_pe_import(self):
        """Chaque entrée retournée a source='pe_import'."""
        mock_entry = MagicMock()
        mock_entry.name = "GetProcAddress"
        mock_entry.iat_address = 0x1000

        mock_imp = MagicMock()
        mock_imp.name = "KERNEL32.dll"
        mock_imp.entries = [mock_entry]

        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = [mock_imp]

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        self.assertGreater(len(result), 0)
        for entry in result:
            self.assertEqual(entry["source"], "pe_import")

    def test_dll_and_function_names_extracted(self):
        """DLL name et function name sont tous les deux extraits."""
        mock_entry = MagicMock()
        mock_entry.name = "GetProcAddress"
        mock_entry.iat_address = 0x2000

        mock_imp = MagicMock()
        mock_imp.name = "KERNEL32.dll"
        mock_imp.entries = [mock_entry]

        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = [mock_imp]

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        values = [e["value"] for e in result]
        self.assertIn("KERNEL32.dll", values)
        self.assertIn("GetProcAddress", values)

    def test_function_address_uses_imagebase_plus_iat(self):
        """L'adresse d'une fonction = imagebase + iat_address."""
        mock_entry = MagicMock()
        mock_entry.name = "LoadLibraryA"
        mock_entry.iat_address = 0x3000

        mock_imp = MagicMock()
        mock_imp.name = "KERNEL32.dll"
        mock_imp.entries = [mock_entry]

        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = [mock_imp]

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        fn_entry = next(e for e in result if e["value"] == "LoadLibraryA")
        expected_addr = f"0x{0x400000 + 0x3000:x}"
        self.assertEqual(fn_entry["addr"], expected_addr)

    def test_min_len_filters_short_function_names(self):
        """Noms plus courts que min_len → exclus."""
        mock_entry = MagicMock()
        mock_entry.name = "foo"  # 3 chars, min_len=4
        mock_entry.iat_address = 0x1000

        mock_imp = MagicMock()
        mock_imp.name = "A.dll"  # 5 chars — kept
        mock_imp.entries = [mock_entry]

        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = [mock_imp]

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f), min_len=4)

        values = [e["value"] for e in result]
        self.assertNotIn("foo", values)

    def test_ordinal_imports_skipped(self):
        """Imports par ordinal (name vide) → ignorés."""
        mock_entry = MagicMock()
        mock_entry.name = ""  # ordinal import, no name
        mock_entry.iat_address = 0x1000

        mock_imp = MagicMock()
        mock_imp.name = "NTDLL.dll"
        mock_imp.entries = [mock_entry]

        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = [mock_imp]

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        values = [e["value"] for e in result]
        self.assertIn("NTDLL.dll", values)
        self.assertNotIn("", values)


class TestExtractStringsPeImportsMerge(unittest.TestCase):
    """Tests d'intégration : fusion des imports PE dans extract_strings."""

    def _fake_import_entry(self, value, addr="0x401000"):
        return {
            "addr": addr,
            "value": value,
            "length": len(value),
            "encoding": "utf-8",
            "source": "pe_import",
        }

    def test_pe_imports_merged_when_no_section_filter(self):
        """Sans filtre de section, les imports PE sont fusionnés."""
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[self._fake_import_entry("LoadLibraryA", "0x401000")],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world test\x00")
                result = extract_strings(str(f), encoding="auto", section=None)

        values = [e["value"] for e in result]
        self.assertIn("LoadLibraryA", values)
        self.assertIn("hello world test", values)

    def test_pe_imports_not_merged_when_section_filter_active(self):
        """Avec filtre de section, les imports PE ne sont PAS fusionnés."""
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[self._fake_import_entry("GetProcAddress")],
        ) as mock_fn:
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world test\x00")
                # section inexistante → retourne []
                extract_strings(str(f), encoding="utf-8", section=".rdata")

        mock_fn.assert_not_called()

    def test_pe_imports_not_merged_for_utf16_encoding(self):
        """Pour encodage UTF-16, les imports PE ne sont PAS fusionnés."""
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[self._fake_import_entry("GetProcAddress")],
        ) as mock_fn:
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"h\x00e\x00l\x00l\x00o\x00\x00\x00")
                extract_strings(str(f), encoding="utf-16-le", section=None)

        mock_fn.assert_not_called()

    def test_dedup_pe_import_same_addr_same_value(self):
        """Import PE avec même (addr, value) qu'une raw string → pas de doublon."""
        # Le raw scan trouve "GetProcAddress" à 0x0, et l'import aussi
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[
                {
                    "addr": "0x0",
                    "value": "GetProcAddress",
                    "length": 14,
                    "encoding": "utf-8",
                    "source": "pe_import",
                }
            ],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                # "GetProcAddress" dans les bytes bruts, à l'offset 0 → addr "0x0"
                f.write_bytes(b"GetProcAddress\x00")
                result = extract_strings(str(f), encoding="utf-8", section=None)

        occurrences = [e for e in result if e["value"] == "GetProcAddress"]
        self.assertEqual(
            len(occurrences), 1, "GetProcAddress ne doit apparaître qu'une seule fois"
        )

    def test_result_includes_source_field_for_pe_imports(self):
        """Les entrées issues des imports ont source='pe_import'."""
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[self._fake_import_entry("VirtualAlloc", "0x402000")],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"\x00" * 8)
                result = extract_strings(str(f), encoding="auto", section=None)

        import_entries = [e for e in result if e.get("source") == "pe_import"]
        self.assertEqual(len(import_entries), 1)
        self.assertEqual(import_entries[0]["value"], "VirtualAlloc")

    def test_raw_strings_do_not_have_source_field(self):
        """Les strings raw n'ont pas de champ source."""
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world from raw scan\x00")
                result = extract_strings(str(f), encoding="utf-8", section=None)

        raw_entries = [e for e in result if "source" not in e]
        self.assertGreater(len(raw_entries), 0)


if __name__ == "__main__":
    unittest.main()
