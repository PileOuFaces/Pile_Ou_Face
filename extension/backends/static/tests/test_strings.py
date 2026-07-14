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

    def test_max_results_limits_during_python_extraction(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"aaaa\x00bbbb\x00cccc\x00dddd\x00")
            result = extract_strings(str(f), min_len=4, max_results=2)
            self.assertEqual(len(result), 2)

    def test_nonexistent_returns_empty(self):
        result = extract_strings("/nonexistent/path/binary")
        self.assertEqual(result, [])

    def test_large_file_does_not_build_per_byte_offset_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "large.bin"
            with f.open("wb") as handle:
                handle.write(b"hello-large-file\x00")
                handle.seek((17 * 1024 * 1024) + 128)
                handle.write(b"\x00")

            with patch(
                "backends.static.search.strings.build_offset_to_vaddr",
                side_effect=AssertionError("per-byte map should not be built"),
            ):
                result = extract_strings(str(f), min_len=4, max_results=1)

            self.assertEqual(len(result), 1)
            self.assertEqual(result[0]["value"], "hello-large-file")

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


class TestLoadDataSlice(unittest.TestCase):
    """Tests pour _load_data_slice."""

    def test_section_found_returns_slice(self):
        """Section existante → retourne le slice et l'offset de base."""
        from backends.static.search.strings import _load_data_slice

        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[(".text", 4, 9)],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"PREFHELLO_SUFFIX")
                result = _load_data_slice(str(f), ".text")

        self.assertEqual(result, (b"HELLO", 4))


class TestExtractStringsSystemEdgeCases(unittest.TestCase):
    """Edge cases pour extract_strings_system."""

    def test_oserror_returns_empty(self):
        """OSError (commande non trouvée) → []."""
        import subprocess

        from backends.static.search.strings import extract_strings_system

        with patch("subprocess.run", side_effect=OSError("not found")):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world\x00")
                result = extract_strings_system(str(f))
        self.assertEqual(result, [])

    def test_timeout_returns_empty(self):
        """TimeoutExpired → []."""
        import subprocess

        from backends.static.search.strings import extract_strings_system

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("strings", 30),
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world\x00")
                result = extract_strings_system(str(f))
        self.assertEqual(result, [])

    def test_nonzero_returncode_returns_empty(self):
        """Returncode != 0 → []."""
        from backends.static.search.strings import extract_strings_system

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stdout = ""
        with patch("subprocess.run", return_value=mock_proc):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world\x00")
                result = extract_strings_system(str(f))
        self.assertEqual(result, [])

    def test_non_matching_line_skipped(self):
        """Lignes sans format '<hex> <string>' → ignorées silencieusement."""
        from backends.static.search.strings import extract_strings_system

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "not a valid line\n   1a hello world\n"
        with patch("subprocess.run", return_value=mock_proc):
            with patch(
                "backends.static.search.strings.build_offset_to_vaddr",
                return_value={},
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    f = Path(tmp) / "bin"
                    f.write_bytes(b"\x00" * 32)
                    result = extract_strings_system(str(f))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "hello world")


class TestExtractFromPeImportsEdgeCases(unittest.TestCase):
    """Edge cases supplémentaires pour _extract_from_pe_imports."""

    def _make_mock_lief(self, imports):
        class _FakePE:
            pass

        mock_binary = _FakePE()
        mock_binary.optional_header = MagicMock()
        mock_binary.optional_header.imagebase = 0x400000
        mock_binary.imports = imports

        mock_lief = MagicMock()
        mock_lief.PE.Binary = _FakePE
        mock_lief.parse.return_value = mock_binary
        return mock_lief

    def test_dll_name_too_short_filtered(self):
        """DLL dont le nom < min_len → pas dans les résultats (branche 89→100)."""
        mock_entry = MagicMock()
        mock_entry.name = "ValidFunction"
        mock_entry.iat_address = 0x1000

        mock_imp = MagicMock()
        mock_imp.name = "AB"  # 2 chars, min_len=4 → filtré
        mock_imp.entries = [mock_entry]

        with patch.dict(sys.modules, {"lief": self._make_mock_lief([mock_imp])}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f), min_len=4)

        values = [e["value"] for e in result]
        self.assertNotIn("AB", values)
        self.assertIn("ValidFunction", values)

    def test_duplicate_pe_import_key_deduplicated(self):
        """Deux entries avec même (addr, fn) → une seule dans les résultats (ligne 109)."""
        mock_entry1 = MagicMock()
        mock_entry1.name = "GetProcAddress"
        mock_entry1.iat_address = 0x1000

        mock_entry2 = MagicMock()
        mock_entry2.name = "GetProcAddress"
        mock_entry2.iat_address = 0x1000  # même clé → dédupliqué

        mock_imp = MagicMock()
        mock_imp.name = "KERNEL32.dll"
        mock_imp.entries = [mock_entry1, mock_entry2]

        with patch.dict(sys.modules, {"lief": self._make_mock_lief([mock_imp])}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        fn_entries = [e for e in result if e["value"] == "GetProcAddress"]
        self.assertEqual(len(fn_entries), 1)

    def test_lief_parse_exception_returns_empty(self):
        """Exception pendant lief.parse → [] sans crash (lignes 121-122)."""
        mock_lief = MagicMock()
        mock_lief.parse.side_effect = RuntimeError("lief internal error")

        with patch.dict(sys.modules, {"lief": mock_lief}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        self.assertEqual(result, [])

    def test_iat_address_zero_uses_0x0(self):
        """entry.iat_address == 0 → addr '0x0' (branche ligne 105-106)."""
        mock_entry = MagicMock()
        mock_entry.name = "SomeFunction"
        mock_entry.iat_address = 0  # zéro → addr "0x0"

        mock_imp = MagicMock()
        mock_imp.name = "NTDLL.dll"
        mock_imp.entries = [mock_entry]

        with patch.dict(sys.modules, {"lief": self._make_mock_lief([mock_imp])}):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "fake.exe"
                f.write_bytes(b"MZ" + b"\x00" * 64)
                result = _extract_from_pe_imports(str(f))

        fn_entry = next(e for e in result if e["value"] == "SomeFunction")
        self.assertEqual(fn_entry["addr"], "0x0")


class TestExtractStringsAddrDedup(unittest.TestCase):
    """Déduplication dans extract_strings quand deux offsets → même VA (ligne 168)."""

    def test_addr_collision_deduplicates_entries(self):
        """Deux 'hello' à des offsets différents mappés sur la même VA → un seul résultat."""
        # offsets 0 et 10 → VA 0x1000 → clé (0x1000, 'hello', 'utf-8') dupliquée
        data = b"hello\x00\x00\x00\x00\x00hello\x00"
        offset_map = {0: 0x1000, 10: 0x1000}

        with patch(
            "backends.static.search.strings.build_offset_to_vaddr",
            return_value=offset_map,
        ):
            with patch(
                "backends.static.search.strings._extract_from_pe_imports",
                return_value=[],
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    f = Path(tmp) / "bin"
                    f.write_bytes(data)
                    result = extract_strings(str(f), encoding="utf-8")

        occurrences = [e for e in result if e["value"] == "hello"]
        self.assertEqual(
            len(occurrences),
            1,
            "hello ne doit apparaître qu'une fois malgré la collision VA",
        )


class TestMain(unittest.TestCase):
    """Tests pour la fonction main() — couverture des lignes 234-306."""

    def _call_main(self, argv):
        import io

        from backends.static.search.strings import main

        with patch("sys.argv", ["strings.py"] + argv):
            with patch("sys.stdout", new_callable=io.StringIO) as mock_out:
                ret = main()
                return ret, mock_out.getvalue()

    def test_no_system_stdout(self):
        """--no-system écrit le JSON sur stdout et retourne 0."""
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.bin"
            f.write_bytes(b"hello world\x00")
            ret, out = self._call_main(["--binary", str(f), "--no-system"])
        self.assertEqual(ret, 0)
        import json

        parsed = json.loads(out)
        self.assertIsInstance(parsed, list)
        values = [e["value"] for e in parsed]
        self.assertIn("hello world", values)

    def test_output_to_file(self):
        """--output écrit dans un fichier et affiche un message de confirmation."""
        import json

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.bin"
            out_path = Path(tmp) / "out.json"
            f.write_bytes(b"hello world\x00")
            ret, stdout_msg = self._call_main(
                ["--binary", str(f), "--no-system", "--output", str(out_path)]
            )
            self.assertEqual(ret, 0)
            self.assertTrue(out_path.exists())
            parsed = json.loads(out_path.read_text(encoding="utf-8"))
            self.assertIsInstance(parsed, list)
            self.assertIn(str(out_path), stdout_msg)

    def test_encoding_utf16_uses_python_impl(self):
        """--encoding utf-16-le force l'impl Python (pas system strings)."""
        import json

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.bin"
            f.write_bytes(b"h\x00e\x00l\x00l\x00o\x00\x00\x00")
            ret, out = self._call_main(["--binary", str(f), "--encoding", "utf-16-le"])
        self.assertEqual(ret, 0)
        values = [e["value"] for e in json.loads(out)]
        self.assertIn("hello", values)

    def test_section_uses_python_impl(self):
        """--section force l'impl Python (section inexistante → [])."""
        import json

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.bin"
            f.write_bytes(b"hello world test\x00")
            ret, out = self._call_main(
                ["--binary", str(f), "--section", ".nonexistent_xyz"]
            )
        self.assertEqual(ret, 0)
        self.assertEqual(json.loads(out), [])

    def test_max_results_limits_raw_strings(self):
        """--max-results=1 : au plus 1 raw string dans les résultats."""
        import json

        with patch(
            "backends.static.search.strings._extract_from_pe_imports", return_value=[]
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "test.bin"
                f.write_bytes(b"aaaa\x00bbbb\x00cccc\x00dddd\x00")
                ret, out = self._call_main(
                    ["--binary", str(f), "--no-system", "--max-results", "1"]
                )
        self.assertEqual(ret, 0)
        self.assertLessEqual(len(json.loads(out)), 1)

    def test_max_results_preserves_pe_imports(self):
        """--max-results : les imports PE sont toujours inclus en dehors de la limite."""
        import json

        pe_entry = {
            "addr": "0x401000",
            "value": "ImportedFunction",
            "length": 16,
            "encoding": "utf-8",
            "source": "pe_import",
        }
        with patch(
            "backends.static.search.strings._extract_from_pe_imports",
            return_value=[pe_entry],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "test.bin"
                # 4 raw strings + 1 PE import → max_results=1 doit garder PE
                f.write_bytes(b"aaaa\x00bbbb\x00cccc\x00dddd\x00")
                ret, out = self._call_main(
                    ["--binary", str(f), "--no-system", "--max-results", "1"]
                )
        self.assertEqual(ret, 0)
        parsed = json.loads(out)
        pe_entries = [e for e in parsed if e.get("source") == "pe_import"]
        self.assertEqual(len(pe_entries), 1)

    def test_system_fallback_to_python(self):
        """Sans --no-system avec --encoding utf-8 : system strings vide → fallback python."""
        import json

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = ""  # system strings retourne vide → fallback python

        with patch("subprocess.run", return_value=mock_proc):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "test.bin"
                f.write_bytes(b"hello world\x00")
                ret, out = self._call_main(["--binary", str(f), "--encoding", "utf-8"])
        self.assertEqual(ret, 0)
        values = [e["value"] for e in json.loads(out)]
        self.assertIn("hello world", values)

    def test_system_returns_results_no_fallback(self):
        """Sans --no-system : system strings retourne des résultats → pas de fallback python."""
        import json

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stdout = "   0 hello world\n"  # system retourne un résultat

        with patch("subprocess.run", return_value=mock_proc):
            with patch(
                "backends.static.search.strings.build_offset_to_vaddr",
                return_value={},
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    f = Path(tmp) / "test.bin"
                    f.write_bytes(b"hello world\x00")
                    ret, out = self._call_main(
                        ["--binary", str(f), "--encoding", "utf-8"]
                    )
        self.assertEqual(ret, 0)
        parsed = json.loads(out)
        self.assertGreater(len(parsed), 0)

    def test_dunder_main_calls_sys_exit(self):
        """Le bloc if __name__ == '__main__' appelle sys.exit(main())."""
        import io
        import runpy

        strings_py = Path(__file__).resolve().parent.parent / "search" / "strings.py"
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello world\x00")
            with patch("sys.argv", ["strings.py", "--binary", str(f), "--no-system"]):
                with patch("sys.stdout", new_callable=io.StringIO):
                    with self.assertRaises(SystemExit) as ctx:
                        runpy.run_path(str(strings_py), run_name="__main__")
        self.assertEqual(ctx.exception.code, 0)


class TestLoadDataSliceAdditional(unittest.TestCase):
    """Tests supplémentaires pour _load_data_slice — section=None, introuvable, OSError."""

    def test_section_none_returns_full_file(self):
        """section=None → retourne tous les octets avec offset_base=0."""
        from backends.static.search.strings import _load_data_slice

        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "bin"
            f.write_bytes(b"hello world")
            result = _load_data_slice(str(f), None)

        self.assertEqual(result, (b"hello world", 0))

    def test_section_not_found_returns_none(self):
        """Section absente des ranges → None (extract_strings retournera [])."""
        from backends.static.search.strings import _load_data_slice

        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[(".text", 0, 50)],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world" * 5)
                result = _load_data_slice(str(f), ".rodata")

        self.assertIsNone(result)

    def test_oserror_returns_none(self):
        """Fichier illisible (OSError) → None."""
        from backends.static.search.strings import _load_data_slice

        result = _load_data_slice("/nonexistent/path/binary.exe", None)
        self.assertIsNone(result)

    def test_section_found_slice_uses_file_offsets(self):
        """Le slice retourné correspond exactement aux octets entre start et end (offsets fichier)."""
        from backends.static.search.strings import _load_data_slice

        # Binary : [PREFIX_16_BYTES][SECTION_DATA][SUFFIX]
        prefix = b"A" * 16
        section_data = b"SECTION_CONTENT!"
        suffix = b"Z" * 32
        binary = prefix + section_data + suffix

        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[(".rodata", 16, 16 + len(section_data))],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(binary)
                result = _load_data_slice(str(f), ".rodata")

        self.assertIsNotNone(result)
        data, offset_base = result
        self.assertEqual(data, section_data)
        self.assertEqual(offset_base, 16)


class TestExtractStringsSectionFilter(unittest.TestCase):
    """Vérifie que extract_strings filtre correctement par section via file offsets.

    Critique pour la non-régression ELF .rodata et PE .rdata :
    - ELF : file_offset != virtual_address → on doit utiliser file_offset
    - PE  : sec.offset (file offset) != sec.virtual_address (RVA) → on doit utiliser sec.offset
    """

    def test_elf_rodata_returns_only_section_strings(self):
        """ELF .rodata : seules les strings dans la section sont retournées."""
        # Layout : [.text strings][.rodata strings]
        text_part = b"in_text_section\x00"  # offset 0-16, hors .rodata
        rodata_part = b"in_rodata_section\x00"  # offset 16-34, dans .rodata
        binary = text_part + rodata_part

        rodata_start = len(text_part)
        rodata_end = len(binary)

        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[
                (".text", 0, rodata_start),
                (".rodata", rodata_start, rodata_end),
            ],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "elf"
                f.write_bytes(binary)

                all_strings = extract_strings(str(f), section=None)
                rodata_strings = extract_strings(str(f), section=".rodata")
                text_strings = extract_strings(str(f), section=".text")

        rodata_values = [s["value"] for s in rodata_strings]
        text_values = [s["value"] for s in text_strings]

        self.assertIn("in_rodata_section", rodata_values)
        self.assertNotIn("in_text_section", rodata_values)

        self.assertIn("in_text_section", text_values)
        self.assertNotIn("in_rodata_section", text_values)

        self.assertGreater(len(all_strings), len(rodata_strings))

    def test_pe_rdata_uses_file_offset_not_rva(self):
        """PE .rdata : le filtre utilise l'offset fichier, pas le RVA.

        Si le code utilisait virtual_address (RVA=0x1000) au lieu de
        sec.offset (file_offset=64), il chercherait au mauvais endroit
        et retournerait [] alors que les strings sont bien présentes.
        """
        # Simule un PE : 64 octets de headers puis la section .rdata
        pe_header = b"\x00" * 64
        rdata_content = b"pe_rdata_string\x00"
        binary = pe_header + rdata_content

        file_offset = len(pe_header)  # 64 — ce que Python utilise
        # RVA fictif = 0x1000 (bien plus grand que file_offset=64) — ne doit PAS être utilisé

        # get_section_file_ranges retourne les offsets FICHIER (pas les RVAs)
        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[(".rdata", file_offset, file_offset + len(rdata_content))],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "pe.exe"
                f.write_bytes(binary)
                result = extract_strings(str(f), section=".rdata")

        values = [s["value"] for s in result]
        self.assertIn(
            "pe_rdata_string",
            values,
            "La string dans .rdata doit être trouvée via l'offset fichier",
        )

    def test_pe_rdata_rva_would_miss_strings(self):
        """Preuve que l'approche VA serait incorrecte : si on utilisait le RVA
        (0x1000 = 4096) au lieu de l'offset fichier (64), le slice serait vide."""
        pe_header = b"\x00" * 64
        rdata_content = b"pe_rdata_string\x00"
        binary = pe_header + rdata_content

        rva = 0x1000  # 4096 — dépasse la taille du fichier (80 octets)

        # Simuler l'approche incorrecte : filtrer avec le RVA
        data = binary
        slice_via_rva = data[rva : rva + len(rdata_content)]
        slice_via_file_offset = data[64 : 64 + len(rdata_content)]

        self.assertEqual(
            slice_via_rva,
            b"",
            "Avec le RVA (0x1000) le slice est vide — approche incorrecte",
        )
        self.assertEqual(
            slice_via_file_offset,
            rdata_content,
            "Avec l'offset fichier (64) le slice est correct",
        )

    def test_nonexistent_section_returns_empty(self):
        """Section inexistante → [] sans exception."""
        with patch(
            "backends.static.binary.sections.get_section_file_ranges",
            return_value=[(".text", 0, 100)],
        ):
            with tempfile.TemporaryDirectory() as tmp:
                f = Path(tmp) / "bin"
                f.write_bytes(b"hello world" * 10)
                result = extract_strings(str(f), section=".rodata")

        self.assertEqual(result, [])

    def test_both_elf_and_pe_section_names_accepted(self):
        """ELF (.rodata) et PE (.rdata) sont tous les deux des noms de section valides."""
        data = b"section_string_here\x00"

        for section_name in (".rodata", ".rdata", ".data", ".text", "__cstring"):
            with patch(
                "backends.static.binary.sections.get_section_file_ranges",
                return_value=[(section_name, 0, len(data))],
            ):
                with tempfile.TemporaryDirectory() as tmp:
                    f = Path(tmp) / "bin"
                    f.write_bytes(data)
                    result = extract_strings(str(f), section=section_name)

            values = [s["value"] for s in result]
            self.assertIn(
                "section_string_here",
                values,
                f"Section {section_name!r} doit retourner les strings présentes",
            )


if __name__ == "__main__":
    unittest.main()
