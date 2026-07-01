# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.symbols."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.symbols import _format_pe_import_address, extract_symbols
from backends.static.tests.util import compile_minimal_elf


class _FakeLief:
    class ELF:
        class Binary:
            def __init__(self, symtab_symbols=None, dynamic_symbols=None):
                self.symtab_symbols = symtab_symbols or []
                self.dynamic_symbols = dynamic_symbols or []

        class Symbol:
            class BINDING:
                GLOBAL = "GLOBAL"
                WEAK = "WEAK"

            class TYPE:
                FUNC = "FUNC"
                OBJECT = "OBJECT"

    class MachO:
        class Binary:
            def __init__(self, symbols=None):
                self.symbols = symbols or []

    class PE:
        class Binary:
            def __init__(self, exported_functions=None, imported_functions=None):
                self.exported_functions = exported_functions or []
                self.imported_functions = imported_functions or []


class _FakeFunction:
    def __init__(self, name, **attrs):
        self.name = name
        for key, value in attrs.items():
            setattr(self, key, value)


class _FakeSymbol:
    def __init__(self, name, **attrs):
        self.name = name
        for key, value in attrs.items():
            setattr(self, key, value)


class TestExtractSymbols(unittest.TestCase):
    """Tests de extract_symbols avec lief."""

    def _with_fake_lief(self, binary):
        import backends.static.binary.symbols as _sym_mod

        previous_lief = _sym_mod.lief
        _FakeLief.parse = staticmethod(lambda _path: binary)
        _sym_mod.lief = _FakeLief
        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)

    def test_real_binary(self):
        """Teste l'extraction de symboles sur un vrai binaire."""
        import backends.static.binary.symbols as _sym_mod

        if _sym_mod.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            symbols = extract_symbols(str(binary))
            self.assertIsInstance(symbols, list)
            self.assertGreater(len(symbols), 0)

            # Vérifier le format
            for sym in symbols:
                self.assertIn("name", sym)
                self.assertIn("addr", sym)
                self.assertIn("type", sym)
                self.assertTrue(sym["name"])  # Non vide

    def test_pe_symbols_no_crash(self):
        """extract_symbols() sur un PE sans exports ne plante pas."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            result = extract_symbols(pe_path)
            self.assertIsInstance(result, list)
            # PE minimal sans exports → liste vide ou quelques imports
        finally:
            os.unlink(pe_path)

    def test_pe_import_address_falls_back_to_function_address(self):
        """LIEF Function imports may expose address without iat_address."""

        class ImportFunction:
            name = "SetEnvironmentVariableW"
            address = 0x8070

        self.assertEqual(_format_pe_import_address(ImportFunction()), "0x8070")

    def test_pe_import_address_prefers_iat_address(self):
        func = _FakeFunction("CreateFileW", iat_address=0x401000, address=0x402000)

        self.assertEqual(_format_pe_import_address(func), "0x401000")

    def test_pe_import_address_falls_back_to_value_then_zero(self):
        self.assertEqual(
            _format_pe_import_address(_FakeFunction("Sleep", value=0x1234)), "0x1234"
        )
        self.assertEqual(_format_pe_import_address(_FakeFunction("Sleep")), "0x0")

    def test_pe_imported_functions_without_iat_address_do_not_crash(self):
        """extract_symbols() handles LIEF PE Function imports without iat_address."""
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            binary = _FakeLief.PE.Binary(
                imported_functions=[
                    _FakeFunction("SetEnvironmentVariableW", address=0x8070),
                    _FakeFunction("Sleep", value=0x8078),
                    _FakeFunction("NoAddress"),
                ]
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=False)

        self.assertEqual(
            symbols,
            [
                {
                    "name": "NoAddress",
                    "addr": "0x0",
                    "type": "U",
                    "size": None,
                },
                {
                    "name": "SetEnvironmentVariableW",
                    "addr": "0x8070",
                    "type": "U",
                    "size": None,
                },
                {"name": "Sleep", "addr": "0x8078", "type": "U", "size": None},
            ],
        )

    def test_pe_defined_only_skips_imported_functions(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            binary = _FakeLief.PE.Binary(
                exported_functions=[_FakeFunction("Exported", address=0x1000)],
                imported_functions=[_FakeFunction("Imported", address=0x2000)],
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=True)

        self.assertEqual(
            symbols,
            [{"name": "Exported", "addr": "0x1000", "type": "T", "size": None}],
        )

    def test_elf_symbols_cover_static_dynamic_and_undefined_filters(self):
        with tempfile.NamedTemporaryFile() as f:
            binary = _FakeLief.ELF.Binary(
                symtab_symbols=[
                    _FakeSymbol(
                        "entry",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="LOCAL",
                        shndx=1,
                        value=0x1000,
                        size=32,
                    ),
                    _FakeSymbol(
                        "extern_skip",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding=_FakeLief.ELF.Symbol.BINDING.GLOBAL,
                        shndx=0,
                        value=0,
                        size=0,
                    ),
                    _FakeSymbol(
                        "weak_symbol",
                        type="NOTYPE",
                        binding=_FakeLief.ELF.Symbol.BINDING.WEAK,
                        shndx=2,
                        value=0x2000,
                        size=0,
                    ),
                ],
                dynamic_symbols=[
                    _FakeSymbol(
                        "dyn_object",
                        type=_FakeLief.ELF.Symbol.TYPE.OBJECT,
                        binding="GLOBAL",
                        shndx=3,
                        value=0x3000,
                        size=8,
                    )
                ],
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=True)

        self.assertEqual(
            symbols,
            [
                {"name": "dyn_object", "addr": "0x3000", "type": "D", "size": 8},
                {"name": "entry", "addr": "0x1000", "type": "T", "size": 32},
                {"name": "weak_symbol", "addr": "0x2000", "type": "W", "size": None},
            ],
        )

    def test_elf_symbols_cover_additional_types_and_size_inference(self):
        with tempfile.NamedTemporaryFile() as f:
            binary = _FakeLief.ELF.Binary(
                symtab_symbols=[
                    _FakeSymbol(
                        "data_object",
                        type=_FakeLief.ELF.Symbol.TYPE.OBJECT,
                        binding="LOCAL",
                        shndx=2,
                        value=0x1800,
                        size=4,
                    ),
                    _FakeSymbol(
                        "extern_keep",
                        type="NOTYPE",
                        binding=_FakeLief.ELF.Symbol.BINDING.GLOBAL,
                        shndx=0,
                        value=0,
                        size=0,
                    ),
                    _FakeSymbol(
                        "func_a",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="LOCAL",
                        shndx=1,
                        value=0x1000,
                        size=0,
                    ),
                    _FakeSymbol(
                        "func_b",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="LOCAL",
                        shndx=1,
                        value=0x1100,
                        size=0,
                    ),
                    _FakeSymbol(
                        "func_b",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="LOCAL",
                        shndx=1,
                        value=0x1200,
                        size=0,
                    ),
                    _FakeSymbol("", type="NOTYPE", binding="LOCAL", shndx=1, value=0),
                ],
                dynamic_symbols=[
                    _FakeSymbol(
                        "dyn_func",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="GLOBAL",
                        shndx=4,
                        value=0x2000,
                        size=0,
                    ),
                    _FakeSymbol(
                        "dyn_skip",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="GLOBAL",
                        shndx=0,
                        value=0,
                        size=0,
                    ),
                    _FakeSymbol(
                        "func_a",
                        type=_FakeLief.ELF.Symbol.TYPE.FUNC,
                        binding="GLOBAL",
                        shndx=4,
                        value=0x3000,
                        size=0,
                    ),
                ],
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=False)

        self.assertEqual(
            symbols,
            [
                {"name": "data_object", "addr": "0x1800", "type": "D", "size": 4},
                {"name": "dyn_func", "addr": "0x2000", "type": "T", "size": None},
                {"name": "dyn_skip", "addr": "0x0", "type": "T", "size": None},
                {"name": "extern_keep", "addr": "0x0", "type": "U", "size": None},
                {"name": "func_a", "addr": "0x1000", "type": "T", "size": 256},
                {"name": "func_b", "addr": "0x1100", "type": "T", "size": 3840},
            ],
        )

    def test_macho_symbols_filter_debug_paths_and_undefined_when_requested(self):
        with tempfile.NamedTemporaryFile() as f:
            binary = _FakeLief.MachO.Binary(
                symbols=[
                    _FakeSymbol("_main", type=0x0E, value=0x1000, size=24),
                    _FakeSymbol("_extern", type=0, value=0, size=0),
                    _FakeSymbol("/tmp/source.c", type=0x0E, value=0x2000, size=0),
                    _FakeSymbol(".hidden", type=0x0E, value=0x3000, size=0),
                    _FakeSymbol("debug_stab", type=0x64, value=0x4000, size=0),
                ]
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=False)

        self.assertEqual(
            symbols,
            [
                {"name": "_extern", "addr": "0x0", "type": "U", "size": None},
                {"name": "_main", "addr": "0x1000", "type": "T", "size": 24},
            ],
        )

    def test_macho_symbols_cover_abs_invalid_type_duplicate_and_defined_only(self):
        with tempfile.NamedTemporaryFile() as f:
            binary = _FakeLief.MachO.Binary(
                symbols=[
                    _FakeSymbol("absolute", type=1, value=0x1111, size=0),
                    _FakeSymbol("bad_type", type=object(), value=0x2222, size=0),
                    _FakeSymbol("bad_type", type=0x0E, value=0x3333, size=0),
                    _FakeSymbol("_extern", type=0, value=0, size=0),
                    _FakeSymbol("", type=0x0E, value=0x4444, size=0),
                ]
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=True)

        self.assertEqual(
            symbols,
            [{"name": "absolute", "addr": "0x1111", "type": "A", "size": None}],
        )

    def test_pe_imported_functions_skip_duplicate_names(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            binary = _FakeLief.PE.Binary(
                imported_functions=[
                    _FakeFunction("Sleep", address=0x1000),
                    _FakeFunction("Sleep", address=0x2000),
                ]
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=False)

        self.assertEqual(
            symbols,
            [{"name": "Sleep", "addr": "0x1000", "type": "U", "size": None}],
        )

    def test_pe_export_edge_cases_and_size_inference(self):
        with tempfile.NamedTemporaryFile(suffix=".exe") as f:
            binary = _FakeLief.PE.Binary(
                exported_functions=[
                    _FakeFunction("Alpha", address=0x1000),
                    _FakeFunction("Alpha", address=0x1100),
                    _FakeFunction("Beta", address=0x1200),
                    _FakeFunction("NoAddress", address=0),
                    _FakeFunction("", address=0x1300),
                ]
            )
            self._with_fake_lief(binary)

            symbols = extract_symbols(f.name, defined_only=True)

        self.assertEqual(
            symbols,
            [
                {"name": "Alpha", "addr": "0x1000", "type": "T", "size": 512},
                {"name": "Beta", "addr": "0x1200", "type": "T", "size": None},
                {"name": "NoAddress", "addr": "0x0", "type": "T", "size": None},
            ],
        )

    def test_missing_binary_returns_empty_list(self):
        self.assertEqual(extract_symbols("/definitely/not/a/binary"), [])

    def test_fallback_returns_empty_for_directory_and_read_errors(self):
        import backends.static.binary.symbols as _sym_mod

        previous_lief = _sym_mod.lief
        _sym_mod.lief = None
        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)

        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(extract_symbols(tmp), [])

        with tempfile.NamedTemporaryFile() as f:
            with mock.patch.object(Path, "read_bytes", side_effect=OSError):
                self.assertEqual(extract_symbols(f.name), [])

    def test_fallback_when_lief_is_unavailable(self):
        import backends.static.binary.symbols as _sym_mod

        previous_lief = _sym_mod.lief
        _sym_mod.lief = None
        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)

        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x00sub_401000\x00")
            f.flush()

            symbols = extract_symbols(f.name)

        self.assertEqual(
            symbols,
            [
                {
                    "name": "sub_401000",
                    "addr": "0x1",
                    "type": "?",
                    "size": None,
                    "source": "string-reference",
                }
            ],
        )

    def test_fallback_when_lief_parse_returns_none_or_raises(self):
        import backends.static.binary.symbols as _sym_mod

        previous_lief = _sym_mod.lief

        class NoneParsingLief(_FakeLief):
            parse = staticmethod(lambda _path: None)

        class RaisingLief(_FakeLief):
            @staticmethod
            def parse(_path):
                raise RuntimeError("parse failed")

        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)
        with tempfile.NamedTemporaryFile() as f:
            f.write(b"\x00main\x00")
            f.flush()

            _sym_mod.lief = NoneParsingLief
            self.assertEqual(extract_symbols(f.name)[0]["name"], "main")

            _sym_mod.lief = RaisingLief
            self.assertEqual(extract_symbols(f.name)[0]["name"], "main")

    def test_main_prints_json_payload(self):
        import contextlib
        import io
        import json
        import sys

        import backends.static.binary.symbols as _sym_mod

        previous_argv = sys.argv
        previous_lief = _sym_mod.lief
        sys.argv = ["symbols.py", "--binary", __file__, "--all"]
        _sym_mod.lief = None
        self.addCleanup(setattr, sys, "argv", previous_argv)
        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)

        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = _sym_mod.main()

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["meta"]["module"], "symbols")
        self.assertIn("symbols", payload)

    def test_main_writes_json_payload_to_output_file(self):
        import contextlib
        import io
        import json
        import sys

        import backends.static.binary.symbols as _sym_mod

        previous_argv = sys.argv
        previous_lief = _sym_mod.lief
        _sym_mod.lief = None
        self.addCleanup(setattr, sys, "argv", previous_argv)
        self.addCleanup(setattr, _sym_mod, "lief", previous_lief)

        with tempfile.NamedTemporaryFile() as output:
            sys.argv = [
                "symbols.py",
                "--binary",
                __file__,
                "--output",
                output.name,
            ]
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = _sym_mod.main()

            payload = json.loads(Path(output.name).read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertIn("Symbols written to", stdout.getvalue())
        self.assertEqual(payload["meta"]["module"], "symbols")

    def test_raw_blob_fallback_symbol_candidates(self):
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00sub_401000\x00main\x00plainword\x00_start\x00")
            raw_path = f.name
        try:
            symbols = extract_symbols(raw_path)
            names = {sym["name"] for sym in symbols}
            self.assertIn("sub_401000", names)
            self.assertIn("main", names)
            self.assertIn("_start", names)
            self.assertNotIn("plainword", names)
            self.assertTrue(
                all(sym.get("source") == "string-reference" for sym in symbols)
            )
        finally:
            os.unlink(raw_path)

    def test_symbols_have_size_field(self):
        """Chaque symbole doit avoir un champ size (int ou None)."""
        import backends.static.binary.symbols as _sym_mod

        if _sym_mod.lief is None:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            binary = compile_minimal_elf(Path(tmp))
            if not binary:
                self.skipTest("gcc non disponible")
            symbols = extract_symbols(str(binary))
            self.assertGreater(len(symbols), 0)
            for sym in symbols:
                self.assertIn("size", sym, f"Missing 'size' in {sym}")
                self.assertTrue(sym["size"] is None or isinstance(sym["size"], int))


if __name__ == "__main__":
    unittest.main()
