# SPDX-License-Identifier: AGPL-3.0-only
"""Regression coverage for raw Mach-O n_type handling (issue #435)."""

import shutil
import subprocess
import sys
import warnings
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from backends.static.binary import symbols


def test_real_lief_symbol_types_preserve_stab_and_external_bits(tmp_path):
    lief = pytest.importorskip("lief")
    records = []
    # Debug records precede their real definitions, as in clang -g output.
    for name, raw_type, value in [
        ("source.c", 0x64, 0),  # N_SO
        ("object.o", 0x66, 0),  # N_OSO
        ("_main", 0x24, 0x1234),  # N_FUN
        ("_main", 0x0F, 0x1000),  # N_SECT | N_EXT
        ("_local", 0x0E, 0x1020),
        ("_private", 0x1F, 0x1040),  # N_PEXT | N_SECT | N_EXT
        ("_absolute", 0x03, 0x42),  # N_ABS | N_EXT
        ("_malloc", 0x01, 0),  # N_UNDF | N_EXT
    ]:
        record = lief.MachO.Symbol()
        record.name, record.raw_type, record.value = name, raw_type, value
        records.append(record)

    class Binary:
        def __init__(self):
            self.symbols = records

    fake_lief = SimpleNamespace(
        parse=lambda _: Binary(),
        ELF=lief.ELF,
        MachO=SimpleNamespace(Binary=Binary),
        PE=lief.PE,
    )
    path = tmp_path / "symbols.macho"
    path.touch()
    with patch.object(symbols, "lief", fake_lief), warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        defined = {s["name"]: s for s in symbols.extract_symbols(str(path))}
        all_symbols = {
            s["name"]: s for s in symbols.extract_symbols(str(path), defined_only=False)
        }
    assert set(defined) == {"_main", "_local", "_private", "_absolute"}
    assert defined["_main"]["addr"] == "0x1000"
    assert defined["_main"]["size"] == 0x20
    assert defined["_private"]["type"] == "T"
    assert defined["_absolute"]["type"] == "A"
    assert all_symbols["_malloc"]["type"] == "U"


@pytest.mark.skipif(sys.platform != "darwin", reason="requires the macOS linker")
def test_clang_debug_macho_retains_real_functions_without_warnings(tmp_path):
    lief = pytest.importorskip("lief")
    clang = shutil.which("clang")
    if not clang:
        pytest.skip("clang unavailable")
    source = tmp_path / "repro.c"
    source.write_text(
        "#include <stdlib.h>\n#include <string.h>\n"
        "__attribute__((noinline)) static void f(size_t count) {\n"
        "  size_t total = count * sizeof(int);\n"
        "  int *items = malloc(total);\n"
        "  if (!items) return;\n"
        "  memset(items, 0, total); free(items);\n"
        "}\nint main(int argc, char **argv) { (void)argv; f((size_t)argc); return 0; }\n"
    )
    binary = tmp_path / "repro"
    subprocess.run([clang, "-O0", "-g", str(source), "-o", str(binary)], check=True)
    parsed = lief.parse(str(binary))
    assert isinstance(parsed, lief.MachO.Binary)
    assert any(s.raw_type & 0xE0 for s in parsed.symbols)
    expected = {
        s.name: s.value
        for s in parsed.symbols
        if not s.raw_type & 0xE0 and s.name in {"_f", "_main"}
    }
    assert set(expected) == {"_f", "_main"}
    with warnings.catch_warnings():
        warnings.simplefilter("error", RuntimeWarning)
        extracted = {s["name"]: s for s in symbols.extract_symbols(str(binary))}
    for name, address in expected.items():
        assert extracted[name]["type"] == "T"
        assert int(extracted[name]["addr"], 16) == address
    assert "repro.c" not in extracted
    assert "_malloc" not in extracted
