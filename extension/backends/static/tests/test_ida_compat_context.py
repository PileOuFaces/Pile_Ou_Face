# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for backends.static.compat.ida.context.IdaContext."""

import importlib.util
import os
import tempfile
from pathlib import Path

import pytest


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()

from backends.static.compat.ida.context import IdaContext, ea_to_addr, parse_ea


@pytest.fixture()
def binary_path(request):
    # AnnotationDb keys annotations by sha256 of file content, so tests
    # sharing an identical fixture ELF would otherwise collide on the
    # same global ~/.pile-ou-face/annotations.db — make each unique.
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "test.elf")
    make_minimal_elf(path)
    with open(path, "ab") as f:
        f.write(request.node.name.encode())
    return path


def test_parse_ea_accepts_hex_and_decimal_strings_and_ints():
    assert parse_ea("0x400078") == 0x400078
    assert parse_ea("4194424") == 4194424
    assert parse_ea(0x400078) == 0x400078


def test_parse_ea_rejects_bool_and_empty_string():
    with pytest.raises(TypeError):
        parse_ea(True)
    with pytest.raises(ValueError):
        parse_ea("")


def test_ea_to_addr_roundtrip():
    assert ea_to_addr(0x400078) == "0x400078"
    assert parse_ea(ea_to_addr(0x400078)) == 0x400078


def test_lines_returns_decoded_instructions(binary_path):
    ctx = IdaContext(binary_path)
    lines = ctx.lines()
    assert len(lines) > 0
    assert all("addr" in line and "text" in line for line in lines)


def test_lines_is_memoized(binary_path):
    ctx = IdaContext(binary_path)
    first = ctx.lines()
    assert ctx.lines() is first


def test_symbols_and_functions_do_not_crash_without_symtab(binary_path):
    ctx = IdaContext(binary_path)
    assert ctx.symbols() == []
    assert ctx.functions() == []


def test_function_containing_returns_none_when_unknown(binary_path):
    ctx = IdaContext(binary_path)
    assert ctx.function_containing(0x400078) is None


def test_store_roundtrip_and_close(binary_path):
    ctx = IdaContext(binary_path)
    store = ctx.store()
    store.rename("0x400078", "my_func", source="script")
    assert ctx.store() is store
    assert ctx.store().get_name("0x400078") == "my_func"
    ctx.close()
