# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for backends.static.compat.ida.shim (fake idc/idautils/idaapi modules)."""

import importlib.util
import os
import sys
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

from backends.static.compat.ida.context import BADADDR, IdaContext
from backends.static.compat.ida.shim import (
    build_idaapi_module,
    build_idautils_module,
    build_idc_module,
    patched_ida_runtime,
)


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


@pytest.fixture()
def ctx(binary_path):
    context = IdaContext(binary_path)
    yield context
    context.close()


def test_idc_badaddr_constant(ctx):
    idc = build_idc_module(ctx)
    assert idc.BADADDR == BADADDR


def test_idc_get_name_ea_simple_unknown_returns_badaddr(ctx):
    idc = build_idc_module(ctx)
    assert idc.get_name_ea_simple("does_not_exist") == BADADDR


def test_idc_set_name_and_get_func_name_roundtrip(ctx):
    idc = build_idc_module(ctx)
    ea = idc.next_head(0)
    assert idc.set_name(ea, "my_renamed_func") is True
    assert idc.get_func_name(ea) == "my_renamed_func"
    assert idc.get_name(ea) == "my_renamed_func"


def test_idc_set_name_persists_with_script_source(ctx):
    idc = build_idc_module(ctx)
    ea = idc.next_head(0)
    idc.set_name(ea, "scripted_name")
    rows = [r for r in ctx.store().list() if r["kind"] == "rename"]
    assert any(r["value"] == "scripted_name" and r["source"] == "script" for r in rows)


def test_idc_set_cmt_and_get_cmt_roundtrip(ctx):
    idc = build_idc_module(ctx)
    ea = idc.next_head(0)
    assert idc.set_cmt(ea, "hello") is True
    assert idc.get_cmt(ea) == "hello"


def test_idc_get_cmt_returns_none_when_absent(ctx):
    idc = build_idc_module(ctx)
    assert idc.get_cmt(0x400078) is None


def test_idc_next_head_and_prev_head_walk_addresses(ctx):
    idc = build_idc_module(ctx)
    first = idc.next_head(0)
    assert first != BADADDR
    second = idc.next_head(first)
    assert second != BADADDR
    assert second > first
    assert idc.prev_head(second) == first
    assert idc.prev_head(first) == BADADDR


def test_idc_get_bytes_returns_raw_instruction_bytes(ctx):
    idc = build_idc_module(ctx)
    ea = idc.next_head(0)
    raw = idc.get_bytes(ea, 1)
    assert raw is not None
    assert len(raw) == 1


def test_idc_get_bytes_unknown_address_returns_none(ctx):
    idc = build_idc_module(ctx)
    assert idc.get_bytes(0x1, 4) is None


def test_idc_getdisasm_returns_text(ctx):
    idc = build_idc_module(ctx)
    ea = idc.next_head(0)
    text = idc.GetDisasm(ea)
    assert isinstance(text, str)
    assert text != ""


def test_idc_getdisasm_unknown_address_returns_empty_string(ctx):
    idc = build_idc_module(ctx)
    assert idc.GetDisasm(0x1) == ""


def test_idc_unmapped_attribute_raises_not_implemented(ctx):
    idc = build_idc_module(ctx)
    with pytest.raises(NotImplementedError):
        idc.some_totally_unmapped_api(1, 2)


def test_idautils_functions_empty_without_symtab(ctx):
    idautils = build_idautils_module(ctx)
    assert list(idautils.Functions()) == []


def test_idautils_unmapped_attribute_raises_not_implemented(ctx):
    idautils = build_idautils_module(ctx)
    with pytest.raises(NotImplementedError):
        idautils.SomeUnmappedThing()


def test_idaapi_get_func_returns_none_when_unknown(ctx):
    idaapi = build_idaapi_module(ctx)
    assert idaapi.get_func(0x400078) is None


def test_idaapi_get_imagebase_zero_without_functions(ctx):
    idaapi = build_idaapi_module(ctx)
    assert idaapi.get_imagebase() == 0


def test_idaapi_unmapped_attribute_raises_not_implemented(ctx):
    idaapi = build_idaapi_module(ctx)
    with pytest.raises(NotImplementedError):
        idaapi.SomeUnmappedThing()


def test_patched_ida_runtime_injects_and_restores_modules(binary_path):
    for name in ("idc", "idautils", "idaapi"):
        sys.modules.pop(name, None)

    with patched_ida_runtime(binary_path) as modules:
        assert sys.modules["idc"] is modules["idc"]
        assert sys.modules["idautils"] is modules["idautils"]
        assert sys.modules["idaapi"] is modules["idaapi"]
        import idc  # noqa: F401 — proves import works transparently

        assert idc.BADADDR == BADADDR

    assert "idc" not in sys.modules
    assert "idautils" not in sys.modules
    assert "idaapi" not in sys.modules


def test_patched_ida_runtime_restores_previous_module(binary_path):
    import types

    sentinel = types.ModuleType("idc")
    sys.modules["idc"] = sentinel
    try:
        with patched_ida_runtime(binary_path):
            assert sys.modules["idc"] is not sentinel
        assert sys.modules["idc"] is sentinel
    finally:
        sys.modules.pop("idc", None)
