# SPDX-License-Identifier: AGPL-3.0-only
"""Integration tests: idc/idautils/idaapi importable transparently in repl.py scripts."""

import base64
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_venv_python = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
PYTHON = _venv_python if os.path.exists(_venv_python) else sys.executable
REPL = os.path.join(ROOT, "backends", "static", "repl", "repl.py")


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def _make_binary(tag: str) -> str:
    tmp = tempfile.mkdtemp()
    path = os.path.join(tmp, "test.elf")
    make_minimal_elf(path)
    with open(path, "ab") as f:
        f.write(tag.encode())
    return path


def _run(code: str, binary: str) -> dict:
    b64 = base64.b64encode(code.encode()).decode()
    r = subprocess.run(
        [PYTHON, REPL, "--code", b64, "--binary", binary],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(r.stdout)


def test_idc_idautils_idaapi_importable():
    binary = _make_binary("test_idc_idautils_idaapi_importable")
    result = _run(
        "import idc, idautils, idaapi\n"
        "print(idc.BADADDR)\n"
        "print(list(idautils.Functions()))\n"
        "print(idaapi.get_imagebase())\n",
        binary,
    )
    assert result["ok"] is True, result["stderr"]
    assert str(idc_badaddr()) in result["stdout"]


def idc_badaddr() -> int:
    from backends.static.compat.ida.context import BADADDR

    return BADADDR


def test_idc_set_name_persists_via_annotation_store():
    binary = _make_binary("test_idc_set_name_persists_via_annotation_store")
    result = _run(
        "import idc\n"
        "ea = idc.next_head(0)\n"
        "idc.set_name(ea, 'scripted_via_repl')\n"
        "print(idc.get_func_name(ea))\n",
        binary,
    )
    assert result["ok"] is True, result["stderr"]
    assert "scripted_via_repl" in result["stdout"]

    from backends.static.annotations.annotations import AnnotationStore

    with AnnotationStore(binary) as store:
        rows = [r for r in store.list() if r["kind"] == "rename"]
        assert any(
            r["value"] == "scripted_via_repl" and r["source"] == "script" for r in rows
        )


def test_unmapped_idc_api_raises_not_implemented():
    binary = _make_binary("test_unmapped_idc_api_raises_not_implemented")
    result = _run("import idc\nidc.jumpto(0x1234)\n", binary)
    assert result["ok"] is False
    assert "NotImplementedError" in result["stderr"]


def test_idc_module_not_leaked_after_script():
    binary = _make_binary("test_idc_module_not_leaked_after_script")
    result = _run(
        "import idc\nprint('ok')\n",
        binary,
    )
    assert result["ok"] is True
