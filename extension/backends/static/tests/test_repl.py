# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the repl.py script executor."""

import base64
import json
import os
import subprocess

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
PYTHON = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
REPL = os.path.join(ROOT, "backends", "static", "repl", "repl.py")
BINARY = os.path.join(ROOT, "examples", "demo_analysis.elf")


def _run(code: str, binary: str = BINARY) -> dict:
    b64 = base64.b64encode(code.encode()).decode()
    r = subprocess.run(
        [PYTHON, REPL, "--code", b64, "--binary", binary],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(r.stdout)


def test_print_hello():
    result = _run('print("hello")')
    assert result["ok"] is True
    assert "hello" in result["stdout"]


def test_binary_variable_injected():
    result = _run("print(binary)")
    assert result["ok"] is True
    assert "demo_analysis.elf" in result["stdout"]


def test_static_modules_importable():
    result = _run(
        "from backends.static.binary.symbols import extract_symbols; print(type(extract_symbols))"
    )
    assert result["ok"] is True
    assert "function" in result["stdout"]


def test_syntax_error():
    result = _run("def ()")
    assert result["ok"] is False
    assert "SyntaxError" in result["stderr"]


def test_runtime_error():
    result = _run("1/0")
    assert result["ok"] is False
    assert "ZeroDivisionError" in result["stderr"]


def test_duration_present():
    result = _run("print(1)")
    assert "duration_ms" in result
    assert isinstance(result["duration_ms"], (int, float))
