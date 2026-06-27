# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for asm_sim.py — static assembly simulator."""

from __future__ import annotations

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.static.disasm.asm_sim import (
    parse_int64,
    parse_program,
    simulate,
    tokenize,
    trim_line,
)


# ── trim_line ────────────────────────────────────────────────────────────────


def test_trim_line_removes_comment():
    assert trim_line("mov rax, 1 ; comment") == "mov rax, 1"


def test_trim_line_strips_whitespace():
    assert trim_line("  push rbp  ") == "push rbp"


def test_trim_line_empty():
    assert trim_line("; full comment") == ""


# ── tokenize ─────────────────────────────────────────────────────────────────


def test_tokenize_simple():
    tokens = tokenize("mov rax, rbx")
    assert tokens[0] == "mov"
    assert "rax" in tokens
    assert "rbx" in tokens


def test_tokenize_ignores_commas():
    tokens = tokenize("add rax, 1")
    assert "," not in tokens


# ── parse_int64 ──────────────────────────────────────────────────────────────


def test_parse_int64_decimal():
    assert parse_int64("42") == 42


def test_parse_int64_hex():
    assert parse_int64("0x10") == 16


def test_parse_int64_negative():
    result = parse_int64("-1")
    assert result is not None and result < 0


def test_parse_int64_invalid():
    assert parse_int64("rax") is None


# ── parse_program + simulate ──────────────────────────────────────────────────


def _run(asm_lines: list[str]) -> list[dict]:
    numbered = [(i + 1, line) for i, line in enumerate(asm_lines)]
    program, labels = parse_program(numbered)
    return simulate(program, labels)


def _reg(trace_step: dict, name: str) -> int | None:
    """Get register value by name from a trace step."""
    for r in trace_step.get("registers", []):
        if r["name"] == name:
            return r["value"]
    return None


def test_simulate_push_pop():
    trace = _run(["push 42", "pop rax"])
    assert len(trace) >= 1


def test_simulate_mov_register():
    trace = _run(["mov rax, 10", "mov rbx, rax"])
    last = trace[-1]
    assert _reg(last, "rbx") == 10


def test_simulate_add():
    trace = _run(["mov rax, 3", "mov rbx, 4", "add rax, rbx"])
    last = trace[-1]
    assert _reg(last, "rax") == 7


def test_simulate_sub():
    trace = _run(["mov rax, 10", "sub rax, 3"])
    last = trace[-1]
    assert _reg(last, "rax") == 7


def test_simulate_returns_list():
    trace = _run(["push rbp"])
    assert isinstance(trace, list)


def test_simulate_empty_program():
    trace = _run([])
    assert isinstance(trace, list)


def test_simulate_trace_has_required_fields():
    trace = _run(["mov rax, 1"])
    if trace:
        for key in ("step", "instr", "registers"):
            assert key in trace[0], f"Missing key: {key}"
