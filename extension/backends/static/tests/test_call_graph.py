# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for call_graph.py."""

from __future__ import annotations

import os
import sys
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

BINARY = os.path.join(ROOT, "examples", "demo_analysis.elf")

from backends.static.disasm.call_graph import build_call_graph, resolve_plt_symbols

# ── resolve_plt_symbols ──────────────────────────────────────────────────────


def test_resolve_plt_returns_dict():
    result = resolve_plt_symbols(BINARY)
    assert isinstance(result, dict)


def test_resolve_plt_nonexistent():
    result = resolve_plt_symbols("/nonexistent/binary")
    assert result == {}


# ── build_call_graph ─────────────────────────────────────────────────────────


def _make_cfg(blocks: list[dict], edges: list[dict] | None = None) -> dict:
    return {"blocks": blocks, "edges": edges or []}


def test_build_call_graph_empty():
    result = build_call_graph(_make_cfg([]), symbols=[], binary_path=None)
    assert "nodes" in result
    assert "edges" in result
    assert result["nodes"] == []
    assert result["edges"] == []


def test_build_call_graph_result_structure():
    """Result must always contain nodes and edges keys."""
    result = build_call_graph(_make_cfg([]), symbols=[], binary_path=None)
    for key in ("nodes", "edges"):
        assert key in result, f"Missing key: {key}"


def test_build_call_graph_with_lines_call():
    """Lines with CALL instructions should produce edges."""
    lines = [
        {"addr": "0x1000", "text": "push rbp"},
        {"addr": "0x1001", "text": "call 0x2000"},
        {"addr": "0x1006", "text": "ret"},
    ]
    result = build_call_graph(_make_cfg([]), symbols=[], lines=lines, binary_path=None)
    assert isinstance(result["edges"], list)


def test_build_call_graph_no_duplicate_nodes():
    """Each address should appear at most once in nodes."""
    lines = [
        {"addr": "0x1000", "text": "call 0x2000"},
        {"addr": "0x1005", "text": "call 0x2000"},  # same target twice
    ]
    result = build_call_graph(_make_cfg([]), symbols=[], lines=lines, binary_path=None)
    node_addrs = [n["addr"] for n in result["nodes"]]
    assert len(node_addrs) == len(set(node_addrs))


def test_build_call_graph_symbols_become_nodes():
    """Symbols should appear in the node list."""
    syms = [{"addr": "0x1000", "name": "main", "type": "func"}]
    result = build_call_graph(_make_cfg([]), symbols=syms, binary_path=None)
    assert isinstance(result["nodes"], list)


class TestBuildCallGraphFallback(unittest.TestCase):
    def test_lines_without_cfg_build_direct_call_edges(self):
        lines = [
            {"addr": "0x1000", "text": "push rbp"},
            {"addr": "0x1001", "text": "call 0x2000 <puts@plt>"},
            {"addr": "0x1006", "text": "ret"},
        ]

        result = build_call_graph(
            _make_cfg([]), symbols=[], lines=lines, binary_path=None
        )

        self.assertEqual(len(result["edges"]), 1)
        self.assertEqual(result["edges"][0]["from"], "0x1001")
        self.assertEqual(result["edges"][0]["to"], "0x2000")
        self.assertEqual(result["edges"][0]["to_name"], "puts@plt")

    def test_lines_fallback_handles_multi_arch_call_bytes(self):
        lines = [
            {"addr": "0x800000", "text": "27bdfff0 addiu sp, sp, -0x10"},
            {"addr": "0x800004", "text": "0c200008 jal 0x800020 <callee>"},
            {"addr": "0x800008", "text": "03e00008 jr ra"},
        ]

        result = build_call_graph(
            _make_cfg([]),
            symbols=[
                {"addr": "0x800000", "name": "main"},
                {"addr": "0x800020", "name": "callee"},
            ],
            lines=lines,
            binary_path=None,
        )

        self.assertEqual(len(result["edges"]), 1)
        edge = result["edges"][0]
        self.assertEqual(edge["from"], "0x800004")
        self.assertEqual(edge["to"], "0x800020")
        self.assertEqual(edge["from_name"], "main")
        self.assertEqual(edge["to_name"], "callee")


class TestResolveMachOStubs(unittest.TestCase):
    def test_macho_stub_resolution_uses_reserved2_entry_size(self):
        from types import SimpleNamespace

        from backends.static.disasm.call_graph import _resolve_macho_stubs

        class FakeSection:
            virtual_address = 0x100001048
            size = 108
            reserved2 = 6

        class FakeBinary:
            imported_functions = [
                SimpleNamespace(name="_strcmp"),
                SimpleNamespace(name="_printf"),
                SimpleNamespace(name="_system"),
            ]

            def get_section(self, name):
                return FakeSection() if name == "__stubs" else None

        result = _resolve_macho_stubs(FakeBinary())

        self.assertEqual(result["0x100001048"], "strcmp@plt")
        self.assertEqual(result["0x10000104e"], "printf@plt")
        self.assertEqual(result["0x100001054"], "system@plt")
