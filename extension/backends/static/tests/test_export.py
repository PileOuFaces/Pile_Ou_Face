# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.export.export."""

import csv
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.export.export import (
    export_cfg_dot,
    export_strings_csv,
    export_symbols_csv,
    export_xrefs_json,
)

SAMPLE_SYMBOLS = [
    {"name": "_main", "addr": "0x401000", "type": "T"},
    {"name": "_puts", "addr": "0x401100", "type": "U"},
]

SAMPLE_STRINGS = [
    {"addr": "0x402000", "value": "hello world", "length": 11},
    {"addr": "0x402020", "value": "foo", "length": 3},
]

SAMPLE_XREF_MAP = {
    "0x401000": [
        {"from_addr": "0x401234", "type": "call", "from_line": 10},
    ],
    "0x402000": [
        {"from_addr": "0x401010", "type": "load", "from_line": 5},
        {"from_addr": "0x401020", "type": "store", "from_line": 7},
    ],
}

SAMPLE_CFG = {
    "blocks": [
        {
            "addr": "0x401000",
            "lines": [
                {"addr": "0x401000", "text": "push rbp", "line": 1},
                {"addr": "0x401001", "text": "jne\t0x401010", "line": 2},
            ],
            "successors": ["0x401010", "0x401003"],
            "is_call": False,
        },
        {
            "addr": "0x401003",
            "lines": [
                {"addr": "0x401003", "text": "ret", "line": 3},
            ],
            "successors": [],
            "is_call": False,
        },
        {
            "addr": "0x401010",
            "lines": [
                {"addr": "0x401010", "text": "mov rax, 0", "line": 4},
            ],
            "successors": [],
            "is_call": False,
        },
    ],
    "edges": [
        {"from": "0x401000", "to": "0x401010", "type": "jmp"},
        {"from": "0x401000", "to": "0x401003", "type": "fallthrough"},
    ],
}


class TestExportSymbolsCsv(unittest.TestCase):
    def test_creates_csv_with_header(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            n = export_symbols_csv(SAMPLE_SYMBOLS, path)
            self.assertEqual(n, 2)
            with open(path, newline="", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
            self.assertEqual(len(reader), 2)
            self.assertEqual(reader[0]["name"], "_main")
            self.assertEqual(reader[0]["addr"], "0x401000")
            self.assertEqual(reader[0]["type"], "T")
        finally:
            Path(path).unlink(missing_ok=True)

    def test_empty_symbols(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            n = export_symbols_csv([], path)
            self.assertEqual(n, 0)
            with open(path, newline="", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
            self.assertEqual(reader, [])
        finally:
            Path(path).unlink(missing_ok=True)


class TestExportStringsCsv(unittest.TestCase):
    def test_creates_csv_with_values(self):
        with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as f:
            path = f.name
        try:
            n = export_strings_csv(SAMPLE_STRINGS, path)
            self.assertEqual(n, 2)
            with open(path, newline="", encoding="utf-8") as f:
                reader = list(csv.DictReader(f))
            self.assertEqual(reader[0]["value"], "hello world")
            self.assertEqual(reader[0]["length"], "11")
        finally:
            Path(path).unlink(missing_ok=True)


class TestExportXrefsJson(unittest.TestCase):
    def test_creates_json_with_map(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            n = export_xrefs_json(SAMPLE_XREF_MAP, path)
            self.assertEqual(n, 2)
            with open(path, encoding="utf-8") as f:
                data = json.load(f)
            self.assertIn("0x401000", data)
            self.assertEqual(len(data["0x402000"]), 2)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_empty_xref_map(self):
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            n = export_xrefs_json({}, path)
            self.assertEqual(n, 0)
        finally:
            Path(path).unlink(missing_ok=True)


class TestExportCfgDot(unittest.TestCase):
    def test_creates_dot_file(self):
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            path = f.name
        try:
            n = export_cfg_dot(SAMPLE_CFG, path)
            self.assertEqual(n, 3)
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("digraph", content)
            self.assertIn("->", content)
            self.assertIn("0x401000", content)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_dot_contains_edge_types(self):
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            path = f.name
        try:
            export_cfg_dot(SAMPLE_CFG, path)
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("fallthrough", content)
            self.assertIn("jmp", content)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_empty_cfg(self):
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            path = f.name
        try:
            n = export_cfg_dot({"blocks": [], "edges": []}, path)
            self.assertEqual(n, 0)
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("digraph", content)
        finally:
            Path(path).unlink(missing_ok=True)

    def test_custom_graph_name(self):
        with tempfile.NamedTemporaryFile(suffix=".dot", delete=False) as f:
            path = f.name
        try:
            export_cfg_dot(SAMPLE_CFG, path, graph_name="MyFunction")
            content = Path(path).read_text(encoding="utf-8")
            self.assertIn("MyFunction", content)
        finally:
            Path(path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
