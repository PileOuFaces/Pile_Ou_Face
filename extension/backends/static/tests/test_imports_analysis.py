# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.imports_analysis."""

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.imports_analysis import (
    _compute_score,
    _extract_string_import_candidates,
    _find_suspicious,
    _group_by_dll,
    analyze_imports,
)


class TestAnalyzeImports(unittest.TestCase):
    def test_nonexistent_file_returns_error(self):
        result = analyze_imports("/nonexistent/binary.exe")
        self.assertIn("error", result)
        self.assertIsInstance(result["imports"], list)
        self.assertIsInstance(result["suspicious"], list)
        self.assertEqual(result["score"], 0)

    def test_pe_no_crash(self):
        """analyze_imports() sur un PE minimal ne plante pas."""
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        import os

        try:
            write_minimal_pe64(pe_path)
            result = analyze_imports(pe_path)
            self.assertIsInstance(result.get("imports"), list)
            self.assertIsInstance(result.get("suspicious"), list)
            self.assertIsInstance(result.get("score"), int)
            self.assertIsNone(result.get("error"))
        finally:
            os.unlink(pe_path)

    def test_result_structure(self):
        """La structure de retour est toujours conforme même sur erreur."""
        result = analyze_imports("/nonexistent")
        for key in ("imports", "suspicious", "score", "error"):
            self.assertIn(key, result)

    def test_raw_blob_fallback_finds_suspicious_string_refs(self):
        import os

        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00VirtualAlloc\x00socket\x00plain\x00")
            raw_path = f.name
        try:
            result = analyze_imports(raw_path)
            self.assertIsNone(result["error"])
            self.assertEqual(result.get("source"), "string-reference")
            self.assertGreater(result["score"], 0)
            names = {entry["function"] for entry in result["suspicious"]}
            self.assertIn("VirtualAlloc", names)
        finally:
            os.unlink(raw_path)


class TestGroupByDll(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(_group_by_dll([]), [])

    def test_groups_correctly(self):
        raw = [
            ("kernel32.dll", "CreateFile"),
            ("kernel32.dll", "ReadFile"),
            ("user32.dll", "MessageBox"),
        ]
        result = _group_by_dll(raw)
        by_dll = {entry["dll"]: entry for entry in result}
        self.assertIn("kernel32.dll", by_dll)
        self.assertEqual(by_dll["kernel32.dll"]["count"], 2)
        self.assertIn("CreateFile", by_dll["kernel32.dll"]["functions"])

    def test_unknown_dll(self):
        raw = [("", "malloc"), ("", "free")]
        result = _group_by_dll(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["dll"], "<unknown>")
        self.assertEqual(result[0]["count"], 2)


class TestFindSuspicious(unittest.TestCase):
    def test_empty_input(self):
        self.assertEqual(_find_suspicious([]), [])

    def test_detects_virtualalloc(self):
        raw = [("kernel32.dll", "VirtualAlloc"), ("kernel32.dll", "ReadFile")]
        result = _find_suspicious(raw)
        names = [r["function"] for r in result]
        self.assertIn("VirtualAlloc", names)
        categories = [r["category"] for r in result]
        self.assertIn("INJECTION", categories)

    def test_no_duplicates(self):
        raw = [("a.dll", "VirtualAlloc"), ("b.dll", "VirtualAlloc")]
        result = _find_suspicious(raw)
        names = [r["function"] for r in result]
        self.assertEqual(len(names), len(set(n.lower() for n in names)))

    def test_detects_isdebuggerpresent(self):
        raw = [("kernel32.dll", "IsDebuggerPresent")]
        result = _find_suspicious(raw)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["category"], "ANTI_DEBUG")

    def test_normal_functions_not_flagged(self):
        raw = [
            ("kernel32.dll", "ReadFile"),
            ("kernel32.dll", "WriteFile"),
            ("libc.so", "printf"),
        ]
        result = _find_suspicious(raw)
        self.assertEqual(result, [])

    def test_string_candidate_extraction_normalizes_versions(self):
        raw = _extract_string_import_candidates(
            b"\x00_system@@GLIBC_2.2.5\x00printf\x00"
        )
        self.assertEqual(raw, [("<strings>", "_system@@GLIBC_2.2.5")])


class TestComputeScore(unittest.TestCase):
    def test_empty_returns_zero(self):
        self.assertEqual(_compute_score([]), 0)

    def test_score_bounded_to_100(self):
        many = [
            {
                "function": f"f{i}",
                "dll": "a.dll",
                "category": "INJECTION",
                "description": "",
            }
            for i in range(20)
        ]
        score = _compute_score(many)
        self.assertLessEqual(score, 100)

    def test_injection_scores_higher_than_network(self):
        inj = [
            {
                "function": "VirtualAlloc",
                "dll": "",
                "category": "INJECTION",
                "description": "",
            }
        ]
        net = [
            {"function": "socket", "dll": "", "category": "NETWORK", "description": ""}
        ]
        self.assertGreater(_compute_score(inj), _compute_score(net))


if __name__ == "__main__":
    unittest.main()
