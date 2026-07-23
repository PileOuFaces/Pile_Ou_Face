# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour l'orchestrateur d'auto-triage IA (#124)."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp import auto_triage as at
from backends.mcp.server import _call_tool
from backends.static.annotations.annotations import AnnotationStore
from backends.static.tests.fixtures.real_binary_corpus import (
    CorpusSpec,
    build_corpus_binary,
)

warnings.filterwarnings(
    "ignore",
    message=r".* is not a valid TYPE\.",
    category=RuntimeWarning,
)


class TestSelectCandidateFunctions(unittest.TestCase):
    def _budget(self, max_functions: int = 200) -> at.TriageBudget:
        return at.TriageBudget(max_functions=max_functions)

    def test_filters_ignored_and_user_annotated(self):
        call_graph = {
            "nodes": [
                {"addr": "0x1000", "name": "_start"},
                {"addr": "0x2000", "name": "do_thing"},
                {"addr": "0x3000", "name": "user_named"},
            ],
            "edges": [],
        }
        existing = [{"addr": "0x3000", "source": "user"}]
        candidates = at.select_candidate_functions(
            call_graph, [], {}, {}, existing, self._budget()
        )
        addrs = {c.addr for c in candidates}
        self.assertEqual(addrs, {"0x2000"})

    def test_sensitive_keyword_callee_boosts_score_and_reason(self):
        call_graph = {
            "nodes": [
                {"addr": "0x1000", "name": "quiet_fn"},
                {"addr": "0x2000", "name": "net_fn"},
            ],
            "edges": [{"from": "0x2000", "to_name": "socket_connect"}],
        }
        candidates = at.select_candidate_functions(
            call_graph, [], {}, {}, [], self._budget()
        )
        by_addr = {c.addr: c for c in candidates}
        self.assertGreater(by_addr["0x2000"].score, by_addr["0x1000"].score)
        self.assertTrue(any("socket" in r for r in by_addr["0x2000"].reasons))

    def test_truncates_to_budget_max_functions(self):
        call_graph = {
            "nodes": [{"addr": f"0x{i:04x}", "name": f"fn_{i}"} for i in range(10)],
            "edges": [],
        }
        candidates = at.select_candidate_functions(
            call_graph, [], {}, {}, [], self._budget(max_functions=3)
        )
        self.assertEqual(len(candidates), 3)


class TestAnalyzeFunction(unittest.TestCase):
    def _candidate(self) -> at.FunctionCandidate:
        return at.FunctionCandidate(addr="0x1000", name="fn", score=1.0, reasons=[])

    @patch("backends.mcp.auto_triage._call_tool")
    @patch("backends.mcp.auto_triage.call_provider_result")
    def test_calls_provider_and_parses_json(self, mock_call, mock_tool):
        mock_tool.return_value = {"ok": False}
        mock_call.return_value = {
            "text": '```json\n{"name": "parse_header", "docstring": "Parses the header.", '
            '"tags": ["filesystem"]}\n```'
        }
        analysis = at.analyze_function(
            self._candidate(), "/tmp/bin", "ollama", None, at.TriageBudget()
        )
        self.assertIsNone(analysis.error)
        self.assertEqual(analysis.generated_name, "parse_header")
        self.assertEqual(analysis.docstring, "Parses the header.")
        self.assertEqual(analysis.tags, ["filesystem"])
        mock_call.assert_called_once()

    @patch("backends.mcp.auto_triage._call_tool")
    @patch("backends.mcp.auto_triage.call_provider_result")
    def test_handles_malformed_llm_response(self, mock_call, mock_tool):
        mock_tool.return_value = {"ok": False}
        mock_call.return_value = {"text": "not json at all"}
        analysis = at.analyze_function(
            self._candidate(), "/tmp/bin", "ollama", None, at.TriageBudget()
        )
        self.assertEqual(analysis.error, "malformed_llm_response")
        self.assertEqual(analysis.generated_name, "")

    @patch("backends.mcp.auto_triage._call_tool")
    @patch("backends.mcp.auto_triage.call_provider_result")
    def test_provider_exception_does_not_raise(self, mock_call, mock_tool):
        mock_tool.return_value = {"ok": False}
        mock_call.side_effect = RuntimeError("network down")
        analysis = at.analyze_function(
            self._candidate(), "/tmp/bin", "ollama", None, at.TriageBudget()
        )
        self.assertIsNotNone(analysis.error)
        self.assertIn("network down", analysis.error or "")


class TestRenderMarkdownReport(unittest.TestCase):
    def test_report_contains_expected_sections(self):
        analyses = [
            at.FunctionAnalysis(
                addr="0x1000",
                name="fn_a",
                generated_name="parse_header",
                docstring="Parses stuff.",
                tags=["filesystem"],
            ),
            at.FunctionAnalysis(
                addr="0x2000",
                name="fn_b",
                generated_name="",
                docstring="",
                tags=[],
                error="malformed_llm_response",
            ),
        ]
        summary = {"text": "Résumé bidon.", "categories": ["filesystem"]}
        stats = {"processed": 2, "annotated": 1, "elapsed_s": 1.234}
        report = at.render_markdown_report("/tmp/some.bin", analyses, summary, stats)
        self.assertIn("# Rapport d'auto-triage IA", report)
        self.assertIn("Résumé exécutif", report)
        self.assertIn("Classification", report)
        self.assertIn("Fonctions prioritaires", report)
        self.assertIn("parse_header", report)
        self.assertIn("fn_b", report)
        self.assertIn("Généré automatiquement par IA", report)


def _mocked_provider_result(call_count: list[int]):
    def _impl(provider, prompt, context, model, on_token=None, generation_options=None):
        call_count[0] += 1
        return {
            "text": json.dumps(
                {
                    "name": f"triaged_fn_{call_count[0]}",
                    "docstring": f"Fonction analysée automatiquement #{call_count[0]}.",
                    "tags": ["other"],
                }
            )
        }

    return _impl


class TestRunAutoTriageEndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls._tmp = tempfile.TemporaryDirectory()
        spec = CorpusSpec("gcc", "-O0", pie=False, stripped=False)
        cls.corpus = build_corpus_binary(Path(cls._tmp.name), spec)
        if not cls.corpus.built:
            raise unittest.SkipTest(
                f"corpus binary unavailable: {cls.corpus.skipped_reason}"
            )
        mapping_result = _call_tool(
            "disassemble", {"binary_path": str(cls.corpus.binary_path), "max_lines": 1}
        )
        if not mapping_result.get("ok"):
            raise unittest.SkipTest("cannot generate mapping for corpus binary")
        cls.mapping_path = mapping_result["mapping_path"]

    @classmethod
    def tearDownClass(cls):
        cls._tmp.cleanup()

    def _run(self, cache_path: str, cancel_check=lambda: False, budget=None):
        events: list[dict] = []
        call_count = [0]
        with patch(
            "backends.mcp.auto_triage.call_provider_result",
            side_effect=_mocked_provider_result(call_count),
        ):
            result = at.run_auto_triage(
                str(self.corpus.binary_path),
                self.mapping_path,
                "ollama",
                None,
                budget or at.TriageBudget(),
                events.append,
                cancel_check,
                cache_path=cache_path,
            )
        return result, events, call_count[0]

    def test_end_to_end_annotates_functions_with_ai_source(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache_path = f.name
        try:
            result, events, calls = self._run(cache_path)
            self.assertGreater(calls, 0)
            self.assertIn("report_markdown", result)
            self.assertIn("Fonctions prioritaires", result["report_markdown"])
            with AnnotationStore(
                str(self.corpus.binary_path), cache_path=cache_path
            ) as store:
                rows = store.list()
            ai_rows = [r for r in rows if r.get("source") == "ai"]
            self.assertGreater(len(ai_rows), 0)
            event_types = {e["type"] for e in events}
            self.assertIn("selection_done", event_types)
            self.assertIn("function_done", event_types)
            self.assertIn("summary", event_types)
            self.assertIn("done", event_types)
        finally:
            Path(cache_path).unlink(missing_ok=True)

    def test_never_overwrites_user_annotation(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache_path = f.name
        try:
            expected = self.corpus.expected_functions
            some_addr = next(iter(expected.values()))
            with AnnotationStore(
                str(self.corpus.binary_path), cache_path=cache_path
            ) as store:
                store.rename(some_addr, "human_chosen_name")

            self._run(cache_path)

            with AnnotationStore(
                str(self.corpus.binary_path), cache_path=cache_path
            ) as store:
                rows = store.list(addr=some_addr)
            rename_rows = [r for r in rows if r["kind"] == "rename"]
            self.assertEqual(len(rename_rows), 1)
            self.assertEqual(rename_rows[0]["value"], "human_chosen_name")
            self.assertEqual(rename_rows[0]["source"], "user")
        finally:
            Path(cache_path).unlink(missing_ok=True)

    def test_cancellation_leaves_no_partial_annotation(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache_path = f.name
        try:
            processed = {"count": 0}

            def cancel_after_two():
                return processed["count"] >= 2

            call_count = [0]
            events: list[dict] = []

            def _tracking_provider(
                provider, prompt, context, model, on_token=None, generation_options=None
            ):
                processed["count"] += 1
                call_count[0] += 1
                return {
                    "text": json.dumps(
                        {
                            "name": f"triaged_fn_{call_count[0]}",
                            "docstring": f"Analyse #{call_count[0]}.",
                            "tags": [],
                        }
                    )
                }

            with patch(
                "backends.mcp.auto_triage.call_provider_result",
                side_effect=_tracking_provider,
            ):
                result = at.run_auto_triage(
                    str(self.corpus.binary_path),
                    self.mapping_path,
                    "ollama",
                    None,
                    at.TriageBudget(),
                    events.append,
                    cancel_after_two,
                    cache_path=cache_path,
                )

            self.assertTrue(result["stats"]["cancelled"])
            event_types = [e["type"] for e in events]
            self.assertIn("cancelled", event_types)

            with AnnotationStore(
                str(self.corpus.binary_path), cache_path=cache_path
            ) as store:
                rows = store.list()
            by_addr: dict[str, set[str]] = {}
            for row in rows:
                if row.get("source") != "ai":
                    continue
                by_addr.setdefault(row["addr"], set()).add(row["kind"])
            for addr, kinds in by_addr.items():
                self.assertEqual(
                    kinds,
                    {"rename", "comment"},
                    f"function at {addr} left half-annotated: {kinds}",
                )
        finally:
            Path(cache_path).unlink(missing_ok=True)

    def test_budget_max_functions_enforced(self):
        with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as f:
            cache_path = f.name
        try:
            result, events, calls = self._run(
                cache_path, budget=at.TriageBudget(max_functions=1)
            )
            selection_events = [e for e in events if e["type"] == "selection_done"]
            self.assertEqual(selection_events[0]["total"], 1)
            # +1 for the single binary-summary synthesis call (not per-function).
            self.assertLessEqual(calls, 2)
        finally:
            Path(cache_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
