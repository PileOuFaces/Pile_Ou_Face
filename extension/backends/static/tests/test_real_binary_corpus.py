# SPDX-License-Identifier: AGPL-3.0-only
"""Corpus de binaires réels compilés pour mesurer les analyseurs static."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
import warnings
from pathlib import Path

from backends.static.disasm.cfg import build_cfg, build_cfg_for_function
from backends.static.disasm.disasm import disassemble_with_capstone
from backends.static.disasm.discover_functions import (
    discover_functions,
    evaluate_function_discovery,
)
from backends.static.disasm.stack_frame import analyse_stack_frame
from backends.static.tests.fixtures.real_binary_corpus import (
    CorpusBinary,
    build_corpus_binary,
    default_corpus_specs,
    expected_cfg_call_edges,
)

warnings.filterwarnings(
    "ignore",
    message=r".* is not a valid TYPE\.",
    category=RuntimeWarning,
)


def _lief_and_capstone_available() -> bool:
    try:
        import capstone  # noqa: F401
        import lief  # noqa: F401

        return True
    except ImportError:
        return False


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _function_name_for_addr(addr: str, expected_functions: dict[str, str]) -> str | None:
    try:
        value = int(str(addr), 16)
    except (TypeError, ValueError):
        return None
    starts = sorted((int(func_addr, 16), name) for name, func_addr in expected_functions.items())
    for index, (start, name) in enumerate(starts):
        end = starts[index + 1][0] if index + 1 < len(starts) else 1 << 128
        if start <= value < end:
            return name
    return None


def _named_cfg_call_edges(cfg: dict, expected_functions: dict[str, str]) -> set[tuple[str, str]]:
    addr_to_name = {addr.lower(): name for name, addr in expected_functions.items()}
    named_edges: set[tuple[str, str]] = set()
    for edge in cfg.get("edges", []):
        if edge.get("type") != "call":
            continue
        source = _function_name_for_addr(edge.get("from", ""), expected_functions)
        target = addr_to_name.get(str(edge.get("to", "")).lower())
        if source and target:
            named_edges.add((source, target))
    return named_edges


@unittest.skipUnless(_lief_and_capstone_available(), "lief et capstone requis")
class TestRealBinaryCorpus(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmpdir = tempfile.TemporaryDirectory()
        cls.root = Path(cls._tmpdir.name)
        cls.corpus: list[CorpusBinary] = [
            built
            for spec in default_corpus_specs()
            if (built := build_corpus_binary(cls.root, spec)).built
        ]

    @classmethod
    def tearDownClass(cls) -> None:
        cls._tmpdir.cleanup()

    def setUp(self) -> None:
        if not self.corpus:
            self.skipTest("aucun compilateur de corpus réel disponible")

    def _collect_case_metrics(self, item: CorpusBinary) -> dict:
        lines = disassemble_with_capstone(str(item.binary_path))
        expected = set(item.expected_functions.values())
        discovered = discover_functions(lines or [], set(), binary_path=str(item.binary_path))
        discovery = evaluate_function_discovery(discovered, expected)

        with warnings.catch_warnings():
            warnings.filterwarnings(
                "ignore",
                message=r".*is not a valid TYPE.*",
                category=RuntimeWarning,
            )
            cfg = build_cfg(lines or [], binary_path=str(item.binary_path))
            main_cfg = build_cfg_for_function(
                lines or [],
                item.expected_functions["main"],
                binary_path=str(item.binary_path),
            )

        stack_summary = None
        if "pof_stacky" in item.expected_functions:
            stack_frame = analyse_stack_frame(
                str(item.binary_path),
                int(item.expected_functions["pof_stacky"], 16),
            )
            stack_summary = {
                "frame_size": stack_frame.get("frame_size", 0),
                "vars": len(stack_frame.get("vars", [])),
                "args": len(stack_frame.get("args", [])),
                "arch": stack_frame.get("arch", "unknown"),
                "abi": stack_frame.get("abi", "unknown"),
            }

        return {
            "case_id": item.spec.case_id,
            "compiler": Path(item.spec.compiler).name,
            "opt": item.spec.opt,
            "pie": item.spec.pie,
            "stripped": item.spec.stripped,
            "arch": item.spec.arch,
            "binary_size": item.binary_path.stat().st_size,
            "expected_functions": dict(sorted(item.expected_functions.items())),
            "function_discovery": discovery,
            "cfg": {
                "blocks": len(cfg.get("blocks", [])),
                "edges": len(cfg.get("edges", [])),
                "edge_types": sorted(
                    {edge.get("type", "unknown") for edge in cfg.get("edges", [])}
                ),
                "named_call_edges": [
                    {"from": source, "to": target}
                    for source, target in sorted(
                        _named_cfg_call_edges(cfg, item.expected_functions)
                    )
                ],
                "main_blocks": len(main_cfg.get("blocks", [])),
                "main_edges": len(main_cfg.get("edges", [])),
            },
            "stack_frame": stack_summary,
        }

    def test_corpus_matrix_has_native_compiler_coverage(self):
        case_ids = {item.spec.case_id for item in self.corpus}
        self.assertTrue(any("o0" in case_id for case_id in case_ids), case_ids)
        self.assertTrue(any("o2" in case_id for case_id in case_ids), case_ids)
        self.assertTrue(any("pie" in case_id for case_id in case_ids), case_ids)
        self.assertTrue(any("symbols" in case_id for case_id in case_ids), case_ids)
        self.assertTrue(
            any("gcc" in case_id for case_id in case_ids)
            or any("clang" in case_id for case_id in case_ids),
            case_ids,
        )

    def test_function_discovery_recall_on_real_binaries(self):
        for item in self.corpus:
            with self.subTest(case=item.spec.case_id):
                lines = disassemble_with_capstone(str(item.binary_path))
                self.assertTrue(lines, item.spec.case_id)
                expected = set(item.expected_functions.values())
                discovered = discover_functions(
                    lines or [], set(), binary_path=str(item.binary_path)
                )
                metrics = evaluate_function_discovery(discovered, expected)

                min_recall = 0.6 if item.spec.stripped or item.spec.opt != "-O0" else 0.8
                self.assertGreaterEqual(metrics["recall"], min_recall, metrics)
                self.assertGreaterEqual(metrics["precision"], 0.5, metrics)
                self.assertEqual(metrics["overlap_count"], 0, metrics)

    def test_cfg_edges_are_recovered_for_real_main(self):
        for item in self.corpus:
            with self.subTest(case=item.spec.case_id):
                lines = disassemble_with_capstone(str(item.binary_path))
                self.assertTrue(lines, item.spec.case_id)
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message=r".*is not a valid TYPE.*",
                        category=RuntimeWarning,
                    )
                    cfg = build_cfg(lines or [], binary_path=str(item.binary_path))
                self.assertGreater(len(cfg["blocks"]), 0)
                self.assertGreater(len(cfg["edges"]), 0)
                edge_types = {edge["type"] for edge in cfg["edges"]}
                self.assertTrue(
                    edge_types & {"call", "jmp", "fallthrough", "jumptable"}, edge_types
                )

                main_addr = item.expected_functions["main"]
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message=r".*is not a valid TYPE.*",
                        category=RuntimeWarning,
                    )
                    main_cfg = build_cfg_for_function(
                        lines or [],
                        main_addr,
                        binary_path=str(item.binary_path),
                    )
                self.assertEqual(main_cfg["func_addr"], main_addr.lower())
                self.assertGreater(len(main_cfg["blocks"]), 0)

    def test_cfg_named_call_edges_match_source_expectations(self):
        for item in self.corpus:
            with self.subTest(case=item.spec.case_id):
                lines = disassemble_with_capstone(str(item.binary_path))
                self.assertTrue(lines, item.spec.case_id)
                with warnings.catch_warnings():
                    warnings.filterwarnings(
                        "ignore",
                        message=r".*is not a valid TYPE.*",
                        category=RuntimeWarning,
                    )
                    cfg = build_cfg(lines or [], binary_path=str(item.binary_path))

                named_edges = _named_cfg_call_edges(cfg, item.expected_functions)
                missing = expected_cfg_call_edges(item.spec) - named_edges
                self.assertEqual(missing, set(), sorted(named_edges))

    def test_stack_frame_schema_on_real_stack_function(self):
        candidates = [
            item
            for item in self.corpus
            if item.spec.opt == "-O0"
            and not item.spec.stripped
            and "pof_stacky" in item.expected_functions
        ]
        if not candidates:
            self.skipTest("aucun binaire -O0 non stripped disponible pour stack frame")

        for item in candidates[:2]:
            with self.subTest(case=item.spec.case_id):
                data = analyse_stack_frame(
                    str(item.binary_path),
                    int(item.expected_functions["pof_stacky"], 16),
                )
                self.assertEqual(data["func_addr"], item.expected_functions["pof_stacky"].lower())
                self.assertIn("frame_size", data)
                self.assertIn("vars", data)
                self.assertIn("args", data)
                self.assertIsInstance(data["vars"], list)
                self.assertIsInstance(data["args"], list)

    def test_real_corpus_metrics_summary_is_available(self):
        cases = [self._collect_case_metrics(item) for item in self.corpus]
        payload = {
            "schema": "pile-ou-face.real-binary-corpus.metrics.v2",
            "case_count": len(cases),
            "cases": cases,
        }

        self.assertEqual(payload["case_count"], len(self.corpus))
        for case in cases:
            self.assertIn("case_id", case)
            self.assertIn("function_discovery", case)
            self.assertIn("cfg", case)
            self.assertIn("recall", case["function_discovery"])
            self.assertIn("precision", case["function_discovery"])
            self.assertIn("named_call_edges", case["cfg"])

        summary_path = os.environ.get("POF_REAL_CORPUS_SUMMARY_JSON")
        if summary_path:
            _write_json(Path(summary_path), payload)


if __name__ == "__main__":
    unittest.main()
