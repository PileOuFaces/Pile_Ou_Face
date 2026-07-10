# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests tying the public arch matrix to the Functions pipeline."""

from __future__ import annotations

import sys
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.arch import (
    FEATURES,
    get_feature_support_matrix,
    get_raw_arch_info,
)
from backends.static.disasm.call_graph import build_call_graph
from backends.static.disasm.cfg import build_cfg
from backends.static.disasm.discover_functions import discover_functions
from backends.static.tests.fixtures.raw_fixture import (
    write_raw_arm32_call_fixture,
    write_raw_arm64_call_fixture,
    write_raw_mips32_be_call_fixture,
    write_raw_mips32_le_call_fixture,
    write_raw_ppc32_be_call_fixture,
    write_raw_ppc32_be_partial_call_fixture,
    write_raw_thumb_call_fixture,
    write_raw_thumb_partial_call_fixture,
    write_raw_x64_call_fixture,
)

try:
    import capstone as _capstone

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


RawFixtureWriter = Callable[[str | Path], dict[str, object]]

RAW_FUNCTION_FIXTURES: tuple[tuple[str, RawFixtureWriter], ...] = (
    ("x64", write_raw_x64_call_fixture),
    ("arm64", write_raw_arm64_call_fixture),
    ("arm32", write_raw_arm32_call_fixture),
    ("thumb", write_raw_thumb_call_fixture),
    ("thumb_partial", write_raw_thumb_partial_call_fixture),
    ("mips32_be", write_raw_mips32_be_call_fixture),
    ("mips32_le", write_raw_mips32_le_call_fixture),
    ("ppc32_be", write_raw_ppc32_be_call_fixture),
    ("ppc32_be_partial", write_raw_ppc32_be_partial_call_fixture),
)

FUNCTION_FEATURES = ("discover_functions", "cfg", "call_graph")
SEMANTIC_LEVELS = {"partial", "full"}
CFG_CALLGRAPH_COVERAGE_DEBT_ISSUE = 82

# These adapters expose semantic CFG/Call Graph support in the public matrix, but
# do not yet have a raw fixture proving "function discovery + CFG + call graph".
# Keep this list explicit so #82 can burn it down adapter by adapter.
CFG_CALLGRAPH_UNFIXTURED_ADAPTERS = {
    "bpf",
    "m68k",
    "riscv",
    "sh",
    "sparc",
    "tricore",
    "wasm",
}


@unittest.skipUnless(_CAPSTONE_AVAILABLE, "capstone not installed")
class TestFunctionArchSupportMatrix(unittest.TestCase):
    def _fixture_adapter_keys(self) -> set[str]:
        adapter_keys: set[str] = set()
        for _label, writer in RAW_FUNCTION_FIXTURES:
            with tempfile.TemporaryDirectory() as tmp:
                sample = writer(tmp)
                raw_profile = sample["raw"]
                info = get_raw_arch_info(
                    str(raw_profile["arch"]),
                    str(raw_profile.get("endian") or ""),
                )
                self.assertIsNotNone(info)
                assert info is not None
                adapter_keys.add(info.adapter.key)
        return adapter_keys

    def test_cfg_call_graph_semantic_claims_have_fixture_or_issue_debt(self):
        matrix = get_feature_support_matrix()
        fixture_adapter_keys = self._fixture_adapter_keys()
        semantic_adapter_keys = {
            adapter_key
            for adapter_key, support in matrix.items()
            if support["cfg"]["level"] in SEMANTIC_LEVELS
            or support["call_graph"]["level"] in SEMANTIC_LEVELS
        }

        missing_fixture_keys = semantic_adapter_keys - fixture_adapter_keys
        self.assertEqual(
            missing_fixture_keys,
            CFG_CALLGRAPH_UNFIXTURED_ADAPTERS,
            (
                "Every adapter that claims semantic CFG/Call Graph support must "
                "either have a raw fixture or be explicitly tracked by "
                f"issue #{CFG_CALLGRAPH_COVERAGE_DEBT_ISSUE}."
            ),
        )

    def test_raw_function_fixtures_are_backed_by_matrix_entries(self):
        matrix = get_feature_support_matrix()

        for label, writer in RAW_FUNCTION_FIXTURES:
            with self.subTest(arch=label), tempfile.TemporaryDirectory() as tmp:
                sample = writer(tmp)
                raw_profile = sample["raw"]
                info = get_raw_arch_info(
                    str(raw_profile["arch"]),
                    str(raw_profile.get("endian") or ""),
                )

                self.assertIsNotNone(info)
                assert info is not None
                self.assertIn(info.adapter.key, matrix)
                self.assertEqual(set(matrix[info.adapter.key]), set(FEATURES))
                self.assertEqual(matrix[info.adapter.key]["disasm"]["level"], "full")
                for feature in FUNCTION_FEATURES:
                    self.assertIn(
                        matrix[info.adapter.key][feature]["level"],
                        SEMANTIC_LEVELS,
                    )

    def test_function_pipeline_matches_semantic_support_claims(self):
        matrix = get_feature_support_matrix()

        for label, writer in RAW_FUNCTION_FIXTURES:
            with self.subTest(arch=label), tempfile.TemporaryDirectory() as tmp:
                sample = writer(tmp)
                raw_profile = sample["raw"]
                info = get_raw_arch_info(
                    str(raw_profile["arch"]),
                    str(raw_profile.get("endian") or ""),
                )

                self.assertIsNotNone(info)
                assert info is not None
                support = matrix[info.adapter.key]

                lines = sample["lines"]
                self.assertGreaterEqual(len(lines), 3)

                discovered = discover_functions(lines, set())
                if support["discover_functions"]["level"] in SEMANTIC_LEVELS:
                    discovered_addrs = {fn["addr"] for fn in discovered}
                    self.assertIn(sample["entry_addr"], discovered_addrs)
                    self.assertIn(sample["target_addr"], discovered_addrs)

                cfg = build_cfg(lines, arch_hint=str(sample.get("arch_hint") or ""))
                if support["cfg"]["level"] in SEMANTIC_LEVELS:
                    self.assertTrue(
                        any(
                            edge.get("type") == "call"
                            and edge.get("from") == sample["entry_addr"]
                            and edge.get("to") == sample["target_addr"]
                            for edge in cfg.get("edges", [])
                        )
                    )

                call_graph = build_call_graph(cfg, discovered, lines=lines)
                if support["call_graph"]["level"] in SEMANTIC_LEVELS:
                    self.assertEqual(len(call_graph["edges"]), 1)
                    self.assertEqual(
                        call_graph["edges"][0]["from_name"],
                        f"sub_{str(sample['entry_addr'])[2:]}",
                    )
                    self.assertEqual(
                        call_graph["edges"][0]["to_name"],
                        f"sub_{str(sample['target_addr'])[2:]}",
                    )


if __name__ == "__main__":
    unittest.main()
