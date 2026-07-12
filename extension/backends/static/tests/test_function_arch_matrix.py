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
    write_raw_bpf_call_fixture,
    write_raw_m68k_call_fixture,
    write_raw_mips32_be_call_fixture,
    write_raw_mips32_le_call_fixture,
    write_raw_ppc32_be_call_fixture,
    write_raw_ppc32_be_partial_call_fixture,
    write_raw_riscv64_call_fixture,
    write_raw_sparc_call_fixture,
    write_raw_sysz_call_fixture,
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
SemanticFixture = dict[str, object]

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
    ("riscv64", write_raw_riscv64_call_fixture),
    ("sparc", write_raw_sparc_call_fixture),
    ("m68k", write_raw_m68k_call_fixture),
    ("bpf", write_raw_bpf_call_fixture),
    ("sysz", write_raw_sysz_call_fixture),
)

FUNCTION_FEATURES = ("discover_functions", "cfg", "call_graph")
SEMANTIC_LEVELS = {"partial", "full"}
CFG_CALLGRAPH_COVERAGE_DEBT_ISSUE = 82

# These adapters expose semantic CFG/Call Graph support in the public matrix, but
# do not yet have a raw fixture proving "function discovery + CFG + call graph".
# Keep this list explicit so #82 can burn it down adapter by adapter.
CFG_CALLGRAPH_UNFIXTURED_ADAPTERS = {
    "sh",
    "tricore",
    "wasm",
}

SEMANTIC_LINE_FIXTURES: tuple[tuple[str, SemanticFixture], ...] = (
    (
        "sh",
        {
            "adapter_key": "sh",
            "arch_hint": "sh4",
            "entry_addr": "0xd000",
            "target_addr": "0xd020",
            "custom_preludes": [(r"\bmov\.l\s+r14\s*,\s*@-r15\b", "sh entry")],
            "lines": [
                {"addr": "0xd000", "text": "mov.l r14,@-r15", "line": 1},
                {"addr": "0xd002", "text": "bsr 0xd020", "line": 2},
                {"addr": "0xd004", "text": "rts", "line": 3},
                {"addr": "0xd020", "text": "rts", "line": 4},
            ],
        },
    ),
    (
        "tricore",
        {
            "adapter_key": "tricore",
            "arch_hint": "tricore",
            "entry_addr": "0x11000",
            "target_addr": "0x11020",
            "custom_preludes": [(r"\bmov\.aa\s+a10\s*,\s*sp\b", "tricore entry")],
            "lines": [
                {"addr": "0x11000", "text": "mov.aa a10, sp", "line": 1},
                {"addr": "0x11004", "text": "call 0x11020", "line": 2},
                {"addr": "0x11008", "text": "ret", "line": 3},
                {"addr": "0x11020", "text": "ret", "line": 4},
            ],
        },
    ),
    (
        "wasm",
        {
            "adapter_key": "wasm",
            "arch_hint": "wasm",
            "entry_addr": "0x12000",
            "target_addr": "0x12020",
            "custom_preludes": [(r"\blocal\.get\s+0\b", "wasm entry")],
            "lines": [
                {"addr": "0x12000", "text": "local.get 0", "line": 1},
                {"addr": "0x12004", "text": "call 0x12020", "line": 2},
                {"addr": "0x12008", "text": "return", "line": 3},
                {"addr": "0x12020", "text": "return", "line": 4},
            ],
        },
    ),
)


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

    def test_unfixtured_raw_adapters_have_semantic_line_fixtures(self):
        semantic_fixture_keys = {
            str(sample["adapter_key"]) for _label, sample in SEMANTIC_LINE_FIXTURES
        }
        self.assertEqual(
            semantic_fixture_keys,
            CFG_CALLGRAPH_UNFIXTURED_ADAPTERS,
            (
                "Every adapter without a raw Capstone fixture must still have "
                "a semantic end-to-end fixture covering function discovery, CFG "
                "and Call Graph direct-call behavior."
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

    def test_semantic_line_fixtures_exercise_cfg_and_call_graph_pipeline(self):
        matrix = get_feature_support_matrix()

        for label, sample in SEMANTIC_LINE_FIXTURES:
            with self.subTest(arch=label):
                adapter_key = str(sample["adapter_key"])
                support = matrix[adapter_key]
                for feature in FUNCTION_FEATURES:
                    self.assertIn(support[feature]["level"], SEMANTIC_LEVELS)

                lines = list(sample["lines"])
                custom_preludes = sample.get("custom_preludes")
                discovered = discover_functions(
                    lines,
                    set(),
                    custom_preludes=custom_preludes,  # type: ignore[arg-type]
                )
                discovered_addrs = {fn["addr"] for fn in discovered}
                self.assertIn(sample["entry_addr"], discovered_addrs)
                self.assertIn(sample["target_addr"], discovered_addrs)

                cfg = build_cfg(lines, arch_hint=str(sample["arch_hint"]))
                self.assertTrue(
                    any(
                        edge.get("type") == "call"
                        and edge.get("from") == sample["entry_addr"]
                        and edge.get("to") == sample["target_addr"]
                        for edge in cfg.get("edges", [])
                    )
                )

                call_graph = build_call_graph(cfg, discovered, lines=lines)
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
