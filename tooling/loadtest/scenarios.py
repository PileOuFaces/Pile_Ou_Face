# SPDX-License-Identifier: AGPL-3.0-only
"""Registre des fixtures et scénarios testés par l'outil de charge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable, TypeAlias

from loadtest.fixtures import FixtureSpec

CommandSpec: TypeAlias = tuple[str, list[str]]


@dataclass(frozen=True)
class FixtureProfile:
    name: str
    num_functions: int
    padding_bytes: int

    def to_spec(self) -> FixtureSpec:
        return FixtureSpec(name=self.name, num_functions=self.num_functions, padding_bytes=self.padding_bytes)


FIXTURE_PROFILES = (
    FixtureProfile(name="small", num_functions=20, padding_bytes=1_000_000),
    FixtureProfile(name="medium", num_functions=200, padding_bytes=20_000_000),
    FixtureProfile(name="large", num_functions=500, padding_bytes=200_000_000),
)


@dataclass(frozen=True)
class Scenario:
    name: str
    script: str  # chemin relatif à extension/ ou au repo si prefixé par tooling/
    build_args: Callable[[Path, Path], list[str]]
    timeout_s: int = 120
    writes_output: bool = True
    prepare: Callable[[Path, Path], tuple[CommandSpec, ...]] | None = None


def _disasm_args(binary_path: Path, out_dir: Path) -> list[str]:
    return [
        "--binary", str(binary_path),
        "--output", str(out_dir / "out.asm"),
        "--output-mapping", str(out_dir / "out.mapping.json"),
    ]


def _strings_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "strings.json")]


def _symbols_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "symbols.json")]


def _headers_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "headers.json")]


def _sections_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "sections.json")]


def _imports_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "imports.json")]


def _entropy_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--output", str(out_dir / "entropy.json")]


def _hex_view_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path), "--offset", "0", "--length", "65536"]


def _pe_resources_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path)]


def _exception_handlers_args(binary_path: Path, out_dir: Path) -> list[str]:
    return ["--binary", str(binary_path)]


def _analysis_index_args(binary_path: Path, out_dir: Path) -> list[str]:
    return [
        "--binary", str(binary_path),
        "--cache-db", str(out_dir / "analysis_index.pfdb"),
        "--force",
    ]


def _function_radar_args(binary_path: Path, out_dir: Path) -> list[str]:
    return [
        "--binary", str(binary_path),
        "--cache-db", str(out_dir / "function_radar.pfdb"),
    ]


def _pipeline_args(kind: str, binary_path: Path, out_dir: Path) -> list[str]:
    mapping_path = out_dir / "disasm.mapping.json"
    if kind == "cfg":
        return ["--mapping", str(mapping_path), "--output", str(out_dir / "cfg.json")]
    if kind == "call_graph":
        return [
            "--mapping", str(mapping_path),
            "--binary", str(binary_path),
            "--output", str(out_dir / "call_graph.json"),
        ]
    return [
        "--mapping", str(mapping_path),
        "--binary", str(binary_path),
        "--mode", "map",
        "--output", str(out_dir / "xrefs_map.json"),
    ]


def _prepare_disasm_mapping(binary_path: Path, out_dir: Path) -> tuple[CommandSpec, ...]:
    return (
        (
            "backends/static/disasm/disasm.py",
            [
                "--binary", str(binary_path),
                "--output", str(out_dir / "disasm.asm"),
                "--output-mapping", str(out_dir / "disasm.mapping.json"),
            ],
        ),
    )


def _cfg_args(binary_path: Path, out_dir: Path) -> list[str]:
    return _pipeline_args("cfg", binary_path, out_dir)


def _call_graph_args(binary_path: Path, out_dir: Path) -> list[str]:
    return _pipeline_args("call_graph", binary_path, out_dir)


def _xrefs_map_args(binary_path: Path, out_dir: Path) -> list[str]:
    return _pipeline_args("xrefs_map", binary_path, out_dir)


# NOTE: `decompile` (backends/static/decompile/decompile.py, Ghidra-backed) is
# deliberately not included yet — likely the highest-RAM backend operation in
# this codebase, worth adding in a follow-up once a decompiler is confirmed
# available in the test environment (unlike these scenarios, it needs external
# tooling configured, not just a compiler and Python dependencies).
SCENARIOS = (
    Scenario(name="disasm", script="backends/static/disasm/disasm.py", build_args=_disasm_args, timeout_s=180),
    Scenario(name="strings", script="backends/static/search/strings.py", build_args=_strings_args, timeout_s=300),
    Scenario(name="symbols", script="backends/static/binary/symbols.py", build_args=_symbols_args),
    Scenario(name="headers", script="backends/static/binary/headers.py", build_args=_headers_args),
    Scenario(name="sections", script="backends/static/binary/sections.py", build_args=_sections_args),
    Scenario(name="imports", script="backends/static/binary/imports_analysis.py", build_args=_imports_args),
    Scenario(name="entropy", script="backends/static/binary/entropy.py", build_args=_entropy_args, timeout_s=180),
    Scenario(name="hex_view", script="backends/static/search/hex_view.py", build_args=_hex_view_args, writes_output=False),
    Scenario(name="pe_resources", script="backends/static/binary/pe_resources.py", build_args=_pe_resources_args, writes_output=False),
    Scenario(name="exception_handlers", script="backends/static/exception_handlers.py", build_args=_exception_handlers_args, writes_output=False),
    Scenario(name="analysis_index", script="backends/static/analysis/analysis_index.py", build_args=_analysis_index_args, timeout_s=240, writes_output=False),
    Scenario(name="function_radar", script="backends/static/analysis/function_radar.py", build_args=_function_radar_args, timeout_s=240, writes_output=False),
    Scenario(name="cfg", script="backends/static/disasm/cfg.py", build_args=_cfg_args, timeout_s=240, prepare=_prepare_disasm_mapping),
    Scenario(name="call_graph", script="backends/static/disasm/call_graph.py", build_args=_call_graph_args, timeout_s=240, prepare=_prepare_disasm_mapping),
    Scenario(name="xrefs_map", script="backends/static/disasm/xrefs.py", build_args=_xrefs_map_args, timeout_s=240, prepare=_prepare_disasm_mapping),
)
