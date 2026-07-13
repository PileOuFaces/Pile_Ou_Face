# SPDX-License-Identifier: AGPL-3.0-only
"""Registre des fixtures et scénarios testés par l'outil de charge."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from loadtest.fixtures import FixtureSpec


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
    script: str  # chemin relatif à extension/, ex: "backends/static/disasm/disasm.py"
    build_args: Callable[[Path, Path], list[str]]
    timeout_s: int = 120


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


# NOTE: `decompile` (backends/static/decompile/decompile.py, Ghidra-backed) is
# deliberately not included yet — likely the highest-RAM backend operation in
# this codebase, worth adding in a follow-up once a decompiler is confirmed
# available in the test environment (unlike disasm/strings/symbols, it needs
# external tooling configured, not just a compiler).
SCENARIOS = (
    Scenario(name="disasm", script="backends/static/disasm/disasm.py", build_args=_disasm_args, timeout_s=180),
    Scenario(name="strings", script="backends/static/search/strings.py", build_args=_strings_args),
    Scenario(name="symbols", script="backends/static/binary/symbols.py", build_args=_symbols_args),
)
