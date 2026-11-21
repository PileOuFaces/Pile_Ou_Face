# SPDX-License-Identifier: AGPL-3.0-only
"""Per-component Python coverage gates (docs/ci/COVERAGE_POLICY.md).

Thresholds live in ``pyproject.toml`` under ``[tool.pof.coverage_gates]``. Each CI job
names the gates it is responsible for; a named gate with no measured data fails, so a
gate can never pass silently because its code was not measured.

Usage: python scripts/check_coverage_gates.py [--data-file .coverage] GATE [GATE ...]
"""

from __future__ import annotations

import argparse
import io
import sys
import tomllib
from pathlib import Path

import coverage
from coverage.exceptions import NoDataError

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def load_gates(pyproject: Path = PYPROJECT) -> dict[str, dict]:
    with pyproject.open("rb") as handle:
        config = tomllib.load(handle)
    return config.get("tool", {}).get("pof", {}).get("coverage_gates", {})


def threshold(gate: dict, platform: str = sys.platform) -> float:
    """`fail_under`, or its documented per-platform value (`fail_under_by_platform`)."""
    return gate.get("fail_under_by_platform", {}).get(platform, gate["fail_under"])


def measure(cov: coverage.Coverage, gate: dict) -> float:
    """Coverage percentage (statements and branches) of the gate's files."""
    return cov.report(
        include=gate["include"],
        omit=gate.get("omit", []),
        file=io.StringIO(),
    )


def check(
    gate_names: list[str],
    data_file: str,
    gates: dict[str, dict],
    config_file: str | bool = str(PYPROJECT),
) -> int:
    unknown = [name for name in gate_names if name not in gates]
    if unknown:
        print(f"Unknown coverage gate(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    cov = coverage.Coverage(data_file=data_file, config_file=config_file)
    cov.load()
    failed = False
    for name in gate_names:
        gate = gates[name]
        try:
            percent = measure(cov, gate)
        except NoDataError:
            print(f"FAIL  {name}: no coverage data for {gate['include']}")
            failed = True
            continue
        required = threshold(gate)
        ok = percent >= required
        failed |= not ok
        print(
            f"{'OK  ' if ok else 'FAIL'}  {name}: {percent:.2f}% (gate {required}% on {sys.platform})"
        )
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--data-file", default=".coverage")
    parser.add_argument("gates", nargs="+")
    args = parser.parse_args(argv)
    return check(args.gates, args.data_file, load_gates())


if __name__ == "__main__":
    sys.exit(main())
