# SPDX-License-Identifier: AGPL-3.0-only
"""Création et chargement des baselines médianes du loadtest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from statistics import median
from typing import Any

from .report import Baseline

MIN_SAMPLES = 3


def _environment_key(metadata: dict[str, Any]) -> tuple[str, str]:
    python = str(metadata.get("python", ""))
    return str(metadata.get("machine", "")), ".".join(python.split(".")[:2])


def build_baseline(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Construit les médianes de rapports issus d'un environnement homogène."""
    if len(reports) < MIN_SAMPLES:
        raise ValueError(f"au moins {MIN_SAMPLES} rapports sont requis")

    environment = _environment_key(reports[0].get("metadata", {}))
    if not all(
        _environment_key(report.get("metadata", {})) == environment
        for report in reports
    ):
        raise ValueError("les rapports ne proviennent pas du même environnement")

    samples: dict[tuple[str, str], list[dict[str, Any]]] = {}
    expected_keys: set[tuple[str, str]] | None = None
    for report in reports:
        rows = report.get("results", [])
        keys = {(str(row["scenario"]), str(row["fixture"])) for row in rows}
        if expected_keys is None:
            expected_keys = keys
        elif keys != expected_keys:
            raise ValueError("les rapports ne couvrent pas les mêmes scénarios")
        for row in rows:
            if (
                row.get("timed_out", False)
                or row.get("returncode", 0) != 0
                or row.get("status")
                in {
                    "memory_limit",
                    "duration_limit",
                    "regression_limit",
                    "error",
                    "timeout",
                }
            ):
                raise ValueError(
                    "un rapport en échec ne peut pas alimenter la baseline"
                )
            key = str(row["scenario"]), str(row["fixture"])
            samples.setdefault(key, []).append(row)

    rows = []
    for (scenario, fixture), values in sorted(samples.items()):
        rows.append(
            {
                "scenario": scenario,
                "fixture": fixture,
                "peak_rss_bytes": int(median(v["peak_rss_bytes"] for v in values)),
                "elapsed_s": median(v["elapsed_s"] for v in values),
            }
        )
    return {
        "schema_version": 1,
        "sample_count": len(reports),
        "environment": {"machine": environment[0], "python": environment[1]},
        "results": rows,
    }


def load_baseline(
    path: Path,
    *,
    expected_machine: str | None = None,
    expected_python: str | None = None,
) -> dict[tuple[str, str], Baseline]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != 1:
        raise ValueError("version de baseline non supportée")
    if payload.get("sample_count", 0) < MIN_SAMPLES:
        raise ValueError(f"baseline non fiable : au moins {MIN_SAMPLES} runs requis")
    environment = payload.get("environment", {})
    if expected_machine and environment.get("machine") != expected_machine:
        raise ValueError("architecture incompatible avec la baseline")
    expected_python_minor = ".".join((expected_python or "").split(".")[:2])
    if expected_python_minor and environment.get("python") != expected_python_minor:
        raise ValueError("version Python incompatible avec la baseline")
    return {
        (str(row["scenario"]), str(row["fixture"])): Baseline(
            peak_rss_bytes=int(row["peak_rss_bytes"]),
            elapsed_s=float(row["elapsed_s"]),
        )
        for row in payload.get("results", [])
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Promouvoir une baseline loadtest")
    parser.add_argument("reports", nargs="+")
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    reports = [
        json.loads(Path(path).read_text(encoding="utf-8")) for path in args.reports
    ]
    payload = build_baseline(reports)
    Path(args.output).write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
