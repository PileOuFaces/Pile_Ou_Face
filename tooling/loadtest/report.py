# SPDX-License-Identifier: AGPL-3.0-only
"""Formatage et évaluation des résultats de l'outil de test de charge."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass


@dataclass
class Result:
    scenario: str
    fixture: str
    binary_size_bytes: int
    peak_rss_bytes: int
    elapsed_s: float
    returncode: int | None
    timed_out: bool


def check_threshold(result: Result, max_ratio: float) -> str:
    """Retourne 'ok', 'exceeded', 'error' ou 'timeout'."""
    if result.timed_out:
        return "timeout"
    if result.returncode != 0:
        return "error"
    if result.binary_size_bytes <= 0:
        return "ok"
    ratio = result.peak_rss_bytes / result.binary_size_bytes
    return "exceeded" if ratio > max_ratio else "ok"


def all_ok(results: list[Result], max_ratio: float) -> bool:
    """True si tous les résultats sont 'ok' (aucun error/exceeded/timeout).

    Une liste vide retourne True (vérité vacueuse : rien n'a échoué).
    """
    return all(check_threshold(r, max_ratio) == "ok" for r in results)


def to_json(results: list[Result]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)


def format_summary_table(results: list[Result], max_ratio: float) -> str:
    header = f"{'scenario':<12} {'fixture':<8} {'peak RSS (Mo)':>14} {'temps (s)':>10} {'statut':>10}"
    lines = [header, "-" * len(header)]
    if not results:
        lines.append("(aucun résultat)")
        return "\n".join(lines)
    for r in results:
        status = check_threshold(r, max_ratio)
        rss_mb = r.peak_rss_bytes / (1024 * 1024)
        lines.append(f"{r.scenario:<12} {r.fixture:<8} {rss_mb:>14.1f} {r.elapsed_s:>10.2f} {status:>10}")
    return "\n".join(lines)
