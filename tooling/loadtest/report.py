# SPDX-License-Identifier: AGPL-3.0-only
"""Formatage et évaluation des résultats de l'outil de test de charge."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass
class Result:
    scenario: str
    fixture: str
    binary_size_bytes: int
    peak_rss_bytes: int
    elapsed_s: float
    returncode: int | None
    timed_out: bool


@dataclass(frozen=True)
class Budget:
    warn_rss_bytes: int
    fail_rss_bytes: int
    warn_duration_s: float
    fail_duration_s: float


@dataclass(frozen=True)
class Evaluation:
    status: str
    reasons: tuple[str, ...] = ()

    @property
    def blocking(self) -> bool:
        return self.status not in {"ok", "warning"}


def evaluate_result(
    result: Result,
    budget: Budget,
    *,
    max_ratio: float | None = None,
) -> Evaluation:
    """Évalue un résultat avec des plafonds absolus RAM et durée.

    Le ratio historique peut rester activé comme garde supplémentaire, mais
    n'est plus le seul signal : sa valeur dépend trop de la taille du fichier
    et du coût fixe de l'interpréteur Python.
    """
    if result.timed_out:
        return Evaluation("timeout", ("timeout",))
    if result.returncode != 0:
        return Evaluation("error", ("returncode",))

    reasons: list[str] = []
    if result.peak_rss_bytes > budget.fail_rss_bytes:
        reasons.append("rss_fail")
    if result.elapsed_s > budget.fail_duration_s:
        reasons.append("duration_fail")
    if (
        max_ratio is not None
        and result.binary_size_bytes > 0
        and result.peak_rss_bytes / result.binary_size_bytes > max_ratio
    ):
        reasons.append("ratio_fail")

    if reasons:
        status = (
            "memory_limit"
            if any(reason in {"rss_fail", "ratio_fail"} for reason in reasons)
            else "duration_limit"
        )
        return Evaluation(status, tuple(reasons))

    if result.peak_rss_bytes > budget.warn_rss_bytes:
        reasons.append("rss_warn")
    if result.elapsed_s > budget.warn_duration_s:
        reasons.append("duration_warn")
    return Evaluation("warning" if reasons else "ok", tuple(reasons))


def check_threshold(result: Result, max_ratio: float) -> str:
    """Compatibilité API : applique uniquement le ratio historique."""
    permissive = Budget(
        warn_rss_bytes=2**63 - 1,
        fail_rss_bytes=2**63 - 1,
        warn_duration_s=float("inf"),
        fail_duration_s=float("inf"),
    )
    evaluation = evaluate_result(result, permissive, max_ratio=max_ratio)
    return "exceeded" if evaluation.status == "memory_limit" else evaluation.status


def all_ok(
    results: list[Result],
    budgets: dict[str, Budget],
    *,
    max_ratio: float | None = None,
) -> bool:
    """True si aucun résultat ne dépasse un plafond bloquant."""
    return all(
        not evaluate_result(
            result, budgets[result.fixture], max_ratio=max_ratio
        ).blocking
        for result in results
    )


def to_json(
    results: list[Result],
    budgets: dict[str, Budget],
    metadata: dict[str, Any],
    *,
    max_ratio: float | None = None,
) -> str:
    rows = []
    for result in results:
        budget = budgets[result.fixture]
        evaluation = evaluate_result(result, budget, max_ratio=max_ratio)
        rows.append(
            {
                **asdict(result),
                "budget": asdict(budget),
                "status": evaluation.status,
                "reasons": list(evaluation.reasons),
                "rss_ratio": (
                    result.peak_rss_bytes / result.binary_size_bytes
                    if result.binary_size_bytes > 0
                    else None
                ),
            }
        )
    return json.dumps(
        {
            "schema_version": 2,
            "metadata": metadata,
            "legacy_max_ratio": max_ratio,
            "results": rows,
        },
        indent=2,
    )


def format_summary_table(
    results: list[Result],
    budgets: dict[str, Budget],
    *,
    max_ratio: float | None = None,
) -> str:
    header = f"{'scenario':<18} {'fixture':<8} {'peak RSS (Mo)':>14} {'temps (s)':>10} {'statut':>16}"
    lines = [header, "-" * len(header)]
    if not results:
        lines.append("(aucun résultat)")
        return "\n".join(lines)
    for result in results:
        evaluation = evaluate_result(
            result,
            budgets[result.fixture],
            max_ratio=max_ratio,
        )
        rss_mb = result.peak_rss_bytes / (1024 * 1024)
        lines.append(
            f"{result.scenario:<18} {result.fixture:<8} {rss_mb:>14.1f} "
            f"{result.elapsed_s:>10.2f} {evaluation.status:>16}"
        )
    return "\n".join(lines)
