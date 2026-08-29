# SPDX-License-Identifier: AGPL-3.0-only
"""Formatage et évaluation des résultats de l'outil de test de charge."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from typing import Any

REGRESSION_WARN_RATIO = 1.20
REGRESSION_FAIL_RATIO = 1.35
# Ratios on sub-second commands amplify normal scheduler/startup jitter. Keep
# the relative gate, but require a meaningful absolute duration delta too.
REGRESSION_WARN_DURATION_DELTA_S = 0.10
REGRESSION_FAIL_DURATION_DELTA_S = 0.50


@dataclass
class Result:
    scenario: str
    fixture: str
    binary_size_bytes: int
    peak_rss_bytes: int
    elapsed_s: float
    returncode: int | None
    timed_out: bool
    memory_limited: bool = False


@dataclass(frozen=True)
class Budget:
    warn_rss_bytes: int
    fail_rss_bytes: int
    warn_duration_s: float
    fail_duration_s: float


@dataclass(frozen=True)
class Baseline:
    peak_rss_bytes: int
    elapsed_s: float


@dataclass(frozen=True)
class Evaluation:
    status: str
    reasons: tuple[str, ...] = ()

    @property
    def blocking(self) -> bool:
        return self.status not in {"ok", "warning"}


def budget_for(
    result: Result,
    budgets: dict[str, Budget],
    scenario_budgets: dict[tuple[str, str], Budget] | None = None,
) -> Budget:
    """Résout d'abord une exception scénario/profil, puis le budget du profil."""
    if scenario_budgets is not None:
        override = scenario_budgets.get((result.scenario, result.fixture))
        if override is not None:
            return override
    return budgets[result.fixture]


def evaluate_result(
    result: Result,
    budget: Budget,
    *,
    baseline: Baseline | None = None,
    regression_warn_ratio: float = REGRESSION_WARN_RATIO,
    regression_fail_ratio: float = REGRESSION_FAIL_RATIO,
    max_ratio: float | None = None,
) -> Evaluation:
    """Évalue un résultat avec des plafonds absolus RAM et durée.

    Le ratio historique peut rester activé comme garde supplémentaire, mais
    n'est plus le seul signal : sa valeur dépend trop de la taille du fichier
    et du coût fixe de l'interpréteur Python.
    """
    if result.timed_out:
        return Evaluation("timeout", ("timeout",))
    if result.memory_limited:
        return Evaluation("memory_limit", ("process_memory_limit",))
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
    if baseline is not None:
        if result.peak_rss_bytes > baseline.peak_rss_bytes * regression_fail_ratio:
            reasons.append("rss_regression_fail")
        if (
            result.elapsed_s > baseline.elapsed_s * regression_fail_ratio
            and result.elapsed_s - baseline.elapsed_s > REGRESSION_FAIL_DURATION_DELTA_S
        ):
            reasons.append("duration_regression_fail")

    if reasons:
        if any(reason in {"rss_fail", "ratio_fail"} for reason in reasons):
            status = "memory_limit"
        elif "duration_fail" in reasons:
            status = "duration_limit"
        else:
            status = "regression_limit"
        return Evaluation(status, tuple(reasons))

    if result.peak_rss_bytes > budget.warn_rss_bytes:
        reasons.append("rss_warn")
    if result.elapsed_s > budget.warn_duration_s:
        reasons.append("duration_warn")
    if baseline is not None:
        if result.peak_rss_bytes > baseline.peak_rss_bytes * regression_warn_ratio:
            reasons.append("rss_regression_warn")
        if (
            result.elapsed_s > baseline.elapsed_s * regression_warn_ratio
            and result.elapsed_s - baseline.elapsed_s > REGRESSION_WARN_DURATION_DELTA_S
        ):
            reasons.append("duration_regression_warn")
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
    scenario_budgets: dict[tuple[str, str], Budget] | None = None,
    baselines: dict[tuple[str, str], Baseline] | None = None,
    max_ratio: float | None = None,
) -> bool:
    """True si aucun résultat ne dépasse un plafond bloquant."""
    return all(
        not evaluate_result(
            result,
            budget_for(result, budgets, scenario_budgets),
            baseline=baselines.get((result.scenario, result.fixture))
            if baselines
            else None,
            max_ratio=max_ratio,
        ).blocking
        for result in results
    )


def to_json(
    results: list[Result],
    budgets: dict[str, Budget],
    metadata: dict[str, Any],
    *,
    scenario_budgets: dict[tuple[str, str], Budget] | None = None,
    baselines: dict[tuple[str, str], Baseline] | None = None,
    max_ratio: float | None = None,
) -> str:
    rows = []
    for result in results:
        budget = budget_for(result, budgets, scenario_budgets)
        baseline = (
            baselines.get((result.scenario, result.fixture)) if baselines else None
        )
        evaluation = evaluate_result(
            result, budget, baseline=baseline, max_ratio=max_ratio
        )
        rows.append(
            {
                **asdict(result),
                "budget": asdict(budget),
                "baseline": asdict(baseline) if baseline else None,
                "baseline_rss_ratio": (
                    result.peak_rss_bytes / baseline.peak_rss_bytes
                    if baseline and baseline.peak_rss_bytes > 0
                    else None
                ),
                "baseline_duration_ratio": (
                    result.elapsed_s / baseline.elapsed_s
                    if baseline and baseline.elapsed_s > 0
                    else None
                ),
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
            "schema_version": 3,
            "metadata": metadata,
            "legacy_max_ratio": max_ratio,
            "regression_thresholds": {
                "warn_ratio": REGRESSION_WARN_RATIO,
                "fail_ratio": REGRESSION_FAIL_RATIO,
            },
            "results": rows,
        },
        indent=2,
    )


def format_summary_table(
    results: list[Result],
    budgets: dict[str, Budget],
    *,
    scenario_budgets: dict[tuple[str, str], Budget] | None = None,
    baselines: dict[tuple[str, str], Baseline] | None = None,
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
            budget_for(result, budgets, scenario_budgets),
            baseline=baselines.get((result.scenario, result.fixture))
            if baselines
            else None,
            max_ratio=max_ratio,
        )
        rss_mb = result.peak_rss_bytes / (1024 * 1024)
        lines.append(
            f"{result.scenario:<18} {result.fixture:<8} {rss_mb:>14.1f} "
            f"{result.elapsed_s:>10.2f} {evaluation.status:>16}"
        )
    return "\n".join(lines)
