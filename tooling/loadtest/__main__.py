# SPDX-License-Identifier: AGPL-3.0-only
"""CLI : python3 -m tooling.loadtest [--scenario NAME] [--size NAME] [--results-dir DIR]"""

from __future__ import annotations

import argparse
import os
import platform
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loadtest.fixtures import build_fixture
from loadtest.baseline import load_baseline
from loadtest.report import Budget, Result, all_ok, format_summary_table, to_json
from loadtest.runner import run_measured
from loadtest.scenarios import FIXTURE_PROFILES, SCENARIOS

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXTENSION_ROOT = REPO_ROOT / "extension"
DEFAULT_FIXTURE_CACHE = Path(__file__).resolve().parent / ".fixture_cache"
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / ".results"
MIB = 1024 * 1024
DEFAULT_BUDGETS = {
    "small": Budget(192 * MIB, 256 * MIB, 1.5, 3.0),
    "medium": Budget(256 * MIB, 384 * MIB, 2.0, 5.0),
    "large": Budget(768 * MIB, 1024 * MIB, 10.0, 30.0),
}
SCENARIO_BUDGETS = {
    # Le scan entropie parcourt chaque octet : sur les runners GitHub Linux,
    # sa variance est supérieure aux autres scénarios medium (mesuré à 5,85 s).
    ("entropy", "medium"): Budget(256 * MIB, 384 * MIB, 4.0, 8.0),
}


def _git_commit() -> str:
    if commit := os.environ.get("GITHUB_SHA"):
        return commit
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    return result.stdout.strip() if result.returncode == 0 else ""


def _total_memory_bytes() -> int | None:
    try:
        return os.sysconf("SC_PAGE_SIZE") * os.sysconf("SC_PHYS_PAGES")
    except (AttributeError, OSError, ValueError):
        return None


def _script_path(script: str) -> Path:
    return (
        REPO_ROOT / script if script.startswith("tooling/") else EXTENSION_ROOT / script
    )


def _run_prepare_commands(
    scenario, binary_path: Path, out_dir: Path, env: dict[str, str]
) -> bool:
    if scenario.prepare is None:
        return True
    for script, cmd_args in scenario.prepare(binary_path, out_dir):
        result = subprocess.run(
            [sys.executable, str(_script_path(script)), *cmd_args],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
        )
        if result.returncode != 0:
            print(
                f"Préparation échouée pour {scenario.name}: {script}\n{result.stderr[-2000:]}",
                file=sys.stderr,
            )
            return False
    return True


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Test de charge des fonctionnalités backend"
    )
    parser.add_argument(
        "--scenario", help="Nom d'un seul scénario à exécuter (défaut: tous)"
    )
    parser.add_argument(
        "--size", help="Nom d'un seul profil de fixture à utiliser (défaut: tous)"
    )
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    parser.add_argument(
        "--baseline",
        type=Path,
        help="Baseline médiane (minimum trois runs) pour les gates +20 %% / +35 %%",
    )
    parser.add_argument(
        "--max-ratio",
        type=float,
        default=None,
        help="Garde ratio historique optionnelle, en complément des budgets absolus",
    )
    args = parser.parse_args(argv)

    try:
        baselines = (
            load_baseline(
                args.baseline,
                expected_machine=platform.machine(),
                expected_python=platform.python_version(),
            )
            if args.baseline
            else None
        )
    except (OSError, ValueError) as error:
        parser.error(str(error))

    scenarios = [s for s in SCENARIOS if not args.scenario or s.name == args.scenario]
    profiles = [p for p in FIXTURE_PROFILES if not args.size or p.name == args.size]
    if not scenarios:
        print(f"Scénario inconnu: {args.scenario}", file=sys.stderr)
        return 2
    if not profiles:
        print(f"Profil de fixture inconnu: {args.size}", file=sys.stderr)
        return 2

    # Les scripts backend (extension/backends/...) font des imports absolus
    # du type `from backends.shared... import ...` : ils supposent que
    # extension/ est sur PYTHONPATH (c'est le cas quand VS Code les lance
    # comme extension, pas quand on les invoque directement en subprocess).
    script_env = {**os.environ, "PYTHONPATH": str(EXTENSION_ROOT)}

    results: list[Result] = []
    for profile in profiles:
        binary_path = build_fixture(profile.to_spec(), cache_dir=DEFAULT_FIXTURE_CACHE)
        binary_size = binary_path.stat().st_size
        for scenario in scenarios:
            script_path = _script_path(scenario.script)
            with tempfile.TemporaryDirectory() as out_tmp:
                out_dir = Path(out_tmp)
                if not _run_prepare_commands(
                    scenario, binary_path, out_dir, script_env
                ):
                    results.append(
                        Result(
                            scenario=scenario.name,
                            fixture=profile.name,
                            binary_size_bytes=binary_size,
                            peak_rss_bytes=0,
                            elapsed_s=0.0,
                            returncode=1,
                            timed_out=False,
                        )
                    )
                    continue
                cmd_args = scenario.build_args(binary_path, out_dir)
                measured = run_measured(
                    [sys.executable, str(script_path), *cmd_args],
                    timeout_s=scenario.timeout_s,
                    env=script_env,
                )
                results.append(
                    Result(
                        scenario=scenario.name,
                        fixture=profile.name,
                        binary_size_bytes=binary_size,
                        peak_rss_bytes=measured["peak_rss_bytes"],
                        elapsed_s=measured["elapsed_s"],
                        returncode=measured["returncode"],
                        timed_out=measured["timed_out"],
                    )
                )

    if baselines:
        missing = {
            (result.scenario, result.fixture)
            for result in results
            if (result.scenario, result.fixture) not in baselines
        }
        if missing:
            names = ", ".join(
                f"{scenario}/{fixture}" for scenario, fixture in sorted(missing)
            )
            print(f"Baseline incomplète : {names}", file=sys.stderr)
            return 2

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    report_path = results_dir / f"loadtest_{int(time.time())}.json"
    metadata = {
        "generated_at_unix": int(time.time()),
        "commit": _git_commit(),
        "os": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count(),
        "total_memory_bytes": _total_memory_bytes(),
    }
    report_path.write_text(
        to_json(
            results,
            DEFAULT_BUDGETS,
            metadata,
            scenario_budgets=SCENARIO_BUDGETS,
            baselines=baselines,
            max_ratio=args.max_ratio,
        ),
        encoding="utf-8",
    )

    print(
        format_summary_table(
            results,
            DEFAULT_BUDGETS,
            scenario_budgets=SCENARIO_BUDGETS,
            baselines=baselines,
            max_ratio=args.max_ratio,
        )
    )
    print(f"\nRapport JSON: {report_path}")

    return (
        0
        if all_ok(
            results,
            DEFAULT_BUDGETS,
            scenario_budgets=SCENARIO_BUDGETS,
            baselines=baselines,
            max_ratio=args.max_ratio,
        )
        else 1
    )


if __name__ == "__main__":
    sys.exit(main())
