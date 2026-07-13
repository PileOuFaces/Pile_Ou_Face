# SPDX-License-Identifier: AGPL-3.0-only
"""CLI : python3 -m tooling.loadtest [--scenario NAME] [--size NAME] [--results-dir DIR]"""

from __future__ import annotations

import argparse
import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from loadtest.fixtures import build_fixture
from loadtest.report import Result, all_ok, format_summary_table, to_json
from loadtest.runner import run_measured
from loadtest.scenarios import FIXTURE_PROFILES, SCENARIOS

EXTENSION_ROOT = Path(__file__).resolve().parent.parent.parent / "extension"
DEFAULT_FIXTURE_CACHE = Path(__file__).resolve().parent / ".fixture_cache"
DEFAULT_RESULTS_DIR = Path(__file__).resolve().parent / ".results"
# Mesuré empiriquement : sur la fixture "small" (~1 Mo), le pic RSS d'un
# script Python (interpréteur + imports du backend) tourne autour de
# 200-230 Mo — un overhead fixe qui domine largement pour les petits
# binaires et n'indique aucun problème réel. Un ratio de 10 ferait
# échouer systématiquement le cas le plus courant (petite fixture).
# 500 laisse de la marge sur les petites fixtures tout en restant capable
# de détecter une vraie dérive mémoire sur les fixtures medium/large où le
# binaire lui-même pèse bien plus lourd que l'overhead de l'interpréteur.
DEFAULT_MAX_RATIO = 500.0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Test de charge des fonctionnalités backend")
    parser.add_argument("--scenario", help="Nom d'un seul scénario à exécuter (défaut: tous)")
    parser.add_argument("--size", help="Nom d'un seul profil de fixture à utiliser (défaut: tous)")
    parser.add_argument("--results-dir", default=str(DEFAULT_RESULTS_DIR))
    parser.add_argument("--max-ratio", type=float, default=DEFAULT_MAX_RATIO,
                         help="Ratio pic RSS / taille binaire au-delà duquel un résultat est signalé")
    args = parser.parse_args(argv)

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
            script_path = EXTENSION_ROOT / scenario.script
            with tempfile.TemporaryDirectory() as out_tmp:
                out_dir = Path(out_tmp)
                cmd_args = scenario.build_args(binary_path, out_dir)
                measured = run_measured(
                    [sys.executable, str(script_path), *cmd_args],
                    timeout_s=scenario.timeout_s,
                    env=script_env,
                )
                results.append(Result(
                    scenario=scenario.name,
                    fixture=profile.name,
                    binary_size_bytes=binary_size,
                    peak_rss_bytes=measured["peak_rss_bytes"],
                    elapsed_s=measured["elapsed_s"],
                    returncode=measured["returncode"],
                    timed_out=measured["timed_out"],
                ))

    results_dir = Path(args.results_dir)
    results_dir.mkdir(parents=True, exist_ok=True)
    report_path = results_dir / f"loadtest_{int(time.time())}.json"
    report_path.write_text(to_json(results), encoding="utf-8")

    print(format_summary_table(results, args.max_ratio))
    print(f"\nRapport JSON: {report_path}")

    return 0 if all_ok(results, args.max_ratio) else 1


if __name__ == "__main__":
    sys.exit(main())
