#!/usr/bin/env python3
"""Adapter Ghidra via PyGhidra pour Pile ou Face.

Usage: python decompile.py --binary <path> [--addr 0x1234] [--full]
Sortie JSON: [{"addr": "0x...", "name": "...", "code": "..."}]

Tout le code Ghidra-spécifique vit ici — jamais dans le moteur générique.
"""
import argparse
import contextlib
import json
import sys
import tempfile
from pathlib import Path


def run(binary: str, addr: str = "", full: bool = False) -> list[dict]:
    try:
        import pyghidra
    except ImportError:
        return [{"error": "pyghidra non installé (pip install pyghidra)"}]

    script_path = Path(__file__).parent / "script.py"
    if not script_path.exists():
        return [{"error": f"Script introuvable : {script_path}"}]

    mode_arg = "full" if full else (addr or "")

    with tempfile.TemporaryDirectory(prefix="pof_ghidra_") as tmp:
        result_file = Path(tmp) / "result.json"

        try:
            # Redirige stdout vers stderr pour ne pas polluer la sortie JSON
            with contextlib.redirect_stdout(sys.stderr):
                pyghidra.run_script(
                    binary,
                    str(script_path),
                    project_location=tmp,
                    project_name="pof_tmp",
                    script_args=[str(result_file), mode_arg],
                    analyze=True,
                )
        except SystemExit:
            pass
        except Exception as exc:
            return [{"error": str(exc)}]

        if result_file.exists():
            try:
                return json.loads(result_file.read_text(encoding="utf-8"))
            except Exception as exc:
                return [{"error": f"JSON invalide dans result.json: {exc}"}]

        return [{"error": "pyghidra.run_script n'a pas produit de résultat"}]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--addr", default="")
    p.add_argument("--full", action="store_true")
    args = p.parse_args()
    print(json.dumps(run(args.binary, args.addr, args.full)))
