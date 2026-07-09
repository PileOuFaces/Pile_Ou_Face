#!/usr/bin/env python3
"""Script angr standalone pour Pile ou Face.
Usage: python decompile.py --binary <path> [--addr 0x1234] [--full]
Sortie JSON: [{"addr": "0x...", "name": "...", "code": "..."}]
"""

import argparse
import json


def run(binary, addr="", full=False):
    try:
        import angr
    except ImportError:
        return [{"error": "angr non disponible"}]
    try:
        p = angr.Project(binary, auto_load_libs=False, load_debug_info=False)
    except Exception as e:
        return [{"error": f"angr load: {e}"}]
    results = []
    try:
        p.analyses.CFGFast(normalize=True, show_progressbar=False)
        if addr:
            a = int(addr, 16) if addr.startswith("0x") else int(addr)
            try:
                fn = p.kb.functions.get_by_addr(a)
            except Exception:
                return [{"error": f"fonction introuvable à {addr}"}]
            fns = [fn]
        else:
            fns = [
                f
                for f in p.kb.functions.values()
                if not f.is_plt and not f.is_simprocedure
            ]
        for fn in fns:
            try:
                d = p.analyses.Decompiler(fn)
                code = d.codegen.text if d.codegen else ""
            except Exception as e:
                code = f"/* angr error: {e} */"
            results.append({"addr": f"0x{fn.addr:x}", "name": fn.name, "code": code})
    except Exception as e:
        return [{"error": str(e)}]
    return results or [{"error": "aucune fonction"}]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--addr", default="")
    p.add_argument("--full", action="store_true")
    args = p.parse_args()
    print(json.dumps(run(args.binary, args.addr, args.full)))
