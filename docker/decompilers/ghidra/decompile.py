#!/usr/bin/env python3
"""Adapter Ghidra via PyGhidra pour Pile ou Face.

Usage: python decompile.py --binary <path> [--addr 0x1234] [--full]
Sortie JSON: [{"addr": "0x...", "name": "...", "code": "..."}]
"""

import argparse
import json
import tempfile


def _decompile_fn(decomp_ifc, fn, monitor):
    addr_str = "0x%x" % fn.getEntryPoint().getOffset()
    try:
        res = decomp_ifc.decompileFunction(fn, 60, monitor)
    except Exception as exc:
        return {
            "addr": addr_str,
            "name": str(fn.getName()),
            "code": "",
            "error": str(exc),
        }
    if res and res.decompileCompleted():
        df = res.getDecompiledFunction()
        code = str(df.getC()) if df else ""
        return {"addr": addr_str, "name": str(fn.getName()), "code": code}
    err_msg = ""
    try:
        err_msg = str(res.getErrorMessage() or "") if res else ""
    except Exception:
        pass
    return {
        "addr": addr_str,
        "name": str(fn.getName()),
        "code": "",
        "error": err_msg or "decompilation non completee",
    }


def run(binary: str, addr: str = "", full: bool = False) -> list[dict]:
    try:
        import pyghidra
    except ImportError:
        return [{"error": "pyghidra non installé (pip install pyghidra)"}]

    try:
        with tempfile.TemporaryDirectory(prefix="pof_ghidra_") as proj_dir:
            with pyghidra.open_program(
                binary, analyze=True, project_location=proj_dir
            ) as flat_api:
                from ghidra.app.decompiler import DecompInterface, DecompileOptions
                from ghidra.util.task import ConsoleTaskMonitor

                program = flat_api.currentProgram
                monitor = ConsoleTaskMonitor()
                fm = program.getFunctionManager()

                decomp_ifc = DecompInterface()
                decomp_ifc.setOptions(DecompileOptions())
                decomp_ifc.openProgram(program)

                try:
                    if full:
                        results = []
                        for fn in fm.getFunctions(True):
                            if not fn.isExternal():
                                results.append(_decompile_fn(decomp_ifc, fn, monitor))
                        return results

                    target_fn = None
                    if addr:
                        try:
                            addr_obj = program.getAddressFactory().getAddress(addr)
                            target_fn = fm.getFunctionContaining(addr_obj)
                            if target_fn is None:
                                target_fn = fm.getFunctionAt(addr_obj)
                        except Exception:
                            pass
                    if target_fn is None:
                        for fn in fm.getFunctions(True):
                            if not fn.isExternal():
                                target_fn = fn
                                break
                    if target_fn:
                        return [_decompile_fn(decomp_ifc, target_fn, monitor)]
                    return [{"error": "aucune fonction trouvee dans le binaire"}]
                finally:
                    decomp_ifc.dispose()

    except Exception as exc:
        return [{"error": str(exc)}]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--binary", required=True)
    p.add_argument("--addr", default="")
    p.add_argument("--full", action="store_true")
    args = p.parse_args()
    print(json.dumps(run(args.binary, args.addr, args.full)))
