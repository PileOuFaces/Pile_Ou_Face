# @category PileOuFace
# Script Python 3 — exécuté dans la JVM Ghidra via pyghidra.run_script()
# Arguments (via getScriptArgs()) :
#   args[0] = chemin fichier de sortie JSON
#   args[1] = adresse hex (ex: "0x401000") | "full" | absent → première fonction
# pyright: reportMissingImports=false
# pyright: reportUndefinedVariable=false
# pyright: reportOptionalMemberAccess=false
from __future__ import print_function
import json

args = getScriptArgs()
output_file = args[0] if len(args) > 0 else "/tmp/pof_result.json"
mode_arg = args[1] if len(args) > 1 else ""
full_mode = (mode_arg == "full")

results = []
decomp_ifc = None

try:
    from ghidra.app.decompiler import DecompInterface, DecompileOptions

    decomp_ifc = DecompInterface()
    opts = DecompileOptions()
    decomp_ifc.setOptions(opts)
    decomp_ifc.openProgram(currentProgram)

    fm = currentProgram.getFunctionManager()

    def decompile_fn(fn):
        addr_str = "0x%x" % fn.getEntryPoint().getOffset()
        res = decomp_ifc.decompileFunction(fn, 60, monitor)
        if res and res.decompileCompleted():
            df = res.getDecompiledFunction()
            code = str(df.getC()) if df else ""
            return {"addr": addr_str, "name": str(fn.getName()), "code": code}
        err_msg = "timeout"
        try:
            err_msg = str(res.getErrorMessage() or "") if res else "timeout"
        except Exception:
            pass
        return {"addr": addr_str, "name": str(fn.getName()), "code": "", "error": err_msg or "decompilation non completee (voir logs analyzeHeadless)"}

    if full_mode:
        for fn in fm.getFunctions(True):
            if not fn.isExternal():
                r = decompile_fn(fn)
                if r.get("code") or r.get("error"):
                    results.append(r)
    else:
        target_fn = None
        if mode_arg and mode_arg != "full":
            try:
                addr_obj = currentProgram.getAddressFactory().getAddress(mode_arg)
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
            results.append(decompile_fn(target_fn))
        else:
            results.append({"error": "aucune fonction trouvee dans le binaire"})

except Exception as exc:
    results = [{"error": str(exc)}]

finally:
    if decomp_ifc is not None:
        try:
            decomp_ifc.dispose()
        except Exception:
            pass

try:
    with open(output_file, "w") as fout:
        fout.write(json.dumps(results))
except Exception as write_exc:
    import sys
    print("pof_script_write_error: " + str(write_exc), file=sys.stderr)
