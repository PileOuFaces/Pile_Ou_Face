# SPDX-License-Identifier: AGPL-3.0-only
"""Shim de compatibilite IDAPython (idc/idautils/idaapi).

Permet a des scripts IDAPython publics non modifies de tourner contre les
backends `backends.static.*` de Pile ou Face, en mappant le sous-ensemble
d'API le plus utilise (fonctions, xrefs, strings, disasm, commentaires,
renommages). Voir `docs/static/idapython-compat.md` pour la table de
compatibilite complete.

Usage (depuis backends/static/repl/repl.py) :

    from backends.static.compat.ida.shim import patched_ida_runtime

    with patched_ida_runtime(binary_path):
        run_user_script(code, exec_globals)
"""
