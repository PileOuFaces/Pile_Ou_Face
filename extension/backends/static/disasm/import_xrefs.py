# SPDX-License-Identifier: AGPL-3.0-only
"""Xrefs pour les fonctions importées : callsites par nom de fonction.

CLI:
  python import_xrefs.py --binary <path> --function <name>

Output JSON:
  {
    "function": "printf",
    "plt_addr": "0x401020",
    "callsites": [{"addr": "0x40118a", "text": "...", "line": 42}],
    "error": null
  }
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path


def _parse_mnem_ops(line: dict) -> tuple[str, str]:
    """Extrait (mnemonic, operands) depuis un dict de ligne de désassemblage.

    Supporte deux formats :
    - Avec clés explicites : {"mnemonic": "call", "operands": "0x401020", ...}
    - Texte brut : {"text": "e8 4b 04 00 00       call     0x100000928", ...}
    """
    mnem = line.get("mnemonic", "")
    ops = line.get("operands", "")
    if mnem:
        return mnem.lower(), ops
    text = line.get("text", "")
    if not text:
        return "", ""
    # Format : "hex_bytes    mnemonic    operands" (séparateurs = 2+ espaces)
    parts = re.split(r"\s{2,}", text.strip(), maxsplit=1)
    if len(parts) < 2:
        return "", ""
    rest = parts[1].split(None, 1)
    return rest[0].lower() if rest else "", rest[1] if len(rest) > 1 else ""


def _get_plt_addr(binary_path: str, fn_name: str) -> str | None:
    """Retourne l'adresse du stub PLT/stubs pour fn_name, ou None."""
    from backends.static.disasm.call_graph import resolve_plt_symbols

    plt_map = resolve_plt_symbols(binary_path)
    # plt_map : {"0x401020": "printf@plt", ...}
    fn_at_plt = fn_name + "@plt"
    for addr, name in plt_map.items():
        if name in (fn_at_plt, fn_name):
            return addr
    return None


def _load_disasm_lines(binary_path: str) -> list[dict]:
    """Charge les lignes de désassemblage depuis le cache ou les calcule."""
    from backends.static.cache.cache import DisasmCache, default_cache_path

    cache_path = default_cache_path(binary_path)
    with DisasmCache(cache_path) as cache:
        result = cache.get_disasm(binary_path)
        if result:
            _, lines = result
            return lines

    # Cache absent — lancer le désassemblage
    from backends.static.disasm.disasm import disassemble_with_capstone

    lines = disassemble_with_capstone(binary_path)
    if lines is None:
        return []

    with DisasmCache(cache_path) as cache:
        cache.save_disasm(binary_path, lines)
    return lines


def _load_xref_map(binary_path: str) -> dict:
    """Charge la map de xrefs depuis le cache ou la reconstruit."""
    from backends.static.cache.cache import DisasmCache, default_cache_path
    from backends.static.disasm.xrefs import build_xref_map

    cache_path = default_cache_path(binary_path)
    with DisasmCache(cache_path) as cache:
        cached = cache.get_xref_map(binary_path)
        if cached:
            return cached

        result = cache.get_disasm(binary_path)
        if result:
            _, lines = result
        else:
            lines = _load_disasm_lines(binary_path)

        if not lines:
            return {}

        xref_map = build_xref_map(lines, binary_path=binary_path)
        cache.save_xref_map(binary_path, xref_map)
        return xref_map


def _callsites_from_xrefs(xref_map: dict, target: str | None) -> list[dict]:
    """Retourne les callsites pointant vers une cible depuis une xref map."""
    if not target:
        return []
    refs = xref_map.get(target, [])
    callsites = []
    for ref in refs:
        if ref.get("type") != "call":
            continue
        callsites.append(
            {
                "addr": ref.get("from_addr", ""),
                "text": ref.get("text", ""),
                "line": ref.get("from_line"),
            }
        )
    return callsites


def find_callsites(binary_path: str, fn_name: str) -> dict:
    """Trouve tous les sites d'appel d'une fonction importée dans le binaire.

    Returns:
        {"function": str, "plt_addr": str|None, "callsites": [...], "error": str|None}
    """
    plt_addr = _get_plt_addr(binary_path, fn_name)
    xref_map = _load_xref_map(binary_path)
    cached_callsites = _callsites_from_xrefs(xref_map, plt_addr)
    if cached_callsites:
        return {
            "function": fn_name,
            "plt_addr": plt_addr,
            "callsites": cached_callsites,
            "error": None,
        }

    lines = _load_disasm_lines(binary_path)
    if not lines:
        return {
            "function": fn_name,
            "plt_addr": plt_addr,
            "callsites": [],
            "error": "Désassemblage indisponible",
        }

    callsites = []
    target = plt_addr  # ex. "0x401020"

    for ln in lines:
        mnem, operands = _parse_mnem_ops(ln)
        if mnem != "call":
            continue
        # Capstone donne l'adresse hex directement dans op_str pour call direct
        # ex. "0x401020" ou "rax" (indirect)
        if not target:
            continue
        # Normaliser pour comparaison (0x401020 == 0x0401020)
        try:
            op_int = int(operands.strip(), 16)
            tgt_int = int(target, 16)
            if op_int == tgt_int:
                callsites.append(
                    {
                        "addr": ln.get("addr", ""),
                        "text": ln.get("text", ""),
                        "line": ln.get("line"),
                    }
                )
        except (ValueError, TypeError):
            pass

    return {
        "function": fn_name,
        "plt_addr": plt_addr,
        "callsites": callsites,
        "error": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Find callsites for an imported function"
    )
    parser.add_argument("--binary", required=True, help="Path to binary")
    parser.add_argument("--function", required=True, help="Imported function name")
    args = parser.parse_args()

    if not Path(args.binary).exists():
        print(json.dumps({"error": f"Fichier introuvable : {args.binary}"}))
        return 1

    result = find_callsites(args.binary, args.function)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
