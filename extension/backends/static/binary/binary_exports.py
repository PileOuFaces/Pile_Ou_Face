# SPDX-License-Identifier: AGPL-3.0-only
"""Liste les fonctions et données exportées d'un binaire (ELF, PE, Mach-O).

Usage:
    python backends/static/binary_exports.py --binary /path/to/binary
"""

from __future__ import annotations

import argparse
import json
import sys

import lief


def _demangle(name: str) -> str:
    """Tente de démangler un nom C++, retourne l'original si échec."""
    try:
        result = lief.demangle(name)
        return result if result else name
    except Exception:
        return name


def _strip_leading_underscore(name: str) -> str:
    """Retire le préfixe _ des symboles C Mach-O (pas __ qui sont internes)."""
    if name.startswith("_") and not name.startswith("__"):
        return name[1:]
    return name


def extract_exports(binary_path: str) -> dict:
    """Extrait les exports d'un binaire.

    Returns:
        {
            "format": "ELF" | "PE" | "Mach-O",
            "exports": [
                {
                    "addr": "0x...",
                    "name": "raw_name",
                    "demangled": "human_name",
                    "type": "function" | "data",
                    "ordinal": int | null,  # PE seulement
                }
            ],
            "count": int,
        }
    """
    binary = lief.parse(binary_path)
    if binary is None:
        return {"error": f"Impossible de parser le binaire : {binary_path}"}

    exports: list[dict] = []

    if isinstance(binary, lief.ELF.Binary):
        fmt = "ELF"
        for fn in binary.exported_functions:
            name = fn.name or ""
            if not name or name.startswith("$"):
                continue
            demangled = _demangle(name)
            exports.append(
                {
                    "addr": hex(fn.address),
                    "name": name,
                    "demangled": demangled if demangled != name else None,
                    "type": "function",
                    "ordinal": None,
                }
            )

    elif isinstance(binary, lief.PE.Binary):
        fmt = "PE"
        pe_export = binary.get_export()
        if pe_export:
            for entry in pe_export.entries:
                name = entry.name or ""
                demangled = _demangle(name) if name else ""
                exports.append(
                    {
                        "addr": hex(entry.address + binary.optional_header.imagebase),
                        "name": name or f"ord_{entry.ordinal}",
                        "demangled": demangled
                        if demangled and demangled != name
                        else None,
                        "type": "function",
                        "ordinal": entry.ordinal,
                    }
                )

    elif isinstance(binary, lief.MachO.Binary):
        fmt = "Mach-O"
        seen_addrs: set[int] = set()

        def _add_macho_sym(raw_name: str, address: int) -> None:
            _SKIP = {"__mh_execute_header", "__mh_dylib_header", "__mh_bundle_header"}
            if not raw_name or raw_name in _SKIP or raw_name.startswith("$"):
                return
            if address == 0 or address in seen_addrs:
                return
            seen_addrs.add(address)
            clean_name = _strip_leading_underscore(raw_name)
            demangled = _demangle(raw_name)
            demangled = (
                _strip_leading_underscore(demangled) if demangled != raw_name else None
            )
            exports.append(
                {
                    "addr": hex(address),
                    "name": clean_name,
                    "demangled": demangled,
                    "type": "function",
                    "ordinal": None,
                }
            )

        # 1. Export trie (fonctions explicitement exportées)
        for fn in binary.exported_functions:
            _add_macho_sym(fn.name or "", fn.address)

        # 2. Symbol table — pour les binaires non strippés, inclure les symboles locaux nommés
        for sym in binary.symbols:
            raw = sym.name or ""
            if not raw or not raw.startswith("_"):
                continue
            try:
                addr = int(sym.value)
            except (TypeError, ValueError):
                continue
            if addr < 0x1000:
                continue
            _add_macho_sym(raw, addr)

    else:
        return {"error": "Format non supporté", "format": str(type(binary))}

    # Trier par adresse
    exports.sort(key=lambda e: int(e["addr"], 16))

    return {
        "format": fmt,
        "exports": exports,
        "count": len(exports),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Liste les exports d'un binaire")
    parser.add_argument("--binary", required=True, help="Chemin du binaire")
    args = parser.parse_args()

    result = extract_exports(args.binary)
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
