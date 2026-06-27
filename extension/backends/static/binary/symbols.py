# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction des symboles d'un binaire (ELF/Mach-O/PE).

Utilise lief pour extraire les symboles (robuste, multi-format).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import re

try:
    import lief
except ImportError:
    lief = None

from backends.shared.log import configure_logging, get_logger, make_meta

logger = get_logger(__name__)

_SYMBOL_NAME_RE = re.compile(rb"[A-Za-z_.$][A-Za-z0-9_.$@]{2,96}")
_COMMON_SYMBOL_PREFIXES = (
    b"_",
    b"sub_",
    b"func_",
    b"main",
    b"start",
)


def _fallback_symbols_from_strings(binary_path: str, defined_only: bool = True) -> list[dict]:
    del defined_only
    path = Path(binary_path)
    if not path.exists() or not path.is_file():
        return []
    try:
        data = path.read_bytes()
    except Exception:
        return []
    seen: set[str] = set()
    symbols: list[dict] = []
    for match in _SYMBOL_NAME_RE.finditer(data):
        raw = match.group()
        if not raw.startswith(_COMMON_SYMBOL_PREFIXES):
            continue
        name = raw.decode("ascii", errors="ignore")
        if not name or name in seen:
            continue
        seen.add(name)
        symbols.append(
            {
                "name": name,
                "addr": hex(match.start()),
                "type": "?",
                "size": None,
                "source": "string-reference",
            }
        )
    return sorted(symbols, key=lambda item: (item["name"], item["addr"]))


@dataclass
class Symbol:
    """Symbole extrait du binaire."""

    name: str
    addr: str
    type: str  # T=code, D=data, B=bss, U=undefined, etc.
    size: int | None = None


def extract_symbols(binary_path: str, defined_only: bool = True) -> list[dict]:
    """Extrait les symboles d'un binaire (ELF, Mach-O, PE).

    Args:
        binary_path: Chemin vers le binaire
        defined_only: Si True, exclut les symboles non définis (extern)

    Returns:
        Liste de {name, addr, type, size} triée par nom
    """
    path = Path(binary_path)
    if not path.exists():
        return []
    if not lief:
        return _fallback_symbols_from_strings(binary_path, defined_only)

    try:
        binary = lief.parse(str(path))
        if binary is None:
            return _fallback_symbols_from_strings(binary_path, defined_only)
    except Exception:
        return _fallback_symbols_from_strings(binary_path, defined_only)

    symbols = []
    seen = set()

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        # Symboles statiques
        for sym in binary.symtab_symbols:
            if not sym.name or sym.name in seen:
                continue
            # Filtrer undefined si demandé
            if defined_only and sym.binding == lief.ELF.Symbol.BINDING.GLOBAL and sym.shndx == 0:
                continue
            seen.add(sym.name)

            # Déterminer le type (T=text, D=data, B=bss, U=undefined)
            sym_type = "?"
            if sym.type == lief.ELF.Symbol.TYPE.FUNC:
                sym_type = "T"  # Function (text)
            elif sym.type == lief.ELF.Symbol.TYPE.OBJECT:
                sym_type = "D"  # Data object
            elif sym.shndx == 0:
                sym_type = "U"  # Undefined
            elif sym.binding == lief.ELF.Symbol.BINDING.WEAK:
                sym_type = "W"  # Weak

            addr = f"0x{sym.value:x}" if sym.value else "0x0"
            sym_size = sym.size if hasattr(sym, "size") and sym.size else None
            symbols.append(Symbol(name=sym.name, addr=addr, type=sym_type, size=sym_size))

        # Symboles dynamiques
        for sym in binary.dynamic_symbols:
            if not sym.name or sym.name in seen:
                continue
            if defined_only and sym.shndx == 0:
                continue
            seen.add(sym.name)

            sym_type = "T" if sym.type == lief.ELF.Symbol.TYPE.FUNC else "D"
            addr = f"0x{sym.value:x}" if sym.value else "0x0"
            sym_size = sym.size if hasattr(sym, "size") and sym.size else None
            symbols.append(Symbol(name=sym.name, addr=addr, type=sym_type, size=sym_size))

    # Mach-O
    elif isinstance(binary, lief.MachO.Binary):
        for sym in binary.symbols:
            if not sym.name or sym.name in seen:
                continue

            # Exclure les symboles STAB/debug (N_SO, N_OSO, N_FUN, etc.)
            # LIEF peut retourner un enum ou un int selon la version — forcer int
            raw_type = getattr(sym, "type", 0)
            try:
                raw_int = int(raw_type)
            except (TypeError, ValueError):
                raw_int = 0
            if raw_int & 0xE0:  # bits STAB définis (N_SO=0x64, N_OSO=0x66, N_FUN=0x24…)
                continue
            # Exclure les noms qui ressemblent à des chemins (symboles N_SO résiduels)
            name = sym.name
            if "/" in name or name.startswith("."):
                continue

            seen.add(name)

            # Déterminer le type Mach-O
            sym_type = "T"  # Par défaut fonction
            if raw_int == 0:  # N_UNDF
                if defined_only:
                    continue
                sym_type = "U"
            elif raw_int == 1:  # N_ABS
                sym_type = "A"

            addr = f"0x{sym.value:x}"
            sym_size = sym.size if hasattr(sym, "size") and sym.size else None
            symbols.append(Symbol(name=name, addr=addr, type=sym_type, size=sym_size))

    # PE
    elif isinstance(binary, lief.PE.Binary):
        # Symboles exportés
        if hasattr(binary, "exported_functions"):
            for func in binary.exported_functions:
                name = func.name
                if not name or name in seen:
                    continue
                seen.add(name)
                addr = f"0x{func.address:x}" if func.address else "0x0"
                symbols.append(Symbol(name=name, addr=addr, type="T", size=None))

        # Symboles importés
        if not defined_only and hasattr(binary, "imported_functions"):
            for func in binary.imported_functions:
                name = func.name
                if not name or name in seen:
                    continue
                seen.add(name)
                addr = f"0x{func.iat_address:x}" if func.iat_address else "0x0"
                symbols.append(Symbol(name=name, addr=addr, type="U", size=None))

    symbols_sorted = sorted(symbols, key=lambda x: x.name)

    # Calculer size par différence d'adresses pour les fonctions sans size lief
    addr_list = sorted(
        [
            (int(s.addr, 16), i)
            for i, s in enumerate(symbols_sorted)
            if s.type in ("T", "t") and s.addr != "0x0"
        ],
        key=lambda x: x[0],
    )
    addr_to_next: dict[int, int] = {}
    for j in range(len(addr_list) - 1):
        cur_addr = addr_list[j][0]
        nxt_addr = addr_list[j + 1][0]
        addr_to_next[cur_addr] = nxt_addr - cur_addr

    result = []
    for s in symbols_sorted:
        size = s.size
        if not size:
            try:
                a = int(s.addr, 16)
                size = addr_to_next.get(a)
            except (ValueError, AttributeError):
                size = None
        result.append({"name": s.name, "addr": s.addr, "type": s.type, "size": size})
    return result


def main() -> int:
    """Point d'entrée CLI : extrait les symboles d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract symbols from binary (LIEF)")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument("--all", action="store_true", help="Include undefined symbols")
    args = parser.parse_args()

    configure_logging()

    symbols = extract_symbols(args.binary, defined_only=not args.all)
    payload = {"meta": make_meta("symbols"), "symbols": symbols}
    out = json.dumps(payload, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Symbols written to {args.output} ({len(symbols)} symbols)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
