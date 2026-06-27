# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Resolve instruction addresses to symbols and source locations via addr2line and nm.
# Normalizes input addresses, applies base adjustments, and parses tool output.
# Returns best-effort mappings while handling missing tools or errors.
# -----------------------------------------------------------------------------

"""@file resolve.py
@brief Helpers de resolution addr2line/nm.

@details Traduit des adresses en symboles et emplacements source.
"""

import shutil
import subprocess
from typing import Dict, List, Optional


def addr2line_map(
    binary_path: str, addresses: List[str], base_adjust: int
) -> Dict[str, Dict[str, object]]:
    """@brief Resolves addr->file/line/func via addr2line.
    @param binary_path Chemin du binaire.
    @param addresses Liste d'adresses hex (0x...).
    @param base_adjust Ajustement PIE a soustraire.
    @return Mapping addr -> {file,line,func}.
    """
    # Déduplique/filtre les adresses et applique un base adjust (PIE).
    unique = []
    seen = set()
    for addr in addresses:
        if not isinstance(addr, str) or not addr.startswith("0x"):
            continue
        if addr in seen:
            continue
        seen.add(addr)
        unique.append(addr)

    if not unique:
        return {}

    adjusted = []
    for addr in unique:
        value = int(addr, 16) - base_adjust
        if value < 0:
            value = 0
        adjusted.append(f"0x{value:x}")

    try:
        result = subprocess.run(
            ["addr2line", "-e", binary_path, "-f", "-C", "-a", *adjusted],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return {}

    if result.returncode != 0:
        return {}

    # addr2line renvoie 3 lignes par adresse: addr, func, file:line.
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    mapping: Dict[str, Dict[str, object]] = {}
    idx = 0
    for orig_addr in unique:
        if idx + 2 >= len(lines):
            break
        addr_line = lines[idx]
        func_line = lines[idx + 1]
        file_line = lines[idx + 2]
        idx += 3

        file_path = None
        line_no = None
        if file_line != "??:0" and ":" in file_line:
            file_path, line_str = file_line.rsplit(":", 1)
            if line_str.isdigit():
                line_no = int(line_str)

        mapping[orig_addr] = {
            "file": file_path,
            "line": line_no,
            "func": None if func_line == "??" else func_line,
        }

    return mapping


def resolve_symbol_addr(
    binary_path: str, symbol: str, base_adjust: int
) -> Optional[int]:
    """@brief Resolves un symbole en adresse via nm.
    @param binary_path Chemin du binaire.
    @param symbol Nom du symbole.
    @param base_adjust Ajustement PIE a ajouter.
    @return Adresse absolue ou None.
    """
    # Utilise nm pour trouver l'adresse d'un symbole, puis applique base_adjust.
    if not shutil.which("nm"):
        return None
    try:
        result = subprocess.run(
            ["nm", "-n", "--defined-only", binary_path],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None

    candidates = [symbol]
    if symbol.startswith("_") and len(symbol) > 1:
        candidates.append(symbol[1:])
    elif symbol:
        candidates.append("_" + symbol)

    for line in result.stdout.splitlines():
        parts = line.strip().split()
        if len(parts) < 3:
            continue
        addr_str, _stype, name = parts[0], parts[1], parts[2]
        if name not in candidates:
            continue
        try:
            addr_val = int(addr_str, 16)
        except ValueError:
            continue
        return addr_val + base_adjust
    return None
