# SPDX-License-Identifier: AGPL-3.0-only
"""Construction d'un index d'analyse statique persistant.

Cette couche fait evoluer le cache `.pfdb` en base d'analyse re-utilisable.
Elle centralise le chargement du binaire, le desassemblage structure, les
fonctions, le CFG, les xrefs et les imports.
"""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import json
from pathlib import Path
from typing import Any

from backends.shared.log import configure_logging, get_logger
from backends.static.binary.imports_analysis import analyze_imports
from backends.static.binary.symbols import extract_symbols
from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm.cfg import build_cfg
from backends.static.disasm.disasm import disassemble_with_capstone
from backends.static.disasm.discover_functions import discover_functions
from backends.static.disasm.xrefs import build_xref_map

logger = get_logger(__name__)


def _with_line_numbers(lines: list[dict]) -> list[dict]:
    """Garantit un champ `line` pour toutes les instructions."""
    result = []
    for idx, line in enumerate(lines, start=1):
        copied = dict(line)
        copied.setdefault("line", idx)
        result.append(copied)
    return result


def _ensure_disasm(cache: DisasmCache, binary_path: str, force: bool) -> list[dict]:
    if not force:
        hit = cache.get_disasm(binary_path)
        if hit is not None:
            _, lines = hit
            if lines:
                return _with_line_numbers(lines)

    lines = disassemble_with_capstone(binary_path)
    if lines is None:
        return []
    lines = _with_line_numbers(lines)
    cache.save_disasm(binary_path, lines)
    return lines


def _ensure_symbols(cache: DisasmCache, binary_path: str, force: bool) -> list[dict]:
    if not force:
        cached = cache.get_symbols(binary_path)
        if cached:
            return cached
    symbols = extract_symbols(binary_path)
    cache.save_symbols(binary_path, symbols)
    return symbols


def _ensure_imports(cache: DisasmCache, binary_path: str, force: bool) -> dict:
    if not force:
        cached = cache.get_imports_analysis(binary_path)
        if cached:
            return cached
    result = analyze_imports(binary_path)
    if not result.get("error"):
        cache.save_imports_analysis(binary_path, result)
    return result


def _ensure_functions(
    cache: DisasmCache,
    binary_path: str,
    lines: list[dict],
    symbols: list[dict],
    force: bool,
) -> list[dict]:
    if not force:
        cached = cache.get_functions(binary_path)
        if cached:
            return cached

    known_addrs = {s.get("addr", "") for s in symbols if s.get("addr")}
    functions = discover_functions(
        lines,
        known_addrs,
        binary_path=binary_path,
    )
    cache.save_functions(binary_path, functions)
    return functions


def _ensure_cfg(
    cache: DisasmCache,
    binary_path: str,
    lines: list[dict],
    force: bool,
) -> dict:
    if not force:
        cached = cache.get_cfg(binary_path)
        if cached:
            return cached
    cfg = build_cfg(lines, binary_path=binary_path)
    cache.save_cfg(binary_path, cfg)
    return cfg


def _ensure_xrefs(
    cache: DisasmCache,
    binary_path: str,
    lines: list[dict],
    force: bool,
) -> dict:
    if not force:
        cached = cache.get_xref_map(binary_path)
        if cached:
            return cached
    xref_map = build_xref_map(lines, binary_path=binary_path)
    cache.save_xref_map(binary_path, xref_map)
    return xref_map


def build_analysis_index(
    binary_path: str,
    cache_db: str | None = None,
    force: bool = False,
) -> dict[str, Any]:
    """Construit ou recharge l'index d'analyse statique d'un binaire."""
    if not Path(binary_path).exists():
        return {
            "binary": binary_path,
            "cache_db": cache_db or "",
            "stats": {
                "instructions": 0,
                "symbols": 0,
                "functions": 0,
                "blocks": 0,
                "edges": 0,
                "xref_targets": 0,
                "imports": 0,
            },
            "errors": {"binary": "Fichier introuvable"},
        }

    db_path = cache_db or default_cache_path(binary_path)

    with DisasmCache(db_path) as cache:
        lines = _ensure_disasm(cache, binary_path, force=force)
        symbols = _ensure_symbols(cache, binary_path, force=force)
        imports = _ensure_imports(cache, binary_path, force=force)
        functions = _ensure_functions(
            cache,
            binary_path,
            lines,
            symbols,
            force=force,
        )
        cfg = _ensure_cfg(cache, binary_path, lines, force=force)
        xrefs = _ensure_xrefs(cache, binary_path, lines, force=force)

    return {
        "binary": binary_path,
        "cache_db": db_path,
        "stats": {
            "instructions": len(lines),
            "symbols": len(symbols),
            "functions": len(functions),
            "blocks": len(cfg.get("blocks", [])),
            "edges": len(cfg.get("edges", [])),
            "xref_targets": len(xrefs),
            "imports": sum(
                len(g.get("functions", [])) for g in imports.get("imports", [])
            ),
        },
        "errors": {
            "imports": imports.get("error"),
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build persistent static analysis index"
    )
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument(
        "--cache-db",
        default=None,
        help="SQLite cache path (.pfdb). Defaults to the binary cache path.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Recompute and overwrite all persisted analysis artifacts.",
    )
    args = parser.parse_args()

    configure_logging()

    result = build_analysis_index(
        args.binary,
        cache_db=args.cache_db,
        force=args.force,
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
