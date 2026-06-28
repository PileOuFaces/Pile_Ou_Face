# SPDX-License-Identifier: AGPL-3.0-only
"""Graphe d'appels (call graph) à partir du CFG et des symboles."""

from __future__ import annotations

import argparse
import json
import os
import sys

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import addr_to_int
from backends.static.binary.arch import (
    detect_binary_arch_from_path,
    iter_supported_adapters,
)
from backends.static.disasm.cfg import (
    _extract_jump_target,
    _extract_symbol_from_operand,
    _get_mnemonic,
    build_cfg,
)

logger = get_logger(__name__)

try:
    import lief as _lief
except ImportError:
    _lief = None


def resolve_plt_symbols(binary_path: str) -> dict[str, str]:
    """Résout les symboles PLT/GOT/stubs depuis le binaire.

    Retourne {stub_addr_hex: "funcname@plt"} pour résoudre les appels
    indirects vers fonctions importées (puts, printf, etc.).

    Supporte ELF (via .rela.plt) et Mach-O (via dyld_chained_fixups/__stubs).
    """
    if not _lief:
        return {}
    try:
        binary = _lief.parse(binary_path)
    except Exception:
        return {}
    if binary is None:
        return {}

    try:
        if isinstance(binary, _lief.ELF.Binary):
            return _resolve_elf_plt(binary)
        if isinstance(binary, _lief.MachO.Binary):
            return _resolve_macho_stubs(binary)
    except Exception as exc:
        logger.debug("PLT resolution failed for %s: %s", binary_path, exc)
    return {}


def _resolve_elf_plt(binary: object) -> dict[str, str]:
    """Résout les stubs PLT ELF via .rela.plt.

    x86-64 : stubs 16 octets, le premier est le resolver (+0).
    """
    plt_map: dict[str, str] = {}

    plt_section = None
    for sec_name in (".plt", ".plt.got", ".plt.sec"):
        sec = binary.get_section(sec_name)  # type: ignore[attr-defined]
        if sec:
            plt_section = sec
            break
    if plt_section is None:
        return plt_map

    try:
        rels = [
            r
            for r in binary.pltgot_relocations  # type: ignore[attr-defined]
            if r.has_symbol and r.symbol.name
        ]
    except Exception:
        return plt_map

    if not rels:
        return plt_map

    rels_sorted = sorted(rels, key=lambda r: r.address)
    plt_base: int = plt_section.virtual_address
    stub_size = 16  # x86-64, premier stub = resolver (+0)

    for i, rel in enumerate(rels_sorted):
        stub_addr = plt_base + stub_size + i * stub_size
        plt_map[f"0x{stub_addr:x}"] = f"{rel.symbol.name}@plt"

    return plt_map


def _resolve_macho_stubs(binary: object) -> dict[str, str]:
    """Résout les stubs Mach-O via dyld_chained_fixups ou dyld_info."""
    plt_map: dict[str, str] = {}

    stubs_section = binary.get_section("__stubs")  # type: ignore[attr-defined]
    if stubs_section is None:
        return plt_map
    stub_base: int = stubs_section.virtual_address
    stubs_size: int = stubs_section.size

    stub_size = int(getattr(stubs_section, "reserved2", 0) or 0)

    def _build_map(bindings: list, name_fn: object) -> dict[str, str]:
        if not bindings or stubs_size <= 0:
            return {}
        entry_size = stub_size or (stubs_size // len(bindings))
        if entry_size <= 0:
            return {}
        result: dict[str, str] = {}
        for i, bind in enumerate(bindings):
            stub_addr = stub_base + i * entry_size
            name = name_fn(bind)  # type: ignore[operator]
            if name:
                result[f"0x{stub_addr:x}"] = f"{name}@plt"
        return result

    # Méthode 1 : dyld_chained_fixups (macOS 12+)
    cf = getattr(binary, "dyld_chained_fixups", None)
    if cf:
        try:
            bindings = sorted(
                [b for b in cf.bindings if b.symbol and b.symbol.name],
                key=lambda b: b.address,
            )
            m = _build_map(bindings, lambda b: b.symbol.name.lstrip("_"))
            if m:
                return m
        except Exception:
            pass

    # Méthode 2 : dyld_info (macOS < 12)
    dyld_info = getattr(binary, "dyld_info", None)
    if dyld_info:
        try:
            bindings = sorted(
                [b for b in dyld_info.bindings if getattr(b, "symbol_name", "")],
                key=lambda b: b.address,
            )
            m = _build_map(bindings, lambda b: b.symbol_name.lstrip("_"))
            if m:
                return m
        except Exception:
            pass

    # Fallback : imported_functions (ordre approximatif)
    try:
        imported = [f for f in binary.imported_functions if f.name]  # type: ignore[attr-defined]
        m = _build_map(imported, lambda f: f.name.lstrip("_"))
        if m:
            return m
    except Exception:
        pass

    return plt_map


def build_call_graph(
    cfg: dict,
    symbols: list[dict],
    lines: list[dict] | None = None,
    binary_path: str | None = None,
) -> dict:
    """Construit le call graph à partir du CFG et des symboles.

    Args:
        cfg: Graphe de flot de contrôle (blocks + edges)
        symbols: Liste de symboles [{addr, name, type}]
        lines: Optionnel, mapping désassemblage pour extraire noms <func@plt>
        binary_path: Optionnel, chemin binaire pour résolution PLT/GOT complète

    Returns:
        {"nodes": [{"addr", "name"}], "edges": [{"from", "to", "from_name", "to_name"}]}
    """
    edges = cfg.get("edges", [])

    # Résoudre les stubs PLT/GOT depuis le binaire si fourni
    plt_map: dict[str, str] = {}
    if binary_path:
        plt_map = resolve_plt_symbols(binary_path)
        if plt_map:
            logger.debug(
                "PLT map: %d stubs resolved from %s", len(plt_map), binary_path
            )

    line_by_addr = {}
    if lines:
        for ln in lines:
            addr = ln.get("addr", "")
            if addr:
                line_by_addr[addr_to_int(addr)] = ln.get("text", "")

    block_map = {b["addr"]: b for b in cfg.get("blocks", [])}

    detected_arch_info = (
        detect_binary_arch_from_path(binary_path) if binary_path else None
    )
    call_adapters = (
        (detected_arch_info.adapter,)
        if detected_arch_info is not None
        else tuple(iter_supported_adapters())
    )

    def _is_call_text(text: str) -> bool:
        mnem = _get_mnemonic(str(text or ""))
        return any(adapter.is_call_mnemonic(mnem) for adapter in call_adapters)

    call_edges = [(e["from"], e["to"]) for e in edges if e.get("type") == "call"]
    if not call_edges and lines:
        seen_direct_calls: set[tuple[str, str]] = set()
        for line in lines:
            text = str(line.get("text", "") or "")
            if not _is_call_text(text):
                continue
            target = _extract_jump_target(text)
            if not target:
                continue
            source = str(line.get("addr", "") or "")
            if not source:
                continue
            source = source if source.startswith("0x") else f"0x{source}"
            edge_key = (source, target)
            if edge_key in seen_direct_calls:
                continue
            seen_direct_calls.add(edge_key)
            call_edges.append(edge_key)

    def get_call_instr_addr(block_addr: str) -> str | None:
        """Adresse de l'instruction call au sein du bloc (dernière instruction)."""
        blk = block_map.get(block_addr)
        if not blk or not blk.get("lines"):
            return None
        for ln in reversed(blk["lines"]):
            if _is_call_text(ln.get("text", "")):
                return ln.get("addr")
        return None

    sym_by_addr = {}
    sym_addrs = []
    for s in symbols:
        addr = s.get("addr", "")
        name = s.get("name", "")
        if addr and name:
            addr_str = addr if isinstance(addr, str) else hex(addr)
            if not addr_str.startswith("0x"):
                addr_str = "0x" + addr_str
            a = addr_to_int(addr_str)
            sym_by_addr[a] = name
            sym_addrs.append(a)
    sym_addrs.sort()

    def addr_to_name(addr: str) -> str:
        a = addr_to_int(addr)
        if a in sym_by_addr:
            return sym_by_addr[a]
        return addr

    def call_target_name(from_block_addr: str, to_addr: str) -> str:
        """Nom de la cible d'appel : PLT map > symbole dynamique > symboles statiques."""
        # 1. PLT map (résolution directe depuis le binaire)
        if to_addr in plt_map:
            return plt_map[to_addr]
        # 2. Symbole dynamique extrait du texte de l'instruction (<puts@plt>)
        call_addr = get_call_instr_addr(from_block_addr) or from_block_addr
        a = addr_to_int(call_addr)
        if a in line_by_addr:
            sym = _extract_symbol_from_operand(line_by_addr[a])
            if sym:
                return sym
        # 3. Symboles statiques (symboles ELF/Mach-O)
        return addr_to_name(to_addr)

    GENERIC_SYMBOLS = frozenset(
        {"__mh_execute_header", "__mh_dylib_header", "__mh_bundle_header"}
    )

    def find_caller(addr: str) -> str:
        a = addr_to_int(addr)
        best = None
        for s in sym_addrs:
            if s <= a:
                best = sym_by_addr[s]
            else:
                break
        name = best or addr
        if name in GENERIC_SYMBOLS:
            return addr
        return name

    nodes_set = set()
    edges_out = []
    for fr, to in call_edges:
        from_name = find_caller(fr)
        to_name = call_target_name(fr, to)
        nodes_set.add((fr, from_name))
        nodes_set.add((to, to_name))
        edges_out.append(
            {
                "from": fr,
                "to": to,
                "from_name": from_name,
                "to_name": to_name,
            }
        )

    nodes = [
        {
            "addr": a,
            "name": n,
            "is_external": ("@plt" in n or "@stub" in n or a in plt_map),
        }
        for a, n in sorted(nodes_set, key=lambda x: addr_to_int(x[0]))
    ]
    return {"nodes": nodes, "edges": edges_out}


def _load_symbols_from_arg(symbols_arg: str | None) -> list[dict]:
    if not symbols_arg:
        return []
    if symbols_arg == "-":
        symbols = json.load(sys.stdin)
    else:
        with open(symbols_arg, encoding="utf-8") as f:
            symbols = json.load(f)
    if not isinstance(symbols, list):
        symbols = symbols.get("symbols", symbols) if isinstance(symbols, dict) else []
    return symbols


def _load_cached_analysis(
    binary_path: str,
    lines: list[dict],
    cache_db: str | None = None,
    arch_hint: str | None = None,
) -> tuple[dict | None, list[dict] | None]:
    from backends.static.binary.symbols import extract_symbols
    from backends.static.cache.cache import DisasmCache, default_cache_path

    cache_path = cache_db or default_cache_path(binary_path)
    with DisasmCache(cache_path) as cache:
        cfg = cache.get_cfg(binary_path)
        symbols = cache.get_symbols(binary_path)

        if cfg is None and lines:
            cfg = build_cfg(lines, binary_path=binary_path, arch_hint=arch_hint)
            if os.path.exists(binary_path):
                cache.save_cfg(binary_path, cfg)

        if symbols is None and os.path.exists(binary_path):
            symbols = extract_symbols(binary_path)
            if symbols:
                cache.save_symbols(binary_path, symbols)

    return cfg, symbols


def main() -> int:
    """Point d'entrée CLI : construit le graphe d'appels à partir du CFG et des symboles."""
    parser = argparse.ArgumentParser(
        description="Build call graph from CFG and symbols"
    )
    parser.add_argument("--mapping", required=True, help="Path to disasm mapping JSON")
    parser.add_argument("--symbols", help="Path to symbols JSON or '-' for stdin")
    parser.add_argument("--binary", help="Binary path for cache/PLT resolution")
    parser.add_argument(
        "--cache-db",
        help="SQLite cache path (.pfdb). Defaults to the binary cache path.",
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    if not os.path.exists(args.mapping):
        logger.error("Mapping file not found: %s", args.mapping)
        return 1

    with open(args.mapping, encoding="utf-8") as f:
        data = json.load(f)
    lines = data.get("lines", [])
    binary_path = args.binary or data.get("binary")
    arch_hint = data.get("raw", {}).get("arch")
    cfg = None
    cached_symbols = None
    if binary_path:
        cfg, cached_symbols = _load_cached_analysis(
            binary_path,
            lines,
            cache_db=args.cache_db,
            arch_hint=arch_hint,
        )

    if cfg is None:
        cfg = build_cfg(lines, binary_path=binary_path, arch_hint=arch_hint)

    symbols = (
        _load_symbols_from_arg(args.symbols) if args.symbols else (cached_symbols or [])
    )

    call_graph = build_call_graph(cfg, symbols, lines=lines, binary_path=binary_path)
    out = json.dumps(call_graph, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Call graph written to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
