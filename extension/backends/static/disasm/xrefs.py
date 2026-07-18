# SPDX-License-Identifier: AGPL-3.0-only
"""Cross-références : qui référence une adresse donnée (jmp, call, load, lea, etc.)."""

from __future__ import annotations

import os
import re

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import normalize_addr as _normalize_addr
from backends.shared.utils import parse_addr as _addr_to_int
from backends.static.annotations.typed_struct_refs import (
    build_typed_struct_index,
    collect_typed_struct_hints,
)
from backends.static.binary.arch import (
    ArchAdapter,
    detect_binary_arch_from_path,
    iter_supported_adapters,
)
from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm.cfg import _extract_jump_target, _get_mnemonic

logger = get_logger(__name__)


def _candidate_adapters(binary_path: str | None = None) -> tuple[ArchAdapter, ...]:
    info = detect_binary_arch_from_path(binary_path) if binary_path else None
    if info is not None:
        return (info.adapter,)
    return tuple(iter_supported_adapters())


def _classify_code_ref_mnemonic(
    mnem: str, adapters: tuple[ArchAdapter, ...]
) -> str | None:
    for adapter in adapters:
        kind = adapter.classify_code_ref_mnemonic(mnem)
        if kind:
            return kind
    return None


def _supports_data_ref_mnemonic(mnem: str, adapters: tuple[ArchAdapter, ...]) -> bool:
    return any(adapter.supports_data_ref_mnemonic(mnem) for adapter in adapters)


def _parse_int_literal(text: str | None) -> int | None:
    if text is None:
        return None
    raw = str(text).strip().lower().replace(" ", "")
    if not raw:
        return None
    sign = -1 if raw.startswith("-") else 1
    normalized = raw.lstrip("+-")
    try:
        if normalized.startswith("0x"):
            return sign * int(normalized, 16)
        return sign * int(normalized, 10)
    except ValueError:
        return None


def _normalize_for_match(text: str) -> str:
    return re.sub(r"\s+", "", text.lower())


_ARM_MEMORY_BASE_ALIASES: dict[str, str] = {
    "fp": "r11",
    "$fp": "r11",
    "$sp": "sp",
    "s0": "r11",
    "s8": "r11",
    "i6": "r11",
    "o6": "sp",
    "r1": "sp",
    "r15": "sp",
    "a10": "sp",
}


def _canonicalize_memory_location(text: str) -> str:
    source = str(text or "")
    match = re.search(r"\[([^\]]+)\]", source)
    if match:
        inner = re.sub(r"\s+", "", match.group(1).strip().lower())
    else:
        offset_base = re.search(
            r"([-+]?(?:0x[0-9a-fA-F]+|\d+))\s*\(\s*([%$\w]+)\s*\)",
            source,
        )
        if not offset_base:
            return ""
        inner = f"{offset_base.group(2)}+{offset_base.group(1)}"
    inner = inner.replace("%", "").replace("$", "")
    if not inner:
        return ""

    arm_match = re.fullmatch(r"([a-z0-9]+)(?:,#?([-+]?(?:0x[0-9a-f]+|\d+)))?", inner)
    if arm_match:
        base = _ARM_MEMORY_BASE_ALIASES.get(arm_match.group(1), arm_match.group(1))
        offset_text = arm_match.group(2)
        if not offset_text:
            return f"[{base}]"
        try:
            offset = (
                int(offset_text, 16) if "0x" in offset_text else int(offset_text, 10)
            )
        except ValueError:
            return ""
        if offset == 0:
            return f"[{base}]"
        sign = "+" if offset > 0 else "-"
        return f"[{base}{sign}0x{abs(offset):x}]"

    x86_match = re.fullmatch(r"([a-z0-9]+)(?:([+-])(0x[0-9a-f]+|\d+))?", inner)
    if x86_match:
        base = _ARM_MEMORY_BASE_ALIASES.get(x86_match.group(1), x86_match.group(1))
        sign = x86_match.group(2)
        offset_text = x86_match.group(3)
        if not sign or not offset_text:
            return f"[{base}]"
        try:
            offset = (
                int(offset_text, 16)
                if offset_text.startswith("0x")
                else int(offset_text, 10)
            )
        except ValueError:
            return ""
        if sign == "-":
            offset = -offset
        if offset == 0:
            return f"[{base}]"
        sign = "+" if offset > 0 else "-"
        return f"[{base}{sign}0x{abs(offset):x}]"
    return ""


def _extract_canonical_memory_locations(text: str) -> set[str]:
    canonical: set[str] = set()
    for match in re.finditer(r"\[[^\]]+\]", str(text or "")):
        value = _canonicalize_memory_location(match.group(0))
        if value:
            canonical.add(value)
    for match in re.finditer(
        r"[-+]?(?:0x[0-9a-fA-F]+|\d+)\s*\(\s*[%$\w]+\s*\)", str(text or "")
    ):
        value = _canonicalize_memory_location(match.group(0))
        if value:
            canonical.add(value)
    return canonical


def _build_function_ranges(functions: list[dict]) -> list[tuple[int, int | None, dict]]:
    starts = []
    for fn in functions:
        start = _addr_to_int(fn.get("addr"))
        if start is None:
            continue
        starts.append((start, fn))
    starts.sort(key=lambda item: item[0])

    ranges = []
    for idx, (start, fn) in enumerate(starts):
        next_start = starts[idx + 1][0] if idx + 1 < len(starts) else None
        size = _addr_to_int(fn.get("size"))
        end = start + size if size and size > 0 else None
        if next_start is not None:
            end = min(end, next_start) if end is not None else next_start
        ranges.append((start, end, fn))
    return ranges


def _find_function_for_addr(
    function_ranges: list[tuple[int, int | None, dict]], addr: str
) -> dict | None:
    target = _addr_to_int(addr)
    if target is None:
        return None
    for start, end, fn in function_ranges:
        if target < start:
            break
        if end is None or target < end:
            return fn
    return None


def _annotation_name_map(entries: list[dict]) -> dict[str, str]:
    result: dict[str, str] = {}
    for entry in entries:
        if entry.get("kind") != "rename":
            continue
        addr = _normalize_addr(entry.get("addr", ""))
        value = str(entry.get("value") or "").strip()
        if addr and value:
            result[addr] = value
    return result


def _symbol_name_map(symbols: list[dict]) -> dict[str, str]:
    result: dict[str, str] = {}
    for symbol in symbols:
        addr = _normalize_addr(symbol.get("addr", ""))
        name = str(symbol.get("name") or "").strip()
        if addr and name:
            result[addr] = name
    return result


def _resolve_function_name(
    fn: dict, rename_map: dict[str, str], symbol_map: dict[str, str]
) -> str:
    addr = _normalize_addr(fn.get("addr", ""))
    return (
        rename_map.get(addr)
        or str(fn.get("name") or "").strip()
        or symbol_map.get(addr)
        or addr
    )


_REGISTER_LOCATION_ALIASES: dict[str, tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
}


def _location_aliases(location: str) -> tuple[str, ...]:
    normalized = str(location or "").strip().lower()
    if not normalized:
        return ()
    if normalized.startswith("["):
        return (normalized,)
    if normalized in _REGISTER_LOCATION_ALIASES:
        return _REGISTER_LOCATION_ALIASES[normalized]
    if re.fullmatch(r"x\d+", normalized):
        return (normalized, f"w{normalized[1:]}")
    if re.fullmatch(r"w\d+", normalized):
        return (f"x{normalized[1:]}", normalized)
    return (normalized,)


def _location_matches_text(location: str, text: str) -> bool:
    if not location or not text:
        return False
    if location.startswith("["):
        canonical_location = _canonicalize_memory_location(location)
        if canonical_location:
            return canonical_location in _extract_canonical_memory_locations(text)
        return _normalize_for_match(location) in _normalize_for_match(text)
    aliases = _location_aliases(location)
    if not aliases:
        return False
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(alias) for alias in aliases) + r")\b",
        re.IGNORECASE,
    )
    return bool(pattern.search(text))


def _extract_stack_hints(text: str, frame: dict | None) -> list[dict]:
    if not frame:
        return []
    hints: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for kind in ("args", "vars"):
        entry_kind = "arg" if kind == "args" else "var"
        for entry in frame.get(kind, []) or []:
            location = str(entry.get("location") or "").strip()
            name = str(entry.get("name") or "").strip()
            if not location or not name:
                continue
            if not _location_matches_text(location, text):
                continue
            key = (entry_kind, location, name)
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                {
                    "kind": entry_kind,
                    "location": location,
                    "name": name,
                    "source": str(entry.get("source") or ""),
                }
            )
    return hints


def _load_stack_frame(
    cache: DisasmCache, binary_path: str, func_addr: str
) -> dict | None:
    frame = cache.get_stack_frame(binary_path, func_addr)
    if frame is not None:
        return frame
    try:
        from backends.static.disasm.stack_frame import analyse_stack_frame

        func_int = _addr_to_int(func_addr)
        if func_int is None:
            return None
        return analyse_stack_frame(binary_path, func_int)
    except Exception:
        return None


def _enrich_refs_with_function_context(
    refs: list[dict],
    functions: list[dict] | None,
    rename_map: dict[str, str] | None = None,
    symbol_map: dict[str, str] | None = None,
) -> list[dict]:
    if not refs or not functions:
        return refs
    function_ranges = _build_function_ranges(functions)
    rename_map = rename_map or {}
    symbol_map = symbol_map or {}
    enriched = []
    for ref in refs:
        entry = dict(ref)
        source_addr = entry.get("from_addr") or entry.get("addr") or ""
        fn = _find_function_for_addr(function_ranges, source_addr)
        if fn:
            func_addr = _normalize_addr(fn.get("addr", ""))
            if func_addr:
                entry["function_addr"] = func_addr
                entry["function_name"] = _resolve_function_name(
                    fn, rename_map, symbol_map
                )
        enriched.append(entry)
    return enriched


def _enrich_refs_with_binary_context(
    refs: list[dict],
    binary_path: str | None,
    functions: list[dict] | None = None,
) -> list[dict]:
    if not refs:
        return refs
    if not binary_path or not os.path.exists(binary_path):
        return _enrich_refs_with_function_context(refs, functions)
    try:
        with DisasmCache(default_cache_path(binary_path)) as cache:
            functions = functions or cache.get_functions(binary_path) or []
            symbols = cache.get_symbols(binary_path) or []
            annotations = cache.get_annotations(binary_path) or []
            function_ranges = _build_function_ranges(functions)
            rename_map = _annotation_name_map(annotations)
            symbol_map = _symbol_name_map(symbols)
            frame_cache: dict[str, dict | None] = {}
            typed_struct_index = build_typed_struct_index(binary_path)
            enriched = []
            for ref in refs:
                entry = dict(ref)
                source_addr = entry.get("from_addr") or entry.get("addr") or ""
                fn = _find_function_for_addr(function_ranges, source_addr)
                if fn:
                    func_addr = _normalize_addr(fn.get("addr", ""))
                    if func_addr:
                        entry["function_addr"] = func_addr
                        entry["function_name"] = _resolve_function_name(
                            fn, rename_map, symbol_map
                        )
                        if func_addr not in frame_cache:
                            frame_cache[func_addr] = _load_stack_frame(
                                cache, binary_path, func_addr
                            )
                        stack_hints = _extract_stack_hints(
                            entry.get("text", ""), frame_cache.get(func_addr)
                        )
                        if stack_hints:
                            entry["stack_hints"] = stack_hints
                typed_struct_hints = collect_typed_struct_hints(
                    typed_struct_index,
                    _extract_addresses_from_text(entry.get("text", ""))
                    + [
                        entry.get("to_addr")
                        or entry.get("target_addr")
                        or entry.get("addr")
                        or ""
                    ],
                )
                if typed_struct_hints:
                    entry["typed_struct_hints"] = typed_struct_hints
                enriched.append(entry)
            return enriched
    except Exception:
        return _enrich_refs_with_function_context(refs, functions)


def _describe_source_context(
    lines: list[dict],
    from_addr: str,
    binary_path: str | None = None,
    functions: list[dict] | None = None,
) -> dict | None:
    from_a = _normalize_addr(from_addr)
    line = next(
        (item for item in lines if _normalize_addr(item.get("addr", "")) == from_a),
        None,
    )
    if line is None:
        return None
    context = {
        "addr": from_a,
        "text": line.get("text", ""),
        "line": line.get("line"),
    }
    enriched = _enrich_refs_with_binary_context(
        [context], binary_path, functions=functions
    )
    return enriched[0] if enriched else context


def _extract_addresses_from_text(text: str) -> list[str]:
    """Extrait toutes les adresses hex (0x...) d'une instruction."""
    matches = re.findall(r"0x([0-9a-fA-F]+)", text, re.IGNORECASE)
    return [_normalize_addr("0x" + m.lower()) for m in matches]


def _instruction_size(line: dict) -> int | None:
    raw_bytes = str(line.get("bytes") or "").strip()
    if raw_bytes:
        byte_tokens = [
            token
            for token in raw_bytes.split()
            if re.fullmatch(r"[0-9a-fA-F]{2}", token)
        ]
        if byte_tokens:
            return len(byte_tokens)

    text = str(line.get("text") or "")
    prefix = []
    for token in text.split():
        if re.fullmatch(r"[0-9a-fA-F]{2}", token):
            prefix.append(token)
            continue
        break
    if prefix:
        return len(prefix)
    return None


def _extract_pc_relative_addresses(line: dict) -> list[str]:
    operands = str(line.get("operands") or "").strip()
    text = operands or str(line.get("text") or "")
    current_addr = _addr_to_int(line.get("addr"))
    instr_size = _instruction_size(line)
    if current_addr is None or instr_size is None:
        return []

    refs: list[str] = []
    seen: set[str] = set()
    for match in re.finditer(
        r"\[(?:%|\$)?(?:rip|eip)\s*([+-]\s*(?:0x[0-9a-fA-F]+|\d+))?\]",
        text,
        re.IGNORECASE,
    ):
        offset = _parse_int_literal(match.group(1) or "0")
        if offset is None:
            continue
        target = _normalize_addr(hex(current_addr + instr_size + offset))
        if target in seen:
            continue
        seen.add(target)
        refs.append(target)
    return refs


def _extract_data_target_addresses(line: dict) -> list[str]:
    targets: list[str] = []
    seen: set[str] = set()
    for addr in _extract_addresses_from_text(str(line.get("text", "") or "")):
        if addr in seen:
            continue
        seen.add(addr)
        targets.append(addr)
    for addr in _extract_pc_relative_addresses(line):
        if addr in seen:
            continue
        seen.add(addr)
        targets.append(addr)
    return targets


def _has_memory_operand(text: str) -> bool:
    source = str(text or "")
    if "[" in source and "]" in source:
        return True
    return bool(re.search(r"[-+]?(?:0x[0-9a-fA-F]+|\d+)\s*\(\s*[%$\w]+\s*\)", source))


def _is_store_ref(text: str) -> bool:
    """Détecte si un accès mémoire est une écriture (store).

    Pour `mov [addr], src`, la première opérande est en mémoire (store).
    Pour `mov dst, [addr]`, la deuxième opérande est en mémoire (load).
    """
    parts = text.split(",", 1)
    first_op = parts[0] if parts else ""
    return "[" in first_op


def _classify_data_ref(mnem: str, text: str) -> str:
    """Retourne le type de ref données : 'lea', 'store', ou 'load'."""
    if mnem in {"lea", "adr", "adrp"}:
        return "lea"
    if mnem in {
        "str",
        "stur",
        "stp",
        "stm",
        "sw",
        "sd",
        "sb",
        "sh",
        "stw",
        "std",
        "st",
        "store",
    } or mnem.startswith("st."):
        return "store"
    if mnem in {
        "ldr",
        "ldrb",
        "ldrh",
        "ldrsw",
        "ldur",
        "ldp",
        "lw",
        "lwu",
        "lb",
        "lbu",
        "lh",
        "lhu",
        "ld",
        "ldw",
        "ldwu",
        "load",
    } or mnem.startswith("ld."):
        return "load"
    if _is_store_ref(text):
        return "store"
    return "load"


def extract_xrefs(
    lines: list[dict],
    target_addr: str,
    include_data: bool = True,
    binary_path: str | None = None,
    functions: list[dict] | None = None,
) -> list[dict]:
    """Extrait les références vers target_addr dans les lignes de désassemblage.

    Args:
        lines: Lignes de désassemblage
        target_addr: Adresse cible
        include_data: Inclure les xrefs données (mov, lea, cmp, etc.)

    Returns:
        [{"from_addr", "from_line", "text", "type": "jmp"|"call"|"jcc"|"load"|"store"|"lea"}, ...]
    """
    target = _normalize_addr(target_addr)
    refs = []
    adapters = _candidate_adapters(binary_path)

    for line in lines:
        addr = _normalize_addr(line.get("addr", ""))
        text = line.get("text", "")
        mnem = _get_mnemonic(text)

        # Code refs (jmp, call)
        ref_kind = _classify_code_ref_mnemonic(mnem, adapters)
        if ref_kind in {"jmp", "jcc", "call"}:
            t = _extract_jump_target(text)
            if t and t == target:
                refs.append(
                    {
                        "from_addr": addr,
                        "from_line": line.get("line"),
                        "text": text,
                        "type": ref_kind,
                    }
                )
            continue

        # Data refs (load, store, lea) : opérande mémoire [addr]
        if (
            include_data
            and _supports_data_ref_mnemonic(mnem, adapters)
            and _has_memory_operand(text)
        ):
            for a in _extract_data_target_addresses(line):
                if a == target:
                    refs.append(
                        {
                            "from_addr": addr,
                            "from_line": line.get("line"),
                            "text": text,
                            "type": _classify_data_ref(mnem, text),
                        }
                    )
                    break

    return _enrich_refs_with_binary_context(refs, binary_path, functions=functions)


def build_xref_map(
    lines: list[dict],
    include_data: bool = True,
    binary_path: str | None = None,
) -> dict:
    """Construit la carte complète des xrefs pour toutes les adresses référencées.

    Args:
        lines: Lignes de désassemblage
        include_data: Inclure les xrefs données (mov, lea, etc.)
        binary_path: Chemin du binaire. Réservé aux enrichissements binaires futurs.

    Returns:
        {target_addr: [{"from_addr", "from_line", "text", "type"}, ...], ...}
    """
    xref_map: dict = {}
    adapters = _candidate_adapters(binary_path)

    for line in lines:
        addr = _normalize_addr(line.get("addr", ""))
        text = line.get("text", "")
        mnem = _get_mnemonic(text)
        line_num = line.get("line")

        # Code refs
        ref_kind = _classify_code_ref_mnemonic(mnem, adapters)
        if ref_kind in {"jmp", "jcc", "call"}:
            t = _extract_jump_target(text)
            if t:
                xref_map.setdefault(t, []).append(
                    {
                        "from_addr": addr,
                        "from_line": line_num,
                        "text": text,
                        "type": ref_kind,
                        "type_info": None,  # Sera enrichi par dwarf.py si disponible
                    }
                )
            continue

        # Data refs
        if (
            include_data
            and _supports_data_ref_mnemonic(mnem, adapters)
            and _has_memory_operand(text)
        ):
            ref_type = _classify_data_ref(mnem, text)
            for a in _extract_data_target_addresses(line):
                xref_map.setdefault(a, []).append(
                    {
                        "from_addr": addr,
                        "from_line": line_num,
                        "text": text,
                        "type": ref_type,
                        "type_info": None,  # Sera enrichi par dwarf.py si disponible
                    }
                )

    return xref_map


def extract_xrefs_from_addr(lines: list[dict], from_addr: str) -> list[str]:
    """Pour une instruction à from_addr, retourne les adresses qu'elle référence (cibles).

    Inclut les cibles de jmp/call ET les adresses dans les opérandes données (mov, lea, etc.).
    """
    from_a = _normalize_addr(from_addr)
    for line in lines:
        if _normalize_addr(line.get("addr", "")) == from_a:
            text = line.get("text", "")
            mnem = _get_mnemonic(text)
            # Code target (jmp/call)
            t = _extract_jump_target(text)
            if t:
                return [t]
            # Data targets (mov, lea, etc.)
            if _supports_data_ref_mnemonic(
                mnem, tuple(iter_supported_adapters())
            ) and _has_memory_operand(text):
                return _extract_data_target_addresses(line)
    return []


def main() -> int:
    """Point d'entrée CLI : extrait les cross-références (mode to/from) pour une adresse."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract xrefs for an address")
    parser.add_argument("--mapping", required=True, help="Path to disasm mapping JSON")
    parser.add_argument(
        "--binary", help="Binary path for function/stack context enrichment"
    )
    parser.add_argument(
        "--functions",
        help="Functions JSON path for raw/function-only context enrichment",
    )
    parser.add_argument(
        "--addr", help="Target address (0xhex or hex) — required unless --mode=map"
    )
    parser.add_argument(
        "--mode",
        choices=["to", "from", "map"],
        default="to",
        help="'to': xrefs pointing to addr, 'from': targets from addr, 'map': full xref map",
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    if not os.path.exists(args.mapping):
        logger.error("Mapping file not found: %s", args.mapping)
        return 1

    # JSON allégé : les lignes vivent dans le SQLite associé.
    from backends.static.disasm.mapping_db import load_mapping_with_lines

    data = load_mapping_with_lines(args.mapping)
    lines = data.get("lines", [])
    binary_path = args.binary or data.get("binary")
    functions = []
    if args.functions and os.path.exists(args.functions):
        with open(args.functions, encoding="utf-8") as f:
            loaded = json.load(f)
        if isinstance(loaded, list):
            functions = loaded
        elif isinstance(loaded, dict):
            functions = loaded.get("functions", []) or []

    if args.mode == "map":
        xmap = build_xref_map(lines)
        out = {"mode": "map", "xref_map": xmap}
    elif not args.addr:
        logger.error("--addr is required unless --mode=map")
        return 1
    elif args.mode == "to":
        refs = extract_xrefs(
            lines, args.addr, binary_path=binary_path, functions=functions
        )
        out = {"addr": args.addr, "mode": "to", "refs": refs}
    else:
        targets = extract_xrefs_from_addr(lines, args.addr)
        out = {
            "addr": args.addr,
            "mode": "from",
            "targets": targets,
            "source": _describe_source_context(
                lines, args.addr, binary_path=binary_path, functions=functions
            ),
        }

    s = json.dumps(out, indent=2)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(s)
        print(f"Xrefs written to {args.output}")
    else:
        print(s)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
