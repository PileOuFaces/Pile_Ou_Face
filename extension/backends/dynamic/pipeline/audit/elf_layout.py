# SPDX-License-Identifier: AGPL-3.0-only
"""ELF layout audit generation for Run Trace."""

from __future__ import annotations

import warnings
import os
from typing import Optional

from backends.dynamic.core.interfaces import TraceConfigLike

from .asm_analysis import (
    audit_plt_symbols,
    safe_hex,
    safe_int,
    stack_relevant_instructions,
)
from .evidence import build_inferred_frame_audit

try:
    from backends.dynamic.engine.unicorn.elf import parse_elf_header, parse_program_headers
except Exception:
    parse_elf_header = None
    parse_program_headers = None


IMPORTANT_ELF_SECTIONS = (
    ".text",
    ".plt",
    ".plt.got",
    ".got",
    ".got.plt",
    ".rodata",
    ".data",
    ".bss",
    ".symtab",
    ".dynsym",
    ".strtab",
    ".dynstr",
    ".rela.plt",
    ".rela.dyn",
    ".eh_frame",
)


def _normalize_path(path: str) -> str:
    cwd = os.getcwd()
    if path.startswith(cwd + os.sep):
        return os.path.relpath(path, cwd)
    return path


def _enum_name(value) -> str:
    name = getattr(value, "name", None)
    if name:
        return str(name)
    return str(value)


def _safe_attr(obj, name: str, default=None):
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", RuntimeWarning)
            return getattr(obj, name, default)
    except Exception:
        return default


def _segment_permissions(flags: int) -> str:
    return "".join(
        (
            "r" if flags & 4 else "-",
            "w" if flags & 2 else "-",
            "x" if flags & 1 else "-",
        )
    )


def _mapped_segments_from_program_headers(
    program_headers: list[dict],
    load_base: int = 0,
    page_size: int = 0x1000,
) -> list[dict]:
    mapped = []
    for index, ph in enumerate(program_headers):
        if ph.get("type") != 1:
            continue
        vaddr = safe_int(ph.get("vaddr"))
        memsz = safe_int(ph.get("memsz")) or 0
        flags = safe_int(ph.get("flags")) or 0
        if vaddr is None:
            continue
        map_start = vaddr & ~(page_size - 1)
        map_end = ((vaddr + memsz + page_size - 1) // page_size) * page_size
        runtime_vaddr = load_base + vaddr
        runtime_map_start = load_base + map_start
        runtime_map_end = load_base + map_end
        mapped.append(
            {
                "index": index,
                "type": "PT_LOAD",
                "vaddr": hex(vaddr),
                "end": hex(vaddr + memsz),
                "map_start": hex(map_start),
                "map_end": hex(map_end),
                "runtime_vaddr": hex(runtime_vaddr),
                "runtime_end": hex(runtime_vaddr + memsz),
                "runtime_map_start": hex(runtime_map_start),
                "runtime_map_end": hex(runtime_map_end),
                "offset": safe_hex(ph.get("offset")),
                "filesz": safe_int(ph.get("filesz")),
                "memsz": memsz,
                "flags": flags,
                "permissions": _segment_permissions(flags),
                "alignment": safe_int(ph.get("align")),
            }
        )
    return mapped


def _section_payload(section) -> dict:
    flags = []
    try:
        flags = [_enum_name(flag) for flag in _safe_attr(section, "flags_list", [])]
    except Exception:
        raw_flags = _safe_attr(section, "flags", None)
        if raw_flags is not None:
            flags = [str(raw_flags)]
    return {
        "name": str(_safe_attr(section, "name", "") or ""),
        "type": _enum_name(_safe_attr(section, "type", "")),
        "virtual_address": safe_hex(_safe_attr(section, "virtual_address", None)),
        "offset": safe_hex(_safe_attr(section, "offset", None)),
        "size": safe_int(_safe_attr(section, "size", None)),
        "entry_size": safe_int(_safe_attr(section, "entry_size", None)),
        "alignment": safe_int(_safe_attr(section, "alignment", None)),
        "flags": flags,
    }


def _symbol_payload(symbol, table: str) -> dict:
    return {
        "name": str(_safe_attr(symbol, "name", "") or ""),
        "value": safe_hex(_safe_attr(symbol, "value", None)),
        "size": safe_int(_safe_attr(symbol, "size", None)),
        "type": _enum_name(_safe_attr(symbol, "type", "")),
        "binding": _enum_name(_safe_attr(symbol, "binding", "")),
        "visibility": _enum_name(_safe_attr(symbol, "visibility", "")),
        "shndx": safe_int(_safe_attr(symbol, "shndx", None)),
        "table": table,
    }


def _relocation_payload(relocation) -> dict:
    symbol = _safe_attr(relocation, "symbol", None)
    section = _safe_attr(relocation, "section", None)
    return {
        "address": safe_hex(_safe_attr(relocation, "address", None)),
        "type": _enum_name(_safe_attr(relocation, "type", "")),
        "addend": safe_int(_safe_attr(relocation, "addend", None)),
        "size": safe_int(_safe_attr(relocation, "size", None)),
        "symbol": str(_safe_attr(symbol, "name", "") or "") if symbol is not None else None,
        "section": str(_safe_attr(section, "name", "") or "") if section is not None else None,
    }


def _lief_elf_layout(binary_path: str) -> dict:
    layout = {
        "section_headers": [],
        "important_sections": {name: None for name in IMPORTANT_ELF_SECTIONS},
        "debug_sections": [],
        "symbols": [],
        "imports": None,
        "exports": None,
        "relocations": [],
        "errors": [],
    }
    try:
        import lief
    except Exception as exc:
        layout["errors"].append({"stage": "lief_import", "message": str(exc)})
        return layout
    try:
        binary = lief.parse(binary_path)
    except Exception as exc:
        layout["errors"].append({"stage": "lief_parse", "message": str(exc)})
        return layout
    if binary is None:
        layout["errors"].append({"stage": "lief_parse", "message": "lief returned null"})
        return layout
    if not isinstance(binary, lief.ELF.Binary):
        layout["errors"].append({"stage": "format", "message": "not an ELF binary"})
        return layout

    sections_by_name = {}
    for section in binary.sections:
        payload = _section_payload(section)
        layout["section_headers"].append(payload)
        name = payload["name"]
        if name:
            sections_by_name.setdefault(name, payload)
        if name.startswith(".debug_") or name == ".debug":
            layout["debug_sections"].append(payload)
    for name in IMPORTANT_ELF_SECTIONS:
        layout["important_sections"][name] = sections_by_name.get(name)

    for symbol in _safe_attr(binary, "symtab_symbols", []) or []:
        layout["symbols"].append(_symbol_payload(symbol, ".symtab"))
    for symbol in _safe_attr(binary, "dynamic_symbols", []) or []:
        layout["symbols"].append(_symbol_payload(symbol, ".dynsym"))
    layout["imports"] = [
        symbol
        for symbol in layout["symbols"]
        if symbol.get("name") and safe_int(symbol.get("shndx")) == 0
    ]
    layout["exports"] = [
        symbol
        for symbol in layout["symbols"]
        if symbol.get("name")
        and safe_int(symbol.get("shndx")) not in {None, 0}
        and symbol.get("value") not in {None, "0x0"}
        and str(symbol.get("binding") or "").upper().endswith(("GLOBAL", "WEAK"))
    ]

    relocation_sets = []
    for attr in ("relocations", "dynamic_relocations", "pltgot_relocations"):
        try:
            relocation_sets.extend(list(getattr(binary, attr, []) or []))
        except Exception as exc:
            layout["errors"].append({"stage": f"relocations.{attr}", "message": str(exc)})
    seen_relocations = set()
    for relocation in relocation_sets:
        payload = _relocation_payload(relocation)
        key = (payload.get("address"), payload.get("type"), payload.get("symbol"))
        if key in seen_relocations:
            continue
        seen_relocations.add(key)
        layout["relocations"].append(payload)

    return layout


def build_elf_layout_audit(
    binary_path: str,
    code: bytes,
    config: TraceConfigLike,
    trace: dict,
    disassembly: Optional[list[dict]],
    functions: list[dict],
) -> dict:
    trace_meta = trace.get("meta", {}) if isinstance(trace, dict) else {}
    runtime_base = safe_int(trace_meta.get("base")) or 0
    audit = {
        "binary": _normalize_path(binary_path),
        "elf_header": None,
        "program_headers": [],
        "section_headers": [],
        "mapped_segments": [],
        "important_sections": {name: None for name in IMPORTANT_ELF_SECTIONS},
        "debug_sections": [],
        "symbols": [],
        "imports": None,
        "exports": None,
        "relocations": [],
        "functions": [],
        "disassembly": disassembly or [],
        "external_call_targets": {},
        "stack_relevant_instructions": [],
        "inferred_frame": {
            "frame_size": 0,
            "rbp_based_accesses": [],
            "rsp_based_accesses": [],
            "probable_stack_slots": [],
            "confidence": 0.0,
            "evidence": [],
        },
        "errors": [],
    }
    if not code.startswith(b"\x7fELF"):
        audit["errors"].append({"stage": "format", "message": "not an ELF binary"})
        return audit
    if parse_elf_header is not None and parse_program_headers is not None:
        try:
            header = parse_elf_header(code)
            audit["elf_header"] = {
                **header,
                "entry_hex": safe_hex(header.get("entry")),
                "phoff_hex": safe_hex(header.get("phoff")),
            }
            audit["program_headers"] = parse_program_headers(code, header)
            audit["mapped_segments"] = _mapped_segments_from_program_headers(
                audit["program_headers"],
                load_base=runtime_base,
            )
        except Exception as exc:
            audit["errors"].append({"stage": "elf_header_program_headers", "message": str(exc)})
    else:
        audit["errors"].append({"stage": "elf_header_program_headers", "message": "ELF parser unavailable"})

    layout = _lief_elf_layout(binary_path)
    for key in (
        "section_headers",
        "important_sections",
        "debug_sections",
        "symbols",
        "imports",
        "exports",
        "relocations",
    ):
        audit[key] = layout.get(key)
    audit["errors"].extend(layout.get("errors", []))

    audit["functions"] = functions
    plt_symbols = audit_plt_symbols(binary_path)
    audit["external_call_targets"] = {hex(addr): name for addr, name in sorted(plt_symbols.items())}
    audit["stack_relevant_instructions"] = stack_relevant_instructions(
        audit["disassembly"],
        audit["functions"],
        plt_symbols,
    )
    audit["inferred_frame"] = build_inferred_frame_audit(
        binary_path,
        audit["functions"],
        audit["stack_relevant_instructions"],
        getattr(config, "start_symbol", None),
    )
    audit["trace_meta_context"] = {
        "base": trace_meta.get("base"),
        "arch_bits": trace_meta.get("arch_bits"),
        "elf_entry": trace_meta.get("elf_entry"),
        "elf_pie": trace_meta.get("elf_pie"),
        "elf_interp": trace_meta.get("elf_interp"),
        "start_symbol": trace_meta.get("start_symbol"),
        "stop_symbol": trace_meta.get("stop_symbol"),
    }
    return audit
