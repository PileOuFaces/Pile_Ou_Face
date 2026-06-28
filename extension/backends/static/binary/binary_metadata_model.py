"""Canonical aggregation layer for static binary metadata.

This module does not replace LIEF, Capstone, nm, objdump, or DWARF helpers. It
normalizes their existing outputs into one stable JSON shape for debug tooling.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backends.static.binary.adapters.dwarf_adapter import load_dwarf_functions
from backends.static.binary.adapters.function_ranges_adapter import (
    build_function_ranges,
)
from backends.static.binary.adapters.lief_adapter import (
    load_binary_facts,
    section_flags_by_name,
)
from backends.static.binary.adapters.plt_adapter import load_plt_entries
from backends.static.binary.adapters.symbols_adapter import load_symbols
from backends.static.binary.sections import extract_sections


def _hex(value: Any) -> str:
    try:
        if isinstance(value, str) and value.lower().startswith("0x"):
            return f"0x{int(value, 16):x}"
        return f"0x{int(value):x}"
    except Exception:
        return "0x0"


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except Exception:
        return None


def _normalize_section(section: dict[str, Any], flags: list[str]) -> dict[str, Any]:
    return {
        "name": str(section.get("name") or ""),
        "vaddr": _hex(
            section.get("vma")
            or section.get("vma_hex")
            or section.get("virtual_address")
            or 0
        ),
        "size": int(section.get("size") or 0),
        "offset": _hex(section.get("offset") or 0),
        "kind": str(section.get("type") or section.get("kind") or "UNKNOWN"),
        "flags": list(flags or []),
        "source": "LIEF",
    }


def _normalize_runtime(binary: dict[str, Any]) -> dict[str, Any]:
    return {
        "base": binary.get("base") or "0x0",
        "entry": binary.get("entry") or "0x0",
        "pie": bool(binary.get("pie")),
    }


def build_binary_metadata_model(binary_path: str) -> dict[str, Any]:
    """Build the normalized binary metadata model for one binary path."""
    path = Path(binary_path)
    diagnostics: list[dict[str, str]] = []
    binary = load_binary_facts(str(path))
    if not path.exists():
        diagnostics.append({"source": "filesystem", "message": "binary not found"})

    raw_sections = extract_sections(str(path)) if path.exists() else []
    flags = section_flags_by_name(str(path)) if path.exists() else {}
    sections = [
        _normalize_section(section, flags.get(str(section.get("name") or ""), []))
        for section in raw_sections
    ]
    sections.sort(key=lambda item: (int(item["vaddr"], 16), item["name"]))

    symbols = load_symbols(str(path)) if path.exists() else []
    symbols.sort(
        key=lambda item: (
            int(str(item.get("addr") or "0x0"), 16),
            str(item.get("name") or ""),
        )
    )

    dwarf_functions, dwarf_error = (
        load_dwarf_functions(str(path)) if path.exists() else ([], "binary not found")
    )
    if dwarf_error:
        diagnostics.append({"source": "DWARF", "message": dwarf_error})

    functions = build_function_ranges(symbols, dwarf_functions)
    plt = load_plt_entries(str(path)) if path.exists() else []

    bits = _int_or_none(binary.get("bits"))
    binary_model = {
        "path": str(path),
        "format": str(binary.get("format") or "UNKNOWN"),
        "arch": str(binary.get("arch") or ""),
        "bits": bits,
        "entry": binary.get("entry") or "0x0",
        "base": binary.get("base") or "0x0",
        "pie": bool(binary.get("pie")),
        "stripped": bool(binary.get("stripped")),
    }
    if binary.get("source") == "unavailable":
        diagnostics.append({"source": "LIEF", "message": "binary metadata unavailable"})

    return {
        "binary": binary_model,
        "sections": sections,
        "symbols": symbols,
        "functions": functions,
        "plt": plt,
        "runtime": _normalize_runtime(binary_model),
        "diagnostics": diagnostics,
    }


def dumps_binary_metadata(model: dict[str, Any]) -> str:
    """Serialize metadata deterministically for CLI/tests."""
    return json.dumps(model, indent=2, sort_keys=False) + "\n"


def emit_binary_metadata_json(binary_path: str) -> str:
    """Build and serialize the normalized binary metadata model."""
    return dumps_binary_metadata(build_binary_metadata_model(binary_path))
