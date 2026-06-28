"""Symbol adapter for the normalized binary metadata model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None

from backends.static.binary.symbols import extract_symbols


def _hex(value: Any) -> str:
    try:
        return f"0x{int(value):x}"
    except Exception:
        return "0x0"


def _enum_name(value: Any) -> str:
    name = getattr(value, "name", None)
    return str(name or value or "").strip()


def _symbol_kind(symbol_type: str) -> str:
    value = str(symbol_type or "").upper()
    if value in {"FUNC", "FUNCTION", "T", "TEXT"}:
        return "FUNC"
    if value in {"OBJECT", "D", "DATA", "B", "BSS"}:
        return "OBJECT"
    if value in {"SECTION"}:
        return "SECTION"
    if value in {"U", "UNDEFINED"}:
        return "UND"
    return "UNKNOWN"


def _elf_section_name(binary: Any, shndx: Any) -> str:
    try:
        idx = int(shndx)
    except Exception:
        return ""
    try:
        if idx > 0 and idx < len(binary.sections):
            return str(binary.sections[idx].name or "")
    except Exception:
        return ""
    return ""


def _from_lief(binary_path: str) -> list[dict[str, Any]]:
    if not lief:
        return []
    try:
        binary = lief.parse(binary_path)
    except Exception:
        return []
    if binary is None:
        return []

    records: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()

    def add_record(
        name: str,
        addr: Any,
        size: Any,
        kind: str,
        binding: str,
        section: str,
        source: str,
    ) -> None:
        clean_name = str(name or "").strip()
        if not clean_name:
            return
        addr_hex = _hex(addr)
        key = (clean_name, addr_hex, source)
        if key in seen:
            return
        seen.add(key)
        records.append(
            {
                "name": clean_name,
                "addr": addr_hex,
                "size": int(size) if isinstance(size, int) and size > 0 else None,
                "kind": _symbol_kind(kind),
                "binding": binding or "",
                "section": section or "",
                "source": source,
            }
        )

    try:
        if isinstance(binary, lief.ELF.Binary):
            for table_name, symbols in (
                ("symtab", binary.symtab_symbols),
                ("dynsym", binary.dynamic_symbols),
            ):
                for sym in symbols:
                    section = _elf_section_name(binary, getattr(sym, "shndx", 0))
                    add_record(
                        sym.name,
                        getattr(sym, "value", 0),
                        getattr(sym, "size", None),
                        _enum_name(getattr(sym, "type", "")),
                        _enum_name(getattr(sym, "binding", "")),
                        section,
                        f"LIEF/{table_name}",
                    )
        elif isinstance(binary, lief.MachO.Binary):
            for sym in binary.symbols:
                add_record(
                    sym.name,
                    getattr(sym, "value", 0),
                    getattr(sym, "size", None),
                    "FUNC",
                    "",
                    "",
                    "LIEF/symbols",
                )
        elif isinstance(binary, lief.PE.Binary):
            for func in getattr(binary, "exported_functions", []):
                add_record(
                    func.name,
                    getattr(func, "address", 0),
                    None,
                    "FUNC",
                    "GLOBAL",
                    "",
                    "LIEF/exports",
                )
            for func in getattr(binary, "imported_functions", []):
                add_record(
                    func.name,
                    getattr(func, "iat_address", 0),
                    None,
                    "UND",
                    "IMPORT",
                    "",
                    "LIEF/imports",
                )
    except Exception:
        return records

    return records


def _from_existing_helper(binary_path: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for sym in extract_symbols(binary_path, defined_only=False):
        records.append(
            {
                "name": str(sym.get("name") or ""),
                "addr": str(sym.get("addr") or "0x0"),
                "size": sym.get("size"),
                "kind": _symbol_kind(str(sym.get("type") or "")),
                "binding": "",
                "section": "",
                "source": sym.get("source") or "symbols.py",
            }
        )
    return records


def load_symbols(binary_path: str) -> list[dict[str, Any]]:
    """Return rich symbols, falling back to the existing symbols.py helper."""
    if not Path(binary_path).exists():
        return []
    records = _from_lief(binary_path)
    if not records:
        records = _from_existing_helper(binary_path)
    return sorted(
        records,
        key=lambda item: (
            int(str(item.get("addr") or "0x0"), 16),
            item.get("name") or "",
        ),
    )
