"""DWARF adapter for the normalized binary metadata model."""

from __future__ import annotations

from typing import Any

from backends.static.binary.dwarf import extract_dwarf_info


def load_dwarf_functions(binary_path: str) -> tuple[list[dict[str, Any]], str | None]:
    """Return normalized DWARF function ranges and an optional diagnostic."""
    info = extract_dwarf_info(binary_path)
    error = info.get("error") if isinstance(info, dict) else "DWARF extraction failed"
    functions: list[dict[str, Any]] = []
    for fn in info.get("functions", []) if isinstance(info, dict) else []:
        name = str(fn.get("name") or "").strip()
        start = str(fn.get("low_pc") or "0x0")
        end = str(fn.get("high_pc") or "0x0")
        if not name or start in {"", "0x0"}:
            continue
        functions.append({
            "name": name,
            "start": start,
            "end": end,
            "source": "DWARF",
        })
    return functions, (str(error) if error else None)
