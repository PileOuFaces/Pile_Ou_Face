"""Function range inference for the normalized binary metadata model."""

from __future__ import annotations

from typing import Any


def _addr_int(value: Any) -> int | None:
    try:
        text = str(value or "").strip()
        if not text or text == "0x0":
            return None
        return int(text, 16) if text.lower().startswith("0x") else int(text)
    except Exception:
        return None


def _hex(value: int | None) -> str:
    return f"0x{int(value):x}" if value is not None and value >= 0 else "0x0"


def build_function_ranges(
    symbols: list[dict[str, Any]],
    dwarf_functions: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Merge DWARF and symbol functions into deterministic function ranges."""
    result_by_start: dict[int, dict[str, Any]] = {}

    for fn in dwarf_functions or []:
        start = _addr_int(fn.get("start"))
        if start is None:
            continue
        result_by_start[start] = {
            "name": str(fn.get("name") or f"sub_{start:x}"),
            "start": _hex(start),
            "end": str(fn.get("end") or "0x0"),
            "source": "DWARF",
        }

    symbol_functions = [
        sym for sym in symbols
        if sym.get("kind") == "FUNC" and _addr_int(sym.get("addr")) is not None
    ]
    symbol_functions.sort(key=lambda item: (_addr_int(item.get("addr")) or 0, str(item.get("name") or "")))
    starts = [_addr_int(sym.get("addr")) for sym in symbol_functions]

    for index, sym in enumerate(symbol_functions):
        start = starts[index]
        if start is None or start in result_by_start:
            continue
        size = sym.get("size")
        end = None
        if isinstance(size, int) and size > 0:
            end = start + size
            source = str(sym.get("source") or "LIEF")
        else:
            next_start = next((candidate for candidate in starts[index + 1:] if candidate and candidate > start), None)
            end = next_start
            source = "symbol+heuristic" if end is not None else str(sym.get("source") or "LIEF")
        result_by_start[start] = {
            "name": str(sym.get("name") or f"sub_{start:x}"),
            "start": _hex(start),
            "end": _hex(end),
            "source": source,
        }

    return [result_by_start[start] for start in sorted(result_by_start)]
