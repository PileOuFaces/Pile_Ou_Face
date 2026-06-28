"""PLT/GOT adapter for the normalized binary metadata model."""

from __future__ import annotations

from typing import Any

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None

from backends.static.disasm.call_graph import resolve_plt_symbols


def _hex(value: Any) -> str:
    try:
        return f"0x{int(value):x}"
    except Exception:
        return "0x0"


def _got_by_name(binary_path: str) -> dict[str, str]:
    if not lief:
        return {}
    try:
        binary = lief.parse(binary_path)
    except Exception:
        return {}
    if binary is None or not isinstance(binary, lief.ELF.Binary):
        return {}
    result: dict[str, str] = {}
    try:
        for rel in binary.pltgot_relocations:
            if rel.has_symbol and rel.symbol.name:
                result[str(rel.symbol.name)] = _hex(rel.address)
    except Exception:
        return result
    return result


def load_plt_entries(binary_path: str) -> list[dict[str, Any]]:
    """Return normalized PLT/GOT entries from existing PLT resolution helpers."""
    plt_map = resolve_plt_symbols(binary_path)
    got_map = _got_by_name(binary_path)
    entries = []
    for plt_addr, raw_name in sorted(
        plt_map.items(), key=lambda item: int(item[0], 16)
    ):
        name = str(raw_name or "").replace("@plt", "")
        entries.append(
            {
                "name": name,
                "plt_addr": plt_addr,
                "got_addr": got_map.get(name, ""),
                "source": "LIEF/PLT",
            }
        )
    return entries
