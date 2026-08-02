# SPDX-License-Identifier: AGPL-3.0-only
"""Etat partage par binaire pour le shim IDAPython.

Charge et met en cache paresseusement les vues (symboles, lignes
desassemblees, xrefs, annotations) dont idc/idautils/idaapi ont besoin,
pour eviter de re-parser le binaire a chaque appel de fonction du shim.
"""

from __future__ import annotations

from backends.static.annotations.annotations import AnnotationStore
from backends.static.binary.symbols import extract_symbols
from backends.static.disasm.disasm import disassemble_with_capstone
from backends.static.disasm.xrefs import build_xref_map

BADADDR = 0xFFFFFFFFFFFFFFFF


def parse_ea(value: object) -> int:
    """Convertit une adresse IDAPython (int ou str hex/dec) en entier."""
    if isinstance(value, bool):
        raise TypeError("ea must be an int or a hex/decimal string")
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        raise ValueError("empty address")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


def ea_to_addr(ea: int) -> str:
    return f"0x{ea:x}"


class IdaContext:
    """Vue paresseuse et memoisee d'un binaire pour le shim idc/idautils/idaapi."""

    def __init__(self, binary_path: str) -> None:
        self.binary_path = binary_path
        self._symbols: list[dict] | None = None
        self._lines: list[dict] | None = None
        self._xref_map: dict | None = None
        self._store: AnnotationStore | None = None

    def symbols(self) -> list[dict]:
        if self._symbols is None:
            self._symbols = extract_symbols(self.binary_path, defined_only=True)
        return self._symbols

    def functions(self) -> list[dict]:
        """Symboles de type fonction (code "T"), tries par adresse."""
        funcs = [s for s in self.symbols() if s.get("type") == "T"]
        return sorted(funcs, key=lambda s: parse_ea(s["addr"]))

    def lines(self) -> list[dict]:
        """Instructions desassemblees en memoire ({addr, text, bytes}, ...)."""
        lines = self._lines
        if lines is None:
            lines = disassemble_with_capstone(self.binary_path) or []
            self._lines = lines
        return lines

    def xref_map(self) -> dict:
        xref_map = self._xref_map
        if xref_map is None:
            xref_map = build_xref_map(self.lines(), binary_path=self.binary_path)
            self._xref_map = xref_map
        return xref_map

    def store(self) -> AnnotationStore:
        if self._store is None:
            self._store = AnnotationStore(self.binary_path)
        return self._store

    def function_containing(self, ea: int) -> dict | None:
        """Symbole fonction dont [addr, addr+size) contient ea, sinon None."""
        for fn in self.functions():
            start = parse_ea(fn["addr"])
            size = int(fn.get("size") or 0)
            end = start + size if size else start
            if start == ea or (size and start <= ea < end):
                return fn
        return None

    def close(self) -> None:
        if self._store is not None:
            self._store.close()
            self._store = None
