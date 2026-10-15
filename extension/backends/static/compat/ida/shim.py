# SPDX-License-Identifier: AGPL-3.0-only
"""Construit les faux modules idc/idautils/idaapi pour un binaire donne.

Meme patron que `backends/dynamic/pipeline/payload_script_runner.py`
(`_make_fake_pwn`/`_patched_runtime`) : un `ModuleType` par API, injecte
dans `sys.modules` le temps de l'execution du script puis restaure.

Toute fonction idc/idautils/idaapi non mappee leve `NotImplementedError`
via `__getattr__` du module plutot que de renvoyer une valeur par defaut
silencieuse — cf. issue #130 (DoD "jamais de faux-negatif silencieux").
"""

from __future__ import annotations

import contextlib
import sys
from types import ModuleType
from typing import Any

from backends.static.annotations.annotations import KIND_RENAME
from backends.static.compat.ida.context import BADADDR, IdaContext, ea_to_addr, parse_ea

_SOURCE = "script"

_IDC_SUPPORTED = (
    "BADADDR",
    "get_func_name",
    "get_name",
    "get_name_ea_simple",
    "get_bytes",
    "get_operand_value",
    "GetDisasm",
    "generate_disasm_line",
    "set_name",
    "set_cmt",
    "get_cmt",
    "next_head",
    "prev_head",
    "here",
)

_IDAUTILS_SUPPORTED = ("Functions", "XrefsTo", "XrefsFrom", "Strings")

_IDAAPI_SUPPORTED = ("get_func", "get_imagebase", "BADADDR")


class Xref:
    """Equivalent minimal de idautils.XrefTypeName / xrefblk_t."""

    def __init__(self, frm: int, to: int, xref_type: str, iscode: bool) -> None:
        self.frm = frm
        self.to = to
        self.type = xref_type
        self.iscode = iscode

    def __repr__(self) -> str:  # pragma: no cover - debug helper
        return f"Xref(frm=0x{self.frm:x}, to=0x{self.to:x}, type={self.type!r})"


class StringItem:
    """Equivalent minimal de idautils.Strings() item."""

    def __init__(self, ea: int, value: str, length: int) -> None:
        self.ea = ea
        self.length = length
        self._value = value

    def __str__(self) -> str:
        return self._value


class FakeFunc:
    """Equivalent minimal de idaapi.func_t."""

    def __init__(self, start_ea: int, end_ea: int) -> None:
        self.start_ea = start_ea
        self.end_ea = end_ea


def _decode_one(ctx: IdaContext, ea: int) -> dict | None:
    """Retourne la ligne desassemblee ({addr, text, bytes}) a l'adresse ea, si connue."""
    target = ea_to_addr(ea)
    for line in ctx.lines():
        if str(line.get("addr", "")).lower() == target:
            return line
    return None


def _sorted_addrs(ctx: IdaContext) -> list[int]:
    return sorted(parse_ea(line["addr"]) for line in ctx.lines() if line.get("addr"))


def _module_getattr(namespace: str, supported: tuple[str, ...]):
    def __getattr__(name: str) -> Any:  # noqa: N807 - module dunder
        if name.startswith("__"):
            raise AttributeError(name)
        raise NotImplementedError(
            f"{namespace}.{name} n'est pas supporte par le shim IDAPython de "
            "Pile ou Face (cf. docs/static/idapython-compat.md). "
            f"API supportee: {', '.join(supported)}"
        )

    return __getattr__


def build_idc_module(ctx: IdaContext) -> ModuleType:
    module = ModuleType("idc")

    def get_func_name(ea: Any) -> str:
        ea_int = parse_ea(ea)
        stored = ctx.store().get_name(ea_to_addr(ea_int))
        if stored:
            return stored
        fn = ctx.function_containing(ea_int)
        return fn["name"] if fn else ""

    def get_name(ea: Any) -> str:
        return get_func_name(ea)

    def get_name_ea_simple(name: str) -> int:
        for sym in ctx.symbols():
            if sym.get("name") == name:
                return parse_ea(sym["addr"])
        for row in ctx.store().list():
            if row.get("kind") == KIND_RENAME and row.get("value") == name:
                return parse_ea(row["addr"])
        return BADADDR

    def get_bytes(ea: Any, size: int) -> bytes | None:
        ea_int = parse_ea(ea)
        line = _decode_one(ctx, ea_int)
        if line is None or "bytes" not in line:
            return None
        raw = bytes.fromhex(str(line["bytes"]).replace(" ", ""))
        return raw[:size] if size <= len(raw) else raw

    def get_operand_value(ea: Any, n: int) -> int:
        line = _decode_one(ctx, parse_ea(ea))
        if line is None:
            raise NotImplementedError(f"idc.get_operand_value: adresse inconnue {ea!r}")
        text = str(line.get("text", ""))
        operands = text.split(None, 1)[1] if " " in text else ""
        parts = [p.strip() for p in operands.split(",") if p.strip()]
        if n >= len(parts):
            raise NotImplementedError(
                f"idc.get_operand_value: operande {n} absent de {text!r}"
            )
        operand = parts[n].strip("[]")
        for token in (operand, operand.split("+")[-1].split("-")[-1]):
            token = token.strip()
            try:
                return int(token, 16) if token.lower().startswith("0x") else int(token)
            except ValueError:
                continue
        raise NotImplementedError(
            f"idc.get_operand_value: operande non-immediat non supporte: {operand!r}"
        )

    def GetDisasm(ea: Any) -> str:  # noqa: N802 - nom impose par l'API IDA
        line = _decode_one(ctx, parse_ea(ea))
        return str(line["text"]) if line else ""

    def set_name(ea: Any, name: str, flags: int = 0) -> bool:
        del flags
        ctx.store().rename(ea_to_addr(parse_ea(ea)), name, source=_SOURCE)
        return True

    def set_cmt(ea: Any, comment: str, rptble: bool = False) -> bool:
        del rptble
        ctx.store().comment(ea_to_addr(parse_ea(ea)), comment, source=_SOURCE)
        return True

    def get_cmt(ea: Any, rptble: bool = False) -> str | None:
        del rptble
        return ctx.store().get_comment(ea_to_addr(parse_ea(ea)))

    def next_head(ea: Any, maxea: Any = BADADDR) -> int:
        ea_int = parse_ea(ea)
        max_ea = parse_ea(maxea) if maxea != BADADDR else None
        for addr in _sorted_addrs(ctx):
            if addr > ea_int and (max_ea is None or addr < max_ea):
                return addr
        return BADADDR

    def prev_head(ea: Any, minea: Any = 0) -> int:
        ea_int = parse_ea(ea)
        min_ea = parse_ea(minea)
        candidates = [a for a in _sorted_addrs(ctx) if min_ea <= a < ea_int]
        return max(candidates) if candidates else BADADDR

    def here() -> int:
        raise NotImplementedError(
            "idc.here() necessite un curseur interactif, indisponible en "
            "execution scriptee headless"
        )

    module.BADADDR = BADADDR
    module.get_func_name = get_func_name
    module.get_name = get_name
    module.get_name_ea_simple = get_name_ea_simple
    module.get_bytes = get_bytes
    module.get_operand_value = get_operand_value
    module.GetDisasm = GetDisasm
    module.generate_disasm_line = lambda ea, flags=0: GetDisasm(ea)
    module.set_name = set_name
    module.set_cmt = set_cmt
    module.get_cmt = get_cmt
    module.next_head = next_head
    module.prev_head = prev_head
    module.here = here
    module.__all__ = list(_IDC_SUPPORTED)
    module.__getattr__ = _module_getattr("idc", _IDC_SUPPORTED)
    return module


def build_idautils_module(ctx: IdaContext) -> ModuleType:
    module = ModuleType("idautils")

    def Functions(start: Any = None, end: Any = None):  # noqa: N802
        lo = parse_ea(start) if start is not None else None
        hi = parse_ea(end) if end is not None else None
        for fn in ctx.functions():
            addr = parse_ea(fn["addr"])
            if lo is not None and addr < lo:
                continue
            if hi is not None and addr >= hi:
                continue
            yield addr

    def XrefsTo(ea: Any, flags: int = 0):  # noqa: N802
        del flags
        target = ea_to_addr(parse_ea(ea))
        for ref in ctx.xref_map().get(target, []):
            frm = parse_ea(ref["from_addr"])
            yield Xref(
                frm=frm,
                to=parse_ea(ea),
                xref_type=ref.get("type", ""),
                iscode=ref.get("type") in {"jmp", "jcc", "call"},
            )

    def XrefsFrom(ea: Any, flags: int = 0):  # noqa: N802
        del flags
        ea_int = parse_ea(ea)
        source = ea_to_addr(ea_int)
        for target, refs in ctx.xref_map().items():
            for ref in refs:
                if parse_ea(ref["from_addr"]) == ea_int:
                    yield Xref(
                        frm=ea_int,
                        to=parse_ea(target),
                        xref_type=ref.get("type", ""),
                        iscode=ref.get("type") in {"jmp", "jcc", "call"},
                    )
        del source

    def Strings(default_setup: bool = True):  # noqa: N802
        del default_setup
        from backends.static.search.strings import extract_strings

        for row in extract_strings(ctx.binary_path):
            yield StringItem(
                ea=parse_ea(row["addr"]),
                value=str(row["value"]),
                length=int(row.get("length") or len(str(row["value"]))),
            )

    module.Functions = Functions
    module.XrefsTo = XrefsTo
    module.XrefsFrom = XrefsFrom
    module.Strings = Strings
    module.__all__ = list(_IDAUTILS_SUPPORTED)
    module.__getattr__ = _module_getattr("idautils", _IDAUTILS_SUPPORTED)
    return module


def build_idaapi_module(ctx: IdaContext) -> ModuleType:
    module = ModuleType("idaapi")

    def get_func(ea: Any):
        fn = ctx.function_containing(parse_ea(ea))
        if fn is None:
            return None
        start = parse_ea(fn["addr"])
        size = int(fn.get("size") or 0)
        return FakeFunc(start_ea=start, end_ea=start + size if size else start)

    def get_imagebase() -> int:
        funcs = ctx.functions()
        if not funcs:
            return 0
        return min(parse_ea(f["addr"]) for f in funcs)

    module.BADADDR = BADADDR
    module.get_func = get_func
    module.get_imagebase = get_imagebase
    module.func_t = FakeFunc
    module.__all__ = list(_IDAAPI_SUPPORTED)
    module.__getattr__ = _module_getattr("idaapi", _IDAAPI_SUPPORTED)
    return module


@contextlib.contextmanager
def patched_ida_runtime(binary_path: str):
    """Injecte idc/idautils/idaapi dans sys.modules pour la duree du bloc.

    Restaure les modules preexistants (le cas echeant) en sortie, comme
    `_patched_runtime` pour pwntools dans payload_script_runner.py.
    """
    ctx = IdaContext(binary_path)
    modules = {
        "idc": build_idc_module(ctx),
        "idautils": build_idautils_module(ctx),
        "idaapi": build_idaapi_module(ctx),
    }
    saved = {name: sys.modules.get(name) for name in modules}
    sys.modules.update(modules)
    try:
        yield modules
    finally:
        for name, previous in saved.items():
            if previous is None:
                sys.modules.pop(name, None)
            else:
                sys.modules[name] = previous
        ctx.close()
