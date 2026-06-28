# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction d'informations DWARF depuis un binaire ELF.

CLI:
  python dwarf.py --binary <path> [--output <json>]

Output JSON:
  {
    "functions": [{"name": str, "low_pc": str, "high_pc": str, "return_type": str}],
    "types":     [{"kind": "struct"|"union"|"base", "name": str, "byte_size": int,
                   "members": [{"name": str, "type": str, "offset": int}]}],
    "variables": [{"name": str, "type": str, "addr": str}],
    "error": null
  }
"""

from __future__ import annotations

from pathlib import Path
from typing import Any


def extract_dwarf_info(binary_path: str) -> dict[str, Any]:
    """Extrait fonctions, types et variables depuis l'info DWARF d'un ELF.

    Retourne {"functions": [...], "types": [...], "variables": [...], "error": None}
    ou {"error": "...", "functions": [], "types": [], "variables": []}
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "error": f"Fichier introuvable : {binary_path}",
            "functions": [],
            "types": [],
            "variables": [],
        }

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {
            "error": "pyelftools non installé (pip install pyelftools)",
            "functions": [],
            "types": [],
            "variables": [],
        }

    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return {
                    "error": "Aucune info DWARF dans ce binaire (compilez avec -g)",
                    "functions": [],
                    "types": [],
                    "variables": [],
                }
            dwarf = elf.get_dwarf_info()
            return _parse_dwarf(dwarf)
    except Exception as e:  # ELFError + any other parse error
        return {"error": str(e), "functions": [], "types": [], "variables": []}


def _parse_dwarf(dwarf: Any) -> dict[str, Any]:
    functions: list[dict] = []
    types: list[dict] = []
    variables: list[dict] = []

    for CU in dwarf.iter_CUs():
        type_map: dict[int, dict] = {}
        _collect_types(CU.get_top_DIE(), type_map)

        for die in CU.get_top_DIE().iter_children():
            tag = die.tag
            if tag == "DW_TAG_subprogram":
                fn = _parse_subprogram(die, type_map)
                if fn:
                    functions.append(fn)
            elif tag in (
                "DW_TAG_structure_type",
                "DW_TAG_union_type",
                "DW_TAG_base_type",
                "DW_TAG_typedef",
            ):
                t = _parse_type_die(die, tag, type_map)
                if t:
                    types.append(t)
            elif tag == "DW_TAG_variable":
                v = _parse_variable(die, type_map)
                if v:
                    variables.append(v)

    return {
        "functions": functions,
        "types": types,
        "variables": variables,
        "error": None,
    }


def _get_str(die: Any, attr: str) -> str:
    a = die.attributes.get(attr)
    if a is None:
        return ""
    v = a.value
    return v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)


def _get_int(die: Any, attr: str, default: int = 0) -> int:
    a = die.attributes.get(attr)
    return int(a.value) if a is not None else default


def _resolve_type(die: Any, type_map: dict) -> str:
    a = die.attributes.get("DW_AT_type")
    if a is None:
        return ""
    ref = type_map.get(a.value)
    return ref.get("name", "") if ref else ""


def _collect_types(top_die: Any, type_map: dict) -> None:
    """Pré-remplit type_map {offset → {name, kind}} pour la résolution."""
    for die in top_die.iter_children():
        if die.tag in (
            "DW_TAG_structure_type",
            "DW_TAG_union_type",
            "DW_TAG_base_type",
            "DW_TAG_typedef",
            "DW_TAG_pointer_type",
            "DW_TAG_const_type",
        ):
            name = _get_str(die, "DW_AT_name") or f"<{die.tag}>"
            kind = {
                "DW_TAG_structure_type": "struct",
                "DW_TAG_union_type": "union",
                "DW_TAG_base_type": "base",
                "DW_TAG_typedef": "typedef",
                "DW_TAG_pointer_type": "pointer",
                "DW_TAG_const_type": "const",
            }.get(die.tag, "other")
            type_map[die.offset] = {"name": name, "kind": kind}


def _parse_subprogram(die: Any, type_map: dict) -> dict | None:
    name = _get_str(die, "DW_AT_name")
    if not name:
        return None
    low_pc = _get_int(die, "DW_AT_low_pc")
    high_pc_attr = die.attributes.get("DW_AT_high_pc")
    if high_pc_attr is not None:
        high_pc_val = int(high_pc_attr.value)
        high_pc = (
            (low_pc + high_pc_val)
            if high_pc_attr.form != "DW_FORM_addr"
            else high_pc_val
        )
    else:
        high_pc = 0
    return {
        "name": name,
        "low_pc": f"0x{low_pc:x}",
        "high_pc": f"0x{high_pc:x}",
        "return_type": _resolve_type(die, type_map),
    }


def _parse_type_die(die: Any, tag: str, type_map: dict) -> dict | None:
    name = _get_str(die, "DW_AT_name")
    if not name:
        return None
    kind = {
        "DW_TAG_structure_type": "struct",
        "DW_TAG_union_type": "union",
        "DW_TAG_base_type": "base",
        "DW_TAG_typedef": "typedef",
    }.get(tag, "other")
    byte_size = _get_int(die, "DW_AT_byte_size")

    members: list[dict] = []
    if tag in ("DW_TAG_structure_type", "DW_TAG_union_type"):
        for child in die.iter_children():
            if child.tag == "DW_TAG_member":
                mname = _get_str(child, "DW_AT_name")
                mtype = _resolve_type(child, type_map)
                offset_attr = child.attributes.get("DW_AT_data_member_location")
                moffset = int(offset_attr.value) if offset_attr is not None else 0
                members.append({"name": mname, "type": mtype, "offset": moffset})

    result: dict = {"kind": kind, "name": name, "byte_size": byte_size}
    if members:
        result["members"] = members
    return result


def _parse_variable(die: Any, type_map: dict) -> dict | None:
    name = _get_str(die, "DW_AT_name")
    if not name:
        return None
    type_name = _resolve_type(die, type_map)
    addr = ""
    loc_attr = die.attributes.get("DW_AT_location")
    if loc_attr is not None and hasattr(loc_attr, "value"):
        try:
            if isinstance(loc_attr.value, bytes) and len(loc_attr.value) >= 5:
                import struct as _struct

                if loc_attr.value[0] == 0x03:
                    raw = loc_attr.value[1:]
                    size = min(len(raw), 8)
                    fmt = {4: "<I", 8: "<Q"}.get(size)
                    if fmt:
                        addr = f"0x{_struct.unpack(fmt, raw[:size])[0]:x}"
        except Exception:
            pass
    if not addr:
        return None  # Ignorer variables locales sans adresse statique
    return {"name": name, "type": type_name, "addr": addr}


def extract_line_mapping(binary_path: str) -> dict[int, dict]:
    """Extrait le mapping adresse → {file, line} depuis le programme de numéros de ligne DWARF.

    Args:
        binary_path: Chemin vers le binaire ELF

    Returns:
        {addr_int: {"file": str, "line": int}} pour chaque point de séquence,
        ou {} si DWARF absent / pyelftools non installé.
    """
    path = Path(binary_path)
    if not path.exists():
        return {}

    try:
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {}

    result: dict[int, dict] = {}
    try:
        with open(binary_path, "rb") as f:
            elf = ELFFile(f)
            if not elf.has_dwarf_info():
                return {}
            dwarf = elf.get_dwarf_info()
            for CU in dwarf.iter_CUs():
                try:
                    lineprog = dwarf.line_program_for_CU(CU)
                except Exception:
                    continue
                if lineprog is None:
                    continue
                file_entries = lineprog["file_entry"]
                for entry in lineprog.get_entries():
                    if entry.state is None or entry.state.file == 0:
                        continue
                    state = entry.state
                    if state.end_sequence:
                        continue
                    try:
                        fe = file_entries[state.file - 1]
                        filename = (
                            fe.name.decode("utf-8", errors="replace")
                            if isinstance(fe.name, bytes)
                            else str(fe.name)
                        )
                    except (IndexError, AttributeError):
                        filename = "?"
                    # Only keep the first mapping per address
                    if state.address not in result:
                        result[state.address] = {"file": filename, "line": state.line}
    except Exception:
        return {}

    return result


def main() -> int:
    """CLI : extrait les infos DWARF d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Extract DWARF debug info from ELF binary"
    )
    parser.add_argument("--binary", required=True, help="ELF binary path")
    parser.add_argument("--output", help="Output JSON file (default: stdout)")
    args = parser.parse_args()

    result = extract_dwarf_info(args.binary)
    out = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        from pathlib import Path as _Path

        _Path(args.output).write_text(out, encoding="utf-8")
        print(f"DWARF info written to {args.output}")
    else:
        print(out)

    return 1 if result.get("error") else 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
