# SPDX-License-Identifier: AGPL-3.0-only
"""Extract DWARF debug information from ELF binaries."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def extract_dwarf_info(binary: str) -> dict:
    """Extract functions, types, and variables from DWARF info in an ELF binary."""
    path = Path(binary)
    if not path.exists():
        return {"error": f"Binary not found: {binary}"}

    try:
        from elftools.common.exceptions import ELFError
        from elftools.elf.elffile import ELFFile
    except ImportError:
        return {"error": "pyelftools is not installed. Run: pip install pyelftools"}

    try:
        with open(binary, "rb") as f:
            try:
                elf = ELFFile(f)
            except ELFError as e:
                return {"error": f"ELF parse error: {e}"}

            if not elf.has_dwarf_info():
                return {"error": "No DWARF info found in binary"}

            dwarfinfo = elf.get_dwarf_info()

            functions = []
            types = []
            variables = []

            for CU in dwarfinfo.iter_CUs():
                for die in CU.iter_DIEs():
                    tag = die.tag

                    # --- Functions ---
                    if tag == "DW_TAG_subprogram":
                        name = _get_attr_str(die, "DW_AT_name")
                        if name is None:
                            continue
                        low_pc = _get_attr_int(die, "DW_AT_low_pc")
                        high_pc = _get_attr_int(die, "DW_AT_high_pc")
                        return_type = _resolve_type(die, CU, dwarfinfo)
                        fn = {
                            "name": name,
                            "low_pc": hex(low_pc) if low_pc is not None else None,
                            "high_pc": hex(high_pc) if high_pc is not None else None,
                            "return_type": return_type,
                        }
                        functions.append(fn)

                    # --- Base types ---
                    elif tag == "DW_TAG_base_type":
                        name = _get_attr_str(die, "DW_AT_name")
                        byte_size = _get_attr_int(die, "DW_AT_byte_size")
                        if name:
                            types.append(
                                {
                                    "kind": "base",
                                    "name": name,
                                    "byte_size": byte_size or 0,
                                }
                            )

                    # --- Struct types ---
                    elif tag == "DW_TAG_structure_type":
                        name = _get_attr_str(die, "DW_AT_name")
                        byte_size = _get_attr_int(die, "DW_AT_byte_size")
                        if name:
                            types.append(
                                {
                                    "kind": "struct",
                                    "name": name,
                                    "byte_size": byte_size or 0,
                                }
                            )

                    # --- Typedef ---
                    elif tag == "DW_TAG_typedef":
                        name = _get_attr_str(die, "DW_AT_name")
                        byte_size = _get_attr_int(die, "DW_AT_byte_size")
                        if name:
                            types.append(
                                {
                                    "kind": "typedef",
                                    "name": name,
                                    "byte_size": byte_size or 0,
                                }
                            )

                    # --- Global variables ---
                    elif tag == "DW_TAG_variable":
                        name = _get_attr_str(die, "DW_AT_name")
                        if name and "DW_AT_external" in die.attributes:
                            var_type = _resolve_type(die, CU, dwarfinfo)
                            variables.append(
                                {
                                    "name": name,
                                    "type": var_type,
                                }
                            )

            return {
                "functions": functions,
                "types": types,
                "variables": variables,
            }

    except Exception as e:
        return {"error": str(e)}


def _get_attr_str(die, attr: str) -> str | None:
    """Get a string attribute from a DIE."""
    if attr in die.attributes:
        val = die.attributes[attr].value
        if isinstance(val, bytes):
            return val.decode("utf-8", errors="replace")
        return str(val)
    return None


def _get_attr_int(die, attr: str) -> int | None:
    """Get an integer attribute from a DIE."""
    if attr in die.attributes:
        val = die.attributes[attr].value
        if isinstance(val, int):
            return val
    return None


def _resolve_type(die, CU, dwarfinfo) -> str | None:
    """Resolve the DW_AT_type reference to a type name."""
    if "DW_AT_type" not in die.attributes:
        return None
    try:
        type_offset = die.attributes["DW_AT_type"].value
        # The offset is relative to the CU header offset
        cu_offset = CU.cu_offset
        abs_offset = cu_offset + type_offset

        for other_die in CU.iter_DIEs():
            if other_die.offset == abs_offset:
                name = _get_attr_str(other_die, "DW_AT_name")
                return name
        return None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description="Extract DWARF info from ELF binary")
    parser.add_argument("--binary", required=True, help="Path to ELF binary")
    args = parser.parse_args()

    result = extract_dwarf_info(args.binary)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
