# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/exception_handlers.py
"""Extraction des gestionnaires d'exceptions (PE SEH, ELF DWARF, Mach-O).

CLI:
  python exception_handlers.py --binary <path>

Output JSON:
  {
    "format": "PE",
    "arch": "x86_64",
    "entries": [
      {"func_start": "0x1000", "func_end": "0x1100",
       "handler": "0x2000", "handler_type": "SEH", "unwind_flags": []}
    ],
    "count": N,
    "error": null
  }
"""

from __future__ import annotations

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import lief

    _LIEF_AVAILABLE = True
except ImportError:
    lief = None
    _LIEF_AVAILABLE = False


def _arch_name(binary) -> str:
    try:
        return binary.header.machine.name
    except Exception:
        try:
            return str(binary.header.cpu_type)
        except Exception:
            return "unknown"


def _pe_exceptions(binary) -> list[dict]:
    entries = []
    imgbase = getattr(getattr(binary, "optional_header", None), "imagebase", 0) or 0
    try:
        for exc in binary.exceptions:
            start = getattr(exc, "rva_start", 0) or 0
            end = getattr(exc, "rva_end", 0) or 0
            entry: dict = {
                "func_start": hex(start + imgbase),
                "func_end": hex(end + imgbase),
                "handler": None,
                "handler_type": "SEH",
                "unwind_flags": [],
            }
            try:
                ui = exc.unwind_info
                uw_flags = getattr(ui, "flags", 0) or 0
                flags = []
                if uw_flags & 0x1:
                    flags.append("EXCEPTION")
                if uw_flags & 0x2:
                    flags.append("TERMINATION")
                if uw_flags & 0x4:
                    flags.append("CHAININFO")
                entry["unwind_flags"] = flags
                handler_rva = getattr(ui, "exception_handler", None)
                if handler_rva:
                    entry["handler"] = hex(handler_rva + imgbase)
                    if "EXCEPTION" in flags:
                        entry["handler_type"] = "C++ EH"
            except Exception:
                pass
            entries.append(entry)
    except (AttributeError, Exception):
        pass

    if not entries:
        try:
            lc = binary.load_configuration
            for handler_rva in lc.se_handler_table:
                entries.append(
                    {
                        "func_start": None,
                        "func_end": None,
                        "handler": hex(handler_rva + imgbase),
                        "handler_type": "SEH",
                        "unwind_flags": [],
                    }
                )
        except Exception:
            pass
    return entries


def _read_dwarf_int(data: bytes, offset: int, size: int, *, signed: bool = False) -> int | None:
    if offset < 0 or size <= 0 or offset + size > len(data):
        return None
    return int.from_bytes(data[offset : offset + size], "little", signed=signed)


def _elf_dwarf_exceptions(binary) -> list[dict]:
    entries = []
    try:
        eh_section = next(
            (s for s in binary.sections if s.name in (".eh_frame", "__eh_frame")),
            None,
        )
        if eh_section is None:
            return []
        data = bytes(eh_section.content)
        base_addr = eh_section.virtual_address
        pos = 0
        while pos + 4 <= len(data):
            initial_length = _read_dwarf_int(data, pos, 4)
            if initial_length is None:
                break
            length = initial_length
            if length == 0:
                break
            is_dwarf64 = length == 0xFFFFFFFF
            if is_dwarf64:
                length64 = _read_dwarf_int(data, pos + 4, 8)
                if length64 is None:
                    break
                length = length64
                content_start = pos + 12
                field_size = 8
            else:
                content_start = pos + 4
                field_size = 4

            record_end = content_start + length
            if length < field_size or record_end > len(data):
                break

            cie_id = _read_dwarf_int(data, content_start, field_size)
            if cie_id is None:
                break
            cie_sentinel = (1 << (field_size * 8)) - 1
            is_fde = cie_id not in (0, cie_sentinel)
            if is_fde:
                pc_offset_pos = content_start + field_size
                pc_range_pos = pc_offset_pos + field_size
                pc_offset = _read_dwarf_int(data, pc_offset_pos, field_size, signed=True)
                pc_range = _read_dwarf_int(data, pc_range_pos, field_size)
                if pc_offset is not None and pc_range is not None:
                    pc_begin = base_addr + pc_offset_pos + pc_offset
                    flags = ["DWARF64"] if is_dwarf64 else []
                    entries.append(
                        {
                            "func_start": hex(pc_begin),
                            "func_end": hex(pc_begin + pc_range),
                            "handler": None,
                            "handler_type": "DWARF FDE",
                            "unwind_flags": flags,
                        }
                    )
            pos = record_end
    except Exception:
        pass
    return entries


def _macho_image_base(binary) -> int:
    for attr in ("imagebase", "image_base"):
        try:
            value = getattr(binary, attr)
            if callable(value):
                value = value()
            if value:
                return int(value)
        except Exception:
            pass
    return 0


def _macho_compact_unwind_entries(binary, section) -> list[dict]:
    data = bytes(getattr(section, "content", b"") or b"")
    image_base = _macho_image_base(binary)
    entries = []
    record_size = 20

    for pos in range(0, len(data) - (len(data) % record_size), record_size):
        range_start = _read_dwarf_int(data, pos, 4)
        range_length = _read_dwarf_int(data, pos + 4, 4)
        encoding = _read_dwarf_int(data, pos + 8, 4)
        personality = _read_dwarf_int(data, pos + 12, 4)
        lsda = _read_dwarf_int(data, pos + 16, 4)
        if range_start is None or range_length is None or not range_length:
            continue

        func_start = image_base + range_start
        flags = [f"encoding=0x{encoding:x}" if encoding is not None else "encoding=unknown"]
        handler = hex(image_base + personality) if personality else None
        if lsda:
            flags.append(f"lsda=0x{image_base + lsda:x}")

        entries.append(
            {
                "func_start": hex(func_start),
                "func_end": hex(func_start + range_length),
                "handler": handler,
                "handler_type": "Mach-O compact unwind",
                "unwind_flags": flags,
            }
        )
    return entries


def _macho_exceptions(binary) -> list[dict]:
    entries = []
    try:
        for section in binary.sections:
            if section.name == "__compact_unwind":
                compact_entries = _macho_compact_unwind_entries(binary, section)
                if compact_entries:
                    entries.extend(compact_entries)
                    continue
            if section.name in ("__eh_frame", "__unwind_info"):
                entries.append(
                    {
                        "func_start": None,
                        "func_end": None,
                        "handler": None,
                        "handler_type": "Mach-O unwind metadata",
                        "unwind_flags": [f"{section.name} present"],
                        "note": "Métadonnée globale détectée, sans résolution par fonction ni handler pour le moment.",
                    }
                )
    except Exception:
        pass
    return entries


def get_exception_handlers(binary_path: str) -> dict:
    if not _LIEF_AVAILABLE:
        return {
            "error": "lief non disponible",
            "format": "unknown",
            "arch": "unknown",
            "entries": [],
            "count": 0,
        }
    if not os.path.isfile(binary_path):
        return {
            "error": f"Fichier introuvable : {binary_path}",
            "format": "unknown",
            "arch": "unknown",
            "entries": [],
            "count": 0,
        }

    binary = lief.parse(binary_path)
    if binary is None:
        return {
            "error": "Parsing échoué",
            "format": "unknown",
            "arch": "unknown",
            "entries": [],
            "count": 0,
        }

    fmt, arch, entries = "unknown", "unknown", []
    if isinstance(binary, lief.PE.Binary):
        fmt, arch = "PE", _arch_name(binary)
        entries = _pe_exceptions(binary)
    elif isinstance(binary, lief.ELF.Binary):
        fmt, arch = "ELF", _arch_name(binary)
        entries = _elf_dwarf_exceptions(binary)
    elif hasattr(lief, "MachO") and isinstance(binary, lief.MachO.Binary):
        fmt, arch = "MachO", _arch_name(binary)
        entries = _macho_exceptions(binary)

    return {"format": fmt, "arch": arch, "entries": entries, "count": len(entries), "error": None}


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract exception handlers")
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(get_exception_handlers(args.binary), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
