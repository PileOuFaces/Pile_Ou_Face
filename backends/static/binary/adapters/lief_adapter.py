"""LIEF-backed binary facts for the normalized metadata model."""

from __future__ import annotations

from pathlib import Path
from typing import Any

try:
    import lief
except ImportError:  # pragma: no cover - optional dependency
    lief = None

from backends.static.binary.arch import detect_binary_arch


def _hex(value: Any) -> str:
    try:
        return f"0x{int(value):x}"
    except Exception:
        return "0x0"


def _enum_name(value: Any) -> str:
    name = getattr(value, "name", None)
    return str(name or value or "").strip()


def _parse(binary_path: str) -> Any:
    if not lief:
        return None
    try:
        return lief.parse(binary_path)
    except Exception:
        return None


def _elf_base(binary: Any) -> int:
    try:
        loads = [
            int(segment.virtual_address)
            for segment in binary.segments
            if _enum_name(getattr(segment, "type", "")).upper() == "LOAD"
        ]
        return min(loads) if loads else 0
    except Exception:
        return 0


def _pe_base(binary: Any) -> int:
    try:
        return int(binary.optional_header.imagebase)
    except Exception:
        return 0


def _macho_base(binary: Any) -> int:
    try:
        return min(int(segment.virtual_address) for segment in binary.segments)
    except Exception:
        return 0


def _is_elf_pie(binary: Any) -> bool:
    file_type = _enum_name(getattr(binary.header, "file_type", "")).upper()
    return file_type == "DYN"


def _is_macho_pie(binary: Any) -> bool:
    flags = str(getattr(getattr(binary, "header", None), "flags_list", "") or "")
    return "PIE" in flags.upper()


def _is_pe_pie(binary: Any) -> bool:
    try:
        return bool(binary.optional_header.has(lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE))
    except Exception:
        return False


def _stripped_from_lief(binary: Any) -> bool:
    try:
        if isinstance(binary, lief.ELF.Binary):
            return len([s for s in binary.symtab_symbols if getattr(s, "name", "")]) <= 1
        if isinstance(binary, lief.MachO.Binary):
            return len([s for s in binary.symbols if getattr(s, "name", "")]) <= 1
        if isinstance(binary, lief.PE.Binary):
            return len([f for f in getattr(binary, "exported_functions", []) if getattr(f, "name", "")]) == 0
    except Exception:
        return False
    return False


def load_binary_facts(binary_path: str) -> dict[str, Any]:
    """Return normalized high-level binary facts from LIEF when available."""
    path = Path(binary_path)
    facts: dict[str, Any] = {
        "path": str(path),
        "format": "UNKNOWN",
        "arch": "",
        "bits": None,
        "entry": "0x0",
        "base": "0x0",
        "pie": False,
        "stripped": False,
        "source": "LIEF",
    }
    binary = _parse(str(path))
    if binary is None:
        facts["source"] = "unavailable"
        return facts

    arch_info = detect_binary_arch(binary)
    if arch_info is not None:
        facts["arch"] = arch_info.raw_name
        facts["bits"] = arch_info.bits

    try:
        facts["entry"] = _hex(getattr(binary, "entrypoint", 0))
    except Exception:
        pass

    try:
        if isinstance(binary, lief.ELF.Binary):
            facts["format"] = "ELF"
            facts["base"] = _hex(_elf_base(binary))
            facts["pie"] = _is_elf_pie(binary)
            if not facts["arch"]:
                facts["arch"] = _enum_name(binary.header.machine_type).lower()
            if facts["bits"] is None:
                facts["bits"] = 64 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 32
        elif isinstance(binary, lief.MachO.Binary):
            facts["format"] = "Mach-O"
            facts["base"] = _hex(_macho_base(binary))
            facts["pie"] = _is_macho_pie(binary)
            if not facts["arch"]:
                facts["arch"] = _enum_name(binary.header.cpu_type).lower()
            if facts["bits"] is None:
                facts["bits"] = 64 if binary.header.is_64bit else 32
        elif isinstance(binary, lief.PE.Binary):
            facts["format"] = "PE"
            facts["base"] = _hex(_pe_base(binary))
            facts["pie"] = _is_pe_pie(binary)
            if not facts["arch"]:
                facts["arch"] = _enum_name(binary.header.machine).lower()
    except Exception:
        pass

    facts["stripped"] = _stripped_from_lief(binary)
    return facts


def section_flags_by_name(binary_path: str) -> dict[str, list[str]]:
    """Return best-effort normalized section flags keyed by section name."""
    binary = _parse(binary_path)
    if binary is None:
        return {}
    flags: dict[str, list[str]] = {}
    try:
        if isinstance(binary, lief.ELF.Binary):
            for section in binary.sections:
                values: list[str] = []
                if section.has(lief.ELF.Section.FLAGS.ALLOC):
                    values.append("READ")
                if section.has(lief.ELF.Section.FLAGS.WRITE):
                    values.append("WRITE")
                if section.has(lief.ELF.Section.FLAGS.EXECINSTR):
                    values.append("EXEC")
                flags[section.name] = values
        elif isinstance(binary, lief.MachO.Binary):
            for section in binary.sections:
                values = ["READ"]
                segment_name = str(getattr(getattr(section, "segment", None), "name", "") or "").upper()
                if "TEXT" in segment_name:
                    values.append("EXEC")
                if "DATA" in segment_name:
                    values.append("WRITE")
                flags[section.name] = values
        elif isinstance(binary, lief.PE.Binary):
            for section in binary.sections:
                characteristics = int(section.characteristics)
                values = []
                pe_flags = lief.PE.Section.CHARACTERISTICS
                if characteristics & int(pe_flags.MEM_READ):
                    values.append("READ")
                if characteristics & int(pe_flags.MEM_WRITE):
                    values.append("WRITE")
                if characteristics & int(pe_flags.MEM_EXECUTE):
                    values.append("EXEC")
                flags[section.name] = values
    except Exception:
        return flags
    return flags


def section_name_for_address(binary_path: str, address: int) -> str:
    """Return the section containing a virtual address, if known."""
    binary = _parse(binary_path)
    if binary is None:
        return ""
    try:
        for section in binary.sections:
            start = int(getattr(section, "virtual_address", 0) or 0)
            size = int(getattr(section, "size", 0) or 0)
            if start <= address < start + size:
                return str(getattr(section, "name", "") or "")
    except Exception:
        return ""
    return ""
