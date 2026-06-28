# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction des sections ELF/Mach-O/PE.

Utilise lief pour parser le binaire (robuste, multi-format).
"""

from __future__ import annotations

from pathlib import Path

try:
    import lief
except ImportError:
    lief = None

from backends.shared.log import configure_logging, get_logger, make_meta

logger = get_logger(__name__)


def _raw_file_range(binary_path: str) -> list[tuple[str, int, int]]:
    path = Path(binary_path)
    if not path.exists() or not path.is_file():
        return []
    return [("raw", 0, path.stat().st_size)]


def _raw_section(binary_path: str) -> list[dict]:
    path = Path(binary_path)
    if not path.exists() or not path.is_file():
        return []
    size = path.stat().st_size
    return [
        {
            "idx": 0,
            "name": "raw",
            "size": size,
            "size_hex": f"0x{size:x}",
            "vma": "0x0",
            "vma_hex": "0x0",
            "type": "RAW",
            "offset": 0,
        }
    ]


def get_section_file_ranges(binary_path: str) -> list[tuple[str, int, int]]:
    """Retourne [(name, file_start, file_end), ...] pour filtrer par section.

    Supporte ELF, Mach-O, PE via lief.

    Args:
        binary_path: Chemin vers le binaire

    Returns:
        Liste de (nom, offset_début, offset_fin) pour chaque section
    """
    path = Path(binary_path)
    if not path.exists():
        return []
    if not lief:
        return _raw_file_range(binary_path)

    try:
        binary = lief.parse(str(path))
        if binary is None:
            return _raw_file_range(binary_path)
    except Exception:
        return _raw_file_range(binary_path)

    result = []

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        for sec in binary.sections:
            name = sec.name
            offset = sec.file_offset
            size = sec.size
            result.append((name, offset, offset + size))

    # Mach-O
    elif isinstance(binary, (lief.MachO.Binary, lief.PE.Binary)):
        for sec in binary.sections:
            name = sec.name
            offset = sec.offset
            size = sec.size
            result.append((name, offset, offset + size))

    return result


def extract_sections(binary_path: str) -> list[dict]:
    """Extrait la table des sections d'un binaire (ELF, Mach-O, PE).

    Args:
        binary_path: Chemin vers le binaire

    Returns:
        Liste de {idx, name, size, size_hex, vma, vma_hex, type}
    """
    path = Path(binary_path)
    if not path.exists():
        return []
    if not lief:
        return _raw_section(binary_path)

    try:
        binary = lief.parse(str(path))
        if binary is None:
            return _raw_section(binary_path)
    except Exception:
        return _raw_section(binary_path)

    sections = []

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        for idx, sec in enumerate(binary.sections):
            # Déterminer le type de section
            sec_type = "UNKNOWN"
            if sec.has(lief.ELF.Section.FLAGS.EXECINSTR):
                sec_type = "TEXT"
            elif sec.has(lief.ELF.Section.FLAGS.WRITE):
                sec_type = "DATA"
            elif sec.has(lief.ELF.Section.FLAGS.ALLOC):
                sec_type = "RODATA"
            elif sec.type == lief.ELF.Section.TYPE.NOBITS:
                sec_type = "BSS"

            sections.append(
                {
                    "idx": idx,
                    "name": sec.name,
                    "size": sec.size,
                    "size_hex": f"0x{sec.size:x}",
                    "vma": f"0x{sec.virtual_address:x}",
                    "vma_hex": f"0x{sec.virtual_address:x}",
                    "type": sec_type,
                    "offset": sec.file_offset,
                }
            )

    # Mach-O
    elif isinstance(binary, lief.MachO.Binary):
        for idx, sec in enumerate(binary.sections):
            # Déterminer le type de section Mach-O
            sec_type = "UNKNOWN"
            segment = sec.segment
            if segment:
                if "TEXT" in segment.name.upper():
                    sec_type = "TEXT"
                elif "DATA" in segment.name.upper():
                    sec_type = "DATA"
                elif "BSS" in sec.name.upper():
                    sec_type = "BSS"
                else:
                    sec_type = "RODATA"

            sections.append(
                {
                    "idx": idx,
                    "name": sec.name,
                    "size": sec.size,
                    "size_hex": f"0x{sec.size:x}",
                    "vma": f"0x{sec.virtual_address:x}",
                    "vma_hex": f"0x{sec.virtual_address:x}",
                    "type": sec_type,
                    "offset": sec.offset,
                    "segment": segment.name if segment else "",
                }
            )

    # PE
    elif isinstance(binary, lief.PE.Binary):
        for idx, sec in enumerate(binary.sections):
            # Déterminer le type de section PE
            sec_type = "UNKNOWN"
            characteristics = sec.characteristics
            SC = lief.PE.Section.CHARACTERISTICS
            if characteristics & int(SC.MEM_EXECUTE):
                sec_type = "TEXT"
            elif characteristics & int(SC.MEM_WRITE):
                sec_type = "DATA"
            elif characteristics & int(SC.MEM_READ):
                sec_type = "RODATA"

            sections.append(
                {
                    "idx": idx,
                    "name": sec.name,
                    "size": sec.size,
                    "size_hex": f"0x{sec.size:x}",
                    "vma": f"0x{sec.virtual_address:x}",
                    "vma_hex": f"0x{sec.virtual_address:x}",
                    "type": sec_type,
                    "offset": sec.offset,
                }
            )

    return sections


def main() -> int:
    """Point d'entrée CLI : extrait la table des sections d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract sections from binary (LIEF)")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    sections = extract_sections(args.binary)
    payload = {"meta": make_meta("sections"), "sections": sections}
    out = json.dumps(payload, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Sections written to {args.output} ({len(sections)} sections)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
