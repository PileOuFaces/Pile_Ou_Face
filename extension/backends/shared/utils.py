# SPDX-License-Identifier: AGPL-3.0-only
"""Utilitaires partagés entre static et dynamic."""

from __future__ import annotations


def build_offset_to_vaddr(binary_path: str) -> dict[int, int]:
    """Construit une table file_offset → virtual_address via lief (ELF/PE/Mach-O).

    Pour chaque segment/section chargeable, mappe chaque offset byte à son
    adresse virtuelle correspondante.
    Retourne un dict vide si lief n'est pas disponible ou en cas d'erreur.
    """
    try:
        import lief  # type: ignore[import-untyped]

        binary = lief.parse(binary_path)
        if binary is None:
            return {}

        mapping: dict[int, int] = {}

        if isinstance(binary, lief.ELF.Binary):
            for seg in binary.segments:
                if seg.file_size == 0 or seg.virtual_address == 0:
                    continue
                fo, va, size = seg.file_offset, seg.virtual_address, seg.file_size
                for i in range(size):
                    mapping[fo + i] = va + i

        elif isinstance(binary, lief.PE.Binary):
            base = binary.optional_header.imagebase
            for sec in binary.sections:
                fo, va, size = sec.offset, base + sec.virtual_address, sec.size
                for i in range(size):
                    mapping[fo + i] = va + i

        elif isinstance(binary, lief.MachO.Binary):
            for seg in binary.segments:
                if seg.file_size == 0 or seg.virtual_address == 0:
                    continue
                fo, va, size = seg.file_offset, seg.virtual_address, int(seg.file_size)
                for i in range(size):
                    mapping[fo + i] = va + i

        return mapping
    except Exception:
        return {}


def normalize_addr(addr: str) -> str:
    """Normalise une adresse en 0xhex."""
    addr = str(addr).strip().lower()
    if addr.startswith("0x"):
        return addr
    return f"0x{addr}"


def parse_addr(value: str | int | None) -> int | None:
    """Parse une adresse en entier, retourne None si absent ou invalide."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return int(text, 16)
    except ValueError:
        return None


def addr_to_int(addr: str) -> int:
    """Convertit une adresse en entier."""
    s = normalize_addr(addr).replace("0x", "")
    return int(s, 16) if s else 0


def validate_addr(addr: str) -> str | None:
    """Valide et normalise une adresse hex.

    Args:
        addr: Adresse sous forme de chaîne (ex: "0x401000", "401000").

    Returns:
        Adresse normalisée (ex: "0x401000") si valide, ``None`` sinon.

    Examples:
        >>> validate_addr("0x401000")
        '0x401000'
        >>> validate_addr("401000")
        '0x401000'
        >>> validate_addr("not_an_addr")
        None
        >>> validate_addr("")
        None
    """
    if not addr:
        return None
    cleaned = str(addr).strip().lower()
    hex_part = cleaned[2:] if cleaned.startswith("0x") else cleaned
    if not hex_part:
        return None
    try:
        int(hex_part, 16)
    except ValueError:
        return None
    return f"0x{hex_part}"
