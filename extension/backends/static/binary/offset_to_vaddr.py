# SPDX-License-Identifier: AGPL-3.0-only
"""Convertit un offset fichier en adresse virtuelle pour un binaire ELF/Mach-O/PE."""

from __future__ import annotations

import struct
from pathlib import Path


def offset_to_vaddr_elf(binary_path: str, file_offset: int) -> int | None:
    """Pour ELF : trouve la section contenant file_offset et retourne l'adresse virtuelle."""
    path = Path(binary_path)
    if not path.exists():
        return None
    data = path.read_bytes()
    if len(data) < 64:
        return None
    # ELF magic
    if data[:4] != b"\x7fELF":
        return None
    is_64 = data[4] == 2
    little_endian = data[5] == 1
    endian = "<" if little_endian else ">"
    if is_64:
        e_shoff = struct.unpack_from(f"{endian}Q", data, 40)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 58)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 60)[0]
        shdr_size = 64
    else:
        e_shoff = struct.unpack_from(f"{endian}I", data, 32)[0]
        e_shentsize = struct.unpack_from(f"{endian}H", data, 46)[0]
        e_shnum = struct.unpack_from(f"{endian}H", data, 48)[0]
        shdr_size = 40
    for i in range(e_shnum):
        shdr_start = e_shoff + i * e_shentsize
        if shdr_start + shdr_size > len(data):
            break
        shdr = data[shdr_start : shdr_start + shdr_size]
        if is_64:
            sh_addr = struct.unpack_from(f"{endian}Q", shdr, 16)[0]
            sh_offset = struct.unpack_from(f"{endian}Q", shdr, 24)[0]
            sh_size = struct.unpack_from(f"{endian}Q", shdr, 32)[0]
        else:
            sh_addr = struct.unpack_from(f"{endian}I", shdr, 12)[0]
            sh_offset = struct.unpack_from(f"{endian}I", shdr, 16)[0]
            sh_size = struct.unpack_from(f"{endian}I", shdr, 20)[0]
        if sh_size == 0:
            continue
        if sh_offset <= file_offset < sh_offset + sh_size:
            return int(sh_addr) + (file_offset - int(sh_offset))
    return None


def offset_to_vaddr_macho(binary_path: str, file_offset: int) -> int | None:
    """Pour Mach-O : trouve le segment contenant file_offset via lief."""
    try:
        import lief

        binary = lief.parse(binary_path)
        if not isinstance(binary, lief.MachO.Binary):
            return None
        for seg in binary.segments:
            seg_offset = seg.file_offset
            seg_size = seg.file_size
            if seg_size == 0:
                continue
            if seg_offset <= file_offset < seg_offset + seg_size:
                return int(seg.virtual_address) + (file_offset - int(seg_offset))
    except Exception:
        pass
    return None


def offset_to_vaddr_pe(binary_path: str, file_offset: int) -> int | None:
    """Pour PE : trouve la section contenant file_offset via lief."""
    try:
        import lief

        binary = lief.parse(binary_path)
        if not isinstance(binary, lief.PE.Binary):
            return None
        image_base = binary.optional_header.imagebase
        for sec in binary.sections:
            raw_offset = sec.offset
            raw_size = sec.size
            if raw_size == 0:
                continue
            if raw_offset <= file_offset < raw_offset + raw_size:
                return (
                    int(image_base)
                    + int(sec.virtual_address)
                    + (file_offset - int(raw_offset))
                )
    except Exception:
        pass
    return None


def offset_to_vaddr(binary_path: str, file_offset: int) -> int | None:
    """Convertit offset fichier en adresse virtuelle (ELF, Mach-O, PE).

    Retourne None si le format n'est pas reconnu ou l'offset hors section.
    """
    path = Path(binary_path)
    if not path.exists():
        return None
    magic = path.read_bytes()[:4]
    if magic == b"\x7fELF":
        return offset_to_vaddr_elf(binary_path, file_offset)
    if magic[:2] == b"MZ":
        return offset_to_vaddr_pe(binary_path, file_offset)
    # Mach-O : magic 0xFEEDFACE / 0xFEEDFACF / 0xCEFAEDFE / 0xCFFAEDFE
    if magic in (
        b"\xfe\xed\xfa\xce",
        b"\xfe\xed\xfa\xcf",
        b"\xce\xfa\xed\xfe",
        b"\xcf\xfa\xed\xfe",
    ):
        return offset_to_vaddr_macho(binary_path, file_offset)
    return None


def main() -> int:
    """CLI : --binary PATH --offset 0xad8 -> stdout: 0x400xxx ou vide."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Convert file offset to virtual address"
    )
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--offset", required=True, help="File offset (hex or decimal)")
    parser.add_argument("--json", action="store_true", help="Output JSON")
    args = parser.parse_args()

    off_str = args.offset.strip().lower()
    file_offset = int(off_str[2:], 16) if off_str.startswith("0x") else int(off_str)

    vaddr = offset_to_vaddr(args.binary, file_offset)
    if args.json:
        print(
            json.dumps(
                {
                    "file_offset": file_offset,
                    "vaddr": f"0x{vaddr:x}" if vaddr is not None else None,
                }
            )
        )
    else:
        if vaddr is not None:
            print(f"0x{vaddr:x}")
    return 0 if vaddr is not None else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
