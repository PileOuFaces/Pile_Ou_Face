# SPDX-License-Identifier: AGPL-3.0-only
"""Génère un binaire PE64 minimal valide pour les tests (aucune dépendance externe)."""

import struct
from pathlib import Path


def make_minimal_pe64() -> bytes:
    """Retourne les bytes d'un PE64 x86-64 minimal (nop;ret dans .text).

    Structure :
      0x000 : DOS header (64 bytes, e_lfanew=0x80)
      0x040-0x7F : padding
      0x080 : PE signature
      0x084 : COFF header (20 bytes)
      0x098 : Optional header PE32+ (240 bytes)
      0x188 : Section table — .text (40 bytes)
      0x1B0-0x1FF : padding pour FileAlignment=0x200
      0x200 : .text content (0x200 bytes, nop;ret)
    Total : 1024 bytes
    """
    file_align = 0x200
    sect_align = 0x1000
    pe_offset = 0x80
    opt_size = 0xF0  # 112 fixed + 128 data dirs

    # 1. DOS header
    dos = bytearray(64)
    dos[0:2] = b"MZ"
    struct.pack_into("<H", dos, 2, 0x90)  # e_cblp
    struct.pack_into("<H", dos, 4, 3)  # e_cp
    struct.pack_into("<H", dos, 8, 4)  # e_cparhdr
    struct.pack_into("<H", dos, 10, 0xFFFF)  # e_maxalloc
    struct.pack_into("<H", dos, 16, 0xB8)  # e_sp
    struct.pack_into("<H", dos, 24, 0x40)  # e_lfarlc
    struct.pack_into("<I", dos, 60, pe_offset)  # e_lfanew

    # 2. Padding to pe_offset
    pad0 = bytes(pe_offset - 64)

    # 3. PE signature
    pe_sig = b"PE\x00\x00"

    # 4. COFF header
    coff = struct.pack(
        "<HHIIIHH",
        0x8664,  # Machine: AMD64
        1,  # NumberOfSections
        0,  # TimeDateStamp
        0,  # PointerToSymbolTable
        0,  # NumberOfSymbols
        opt_size,  # SizeOfOptionalHeader
        0x0022,  # Characteristics: EXECUTABLE | LARGE_ADDRESS_AWARE
    )

    # 5. Optional header PE32+ (112 bytes fixed + 128 bytes data dirs = 240)
    opt_fixed = struct.pack(
        "<HBBIIIIIQIIHHHHHHI I I I H H Q Q Q Q I I",
        0x020B,  # Magic: PE32+
        14,
        0,  # Linker version
        file_align,  # SizeOfCode
        0,
        0,  # SizeOfInitialized/UninitializedData
        sect_align,  # AddressOfEntryPoint = 0x1000
        sect_align,  # BaseOfCode = 0x1000
        0x140000000,  # ImageBase
        sect_align,  # SectionAlignment
        file_align,  # FileAlignment
        6,
        0,  # MajorOS/Minor version
        0,
        0,  # MajorImage/Minor version
        6,
        0,  # MajorSubsystem/Minor version
        0,  # Win32VersionValue
        sect_align * 2,  # SizeOfImage = 0x2000
        file_align,  # SizeOfHeaders = 0x200
        0,  # CheckSum
        3,  # Subsystem: CUI
        0,  # DllCharacteristics
        0x100000,  # SizeOfStackReserve
        0x1000,  # SizeOfStackCommit
        0x100000,  # SizeOfHeapReserve
        0x1000,  # SizeOfHeapCommit
        0,  # LoaderFlags
        16,  # NumberOfRvaAndSizes
    )
    opt = opt_fixed + bytes(128)  # data directories (all zeros)

    # 6. Section table (.text, 40 bytes)
    sect = struct.pack(
        "<8sIIIIIIHHI",
        b".text\x00\x00\x00",
        2,  # VirtualSize
        sect_align,  # VirtualAddress = 0x1000
        file_align,  # SizeOfRawData = 0x200
        file_align,  # PointerToRawData = 0x200
        0,
        0,
        0,
        0,  # Relocations/Linenumbers
        0x60000020,  # Characteristics: CNT_CODE|MEM_EXECUTE|MEM_READ
    )

    # 7. Assemble headers + pad to 0x200
    headers = bytes(dos) + pad0 + pe_sig + coff + opt + sect
    headers += bytes(file_align - len(headers))  # align

    # 8. .text section: nop;ret + padding
    text = bytes([0x90, 0xC3]) + bytes(file_align - 2)

    return headers + text


def write_minimal_pe64(path: str) -> str:
    """Écrit le PE64 dans path et retourne le chemin."""
    data = make_minimal_pe64()
    Path(path).write_bytes(data)
    return path
