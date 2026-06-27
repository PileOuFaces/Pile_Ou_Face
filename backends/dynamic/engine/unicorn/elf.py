# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Parse little-endian ELF32/ELF64 headers and program headers from a byte blob.
# Exposes u16/u32/u64 readers and returns PT_* entries as dictionaries.
# Includes a helper to read null-terminated strings from binary data.
# -----------------------------------------------------------------------------

"""@file elf.py
@brief Helpers minimalistes pour parser des ELF.

@details Lit en-tetes ELF et program headers depuis un blob binaire.
"""

from typing import List


def read_u16(data: bytes, offset: int) -> int:
    """@brief Lit un uint16 little-endian depuis un blob.
    @param data Blob source.
    @param offset Offset dans le blob.
    @return Valeur lue.
    """
    return int.from_bytes(data[offset : offset + 2], "little")


def read_u32(data: bytes, offset: int) -> int:
    """@brief Lit un uint32 little-endian depuis un blob.
    @param data Blob source.
    @param offset Offset dans le blob.
    @return Valeur lue.
    """
    return int.from_bytes(data[offset : offset + 4], "little")


def read_u64(data: bytes, offset: int) -> int:
    """@brief Lit un uint64 little-endian depuis un blob.
    @param data Blob source.
    @param offset Offset dans le blob.
    @return Valeur lue.
    """
    return int.from_bytes(data[offset : offset + 8], "little")


def parse_elf_header(blob: bytes) -> dict:
    """@brief Parse l'en-tete ELF32/ELF64.
    @param blob Blob ELF complet.
    @return Dictionnaire d'infos ELF.
    @throws ValueError si le format n'est pas supporte.
    """
    if len(blob) < 16 or blob[:4] != b"\x7fELF":
        raise ValueError("Not an ELF file")
    elf_class = blob[4]
    endian = blob[5]
    if endian != 1:
        raise ValueError("Only little-endian ELF supported")

    if elf_class == 1:
        return {
            "class": 32,
            "type": read_u16(blob, 16),
            "machine": read_u16(blob, 18),
            "entry": read_u32(blob, 24),
            "phoff": read_u32(blob, 28),
            "phentsize": read_u16(blob, 42),
            "phnum": read_u16(blob, 44),
        }
    if elf_class == 2:
        return {
            "class": 64,
            "type": read_u16(blob, 16),
            "machine": read_u16(blob, 18),
            "entry": read_u64(blob, 24),
            "phoff": read_u64(blob, 32),
            "phentsize": read_u16(blob, 54),
            "phnum": read_u16(blob, 56),
        }
    raise ValueError("Unsupported ELF class")


def parse_program_headers(blob: bytes, header: dict) -> List[dict]:
    """@brief Parse les program headers.
    @param blob Blob ELF complet.
    @param header En-tete ELF decode.
    @return Liste de dictionnaires PT_*.
    """
    phoff = header["phoff"]
    phentsize = header["phentsize"]
    phnum = header["phnum"]
    entries = []

    for idx in range(phnum):
        offset = phoff + idx * phentsize
        if header["class"] == 32:
            p_type = read_u32(blob, offset)
            p_offset = read_u32(blob, offset + 4)
            p_vaddr = read_u32(blob, offset + 8)
            p_paddr = read_u32(blob, offset + 12)
            p_filesz = read_u32(blob, offset + 16)
            p_memsz = read_u32(blob, offset + 20)
            p_flags = read_u32(blob, offset + 24)
            p_align = read_u32(blob, offset + 28)
        else:
            p_type = read_u32(blob, offset)
            p_flags = read_u32(blob, offset + 4)
            p_offset = read_u64(blob, offset + 8)
            p_vaddr = read_u64(blob, offset + 16)
            p_paddr = read_u64(blob, offset + 24)
            p_filesz = read_u64(blob, offset + 32)
            p_memsz = read_u64(blob, offset + 40)
            p_align = read_u64(blob, offset + 48)

        entries.append(
            {
                "type": p_type,
                "offset": p_offset,
                "vaddr": p_vaddr,
                "paddr": p_paddr,
                "filesz": p_filesz,
                "memsz": p_memsz,
                "flags": p_flags,
                "align": p_align,
            }
        )
    return entries


def read_c_string(blob: bytes, offset: int) -> str:
    """@brief Lit une chaine C terminee par \\0.
    @param blob Blob source.
    @param offset Offset de depart.
    @return Chaine decodee en UTF-8 (replace).
    """
    end = blob.find(b"\x00", offset)
    if end == -1:
        end = len(blob)
    return blob[offset:end].decode("utf-8", errors="replace")
