# SPDX-License-Identifier: AGPL-3.0-only
"""Génère un ELF x86-64 minimal valide pour les tests CI."""

import os
import struct


def make_minimal_elf(path: str) -> None:
    """
    Crée un ELF x86-64 minimal avec une section .text contenant
    des instructions x86-64 réalistes (prologue/épilogue de fonction).
    """
    # Instructions x86-64
    text = bytes(
        [
            0x55,  # push rbp
            0x48,
            0x89,
            0xE5,  # mov rbp, rsp
            0x48,
            0x83,
            0xEC,
            0x10,  # sub rsp, 0x10
            0x48,
            0x89,
            0x7D,
            0xF8,  # mov [rbp-0x8], rdi
            0x8B,
            0x45,
            0xF8,  # mov eax, [rbp-0x8]
            0x31,
            0xC0,  # xor eax, eax
            0xC9,  # leave
            0xC3,  # ret
        ]
    )
    text = text.ljust(0x100, b"\x90")

    e_entry = 0x400078
    e_phoff = 0x40
    text_off = 0x78

    shstrtab = b"\x00.text\x00.shstrtab\x00"
    shstrtab = shstrtab.ljust(0x20, b"\x00")
    shstrtab_off = text_off + len(text)
    e_shoff = shstrtab_off + len(shstrtab)
    e_shnum = 3
    e_shstrndx = 2

    # ELF header (64 bytes)
    ident = (
        b"\x7fELF"
        + bytes(
            [
                2,  # EI_CLASS  = ELFCLASS64
                1,  # EI_DATA   = ELFDATA2LSB
                1,  # EI_VERSION
                0,  # EI_OSABI
            ]
        )
        + b"\x00" * 8
    )

    elf_hdr = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        2,  # ET_EXEC
        0x3E,  # EM_X86_64
        1,  # EV_CURRENT
        e_entry,
        e_phoff,
        e_shoff,
        0,  # e_flags
        0x40,  # e_ehsize
        0x38,  # e_phentsize
        1,  # e_phnum
        0x40,  # e_shentsize
        e_shnum,
        e_shstrndx,
    )

    # Program header PT_LOAD (56 bytes)
    ph = struct.pack(
        "<IIQQQQQQ",
        1,  # PT_LOAD
        5,  # PF_R | PF_X
        text_off,  # p_offset
        e_entry,  # p_vaddr
        e_entry,  # p_paddr
        len(text),  # p_filesz
        len(text),  # p_memsz
        0x200000,  # p_align
    )

    # Section headers
    sh_null = b"\x00" * 0x40

    sh_text = struct.pack(
        "<IIQQQQIIQQ",
        1,  # sh_name  → ".text"
        1,  # SHT_PROGBITS
        6,  # SHF_ALLOC | SHF_EXECINSTR
        e_entry,
        text_off,
        len(text),
        0,
        0,
        16,
        0,
    )

    sh_shstrtab = struct.pack(
        "<IIQQQQIIQQ",
        7,  # sh_name  → ".shstrtab"
        3,  # SHT_STRTAB
        0,
        0,
        shstrtab_off,
        len(shstrtab),
        0,
        0,
        1,
        0,
    )

    content = bytearray(e_shoff + e_shnum * 0x40)
    content[0x00:0x40] = elf_hdr
    content[0x40 : 0x40 + len(ph)] = ph
    content[text_off : text_off + len(text)] = text
    content[shstrtab_off : shstrtab_off + len(shstrtab)] = shstrtab
    content[e_shoff + 0x00 : e_shoff + 0x40] = sh_null
    content[e_shoff + 0x40 : e_shoff + 0x80] = sh_text
    content[e_shoff + 0x80 : e_shoff + 0xC0] = sh_shstrtab

    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "wb") as f:
        f.write(bytes(content))
