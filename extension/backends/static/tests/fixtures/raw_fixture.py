# SPDX-License-Identifier: AGPL-3.0-only
"""Fixtures réutilisables pour les blobs bruts / shellcodes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from backends.static.disasm.disasm import disassemble_with_capstone

RAW_X64_CALL_BLOB = bytes.fromhex("554889e5e807000000c3909090909090554889e5c3")

RAW_ARM64_CALL_BLOB = bytes.fromhex(
    "fd7bbfa9"  # stp x29, x30, [sp, #-0x10]!
    "fd030091"  # mov x29, sp
    "03000094"  # bl #target
    "fd7bc1a8"  # ldp x29, x30, [sp], #0x10
    "c0035fd6"  # ret
    "c0035fd6"  # target: ret
)

RAW_ARM32_CALL_BLOB = bytes.fromhex(
    "00482de9"  # push {fp, lr}
    "04b08de2"  # add fp, sp, #4
    "000000eb"  # bl #target
    "0088bde8"  # pop {fp, pc}
    "1eff2fe1"  # target: bx lr
)

RAW_THUMB_CALL_BLOB = bytes.fromhex(
    "00b5"  # push {lr}
    "00f005f8"  # bl #target
    "00bd"  # pop {pc}
    "00bf"  # nop
    "00bf"  # nop
    "00bf"  # nop
    "00bf"  # nop
    "7047"  # target: bx lr
)

# MIPS32 big-endian: addiu $sp,-8 / sw $ra,4($sp) / jal target /
#   nop / lw $ra,4($sp) / addiu $sp,8 / jr $ra / nop
RAW_MIPS32_BE_CALL_BLOB = bytes.fromhex(
    "27BDFFF8"  # addiu $sp, $sp, -8
    "AFBF0004"  # sw    $ra, 4($sp)
    "0C200006"  # jal   0x800018
    "00000000"  # nop   (delay slot)
    "8FBF0004"  # lw    $ra, 4($sp)
    "27BD0008"  # addiu $sp, $sp, 8
    "03E00008"  # jr    $ra
    "00000000"  # nop   (delay slot)
)

# MIPS32 little-endian: same logic, bytes reversed per word
RAW_MIPS32_LE_CALL_BLOB = bytes.fromhex(
    "F8FFBD27"  # addiu $sp, $sp, -8
    "0400BFAF"  # sw    $ra, 4($sp)
    "0600200C"  # jal   0x800018
    "00000000"  # nop
    "0400BF8F"  # lw    $ra, 4($sp)
    "0800BD27"  # addiu $sp, $sp, 8
    "0800E003"  # jr    $ra
    "00000000"  # nop
)

# PPC32 big-endian: stw r1,-8(r1) / mflr r0 / stw r0,12(r1) / bl target /
#   lwz r0,12(r1) / mtlr r0 / addi r1,r1,8 / blr / blr (target stub)
RAW_PPC32_BE_CALL_BLOB = bytes.fromhex(
    "9021FFF8"  # stw  r1, -8(r1)
    "7C0802A6"  # mflr r0
    "9001000C"  # stw  r0, 0xc(r1)
    "48000015"  # bl   0x900020
    "8001000C"  # lwz  r0, 0xc(r1)
    "7C0803A6"  # mtlr r0
    "38210008"  # addi r1, r1, 8
    "4E800020"  # blr
    "4E800020"  # blr  (target stub at 0x900020)
)

RAW_X64_PROFILE = {
    "arch": "i386:x86-64",
    "base_addr": "0x500000",
    "endian": "little",
}

RAW_ARM64_PROFILE = {
    "arch": "aarch64",
    "base_addr": "0x600000",
    "endian": "little",
}

RAW_ARM32_PROFILE = {
    "arch": "arm",
    "base_addr": "0x700000",
    "endian": "little",
}

RAW_THUMB_PROFILE = {
    "arch": "thumb",
    "base_addr": "0x710000",
    "endian": "little",
}

RAW_THUMB_PARTIAL_PROFILE = {
    "arch": "thumb",
    "base_addr": "0x712340",
    "endian": "little",
}

RAW_MIPS32_BE_PROFILE = {
    "arch": "mips32",
    "base_addr": "0x800000",
    "endian": "big",
}

RAW_PPC32_BE_PARTIAL_PROFILE = {
    "arch": "ppc32",
    "base_addr": "0x902100",
    "endian": "big",
}

RAW_MIPS32_LE_PROFILE = {
    "arch": "mips32",
    "base_addr": "0x800000",
    "endian": "little",
}

RAW_PPC32_BE_PROFILE = {
    "arch": "ppc32",
    "base_addr": "0x900000",
    "endian": "big",
}


def _write_raw_fixture(
    tmpdir: str | Path,
    *,
    stem: str,
    blob: bytes,
    raw_profile: dict[str, str],
    call_site_addr: str,
    target_addr: str,
) -> dict[str, Any]:
    root = Path(tmpdir)
    blob_path = root / f"{stem}.bin"
    mapping_path = root / f"{stem}.mapping.json"
    asm_path = root / f"{stem}.disasm.asm"

    blob_path.write_bytes(blob)
    lines = (
        disassemble_with_capstone(
            str(blob_path),
            raw_arch=raw_profile["arch"],
            raw_base_addr=raw_profile["base_addr"],
            raw_endian=raw_profile["endian"],
        )
        or []
    )

    mapping = {
        "path": str(asm_path),
        "binary": str(blob_path),
        "raw": dict(raw_profile),
        "lines": lines,
    }
    mapping_path.write_text(json.dumps(mapping, indent=2), encoding="utf-8")

    return {
        "blob_path": blob_path,
        "mapping_path": mapping_path,
        "asm_path": asm_path,
        "lines": lines,
        "raw": dict(raw_profile),
        "arch_hint": raw_profile.get("arch"),
        "entry_addr": raw_profile["base_addr"],
        "call_site_addr": call_site_addr,
        "target_addr": target_addr,
    }


def write_raw_x64_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode x86-64 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_x64_call",
        blob=RAW_X64_CALL_BLOB,
        raw_profile=RAW_X64_PROFILE,
        call_site_addr="0x500004",
        target_addr="0x500010",
    )


def write_raw_arm64_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode ARM64 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_arm64_call",
        blob=RAW_ARM64_CALL_BLOB,
        raw_profile=RAW_ARM64_PROFILE,
        call_site_addr="0x600008",
        target_addr="0x600014",
    )


def write_raw_arm32_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode ARM32 brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_arm32_call",
        blob=RAW_ARM32_CALL_BLOB,
        raw_profile=RAW_ARM32_PROFILE,
        call_site_addr="0x700008",
        target_addr="0x700010",
    )


def write_raw_thumb_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode Thumb brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_thumb_call",
        blob=RAW_THUMB_CALL_BLOB,
        raw_profile=RAW_THUMB_PROFILE,
        call_site_addr="0x710002",
        target_addr="0x710010",
    )


def write_raw_thumb_partial_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un dump partiel Thumb avec base virtuelle non triviale."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_thumb_partial_call",
        blob=RAW_THUMB_CALL_BLOB,
        raw_profile=RAW_THUMB_PARTIAL_PROFILE,
        call_site_addr="0x712342",
        target_addr="0x712350",
    )


def write_raw_mips32_be_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode MIPS32 big-endian brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_mips32_be_call",
        blob=RAW_MIPS32_BE_CALL_BLOB,
        raw_profile=RAW_MIPS32_BE_PROFILE,
        call_site_addr="0x800008",
        target_addr="0x800018",
    )


def write_raw_ppc32_be_partial_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un dump partiel PPC32 big-endian avec base virtuelle non triviale."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_ppc32_be_partial_call",
        blob=RAW_PPC32_BE_CALL_BLOB,
        raw_profile=RAW_PPC32_BE_PARTIAL_PROFILE,
        call_site_addr="0x90210c",
        target_addr="0x902120",
    )


def write_raw_mips32_le_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode MIPS32 little-endian brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_mips32_le_call",
        blob=RAW_MIPS32_LE_CALL_BLOB,
        raw_profile=RAW_MIPS32_LE_PROFILE,
        call_site_addr="0x800008",
        target_addr="0x800018",
    )


def write_raw_ppc32_be_call_fixture(tmpdir: str | Path) -> dict[str, Any]:
    """Écrit un petit shellcode PPC32 big-endian brut avec un appel interne."""
    return _write_raw_fixture(
        tmpdir,
        stem="raw_ppc32_be_call",
        blob=RAW_PPC32_BE_CALL_BLOB,
        raw_profile=RAW_PPC32_BE_PROFILE,
        call_site_addr="0x90000c",
        target_addr="0x900020",
    )
