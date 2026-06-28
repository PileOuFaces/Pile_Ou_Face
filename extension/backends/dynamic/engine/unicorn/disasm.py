# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Disassemble x86 instruction bytes using Capstone when available.
# Falls back to raw hex if Capstone is missing or no instruction decodes.
# Selects 32/64-bit mode from arch_bits and returns a single-line string.
# -----------------------------------------------------------------------------

"""@file disasm.py
@brief Helpers de desassemblage (Capstone optionnel).

@details Utilise Capstone si present, sinon retourne une sortie hex brute.
"""

import importlib.util
from typing import Any


def capstone_available() -> bool:
    """@brief Indique si Capstone est disponible.
    @return True si le module Capstone est chargeable.
    """
    return importlib.util.find_spec("capstone") is not None


def decode_instruction(code_bytes: bytes, addr: int, arch_bits: int) -> dict[str, Any]:
    """@brief Decode une instruction en format structure.
    @param code_bytes Bytes a desassembler.
    @param addr Adresse de base pour le desassemblage.
    @param arch_bits Bitness CPU (32 ou 64).
    @return Dictionnaire {address,size,bytes,mnemonic,operands,text}.
    """
    if not code_bytes:
        return {
            "address": hex(addr),
            "size": 0,
            "bytes": "",
            "mnemonic": "(no-bytes)",
            "operands": "",
            "text": "(no bytes)",
        }
    if not capstone_available():
        text = code_bytes.hex()
        return {
            "address": hex(addr),
            "size": len(code_bytes),
            "bytes": code_bytes.hex(),
            "mnemonic": text,
            "operands": "",
            "text": text,
        }

    from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, Cs  # type: ignore

    mode = CS_MODE_64 if arch_bits == 64 else CS_MODE_32
    disasm = Cs(CS_ARCH_X86, mode)
    for insn in disasm.disasm(code_bytes, addr):
        return {
            "address": f"0x{insn.address:x}",
            "size": insn.size,
            "bytes": bytes(insn.bytes).hex(),
            "mnemonic": insn.mnemonic,
            "operands": insn.op_str,
            "text": f"{insn.mnemonic} {insn.op_str}".strip(),
        }
    text = code_bytes.hex()
    return {
        "address": hex(addr),
        "size": len(code_bytes),
        "bytes": text,
        "mnemonic": text,
        "operands": "",
        "text": text,
    }


def format_instr(code_bytes: bytes, addr: int, arch_bits: int) -> str:
    """@brief Formate une instruction en texte lisible.
    @param code_bytes Bytes a desassembler.
    @param addr Adresse de base pour le desassemblage.
    @param arch_bits Bitness CPU (32 ou 64).
    @return Chaine mnemonique ou hex brut.
    """
    return decode_instruction(code_bytes, addr, arch_bits)["text"]
