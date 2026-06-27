# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Define x86 register ordering for snapshot display in 32-bit and 64-bit modes.
# Expose get_reg_order and get_pc_sp to locate IP/SP registers per architecture.
# -----------------------------------------------------------------------------

"""@file regs.py
@brief Definitions des registres x86 et helpers associes.

@details Fournit l'ordre d'affichage et l'identification PC/SP par architecture.
"""

from typing import List, Tuple

from unicorn.x86_const import (
    UC_X86_REG_RAX,
    UC_X86_REG_RBX,
    UC_X86_REG_RCX,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
    UC_X86_REG_RDI,
    UC_X86_REG_RBP,
    UC_X86_REG_RSP,
    UC_X86_REG_RIP,
    UC_X86_REG_R8,
    UC_X86_REG_R9,
    UC_X86_REG_R10,
    UC_X86_REG_R11,
    UC_X86_REG_R12,
    UC_X86_REG_R13,
    UC_X86_REG_R14,
    UC_X86_REG_R15,
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_ESI,
    UC_X86_REG_EDI,
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_EIP,
)

REG_ORDER_64: List[Tuple[str, int]] = [
    ("rax", UC_X86_REG_RAX),
    ("rbx", UC_X86_REG_RBX),
    ("rcx", UC_X86_REG_RCX),
    ("rdx", UC_X86_REG_RDX),
    ("rsi", UC_X86_REG_RSI),
    ("rdi", UC_X86_REG_RDI),
    ("rbp", UC_X86_REG_RBP),
    ("rsp", UC_X86_REG_RSP),
    ("rip", UC_X86_REG_RIP),
    ("r8", UC_X86_REG_R8),
    ("r9", UC_X86_REG_R9),
    ("r10", UC_X86_REG_R10),
    ("r11", UC_X86_REG_R11),
    ("r12", UC_X86_REG_R12),
    ("r13", UC_X86_REG_R13),
    ("r14", UC_X86_REG_R14),
    ("r15", UC_X86_REG_R15),
]

REG_ORDER_32: List[Tuple[str, int]] = [
    ("eax", UC_X86_REG_EAX),
    ("ebx", UC_X86_REG_EBX),
    ("ecx", UC_X86_REG_ECX),
    ("edx", UC_X86_REG_EDX),
    ("esi", UC_X86_REG_ESI),
    ("edi", UC_X86_REG_EDI),
    ("ebp", UC_X86_REG_EBP),
    ("esp", UC_X86_REG_ESP),
    ("eip", UC_X86_REG_EIP),
]


def get_reg_order(arch_bits: int) -> List[Tuple[str, int]]:
    """@brief Retourne l'ordre d'affichage des registres.
    @param arch_bits Bitness CPU (32 ou 64).
    @return Liste des couples (nom, id Unicorn).
    """
    return REG_ORDER_64 if arch_bits == 64 else REG_ORDER_32


def get_pc_sp(arch_bits: int) -> tuple:
    """@brief Retourne les registres PC et SP.
    @param arch_bits Bitness CPU (32 ou 64).
    @return Tuple (pc_reg, sp_reg).
    """
    if arch_bits == 64:
        return UC_X86_REG_RIP, UC_X86_REG_RSP
    return UC_X86_REG_EIP, UC_X86_REG_ESP


def get_rbp(arch_bits: int) -> int:
    """@brief Retourne le registre RBP/EBP.
    @param arch_bits Bitness CPU (32 ou 64).
    @return Id Unicorn du registre frame pointer.
    """
    return UC_X86_REG_RBP if arch_bits == 64 else UC_X86_REG_EBP
