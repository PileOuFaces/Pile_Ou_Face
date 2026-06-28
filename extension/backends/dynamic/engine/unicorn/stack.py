# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Stack mapping and initialization helpers for Unicorn emulation.
# Maps a stack region, sets SP/BP, and builds argv/env/auxv layouts.
# Provides alignment helpers for page and word boundaries.
# -----------------------------------------------------------------------------

"""@file stack.py
@brief Utilitaires de pile pour la trace Unicorn.

@details Mappe la pile, aligne, et construit argv/env/auxv.
"""

import contextlib

from unicorn import UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_EBP,
    UC_X86_REG_ESP,
    UC_X86_REG_RBP,
    UC_X86_REG_RSP,
)

from .config import TraceConfig


def _stack_top_headroom(stack_size: int) -> int:
    """Réserve une marge au-dessus du SP initial pour les gros overflows."""
    if stack_size <= 0:
        return 0
    return max(0x1000, min(0x10000, stack_size // 4))


def align_up(value: int, align: int) -> int:
    """@brief Aligne une valeur sur une limite de puissance de deux.
    @param value Valeur a aligner.
    @param align Taille d'alignement.
    @return Valeur alignee.
    """
    return (value + align - 1) & ~(align - 1)


def init_stack(uc, config: TraceConfig) -> int:
    """@brief Mappe la pile et initialise SP/BP.
    @param uc Instance Unicorn.
    @param config Configuration de trace.
    @return Valeur initiale du SP.
    """
    # Mappe la zone pile et positionne SP/BP en haut de la pile.
    uc.mem_map(config.stack_base, config.stack_size, UC_PROT_ALL)
    word_size = 8 if config.arch_bits == 64 else 4
    stack_limit = config.stack_base + config.stack_size
    headroom = _stack_top_headroom(config.stack_size)
    sp = max(config.stack_base + word_size, stack_limit - headroom - word_size)
    if config.arch_bits == 64:
        uc.reg_write(UC_X86_REG_RSP, sp)
        uc.reg_write(UC_X86_REG_RBP, sp)
    else:
        uc.reg_write(UC_X86_REG_ESP, sp)
        uc.reg_write(UC_X86_REG_EBP, sp)
    return sp


def inject_stack_payload(uc, sp: int, config: TraceConfig) -> None:
    """Injecte un payload dans la pile au démarrage (visible dès le 1er snapshot).

    Écrit les octets à l'adresse [sp + offset] avant toute exécution.
    Attention: si le programme initialise ensuite cette zone (ex. mov [rbp-0x14], 0),
    la valeur sera écrasée. Dans ce cas, utiliser memory_patches (Patch at RIP) à une
    adresse après l'initialisation.

    @param uc Instance Unicorn.
    @param sp SP initial (ou après build_initial_stack pour ELF).
    @param config Configuration avec stack_payload = (offset, bytes).
        offset: décalage par rapport à sp (ex. -28 pour [RBP-0x14] après prologue).
    """
    if config.stack_payload is None:
        return
    offset, payload = config.stack_payload
    addr = sp + offset
    with contextlib.suppress(Exception):
        uc.mem_write(addr, payload)


def build_initial_stack(
    uc,
    config: TraceConfig,
    argv: list[str | bytes],
    env: list[str | bytes],
    auxv: list[tuple[int, int]],
) -> int:
    """@brief Construit un layout argc/argv/envp/auxv minimal.
    @param uc Instance Unicorn.
    @param config Configuration de trace.
    @param argv Arguments argv.
    @param env Environnement.
    @param auxv Table auxv.
    @return Nouveau SP.
    """
    # Construit un layout argc/argv/envp/auxv minimal (Linux ABI).
    word_size = 8 if config.arch_bits == 64 else 4
    stack_limit = config.stack_base + config.stack_size
    headroom = _stack_top_headroom(config.stack_size)
    sp = max(config.stack_base + word_size, stack_limit - headroom)

    def push_bytes(data: bytes) -> int:
        """@brief Pousse des bytes bruts sur la pile.
        @param data Donnees a ecrire.
        @return Adresse de debut ecrite.
        """
        nonlocal sp
        sp -= len(data)
        uc.mem_write(sp, data)
        return sp

    def push_ptr(value: int) -> None:
        """@brief Pousse un pointeur sur la pile.
        @param value Valeur a ecrire.
        """
        nonlocal sp
        sp -= word_size
        masked = value & ((1 << (word_size * 8)) - 1)
        uc.mem_write(sp, masked.to_bytes(word_size, "little", signed=False))

    # Place d'abord les chaînes et mémorise leurs pointeurs.
    env_ptrs: list[int] = []
    for item in reversed(env):
        raw = item if isinstance(item, bytes) else item.encode("utf-8", errors="ignore")
        addr = push_bytes(raw + b"\x00")
        env_ptrs.insert(0, addr)

    argv_ptrs: list[int] = []
    for item in reversed(argv):
        raw = item if isinstance(item, bytes) else item.encode("utf-8", errors="ignore")
        addr = push_bytes(raw + b"\x00")
        argv_ptrs.insert(0, addr)

    # Alignement avant les tables de pointeurs.
    sp &= ~(word_size - 1)

    # Table auxv (clé/valeur) puis terminaison AT_NULL.
    push_ptr(0)
    push_ptr(0)
    for key, value in reversed(auxv):
        push_ptr(value)
        push_ptr(key)

    # envp[] puis terminator NULL.
    push_ptr(0)
    for ptr in reversed(env_ptrs):
        push_ptr(ptr)

    # argv[] puis terminator NULL.
    push_ptr(0)
    for ptr in reversed(argv_ptrs):
        push_ptr(ptr)

    # argc.
    push_ptr(len(argv_ptrs))

    # Alignement final du SP.
    sp &= ~(word_size - 1)
    return sp
