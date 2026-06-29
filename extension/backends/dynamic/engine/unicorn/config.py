# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# TraceConfig dataclass describing Unicorn tracing parameters.
# Captures memory layout, step limits, arch bitness, stdin injection, and start options.
# -----------------------------------------------------------------------------

"""@file config.py
@brief Definitions de configuration pour la trace Unicorn.

@details Decrit les parametres de memoire, limite de pas et options d'init.
"""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass


@dataclass
class TraceConfig:
    """@class TraceConfig
    @brief Regroupe les parametres de trace Unicorn.
    @details Utilise par les fonctions de trace pour initialiser Unicorn.
    """

    # Base address for raw binaries or PIE relocation.
    base: int
    # Base address of the emulated stack mapping.
    stack_base: int
    # Size of the stack mapping in bytes.
    stack_size: int
    # Instruction limit for the trace loop.
    max_steps: int
    # Number of stack words to capture in each snapshot.
    stack_entries: int
    # Architecture bitness for raw binaries.
    arch_bits: int
    # Base address used to map PT_INTERP (ld-linux).
    interp_base: int
    # If true, start execution at the interpreter entrypoint.
    start_interp: bool
    # Bytes injected into read(0, ...) syscalls.
    stdin_data: bytes
    # Optional RBP-relative offset of a buffer to highlight.
    buffer_offset: int | None
    # Size (bytes) of the highlighted buffer.
    buffer_size: int
    # Optional symbol name to start from (e.g. main).
    start_symbol: str | None
    # Optional argv[1] string injected into the initial stack.
    argv1: str | None
    # Optional exact argv[1] bytes. Cannot contain NUL because argv strings are
    # NUL-terminated by the ABI.
    argv1_data: bytes | None = None
    # Optional symbol name to stop at (e.g. win).
    stop_symbol: str | None = None
    # Optional address at which to start recording snapshots (skip loader).
    capture_start_addr: int | None = None
    # Optional hard cap on loader steps before capture starts.
    loader_max_steps: int | None = None
    # Optional list of (start, end) ranges to capture snapshots.
    capture_ranges: Sequence[tuple[int, int]] | None = None
    # Optional address to stop tracing.
    stop_addr: int | None = None
    # Optional memory patches: when RIP hits trigger_rip, write at [RBP+rbp_offset].
    # Third element: int = 32-bit value, bytes = payload (plusieurs octets).
    # Ex: pour stack3, utiliser RIP=0x1000004ab (après mov [rbp-0x14],0) pour voir la valeur avant 1000004ad.
    memory_patches: Sequence[tuple[int, int, int | bytes]] | None = None
    # Optional payload injected at start: (offset_from_initial_sp, bytes).
    # Visible dès le 1er snapshot. Éviter si le programme initialise cette zone ensuite.
    stack_payload: tuple[int, bytes] | None = None
    # Guest path -> file bytes mapping for simulated libc FILE* calls.
    virtual_files: Mapping[str, bytes] | None = None
