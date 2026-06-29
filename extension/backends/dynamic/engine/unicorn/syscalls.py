# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Emulate read(0, ...) by injecting configured stdin bytes into guest memory.
# Hooks 32-bit int 0x80 and 64-bit syscall paths and writes return values.
# Advances EIP for int 0x80 reads to skip the interrupt instruction.
# -----------------------------------------------------------------------------

"""@file syscalls.py
@brief Hooks syscall pour l'injection stdin.

@details Emule read(0, ...) pour les chemins 32-bit et 64-bit.
"""

from unicorn.x86_const import (
    UC_X86_REG_EAX,
    UC_X86_REG_EBX,
    UC_X86_REG_ECX,
    UC_X86_REG_EDX,
    UC_X86_REG_EIP,
    UC_X86_REG_RAX,
    UC_X86_REG_RDI,
    UC_X86_REG_RDX,
    UC_X86_REG_RSI,
)


class ReadSyscallEmulator:
    """@class ReadSyscallEmulator
    @brief Emule la syscall read pour stdin.
    @details Ecrit les bytes configures dans la memoire emulee.
    """

    def __init__(self, config) -> None:
        """@brief Initialise l'emulateur de read.
        @param config Configuration de trace.
        """
        self._config = config
        self._stdin_pos = 0

    def _handle_read(self, uc_engine, fd: int, buf: int, count: int) -> int:
        """@brief Ecrit stdin dans un buffer memoire.
        @param uc_engine Instance Unicorn.
        @param fd Descripteur fichier.
        @param buf Adresse buffer.
        @param count Taille demandee.
        @return Nombre de bytes ecrits ou -1.
        """
        # Injecte stdin uniquement sur fd=0, renvoie nb de bytes copiés.
        if fd != 0:
            return -1
        remaining = len(self._config.stdin_data) - self._stdin_pos
        to_copy = min(count, max(remaining, 0))
        if to_copy > 0:
            chunk = self._config.stdin_data[self._stdin_pos : self._stdin_pos + to_copy]
            uc_engine.mem_write(buf, chunk)
            self._stdin_pos += to_copy
        return to_copy

    def hook_intr(self, uc_engine, intno: int, _user_data: object) -> None:
        """@brief Hook 32-bit pour int 0x80.
        @param uc_engine Instance Unicorn.
        @param intno Numero d'interruption.
        @param _user_data Donnees utilisateur (ignore).
        """
        # Chemin 32-bit: int 0x80 avec sys_read = 3.
        if self._config.arch_bits != 32:
            return
        if intno != 0x80:
            return
        syscall_no = uc_engine.reg_read(UC_X86_REG_EAX)
        if syscall_no == 3:  # sys_read
            fd = uc_engine.reg_read(UC_X86_REG_EBX)
            buf = uc_engine.reg_read(UC_X86_REG_ECX)
            count = uc_engine.reg_read(UC_X86_REG_EDX)
            result = self._handle_read(uc_engine, fd, buf, count)
            uc_engine.reg_write(UC_X86_REG_EAX, result)
            eip = uc_engine.reg_read(UC_X86_REG_EIP)
            uc_engine.reg_write(UC_X86_REG_EIP, eip + 2)

    def hook_syscall(self, uc_engine, _user_data: object) -> None:
        """@brief Hook 64-bit pour l'instruction syscall.
        @param uc_engine Instance Unicorn.
        @param _user_data Donnees utilisateur (ignore).
        """
        # Chemin 64-bit: instruction syscall avec sys_read = 0.
        if self._config.arch_bits != 64:
            return
        syscall_no = uc_engine.reg_read(UC_X86_REG_RAX)
        if syscall_no == 0:  # sys_read
            fd = uc_engine.reg_read(UC_X86_REG_RDI)
            buf = uc_engine.reg_read(UC_X86_REG_RSI)
            count = uc_engine.reg_read(UC_X86_REG_RDX)
            result = self._handle_read(uc_engine, fd, buf, count)
            uc_engine.reg_write(UC_X86_REG_RAX, result)
