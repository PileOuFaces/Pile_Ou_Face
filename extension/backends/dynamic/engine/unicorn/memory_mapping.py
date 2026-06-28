# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from unicorn import UC_PROT_ALL, UcError

from .regs import get_reg_order
from .stack import align_up


def _in_capture_ranges(addr: int, capture_ranges: list[tuple] | None) -> bool:
    if not capture_ranges:
        return True
    return any(start <= addr < end for start, end in capture_ranges)


def _read_word(uc, addr: int, word_size: int) -> int | None:
    try:
        raw = bytes(uc.mem_read(addr, word_size))
    except UcError:
        return None
    return int.from_bytes(raw, "little", signed=False)


def _safe_read_bytes(uc, addr: int, size: int) -> bytes:
    if size <= 0:
        return b""
    try:
        return bytes(uc.mem_read(addr, size))
    except UcError:
        return b""


def _infer_call_target_from_return(uc, ret_addr: int, arch_bits: int) -> int | None:
    # call rel32: E8 xx xx xx xx
    try:
        insn = bytes(uc.mem_read(ret_addr - 5, 5))
    except UcError:
        return None
    if len(insn) != 5 or insn[0] != 0xE8:
        return None
    rel = int.from_bytes(insn[1:], "little", signed=True)
    mask = 0xFFFFFFFFFFFFFFFF if arch_bits == 64 else 0xFFFFFFFF
    return (ret_addr + rel) & mask


def _copy_c_string(uc, src: int, dst: int, max_len: int = 0x20000) -> int | None:
    if src == 0 or dst == 0:
        return None
    copied = 0
    try:
        while copied < max_len:
            byte = bytes(uc.mem_read(src + copied, 1))
            uc.mem_write(dst + copied, byte)
            copied += 1
            if byte == b"\x00":
                break
    except UcError:
        return None
    return copied


def _copy_n_bytes(uc, src: int, dst: int, n: int) -> int | None:
    if src == 0 or dst == 0 or n < 0:
        return None
    if n == 0:
        return 0
    try:
        blob = bytes(uc.mem_read(src, n))
        uc.mem_write(dst, blob)
    except UcError:
        return None
    return n


def _virtual_alloc(uc, state: dict, size: int) -> int | None:
    if size <= 0:
        return None
    arch_bits = int(state.get("arch_bits", 64))
    default_base = 0x60000000 if arch_bits == 32 else 0x600000000000
    base = int(state.get("virtual_heap_next", 0) or default_base)
    map_size = align_up(size, 0x1000)
    try:
        uc.mem_map(base, map_size, UC_PROT_ALL)
    except UcError:
        return None
    state["virtual_heap_next"] = base + map_size
    return base


def _memset_bytes(uc, dst: int, value: int, n: int) -> int | None:
    if dst == 0 or n < 0:
        return None
    if n == 0:
        return 0
    try:
        uc.mem_write(dst, bytes([value & 0xFF]) * n)
    except UcError:
        return None
    return n


def _strlen_at(uc, src: int, max_len: int = 0x20000) -> int | None:
    if src == 0:
        return None
    length = 0
    try:
        while length < max_len:
            byte = bytes(uc.mem_read(src + length, 1))
            if byte == b"\x00":
                return length
            length += 1
    except UcError:
        return None
    return None


def _read_c_string_bytes(uc, addr: int, max_len: int = 0x2000) -> bytes | None:
    if addr == 0:
        return None
    size = _strlen_at(uc, addr, max_len=max_len)
    if size is None:
        return None
    return _safe_read_bytes(uc, addr, size)


def _read_c_string_from_memory(uc, addr: int, max_len: int = 0x2000) -> str | None:
    raw = _read_c_string_bytes(uc, addr, max_len=max_len)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def _bytes_to_hex(data: bytes | bytearray | list[int]) -> str:
    return " ".join(f"{int(byte) & 0xFF:02x}" for byte in bytes(data))


def _hex_opt(value: int | None) -> str | None:
    if value is None:
        return None
    try:
        return hex(int(value))
    except Exception:
        return None


def _read_register_dump(uc, arch_bits: int) -> dict[str, str]:
    dump: dict[str, str] = {}
    for name, reg_id in get_reg_order(arch_bits):
        try:
            dump[name] = hex(int(uc.reg_read(reg_id)))
        except UcError:
            continue
    return dump


def _read_snapshot_registers(snapshot: dict, stage: str = "after") -> dict[str, str]:
    cpu = snapshot.get("cpu") if isinstance(snapshot, dict) else None
    stage_payload = cpu.get(stage) if isinstance(cpu, dict) else None
    registers = (
        stage_payload.get("registers") if isinstance(stage_payload, dict) else None
    )
    return registers if isinstance(registers, dict) else {}
