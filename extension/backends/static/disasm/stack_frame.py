# SPDX-License-Identifier: AGPL-3.0-only
"""Analyse de stack frame avec support frame-pointer-less, ARM64/ARM32 et args registres."""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Allow running as a script directly (not only via `python -m`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.shared.exceptions import BinaryNotFoundError, BinaryParseError
from backends.static.binary.arch import ABI_ARG_REGISTERS, ArchInfo, detect_binary_arch
from backends.static.cache.cache import DisasmCache, default_cache_path

try:
    import capstone
except ImportError:
    capstone = None

try:
    import lief
except ImportError:
    lief = None


STACK_FRAME_CACHE_VERSION = 5
X86_STACK_RE = re.compile(
    r"\[(rbp|ebp|rsp|esp)(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?\]",
    re.IGNORECASE,
)
ARM64_STACK_RE = re.compile(
    r"\[(x29|sp)(?:\s*,\s*#?(-?0x[0-9a-fA-F]+|-?\d+))?\]",
    re.IGNORECASE,
)
ARM32_STACK_RE = re.compile(
    r"\[(r11|fp|sp)(?:\s*,\s*#?(-?0x[0-9a-fA-F]+|-?\d+))?\]",
    re.IGNORECASE,
)
OFFSET_BASE_STACK_RE = re.compile(
    r"(-?0x[0-9a-fA-F]+|-?\d+)\s*\(\s*(\$?sp|\$?fp|\$?s8|sp|fp|s0|r1|r15|a10)\s*\)",
    re.IGNORECASE,
)
SPARC_STACK_RE = re.compile(
    r"\[\s*%?(sp|fp|o6|i6)(?:\s*([+-])\s*(0x[0-9a-fA-F]+|\d+))?\s*\]",
    re.IGNORECASE,
)


X86_REGISTER_ALIASES: dict[str, tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
    "r10": ("r10", "r10d", "r10w", "r10b"),
    "r11": ("r11", "r11d", "r11w", "r11b"),
    "r12": ("r12", "r12d", "r12w", "r12b"),
    "r13": ("r13", "r13d", "r13w", "r13b"),
    "r14": ("r14", "r14d", "r14w", "r14b"),
    "r15": ("r15", "r15d", "r15w", "r15b"),
}


def _register_aliases(reg: str) -> tuple[str, ...]:
    normalized = str(reg or "").strip().lower()
    if not normalized:
        return ()
    if normalized in X86_REGISTER_ALIASES:
        return X86_REGISTER_ALIASES[normalized]
    if normalized.startswith("x") and normalized[1:].isdigit():
        suffix = normalized[1:]
        return (normalized, f"w{suffix}")
    if normalized.startswith("w") and normalized[1:].isdigit():
        suffix = normalized[1:]
        return (f"x{suffix}", normalized)
    if normalized.startswith("r") and normalized[1:].isdigit():
        suffix = normalized[1:]
        return (normalized, f"e{suffix}" if suffix.isdigit() else normalized)
    return (normalized,)


def _get_arch_info(binary) -> ArchInfo | None:
    return detect_binary_arch(binary)


def _get_arch_mode(binary) -> tuple[int, int] | None:
    """Return (capstone_arch, capstone_mode) for the binary, or None if unsupported."""
    info = _get_arch_info(binary)
    return info.capstone_tuple if info else None


def _detect_abi(binary) -> tuple[str, int, str]:
    """Retourne (arch_family, ptr_size, abi_name)."""
    info = _get_arch_info(binary)
    if info is None:
        return ("unknown", 8, "unknown")
    return (info.family, info.ptr_size, info.abi)


def _get_code_bytes(binary, start_addr: int) -> tuple[bytes, int] | None:
    """Find the code bytes starting at start_addr within the binary."""
    sections = []
    if lief and isinstance(binary, lief.PE.Binary):
        base = binary.optional_header.imagebase
        for sec in binary.sections:
            va = sec.virtual_address + base
            size = sec.size
            if va <= start_addr < va + size:
                return bytes(sec.content)[start_addr - va :], start_addr
        return None

    if (
        lief
        and isinstance(binary, lief.ELF.Binary)
        or lief
        and isinstance(binary, lief.MachO.Binary)
    ):
        sections = list(binary.sections)

    for sec in sections:
        va = sec.virtual_address
        content = bytes(sec.content)
        if content and va <= start_addr < va + len(content):
            return content[start_addr - va :], start_addr
    return None


def _cache_key(func_addr: int) -> str:
    return f"0x{func_addr:x}"


def _parse_int(value: str) -> int | None:
    value = str(value).strip().lower()
    if not value:
        return None
    try:
        return (
            int(value, 16)
            if value.startswith("0x") or value.startswith("-0x")
            else int(value)
        )
    except ValueError:
        return None


def _format_stack_location(base_reg: str, raw_offset: int) -> str:
    if raw_offset == 0:
        return f"[{base_reg}]"
    sign = "+" if raw_offset > 0 else "-"
    value = abs(raw_offset)
    return f"[{base_reg}{sign}0x{value:x}]"


def _canonical_frame_base(base_reg: str) -> str:
    normalized = str(base_reg or "").strip().lower()
    normalized = normalized.lstrip("$%")
    if normalized in {"fp", "s8", "s0", "i6"}:
        return "r11"
    if normalized == "o6":
        return "sp"
    if normalized == "r1":
        return "sp"
    if normalized in {"r15", "a10"}:
        return "sp"
    return normalized


def _stack_arg_start_offset(
    base_reg: str, arch_family: str, ptr_size: int, abi_name: str
) -> int:
    base = _canonical_frame_base(base_reg)
    if base in {"rbp", "ebp", "rsp", "esp"}:
        if abi_name == "win64":
            return 0x30
        return ptr_size * 2
    if arch_family == "arm" and base in {"r11", "fp"}:
        return ptr_size * 2
    if arch_family == "arm64" and base == "x29":
        return 0x10
    if base == "sp":
        return 0
    return ptr_size * 2


def _parse_stack_access(op_str: str, arch_family: str) -> tuple[str, int, str] | None:
    if arch_family == "arm64":
        matcher = ARM64_STACK_RE
    elif arch_family == "arm":
        matcher = ARM32_STACK_RE
    elif arch_family == "sparc":
        match = SPARC_STACK_RE.search(op_str)
        if not match:
            return None
        base_reg = _canonical_frame_base(match.group(1).lower())
        sign = match.group(2)
        raw = match.group(3) or "0"
        if sign == "-":
            raw = f"-{raw}"
        offset = _parse_int(raw)
        if offset is None:
            return None
        return base_reg, offset, _format_stack_location(base_reg, offset)
    elif arch_family in {"mips", "ppc", "riscv", "sh", "tricore"}:
        match = OFFSET_BASE_STACK_RE.search(op_str)
        if not match:
            return None
        raw = match.group(1) or "0"
        base_reg = _canonical_frame_base(match.group(2).lower())
        offset = _parse_int(raw)
        if offset is None:
            return None
        return base_reg, offset, _format_stack_location(base_reg, offset)
    else:
        matcher = X86_STACK_RE
    match = matcher.search(op_str)
    if not match:
        return None
    base_reg = _canonical_frame_base(match.group(1).lower())
    if arch_family in {"arm64", "arm"}:
        raw = match.group(2) or "0"
    else:
        sign = match.group(2)
        raw = match.group(3) or "0"
        if sign == "-":
            raw = f"-{raw}"
    offset = _parse_int(raw)
    if offset is None:
        return None
    return base_reg, offset, _format_stack_location(base_reg, offset)


def _size_from_instruction(ins, ptr_size: int) -> int:
    """Déduit la taille mémoire manipulée."""
    op_lower = ins.op_str.lower()
    if "xmmword" in op_lower:
        return 16
    if "qword" in op_lower:
        return 8
    if "dword" in op_lower:
        return 4
    if re.search(r"\bword\b", op_lower):
        return 2
    if "byte" in op_lower:
        return 1
    if ins.mnemonic.lower() in {"stp", "ldp"}:
        return 16 if "x" in op_lower else 8
    if re.search(r"\bw\d+\b", op_lower):
        return 4
    if re.search(r"\bx\d+\b", op_lower):
        return 8
    return ptr_size


def _preindexed_sp_delta(op_str: str) -> int:
    match = re.search(r"\[sp\s*,\s*#-?(0x[0-9a-fA-F]+|\d+)\]!", op_str, re.IGNORECASE)
    if not match:
        return 0
    value = _parse_int(match.group(1))
    return abs(value or 0)


def _register_list_count(op_str: str) -> int:
    match = re.search(r"\{([^}]+)\}", op_str)
    if not match:
        return 0
    total = 0
    for chunk in match.group(1).split(","):
        token = chunk.strip().lower()
        if not token:
            continue
        if "-" in token:
            start, end = [part.strip() for part in token.split("-", 1)]
            start_match = re.fullmatch(r"([a-z]+)(\d+)", start)
            end_match = re.fullmatch(r"([a-z]+)(\d+)", end)
            if start_match and end_match and start_match.group(1) == end_match.group(1):
                total += abs(int(end_match.group(2)) - int(start_match.group(2))) + 1
                continue
        total += 1
    return total


def _extract_frame_pointer_anchor(
    ins, arch_family: str, stack_adjust: int
) -> tuple[str, int] | None:
    mnem = ins.mnemonic.lower()
    op_str = ins.op_str.lower()

    if arch_family == "arm64":
        if mnem == "mov" and re.fullmatch(r"x29\s*,\s*sp", op_str):
            return ("x29", stack_adjust)
        if mnem == "add":
            match = re.fullmatch(r"x29\s*,\s*sp\s*,\s*#?(0x[0-9a-f]+|\d+)", op_str)
            if match:
                imm = _parse_int(match.group(1)) or 0
                return ("x29", max(0, stack_adjust - imm))
        return None

    if arch_family == "arm":
        if mnem == "mov" and re.fullmatch(r"(r11|fp)\s*,\s*sp", op_str):
            return ("r11", stack_adjust)
        if mnem == "add":
            match = re.fullmatch(r"(r11|fp)\s*,\s*sp\s*,\s*#?(0x[0-9a-f]+|\d+)", op_str)
            if match:
                imm = _parse_int(match.group(2)) or 0
                return ("r11", max(0, stack_adjust - imm))
        return None

    return None


def _postindexed_sp_delta(op_str: str) -> int:
    match = re.search(r"\[sp\]\s*,\s*#(0x[0-9a-fA-F]+|\d+)", op_str, re.IGNORECASE)
    if not match:
        return 0
    return _parse_int(match.group(1)) or 0


def _split_operands(op_str: str) -> list[str]:
    return [part.strip().lower() for part in str(op_str or "").split(",")]


def _is_x86_stack_pointer(operand: str) -> bool:
    return operand.strip().lower() in {"rsp", "esp"}


def _x86_alignment_from_and_mask(mask: int | None, ptr_size: int) -> int | None:
    if mask is None:
        return None
    if mask < 0:
        alignment = abs(mask)
    else:
        bit_mask = (1 << (ptr_size * 8)) - 1
        normalized = mask & bit_mask
        alignment = normalized & -normalized
    if alignment <= 1 or alignment > 0x1000:
        return None
    if alignment & (alignment - 1):
        return None
    return alignment


def _round_up(value: int, alignment: int) -> int:
    if alignment <= 0:
        return value
    return ((value + alignment - 1) // alignment) * alignment


def _update_x86_stack_adjust_state(
    stack_adjust: int, stack_adjust_known: bool, ins, ptr_size: int
) -> tuple[int, bool]:
    """Track x86 stack pointer movement.

    ``stack_adjust_known`` becomes false after dynamic alloca-style updates
    such as ``sub rsp, rax``. In that state the current frame size still keeps
    a safe lower bound, but rsp-relative accesses are too ambiguous to classify.
    """
    mnem = ins.mnemonic.lower()
    op_str = ins.op_str.lower()
    operands = _split_operands(op_str)
    dst = operands[0] if operands else ""

    if mnem == "push":
        return stack_adjust + ptr_size, stack_adjust_known
    if mnem == "pop":
        return max(0, stack_adjust - ptr_size), stack_adjust_known
    if mnem == "leave":
        return 0, True
    if mnem == "mov" and len(operands) >= 2 and operands[0] in {"rsp", "esp"}:
        if operands[1] in {"rbp", "ebp"}:
            return 0, True
        return stack_adjust, False

    if not _is_x86_stack_pointer(dst):
        return stack_adjust, stack_adjust_known

    if mnem in {"sub", "add"}:
        imm = _parse_int(operands[-1]) if len(operands) >= 2 else None
        if imm is None:
            return stack_adjust, False
        if mnem == "sub":
            return stack_adjust + imm, stack_adjust_known
        return max(0, stack_adjust - imm), stack_adjust_known

    if mnem == "and":
        mask = _parse_int(operands[-1]) if len(operands) >= 2 else None
        alignment = _x86_alignment_from_and_mask(mask, ptr_size)
        if alignment is None:
            return stack_adjust, False
        if not stack_adjust_known:
            return stack_adjust, False
        return _round_up(stack_adjust, alignment), True

    if mnem == "lea":
        access = _parse_stack_access(op_str, "x86")
        if not access:
            return stack_adjust, False
        base_reg, raw_offset, _location = access
        if base_reg not in {"rsp", "esp"}:
            return stack_adjust, False
        if raw_offset < 0:
            return stack_adjust + abs(raw_offset), stack_adjust_known
        return max(0, stack_adjust - raw_offset), stack_adjust_known

    return stack_adjust, stack_adjust_known


def _update_arm64_stack_adjust_state(
    stack_adjust: int, stack_adjust_known: bool, ins
) -> tuple[int, bool]:
    """Track ARM64 stack pointer movement.

    Static prologue/epilogue patterns keep a precise adjustment. Dynamic
    alloca-style updates such as ``sub sp, sp, x8`` keep the current value as a
    lower bound and mark subsequent sp-relative accesses as ambiguous.
    """
    mnem = ins.mnemonic.lower()
    op_str = ins.op_str.lower()

    if mnem == "mov" and re.fullmatch(r"sp\s*,\s*x29", op_str):
        return 0, True

    if mnem in {"sub", "add"} and op_str.startswith("sp, sp"):
        imm = _parse_int(op_str.split(",")[-1].strip().lstrip("#"))
        if imm is None:
            return stack_adjust, False
        if mnem == "sub":
            return stack_adjust + imm, stack_adjust_known
        return max(0, stack_adjust - imm), stack_adjust_known

    if mnem == "add":
        match = re.fullmatch(r"sp\s*,\s*x29\s*,\s*#?(0x[0-9a-f]+|\d+)", op_str)
        if match:
            return _parse_int(match.group(1)) or 0, True

    if mnem in {"stp", "str"}:
        delta = _preindexed_sp_delta(op_str)
        if delta:
            return stack_adjust + delta, stack_adjust_known
    if mnem in {"ldp", "ldr"}:
        delta = _postindexed_sp_delta(op_str)
        if delta:
            return max(0, stack_adjust - delta), stack_adjust_known
    return stack_adjust, stack_adjust_known


def _update_stack_adjust(
    stack_adjust: int, ins, arch_family: str, ptr_size: int
) -> int:
    """Met à jour l'ajustement courant du stack pointer depuis l'entrée de fonction."""
    mnem = ins.mnemonic.lower()
    op_str = ins.op_str.lower()

    if arch_family == "x86":
        updated, _known = _update_x86_stack_adjust_state(
            stack_adjust, True, ins, ptr_size
        )
        return updated

    if arch_family == "arm64":
        updated, _known = _update_arm64_stack_adjust_state(stack_adjust, True, ins)
        return updated

    if arch_family == "arm":
        if mnem == "push":
            reg_count = _register_list_count(op_str)
            if reg_count:
                return stack_adjust + (reg_count * ptr_size)
        if mnem == "pop":
            reg_count = _register_list_count(op_str)
            if reg_count:
                return max(0, stack_adjust - (reg_count * ptr_size))
        if mnem == "stmdb" and op_str.startswith("sp!"):
            reg_count = _register_list_count(op_str)
            if reg_count:
                return stack_adjust + (reg_count * ptr_size)
        if mnem in {"ldmia", "ldm"} and (
            op_str.startswith("sp!") or op_str.startswith("sp,")
        ):
            reg_count = _register_list_count(op_str)
            if reg_count:
                return max(0, stack_adjust - (reg_count * ptr_size))
        if mnem == "sub" and op_str.startswith("sp, sp"):
            imm = _parse_int(op_str.split(",")[-1].strip().lstrip("#"))
            if imm:
                return stack_adjust + imm
        if mnem == "add" and op_str.startswith("sp, sp"):
            imm = _parse_int(op_str.split(",")[-1].strip().lstrip("#"))
            if imm:
                return max(0, stack_adjust - imm)
        return stack_adjust

    if arch_family == "riscv":
        if mnem in {"addi", "addiw"} and op_str.startswith("sp, sp"):
            imm = _parse_int(op_str.split(",")[-1].strip())
            if imm is not None:
                return (
                    stack_adjust + abs(imm) if imm < 0 else max(0, stack_adjust - imm)
                )
        return stack_adjust

    if arch_family == "mips":
        if mnem in {"addiu", "addi", "daddiu"} and re.match(
            r"\$?sp\s*,\s*\$?sp\s*,", op_str
        ):
            imm = _parse_int(op_str.split(",")[-1].strip())
            if imm is not None:
                return (
                    stack_adjust + abs(imm) if imm < 0 else max(0, stack_adjust - imm)
                )
        return stack_adjust

    if arch_family == "ppc":
        if mnem in {"stwu", "stdu"}:
            match = re.search(r"(-?0x[0-9a-fA-F]+|-?\d+)\s*\(\s*r?1\s*\)", op_str)
            if match:
                imm = _parse_int(match.group(1))
                if imm is not None and imm < 0:
                    return stack_adjust + abs(imm)
        if mnem in {"addi", "addis"} and re.match(r"r?1\s*,\s*r?1\s*,", op_str):
            imm = _parse_int(op_str.split(",")[-1].strip())
            if imm is not None:
                return (
                    stack_adjust + abs(imm) if imm < 0 else max(0, stack_adjust - imm)
                )
        return stack_adjust

    if arch_family == "sparc":
        if mnem == "save":
            parts = [part.strip().lstrip("%") for part in op_str.split(",")]
            if len(parts) >= 2 and parts[0] in {"sp", "o6"}:
                imm = _parse_int(parts[1])
                if imm is not None and imm < 0:
                    return stack_adjust + abs(imm)
        if mnem == "restore":
            return 0
        return stack_adjust

    return stack_adjust


def _is_register_arg_used(instrs: list, reg: str) -> bool:
    aliases = _register_aliases(reg)
    if not aliases:
        return False
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(alias) for alias in aliases) + r")\b",
        re.IGNORECASE,
    )
    for ins in instrs[:32]:
        op_str = ins.op_str.lower()
        if pattern.search(op_str):
            return True
        if ins.mnemonic.lower() in {"ret", "retn"}:
            break
    return False


def _infer_register_args(
    instrs: list, abi_name: str, ptr_size: int, arch_info: ArchInfo | None = None
) -> list[dict]:
    regs = (
        arch_info.arg_registers
        if arch_info is not None
        else ABI_ARG_REGISTERS.get(abi_name, ())
    )
    args = []
    for reg in regs:
        if not _is_register_arg_used(instrs, reg):
            continue
        args.append(
            {
                "name": f"arg_{reg}",
                "offset": None,
                "size": ptr_size,
                "source": "abi",
                "location": reg,
            }
        )
    return args


def _classify_stack_access(
    base_reg: str,
    raw_offset: int,
    location: str,
    *,
    arch_family: str,
    abi_name: str,
    stack_adjust: int,
    ptr_size: int,
    frame_arg_starts: dict[str, int] | None = None,
) -> tuple[str, int, str] | None:
    """Retourne (kind, normalized_offset, location) pour var/arg ou None."""
    canonical_base = _canonical_frame_base(base_reg)
    frame_arg_starts = frame_arg_starts or {}
    arg_start = frame_arg_starts.get(
        canonical_base,
        _stack_arg_start_offset(canonical_base, arch_family, ptr_size, abi_name),
    )
    if base_reg in {"rbp", "ebp", "x29", "r11", "fp"}:
        if raw_offset < 0:
            return ("var", raw_offset, location)
        if raw_offset >= arg_start:
            return ("arg", raw_offset, location)
        return None

    if base_reg in {"rsp", "esp", "sp"}:
        normalized = raw_offset - stack_adjust
        if normalized < 0:
            return ("var", normalized, location)
        if arch_family == "x86":
            arg_offset = raw_offset - stack_adjust + ptr_size
            if arg_offset >= arg_start:
                return ("arg", arg_offset, location)
            return None
        if normalized >= 0:
            return ("arg", normalized, location)
        return None

    return None


def _merge_stack_entry(entries: dict[tuple[str, str], dict], entry: dict) -> None:
    key = (entry["kind"], entry["location"])
    existing = entries.get(key)
    if existing is None or entry["size"] > existing["size"]:
        entries[key] = entry


def analyse_stack_frame(binary_path: str, func_addr: int) -> dict:
    """Analyse the stack frame of the function at func_addr."""
    if not Path(binary_path).exists():
        raise BinaryNotFoundError(f"Binary not found: {binary_path}")

    cache_addr = _cache_key(func_addr)
    try:
        with DisasmCache(default_cache_path(binary_path)) as cache:
            cached = cache.get_stack_frame(binary_path, cache_addr)
            if (
                cached is not None
                and cached.get("version") == STACK_FRAME_CACHE_VERSION
            ):
                return cached
    except Exception:
        pass

    result: dict = {
        "version": STACK_FRAME_CACHE_VERSION,
        "func_addr": cache_addr,
        "frame_size": 0,
        "vars": [],
        "args": [],
        "arch": "unknown",
        "abi": "unknown",
    }

    if not lief or not capstone:
        return result

    try:
        binary = lief.parse(binary_path)
        if binary is None:
            raise BinaryParseError(f"lief could not parse: {binary_path}")
    except (BinaryNotFoundError, BinaryParseError):
        raise
    except Exception as exc:
        raise BinaryParseError(f"Failed to parse: {binary_path}") from exc

    arch_info = _get_arch_info(binary)
    arch_mode = _get_arch_mode(binary)
    if not arch_mode:
        return result

    arch_family, ptr_size, abi_name = _detect_abi(binary)
    result["arch"] = arch_family
    result["abi"] = abi_name

    code_data = _get_code_bytes(binary, func_addr)
    if not code_data:
        return result

    code_bytes, base_addr = code_data
    md = capstone.Cs(*arch_mode)
    md.detail = True
    instrs = list(md.disasm(code_bytes, base_addr))[:512]

    stack_adjust = 0
    stack_adjust_known = True
    frame_size = 0
    stack_entries: dict[tuple[str, str], dict] = {}
    frame_arg_starts: dict[str, int] = {}

    for ins in instrs:
        mnem = ins.mnemonic.lower()
        if mnem in {"ret", "retn", "retq"}:
            break

        if arch_family == "x86":
            stack_adjust, stack_adjust_known = _update_x86_stack_adjust_state(
                stack_adjust, stack_adjust_known, ins, ptr_size
            )
        elif arch_family == "arm64":
            stack_adjust, stack_adjust_known = _update_arm64_stack_adjust_state(
                stack_adjust, stack_adjust_known, ins
            )
        else:
            stack_adjust = _update_stack_adjust(
                stack_adjust, ins, arch_family, ptr_size
            )
        frame_size = max(frame_size, stack_adjust)
        frame_anchor = _extract_frame_pointer_anchor(ins, arch_family, stack_adjust)
        if frame_anchor:
            base_reg, arg_start = frame_anchor
            frame_arg_starts[base_reg] = arg_start

        if mnem in {"push", "pop", "stp", "ldp"}:
            continue

        access = _parse_stack_access(ins.op_str, arch_family)
        if not access:
            continue

        base_reg, raw_offset, location = access
        if (
            arch_family in {"x86", "arm64"}
            and not stack_adjust_known
            and _canonical_frame_base(base_reg) in {"rsp", "esp", "sp"}
        ):
            continue
        classified = _classify_stack_access(
            base_reg,
            raw_offset,
            location,
            arch_family=arch_family,
            abi_name=abi_name,
            stack_adjust=stack_adjust,
            ptr_size=ptr_size,
            frame_arg_starts=frame_arg_starts,
        )
        if not classified:
            continue

        kind, normalized_offset, normalized_location = classified
        name_prefix = "var" if kind == "var" else "arg"
        auto_suffix = (
            f"{abs(normalized_offset):x}"
            if normalized_offset is not None
            else normalized_location.replace("[", "")
            .replace("]", "")
            .replace("+", "_")
            .replace("-", "_")
        )
        _merge_stack_entry(
            stack_entries,
            {
                "kind": kind,
                "name": f"{name_prefix}_{auto_suffix}",
                "offset": normalized_offset,
                "size": _size_from_instruction(ins, ptr_size),
                "source": "auto",
                "location": normalized_location,
            },
        )

    result["frame_size"] = frame_size

    args_list = _infer_register_args(instrs, abi_name, ptr_size, arch_info=arch_info)
    vars_list = []
    stack_args = []

    for entry in sorted(
        stack_entries.values(),
        key=lambda item: (
            item["kind"],
            item["offset"] if item["offset"] is not None else 0,
            item["location"],
        ),
    ):
        item = {
            "name": entry["name"],
            "offset": entry["offset"],
            "size": entry["size"],
            "source": entry["source"],
            "location": entry["location"],
        }
        if entry["kind"] == "var":
            vars_list.append(item)
        else:
            stack_args.append(item)

    result["vars"] = sorted(
        vars_list,
        key=lambda value: value["offset"] if value["offset"] is not None else 0,
    )
    result["args"] = args_list + sorted(
        stack_args,
        key=lambda value: value["offset"] if value["offset"] is not None else 0,
    )

    try:
        with DisasmCache(default_cache_path(binary_path)) as cache:
            cache.save_stack_frame(binary_path, result)
    except Exception:
        pass

    return result


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(description="Stack frame analyser")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument(
        "--addr", required=True, help="Function address (hex or decimal)"
    )
    args = parser.parse_args()

    if not lief:
        print(
            json.dumps({"error": "lief not installed. Install with: pip install lief"})
        )
        return 1
    if not capstone:
        print(
            json.dumps(
                {"error": "capstone not installed. Install with: pip install capstone"}
            )
        )
        return 1

    try:
        addr = int(args.addr, 16) if args.addr.startswith("0x") else int(args.addr)
        result = analyse_stack_frame(args.binary, addr)
    except BinaryNotFoundError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except BinaryParseError as exc:
        print(json.dumps({"error": str(exc)}))
        return 1
    except Exception as exc:
        print(json.dumps({"error": str(exc)}))
        return 1

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
