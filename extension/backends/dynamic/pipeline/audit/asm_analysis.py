# SPDX-License-Identifier: AGPL-3.0-only
"""Assembly evidence extraction for Run Trace audits."""

from __future__ import annotations

import re
import shutil
import subprocess
from typing import Optional

STACK_RELEVANT_CALLS = {
    "strcpy",
    "read",
    "scanf",
    "fgets",
    "gets",
    "memcpy",
    "memmove",
    "printf",
}

BUFFER_PROOF_SINKS = {
    "strcpy": 0,
    "gets": 0,
    "fgets": 0,
    "read": 1,
    "scanf": 1,
    "memcpy": 0,
    "memmove": 0,
}

X86_64_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")


def safe_int(value) -> Optional[int]:
    try:
        if value is None:
            return None
        if isinstance(value, str):
            return int(value, 0)
        return int(value)
    except Exception:
        return None


def safe_hex(value) -> Optional[str]:
    parsed = safe_int(value)
    return hex(parsed) if parsed is not None else None


def line_addr(line: dict) -> Optional[int]:
    return safe_int(line.get("addr")) if isinstance(line, dict) else None


def function_ranges(functions: list[dict]) -> list[dict]:
    ranges = []
    parsed = []
    for fn in functions:
        addr = safe_int(fn.get("addr"))
        if addr is None:
            continue
        parsed.append((addr, safe_int(fn.get("size")), fn))
    parsed.sort(key=lambda item: item[0])
    for index, (addr, size, fn) in enumerate(parsed):
        next_addr = parsed[index + 1][0] if index + 1 < len(parsed) else None
        end = addr + size if size and size > 0 else next_addr
        if next_addr is not None and end is not None:
            end = min(end, next_addr)
        ranges.append({"start": addr, "end": end, "function": fn})
    return ranges


def function_for_addr(ranges: list[dict], addr: Optional[int]) -> Optional[dict]:
    if addr is None:
        return None
    for entry in ranges:
        start = entry.get("start")
        end = entry.get("end")
        if start is None or addr < start:
            continue
        if end is None or addr < end:
            return entry.get("function")
    return None


def audit_plt_symbols(binary_path: str) -> dict[int, str]:
    if not shutil.which("objdump"):
        return {}
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return {}
    if result.returncode != 0:
        return {}
    out: dict[int, str] = {}
    pattern = re.compile(r"^\s*([0-9a-fA-F]+)\s+<([^>]+)@plt(?:\.sec)?>:")
    for line in result.stdout.splitlines():
        match = pattern.match(line)
        if not match:
            continue
        addr = safe_int(f"0x{match.group(1)}")
        if addr is not None:
            out[addr] = match.group(2)
    return out


def stack_accesses_from_operands(operands: str) -> list[dict]:
    out = []
    pattern = r"\[(r(?:b|s)p|e(?:b|s)p)\s*([+-])?\s*(0x[0-9a-fA-F]+|\d+)?[^\]]*\]"
    for match in re.finditer(pattern, operands):
        base = match.group(1).lower()
        sign = match.group(2) or "+"
        raw_offset = match.group(3) or "0"
        offset = safe_int(raw_offset) or 0
        if sign == "-":
            offset = -offset
        out.append({"base": base, "offset": offset, "expression": match.group(0)})
    return out


def call_target_name(operands: str, plt_symbols: dict[int, str]) -> Optional[str]:
    normalized = re.sub(r"\s+", "", operands.lower())
    name = re.sub(r"^.*<([^>@]+)(?:@[^>]*)?>.*$", r"\1", normalized)
    if name != normalized:
        return name
    target = safe_int(normalized)
    if target is not None:
        return plt_symbols.get(target)
    return None


def instruction_kind(line: dict, plt_symbols: dict[int, str]) -> Optional[str]:
    mnemonic = str(line.get("mnemonic") or "").strip().lower()
    operands = str(line.get("operands") or "").strip()
    normalized_operands = re.sub(r"\s+", "", operands.lower())
    if mnemonic in {"sub", "add"} and re.match(r"^(rsp|esp),", normalized_operands):
        return f"{mnemonic}_sp"
    if mnemonic in {"push", "pop"} and normalized_operands in {"rbp", "ebp"}:
        return f"{mnemonic}_bp"
    if mnemonic == "mov" and normalized_operands in {"rbp,rsp", "ebp,esp"}:
        return "mov_bp_sp"
    accesses = stack_accesses_from_operands(operands)
    if mnemonic == "lea" and accesses:
        return "lea_stack_address"
    if mnemonic == "mov" and accesses:
        first_operand = operands.split(",", 1)[0].strip().lower()
        if first_operand.startswith("["):
            return "mov_stack_write"
        return "mov_stack_read"
    if mnemonic == "call":
        target = call_target_name(operands, plt_symbols)
        if target and any(name in target for name in STACK_RELEVANT_CALLS):
            return "call_stack_relevant_function"
    return None


def stack_relevant_instructions(
    disassembly: list[dict],
    functions: list[dict],
    plt_symbols: dict[int, str],
) -> list[dict]:
    ranges = function_ranges(functions)
    out = []
    for line in disassembly if isinstance(disassembly, list) else []:
        if not isinstance(line, dict):
            continue
        kind = instruction_kind(line, plt_symbols)
        if not kind:
            continue
        addr = line_addr(line)
        fn = function_for_addr(ranges, addr)
        operands = str(line.get("operands") or "").strip()
        call_target = call_target_name(operands, plt_symbols) if kind == "call_stack_relevant_function" else None
        out.append(
            {
                "addr": safe_hex(addr),
                "function": fn.get("name") if isinstance(fn, dict) else None,
                "kind": kind,
                "mnemonic": str(line.get("mnemonic") or "").strip(),
                "operands": operands,
                "call_target": call_target,
                "text": str(line.get("text") or "").strip(),
                "stack_accesses": stack_accesses_from_operands(operands),
            }
        )
    return out


def register_name(value: str) -> str:
    return str(value or "").strip().lower().lstrip("%")


def dest_reg_from_operands(operands: str) -> Optional[str]:
    first = str(operands or "").split(",", 1)[0].strip()
    if re.fullmatch(r"%?[a-z][a-z0-9]*", first, re.IGNORECASE):
        return register_name(first)
    return None


def source_reg_from_mov(operands: str) -> Optional[str]:
    parts = str(operands or "").split(",", 1)
    if len(parts) != 2:
        return None
    source = parts[1].strip()
    if re.fullmatch(r"%?[a-z][a-z0-9]*", source, re.IGNORECASE):
        return register_name(source)
    return None
