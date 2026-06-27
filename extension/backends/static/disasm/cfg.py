# SPDX-License-Identifier: AGPL-3.0-only
"""Graphe de flux de contrôle (CFG) à partir du désassemblage.

Parse les lignes objdump pour construire des blocs de base et les arcs.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from backends.shared.utils import normalize_addr as _normalize_addr
from backends.shared.log import configure_logging, get_logger
from backends.static.binary.arch import (
    ArchAdapter,
    detect_binary_arch_from_path,
    get_feature_support,
    iter_supported_adapters,
)

try:
    import lief
except ImportError:
    lief = None

try:
    import capstone as _capstone
except ImportError:
    _capstone = None

logger = get_logger(__name__)


@dataclass
class BasicBlock:
    """Bloc de base : séquence d'instructions sans branchement interne."""

    addr: str  # Adresse de la première instruction
    lines: list[dict]  # [{addr, text, line}, ...]
    successors: list[str] = field(default_factory=list)  # Adresses des blocs cibles
    is_call: bool = False  # Dernière instruction = call
    is_switch: bool = False  # Bloc se termine par une jump table (switch)
    switch_cases: list[dict] = field(default_factory=list)  # [{case: N, target: addr}]
    incoming_switch_cases: list[dict] = field(default_factory=list)  # [{case, from}]


RET_MNEMONICS = {"ret", "retn", "retq", "retf"}
PUSH_MNEMONIC = "push"
ARM64_RET_MNEMONICS = {"ret", "retab", "retaa", "retaa"}


def _candidate_adapters(
    binary_path: str | None = None, arch_hint: str | None = None
) -> tuple[ArchAdapter, ...]:
    if arch_hint:
        from backends.static.binary.arch import get_raw_arch_info

        hint_info = get_raw_arch_info(arch_hint)
        if hint_info is not None:
            return (hint_info.adapter,)
    info = detect_binary_arch_from_path(binary_path) if binary_path else None
    if info is not None:
        return (info.adapter,)
    return tuple(iter_supported_adapters())


def _extract_symbol_from_operand(text: str) -> Optional[str]:
    """Extrait le symbole des opérandes objdump : <puts@plt>, <_main+0x2e>, etc."""
    match = re.search(r"<\s*([^>]+)\s*>", text)
    return match.group(1).strip() if match else None


def _extract_jump_target(text: str) -> Optional[str]:
    """Extrait l'adresse cible d'une instruction jmp/call/jcc.
    Supporte: 0x1000004be, 401240, 0x1000004be <_main+0x2e>
    """
    search_area = str(text or "")
    mnem = _get_mnemonic(search_area)
    if mnem and not mnem.startswith("0x") and not re.fullmatch(r"[0-9a-fA-F]{4,}", mnem):
        match = re.search(rf"\b{re.escape(mnem)}\b(.*)$", search_area, re.IGNORECASE)
        if match:
            search_area = match.group(1)

    # Dernier token souvent l'adresse (Intel: jmp 0x401240, call 0x100000470)
    # Pattern: hex (0x...) ou décimal
    match = re.search(r"0x([0-9a-fA-F]+)", search_area)
    if match:
        return _normalize_addr("0x" + match.group(1).lower())
    # Sans 0x: 401240 ou 1000004be (objdump macOS)
    match = re.search(r"\b([0-9a-fA-F]{6,})\b", search_area)
    if match:
        return _normalize_addr("0x" + match.group(1).lower())
    return None


def _get_mnemonic(text: str) -> str:
    """Retourne le mnémonique de l'instruction.
    Objdump format: 'bytes\\tmnemonic\\toperands' - on ignore les bytes hex et adresses.
    """
    parts = text.split()
    for p in parts:
        pl = p.lower()
        if pl.startswith("0x"):
            continue
        if len(pl) <= 2 and all(c in "0123456789abcdef" for c in pl):
            continue
        if len(pl) >= 6 and all(c in "0123456789abcdef" for c in pl):
            continue
        return pl
    return parts[0].lower() if parts else ""


def _is_branch(
    text: str,
    adapters: tuple[ArchAdapter, ...] | None = None,
) -> tuple[bool, bool, Optional[str]]:
    """(is_branch, is_call, target_addr).
    Supporte x86/x64 (call, jmp, ret) et ARM64 (bl, blr, b, br, ret).
    """
    mnem = _get_mnemonic(text)
    operands = re.split(rf"\b{re.escape(mnem)}\b", str(text or ""), maxsplit=1, flags=re.IGNORECASE)
    op_str = operands[1] if len(operands) == 2 else ""
    for adapter in adapters or tuple(iter_supported_adapters()):
        if adapter.is_return_instruction(mnem, op_str):
            return True, False, None
        kind = adapter.classify_code_ref_mnemonic(mnem)
        if kind == "ret":
            return True, False, None
        if kind == "call":
            target = _extract_jump_target(text)
            return True, True, target
        if kind in {"jmp", "jcc"}:
            target = _extract_jump_target(text)
            return True, False, target
    return False, False, None


def _is_jump_table(text: str) -> bool:
    """Détecte si l'instruction est un saut indirect via jump table.

    Patterns typiques:
    - x86-64: jmp qword ptr [rip+rax*8+offset], jmp [base+index*8]
    - x86-32: jmp dword ptr [eax*4+offset]
    - ARM64: br x8 (après ldr depuis table)
    """
    text_lower = text.lower()
    mnem = _get_mnemonic(text)

    if mnem == "jmp":
        # Détection de sauts indirects: présence de crochets [...] = accès mémoire
        # Sauts directs n'ont PAS de crochets (jmp 0x401000)
        # Sauts indirects ont des crochets (jmp [rax], jmp qword ptr [rip+rax*8])
        if "[" not in text_lower:
            return False  # Pas de crochet = saut direct

        # C'est un saut indirect. Vérifier les patterns typiques de jump table:
        # 1. Multiplication par taille de pointeur (*4, *8)
        if "*4" in text_lower or "*8" in text_lower:
            return True

        # 2. Accès mémoire avec offset (qword ptr, dword ptr, rip, registres)
        # Ces patterns indiquent généralement une jump table
        if any(p in text_lower for p in ["qword ptr", "dword ptr", "[rip", "[r", "[e"]):
            return True

    # ARM64/MIPS/RISC-V/PPC: branchement via registre / compteur
    elif mnem in {"br", "bctr", "bcctr"}:
        return True
    elif mnem == "jr":
        jump_reg = _extract_register_jump_target(text)
        return jump_reg not in {None, "ra", "lr"}
    elif mnem == "jalr":
        return _extract_register_jump_target(text) is not None

    return False


def _detect_switch_max_case(block_lines: list[dict]) -> Optional[int]:
    """Cherche en arrière dans le bloc pour un 'cmp reg, N' avant le saut indirect.

    Retourne le nombre de cas (N+1) si trouvé, sinon None.
    Patterns reconnus :
    - cmp rax, 0xN  / cmp eax, N  (borne supérieure)
    - sub eax, N (normalisation d'index)
    """
    cmp_re = re.compile(r"\bcmp\b.*,\s*#?(?:0x)?([0-9a-fA-F]+)\b", re.IGNORECASE)
    for ln in reversed(block_lines):
        text = ln.get("text", "")
        mnem = _get_mnemonic(text)
        if mnem in ("jmp", "br"):
            continue
        m = cmp_re.search(text)
        if m:
            try:
                return int(m.group(1), 16) + 1  # N cases : 0..N
            except ValueError:
                return None
        # Stop if we hit a terminator other than the jmp we're searching past
        if mnem in RET_MNEMONICS or mnem in ARM64_RET_MNEMONICS:
            break
    return None


def _append_incoming_switch_case(
    block: BasicBlock, source_addr: str, case_label: int | str | None
) -> None:
    entry = {"from": source_addr, "case": case_label}
    if entry not in block.incoming_switch_cases:
        block.incoming_switch_cases.append(entry)


def _extract_jump_table_base(text: str) -> Optional[str]:
    """Tente d'extraire l'adresse de base d'une jump table depuis l'instruction.

    Exemples:
    - jmp qword ptr [rip+rax*8+0x2004] → 0x2004 (offset relatif)
    - jmp [0x401234+rax*8] → 0x401234 (adresse absolue)
    """
    # Chercher un offset hex dans l'instruction
    # Pattern: +0xHEX ou simplement 0xHEX après [
    matches = re.findall(r"[+\[][\s]*(0x[0-9a-fA-F]+)", text)
    if matches:
        # Retourner la première adresse trouvée
        return _normalize_addr(matches[0])
    return None


def _parse_int_literal(text: str | None) -> Optional[int]:
    if text is None:
        return None
    raw = str(text).strip().lower().replace(" ", "")
    if not raw:
        return None
    sign = -1 if raw.startswith("-") else 1
    normalized = raw.lstrip("+-")
    try:
        if normalized.startswith("0x"):
            return sign * int(normalized, 16)
        return sign * int(normalized, 10)
    except ValueError:
        return None


def _normalize_register_name(value: str | None) -> str:
    return str(value or "").strip().lower().lstrip("$%").rstrip(",")


def _binary_is_64bit(binary) -> bool:
    hdr = getattr(binary, "header", None)
    if hdr is None:
        return True
    identity_class = getattr(hdr, "identity_class", None)
    if identity_class is not None:
        return str(identity_class) == "CLASS.ELF64"
    is_64bit = getattr(hdr, "is_64bit", None)
    if is_64bit is not None:
        return bool(is_64bit)
    machine = getattr(getattr(hdr, "machine", None), "name", "")
    return str(machine).upper() in {"AMD64", "AARCH64", "ARM64"}


def _extract_register_jump_target(text: str) -> Optional[str]:
    mnem = _get_mnemonic(text)
    if mnem not in {"jmp", "br", "jr", "jalr", "bctr", "bcctr"}:
        return None
    if "[" in text:
        return None
    if mnem in {"bctr", "bcctr"}:
        return "ctr"
    if mnem == "jalr":
        operands_match = re.search(rf"\b{re.escape(mnem)}\b\s+(.+)$", text, re.IGNORECASE)
        if not operands_match:
            return None
        operands = [
            _normalize_register_name(operand)
            for operand in operands_match.group(1).split(",")
            if operand.strip()
        ]
        if not operands:
            return None
        if len(operands) == 1:
            return operands[0]
        if len(operands) >= 2 and operands[0] in {"zero", "x0"}:
            return operands[1]
        return None
    match = re.search(
        rf"\b{re.escape(mnem)}\b\s+([$%]?[a-z][a-z0-9]*)\b",
        text,
        re.IGNORECASE,
    )
    return _normalize_register_name(match.group(1)) if match else None


def _resolve_table_addr_from_lea(
    line: dict,
    register: str,
    parsed_binary,
    detected_arch_info,
) -> Optional[int]:
    text = str(line.get("text", "") or "")
    if _get_mnemonic(text) != "lea":
        return None
    match = re.search(r"\blea\b\s+([a-z0-9]+)\s*,\s*\[(.+)\]", text, re.IGNORECASE)
    if not match or match.group(1).lower() != register.lower():
        return None
    expr = match.group(2).replace(" ", "").lower()
    if "rip" in expr:
        offset_match = re.search(r"rip([+-](?:0x)?[0-9a-f]+)?", expr, re.IGNORECASE)
        offset = _parse_int_literal(offset_match.group(1) if offset_match else "0")
        if offset is None:
            return None
        curr_addr = int(_normalize_addr(line["addr"]), 16)
        arch_family = detected_arch_info.family if detected_arch_info is not None else "x86"
        return _resolve_rip_relative_table(
            curr_addr,
            offset,
            parsed_binary,
            _binary_is_64bit(parsed_binary),
            arch=arch_family,
        )
    absolute_match = re.search(r"(0x[0-9a-f]+)", expr, re.IGNORECASE)
    if absolute_match:
        return int(absolute_match.group(1), 16)
    return None


def _extract_memory_base_register(expr: str) -> Optional[str]:
    cleaned = str(expr or "").replace(" ", "").lower()
    match = re.match(r"[$%]?([a-z][a-z0-9]+)", cleaned)
    return _normalize_register_name(match.group(1)) if match else None


def _extract_operand_register(expr: str) -> Optional[str]:
    cleaned = str(expr or "").strip().lower()
    match = re.search(r"[$%]?([a-z][a-z0-9]+)\b", cleaned)
    return _normalize_register_name(match.group(1)) if match else None


def _resolve_table_addr_from_arm_setup(
    block_lines: list[dict],
    register: str,
) -> Optional[int]:
    """Résout une base de jump table ARM64 depuis adr/adrp + add."""
    reg = str(register or "").strip().lower()
    if not reg:
        return None

    page_addr: Optional[int] = None
    direct_addr: Optional[int] = None
    add_offset = 0

    for line in reversed(block_lines):
        text = str(line.get("text", "") or "")
        mnem = _get_mnemonic(text)
        if mnem == "adr":
            match = re.search(
                r"\badr\b\s+([a-z0-9]+)\s*,\s*#?(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and match.group(1).lower() == reg:
                direct_addr = _parse_int_literal(match.group(2))
                if direct_addr is not None:
                    return direct_addr
        elif mnem == "add":
            match = re.search(
                r"\badd\b\s+([a-z0-9]+)\s*,\s*([a-z0-9]+)\s*,\s*#?(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and match.group(1).lower() == reg and match.group(2).lower() == reg:
                parsed = _parse_int_literal(match.group(3))
                if parsed is not None:
                    add_offset = parsed
                    if page_addr is not None:
                        return page_addr + add_offset
        elif mnem == "adrp":
            match = re.search(
                r"\badrp\b\s+([a-z0-9]+)\s*,\s*#?(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and match.group(1).lower() == reg:
                page_addr = _parse_int_literal(match.group(2))
                if page_addr is not None:
                    return page_addr + add_offset

    return direct_addr


def _resolve_table_addr_from_arch_setup(
    block_lines: list[dict],
    register: str,
    detected_arch_info,
) -> Optional[int]:
    reg = _normalize_register_name(register)
    family = (getattr(detected_arch_info, "family", None) or "").lower()
    if not reg or family not in {"mips", "riscv", "ppc"}:
        return None

    upper_base: Optional[int] = None
    add_offset = 0

    for line in reversed(block_lines):
        text = str(line.get("text", "") or "")
        mnem = _get_mnemonic(text)
        curr_addr = _parse_int_literal(line.get("addr"))

        if family == "riscv" and mnem == "auipc":
            match = re.search(
                r"\bauipc\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                if upper is not None and curr_addr is not None:
                    return curr_addr + (upper << 12) + add_offset

        if family == "riscv" and mnem == "lui":
            match = re.search(
                r"\blui\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                if upper is not None:
                    return (upper << 12) + add_offset

        if family == "mips" and mnem == "lui":
            match = re.search(
                r"\blui\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                if upper is not None:
                    return (upper << 16) + add_offset

        if family == "ppc" and mnem == "lis":
            match = re.search(
                r"\blis\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                if upper is not None:
                    return (upper << 16) + add_offset

        if family == "riscv" and mnem == "addi":
            match = re.search(
                r"\baddi\b\s+([a-z0-9$]+)\s*,\s*([a-z0-9$]+)\s*,\s*(-?0x[0-9a-f]+|-?\d+)",
                text,
                re.IGNORECASE,
            )
            if (
                match
                and _normalize_register_name(match.group(1)) == reg
                and _normalize_register_name(match.group(2)) == reg
            ):
                parsed = _parse_int_literal(match.group(3))
                if parsed is not None:
                    add_offset = parsed
                    if upper_base is not None:
                        return upper_base + add_offset
                    continue

        if family == "mips" and mnem in {"addiu", "addi", "daddiu", "ori"}:
            match = re.search(
                rf"\b{re.escape(mnem)}\b\s+([a-z0-9$]+)\s*,\s*([a-z0-9$]+)\s*,\s*(-?0x[0-9a-f]+|-?\d+)",
                text,
                re.IGNORECASE,
            )
            if (
                match
                and _normalize_register_name(match.group(1)) == reg
                and _normalize_register_name(match.group(2)) == reg
            ):
                parsed = _parse_int_literal(match.group(3))
                if parsed is not None:
                    add_offset = parsed
                    if upper_base is not None:
                        return upper_base + add_offset
                    continue

        if family == "ppc" and mnem == "addi":
            match = re.search(
                r"\baddi\b\s+([a-z0-9$]+)\s*,\s*([a-z0-9$]+)\s*,\s*(-?0x[0-9a-f]+|-?\d+)",
                text,
                re.IGNORECASE,
            )
            if (
                match
                and _normalize_register_name(match.group(1)) == reg
                and _normalize_register_name(match.group(2)) == reg
            ):
                parsed = _parse_int_literal(match.group(3))
                if parsed is not None:
                    add_offset = parsed
                    if upper_base is not None:
                        return upper_base + add_offset
                    continue

        if family == "riscv" and mnem == "auipc":
            upper_base = None
        elif family == "riscv" and mnem == "lui":
            match = re.search(
                r"\blui\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                upper_base = (upper << 12) if upper is not None else None
        elif family == "mips" and mnem == "lui":
            match = re.search(
                r"\blui\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                upper_base = (upper << 16) if upper is not None else None
        elif family == "ppc" and mnem == "lis":
            match = re.search(
                r"\blis\b\s+([a-z0-9$]+)\s*,\s*(0x[0-9a-f]+|\d+)",
                text,
                re.IGNORECASE,
            )
            if match and _normalize_register_name(match.group(1)) == reg:
                upper = _parse_int_literal(match.group(2))
                upper_base = (upper << 16) if upper is not None else None

    return None


def _resolve_register_jump_table(
    block_lines: list[dict],
    *,
    binary_path: str | None,
    parsed_binary,
    detected_arch_info,
) -> tuple[list[str], Optional[str]]:
    """Tente de résoudre un switch de type lea+load+add+jmp reg.

    Retourne (entries, table_kind) où table_kind vaut "absolute" ou "relative".
    """
    if not binary_path or parsed_binary is None or not block_lines:
        return [], None

    jump_reg = _extract_register_jump_target(block_lines[-1].get("text", ""))
    if not jump_reg:
        return [], None

    effective_jump_reg = jump_reg
    if jump_reg == "ctr":
        for idx in range(len(block_lines) - 2, -1, -1):
            text = str(block_lines[idx].get("text", "") or "")
            match = re.search(r"\bmtctr\b\s+([a-z0-9$]+)\b", text, re.IGNORECASE)
            if match:
                effective_jump_reg = _normalize_register_name(match.group(1))
                break
        if effective_jump_reg == "ctr":
            return [], None

    relative_base_reg = None
    load_search_end = len(block_lines) - 2
    for idx in range(len(block_lines) - 2, -1, -1):
        text = str(block_lines[idx].get("text", "") or "")
        add_mnem = _get_mnemonic(text)
        if add_mnem in {"add", "addu", "daddu"}:
            ops_text = re.split(
                rf"\b{re.escape(add_mnem)}\b", text, maxsplit=1, flags=re.IGNORECASE
            )
            if len(ops_text) == 2:
                operands = [
                    operand.strip() for operand in ops_text[1].split(",") if operand.strip()
                ]
                if operands:
                    dest_reg = _extract_operand_register(operands[0])
                    if dest_reg == effective_jump_reg:
                        source_regs = [
                            reg
                            for reg in (
                                _extract_operand_register(operand) for operand in operands[1:]
                            )
                            if reg is not None
                        ]
                        relative_base_reg = next(
                            (reg for reg in source_regs if reg != effective_jump_reg),
                            None,
                        )
                        if relative_base_reg:
                            load_search_end = idx - 1
                            break

    load_expr = None
    entry_size = None
    load_idx = None
    base_reg = None
    for idx in range(load_search_end, -1, -1):
        text = str(block_lines[idx].get("text", "") or "")
        match = re.search(
            r"\b(?:movsxd|mov)\b\s+([a-z0-9$]+)\s*,\s*(?:[a-z]+\s+ptr\s+)?\[(.+)\]",
            text,
            re.IGNORECASE,
        )
        if match and _normalize_register_name(match.group(1)) == effective_jump_reg:
            expr = match.group(2).replace(" ", "").lower()
            if "*8" in expr:
                entry_size = 8
            elif "*4" in expr:
                entry_size = 4
            else:
                continue
            if relative_base_reg and relative_base_reg not in expr:
                continue
            load_expr = expr
            load_idx = idx
            base_reg = relative_base_reg or _extract_memory_base_register(expr)
            break

        arm_match = re.search(
            r"\b(ldr|ldrsw)\b\s+([a-z0-9$]+)\s*,\s*\[(.+)\]",
            text,
            re.IGNORECASE,
        )
        if arm_match and _normalize_register_name(arm_match.group(2)) == effective_jump_reg:
            expr = arm_match.group(3).replace(" ", "").lower()
            if relative_base_reg and relative_base_reg not in expr:
                continue
            if any(token in expr for token in ("lsl#3", "uxtw#3", "sxtw#3")):
                entry_size = 8
            elif (
                any(token in expr for token in ("lsl#2", "uxtw#2", "sxtw#2"))
                or arm_match.group(1).lower() == "ldrsw"
            ):
                entry_size = 4
            else:
                entry_size = 8 if effective_jump_reg.startswith("x") else 4
            load_expr = expr
            load_idx = idx
            base_reg = relative_base_reg or _extract_memory_base_register(expr)
            break

        mips_riscv_match = re.search(
            r"\b(ld|lw|lwu|lwz)\b\s+([a-z0-9$]+)\s*,\s*(-?0x[0-9a-f]+|-?\d+)?\(([a-z0-9$]+)\)",
            text,
            re.IGNORECASE,
        )
        if (
            mips_riscv_match
            and _normalize_register_name(mips_riscv_match.group(2)) == effective_jump_reg
        ):
            base_candidate = _normalize_register_name(mips_riscv_match.group(4))
            if relative_base_reg and base_candidate != relative_base_reg:
                continue
            load_expr = f"{base_candidate}()"
            load_idx = idx
            base_reg = relative_base_reg or base_candidate
            entry_size = 8 if mips_riscv_match.group(1).lower() == "ld" else 4
            break

        ppc_match = re.search(
            r"\b(lwzx|ldx)\b\s+([a-z0-9$]+)\s*,\s*([a-z0-9$]+)\s*,\s*([a-z0-9$]+)",
            text,
            re.IGNORECASE,
        )
        if ppc_match and _normalize_register_name(ppc_match.group(2)) == effective_jump_reg:
            base_candidate = _normalize_register_name(ppc_match.group(3))
            if relative_base_reg and base_candidate != relative_base_reg:
                continue
            load_expr = f"{base_candidate}()"
            load_idx = idx
            base_reg = relative_base_reg or base_candidate
            entry_size = 8 if ppc_match.group(1).lower() == "ldx" else 4
            break

    if not load_expr or load_idx is None or entry_size is None:
        return [], None

    if base_reg is None:
        for idx in range(load_idx - 1, -1, -1):
            text = str(block_lines[idx].get("text", "") or "")
            match = re.search(r"\blea\b\s+([a-z0-9]+)\s*,", text, re.IGNORECASE)
            if not match:
                continue
            candidate = match.group(1).lower()
            if candidate in load_expr:
                base_reg = candidate
                break

    if not base_reg:
        return [], None

    table_addr = None
    table_addr = _resolve_table_addr_from_arm_setup(block_lines[:load_idx], base_reg)
    if table_addr is None:
        table_addr = _resolve_table_addr_from_arch_setup(
            block_lines[:load_idx], base_reg, detected_arch_info
        )
    if table_addr is None:
        for idx in range(load_idx - 1, -1, -1):
            table_addr = _resolve_table_addr_from_lea(
                block_lines[idx], base_reg, parsed_binary, detected_arch_info
            )
            if table_addr is not None:
                break
    if table_addr is None:
        return [], None

    max_entries = _detect_switch_max_case(block_lines) or 256
    if relative_base_reg:
        entries = _read_jump_table_entries(
            binary_path,
            table_addr,
            max_entries=max_entries,
            parsed_binary=parsed_binary,
            entry_mode="relative",
            base_addr=table_addr,
            entry_size=entry_size,
        )
        return entries, "relative"

    entries = _read_jump_table_entries(
        binary_path,
        table_addr,
        max_entries=max_entries,
        parsed_binary=parsed_binary,
        entry_mode="absolute",
        entry_size=entry_size,
    )
    return entries, "absolute"


def _read_bytes_at(binary, vaddr: int, size: int) -> bytes:
    """Lit size bytes a l'adresse virtuelle vaddr depuis le binaire lief parse."""
    if not lief:
        return b""
    try:
        for sec in binary.sections:
            sec_va = sec.virtual_address
            sec_size = sec.size
            if sec_va <= vaddr < sec_va + sec_size:
                file_offset = getattr(sec, "file_offset", getattr(sec, "offset", 0))
                offset_in_section = vaddr - sec_va
                with open(binary.name, "rb") as f:
                    f.seek(file_offset + offset_in_section)
                    available = sec_size - offset_in_section
                    data = f.read(min(size, available))
                    if len(data) < 1:
                        return b""
                    return data
    except Exception:
        pass
    return b""


def _section_is_exec(sec, binary) -> bool:
    """Verifie si une section est executable.

    - ELF   : EXECINSTR dans flags_list
    - PE    : CNT_CODE dans characteristics_list
    - MachO : segment_name == '__TEXT'
    - Fallback si lief absent : True
    """
    if not lief:
        return True
    try:
        if isinstance(binary, lief.ELF.Binary):
            return lief.ELF.Section.FLAGS.EXECINSTR in sec.flags_list
        if isinstance(binary, lief.PE.Binary):
            return lief.PE.Section.CHARACTERISTICS.CNT_CODE in sec.characteristics_list
        if isinstance(binary, lief.MachO.Binary):
            return sec.segment_name.strip("\x00") == "__TEXT"
    except Exception:
        pass
    return False


def _is_valid_code_addr(addr: int, binary) -> bool:
    """Verifie que addr appartient a une section executable du binaire.

    Parcourt les sections lief et delegue le test a _section_is_exec.
    Fallback si lief absent : addr >= 0x1000.
    """
    if not lief:
        return addr >= 0x1000
    try:
        for sec in binary.sections:
            sec_va = sec.virtual_address
            if sec_va <= addr < sec_va + sec.size:
                return _section_is_exec(sec, binary)
    except Exception:
        pass
    return False


def _resolve_rip_relative_table(
    jmp_addr: int, offset: int, binary, is_64bit: bool = True, arch: str = "x86"
) -> int:
    """Calcule l'adresse absolue d'une jump table referencee via RIP-relatif.

    Utilise capstone pour desassembler l'instruction a jmp_addr et determiner
    next_instr_addr, puis retourne next_instr_addr + offset.
    Fallback si capstone absent : jmp_addr + 6 + offset.

    Args:
        arch: Architecture cible, "x86" (defaut) ou "arm64".
    """
    if _capstone is None:
        return jmp_addr + 6 + offset

    try:
        raw = _read_bytes_at(binary, jmp_addr, 15)  # taille max instruction x86
        if len(raw) < 2:
            return jmp_addr + 6 + offset
        if arch == "arm64":
            cs_arch = _capstone.CS_ARCH_ARM64
            cs_mode = _capstone.CS_MODE_LITTLE_ENDIAN
        else:
            cs_arch = _capstone.CS_ARCH_X86
            cs_mode = _capstone.CS_MODE_64 if is_64bit else _capstone.CS_MODE_32
        md = _capstone.Cs(cs_arch, cs_mode)
        for instr in md.disasm(raw, jmp_addr):
            next_instr_addr = instr.address + instr.size
            return next_instr_addr + offset
    except Exception:
        pass

    return jmp_addr + 6 + offset


def _read_jump_table_entries(
    binary_path: str | None,
    table_addr: int,
    max_entries: int = 64,
    *,
    parsed_binary=None,
    entry_mode: str = "absolute",
    base_addr: int | None = None,
    entry_size: int | None = None,
) -> list[str]:
    """Lit les entrées d'une jump table depuis le binaire.

    Args:
        binary_path: Chemin vers le binaire (None = pas de lecture)
        table_addr: Adresse virtuelle de la table
        max_entries: Nombre maximum d'entrées à lire

    Returns:
        Liste d'adresses (format 0xhex)
    """
    if not binary_path:
        return []
    if not lief:
        return []

    binary = parsed_binary
    if binary is None:
        try:
            binary = lief.parse(binary_path)
            if not binary:
                return []
        except Exception:
            return []

    # Convertir l'adresse virtuelle en offset fichier
    file_offset = None
    detected_entry_size = entry_size

    if isinstance(binary, lief.ELF.Binary):
        # Trouver la section contenant cette adresse
        for sec in binary.sections:
            if sec.virtual_address <= table_addr < sec.virtual_address + sec.size:
                offset_in_section = table_addr - sec.virtual_address
                file_offset = sec.file_offset + offset_in_section
                break
        # Déterminer la taille des pointeurs
        if detected_entry_size is None:
            detected_entry_size = (
                8 if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else 4
            )

    elif isinstance(binary, lief.MachO.Binary):
        # Trouver la section contenant cette adresse
        for sec in binary.sections:
            if sec.virtual_address <= table_addr < sec.virtual_address + sec.size:
                offset_in_section = table_addr - sec.virtual_address
                file_offset = sec.offset + offset_in_section
                break
        if detected_entry_size is None:
            detected_entry_size = 8 if binary.header.is_64bit else 4

    elif isinstance(binary, lief.PE.Binary):
        # PE: trouver la section
        for sec in binary.sections:
            if sec.virtual_address <= table_addr < sec.virtual_address + sec.size:
                offset_in_section = table_addr - sec.virtual_address
                file_offset = sec.offset + offset_in_section
                break
        if detected_entry_size is None:
            detected_entry_size = 8 if binary.header.machine.name == "AMD64" else 4

    if detected_entry_size is None:
        detected_entry_size = 8

    if file_offset is None:
        return []

    # Lire les données brutes du binaire
    try:
        with open(binary_path, "rb") as f:
            f.seek(file_offset)
            data = f.read(max_entries * detected_entry_size)
    except Exception:
        return []

    # Parser les entrées de la table
    import struct

    entries = []
    if entry_mode == "relative":
        fmt = "<q" if detected_entry_size == 8 else "<i"
    else:
        fmt = "<Q" if detected_entry_size == 8 else "<I"

    for i in range(0, min(len(data), max_entries * detected_entry_size), detected_entry_size):
        if i + detected_entry_size > len(data):
            break

        chunk = data[i : i + detected_entry_size]
        if len(chunk) < detected_entry_size:
            break

        try:
            raw_value = struct.unpack(fmt, chunk)[0]
            addr = raw_value if entry_mode == "absolute" else (base_addr or table_addr) + raw_value
            # Filtrer les entrées invalides (0, ou hors de l'espace d'adressage raisonnable)
            if addr == 0:
                break
            if not _is_valid_code_addr(addr, binary):
                break
            entries.append(f"0x{addr:x}")
        except struct.error:
            break

    return entries


def build_cfg(
    lines: list[dict],
    binary_path: str | None = None,
    arch_hint: str | None = None,
) -> dict:
    """Construit le CFG à partir des lignes de désassemblage.

    Args:
        lines: Lignes de désassemblage
        binary_path: Chemin vers le binaire (optionnel, pour jump tables)
        arch_hint: Clé d'architecture (ex. "ppc32") pour les blobs bruts

    Returns:
        {
            "blocks": [{"addr", "lines", "successors", "is_call"}],
            "edges": [{"from", "to", "type": "jmp"|"call"|"fallthrough"|"jumptable"}],
        }
    """
    if not lines:
        return {"blocks": [], "edges": [], "support_level": "unsupported"}

    # Adresses qui sont cibles de sauts (début de bloc)
    adapters = _candidate_adapters(binary_path, arch_hint=arch_hint)
    if arch_hint:
        from backends.static.binary.arch import get_raw_arch_info

        detected_arch_info = get_raw_arch_info(arch_hint)
    else:
        detected_arch_info = detect_binary_arch_from_path(binary_path) if binary_path else None
    support_adapter = detected_arch_info.adapter if detected_arch_info is not None else adapters[0]
    support = get_feature_support(support_adapter, "cfg")
    branch_targets = set()
    # Pour chaque instruction de branchement, enregistrer la cible
    for line in lines:
        text = line.get("text", "")
        _, _, target = _is_branch(text, adapters=adapters)
        if target:
            branch_targets.add(target)

    # push+ret = jmp : séquence push addr; [nop]*; ret saute vers addr
    pending_push_target = None
    for i, line in enumerate(lines):
        text = line.get("text", "")
        mnem = _get_mnemonic(text)
        if mnem == PUSH_MNEMONIC:
            target = _extract_jump_target(text)
            pending_push_target = target if target else pending_push_target
        elif mnem in RET_MNEMONICS and pending_push_target:
            branch_targets.add(pending_push_target)
            pending_push_target = None
        elif mnem not in ("nop", "int3", "ud2", "nopw", "align", "data16"):
            pending_push_target = None

    # Début de bloc = première instruction ou cible de saut ou instruction après un saut
    block_starts = {_normalize_addr(lines[0]["addr"])}
    block_starts.update(branch_targets)

    for i, line in enumerate(lines):
        addr = _normalize_addr(line["addr"])
        is_br, _, _ = _is_branch(line.get("text", ""), adapters=adapters)
        if is_br and i + 1 < len(lines):
            next_addr = _normalize_addr(lines[i + 1]["addr"])
            block_starts.add(next_addr)

    # Parser le binaire une seule fois pour les jump tables
    _parsed_binary = None
    if lief and binary_path:
        try:
            _parsed_binary = lief.parse(binary_path)
        except Exception:
            pass

    # Construire les blocs
    blocks = []
    block_map = {}  # addr -> index du bloc

    i = 0
    while i < len(lines):
        line = lines[i]
        addr = _normalize_addr(line["addr"])
        if addr not in block_starts:
            i += 1
            continue

        block_lines: list[dict] = []
        successors = []
        is_call = False
        _block_switch_entries: list[str] = []

        while i < len(lines):
            ln = lines[i]
            a = _normalize_addr(ln["addr"])
            if a != addr and a in block_starts and len(block_lines) > 0:
                break
            block_lines.append(ln)
            text = ln.get("text", "")
            is_br, is_c, target = _is_branch(text, adapters=adapters)
            if is_br:
                if target:
                    successors.append(target)

                # Jump table : détecter et extraire les cibles
                _switch_entries: list[str] = []
                if _is_jump_table(text):
                    table_base = _extract_jump_table_base(text)
                    if table_base:
                        # Convertir en adresse absolue si c'est un offset RIP-relative
                        # (heuristique simple : si < 0x10000, c'est probablement un offset)
                        base_int = int(table_base, 16)
                        if base_int < 0x10000:
                            # Offset relatif : résoudre via RIP-relative avec capstone
                            curr_addr = int(_normalize_addr(ln["addr"]), 16)
                            _resolved_bin = _parsed_binary
                            if _resolved_bin is not None:
                                _is_64 = True
                                hdr = getattr(_resolved_bin, "header", None)
                                if hdr:
                                    if hasattr(hdr, "identity_class"):
                                        _is_64 = str(hdr.identity_class) == "CLASS.ELF64"
                                    elif hasattr(hdr, "is_64bit"):
                                        _is_64 = bool(hdr.is_64bit)
                                arch_family = (
                                    detected_arch_info.family
                                    if detected_arch_info is not None
                                    else "x86"
                                )
                                table_addr = _resolve_rip_relative_table(
                                    curr_addr, base_int, _resolved_bin, _is_64, arch=arch_family
                                )
                            else:
                                table_addr = curr_addr + 6 + base_int
                        else:
                            table_addr = base_int

                        # Lire les entrées de la table
                        _max_entries = _detect_switch_max_case(block_lines) or 256
                        _switch_entries = _read_jump_table_entries(
                            binary_path,
                            table_addr,
                            parsed_binary=_parsed_binary,
                            max_entries=_max_entries,
                        )
                        if _switch_entries:
                            # L'adresse extraite par _extract_jump_target est l'adresse
                            # de la table elle-même, pas une vraie cible de code.
                            # On la retire au profit des vraies cibles de la table.
                            if target and target in successors:
                                successors.remove(target)
                            for entry in _switch_entries:
                                if entry not in successors:
                                    successors.append(entry)
                    if not _switch_entries:
                        _switch_entries, _ = _resolve_register_jump_table(
                            block_lines,
                            binary_path=binary_path,
                            parsed_binary=_parsed_binary,
                            detected_arch_info=detected_arch_info,
                        )
                        if _switch_entries:
                            for entry in _switch_entries:
                                if entry not in successors:
                                    successors.append(entry)
                else:
                    _switch_entries, _ = _resolve_register_jump_table(
                        block_lines,
                        binary_path=binary_path,
                        parsed_binary=_parsed_binary,
                        detected_arch_info=detected_arch_info,
                    )
                    if _switch_entries:
                        for entry in _switch_entries:
                            if entry not in successors:
                                successors.append(entry)

                # push+ret = jmp : chercher le push imm le plus récent dans le bloc avant ret
                mnem = _get_mnemonic(text)
                if mnem in RET_MNEMONICS and len(block_lines) >= 2:
                    for j in range(len(block_lines) - 2, -1, -1):
                        prev_text = block_lines[j].get("text", "")
                        if _get_mnemonic(prev_text) == PUSH_MNEMONIC:
                            push_target = _extract_jump_target(prev_text)
                            if push_target and push_target not in successors:
                                successors.append(push_target)
                            break
                        prev_mnem = _get_mnemonic(prev_text)
                        if prev_mnem not in (
                            "nop",
                            "int3",
                            "ud2",
                            "nopw",
                            "align",
                            "data16",
                        ):
                            break
                if is_c:
                    is_call = True
                # Track switch table entries for annotation
                _block_switch_entries = _switch_entries if _switch_entries else []
                branch_kind = None
                operands = re.split(
                    rf"\b{re.escape(mnem)}\b", str(text or ""), maxsplit=1, flags=re.IGNORECASE
                )
                op_str = operands[1] if len(operands) == 2 else ""
                for adapter in adapters:
                    if adapter.is_return_instruction(mnem, op_str):
                        branch_kind = "ret"
                        break
                    branch_kind = adapter.classify_code_ref_mnemonic(mnem)
                    if branch_kind:
                        break
                if _block_switch_entries:
                    branch_kind = "jmp"
                if branch_kind not in {"jmp", "ret"} and i + 1 < len(lines):
                    next_a = _normalize_addr(lines[i + 1]["addr"])
                    if next_a not in successors:
                        successors.append(next_a)
                i += 1
                break
            i += 1
        # Ne pas re-incrémenter ici : la boucle interne a déjà positionné i
        # soit sur le prochain block_start (case 1), soit sur l'instruction
        # qui suit le branchement (case 2 : `i += 1; break` dans le inner).

        if block_lines:
            # Detect switch: build case annotations if jump table was found
            is_switch_block = bool(_block_switch_entries)
            switch_cases: list[dict] = []
            if is_switch_block:
                max_cases = _detect_switch_max_case(block_lines)
                for case_idx, entry in enumerate(_block_switch_entries):
                    switch_cases.append({"case": case_idx, "target": entry})
                # If we found fewer entries than cmp bound, note it
                if max_cases and len(switch_cases) < max_cases:
                    switch_cases.append({"case": "default", "target": None})
            blk = BasicBlock(
                addr=addr,
                lines=block_lines,
                successors=successors,
                is_call=is_call,
                is_switch=is_switch_block,
                switch_cases=switch_cases,
            )
            blocks.append(blk)
            block_map[addr] = len(blocks) - 1

    # Construire les edges
    edges = []
    for blk in blocks:
        for idx, succ in enumerate(blk.successors):
            if blk.is_switch:
                # Jump table : tous les successeurs sont des arcs jumptable
                # (testé en premier pour éviter la co-existence is_call+is_switch)
                edge_type = "jumptable"
            elif blk.is_call and len(blk.successors) == 1:
                edge_type = "call"
            elif blk.is_call and len(blk.successors) == 2:
                edge_type = "call" if idx == 0 else "fallthrough"
            elif len(blk.successors) == 2:
                edge_type = "jmp" if idx == 0 else "fallthrough"
            else:
                edge_type = "jmp"
            edge: dict = {"from": blk.addr, "to": succ, "type": edge_type}
            if edge_type == "jumptable":
                matching_cases = [
                    sc.get("case") for sc in blk.switch_cases if sc.get("target") == succ
                ]
                if matching_cases:
                    edge["case_label"] = matching_cases[0]
                    if len(matching_cases) > 1:
                        edge["case_labels"] = matching_cases
                else:
                    # Aucun match dans switch_cases → arc default
                    edge["case_label"] = "default"
            edges.append(edge)

    block_by_addr = {block.addr: block for block in blocks}
    for source_block in blocks:
        if not source_block.is_switch:
            continue
        for switch_case in source_block.switch_cases:
            target_addr = switch_case.get("target")
            if not target_addr:
                continue
            target_block = block_by_addr.get(target_addr)
            if not target_block:
                continue
            _append_incoming_switch_case(
                target_block,
                source_block.addr,
                switch_case.get("case"),
            )

    serialized_blocks = []
    for b in blocks:
        incoming_case_labels = [entry.get("case") for entry in b.incoming_switch_cases]
        unresolved_default = b.is_switch and any(
            sc.get("case") == "default" and sc.get("target") is None for sc in b.switch_cases
        )
        bd: dict = {
            "addr": b.addr,
            "lines": b.lines,
            "successors": b.successors,
            "is_call": b.is_call,
            "is_switch": b.is_switch,
            "switch_cases": b.switch_cases,
            "incoming_switch_cases": b.incoming_switch_cases,
            "incoming_case_labels": incoming_case_labels,
        }
        if unresolved_default:
            bd["unresolved_default"] = True
        serialized_blocks.append(bd)

    return {
        "blocks": serialized_blocks,
        "edges": edges,
        "support_level": support.level,
        "support_note": support.note,
    }


def build_cfg_for_function(
    lines: list[dict],
    func_addr: str,
    binary_path: str | None = None,
) -> dict:
    """Construit le CFG pour une seule fonction.

    Effectue un BFS depuis le bloc de début de la fonction, en suivant
    tous les edges sauf les edges "call" (qui traversent vers d'autres fonctions).

    Args:
        lines: Toutes les lignes de désassemblage
        func_addr: Adresse de début de la fonction (ex: "0x401000")
        binary_path: Chemin vers le binaire (pour jump tables)

    Returns:
        {"func_addr": str, "blocks": [...], "edges": [...]}
        Seulement les blocs et edges appartenant à la fonction.
    """
    from collections import defaultdict

    func_addr_norm = _normalize_addr(func_addr)

    full_cfg = build_cfg(lines, binary_path=binary_path)
    if not full_cfg["blocks"]:
        return {"func_addr": func_addr_norm, "blocks": [], "edges": []}

    block_by_addr = {b["addr"]: b for b in full_cfg["blocks"]}

    if func_addr_norm not in block_by_addr:
        return {"func_addr": func_addr_norm, "blocks": [], "edges": []}

    # Index des edges non-call (on ne traverse pas les appels de fonctions)
    non_call_successors: dict = defaultdict(list)
    for edge in full_cfg["edges"]:
        if edge["type"] != "call":
            non_call_successors[edge["from"]].append(edge["to"])

    # BFS depuis le bloc de départ
    visited: set = set()
    queue = [func_addr_norm]
    while queue:
        addr = queue.pop(0)
        if addr in visited:
            continue
        visited.add(addr)
        for succ in non_call_successors[addr]:
            if succ not in visited and succ in block_by_addr:
                queue.append(succ)

    func_blocks = [b for b in full_cfg["blocks"] if b["addr"] in visited]
    func_edges = [e for e in full_cfg["edges"] if e["from"] in visited and e["to"] in visited]

    return {
        "func_addr": func_addr_norm,
        "blocks": func_blocks,
        "edges": func_edges,
    }


def main() -> int:
    """Point d'entrée CLI : construit le CFG à partir du mapping de désassemblage."""
    import argparse
    import json
    import os

    parser = argparse.ArgumentParser(description="Build CFG from disassembly mapping")
    parser.add_argument("--mapping", required=True, help="Path to disasm mapping JSON")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument(
        "--function", help="Export CFG for a single function address (e.g. 0x401000)"
    )
    args = parser.parse_args()

    configure_logging()

    if not os.path.exists(args.mapping):
        logger.error("Mapping file not found: %s", args.mapping)
        return 1

    with open(args.mapping, "r", encoding="utf-8") as f:
        data = json.load(f)
    lines = data.get("lines", [])
    binary_path = data.get("binary")  # Chemin vers le binaire pour jump tables

    if args.function:
        cfg = build_cfg_for_function(lines, args.function, binary_path=binary_path)
        label = f"function {args.function}"
    else:
        cfg = build_cfg(lines, binary_path=binary_path)
        label = "full binary"

    out = json.dumps(cfg, indent=2)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"CFG ({label}) written to {args.output} ({len(cfg['blocks'])} blocks)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
