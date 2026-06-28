#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Génère une trace statique (input.asm -> output.json).

Simule un petit sous-ensemble d'instructions et exporte des snapshots.
Voir docs/ARCHITECTURE_SCALABLE.md.
"""

from __future__ import annotations

import argparse
import json
import os

STACK_MAX = 1024
WORD_SIZE = 8
REG_NAMES = [
    "rax",
    "rbx",
    "rcx",
    "rdx",
    "rsi",
    "rdi",
    "rbp",
    "rsp",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
    "eax",
    "ebx",
    "ecx",
    "edx",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8_arm",
    "r9_arm",
    "r10_arm",
    "r11_arm",
    "r12_arm",
    "sp",
    "lr",
    "pc",
    "x0",
    "x1",
    "x2",
    "x3",
    "x4",
    "x5",
    "x6",
    "x7",
    "x8",
    "x9",
    "x10",
    "x11",
    "x12",
    "x13",
    "x14",
    "x15",
    "x16",
    "x17",
    "x18",
    "x19",
    "x20",
    "x21",
    "x22",
    "x23",
    "x24",
    "x25",
    "x26",
    "x27",
    "x28",
    "x29",
    "x30",
    "x31",
    "zero",
    "ra",
    "a0",
    "a1",
    "a2",
    "a3",
    "a4",
    "a5",
    "a6",
    "a7",
    "t0",
    "t1",
    "t2",
    "t3",
    "t4",
    "t5",
    "t6",
    "s0",
    "s1",
    "s2",
    "s3",
    "s4",
    "s5",
    "s6",
    "s7",
    "s8",
    "s9",
    "s10",
    "s11",
]

REG_ALIASES = {
    "$zero": "zero",
    "$0": "zero",
    "x0": "zero",
    "$ra": "ra",
    "$sp": "sp",
    "%sp": "sp",
    "%fp": "r11",
    "fp": "r11",
    "w0": "x0",
    "w1": "x1",
    "w2": "x2",
    "w3": "x3",
    "w4": "x4",
    "w5": "x5",
    "w6": "x6",
    "w7": "x7",
}


def trim_line(text: str) -> str:
    """Supprime les commentaires (;) et les espaces superflus."""
    if ";" in text:
        text = text.split(";", 1)[0]
    text = text.rstrip(" \t\r\n").lstrip(" \t")
    return text


def tokenize(text: str) -> list[str]:
    """Découpe une ligne en tokens (séparateurs : espace, tab, virgule)."""
    if not text:
        return []
    parts: list[str] = []
    current: list[str] = []
    for ch in text:
        if ch in (" ", "\t", ","):
            if current:
                parts.append("".join(current))
                current = []
            continue
        current.append(ch)
    if current:
        parts.append("".join(current))
    return parts


def parse_int64(token: str) -> int | None:
    """Parse un entier (décimal ou hex 0x) avec signe optionnel. Retourne None si invalide."""
    if not token:
        return None
    sign = 1
    token = token.strip()
    if token.startswith("#"):
        token = token[1:]
    if not token:
        return None
    if token[0] in ("+", "-"):
        sign = -1 if token[0] == "-" else 1
        token = token[1:]
    base = 10
    if token.startswith(("0x", "0X")):
        base = 16
        token = token[2:]
    if not token:
        return None
    try:
        return sign * int(token, base)
    except ValueError:
        return None


def normalize_register(token: str) -> str:
    """Normalise quelques alias de registres multi-arch."""
    cleaned = str(token or "").strip().lower().rstrip("!")
    cleaned = cleaned.strip("{}")
    return REG_ALIASES.get(cleaned, cleaned.lstrip("$%"))


def get_operand_value(regs: dict[str, int], token: str) -> int | None:
    """Retourne la valeur d'un opérande (registre ou littéral)."""
    reg = normalize_register(token)
    if reg in regs:
        return regs[reg]
    return parse_int64(token)


def set_register(regs: dict[str, int], token: str, value: int) -> bool:
    reg = normalize_register(token)
    if reg in {"zero", "x0"}:
        regs["zero"] = 0
        return True
    if reg not in regs:
        return False
    regs[reg] = value
    return True


def dump_state(step: int, instr: str, line: int, stack: list, regs: dict) -> dict:
    """Produit un snapshot au format JSON (step, instr, line, stack, registers)."""
    stack_items = [
        {"id": e["id"], "pos": idx, "size": WORD_SIZE, "value": e["value"]}
        for idx, e in enumerate(stack)
    ]
    reg_items = [
        {"name": n, "pos": idx, "size": WORD_SIZE, "value": regs.get(n, 0)}
        for idx, n in enumerate(REG_NAMES)
    ]
    return {
        "step": step,
        "instr": instr or "",
        "line": line,
        "stack": stack_items,
        "registers": reg_items,
    }


def parse_program(lines: list[tuple[int, str]]) -> tuple[list[dict], dict[str, int]]:
    """Parse un programme asm : instructions + table des labels. Retourne (program, labels)."""
    program: list[dict] = []
    labels: dict[str, int] = {}
    for line_number, raw in lines:
        trimmed = trim_line(raw)
        if not trimmed:
            continue
        instr_text = trimmed
        tokens = tokenize(trimmed)
        if not tokens:
            continue
        tok_index = 0
        while tok_index < len(tokens) and tokens[tok_index].endswith(":"):
            label_name = tokens[tok_index][:-1]
            if not label_name:
                tok_index += 1
                continue
            if label_name not in labels:
                labels[label_name] = len(program)
            tok_index += 1
        if tok_index >= len(tokens):
            continue
        program.append(
            {"instr": instr_text, "line": line_number, "tokens": tokens[tok_index:]}
        )
    return program, labels


def simulate(program: list[dict], labels: dict[str, int]) -> list[dict]:
    """Simule l'exécution du programme et retourne la liste des snapshots."""
    regs: dict[str, int] = {name: 0 for name in REG_NAMES}
    stack: list[dict] = []
    next_id = 1
    snapshots: list[dict] = []
    step = 0
    pc = 0
    zero_flag = False

    while 0 <= pc < len(program):
        inst = program[pc]
        tokens = inst["tokens"]
        op = tokens[0].lower() if tokens else ""
        handled = False
        jumped = False

        if op in {"ret", "retq", "retn"}:
            break
        if (
            op in {"jr", "bx"}
            and len(tokens) >= 2
            and normalize_register(tokens[1]) in {"ra", "lr"}
        ):
            break

        if op in {"mov", "mv", "move", "li", "la"} and len(tokens) >= 3:
            dst, src = tokens[1], tokens[2]
            value = get_operand_value(regs, src)
            if value is not None and set_register(regs, dst, value):
                handled = True
        elif op == "push" and len(tokens) >= 2:
            value = get_operand_value(regs, tokens[1])
            if value is not None and len(stack) < STACK_MAX:
                stack.append({"id": next_id, "value": value})
                next_id += 1
                handled = True
        elif op == "pop":
            if stack:
                value = stack.pop()["value"]
                if len(tokens) >= 2:
                    set_register(regs, tokens[1], value)
                handled = True
        elif op in ("add", "sub", "mul", "div") and len(tokens) == 1:
            if len(stack) >= 2:
                b, a = stack.pop()["value"], stack.pop()["value"]
                if op == "add":
                    res = a + b
                elif op == "sub":
                    res = a - b
                elif op == "mul":
                    res = a * b
                else:
                    res = int(a / b) if b != 0 else None
                if res is not None:
                    stack.append({"id": next_id, "value": res})
                    next_id += 1
                    handled = True
        elif (
            op in ("add", "sub", "mul", "div", "addi", "addiu", "daddiu", "subi")
            and len(tokens) >= 3
        ):
            dst, src = tokens[1], tokens[2]
            lhs = get_operand_value(regs, dst if len(tokens) == 3 else src)
            rhs = get_operand_value(regs, tokens[2] if len(tokens) == 3 else tokens[3])
            if lhs is not None and rhs is not None:
                if op in {"add", "addi", "addiu", "daddiu"}:
                    res = lhs + rhs
                elif op in {"sub", "subi"}:
                    res = lhs - rhs
                elif op == "mul":
                    res = lhs * rhs
                else:
                    res = int(lhs / rhs) if rhs != 0 else None
                if res is not None and set_register(regs, dst, res):
                    handled = True
        elif op in {"jmp", "j", "b", "ba"} and len(tokens) >= 2:
            target = labels.get(tokens[1], -1)
            if target >= 0:
                pc = target
                jumped = True
        elif op == "loop" and len(tokens) >= 2:
            regs["rcx"] = regs.get("rcx", 0) - 1
            target = labels.get(tokens[1], -1)
            if target >= 0 and regs.get("rcx", 0) != 0:
                pc = target
                jumped = True
            handled = True
        elif op == "cmp" and len(tokens) >= 3:
            lhs = get_operand_value(regs, tokens[1])
            rhs = get_operand_value(regs, tokens[2])
            if lhs is not None and rhs is not None:
                zero_flag = lhs == rhs
                handled = True
        elif (
            op in {"je", "jz"}
            and len(tokens) >= 2
            and zero_flag
            or op in {"jne", "jnz"}
            and len(tokens) >= 2
            and not zero_flag
        ):
            target = labels.get(tokens[1], -1)
            if target >= 0:
                pc = target
                jumped = True
        elif op in {"beq", "bne"} and len(tokens) >= 4:
            lhs = get_operand_value(regs, tokens[1])
            rhs = get_operand_value(regs, tokens[2])
            target = labels.get(tokens[3], -1)
            should_jump = (
                lhs is not None
                and rhs is not None
                and target >= 0
                and ((op == "beq" and lhs == rhs) or (op == "bne" and lhs != rhs))
            )
            if should_jump:
                pc = target
                jumped = True
            handled = lhs is not None and rhs is not None
        elif op in {"beqz", "bnez"} and len(tokens) >= 3:
            lhs = get_operand_value(regs, tokens[1])
            target = labels.get(tokens[2], -1)
            should_jump = (
                lhs is not None
                and target >= 0
                and ((op == "beqz" and lhs == 0) or (op == "bnez" and lhs != 0))
            )
            if should_jump:
                pc = target
                jumped = True
            handled = lhs is not None

        if not jumped:
            pc += 1
        regs["zero"] = 0
        if handled:
            step += 1
            snapshots.append(dump_state(step, inst["instr"], inst["line"], stack, regs))

    return snapshots


def main() -> int:
    """Point d'entrée CLI : input.asm -> output.json (trace statique)."""
    parser = argparse.ArgumentParser(description="Static stack parser for input.asm")
    parser.add_argument("--input", required=True, help="Path to input.asm")
    parser.add_argument("--output", default="output.json", help="Output JSON path")
    args = parser.parse_args()

    if not os.path.exists(args.input):
        raise SystemExit(f"input.asm introuvable: {args.input}")

    with open(args.input, encoding="utf-8") as handle:
        raw_lines = handle.readlines()

    lines = [(idx + 1, line) for idx, line in enumerate(raw_lines)]
    program, labels = parse_program(lines)
    snapshots = simulate(program, labels)

    payload = {
        "snapshots": snapshots,
        "meta": {"view_mode": "static", "asm_path": args.input, "word_size": WORD_SIZE},
        "risks": [],
    }

    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
