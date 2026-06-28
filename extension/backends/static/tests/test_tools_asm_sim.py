# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour tools.static.asm_sim."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.disasm.asm_sim import (
    main,
    parse_int64,
    parse_program,
    simulate,
    tokenize,
    trim_line,
)


class TestTrimLine(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(trim_line(""), "")
        self.assertEqual(trim_line("   "), "")

    def test_comment_removed(self):
        self.assertEqual(trim_line("push 1 ; comment"), "push 1")
        self.assertEqual(trim_line("mov rax, 0  ; trailing"), "mov rax, 0")

    def test_strip_whitespace(self):
        self.assertEqual(trim_line("  push 1  "), "push 1")


class TestTokenize(unittest.TestCase):
    def test_empty(self):
        self.assertEqual(tokenize(""), [])

    def test_simple(self):
        self.assertEqual(tokenize("push 1"), ["push", "1"])
        self.assertEqual(tokenize("mov rax, rbx"), ["mov", "rax", "rbx"])

    def test_comma_separator(self):
        self.assertEqual(tokenize("add rax,rbx"), ["add", "rax", "rbx"])


class TestParseInt64(unittest.TestCase):
    def test_decimal(self):
        self.assertEqual(parse_int64("0"), 0)
        self.assertEqual(parse_int64("42"), 42)
        self.assertEqual(parse_int64("-10"), -10)

    def test_hex(self):
        self.assertEqual(parse_int64("0x40"), 64)
        self.assertEqual(parse_int64("0xFF"), 255)
        self.assertEqual(parse_int64("-0x10"), -16)

    def test_invalid(self):
        self.assertIsNone(parse_int64(""))
        self.assertIsNone(parse_int64("abc"))
        self.assertIsNone(parse_int64("0x"))


class TestParseProgram(unittest.TestCase):
    def test_labels(self):
        lines = [(1, "start:"), (2, "push 1"), (3, "pop rax")]
        program, labels = parse_program(lines)
        self.assertIn("start", labels)
        self.assertEqual(labels["start"], 0)
        self.assertEqual(len(program), 2)

    def test_instruction_with_label(self):
        lines = [(1, "loop:"), (2, "push rcx"), (3, "jmp loop")]
        program, labels = parse_program(lines)
        self.assertEqual(labels["loop"], 0)
        self.assertEqual(program[0]["tokens"][0], "push")
        self.assertEqual(program[1]["tokens"][0], "jmp")


class TestSimulate(unittest.TestCase):
    def test_push_pop(self):
        lines = [(1, "push 1"), (2, "push 2"), (3, "pop rax")]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        self.assertGreaterEqual(len(snapshots), 2)
        last = snapshots[-1]
        self.assertEqual(last["registers"][0]["name"], "rax")
        self.assertEqual(last["registers"][0]["value"], 2)

    def test_add_stack(self):
        lines = [(1, "push 1"), (2, "push 2"), (3, "add"), (4, "pop rax")]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        rax = next(r for r in last["registers"] if r["name"] == "rax")
        self.assertEqual(rax["value"], 3)

    def test_mov(self):
        lines = [(1, "mov rax, 42"), (2, "mov rbx, rax")]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        rax = next(r for r in last["registers"] if r["name"] == "rax")
        rbx = next(r for r in last["registers"] if r["name"] == "rbx")
        self.assertEqual(rax["value"], 42)
        self.assertEqual(rbx["value"], 42)

    def test_jmp(self):
        lines = [
            (1, "push 1"),
            (2, "jmp skip"),
            (3, "push 99"),
            (4, "skip:"),
            (5, "pop rax"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        rax = next(r for r in last["registers"] if r["name"] == "rax")
        self.assertEqual(rax["value"], 1)

    def test_riscv_style_li_addi_and_mv(self):
        lines = [
            (1, "li a0, 4"),
            (2, "addi a1, a0, 6"),
            (3, "mv a2, a1"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        a1 = next(r for r in last["registers"] if r["name"] == "a1")
        a2 = next(r for r in last["registers"] if r["name"] == "a2")
        self.assertEqual(a1["value"], 10)
        self.assertEqual(a2["value"], 10)

    def test_mips_style_register_alias_and_branch(self):
        lines = [
            (1, "li $a0, 1"),
            (2, "li $a1, 2"),
            (3, "bne $a0, $a1, different"),
            (4, "li $a2, 99"),
            (5, "different:"),
            (6, "move $a2, $a1"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        a2 = next(r for r in last["registers"] if r["name"] == "a2")
        self.assertEqual(a2["value"], 2)

    def test_arm_style_hash_immediates_and_branch(self):
        lines = [
            (1, "mov r0, #3"),
            (2, "add r1, r0, #4"),
            (3, "cmp r1, #7"),
            (4, "beq done"),
            (5, "mov r2, #99"),
            (6, "done:"),
            (7, "mov r2, r1"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        r2 = next(r for r in last["registers"] if r["name"] == "r2")
        self.assertEqual(r2["value"], 7)

    def test_return_stops_trace(self):
        lines = [
            (1, "mov rax, 1"),
            (2, "ret"),
            (3, "mov rax, 99"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        rax = next(r for r in last["registers"] if r["name"] == "rax")
        self.assertEqual(rax["value"], 1)

    def test_beqz_and_la_aliases(self):
        lines = [
            (1, "la a0, 0x4000"),
            (2, "li a1, 0"),
            (3, "beqz a1, done"),
            (4, "li a0, 0"),
            (5, "done:"),
        ]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        last = snapshots[-1]
        a0 = next(r for r in last["registers"] if r["name"] == "a0")
        self.assertEqual(a0["value"], 0x4000)


class TestMain(unittest.TestCase):
    def test_full_pipeline(self):
        with tempfile.TemporaryDirectory() as tmp:
            asm = Path(tmp) / "input.asm"
            asm.write_text("""start:
    push 1
    push 2
    add
    pop rax
""")
            out = Path(tmp) / "output.json"
            old_argv = sys.argv
            try:
                sys.argv = ["asm_sim", "--input", str(asm), "--output", str(out)]
                main()
            finally:
                sys.argv = old_argv
            self.assertTrue(out.exists())
            data = json.loads(out.read_text())
            self.assertIn("snapshots", data)
            self.assertIn("meta", data)
            self.assertEqual(data["meta"]["view_mode"], "static")
            self.assertGreater(len(data["snapshots"]), 0)

    def test_missing_input_exits(self):
        old_argv = sys.argv
        try:
            sys.argv = [
                "asm_sim",
                "--input",
                "/nonexistent.asm",
                "--output",
                "/tmp/out.json",
            ]
            with self.assertRaises(SystemExit):
                main()
        finally:
            sys.argv = old_argv


if __name__ == "__main__":
    unittest.main()
