# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for pwntools payload script extraction."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.pipeline.payload_script_runner import analyze_script_text


class TestPayloadScriptRunner(unittest.TestCase):
    def test_global_payload_variable_is_exported(self):
        result = analyze_script_text('payload = b"A" * 8', source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertIn("payload", result["globals"])
        self.assertEqual(result["globals"]["payload"]["size"], 8)
        self.assertEqual(result["globals"]["payload"]["hex"], "4141414141414141")

    def test_sendline_capture_is_recorded(self):
        script = "\n".join([
            "from pwn import *",
            'payload = b"A" * 4',
            'io = process("./chall")',
            "io.sendline(payload)",
        ])

        result = analyze_script_text(script, source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["captured"]), 1)
        self.assertEqual(len(result["captures"]), 1)
        self.assertEqual(result["captured"][0]["kind"], "sendline")
        self.assertEqual(result["captures"][0]["type"], "sendline")
        self.assertEqual(result["captures"][0]["data"], "414141410a")
        self.assertEqual(result["captured"][0]["size"], 5)
        self.assertEqual(result["processes"][0]["argv"], ["./chall"])

    def test_p32_and_p64_are_supported(self):
        script = "\n".join([
            "from pwn import *",
            "payload = p32(0xdeadbeef) + p64(0x1122334455667788)",
        ])

        result = analyze_script_text(script, source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(
            result["globals"]["payload"]["hex"],
            "efbeadde8877665544332211",
        )

    def test_flat_is_supported(self):
        script = "\n".join([
            "from pwn import *",
            'payload = flat(b"AA", 0x42424242, word_size=4)',
        ])

        result = analyze_script_text(script, source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(result["globals"]["payload"]["hex"], "414142424242")

    def test_flat_word_size_64_is_treated_as_64_bits(self):
        script = "\n".join([
            "from pwn import *",
            "payload = flat(-1, word_size=64)",
        ])

        result = analyze_script_text(script, source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(result["globals"]["payload"]["hex"], "ffffffffffffffff")

    def test_missing_payload_emits_warning(self):
        result = analyze_script_text('print("hello")', source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(result["captured"], [])
        self.assertEqual(result["captures"], [])
        self.assertIn("Aucun payload capture", " ".join(result["warnings"]))

    def test_remote_is_blocked_but_sends_are_captured(self):
        script = "\n".join([
            "from pwn import *",
            "io = remote('example.com', 31337)",
            'io.send(b"PING")',
        ])

        result = analyze_script_text(script, source_file_name="solve.py")

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["captured"]), 1)
        self.assertEqual(result["captured"][0]["kind"], "send")
        self.assertIn("reseau desactive", " ".join(result["warnings"]))

    def test_script_can_use_sys_argv_elf_symbols_process_and_sendlineafter(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary_path = Path(tmpdir) / "chall"
            binary_path.write_bytes(b"\x7fELF\x00main\x00func_stub\x00")
            script = "\n".join([
                "from pwn import *",
                "import sys",
                "exe = sys.argv[1]",
                "elf = ELF(exe)",
                "io = process(exe)",
                "payload = flat(b'AAAA', p32(elf.symbols['main']))",
                "io.sendlineafter(b'> ', payload)",
            ])

            result = analyze_script_text(
                script,
                source_file_name="solve.py",
                script_args=[str(binary_path)],
                script_root=tmpdir,
            )

        self.assertTrue(result["ok"])
        self.assertEqual(len(result["captured"]), 1)
        self.assertEqual(result["captured"][0]["kind"], "sendlineafter")
        self.assertEqual(result["captured"][0]["processArgs"], [str(binary_path)])
        self.assertTrue(result["captured"][0]["hex"].startswith("41414141"))
        self.assertIn("payload", result["globals"])


if __name__ == "__main__":
    unittest.main()
