# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for label injection in disasm.py."""

import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import capstone as _capstone
    import lief as _lief

    _DISASM_AVAILABLE = True
except ImportError:
    _DISASM_AVAILABLE = False


def _import_make_elf():
    p = Path(__file__).parent / "fixtures" / "make_elf.py"
    spec = importlib.util.spec_from_file_location("make_elf", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.make_minimal_elf


make_minimal_elf = _import_make_elf()


def run_disasm(binary, extra_args, tmp_dir):
    tmp_asm = os.path.join(tmp_dir, "out.asm")
    r = subprocess.run(
        [
            sys.executable,
            "backends/static/disasm/disasm.py",
            "--binary",
            binary,
            "--output",
            tmp_asm,
        ]
        + extra_args,
        capture_output=True,
        text=True,
        cwd=str(ROOT),
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )
    asm = Path(tmp_asm).read_text() if Path(tmp_asm).exists() else ""
    return r, asm


def make_ann(d, entries):
    p = Path(d) / "ann.json"
    p.write_text(json.dumps(entries))
    return str(p)


@unittest.skipUnless(_DISASM_AVAILABLE, "lief/capstone not installed")
class TestLabelsInline(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.binary = os.path.join(self.tmp, "test.elf")
        make_minimal_elf(self.binary)

    def test_no_annotations_no_crash(self):
        """Disasm without --annotations-json works normally."""
        r, asm = run_disasm(self.binary, [], self.tmp)
        self.assertEqual(r.returncode, 0, msg=f"stderr: {r.stderr}")
        self.assertGreater(len(asm), 0)

    def test_label_header_inserted(self):
        """When an address has a name, a label line appears before it."""
        _, asm = run_disasm(self.binary, [], self.tmp)
        lines = [l for l in asm.splitlines() if l.strip().startswith("0x")]
        if not lines:
            self.skipTest("No disasm lines found")
        addr_str = lines[0].strip().split(":")[0].strip()
        with tempfile.TemporaryDirectory() as d:
            ann = make_ann(d, {addr_str: {"name": "my_func", "comment": ""}})
            _, asm2 = run_disasm(self.binary, ["--annotations-json", ann], self.tmp)
        self.assertIn("my_func:", asm2)

    def test_call_operand_replaced(self):
        """call 0x<addr> becomes call <name> when name is known."""
        _, asm = run_disasm(self.binary, [], self.tmp)
        calls = [l for l in asm.splitlines() if "call" in l and "0x" in l]
        if not calls:
            self.skipTest("No call instructions found")
        target = None
        for call_line in calls:
            m = re.search(r"(0x[0-9a-f]+)\s*$", call_line)
            if m:
                target = m.group(1)
                break
        if not target:
            self.skipTest("Could not parse call target")
        with tempfile.TemporaryDirectory() as d:
            ann = make_ann(d, {target: {"name": "encrypt_payload", "comment": ""}})
            _, asm2 = run_disasm(self.binary, ["--annotations-json", ann], self.tmp)
        self.assertIn("encrypt_payload", asm2)


if __name__ == "__main__":
    unittest.main()
