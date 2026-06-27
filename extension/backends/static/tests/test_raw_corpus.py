# SPDX-License-Identifier: AGPL-3.0-only
"""Corpus de régression pour blobs bruts / shellcodes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.disasm.call_graph import build_call_graph
from backends.static.disasm.cfg import build_cfg
from backends.static.disasm.discover_functions import discover_functions
from backends.static.search.search import search_in_binary
from backends.static.tests.fixtures.raw_fixture import (
    write_raw_arm32_call_fixture,
    write_raw_arm64_call_fixture,
    write_raw_mips32_be_call_fixture,
    write_raw_mips32_le_call_fixture,
    write_raw_ppc32_be_partial_call_fixture,
    write_raw_ppc32_be_call_fixture,
    write_raw_thumb_call_fixture,
    write_raw_thumb_partial_call_fixture,
    write_raw_x64_call_fixture,
)
from backends.static.disasm.xrefs import extract_xrefs

try:
    import capstone as _capstone

    _CAPSTONE_AVAILABLE = True
except ImportError:
    _CAPSTONE_AVAILABLE = False


RAW_FIXTURE_WRITERS = (
    ("x64", write_raw_x64_call_fixture),
    ("arm64", write_raw_arm64_call_fixture),
    ("arm32", write_raw_arm32_call_fixture),
    ("thumb", write_raw_thumb_call_fixture),
    ("thumb_partial", write_raw_thumb_partial_call_fixture),
    ("mips32_be", write_raw_mips32_be_call_fixture),
    ("mips32_le", write_raw_mips32_le_call_fixture),
    ("ppc32_be", write_raw_ppc32_be_call_fixture),
    ("ppc32_be_partial", write_raw_ppc32_be_partial_call_fixture),
)


@unittest.skipUnless(_CAPSTONE_AVAILABLE, "capstone not installed")
class TestRawCorpus(unittest.TestCase):
    def test_raw_shellcode_python_pipeline(self):
        for label, writer in RAW_FIXTURE_WRITERS:
            with self.subTest(arch=label), tempfile.TemporaryDirectory() as tmp:
                sample = writer(tmp)
                lines = sample["lines"]

                self.assertGreaterEqual(len(lines), 3)
                self.assertEqual(lines[0]["addr"], sample["entry_addr"])

                discovered = discover_functions(lines, set())
                discovered_addrs = {fn["addr"] for fn in discovered}
                self.assertIn(sample["entry_addr"], discovered_addrs)
                self.assertIn(sample["target_addr"], discovered_addrs)

                cfg = build_cfg(lines, arch_hint=sample.get("arch_hint"))
                self.assertTrue(
                    any(
                        edge.get("type") == "call"
                        and edge.get("from") == sample["entry_addr"]
                        and edge.get("to") == sample["target_addr"]
                        for edge in cfg.get("edges", [])
                    )
                )

                call_graph = build_call_graph(cfg, discovered, lines=lines)
                self.assertEqual(len(call_graph["edges"]), 1)
                self.assertEqual(
                    call_graph["edges"][0]["from_name"], f"sub_{sample['entry_addr'][2:]}"
                )
                self.assertEqual(
                    call_graph["edges"][0]["to_name"], f"sub_{sample['target_addr'][2:]}"
                )

                refs = extract_xrefs(lines, sample["target_addr"], functions=discovered)
                self.assertEqual(len(refs), 1)
                self.assertEqual(refs[0]["type"], "call")
                self.assertEqual(refs[0]["from_addr"], sample["call_site_addr"])
                self.assertEqual(refs[0]["function_addr"], sample["entry_addr"])
                self.assertEqual(refs[0]["function_name"], f"sub_{sample['entry_addr'][2:]}")

                call_bytes = next(
                    line["bytes"].replace(" ", "").lower()
                    for line in lines
                    if line["addr"] == sample["call_site_addr"]
                )
                hits = search_in_binary(
                    str(sample["blob_path"]),
                    call_bytes,
                    mode="hex",
                    raw_base_addr=sample["raw"]["base_addr"],
                )
                self.assertEqual(len(hits), 1)
                self.assertEqual(hits[0]["vaddr_hex"], sample["call_site_addr"])

    def test_raw_shellcode_cli_pipeline(self):
        env = {**os.environ, "PYTHONPATH": str(ROOT)}

        for label, writer in RAW_FIXTURE_WRITERS:
            with self.subTest(arch=label), tempfile.TemporaryDirectory() as tmp:
                sample = writer(tmp)
                mapping_path = Path(sample["mapping_path"])
                discovered_path = Path(tmp) / f"{mapping_path.stem}.discovered.json"

                discovered_proc = subprocess.run(
                    [
                        sys.executable,
                        "backends/static/disasm/discover_functions.py",
                        "--mapping",
                        str(mapping_path),
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    env=env,
                )
                self.assertEqual(discovered_proc.returncode, 0, discovered_proc.stderr)
                discovered = json.loads(discovered_proc.stdout)
                discovered_addrs = {fn["addr"] for fn in discovered}
                self.assertIn(sample["entry_addr"], discovered_addrs)
                self.assertIn(sample["target_addr"], discovered_addrs)
                discovered_path.write_text(
                    json.dumps(discovered, indent=2),
                    encoding="utf-8",
                )

                call_graph_proc = subprocess.run(
                    [
                        sys.executable,
                        "backends/static/disasm/call_graph.py",
                        "--mapping",
                        str(mapping_path),
                        "--symbols",
                        str(discovered_path),
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    env=env,
                )
                self.assertEqual(call_graph_proc.returncode, 0, call_graph_proc.stderr)
                call_graph = json.loads(call_graph_proc.stdout)
                self.assertEqual(len(call_graph["edges"]), 1)
                self.assertEqual(
                    call_graph["edges"][0]["from_name"], f"sub_{sample['entry_addr'][2:]}"
                )
                self.assertEqual(
                    call_graph["edges"][0]["to_name"], f"sub_{sample['target_addr'][2:]}"
                )

                xrefs_proc = subprocess.run(
                    [
                        sys.executable,
                        "backends/static/disasm/xrefs.py",
                        "--mapping",
                        str(mapping_path),
                        "--functions",
                        str(discovered_path),
                        "--addr",
                        sample["target_addr"],
                        "--mode",
                        "to",
                    ],
                    capture_output=True,
                    text=True,
                    cwd=str(ROOT),
                    env=env,
                )
                self.assertEqual(xrefs_proc.returncode, 0, xrefs_proc.stderr)
                xrefs = json.loads(xrefs_proc.stdout)
                self.assertEqual(len(xrefs["refs"]), 1)
                self.assertEqual(xrefs["refs"][0]["from_addr"], sample["call_site_addr"])
                self.assertEqual(
                    xrefs["refs"][0]["function_name"], f"sub_{sample['entry_addr'][2:]}"
                )


if __name__ == "__main__":
    unittest.main()
