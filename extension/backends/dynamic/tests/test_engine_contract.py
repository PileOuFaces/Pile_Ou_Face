# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the dynamic runtime engine contract."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.dynamic.core.interfaces import ExecutionEngine, TraceConfigLike
from backends.dynamic.engine.unicorn import create_engine
from backends.dynamic.engine.unicorn.config import TraceConfig
from backends.dynamic.pipeline.run_pipeline import run_pipeline


class FakeEngine:
    name = "fake"

    def __init__(self) -> None:
        self.seen_binary_path: str | None = None
        self.seen_code: bytes = b""

    def trace_binary(
        self,
        code_bytes: bytes,
        config: TraceConfigLike,
        binary_path: str | None,
    ) -> dict:
        self.seen_code = code_bytes
        self.seen_binary_path = binary_path
        return {
            "snapshots": [],
            "meta": {"engine": self.name, "code_size": len(code_bytes)},
        }


class TestDynamicEngineContract(unittest.TestCase):
    def test_pipeline_accepts_execution_engine_contract(self):
        with TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample.bin"
            binary.write_bytes(b"\x90\xc3")
            engine = FakeEngine()

            result = run_pipeline(str(binary), None, object(), None, engine=engine)

        self.assertIsInstance(engine, ExecutionEngine)
        self.assertEqual(engine.seen_code, b"\x90\xc3")
        self.assertEqual(engine.seen_binary_path, str(binary))
        self.assertEqual(result["snapshots"], [])
        self.assertEqual(result["analysisByStep"], {})
        self.assertEqual(result["meta"]["engine"], "fake")
        self.assertEqual(result["meta"]["code_size"], 2)
        self.assertEqual(result["meta"]["dynamic_model_version"], 2)

    def test_unicorn_engine_satisfies_execution_engine_contract(self):
        engine = create_engine()

        self.assertIsInstance(engine, ExecutionEngine)
        self.assertEqual(engine.name, "unicorn")

    def test_unicorn_trace_config_satisfies_config_contract(self):
        config = TraceConfig(
            base=0x400000,
            stack_base=0x7FFFFFFDE000,
            stack_size=0x20000,
            max_steps=10,
            stack_entries=8,
            arch_bits=64,
            interp_base=0x7F0000000000,
            start_interp=False,
            stdin_data=b"",
            buffer_offset=None,
            buffer_size=0,
            start_symbol=None,
            argv1=None,
        )

        self.assertIsInstance(config, TraceConfigLike)

    def test_compat_pipeline_wrapper_reexports_canonical_function(self):
        from backends.dynamic.pipeline.run_pipeline import run_pipeline as canonical
        from backends.dynamic.run_pipeline import run_pipeline as compat

        self.assertIs(compat, canonical)


if __name__ == "__main__":
    unittest.main()
