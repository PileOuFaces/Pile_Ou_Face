# SPDX-License-Identifier: AGPL-3.0-only
"""__stack_chk_fail must surface as a typed crash, not be silently discarded.

Stabilization audit follow-up (stack-canary PR #2, after the TLS bootstrap
PR): the traced program's own stack protector can now actually run and
detect a corrupted canary (TLS/fs:0x28 is bootstrapped). But when it calls
__stack_chk_fail, `_simulate_symbol_with_args` (tracer.py) still handles it
identically to exit()/abort(): a clean uc.emu_stop(), no crash recorded.
`trace["crash"]` stays None, so diagnostics.py never sees anything.

This file has two layers, matching the requested test plan:
  * TestStackChkFailSignal -- a fast, isolated unit test directly against
    `_simulate_symbol_with_args`, using a minimal fake Unicorn engine.
  * TestStackChkFailCorpus -- an end-to-end test compiling a real
    -fstack-protector-all -O0 -fno-omit-frame-pointer C program and tracing
    it with the real engine (`trace_binary`).

Both are skipped (not failed) when their optional dependency (unicorn, gcc)
is unavailable, matching the existing convention in this test package.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    from backends.dynamic.engine.unicorn.config import TraceConfig
    from backends.dynamic.engine.unicorn.tracer import (
        _simulate_symbol_with_args,
        trace_binary,
    )
except SystemExit as exc:  # pragma: no cover - optional dependency in local envs
    TraceConfig = None
    trace_binary = None
    _simulate_symbol_with_args = None
    UNICORN_SKIP_REASON = str(exc)
else:
    UNICORN_SKIP_REASON = ""


class _FakeUc:
    """Minimal Unicorn stand-in -- only what _record_crash_context/emu_stop need."""

    def __init__(self) -> None:
        self.stopped = False
        self._pc = 0x401234

    def reg_read(self, _reg_id: int) -> int:
        return self._pc

    def emu_stop(self) -> None:
        self.stopped = True


@unittest.skipIf(_simulate_symbol_with_args is None, UNICORN_SKIP_REASON)
class TestStackChkFailSignal(unittest.TestCase):
    def test_stack_chk_fail_call_is_recorded_as_a_typed_crash_context(self):
        """RED before the fix: state.get("crash_context") stays None -- the
        signal is silently discarded, identically to exit()/abort()."""
        uc = _FakeUc()
        state: dict = {"pc_reg": 0}

        result = _simulate_symbol_with_args(
            uc, 64, "__stack_chk_fail", 0x7FFF0000, 8, state
        )

        self.assertEqual(result, 0)
        self.assertTrue(uc.stopped)
        self.assertIsInstance(state.get("crash_context"), dict)
        self.assertEqual(state["crash_context"]["type"], "stack_chk_fail")

    def test_exit_and_abort_still_stop_cleanly_without_a_crash_context(self):
        """Regression guard: exit()/abort() keep their pre-existing behavior
        -- clean stop, no crash_context. Only __stack_chk_fail gets the new
        typed-crash treatment; this must not leak onto normal termination."""
        for symbol in ("exit", "_exit", "abort"):
            with self.subTest(symbol=symbol):
                uc = _FakeUc()
                state: dict = {"pc_reg": 0}

                result = _simulate_symbol_with_args(
                    uc, 64, symbol, 0x7FFF0000, 8, state
                )

                self.assertEqual(result, 0)
                self.assertTrue(uc.stopped)
                self.assertIsNone(state.get("crash_context"))


# --- End-to-end corpus: canary_intact / canary_corrupted -------------------


_CANARY_SOURCE = r"""
    #include <string.h>
    volatile int sink;
    __attribute__((noinline)) void done(void) { sink += 1; }
    __attribute__((noinline, noipa)) void vulnerable(const char *input) {
        char buf[16];
        strcpy(buf, input);
    }
    int main(int argc, char **argv) {
        if (argc > 1) {
            vulnerable(argv[1]);
        }
        done();
        return 0;
    }
"""


def _compile_canary_c(tmpdir: str, name: str) -> Path:
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("gcc is required for the canary corpus tests")
    src = Path(tmpdir) / f"{name}.c"
    binary = Path(tmpdir) / name
    src.write_text(textwrap.dedent(_CANARY_SOURCE), encoding="utf-8")
    result = subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-fstack-protector-all",
            "-fno-omit-frame-pointer",
            str(src),
            "-o",
            str(binary),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise unittest.SkipTest(f"gcc failed: {result.stderr.strip()}")
    return binary


def _canary_config(argv1: str | None) -> TraceConfig:
    return TraceConfig(
        base=0x400000,
        stack_base=0x7FFFFFFDE000,
        stack_size=0x40000,
        max_steps=20000,
        stack_entries=32,
        arch_bits=64,
        interp_base=0x7F0000000000,
        start_interp=False,
        stdin_data=b"",
        buffer_offset=None,
        buffer_size=0,
        start_symbol="main",
        argv1=argv1,
        stop_symbol="done",
        capture_ranges=[],
    )


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestStackChkFailCorpus(unittest.TestCase):
    """canary_intact / canary_corrupted, same source, only argv1 differs."""

    def test_canary_intact_reaches_done_with_no_crash_and_no_false_positive(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_canary_c(tmpdir, "canary_intact")
            result = trace_binary(
                binary.read_bytes(), _canary_config(argv1="AAAA"), str(binary)
            )

        self.assertIsNone(result["meta"]["error"])
        self.assertIsNone(result.get("crash"))
        self.assertEqual(
            result["snapshots"][-1]["instruction"]["address"],
            result["meta"]["stop_addr"],
        )

    def test_canary_corrupted_is_reported_as_a_typed_stack_chk_fail_crash(self):
        """RED before the fix: crash stays None even though
        __stack_chk_fail is reached (simulated_external_calls proves it)."""
        overflow_payload = "A" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_canary_c(tmpdir, "canary_corrupted")
            result = trace_binary(
                binary.read_bytes(),
                _canary_config(argv1=overflow_payload),
                str(binary),
            )

        self.assertEqual(
            result["meta"].get("simulated_external_calls", {}).get(
                "__stack_chk_fail"
            ),
            1,
        )
        self.assertIsNotNone(
            result.get("crash"),
            "expected a typed crash once __stack_chk_fail fires -- got None",
        )
        self.assertEqual(result["crash"]["type"], "stack_chk_fail")
        reason = str(result["crash"].get("reason") or "").lower()
        self.assertTrue(
            "protecteur" in reason or "canary" in reason or "stack_chk_fail" in reason,
            f"unexpected crash reason: {result['crash'].get('reason')!r}",
        )


if __name__ == "__main__":
    unittest.main()
