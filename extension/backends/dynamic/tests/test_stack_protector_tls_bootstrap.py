# SPDX-License-Identifier: AGPL-3.0-only
"""Execution-infrastructure tests for the minimal TLS/FS_BASE bootstrap.

Stabilization audit context (stack-canary follow-up, infrastructure-only
PR): any binary compiled with -fstack-protector reads/checks its canary at
`fs:0x28` (standard glibc x86_64 layout). Before this fix, the Unicorn
engine never configured FS_BASE, so that very first read faulted with a
generic `UC_ERR_READ_UNMAPPED` -- on function ENTRY, before any overflow --
making it impossible to trace a canary-protected binary at all, corrupted or
not. `init_tls()` (engine/unicorn/stack.py) maps a small TLS page and points
FS_BASE at it so this read succeeds.

The __stack_chk_fail signal itself (tracer.py used to treat it like
exit()/abort(): a clean stop, no crash recorded) was fixed in a follow-up PR
(fix/dynamic-stack-chk-fail-crash) -- see test_stack_chk_fail_crash.py for
the dedicated coverage of that fix.
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
    from backends.dynamic.engine.unicorn.tracer import trace_binary
except SystemExit as exc:  # pragma: no cover - optional dependency in local envs
    TraceConfig = None
    trace_binary = None
    UNICORN_SKIP_REASON = str(exc)
else:
    UNICORN_SKIP_REASON = ""


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
class TestStackProtectorTlsBootstrap(unittest.TestCase):
    """Minimal canary_intact / canary_corrupted validation corpus.

    Both programs share the exact same source (-fstack-protector-all, a
    16-byte stack buffer copied with strcpy) -- only the argv1 payload
    differs.
    """

    def test_canary_intact_program_runs_to_done_without_a_tls_read_crash(self):
        """Before the TLS fix: `mov rax, fs:0x28` in vulnerable()'s prologue
        faulted immediately with UC_ERR_READ_UNMAPPED, regardless of argv1.
        After the fix: the canary round-trips through the mapped TLS page
        and the untouched program runs cleanly to `done()`."""
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

    def test_canary_corrupted_program_reaches_stack_chk_fail_and_is_now_reported(
        self,
    ):
        """Updated by the stack_chk_fail follow-up PR (fix/dynamic-stack-chk-fail-crash).

        This test used to document that __stack_chk_fail was reached but
        its signal discarded (crash stayed None) -- that bug is now fixed
        (see test_stack_chk_fail_crash.py for the dedicated coverage of the
        fix itself). Kept here, adapted rather than deleted, so this file's
        own canary_intact/canary_corrupted corpus stays a complete,
        self-contained TLS regression pair.
        """
        overflow_payload = "A" * 64
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_canary_c(tmpdir, "canary_corrupted")
            result = trace_binary(
                binary.read_bytes(),
                _canary_config(argv1=overflow_payload),
                str(binary),
            )

        self.assertIsNone(result["meta"]["error"])
        simulated_calls = result["meta"].get("simulated_external_calls", {})
        self.assertEqual(
            simulated_calls.get("__stack_chk_fail"),
            1,
            "expected the corrupted canary to actually reach "
            "__stack_chk_fail now that TLS/fs:0x28 no longer faults",
        )
        self.assertIsNotNone(result.get("crash"))
        self.assertEqual(result["crash"]["type"], "stack_chk_fail")


if __name__ == "__main__":
    unittest.main()
