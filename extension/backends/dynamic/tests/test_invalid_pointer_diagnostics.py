# SPDX-License-Identifier: AGPL-3.0-only
"""Fix mislabeled memory crashes: a NULL/invalid pointer dereference must
never be attributed to saved_bp/return_address corruption without evidence,
and must never be downgraded to an "info, not a real problem" severity.

Root cause (see tmp/audits/pointers-pedagogy-audit.md and GitHub issue
#300), two independent defects, both in `run_pipeline.py`:

1. `_guess_crash_slot`'s saved_bp branch fires on *any* unmapped_read/
   unmapped_write crash via the condition `... or not _is_code_address
   (bp_value, code_ranges)` -- `bp_value` (the `rbp` register) is *never*
   a code address, corrupted or not, so this clause is tautologically
   true and the branch attributes every data-access crash to saved_bp
   regardless of the actual faulting address. The return_address branch
   has the mirror defect (`not _is_code_address(ip_value, ...)` is always
   true for any unmapped_fetch, since the crash itself proves the fetch
   address isn't known code).

2. `_build_crash_report`'s `fatal_crash -> benign_termination/
   emulator_stop` downgrade (gated on `_has_control_corruption_evidence`,
   which only ever checks saved_bp/return_address evidence) applies to
   *every* crash type, not just unmapped_fetch (the only case with a
   legitimate "ran past main into unemulated libc" ambiguity) -- so a
   genuine, unambiguous NULL/wild-pointer data-access crash gets
   presented as severity "info", "not a real problem".

`_diagnose_control_slots` (the evidence-gated saved_bp_corrupted/
return_address_corrupted mechanism, driven by real overflow/write
evidence) is a completely separate code path, untouched by this fix --
confirmed by real-corpus tests below.

All corpora are real `gcc -O0 -g -fno-stack-protector -no-pie` binaries
traced through the real Unicorn engine and the real run_pipeline -- no
synthetic snapshot fixtures for the RED/GREEN proof (synthetic fixtures
in test_diagnostics.py are re-verified separately as non-regression).
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

from backends.dynamic.pipeline.run_pipeline import run_pipeline


def _gcc_compile(tmpdir: str, name: str, source: str, extra_flags: tuple = ()) -> Path:
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("gcc is required for the invalid-pointer corpus")
    src = Path(tmpdir) / f"{name}.c"
    binary = Path(tmpdir) / name
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    result = subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-stack-protector",
            "-no-pie",
            *extra_flags,
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


def _config(**overrides) -> TraceConfig:
    base = {
        "base": 0x400000,
        "stack_base": 0x7FFFFFFDE000,
        "stack_size": 0x40000,
        "max_steps": 200,
        "stack_entries": 32,
        "arch_bits": 64,
        "interp_base": 0x7F0000000000,
        "start_interp": False,
        "stdin_data": b"",
        "buffer_offset": None,
        "buffer_size": 0,
        "start_symbol": "main",
        "argv1": None,
        "stop_symbol": None,
        "capture_ranges": [],
    }
    base.update(overrides)
    return TraceConfig(**base)


def _trace(binary_path: Path, **config_overrides) -> dict:
    # A real output_path is required for disasm_lines (code_ranges), same
    # gap as #299's test harness -- needed here too since _classify_crash
    # and _is_code_address both consult code_ranges.
    output_path = str(binary_path) + ".output.json"
    result = run_pipeline(
        str(binary_path), None, _config(**config_overrides), output_path
    )
    return result


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestInvalidPointerDiagnostics(unittest.TestCase):
    # ------------------------------------------------------------------
    # Test 1 -- NULL read direct (PoC A)
    # ------------------------------------------------------------------
    def test_null_read_is_diagnosed_correctly_not_as_saved_bp_corruption(self):
        """RED before the fix: suspectOverwrittenSlot is fabricated as
        saved_bp, and classification is downgraded to emulator_stop/info
        even though this is a genuine, fatal NULL dereference."""
        source = """
            #include <stddef.h>
            int main(void) {
                int *p = NULL;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "a_null_read", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("type"), "unmapped_read")
        self.assertEqual(crash.get("memoryAddress"), "0x0")
        self.assertIsNone(
            crash.get("suspectOverwrittenSlot"),
            f"no evidence ties this crash to saved_bp: {crash.get('suspectOverwrittenSlot')}",
        )
        self.assertEqual(crash.get("classification"), "fatal_crash")

        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertIn("null_pointer_dereference", kinds)
        null_diag = next(
            diag for diag in diagnostics if diag["kind"] == "null_pointer_dereference"
        )
        self.assertEqual(null_diag["severity"], "error")
        self.assertIsNone(null_diag.get("slot"))

    # ------------------------------------------------------------------
    # Test 2 -- proven pointer stack -> NULL, then dereferenced (PoC B)
    # ------------------------------------------------------------------
    def test_stack_to_null_read_gets_the_same_diagnostic_family(self):
        source = """
            #include <stddef.h>
            int main(void) {
                int x = 42;
                int *p = &x;
                p = NULL;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "b_stack_to_null", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("memoryAddress"), "0x0")
        self.assertIsNone(crash.get("suspectOverwrittenSlot"))
        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertIn("null_pointer_dereference", kinds)

    # ------------------------------------------------------------------
    # Test 3 -- invalid read, non-NULL (PoC C): never "null"
    # ------------------------------------------------------------------
    def test_invalid_read_nonnull_is_never_labeled_null(self):
        source = """
            int main(void) {
                int *p = (int *)0x4141414141414141UL;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "c_invalid_read", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertNotEqual(crash.get("memoryAddress"), "0x0")
        self.assertIsNone(
            crash.get("suspectOverwrittenSlot"),
            "an address unrelated to saved_bp must not be blamed on it",
        )
        self.assertEqual(crash.get("classification"), "fatal_crash")
        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertNotIn("null_pointer_dereference", kinds)
        self.assertIn("fatal_crash", kinds)

    # ------------------------------------------------------------------
    # Test 4 -- NULL write (PoC D): read/write distinction preserved
    # ------------------------------------------------------------------
    def test_null_write_is_diagnosed_as_write_not_read(self):
        source = """
            #include <stddef.h>
            int main(void) {
                int *p = NULL;
                *p = 42;
                return 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "d_null_write", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("type"), "unmapped_write")
        self.assertEqual(crash.get("memoryAddress"), "0x0")
        self.assertIsNone(crash.get("suspectOverwrittenSlot"))
        diagnostics = result.get("diagnostics") or []
        null_diag = next(
            (
                diag
                for diag in diagnostics
                if diag["kind"] == "null_pointer_dereference"
            ),
            None,
        )
        self.assertIsNotNone(null_diag)
        self.assertIn(
            "criture", null_diag["message"]
        )  # "Ecriture..." (accent-stripped)
        self.assertNotIn("Lecture", null_diag["message"])

    # ------------------------------------------------------------------
    # Test 5 -- invalid write, non-NULL (PoC E): never "null"
    # ------------------------------------------------------------------
    def test_invalid_write_nonnull_is_never_labeled_null(self):
        source = """
            int main(void) {
                int *p = (int *)0x4141414141414141UL;
                *p = 42;
                return 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "e_invalid_write", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("type"), "unmapped_write")
        self.assertIsNone(crash.get("suspectOverwrittenSlot"))
        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertNotIn("null_pointer_dereference", kinds)

    # ------------------------------------------------------------------
    # Test 6 -- invalid fetch (PoC F): classification untouched, no false
    # return_address attribution when there is no evidence
    # ------------------------------------------------------------------
    def test_invalid_fetch_has_no_false_return_address_attribution(self):
        """Non-regression: unmapped_fetch keeps its existing classification
        behaviour (this fix deliberately does not touch the fetch-specific
        benign-termination ambiguity) -- but a wild `call rax` unrelated to
        this frame's own return_address slot must not be blamed on it."""
        source = """
            int main(void) {
                void (*fn)(void) = (void (*)(void))0x4141414141414141UL;
                fn();
                return 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "f_invalid_fetch", source)
            result = _trace(binary, max_steps=20)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("type"), "unmapped_fetch")
        slot = crash.get("suspectOverwrittenSlot")
        if slot is not None:
            self.fail(
                "no evidence ties this wild `call rax` to the frame's own "
                f"return_address slot: {slot}"
            )

    # ------------------------------------------------------------------
    # Test 7 -- genuine saved_bp corruption (PoC G): still detected
    # ------------------------------------------------------------------
    def test_genuine_saved_bp_corruption_still_detected(self):
        source = """
            #include <string.h>
            __attribute__((noinline, noipa)) void vulnerable(const char *input) {
                char buf[16];
                strcpy(buf, input);
            }
            int main(int argc, char **argv) {
                if (argc > 1) {
                    vulnerable(argv[1]);
                }
                return 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(
                tmpdir, "g_saved_bp", source, extra_flags=("-fno-omit-frame-pointer",)
            )
            result = _trace(binary, max_steps=100, argv1="A" * 23)

        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertIn(
            "saved_bp_corrupted",
            kinds,
            f"genuine saved_bp corruption must still be reported; got kinds={kinds}",
        )

    # ------------------------------------------------------------------
    # Test 8 -- genuine return-address corruption / control hijack (PoC H)
    # ------------------------------------------------------------------
    def test_genuine_return_address_corruption_still_detected(self):
        source = """
            #include <string.h>
            __attribute__((noinline, noipa)) void vulnerable(const char *input) {
                char buf[16];
                strcpy(buf, input);
            }
            int main(int argc, char **argv) {
                if (argc > 1) {
                    vulnerable(argv[1]);
                }
                return 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(
                tmpdir, "h_ret", source, extra_flags=("-fno-omit-frame-pointer",)
            )
            result = _trace(binary, max_steps=100, argv1="A" * 80)

        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertTrue(
            {"return_address_corrupted", "control_hijack", "fatal_crash"} & kinds,
            f"genuine return_address corruption must still be reported; got kinds={kinds}",
        )

    # ------------------------------------------------------------------
    # Test 9 -- stack_chk_fail: unchanged
    # ------------------------------------------------------------------
    def test_stack_chk_fail_still_reported_unchanged(self):
        source = """
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
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(
                tmpdir,
                "i_canary",
                source,
                extra_flags=("-fstack-protector-all", "-fno-omit-frame-pointer"),
            )
            result = _trace(binary, argv1="A" * 64, stop_symbol="done", max_steps=20000)

        crash = result.get("crash")
        self.assertIsNotNone(crash)
        self.assertEqual(crash.get("type"), "stack_chk_fail")
        self.assertEqual(crash.get("classification"), "stack_chk_fail")
        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertIn("stack_chk_fail", kinds)

    # ------------------------------------------------------------------
    # Test 10 -- plain zero int, no dereference: no crash, no diagnostic
    # ------------------------------------------------------------------
    def test_plain_zero_int_without_dereference_has_no_null_diagnostic(self):
        source = """
            int main(void) {
                int x = 0;
                return x;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "j_zero_int", source)
            result = _trace(binary, max_steps=8)

        self.assertIsNone(result.get("crash"))
        diagnostics = result.get("diagnostics") or []
        kinds = {diag.get("kind") for diag in diagnostics}
        self.assertNotIn("null_pointer_dereference", kinds)


if __name__ == "__main__":
    unittest.main()
