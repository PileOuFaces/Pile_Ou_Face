# SPDX-License-Identifier: AGPL-3.0-only
"""A leaf function that uses the x86-64 red zone instead of `sub rsp, N`
must still show its local variables in the Stack Model.

Root cause (see tmp/audits/pointers-pedagogy-audit.md and GitHub issue
#298): `build_dynamic_analysis` (stack_model.py) only flips
`frame_allocated` to True once it observes the literal instruction
`sub rsp,N`/`sub esp,N` after `mov rbp,rsp`. A leaf function with few
enough locals can use the System V ABI red zone (128 bytes below rsp)
instead of ever emitting `sub rsp`, which is exactly what `gcc -O0`
produces for the simplest possible pointer example
(`int main(void) { int x = 42; int *p = &x; return *p; }`) compiled
without any special flag. `frame_allocated` then stays False for the
entire function, and `_slot_role_label` (stack_model.py) silently drops
every slot that is not `saved_bp`/`return_address` -- not shown as
"unknown", just absent.

All corpora below are real `gcc -O0 -g -fno-stack-protector -no-pie`
binaries (deliberately WITHOUT `-mno-red-zone`, the opposite of issue
#297's tests, to isolate this bug) traced through the real Unicorn
engine and the real `build_dynamic_analysis` pipeline -- no synthetic
snapshot fixtures.
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
        raise unittest.SkipTest("gcc is required for the red-zone corpus")
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
            # Deliberately NOT -mno-red-zone: this is the whole point.
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
        # Same rationale as test_pointer_slot_fragmentation.py: a trivial
        # done() call stops the trace right after the interesting
        # computation, before it runs off main's own `ret` into libc's
        # unmapped-in-this-emulator startup/teardown path.
        "stop_symbol": "done",
        "capture_ranges": [],
    }
    base.update(overrides)
    return TraceConfig(**base)


def _trace(binary_path: Path, **config_overrides) -> dict:
    result = run_pipeline(str(binary_path), None, _config(**config_overrides), None)
    assert result["meta"].get("error") is None, result["meta"].get("error")
    return result


def _all_slots(result: dict):
    for analysis in result["analysisByStep"].values():
        yield from (analysis.get("frame") or {}).get("slots", [])


def _slots_with_role(result: dict, role: str):
    return [slot for slot in _all_slots(result) if slot.get("role") == role]


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestRedZoneFrameAllocation(unittest.TestCase):
    # ------------------------------------------------------------------
    # Test 1 -- leaf function, red zone, no explicit -mno-red-zone
    # ------------------------------------------------------------------
    def test_leaf_function_locals_are_visible_without_sub_rsp(self):
        """RED before the fix: analysisByStep has zero slots for x/p --
        only saved_bp/return_address -- because gcc never emits `sub rsp`
        for this function (confirmed via objdump: push/mov rbp,rsp/mov
        [rbp-0xc].../lea/mov [rbp-8].../pop rbp/ret, no `sub` anywhere).

        This is the exact source from the issue, with no `done()`/global
        sink sentinel: calling any function at all -- even a no-op --
        would make `main` non-leaf and gcc would stop using the red zone,
        defeating the whole point of this test. Instead, `max_steps=8`
        stops the trace right after `pop rbp` (the 8th real instruction),
        before `ret` would jump to the synthetic return address set up
        for a trace that starts directly at `main` -- which is otherwise
        an unmapped-fetch crash unrelated to the bug under test."""
        source = """
            int main(void) {
                int x = 42;
                int *p = &x;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "a_simple", source)
            result = _trace(binary, stop_symbol=None, max_steps=8)

        locals_ = _slots_with_role(result, "local")
        self.assertTrue(
            locals_,
            "expected local slots for x/p to be visible even though this "
            "leaf function uses the red zone instead of `sub rsp`",
        )
        pointer_slots = [
            slot
            for slot in locals_
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(
            pointer_slots,
            f"expected p to be a single 8-byte pointerKind=='stack' slot; got {locals_}",
        )

    # ------------------------------------------------------------------
    # Test 2 -- no caller-frame noise before the real prologue completes
    # ------------------------------------------------------------------
    def test_no_slots_appear_before_mov_rbp_rsp_completes(self):
        """Non-regression: between `push rbp` (frame_pointer_ready=False)
        and `mov rbp, rsp`, nothing must be shown -- rbp still belongs to
        the caller at that point. This must hold identically before and
        after the fix; the new evidence path only ever fires once
        frame_pointer_ready is already True."""
        source = """
            int main(void) {
                int x = 42;
                int *p = &x;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "a_simple_noise", source)
            result = _trace(binary, stop_symbol=None, max_steps=8)

        steps = sorted(result["analysisByStep"].items(), key=lambda kv: int(kv[0]))
        # Step 1 is `push rbp` itself (frame_pointer_ready still False at
        # this point): only saved_bp/return_address may be visible.
        first_step_slots = (steps[0][1].get("frame") or {}).get("slots", [])
        first_step_roles = {slot.get("role") for slot in first_step_slots}
        self.assertTrue(
            first_step_roles <= {"saved_bp", "return_address"},
            f"unexpected content before the frame is established: {first_step_slots}",
        )

    # ------------------------------------------------------------------
    # Test 3 -- non-leaf function (real `sub rsp`) behaviour is unchanged
    # ------------------------------------------------------------------
    def test_non_leaf_function_still_uses_sub_rsp_as_before(self):
        """Non-regression: a function that reserves space the normal way
        must keep working exactly as before -- this fix only adds a
        second, independent way to prove frame_allocated, it must not
        remove or weaken the existing `sub rsp` detection."""
        source = """
            volatile int sink;
            void done(void) {}
            __attribute__((noinline)) int helper(int a, int b) { return a + b; }
            int main(void) {
                int x = 42;
                int *p = &x;
                sink = helper(*p, 1);
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "b_nonleaf", source)
            result = _trace(binary)

        locals_ = _slots_with_role(result, "local")
        self.assertTrue(locals_, "main (non-leaf, real sub rsp) must still show locals")
        pointer_slots = [
            slot
            for slot in locals_
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(
            pointer_slots, f"p must still be classified correctly: {locals_}"
        )

    # ------------------------------------------------------------------
    # Test 4 -- canary/control-slot non-regression (real stack-protector corpus)
    # ------------------------------------------------------------------
    def test_canary_corpus_unaffected_by_red_zone_evidence_path(self):
        """The stack-protector corpus's `vulnerable()` allocates via
        `sub rsp` (a 16-byte buffer forces it) -- this test proves the new
        evidence path, which can only ever set frame_allocated True (never
        False, never earlier than a real write proves), does not disturb
        saved_bp/return_address or the existing __stack_chk_fail typed
        crash detection."""
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
                "canary_intact",
                source,
                extra_flags=("-fstack-protector-all", "-fno-omit-frame-pointer"),
            )
            result = _trace(binary, argv1="AAAA", max_steps=20000)

        self.assertIsNone(result.get("crash"))
        for step, analysis in result["analysisByStep"].items():
            slots = (analysis.get("frame") or {}).get("slots", [])
            for role in ("saved_bp", "return_address"):
                matching = [s for s in slots if s.get("role") == role]
                for slot in matching:
                    self.assertEqual(
                        slot.get("size"),
                        8,
                        f"step {step}: {role} must stay a single 8-byte slot, got {slot}",
                    )
                self.assertLessEqual(
                    len(matching),
                    1,
                    f"step {step}: {role} appears {len(matching)} times: {slots}",
                )


if __name__ == "__main__":
    unittest.main()
