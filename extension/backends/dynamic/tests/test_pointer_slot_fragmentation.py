# SPDX-License-Identifier: AGPL-3.0-only
"""A pointer-sized (8-byte on x86_64) local variable must never be silently
split into two 4-byte slots by the Stack Model.

Root cause (see tmp/audits/pointers-pedagogy-audit.md and GitHub issue #297):
`analyse_stack_frame` (backends/static/disasm/stack_frame.py) treats a bare
`lea reg, [rbp+-N]` -- an address computation that never touches memory --
as if it were a memory access of the architecture's native pointer size
(`_size_from_instruction`'s fallback `return ptr_size`). `_merge_stack_entry`
then keeps the *largest* size ever seen for a given stack offset, so this
phantom 8-byte "access" silently overwrites the correctly-detected 4-byte
size of an adjacent local (from its real `mov dword ptr [...]`), inflating
its declared static region until it overlaps the next slot up (another
local, `saved_bp`, or `return_address`). `_build_slots` (stack_model.py)
then injects that overlap's boundaries verbatim, splitting the neighbour's
true pointer-sized span into two 4-byte fragments and losing `pointerKind`.

All four corpora below are real `gcc -O0 -g -mno-red-zone` binaries traced
through the real Unicorn engine and the real `build_dynamic_analysis`
pipeline -- no synthetic snapshot fixtures. `-mno-red-zone` is used
deliberately to keep this test isolated from the separate red-zone
visibility issue (#298): every local here is reserved by an explicit
`sub rsp, N`, so any missing/split slot is attributable only to the
fragmentation bug this test targets.
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
        raise unittest.SkipTest("gcc is required for the pointer-fragmentation corpus")
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
            "-mno-red-zone",
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


def _config(**overrides) -> "TraceConfig":
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
        # Every corpus below calls a trivial `done()` right after the
        # interesting computation and before returning, exactly like the
        # existing canary corpus (test_stack_chk_fail_crash.py). Without an
        # explicit stop point, tracing `main` to its own `ret` continues
        # into libc's real (unmapped-in-this-emulator) startup/teardown
        # path and crashes with UC_ERR_FETCH_UNMAPPED -- a harness problem
        # unrelated to the slot-fragmentation bug under test.
        "stop_symbol": "done",
        "capture_ranges": [],
    }
    base.update(overrides)
    return TraceConfig(**base)


def _trace(binary_path: Path, **config_overrides) -> dict:
    result = run_pipeline(
        str(binary_path), None, _config(**config_overrides), None
    )
    assert result["meta"].get("error") is None, result["meta"].get("error")
    return result


def _all_slots(result: dict):
    """Yield (step_key, snapshot, slot) for every slot at every step."""
    snapshots_by_step = {
        str(snap.get("step")): snap for snap in result["snapshots"]
    }
    for step, analysis in result["analysisByStep"].items():
        snap = snapshots_by_step.get(step, {})
        for slot in (analysis.get("frame") or {}).get("slots", []):
            yield step, snap, slot


def _slots_with_role(result: dict, role: str):
    return [slot for _step, _snap, slot in _all_slots(result) if slot.get("role") == role]


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestPointerSlotFragmentation(unittest.TestCase):
    """RED before the fix (issue #297): each assertion below currently fails
    because a pointer-sized local/control slot is split into two 4-byte
    fragments and loses `pointerKind`."""

    # ------------------------------------------------------------------
    # Test 1 -- simple pointer (PoC A)
    # ------------------------------------------------------------------
    def test_simple_pointer_is_a_single_pointer_sized_slot_with_stack_kind(self):
        source = """
            volatile int sink;
            void done(void) {}
            int main(void) {
                int x = 42;
                int *p = &x;
                sink = *p;
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "a_simple", source)
            result = _trace(binary)

        locals_ = _slots_with_role(result, "local")
        self.assertTrue(locals_, "expected at least one local slot")

        # No local slot may ever be a 4-byte fragment of what is really an
        # 8-byte pointer: for every step, no two *adjacent* 4-byte local
        # slots may together span exactly word_size bytes while the low
        # half's value display looks like the low 32 bits of a full stack
        # address (the tell-tale signature of the bug).
        pointer_sized_stack_slots = [
            slot
            for slot in locals_
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(
            pointer_sized_stack_slots,
            "expected p to appear as a single 8-byte slot with "
            f"pointerKind == 'stack' at least once; local slots seen: {locals_}",
        )

        # And the fragmented-into-two-4-byte-halves shape must never occur.
        fragmented = [
            slot
            for slot in locals_
            if slot.get("size") == 4 and slot.get("pointerKind") is None
            and str(slot.get("valueDisplay") or "").startswith("0x")
        ]
        self.assertFalse(
            fragmented,
            f"pointer-looking value stuck in an unclassified 4-byte slot: {fragmented}",
        )

    # ------------------------------------------------------------------
    # Test 2 -- reassignment (PoC C)
    # ------------------------------------------------------------------
    def test_pointer_reassignment_keeps_a_stable_pointer_sized_slot(self):
        source = """
            volatile int sink;
            void done(void) {}
            int main(void) {
                int a = 1;
                int b = 2;
                int *p = &a;
                p = &b;
                sink = *p;
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "c_reassign", source)
            result = _trace(binary)

        stack_pointer_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertGreaterEqual(
            len(stack_pointer_slots),
            2,
            "expected p to be observed as an 8-byte stack-pointer slot both "
            f"before and after reassignment; got: {stack_pointer_slots}",
        )
        addresses = {slot["start"] for slot in stack_pointer_slots}
        self.assertEqual(
            len(addresses),
            1,
            f"p's slot address must stay the same across reassignment, got {addresses}",
        )
        values = {slot["valueDisplay"] for slot in stack_pointer_slots}
        self.assertGreaterEqual(
            len(values),
            2,
            f"expected the pointer's value to actually change (&a then &b), got {values}",
        )

    # ------------------------------------------------------------------
    # Test 3 -- double pointer (PoC D)
    # ------------------------------------------------------------------
    def test_double_pointer_both_levels_stay_pointer_sized(self):
        source = """
            volatile int sink;
            void done(void) {}
            int main(void) {
                int x = 42;
                int *p = &x;
                int **pp = &p;
                sink = **pp;
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "d_doubleptr", source)
            result = _trace(binary)

        stack_pointer_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        distinct_addresses = {slot["start"] for slot in stack_pointer_slots}
        self.assertGreaterEqual(
            len(distinct_addresses),
            2,
            "expected both p and pp to appear as distinct 8-byte "
            f"pointerKind=='stack' slots; got addresses: {distinct_addresses}",
        )

    # ------------------------------------------------------------------
    # Test 4 -- saved_bp integrity across a call (PoC I)
    # ------------------------------------------------------------------
    def test_saved_bp_is_never_split_by_an_adjacent_local(self):
        source = """
            void done(void) {}
            void change(int *p) {
                *p = 123;
            }
            int main(void) {
                int x = 42;
                change(&x);
                done();
                return x;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "i_argptr", source)
            result = _trace(binary)

        saved_bp_slots = _slots_with_role(result, "saved_bp")
        self.assertTrue(saved_bp_slots, "expected at least one saved_bp slot")

        for step, _snap, slot in _all_slots(result):
            if slot.get("role") != "saved_bp":
                continue
            self.assertEqual(
                slot.get("size"),
                8,
                f"step {step}: saved_bp must always be a single 8-byte slot, "
                f"got size={slot.get('size')} (slot={slot})",
            )

        # No two saved_bp entries may ever coexist in the same step's slot
        # list (the observed bug: main's `x` -- referenced only via `lea`
        # -- inflates to 8 bytes and overlaps [bp, bp+8), splitting
        # saved_bp into two duplicate-labelled 4-byte rows).
        for step, analysis in result["analysisByStep"].items():
            slots = (analysis.get("frame") or {}).get("slots", [])
            bp_count = sum(1 for s in slots if s.get("role") == "saved_bp")
            self.assertLessEqual(
                bp_count, 1, f"step {step}: saved_bp appears {bp_count} times: {slots}"
            )

    # ------------------------------------------------------------------
    # Test 5 -- a real buffer must not be fused into a fake pointer slot
    # ------------------------------------------------------------------
    def test_byte_manipulated_buffer_is_not_fused_into_a_pointer_slot(self):
        source = """
            volatile int sink;
            void done(void) {}
            int main(void) {
                char buf[16];
                for (int i = 0; i < 16; i++) {
                    buf[i] = (char)('a' + i);
                }
                sink = buf[0];
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "e_buffer", source)
            result = _trace(binary)

        # A real char buffer must never show up as an 8-byte slot claiming
        # pointerKind == "stack" -- that would mean the fragmentation fix
        # over-corrected by fusing genuinely-separate byte cells together.
        bogus_pointer_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertFalse(
            bogus_pointer_slots,
            f"a plain char buffer must not be reported as a pointer slot: {bogus_pointer_slots}",
        )

    # ------------------------------------------------------------------
    # Test 6 -- canary/control-slot non-regression (real stack-protector corpus)
    # ------------------------------------------------------------------
    def test_canary_corpus_keeps_saved_bp_and_return_address_intact(self):
        """No `role="canary"` exists anywhere in stack_model.py today (grep
        confirmed at audit time) -- the separate canary workstream (#228,
        #229) lives elsewhere. The real, checkable invariant here is that
        saved_bp/return_address stay single, non-fragmented pointer-sized
        slots in a real -fstack-protector-all binary, and that the
        existing __stack_chk_fail typed-crash detection is unaffected."""
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
            result = _trace(
                binary,
                argv1="AAAA",
                stop_symbol="done",
                max_steps=20000,
            )

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

    # ------------------------------------------------------------------
    # Test 7 -- legitimate partial sub-writes to a genuinely 8-byte object
    # ------------------------------------------------------------------
    def test_genuine_partial_writes_to_an_eight_byte_object_stay_split(self):
        """A union whose 8-byte member is zeroed once (a real qword write)
        and then genuinely overwritten in two independent 4-byte halves
        must keep showing two 4-byte slots -- the fix must not conclude
        that "an 8-byte access existed once" means the sub-boundaries
        should be erased. No `lea` is involved anywhere in this source, so
        this path is completely untouched by the fragmentation fix; it
        exists to prove the fix does not overreach."""
        source = """
            volatile int sink;
            void done(void) {}
            int main(void) {
                union { long l; struct { int a; int b; } s; } u;
                u.l = 0;
                u.s.a = 1;
                u.s.b = 2;
                sink = u.s.a + u.s.b;
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "f_partial", source)
            result = _trace(binary)

        locals_ = _slots_with_role(result, "local")
        four_byte_locals = {slot["start"] for slot in locals_ if slot.get("size") == 4}
        self.assertGreaterEqual(
            len(four_byte_locals),
            2,
            "expected u.s.a and u.s.b to remain two distinct 4-byte slots "
            f"despite the earlier 8-byte zeroing write; local slots: {locals_}",
        )


if __name__ == "__main__":
    unittest.main()
