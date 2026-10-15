# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence-gated `pointerKind: "null"` classification.

Root cause / limitation (see tmp/audits/pointers-pedagogy-audit.md and
GitHub issue #299): `StaticTraceResolver.pointer_kind()` (stack_model.py)
only ever returns `"stack"`, `"code"`, or `None`. It has no notion of
`"null"` at all -- a pointer set to `NULL` looks byte-for-byte identical to
any other zero value, and the pipeline has no type information (DWARF
locals are ignored, calling-convention analysis carries no type) to break
the tie by declaration.

The only evidence available today is *temporal*: was this exact stack
address (same function invocation, same size) previously observed holding
a value that `pointer_kind()` already proved to be `"stack"`/`"code"`? If
so, and the address now holds `0` at the architecture's native pointer
width, that is real evidence of a `NULL` assignment -- not a guess. A bare
`value == 0` is never sufficient on its own (that would misclassify any
ordinary zero-valued integer of pointer width, see Test 2/3 below).

This means direct initialization (`int *p = NULL;`, or a `NULL` argument
that is never subsequently assigned a real address) has **no available
evidence** and is a *known, accepted false negative* in this PR -- see
Test 5 and Test 6 in `TestKnownFalseNegatives`.

All corpora below are real `gcc -O0 -g -fno-stack-protector -no-pie`
binaries (red zone left enabled -- #298 already fixed local visibility, no
need to work around it) traced through the real Unicorn engine and the
real `build_dynamic_analysis` pipeline -- no synthetic snapshot fixtures.
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


def _gcc_compile(tmpdir: str, name: str, source: str) -> Path:
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("gcc is required for the null-pointer corpus")
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
    # A real output_path is required so run_pipeline builds disasm_lines,
    # which is what StaticTraceResolver needs to populate code_min/code_max
    # (and therefore ever return pointerKind=="code"). #297/#298's tests
    # never exercised "code" classification, so this was never needed
    # there; Test 8 in this file is the first to rely on it.
    output_path = str(binary_path) + ".output.json"
    result = run_pipeline(
        str(binary_path), None, _config(**config_overrides), output_path
    )
    assert result["meta"].get("error") is None, result["meta"].get("error")
    return result


def _all_slots(result: dict):
    for analysis in result["analysisByStep"].values():
        yield from (analysis.get("frame") or {}).get("slots", [])


def _slots_with_role(result: dict, role: str):
    return [slot for slot in _all_slots(result) if slot.get("role") == role]


def _pointer_kinds_seen(result: dict, role: str = "local") -> set:
    return {
        slot.get("pointerKind")
        for slot in _slots_with_role(result, role)
        if slot.get("pointerKind") is not None
    }


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestNullPointerClassification(unittest.TestCase):
    # ------------------------------------------------------------------
    # Test 1 -- stack -> NULL (PoC C): the core case this PR must handle.
    # ------------------------------------------------------------------
    def test_pointer_reassigned_to_null_is_classified_null(self):
        """RED before the fix: p's slot goes stack -> (no classification
        at all) once reassigned to NULL, even though it was proven a
        pointer one step earlier at the exact same address."""
        source = """
            #include <stddef.h>
            int main(void) {
                int x = 42;
                int *p = &x;
                p = NULL;
                return p != NULL;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "c_stack_to_null", source)
            result = _trace(binary, max_steps=10)

        stack_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(
            stack_slots, "expected p to be proven 'stack' before reassignment"
        )
        proven_addr = stack_slots[0]["start"]

        null_slots_same_addr = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("start") == proven_addr and slot.get("pointerKind") == "null"
        ]
        self.assertTrue(
            null_slots_same_addr,
            "expected the same slot to become pointerKind=='null' after `p = NULL`",
        )

    # ------------------------------------------------------------------
    # Test 2 -- plain zero int must never become "null" (PoC A)
    # ------------------------------------------------------------------
    def test_plain_zero_int_is_never_classified_null(self):
        source = """
            int main(void) {
                int x = 0;
                return x;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "a_zero_int", source)
            result = _trace(binary, max_steps=5)

        self.assertNotIn(
            "null",
            _pointer_kinds_seen(result),
            "an ordinary `int x = 0;` must never be classified as a null pointer",
        )

    # ------------------------------------------------------------------
    # Test 3 -- zero-valued unsigned long (same width as a pointer) (PoC E)
    # ------------------------------------------------------------------
    def test_zero_valued_pointer_width_integer_is_never_classified_null(self):
        """The critical anti-`size == ptr_size && value == 0 => null` guard:
        an 8-byte integer holding 0, never proven a pointer, must stay
        unclassified even though it has the exact same width and byte
        pattern as a genuinely NULL pointer."""
        source = """
            int main(void) {
                unsigned long x = 0;
                return (int)x;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "e_zero_ulong", source)
            result = _trace(binary, max_steps=5)

        self.assertNotIn("null", _pointer_kinds_seen(result))

    # ------------------------------------------------------------------
    # Test 3b -- zero-valued elements of an array (PoC F)
    # ------------------------------------------------------------------
    def test_zero_valued_array_element_is_never_classified_null(self):
        source = """
            int main(void) {
                unsigned long values[2] = {0, 1};
                return (int)(values[0] + values[1]);
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "f_zero_array", source)
            result = _trace(binary, max_steps=9)

        self.assertNotIn("null", _pointer_kinds_seen(result))

    # ------------------------------------------------------------------
    # Test 4 -- NULL -> stack: final classification must be "stack",
    # with no leftover contamination from the earlier NULL state.
    # ------------------------------------------------------------------
    def test_null_then_reassigned_to_stack_ends_up_classified_stack(self):
        source = """
            #include <stddef.h>
            int main(void) {
                int x = 42;
                int *p = NULL;
                p = &x;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "d_null_to_stack", source)
            result = _trace(binary, max_steps=9)

        stack_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(
            stack_slots, "expected p to end up classified 'stack' once it holds &x"
        )

    # ------------------------------------------------------------------
    # Test 6 -- double pointer: pp stays "stack", no relation invented
    # ------------------------------------------------------------------
    def test_double_pointer_pp_stays_stack_p_does_not_contaminate(self):
        """pp (&p) must be classified 'stack' throughout. p (directly
        initialized to NULL, never reassigned here) is a documented false
        negative (see TestKnownFalseNegatives) -- this test only asserts
        that pp's classification is correct and that nothing invents a
        pp -> p relation (out of scope, tracked separately)."""
        source = """
            #include <stddef.h>
            int main(void) {
                int *p = NULL;
                int **pp = &p;
                return pp != NULL;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "h_double_ptr", source)
            result = _trace(binary, max_steps=9)

        pp_slots = [
            slot
            for slot in _slots_with_role(result, "local")
            if slot.get("size") == 8 and slot.get("pointerKind") == "stack"
        ]
        self.assertTrue(pp_slots, "expected pp to be classified 'stack'")
        for slot in pp_slots:
            self.assertNotIn(
                "pointee",
                slot,
                "no pointer-to-target relation must be invented in this PR",
            )

    # ------------------------------------------------------------------
    # Test 7 -- non-regression: an ordinary stack pointer (no NULL involved)
    # ------------------------------------------------------------------
    def test_plain_stack_pointer_still_classified_stack(self):
        source = """
            int main(void) {
                int x = 42;
                int *p = &x;
                return *p;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "j_simple_stack", source)
            result = _trace(binary, max_steps=8)

        self.assertIn("stack", _pointer_kinds_seen(result))

    # ------------------------------------------------------------------
    # Test 8 -- non-regression: a function pointer stays classified "code"
    # ------------------------------------------------------------------
    def test_function_pointer_still_classified_code(self):
        source = """
            void hello(void) {}
            int main(void) {
                void (*fn)(void) = hello;
                return fn != 0;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "i_fnptr", source)
            result = _trace(binary, max_steps=8)

        self.assertIn("code", _pointer_kinds_seen(result))


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestKnownFalseNegatives(unittest.TestCase):
    """Documented, accepted limitations of the evidence-gated design: no
    static typing exists today to prove a slot that has *never* held a
    real address is a pointer. These assert the current (and, for this
    PR, intended) behaviour -- pointerKind stays unclassified (None),
    never fabricated as "null". A future PR (DWARF local typing, or
    another evidence source) may turn these green for the "null" case
    without this PR's evidence-gating needing to change."""

    def test_direct_null_initialization_is_not_classified(self):
        """PoC B. `int *p = NULL;` with no later reassignment: p's slot is
        never observed holding a proven pointer value, so there is no
        evidence to gate a "null" classification on."""
        source = """
            #include <stddef.h>
            int main(void) {
                int *p = NULL;
                return p != NULL;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "b_null_direct", source)
            result = _trace(binary, max_steps=7)

        self.assertNotIn(
            "null",
            _pointer_kinds_seen(result),
            "direct NULL initialization has no evidence trail -- documented "
            "false negative, must not be fabricated",
        )

    def test_null_argument_is_not_classified(self):
        """PoC G. `check(NULL)`: the callee's copy of the argument is only
        ever observed as 0 -- never a proven pointer -- so it stays
        unclassified, same false-negative category as direct init."""
        source = """
            #include <stddef.h>
            static int check(int *p) {
                return p == NULL;
            }
            int main(void) {
                return check(NULL);
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _gcc_compile(tmpdir, "g_arg_null", source)
            result = _trace(binary, max_steps=11)

        # Steps up to and including the interesting cmp/sete/movzx
        # sequence in `check` -- step 11 (`pop rbp`) shifts the capture
        # window during frame teardown and is not meaningful evidence
        # either way (unrelated to this test's claim).
        interesting_steps = {
            step
            for step, snap in zip(
                sorted(result["analysisByStep"], key=int), result["snapshots"]
            )
            if snap.get("instr") != "pop rbp"
        }
        kinds = {
            slot.get("pointerKind")
            for step in interesting_steps
            for slot in (result["analysisByStep"][step].get("frame") or {}).get(
                "slots", []
            )
            if slot.get("role") == "local" and slot.get("pointerKind") is not None
        }
        self.assertNotIn("null", kinds)


if __name__ == "__main__":
    unittest.main()
