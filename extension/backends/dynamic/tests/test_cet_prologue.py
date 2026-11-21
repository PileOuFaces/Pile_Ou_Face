# SPDX-License-Identifier: AGPL-3.0-only
"""Stack Model with CET landing pads (`endbr64` before `push rbp`).

Ubuntu's gcc enables `-fcf-protection` by default: every function then starts with
`endbr64`. That first step used to show the *caller's* stack data as this
function's locals, because the entry check compared the function address with the
instruction pointer read *after* the step. Real `gcc -O0` binaries traced through
Unicorn and the real pipeline, with and without CET.
"""

from __future__ import annotations

import copy
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
except SystemExit as exc:  # pragma: no cover - optional dependency in local envs
    TraceConfig = None
    UNICORN_SKIP_REASON = str(exc)
else:
    UNICORN_SKIP_REASON = ""

from backends.dynamic.pipeline.run_pipeline import run_pipeline  # noqa: E402
from backends.dynamic.pipeline.stack_model import (  # noqa: E402
    _is_cet_landing_pad,
    build_dynamic_analysis,
)

CF_PROTECTION = ("-fcf-protection=none", "-fcf-protection=full")
FRAME_CONTROL_ROLES = {"saved_bp", "return_address"}
TWO_CALLS = """
    int helper(int a) {
        int x = a;
        return x;
    }

    int main(void) {
        int r = helper(1);
        r += helper(2);
        return r;
    }
"""
# Reaches the second helper() entry, then stops before main's `ret`.
TWO_CALLS_MAX_STEPS = 26
SIMPLE_MAIN = """
    int main(void) {
        int x = 42;
        int *p = &x;
        return *p;
    }
"""
# Stays inside main (no stop symbol), before its `ret`.
MAX_STEPS = 6
# Frameless main without CET returns at step 6.
FRAMELESS_MAX_STEPS = 5


def _compile(
    tmpdir: str, name: str, flags: tuple[str, ...], source: str = SIMPLE_MAIN
) -> Path:
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("gcc is required for the CET corpus")
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
            *flags,
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


def _trace(binary: Path, max_steps: int = MAX_STEPS) -> dict:
    config = TraceConfig(
        base=0x400000,
        stack_base=0x7FFFFFFDE000,
        stack_size=0x40000,
        max_steps=max_steps,
        stack_entries=32,
        arch_bits=64,
        interp_base=0x7F0000000000,
        start_interp=False,
        stdin_data=b"",
        buffer_offset=None,
        buffer_size=0,
        start_symbol="main",
        argv1=None,
        stop_symbol=None,
        capture_ranges=[],
    )
    result = run_pipeline(str(binary), None, config, None)
    assert result["meta"].get("error") is None, result["meta"].get("error")
    return result


def _instr(snapshot: dict) -> str:
    instruction = snapshot.get("instruction")
    text = (
        instruction.get("text")
        if isinstance(instruction, dict)
        else snapshot.get("instr")
    )
    return str(text or "").strip().lower()


def _steps(result: dict) -> list[tuple[dict, list[dict]]]:
    """(snapshot, slots) in execution order."""
    ordered = sorted(result["analysisByStep"].items(), key=lambda kv: int(kv[0]))
    return [
        (
            result["snapshots"][int(step) - 1],
            (analysis.get("frame") or {}).get("slots", []),
        )
        for step, analysis in ordered
    ]


def _roles(slots: list[dict]) -> set[str]:
    return {slot.get("role") for slot in slots}


@unittest.skipIf(TraceConfig is None, UNICORN_SKIP_REASON)
class TestCetPrologue(unittest.TestCase):
    def _trace_with(self, *flags: str, max_steps: int = MAX_STEPS) -> dict:
        with tempfile.TemporaryDirectory() as tmpdir:
            return _trace(_compile(tmpdir, "cet_probe", flags), max_steps)

    def test_landing_pad_is_emitted_only_with_cf_protection(self):
        """Guards the corpus itself: the two builds really differ by `endbr64`."""
        for flag, expected in (
            ("-fcf-protection=none", False),
            ("-fcf-protection=full", True),
        ):
            with self.subTest(flag=flag):
                first = _instr(_steps(self._trace_with(flag))[0][0])
                self.assertEqual(_is_cet_landing_pad(first), expected, first)

    def test_no_slot_before_the_frame_pointer_is_established(self):
        for flag in CF_PROTECTION:
            with self.subTest(flag=flag):
                for snapshot, slots in _steps(self._trace_with(flag)):
                    if _instr(snapshot) == "mov rbp, rsp":
                        break
                    self.assertLessEqual(
                        _roles(slots),
                        FRAME_CONTROL_ROLES,
                        f"{flag}: caller data shown at `{_instr(snapshot)}`: {slots}",
                    )
                else:
                    self.fail(
                        f"{flag}: `mov rbp, rsp` not reached in {MAX_STEPS} steps"
                    )

    def test_cet_and_classic_prologues_end_with_the_same_locals(self):
        def final_locals(flag):
            _, slots = _steps(self._trace_with(flag))[-1]
            return sorted(
                (slot.get("offsetFromBp"), slot.get("size"))
                for slot in slots
                if slot.get("role") == "local"
            )

        classic = final_locals("-fcf-protection=none")
        self.assertTrue(classic, "expected x/p as locals once the frame exists")
        self.assertEqual(final_locals("-fcf-protection=full"), classic)

    def test_frameless_function_keeps_its_historical_slots_with_cet(self):
        """No `push rbp` after `endbr64`: the landing pad must not hide the frame."""

        def roles_after_entry(flag):
            steps = _steps(
                self._trace_with(
                    "-fomit-frame-pointer", flag, max_steps=FRAMELESS_MAX_STEPS
                )
            )
            # Skip the CET landing pad itself so both builds compare the same code.
            body = [
                slots for snap, slots in steps if not _is_cet_landing_pad(_instr(snap))
            ]
            return [sorted(_roles(slots)) for slots in body]

        with_cet = roles_after_entry("-fcf-protection=full")
        classic = roles_after_entry("-fcf-protection=none")
        # Same step budget, so the CET build has one body step fewer (its endbr64).
        common = min(len(with_cet), len(classic))
        self.assertGreaterEqual(common, FRAMELESS_MAX_STEPS - 1)
        self.assertEqual(with_cet[:common], classic[:common])

    def test_every_call_hides_caller_data_until_its_frame_exists(self):
        """Second call to the same function: neither its `call` step nor its
        `endbr64` may show the caller's data, whatever the first call left."""
        for flag in CF_PROTECTION:
            with self.subTest(flag=flag), tempfile.TemporaryDirectory() as tmpdir:
                binary = _compile(tmpdir, "two_calls", (flag,), TWO_CALLS)
                steps = _steps(_trace(binary, TWO_CALLS_MAX_STEPS))
                calls = [
                    i
                    for i, (snap, _) in enumerate(steps)
                    if _instr(snap).startswith("call")
                ]
                self.assertGreaterEqual(len(calls), 2, "two helper() calls expected")
                for call_index in calls:
                    for snap, slots in steps[call_index:]:
                        if _instr(snap) == "mov rbp, rsp":
                            break
                        self.assertLessEqual(
                            _roles(slots),
                            FRAME_CONTROL_ROLES,
                            f"{flag}, call at step {call_index + 1}: `{_instr(snap)}`: {slots}",
                        )

    def test_endbr_inside_a_function_does_not_reset_the_frame(self):
        """Only a landing pad proven to be the entry (address match) counts."""
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile(tmpdir, "cet_probe", ("-fcf-protection=full",))
            result = _trace(binary)
            snapshots = copy.deepcopy(result["snapshots"])
            target = 1 + next(
                i for i, snap in enumerate(snapshots) if _instr(snap) == "mov rbp, rsp"
            )
            step = str(target + 1)
            reference = build_dynamic_analysis(snapshots, result["meta"], str(binary))
            # The direct call reproduces the pipeline's own analysis for that step.
            self.assertEqual(
                _roles((reference[step].get("frame") or {}).get("slots", [])),
                _roles(
                    (result["analysisByStep"][step].get("frame") or {}).get("slots", [])
                ),
            )
            instruction = snapshots[target].get("instruction")
            if isinstance(instruction, dict):
                instruction["text"] = "endbr64"
            else:
                snapshots[target]["instr"] = "endbr64"
            mutated = build_dynamic_analysis(snapshots, result["meta"], str(binary))
        self.assertIn(
            "local", _roles((reference[step].get("frame") or {}).get("slots", []))
        )
        self.assertEqual(
            _roles((mutated[step].get("frame") or {}).get("slots", [])),
            _roles((reference[step].get("frame") or {}).get("slots", [])),
        )


if __name__ == "__main__":
    unittest.main()
