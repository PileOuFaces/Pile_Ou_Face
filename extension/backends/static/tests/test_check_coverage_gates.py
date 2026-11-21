# SPDX-License-Identifier: AGPL-3.0-only
"""CI coverage gate script (scripts/check_coverage_gates.py)."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import coverage
import pytest

SCRIPT = Path(__file__).resolve().parents[3] / "scripts" / "check_coverage_gates.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("check_coverage_gates", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def measured(tmp_path):
    """A .coverage file where pkg/half.py is 75 % covered and pkg/full.py 100 %.

    Written with CoverageData, without tracing: a second tracer started inside the
    CI's ``coverage run`` would disturb the measurement of the following tests.
    """
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    half = pkg / "half.py"
    half.write_text("def used():\n    return 1\n\n\ndef unused():\n    return 2\n")
    full = pkg / "full.py"
    full.write_text("VALUE = 1\n")
    data_file = str(tmp_path / ".coverage")
    data = coverage.CoverageData(basename=data_file)
    data.add_lines({str(half): [1, 2, 5], str(full): [1]})
    data.write()
    return data_file


def _gates(**thresholds):
    patterns = {
        "half": "*/pkg/half.py",
        "full": "*/pkg/full.py",
        "absent": "*/elsewhere/*",
    }
    return {
        name: {"include": [patterns[name]], "fail_under": value}
        for name, value in thresholds.items()
    }


def _check(module, names, data_file, gates):
    return module.check(names, data_file, gates, config_file=False)


def test_passes_when_every_named_gate_is_met(measured, capsys):
    gates_module = _load_script()
    assert _check(gates_module, ["full"], measured, _gates(full=100)) == 0
    assert "OK" in capsys.readouterr().out


def test_fails_below_the_threshold(measured, capsys):
    gates_module = _load_script()
    assert _check(gates_module, ["half"], measured, _gates(half=80)) == 1
    assert "FAIL  half" in capsys.readouterr().out


def test_fails_when_a_named_gate_has_no_data(measured, capsys):
    gates_module = _load_script()
    assert _check(gates_module, ["absent"], measured, _gates(absent=0)) == 1
    assert "no coverage data" in capsys.readouterr().out


def test_rejects_an_unknown_gate(measured):
    gates_module = _load_script()
    assert _check(gates_module, ["missing"], measured, _gates(full=0)) == 2


def test_platform_threshold_overrides_the_default_only_for_that_platform():
    gate = {
        "include": ["*"],
        "fail_under": 69,
        "fail_under_by_platform": {"darwin": 68},
    }
    gates_module = _load_script()
    assert gates_module.threshold(gate, "darwin") == 68
    assert gates_module.threshold(gate, "linux") == 69
    assert gates_module.threshold({"include": ["*"], "fail_under": 69}, "darwin") == 69


def test_job_selects_only_the_gates_that_list_it():
    gates = {
        "a": {"include": ["*"], "fail_under": 1, "jobs": ["full-test"]},
        "b": {"include": ["*"], "fail_under": 1, "jobs": ["dynamic-unicorn"]},
        "c": {"include": ["*"], "fail_under": 1},
    }
    gates_module = _load_script()
    assert gates_module.gates_for_job("full-test", gates) == ["a"]
    assert gates_module.gates_for_job("dynamic-unicorn", gates) == ["b"]
    assert gates_module.gates_for_job("other", gates) == []


def test_every_configured_gate_is_enforced_by_a_ci_job():
    workflow = (SCRIPT.parents[2] / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )
    # A commented-out call does not enforce anything.
    commands = [
        line.strip()
        for line in workflow.splitlines()
        if not line.strip().startswith("#")
    ]
    for name, gate in _load_script().load_gates().items():
        assert gate.get("jobs"), f"gate {name} is enforced by no job"
        for job in gate["jobs"]:
            expected = f"check_coverage_gates.py --job {job}"
            assert any(expected in command for command in commands), (name, job)


def test_pyproject_defines_the_documented_gates():
    gates = _load_script().load_gates()
    assert gates["static+plugins"]["fail_under"] == 69
    assert gates["static+plugins"]["fail_under_by_platform"] == {"darwin": 68}
    assert gates["dynamic"]["fail_under"] == 69
    assert gates["mcp"]["fail_under"] == 61
