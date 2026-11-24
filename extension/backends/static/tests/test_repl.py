# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the repl.py script executor."""

import base64
import json
import os
import signal
import subprocess
import sys
import time

import pytest

from backends.static.repl import repl
from backends.static.repl.repl import execute_script

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
_venv_python = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
PYTHON = _venv_python if os.path.exists(_venv_python) else sys.executable
REPL = os.path.join(ROOT, "backends", "static", "repl", "repl.py")
BINARY = os.path.join(ROOT, "examples", "demo_analysis.elf")

requires_demo = pytest.mark.skipif(
    not os.path.exists(BINARY),
    reason="demo_analysis.elf not found — run 'make demo' first",
)

SHORT_TIMEOUT_S = 2
MAX_RETURN_S = 10  # acceptance bound: the call must return well before this
NORMAL_TIMEOUT_S = 20


def _run(code: str, binary: str = BINARY) -> dict:
    b64 = base64.b64encode(code.encode()).decode()
    r = subprocess.run(
        [PYTHON, REPL, "--code", b64, "--binary", binary],
        capture_output=True,
        text=True,
        timeout=60,
    )
    return json.loads(r.stdout)


@requires_demo
def test_print_hello():
    result = _run('print("hello")')
    assert result["ok"] is True
    assert "hello" in result["stdout"]


@requires_demo
def test_binary_variable_injected():
    result = _run("print(binary)")
    assert result["ok"] is True
    assert "demo_analysis.elf" in result["stdout"]


@requires_demo
def test_static_modules_importable():
    result = _run(
        "from backends.static.binary.symbols import extract_symbols; print(type(extract_symbols))"
    )
    assert result["ok"] is True
    assert "function" in result["stdout"]


@requires_demo
def test_syntax_error():
    result = _run("def ()")
    assert result["ok"] is False
    assert "SyntaxError" in result["stderr"]


@requires_demo
def test_runtime_error():
    result = _run("1/0")
    assert result["ok"] is False
    assert "ZeroDivisionError" in result["stderr"]


@requires_demo
def test_duration_present():
    result = _run("print(1)")
    assert "duration_ms" in result
    assert isinstance(result["duration_ms"], (int, float))


def _pid_alive(pid: int) -> bool:
    """True if *pid* is running; a zombie counts as dead (already killed)."""
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:
        with open(f"/proc/{pid}/stat") as fh:
            state = fh.read().rsplit(")", 1)[1].split()[0]
    except FileNotFoundError:
        return not os.path.isdir("/proc")
    return state != "Z"


def test_infinite_loop_is_stopped_and_output_kept():
    code = 'print("before-loop", flush=True)\nwhile True:\n    pass\n'
    start = time.monotonic()
    result = execute_script(code, "", timeout=SHORT_TIMEOUT_S)
    assert time.monotonic() - start < MAX_RETURN_S
    assert result["ok"] is False
    assert "TimeoutError" in result["stderr"]
    assert f"{SHORT_TIMEOUT_S}s" in result["stderr"]
    assert "before-loop" in result["stdout"]
    assert set(result) == {"ok", "stdout", "stderr", "duration_ms"}


def test_unflushed_output_before_loop_is_kept():
    result = execute_script(
        'print("no-flush")\nwhile True: pass\n', "", timeout=SHORT_TIMEOUT_S
    )
    assert result["ok"] is False
    assert "no-flush" in result["stdout"]


@pytest.mark.skipif(os.name != "posix", reason="process-group kill is POSIX only")
def test_timeout_kills_spawned_subprocess():
    code = (
        "import subprocess, time\n"
        "p = subprocess.Popen(['sleep', '60'])\n"
        "print(f'PID={p.pid}', flush=True)\n"
        "while True:\n"
        "    time.sleep(0.1)\n"
    )
    result = execute_script(code, "", timeout=SHORT_TIMEOUT_S)
    assert result["ok"] is False
    pid = int(result["stdout"].split("PID=", 1)[1].split()[0])
    deadline = time.monotonic() + MAX_RETURN_S
    while _pid_alive(pid) and time.monotonic() < deadline:
        time.sleep(0.1)
    assert not _pid_alive(pid)


SURVIVOR_SLEEP_S = 60


def test_output_kept_when_survivor_holds_pipes():
    """A descendant that escapes the kill keeps stdout/stderr open (EOF never
    comes); output printed before the stop must still be returned. On POSIX
    the descendant leaves the process group to mimic the Windows behaviour."""
    # Real drain budget: both pipes share it, so the return stays well bounded.
    code = (
        "import os, subprocess, sys, time\n"
        "kw = {'start_new_session': True} if os.name == 'posix' else {}\n"
        "p = subprocess.Popen([sys.executable, '-c',"
        f" 'import time; time.sleep({SURVIVOR_SLEEP_S})'], **kw)\n"
        "print(f'marker PID={p.pid}', flush=True)\n"
        "while True:\n"
        "    time.sleep(0.1)\n"
    )
    start = time.monotonic()
    result = execute_script(code, "", timeout=SHORT_TIMEOUT_S)
    elapsed = time.monotonic() - start
    pid = int(result["stdout"].split("PID=", 1)[1].split()[0])
    try:
        assert elapsed < MAX_RETURN_S
        assert result["ok"] is False
        assert "marker" in result["stdout"]
        assert "TimeoutError" in result["stderr"]
    finally:
        if os.name == "posix":
            os.kill(pid, signal.SIGKILL)
        else:
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)


def test_success_and_binary_injected_without_demo():
    result = execute_script("print(binary)", "/some/bin.elf", timeout=NORMAL_TIMEOUT_S)
    assert result["ok"] is True, result["stderr"]
    assert "/some/bin.elf" in result["stdout"]
    assert result["stderr"] == ""


def test_runtime_error_in_child():
    result = execute_script("1/0", "", timeout=NORMAL_TIMEOUT_S)
    assert result["ok"] is False
    assert "ZeroDivisionError" in result["stderr"]
    assert "TimeoutError" not in result["stderr"]


def test_stopped_collector_keeps_nothing_more_and_its_thread_ends():
    read_fd, write_fd = os.pipe()
    with (
        os.fdopen(read_fd, "rb") as stream,
        os.fdopen(write_fd, "wb", buffering=0) as writer,
    ):
        collector = repl._PipeCollector(stream)
        writer.write(b"before")
        deadline = time.monotonic() + MAX_RETURN_S
        while collector.data() != b"before" and time.monotonic() < deadline:
            time.sleep(0.01)
        collector.stop()
        writer.write(b"after")  # a survivor still writing after the result was returned
        assert collector.join(MAX_RETURN_S) is True
        assert collector.data() == b"before"


def test_cli_exits_zero_with_a_failed_result_so_the_extension_keeps_the_output():
    """The extension (runPython) rejects a non-zero exit and drops stdout: the CLI
    reports a failed script in its JSON, with exit code 0."""
    code = base64.b64encode(b"print('before-error')\n1/0\n").decode()
    proc = subprocess.run(
        [PYTHON, REPL, "--code", code, "--binary", ""],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stderr
    result = json.loads(proc.stdout)
    assert result["ok"] is False
    assert "before-error" in result["stdout"]
    assert "ZeroDivisionError" in result["stderr"]


def test_syntax_error_without_demo():
    result = execute_script("def ()", "", timeout=NORMAL_TIMEOUT_S)
    assert result["ok"] is False
    assert "SyntaxError" in result["stderr"]
