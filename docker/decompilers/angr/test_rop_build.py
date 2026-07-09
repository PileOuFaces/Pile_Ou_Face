"""Smoke-test for rop_build.py — runs inside the angr Docker container.

Usage (from project root):
    docker run --rm pile-ou-face/decompiler-angr:latest \
        /opt/pof-venv/bin/python3 /opt/pof/test_rop_build.py

The bundled test binary (testdata/vuln_x64.elf) is an intentionally vulnerable
x86_64 ELF compiled with -fno-stack-protector -no-pie on Ubuntu 20.04 / glibc 2.31.
It contains a pop rdi; ret gadget (from __libc_csu_init) and system() in its PLT.
"""

import json
import subprocess
import sys

# Bundled x86_64 ELF with pop rdi; ret gadget + system() in PLT.
BINARY = "/opt/pof/testdata/vuln_x64.elf"
SCRIPT = "/opt/pof/rop_build.py"
PYTHON = "/opt/pof-venv/bin/python3"


def run(goal: str) -> dict:
    proc = subprocess.run(
        [PYTHON, SCRIPT, "--binary", BINARY, "--goal", goal],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"exit {proc.returncode}: {proc.stderr[:300]}"
    data = json.loads(proc.stdout.strip())
    return data


API_ERROR_MARKERS = ("has no attribute", "AttributeError", "TypeError", "not installed")


def assert_valid(result: dict, goal: str) -> None:
    """Output must be valid JSON with expected keys and no API errors.
    ok=False is acceptable when the binary lacks gadgets; API bugs are not."""
    assert result["goal"] == goal, f"goal mismatch: {result}"
    assert isinstance(result["chain"], list), "chain must be a list"
    if result.get("ok"):
        assert len(result.get("payload_hex", "")) > 0, "ok=True but empty payload"
        assert result["confidence"] in ("high", "low", "medium")
    else:
        err = result.get("error", "")
        for marker in API_ERROR_MARKERS:
            assert marker not in err, f"API error (not a gadget shortage): {err}"


def test_ret2syscall_x64() -> None:
    r = run("ret2syscall_x64")
    assert_valid(r, "ret2syscall_x64")
    status = (
        f"{len(r['chain'])} gadgets" if r["ok"] else f"no gadgets ({r['error'][:60]})"
    )
    print(f"  ret2syscall_x64: {status}")


def test_ret2libc_x64() -> None:
    r = run("ret2libc_x64")
    assert_valid(r, "ret2libc_x64")
    status = (
        f"{len(r['chain'])} gadgets" if r["ok"] else f"no gadgets ({r['error'][:60]})"
    )
    print(f"  ret2libc_x64: {status}")


def test_stack_pivot() -> None:
    r = run("stack_pivot")
    assert_valid(r, "stack_pivot")
    status = (
        f"{len(r['chain'])} gadgets" if r["ok"] else f"no gadgets ({r['error'][:60]})"
    )
    print(f"  stack_pivot: {status}")


def test_unknown_goal() -> None:
    proc = subprocess.run(
        [PYTHON, SCRIPT, "--binary", BINARY, "--goal", "bad_goal"],
        capture_output=True,
        text=True,
    )
    data = json.loads(proc.stdout.strip())
    assert data["ok"] is False
    assert "Unknown goal" in data["error"]
    print("  unknown_goal: rejected correctly")


if __name__ == "__main__":
    tests = [
        test_ret2syscall_x64,
        test_ret2libc_x64,
        test_stack_pivot,
        test_unknown_goal,
    ]
    failed = []
    for t in tests:
        try:
            print(f"[RUN] {t.__name__}")
            t()
            print(f"[PASS] {t.__name__}")
        except Exception as exc:
            print(f"[FAIL] {t.__name__}: {exc}")
            failed.append(t.__name__)
    if failed:
        print(f"\nFAILED: {failed}")
        sys.exit(1)
    print(f"\nAll {len(tests)} tests passed.")
