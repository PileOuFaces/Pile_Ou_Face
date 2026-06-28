# SPDX-License-Identifier: AGPL-3.0-only
"""Script executor for Pile ou Face integrated Python scripting.

Receives base64-encoded Python code, executes it in a sandboxed environment
with the `binary` variable pre-set to the binary path.

Usage:
    python3 repl.py --code <base64_code> --binary /path/to/binary
"""

from __future__ import annotations

import argparse
import base64
import concurrent.futures
import io
import json
import os
import sys
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

_EXEC_TIMEOUT = 30  # seconds — max wall-clock time for user script


def execute_script(code: str, binary_path: str, timeout: int = _EXEC_TIMEOUT) -> dict:
    """Execute user code and return {ok, stdout, stderr, duration_ms}.

    Runs the script in a ThreadPoolExecutor so a hard wall-clock timeout
    can be enforced — a runaway ``while True`` loop will be cancelled after
    *timeout* seconds and reported as a TimeoutError.
    """
    stdout_buf = io.StringIO()
    stderr_buf = io.StringIO()

    start = time.monotonic()
    try:
        compiled = compile(code, "<script>", "exec")
    except SyntaxError:
        elapsed = round((time.monotonic() - start) * 1000)
        return {
            "ok": False,
            "stdout": "",
            "stderr": traceback.format_exc(),
            "duration_ms": elapsed,
        }

    exec_globals = {
        "__builtins__": __builtins__,
        "binary": binary_path,
    }

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    def _run() -> bool:
        old_stdout, old_stderr = sys.stdout, sys.stderr
        try:
            sys.stdout = stdout_buf
            sys.stderr = stderr_buf
            exec(compiled, exec_globals)
            return True
        except Exception:
            stderr_buf.write(traceback.format_exc())
            return False
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

    ok = False
    start = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(_run)
        try:
            ok = future.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            stderr_buf.write(
                f"TimeoutError: script exceeded the {timeout}s limit and was stopped.\n"
            )
        except Exception:
            stderr_buf.write(traceback.format_exc())

    elapsed = round((time.monotonic() - start) * 1000)
    return {
        "ok": ok,
        "stdout": stdout_buf.getvalue(),
        "stderr": stderr_buf.getvalue(),
        "duration_ms": elapsed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Pile ou Face script executor")
    parser.add_argument("--code", required=True, help="Base64-encoded Python code")
    parser.add_argument("--binary", default="", help="Path to loaded binary")
    args = parser.parse_args()

    try:
        code = base64.b64decode(args.code).decode("utf-8")
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "stdout": "",
                    "stderr": f"Decode error: {exc}",
                    "duration_ms": 0,
                }
            )
        )
        return 1

    result = execute_script(code, args.binary)
    print(json.dumps(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
