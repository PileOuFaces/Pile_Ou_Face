# SPDX-License-Identifier: AGPL-3.0-only
"""Script executor for Pile ou Face integrated Python scripting.

Receives base64-encoded Python code and runs it in a separate child Python
process with the `binary` variable pre-set to the binary path.

Guarantees: a wall-clock timeout and a hard stop. When the timeout expires,
the child is killed (on POSIX its whole process group, so subprocesses it
spawned die too) and the output produced before the stop is returned.

Non-guarantees: this is NOT a sandbox. The script runs with the same user,
filesystem, network and environment access as the extension. On Windows only
the child process itself is killed; processes it spawned may survive.

Usage:
    python3 repl.py --code <base64_code> --binary /path/to/binary
"""

from __future__ import annotations

import argparse
import base64
import builtins
import json
import os
import signal
import subprocess
import sys
import threading
import time
import traceback

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

_EXEC_TIMEOUT = 30  # seconds — max wall-clock time for user script
_DRAIN_TIMEOUT = 5  # seconds — max wait for pipes to close after a kill
_CHILD_FLAG = "--child"  # internal: run the payload received on stdin


def _elapsed_ms(start: float) -> int:
    return round((time.monotonic() - start) * 1000)


def _run_child() -> int:
    """Child entry point: execute the JSON payload read from stdin."""
    payload = json.loads(sys.stdin.read())
    exec_globals = {"__builtins__": builtins, "binary": payload["binary"]}

    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)

    from backends.static.compat.ida.shim import patched_ida_runtime

    try:
        compiled = compile(payload["code"], "<script>", "exec")
        with patched_ida_runtime(payload["binary"]):
            builtins.exec(compiled, exec_globals)
    except Exception:
        sys.stderr.write(traceback.format_exc())
        return 1
    return 0


def _spawn_child() -> subprocess.Popen:
    kwargs: dict = {}
    if os.name == "posix":
        kwargs["start_new_session"] = True  # own process group, killed as a whole
    else:
        kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
    env = dict(os.environ, PYTHONIOENCODING="utf-8")
    return subprocess.Popen(
        [sys.executable, "-u", os.path.abspath(__file__), _CHILD_FLAG],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
        **kwargs,
    )


def _kill_child(proc: subprocess.Popen) -> None:
    """Kill the child (and on POSIX, its whole process group)."""
    if os.name == "posix":
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass  # group already gone
    else:
        proc.kill()


class _PipeCollector:
    """Read a pipe in a background thread, keeping every chunk as it arrives.

    Unlike ``Popen.communicate``, whose ``TimeoutExpired`` carries no partial
    output on Windows, the data read so far stays available even if a
    surviving descendant keeps the pipe open and EOF never comes.
    """

    _CHUNK = 65536

    def __init__(self, stream) -> None:
        self._stream = stream
        self._chunks: list[bytes] = []
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._thread = threading.Thread(target=self._pump, daemon=True)
        self._thread.start()

    def _pump(self) -> None:
        try:
            for chunk in iter(lambda: self._stream.read1(self._CHUNK), b""):
                if self._stopped.is_set():
                    break  # result already returned: keep nothing more
                with self._lock:
                    self._chunks.append(chunk)
        except (OSError, ValueError):
            pass  # pipe closed under us after a kill: keep what was read

    def stop(self) -> None:
        """Stop collecting: a survivor that keeps the pipe open and writes no
        longer grows memory. Closing the stream from here could deadlock on
        the buffered reader's lock, so the thread exits at its next read."""
        self._stopped.set()

    def discard(self) -> None:
        """Drop the kept output once it has been returned: a silent survivor may
        keep this collector (and its thread) alive."""
        self.stop()
        with self._lock:
            self._chunks.clear()

    def join(self, timeout: float) -> bool:
        """Wait up to *timeout* s for EOF; return True if the pipe was closed."""
        self._thread.join(max(0.0, timeout))
        return not self._thread.is_alive()

    def data(self) -> bytes:
        with self._lock:
            return b"".join(self._chunks)


def _feed_stdin(proc: subprocess.Popen, payload: bytes) -> None:
    try:
        proc.stdin.write(payload)
        proc.stdin.close()
    except (BrokenPipeError, OSError):
        pass  # child died before reading its input; its stderr explains why


def _wait_until(proc: subprocess.Popen, readers: list, deadline: float) -> bool:
    """Wait for the child to exit and both pipes to close; False on deadline."""
    try:
        proc.wait(timeout=max(0.0, deadline - time.monotonic()))
    except subprocess.TimeoutExpired:
        return False
    return all(r.join(deadline - time.monotonic()) for r in readers)


def _decode(data: bytes | None) -> str:
    return (data or b"").decode("utf-8", errors="replace")


def execute_script(code: str, binary_path: str, timeout: int = _EXEC_TIMEOUT) -> dict:
    """Execute user code and return {ok, stdout, stderr, duration_ms}.

    The script runs in a child Python process. If it is still running after
    *timeout* seconds, the child is killed (POSIX: its whole process group;
    Windows: the child process only) and a TimeoutError message is appended
    to ``stderr``; output produced before the stop is kept. No OS-level
    confinement is applied: the script has the same rights as the caller.
    """
    start = time.monotonic()
    try:
        compile(code, "<script>", "exec")
    except SyntaxError:
        return {
            "ok": False,
            "stdout": "",
            "stderr": traceback.format_exc(),
            "duration_ms": _elapsed_ms(start),
        }

    payload = json.dumps({"code": code, "binary": binary_path}).encode("utf-8")
    proc = _spawn_child()
    timeout_msg = ""
    try:
        readers = [_PipeCollector(proc.stdout), _PipeCollector(proc.stderr)]
        threading.Thread(target=_feed_stdin, args=(proc, payload), daemon=True).start()
        if not _wait_until(proc, readers, start + timeout):
            _kill_child(proc)
            proc.wait()
            # Bounded: a process that escaped the kill (e.g. a Windows
            # grandchild) may keep the pipes open forever.
            drain_deadline = (
                time.monotonic() + _DRAIN_TIMEOUT
            )  # one budget for both pipes
            for reader in readers:
                reader.join(drain_deadline - time.monotonic())
                reader.stop()
            timeout_msg = (
                f"TimeoutError: script exceeded the {timeout}s limit and was stopped.\n"
            )
    finally:
        if proc.poll() is None:
            _kill_child(proc)

    result = {
        "ok": not timeout_msg and proc.returncode == 0,
        "stdout": _decode(readers[0].data()),
        "stderr": _decode(readers[1].data()) + timeout_msg,
        "duration_ms": _elapsed_ms(start),
    }
    for reader in readers:
        reader.discard()
    return result


def main() -> int:
    if sys.argv[1:] == [_CHILD_FLAG]:
        return _run_child()

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
    # Le résultat (ok, stdout, stderr) est dans le JSON : un code non nul ferait
    # rejeter l'appel par l'extension, qui perdrait alors la sortie conservée.
    return 0


if __name__ == "__main__":
    sys.exit(main())
