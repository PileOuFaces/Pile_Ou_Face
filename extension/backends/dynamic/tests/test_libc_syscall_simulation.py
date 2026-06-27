# SPDX-License-Identifier: AGPL-3.0-only
"""Regression tests for simulated libc/syscall bridge calls."""

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


def _compile_c(source: str, tmpdir: str, name: str = "prog") -> Path:
    if shutil.which("gcc") is None:
        raise unittest.SkipTest("gcc is required for dynamic ELF tests")
    src = Path(tmpdir) / f"{name}.c"
    binary = Path(tmpdir) / name
    src.write_text(textwrap.dedent(source), encoding="utf-8")
    result = subprocess.run(
        [
            "gcc",
            "-O0",
            "-g",
            "-fno-pie",
            "-no-pie",
            "-fno-stack-protector",
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


def _config(
    *,
    start_symbol: str = "main",
    stop_symbol: str = "done",
    argv1: str | None = None,
    virtual_files: dict[str, bytes] | None = None,
) -> TraceConfig:
    return TraceConfig(
        base=0x400000,
        stack_base=0x7FFFFFFDE000,
        stack_size=0x40000,
        max_steps=5000,
        stack_entries=32,
        arch_bits=64,
        interp_base=0x7F0000000000,
        start_interp=False,
        stdin_data=b"",
        buffer_offset=None,
        buffer_size=0,
        start_symbol=start_symbol,
        argv1=argv1,
        stop_symbol=stop_symbol,
        capture_ranges=[],
        virtual_files=virtual_files,
    )


def _trace(binary: Path, config: TraceConfig) -> dict:
    return trace_binary(binary.read_bytes(), config, str(binary))


def _external_snapshot(result: dict, symbol: str) -> dict:
    for snapshot in result.get("snapshots", []):
        if snapshot.get("effects", {}).get("external_symbol") == symbol:
            return snapshot
    raise AssertionError(f"missing simulated external call for {symbol}")


@unittest.skipIf(trace_binary is None, UNICORN_SKIP_REASON)
class TestLibcSyscallSimulation(unittest.TestCase):
    def test_getpid_call_continues_and_writes_rax(self):
        source = """
            #include <unistd.h>
            volatile int sink;
            __attribute__((noinline)) void done(void) { sink += 1; }
            int main(void) {
                sink = (int)getpid();
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_c(source, tmpdir, "getpid_prog")
            result = _trace(binary, _config())

        self.assertIsNone(result["meta"]["error"])
        self.assertEqual(result["meta"]["simulated_external_calls"].get("getpid"), 1)
        self.assertEqual(
            result["snapshots"][-1]["instruction"]["address"],
            result["meta"]["stop_addr"],
        )
        call = _external_snapshot(result, "getpid")
        self.assertEqual(call["cpu"]["after"]["registers"].get("rax"), "0x539")
        self.assertTrue(call["effects"]["external_simulated"])

    def test_getuid_call_continues_and_writes_rax(self):
        source = """
            #include <unistd.h>
            volatile int sink;
            __attribute__((noinline)) void done(void) { sink += 1; }
            int main(void) {
                sink = (int)getuid();
                done();
                return sink;
            }
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_c(source, tmpdir, "getuid_prog")
            result = _trace(binary, _config())

        self.assertIsNone(result["meta"]["error"])
        self.assertEqual(result["meta"]["simulated_external_calls"].get("getuid"), 1)
        self.assertEqual(
            result["snapshots"][-1]["instruction"]["address"],
            result["meta"]["stop_addr"],
        )
        call = _external_snapshot(result, "getuid")
        self.assertEqual(call["cpu"]["after"]["registers"].get("rax"), "0x3e8")
        self.assertTrue(call["effects"]["external_simulated"])

    def test_rootme5_like_file_flow_reaches_cpstr_after_getpid_getuid(self):
        source = r"""
            #include <stdio.h>
            #include <string.h>
            #include <unistd.h>
            #include <sys/types.h>

            #define BUFFER 512

            struct InitState {
              char username[128];
              uid_t uid;
              pid_t pid;
            };

            __attribute__((noinline)) void cpstr(char *dst, const char *src) {
              for (; *src; src++, dst++) {
                *dst = *src;
              }
              *dst = 0;
            }

            struct InitState load_init(char *filename) {
              FILE *file;
              struct InitState init;
              char buff[BUFFER + 1];

              file = fopen(filename, "r");
              if (file == NULL) {
                return init;
              }

              memset(&init, 0, sizeof(struct InitState));
              init.pid = getpid();
              init.uid = getuid();

              while (fgets(buff, BUFFER, file) != NULL) {
                if (strncmp(buff, "USERNAME=", 9) == 0) {
                  cpstr(init.username, buff + 9);
                }
              }
              fclose(file);
              return init;
            }

            int main(int argc, char **argv) {
              struct InitState init;
              if (argc != 2) {
                return 2;
              }
              init = load_init(argv[1]);
              return init.username[0];
            }
        """
        guest_path = "/virtual/rootme5.conf"
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = _compile_c(source, tmpdir, "rootme5_like")
            result = _trace(
                binary,
                _config(
                    stop_symbol="cpstr",
                    argv1=guest_path,
                    virtual_files={guest_path: b"USERNAME=alice\n"},
                ),
            )

        self.assertIsNone(result["meta"]["error"])
        simulated = result["meta"]["simulated_external_calls"]
        self.assertEqual(simulated.get("fopen"), 1)
        self.assertEqual(simulated.get("getpid"), 1)
        self.assertEqual(simulated.get("getuid"), 1)
        self.assertGreaterEqual(simulated.get("fgets", 0), 1)
        self.assertEqual(
            result["snapshots"][-1]["instruction"]["address"],
            result["meta"]["stop_addr"],
        )


if __name__ == "__main__":
    unittest.main()
