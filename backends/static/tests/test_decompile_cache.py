# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_decompile_cache.py
import sys, os, tempfile, unittest, json, time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import (
    _build_cache_meta,
    _cache_key,
    _read_cache,
    _write_cache,
    _stack_signature,
    decompile_function,
)

# ---------------------------------------------------------------------------
# Helpers partagés pour mocker la nouvelle architecture multi-décompilateur
# ---------------------------------------------------------------------------


def _make_run_custom(results_by_name: dict):
    """Retourne un fake _run_custom_decompiler qui dispatch par nom de décompilateur."""

    def _fake(decompiler, binary_path, addr="", func_name="", full=False, **kw):
        if decompiler in results_by_name:
            r = dict(results_by_name[decompiler])
            r.setdefault("decompiler", decompiler)
            return r
        return {
            "addr": addr,
            "code": "",
            "error": f"no mock for {decompiler}",
            "decompiler": decompiler,
        }

    return _fake


def _available_only(*names):
    """Retourne un fake _is_decompiler_available qui n'autorise que *names."""

    def _fake(decompiler, provider="auto"):
        return decompiler in names

    return _fake


def _decompiler_order(*names):
    """Retourne un fake _auto_decompiler_order."""
    return lambda: list(names)


# ---------------------------------------------------------------------------
# Tests des helpers de cache
# ---------------------------------------------------------------------------


class TestCacheHelpers(unittest.TestCase):
    def test_cache_key_returns_16_hex_chars(self):
        key = _cache_key("/bin/ls", "0x401000")
        self.assertEqual(len(key), 16)
        self.assertTrue(all(c in "0123456789abcdef" for c in key))

    def test_cache_key_changes_with_addr(self):
        k1 = _cache_key("/bin/ls", "0x401000")
        k2 = _cache_key("/bin/ls", "0x401010")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_path(self):
        k1 = _cache_key("/bin/ls", "0x401000")
        k2 = _cache_key("/bin/cat", "0x401000")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_decompiler(self):
        k1 = _cache_key("/bin/ls", "0x401000", decompiler="tool_b")
        k2 = _cache_key("/bin/ls", "0x401000", decompiler="ghidra")
        self.assertNotEqual(k1, k2)

    def test_cache_key_changes_with_annotations_mtime(self):
        import time

        with tempfile.TemporaryDirectory() as d:
            ann_path = Path(d) / "ann.json"
            ann_path.write_text('{"0x401000": {"name": "foo"}}')
            k1 = _cache_key("/bin/ls", "0x401000", annotations_json=str(ann_path))
            time.sleep(0.01)
            ann_path.write_text('{"0x401000": {"name": "bar"}}')
            k2 = _cache_key("/bin/ls", "0x401000", annotations_json=str(ann_path))
            self.assertNotEqual(k1, k2)

    def test_cache_key_reuses_identical_binary_content_across_paths(self):
        with tempfile.TemporaryDirectory() as d:
            a = Path(d) / "a.bin"
            b = Path(d) / "b.bin"
            payload = b"\x7fELF" + b"A" * 64
            a.write_bytes(payload)
            b.write_bytes(payload)
            k1 = _cache_key(str(a), "0x401000")
            k2 = _cache_key(str(b), "0x401000")
            self.assertEqual(k1, k2)

    def test_read_cache_returns_none_if_missing(self):
        with tempfile.TemporaryDirectory() as d:
            result = _read_cache("deadbeefcafe1234", Path(d))
            self.assertIsNone(result)

    def test_write_then_read_cache(self):
        with tempfile.TemporaryDirectory() as d:
            data = {"addr": "0x401000", "code": "int f() {}", "error": None}
            _write_cache("deadbeefcafe1234", Path(d), data)
            result = _read_cache("deadbeefcafe1234", Path(d))
            self.assertEqual(result, data)

    def test_write_cache_creates_dir(self):
        with tempfile.TemporaryDirectory() as d:
            subdir = Path(d) / "nested" / "cache"
            _write_cache("deadbeefcafe1234", subdir, {"x": 1})
            self.assertTrue((subdir / "deadbeefcafe1234.json").exists())

    def test_write_cache_can_embed_binary_metadata(self):
        with tempfile.TemporaryDirectory() as d:
            binary = Path(d) / "demo.bin"
            binary.write_bytes(b"demo")
            subdir = Path(d) / "cache"
            _write_cache("deadbeefcafe1234", subdir, {"x": 1}, meta=_build_cache_meta(str(binary)))
            result = _read_cache("deadbeefcafe1234", subdir)
            self.assertEqual(result["x"], 1)
            self.assertEqual(result["_cache_meta"]["binary_path"], str(binary.resolve()))
            self.assertEqual(result["_cache_meta"]["binary_size"], 4)


# ---------------------------------------------------------------------------
# Tests du comportement de cache dans decompile_function
# ---------------------------------------------------------------------------


class TestDecompileFunctionCache(unittest.TestCase):
    _empty_stack = {"arch": "unknown", "abi": "unknown", "frame_size": 0, "vars": [], "args": []}

    def _base_patches(self, decompiler="tool_a", fake_code="/* live */"):
        return [
            mock.patch(
                "backends.static.decompile.decompile._auto_decompiler_order",
                _decompiler_order(decompiler),
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available",
                _available_only(decompiler),
            ),
            mock.patch(
                "backends.static.decompile.decompile._run_custom_decompiler",
                _make_run_custom(
                    {decompiler: {"addr": "0x401000", "code": fake_code, "error": None}}
                ),
            ),
            mock.patch(
                "backends.static.decompile.decompile.typed_struct_signature", return_value=""
            ),
            mock.patch(
                "backends.static.disasm.stack_frame.analyse_stack_frame",
                return_value=self._empty_stack,
            ),
        ]

    def test_cache_hit_skips_decompiler(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            cached = {
                "addr": "0x401000",
                "code": "/* cached */",
                "error": None,
                "decompiler": "tool_a",
            }
            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(self._empty_stack, None),
                typed_structs_signature="",
            )
            _write_cache(key, cache_dir, cached)

            run_called = {"n": 0}

            def counting_run(decompiler, binary_path, addr="", **kw):
                run_called["n"] += 1
                return {"addr": addr, "code": "/* live */", "error": None}

            with (
                mock.patch(
                    "backends.static.decompile.decompile._auto_decompiler_order",
                    _decompiler_order("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    _available_only("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._run_custom_decompiler", counting_run
                ),
                mock.patch(
                    "backends.static.decompile.decompile.typed_struct_signature", return_value=""
                ),
                mock.patch(
                    "backends.static.disasm.stack_frame.analyse_stack_frame",
                    return_value=self._empty_stack,
                ),
            ):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            self.assertEqual(run_called["n"], 0)
            self.assertEqual(result["code"], "/* cached */")

    def test_cache_miss_writes_cache(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            with (
                mock.patch(
                    "backends.static.decompile.decompile._auto_decompiler_order",
                    _decompiler_order("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    _available_only("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._run_custom_decompiler",
                    _make_run_custom(
                        {"tool_a": {"addr": "0x401000", "code": "int f(){}", "error": None}}
                    ),
                ),
                mock.patch(
                    "backends.static.decompile.decompile.typed_struct_signature", return_value=""
                ),
                mock.patch(
                    "backends.static.disasm.stack_frame.analyse_stack_frame",
                    return_value=self._empty_stack,
                ),
            ):
                decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(self._empty_stack, None),
                typed_structs_signature="",
            )
            cached = _read_cache(key, cache_dir)
            self.assertIsNotNone(cached)
            self.assertEqual(cached["code"], "int f(){}")

    def test_error_result_not_cached(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            with (
                mock.patch(
                    "backends.static.decompile.decompile._auto_decompiler_order",
                    _decompiler_order("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    lambda d, p="auto": False,
                ),
                mock.patch(
                    "backends.static.decompile.decompile.typed_struct_signature", return_value=""
                ),
                mock.patch(
                    "backends.static.disasm.stack_frame.analyse_stack_frame",
                    return_value=self._empty_stack,
                ),
            ):
                decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            key = _cache_key(
                "/bin/ls",
                "0x401000",
                stack_signature=_stack_signature(self._empty_stack, None),
                typed_structs_signature="",
            )
            self.assertIsNone(_read_cache(key, cache_dir))

    def test_auto_mode_runs_available_backends(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            calls = []

            def run_custom(decompiler, binary_path, addr="", func_name="", full=False, **kw):
                calls.append(decompiler)
                codes = {
                    "tool_a": "int tool_a_f() { return 0; }",
                    "ghidra": "int ghidra_f() {\n  local_10 = 0;\n  return local_10;\n}",
                    "retdec": "int retdec_f(int argc, char **argv) {\n    if (argc > 1) {\n        helper(argv[1]);\n    }\n    return 1;\n}\n",
                }
                delays = {"tool_a": 0.01, "ghidra": 0.02, "retdec": 0.05}
                time.sleep(delays.get(decompiler, 0))
                return {
                    "addr": addr,
                    "code": codes.get(decompiler, ""),
                    "error": None,
                    "decompiler": decompiler,
                }

            with (
                mock.patch(
                    "backends.static.decompile.decompile._auto_decompiler_order",
                    _decompiler_order("retdec", "ghidra", "tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    _available_only("retdec", "ghidra", "tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._run_custom_decompiler", run_custom
                ),
                mock.patch(
                    "backends.static.disasm.stack_frame.analyse_stack_frame",
                    return_value=self._empty_stack,
                ),
            ):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            self.assertEqual(set(calls), {"retdec", "ghidra", "tool_a"})
            self.assertIn("addr", result)
            self.assertEqual(result["decompiler"], "retdec")
            self.assertEqual(result["quality_details"]["selected_backend"], "retdec")
            self.assertEqual(len(result["quality_details"]["backends"]), 3)
            self.assertGreater(
                result["quality_details"]["selected_score"],
                next(
                    entry["score"]
                    for entry in result["quality_details"]["backends"]
                    if entry["decompiler"] == "tool_a"
                ),
            )

    def test_auto_mode_single_backend(self):
        with tempfile.TemporaryDirectory() as d:
            cache_dir = Path(d)
            calls = []

            def run_custom(decompiler, binary_path, addr="", **kw):
                calls.append(decompiler)
                return {
                    "addr": addr,
                    "code": "int f() { return 0; }",
                    "error": None,
                    "decompiler": decompiler,
                }

            with (
                mock.patch(
                    "backends.static.decompile.decompile._auto_decompiler_order",
                    _decompiler_order("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    _available_only("tool_a"),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._run_custom_decompiler", run_custom
                ),
                mock.patch(
                    "backends.static.disasm.stack_frame.analyse_stack_frame",
                    return_value=self._empty_stack,
                ),
            ):
                result = decompile_function("/bin/ls", "0x401000", cache_dir=cache_dir)

            self.assertIn("tool_a", calls)
            self.assertIn("addr", result)

    def test_decompile_binary_auto_runs_backends(self):
        calls = []

        def run_custom(decompiler, binary_path, addr="", full=False, **kw):
            calls.append(decompiler)
            delays = {"tool_a": 0.01, "ghidra": 0.02, "retdec": 0.05}
            time.sleep(delays.get(decompiler, 0))
            function_map = {
                "tool_a": [
                    {"addr": "0x401000", "code": "int f_tool_a() { return 0; }", "error": None}
                ],
                "ghidra": [
                    {"addr": "0x401000", "code": "int f_ghidra() { return 0; }", "error": None}
                ],
                "retdec": [
                    {
                        "addr": "0x401000",
                        "code": "int f_retdec() { helper(); return 0; }",
                        "error": None,
                    },
                    {"addr": "0x401040", "code": "int helper() { return 1; }", "error": None},
                ],
            }
            funcs = function_map[decompiler]
            return {"functions": funcs, "error": None, "decompiler": decompiler}

        from backends.static.decompile.decompile import decompile_binary

        with (
            mock.patch(
                "backends.static.decompile.decompile._auto_decompiler_order",
                _decompiler_order("retdec", "ghidra", "tool_a"),
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available",
                _available_only("retdec", "ghidra", "tool_a"),
            ),
            mock.patch("backends.static.decompile.decompile._run_custom_decompiler", run_custom),
        ):
            result = decompile_binary("/bin/ls")

        self.assertEqual(set(calls), {"retdec", "ghidra", "tool_a"})
        self.assertIn("quality_details", result)
        self.assertEqual(result["decompiler"], "retdec")
        self.assertEqual(result["quality_details"]["selected_backend"], "retdec")
        self.assertEqual(len(result["quality_details"]["backends"]), 3)


class TestCLICacheDir(unittest.TestCase):
    def test_cache_dir_arg_accepted(self):
        """--cache-dir est reconnu sans lever d'erreur argparse."""
        import subprocess, sys

        with tempfile.TemporaryDirectory() as d:
            result = subprocess.run(
                [
                    sys.executable,
                    "backends/static/decompile/decompile.py",
                    "--binary",
                    "/nonexistent",
                    "--addr",
                    "0x401000",
                    "--cache-dir",
                    d,
                ],
                capture_output=True,
                text=True,
                cwd=str(ROOT),
            )
            self.assertNotIn("unrecognized arguments", result.stderr)
            self.assertNotIn("error: unrecognized", result.stderr)
            if result.stdout.strip():
                out = json.loads(result.stdout)
                self.assertIn("error", out)


if __name__ == "__main__":
    unittest.main()
