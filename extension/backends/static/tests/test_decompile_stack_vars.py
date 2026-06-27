# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_decompile_stack_vars.py
import sys, tempfile, unittest
from pathlib import Path
from unittest import mock
from contextlib import ExitStack

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import decompile_function, _postprocess_code


class TestPostprocessStackVars(unittest.TestCase):
    def test_substitutes_rbp_minus_offset(self):
        code = "int x = *(uint32_t *)(rbp - 0x8);"
        stack_vars = [{"name": "my_var", "offset": -8}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("my_var", result)

    def test_no_crash_when_stack_vars_empty(self):
        code = "int x = *(uint32_t *)(rbp - 0x8);"
        result = _postprocess_code(code, {}, [])
        self.assertEqual(result, code)

    def test_no_crash_when_stack_vars_none(self):
        code = "int x = *(uint32_t *)(rbp - 0x8);"
        result = _postprocess_code(code, {}, None)
        self.assertEqual(result, code)

    def test_substitutes_multiple_vars(self):
        code = "a = (rbp - 0x8); b = (rbp - 0x10);"
        stack_vars = [{"name": "count", "offset": -8}, {"name": "ptr", "offset": -16}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("count", result)
        self.assertIn("ptr", result)

    def test_substitutes_rsp_location_using_location_field(self):
        code = "tmp = *(uint64_t *)(rsp + 0x18);"
        stack_vars = [{"name": "saved_tmp", "offset": -16, "location": "[rsp+0x18]"}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("saved_tmp", result)

    def test_substitutes_arm64_location_using_location_field(self):
        code = "tmp = *(uint64_t *)(sp + 0x18);"
        stack_vars = [{"name": "saved_x19", "offset": -72, "location": "[sp+0x18]"}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("saved_x19", result)

    def test_substitutes_arm32_fp_location_using_location_field(self):
        code = "tmp = *(uint32_t *)(fp + 0x8);"
        stack_vars = [{"name": "arg_fp", "offset": 8, "location": "[r11+0x8]"}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("arg_fp", result)

    def test_substitutes_register_args_from_location_aliases(self):
        code = "return edi + esi;"
        stack_vars = [
            {"name": "arg_left", "location": "rdi", "source": "abi"},
            {"name": "arg_right", "location": "rsi", "source": "abi"},
        ]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("arg_left", result)
        self.assertIn("arg_right", result)

    def test_substitutes_arm_register_args_from_location_aliases(self):
        code = "x0 = x0 + w1;"
        stack_vars = [
            {"name": "arg_x0", "location": "x0", "source": "abi"},
            {"name": "arg_x1", "location": "x1", "source": "abi"},
        ]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("arg_x0", result)
        self.assertIn("arg_x1", result)

    def test_substitutes_annotation_variants_like_dat_and_lab(self):
        code = "return DAT_00401000 + LAB_00401000;"
        result = _postprocess_code(code, {"401000": "g_config_ptr"}, None)
        self.assertIn("g_config_ptr", result)
        self.assertNotIn("DAT_00401000", result)
        self.assertNotIn("LAB_00401000", result)

    def test_substitutes_ghidra_local_tokens(self):
        code = "undefined8 local_10;\nlocal_10 = 0;\nreturn local_10;"
        stack_vars = [{"name": "saved_ctx", "offset": -0x10, "size": 8}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("saved_ctx", result)
        self.assertNotIn("local_10", result)

    def test_substitutes_r2_var_tokens(self):
        code = "var_18h = 0;\nreturn var_18h;"
        stack_vars = [{"name": "decoded_len", "offset": -0x18, "size": 8}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("decoded_len", result)
        self.assertNotIn("var_18h", result)

    def test_substitutes_ghidra_stack_family_tokens(self):
        code = "auStack_20[0] = 0;\nreturn puStack_20;"
        stack_vars = [{"name": "key_material", "offset": -0x20, "size": 16}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("key_material", result)
        self.assertNotIn("auStack_20", result)
        self.assertNotIn("puStack_20", result)

    def test_substitutes_param_tokens_from_arg_order(self):
        code = "return param_1 + param_2;"
        stack_vars = [
            {"name": "arg_left", "location": "rdi", "source": "abi"},
            {"name": "arg_right", "location": "rsi", "source": "abi"},
        ]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("arg_left", result)
        self.assertIn("arg_right", result)
        self.assertNotIn("param_1", result)
        self.assertNotIn("param_2", result)

    def test_substitutes_stack0x_tokens_for_negative_offsets(self):
        code = "*(undefined8 *)stack0xfffffffffffffff8 = 0;\nreturn stack0xfffffffffffffff8;"
        stack_vars = [{"name": "saved_cookie", "offset": -8, "size": 8}]
        result = _postprocess_code(code, {}, stack_vars)
        self.assertIn("saved_cookie", result)
        self.assertNotIn("stack0xfffffffffffffff8", result)


def _make_run_custom(fake_code, decompiler="tool_a"):
    def _fake(d, binary_path, addr="", func_name="", full=False, **kw):
        if d == decompiler:
            return {"addr": addr, "code": fake_code, "error": None, "decompiler": decompiler}
        return {"addr": addr, "code": "", "error": f"no mock for {d}", "decompiler": d}

    return _fake


class TestDecompileFunctionStackVars(unittest.TestCase):
    def _base_patches(self, fake_code="int f() { *(uint32_t *)(rbp - 0x8); }"):
        return [
            mock.patch(
                "backends.static.decompile.decompile._auto_decompiler_order", lambda: ["tool_a"]
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available",
                lambda d, p="auto": d == "tool_a",
            ),
            mock.patch(
                "backends.static.decompile.decompile._run_custom_decompiler",
                _make_run_custom(fake_code, "tool_a"),
            ),
        ]

    def test_stack_vars_injected_from_analyse_stack_frame(self):
        fake_stack = {
            "vars": [{"name": "my_var", "offset": -8, "size": 4, "source": "auto"}],
            "args": [],
        }
        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches():
                    stack.enter_context(p)
                # Patch analyse_stack_frame at the module level it's imported from
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value=fake_stack,
                    )
                )
                result = decompile_function("/bin/ls", "0x401000", cache_dir=Path(d))
        self.assertIn("my_var", result.get("code", ""))

    def test_graceful_degradation_if_analyse_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches("int f() {}"):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        side_effect=Exception("capstone not available"),
                    )
                )
                result = decompile_function("/bin/ls", "0x401000", cache_dir=Path(d))
        self.assertIsNone(result.get("error"))
        self.assertIn("int f()", result.get("code", ""))

    def test_decimal_addr_does_not_crash(self):
        """addr sans préfixe 0x (décimal) ne doit pas crasher l'injection stack vars."""
        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches("int f() {}"):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value={"vars": [], "args": []},
                    )
                )
                result = decompile_function("/bin/ls", "4198400", cache_dir=Path(d))
        self.assertIsNone(result.get("error"))

    def test_explicit_stack_vars_not_overwritten(self):
        """Si stack_vars est passé explicitement, ne pas appeler analyse_stack_frame."""
        explicit_vars = [{"name": "explicit_var", "offset": -8}]
        analyse_called = {"n": 0}

        def fake_analyse(bp, addr):
            analyse_called["n"] += 1
            return {"vars": [], "args": []}

        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches("int f() { *(uint32_t *)(rbp - 0x8); }"):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame", fake_analyse
                    )
                )
                result = decompile_function(
                    "/bin/ls", "0x401000", stack_vars=explicit_vars, cache_dir=Path(d)
                )
        self.assertEqual(analyse_called["n"], 0)
        self.assertIn("explicit_var", result.get("code", ""))

    def test_cache_key_follows_stack_frame_payload(self):
        fake_code = "int f() { return *(uint64_t *)(rsp + 0x18); }"
        first_stack = {
            "arch": "x86",
            "abi": "win64",
            "frame_size": 40,
            "vars": [
                {
                    "name": "first_tmp",
                    "offset": -16,
                    "location": "[rsp+0x18]",
                    "size": 8,
                    "source": "auto",
                }
            ],
            "args": [],
        }
        second_stack = {
            "arch": "x86",
            "abi": "win64",
            "frame_size": 40,
            "vars": [
                {
                    "name": "second_tmp",
                    "offset": -16,
                    "location": "[rsp+0x18]",
                    "size": 8,
                    "source": "auto",
                }
            ],
            "args": [],
        }
        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches(fake_code):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value=first_stack,
                    )
                )
                first = decompile_function("/bin/ls", "0x401000", cache_dir=Path(d))
            with ExitStack() as stack:
                for p in self._base_patches(fake_code):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value=second_stack,
                    )
                )
                second = decompile_function("/bin/ls", "0x401000", cache_dir=Path(d))
        self.assertIn("first_tmp", first.get("code", ""))
        self.assertIn("second_tmp", second.get("code", ""))
        self.assertEqual(second.get("stack_frame", {}).get("abi"), "win64")

    def test_annotations_are_reported_in_result_payload(self):
        fake_stack = {"vars": [], "args": []}
        with tempfile.TemporaryDirectory() as d:
            ann_path = Path(d) / "annotations.json"
            ann_path.write_text(
                '{"0x401000": {"name": "decrypt_cfg", "comment": "Point d\'entree de decryption"}}',
                encoding="utf-8",
            )
            with ExitStack() as stack:
                for p in self._base_patches("int f() { return DAT_00401000; }"):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value=fake_stack,
                    )
                )
                result = decompile_function(
                    "/bin/ls",
                    "0x401000",
                    annotations_json=str(ann_path),
                    cache_dir=Path(d),
                )
        annotations = result.get("annotations") or []
        self.assertEqual(len(annotations), 1)
        self.assertEqual(annotations[0]["name"], "decrypt_cfg")
        self.assertIn("decryption", annotations[0]["comment"])

    def test_pipeline_substitutes_decompiler_specific_stack_aliases(self):
        fake_stack = {
            "vars": [{"name": "saved_ctx", "offset": -0x10, "size": 8, "source": "auto"}],
            "args": [{"name": "arg_left", "location": "rdi", "source": "abi"}],
        }
        fake_code = "undefined8 local_10;\nlocal_10 = param_1;\nreturn local_10;"
        with tempfile.TemporaryDirectory() as d:
            with ExitStack() as stack:
                for p in self._base_patches(fake_code):
                    stack.enter_context(p)
                stack.enter_context(
                    mock.patch(
                        "backends.static.disasm.stack_frame.analyse_stack_frame",
                        return_value=fake_stack,
                    )
                )
                result = decompile_function("/bin/ls", "0x401000", cache_dir=Path(d))
        self.assertIn("saved_ctx", result.get("code", ""))
        self.assertIn("arg_left", result.get("code", ""))
        self.assertNotIn("local_10", result.get("code", ""))
        self.assertNotIn("param_1", result.get("code", ""))


if __name__ == "__main__":
    unittest.main()
