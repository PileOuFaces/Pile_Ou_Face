# SPDX-License-Identifier: AGPL-3.0-only
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import (
    _postprocess_code,
    _rewrite_typed_enum_literals,
    _rewrite_typed_enum_switch_cases,
    _rewrite_typed_field_access,
)


class TestRewriteTypedFieldAccess(unittest.TestCase):
    def test_rewrites_simple_field_access(self):
        code = "int a = *(int *)(param_2 + 8);"
        result = _rewrite_typed_field_access(code, {"param_2": {8: "mode"}})
        self.assertEqual(result, "int a = param_2->mode;")

    def test_rewrites_field_at_offset_zero_variant(self):
        code = "int a = *(int *)(param_2 + 0);"
        result = _rewrite_typed_field_access(code, {"param_2": {0: "x"}})
        self.assertEqual(result, "int a = param_2->x;")

    def test_no_substitution_for_unknown_offset(self):
        code = "int a = *(int *)(param_2 + 0x100);"
        result = _rewrite_typed_field_access(code, {"param_2": {8: "mode"}})
        self.assertEqual(result, code)

    def test_no_substitution_for_non_constant_offset(self):
        code = "int a = *(int *)(param_2 + i * 8);"
        result = _rewrite_typed_field_access(code, {"param_2": {8: "mode"}})
        self.assertEqual(result, code)

    def test_substitution_happens_despite_cast_mismatch(self):
        # Field is declared as an enum/int but the decompiler emitted a char* cast;
        # this lot substitutes on offset alone, imprecise but informative.
        code = "char c = *(char *)(param_2 + 8);"
        result = _rewrite_typed_field_access(code, {"param_2": {8: "mode"}})
        self.assertEqual(result, "char c = param_2->mode;")

    def test_no_op_on_empty_map(self):
        code = "int a = *(int *)(param_2 + 8);"
        self.assertEqual(_rewrite_typed_field_access(code, {}), code)
        self.assertEqual(_rewrite_typed_field_access(code, None), code)

    def test_no_op_on_empty_code(self):
        self.assertEqual(_rewrite_typed_field_access("", {"param_2": {8: "mode"}}), "")


class TestRewriteTypedEnumLiterals(unittest.TestCase):
    def test_rewrites_equality_comparison(self):
        code = "if (mode == 2) { return; }"
        result = _rewrite_typed_enum_literals(code, {"mode": {2: "MODE_READY"}})
        self.assertEqual(result, "if (mode == MODE_READY) { return; }")

    def test_rewrites_inequality_comparison(self):
        code = "if (mode != 0) { return; }"
        result = _rewrite_typed_enum_literals(code, {"mode": {0: "MODE_INIT"}})
        self.assertEqual(result, "if (mode != MODE_INIT) { return; }")

    def test_rewrites_field_access_expression(self):
        code = "if (param_2->mode == 2) { return; }"
        result = _rewrite_typed_enum_literals(
            code, {"param_2->mode": {2: "MODE_READY"}}
        )
        self.assertEqual(result, "if (param_2->mode == MODE_READY) { return; }")

    def test_no_substitution_for_unknown_value(self):
        code = "if (mode == 99) { return; }"
        result = _rewrite_typed_enum_literals(code, {"mode": {2: "MODE_READY"}})
        self.assertEqual(result, code)

    def test_no_op_on_empty_map(self):
        code = "if (mode == 2) { return; }"
        self.assertEqual(_rewrite_typed_enum_literals(code, {}), code)
        self.assertEqual(_rewrite_typed_enum_literals(code, None), code)


class TestRewriteTypedEnumSwitchCases(unittest.TestCase):
    def test_rewrites_case_labels_in_switch_block(self):
        code = "switch (mode) { case 0: init(); break; case 2: ready(); break; }"
        result = _rewrite_typed_enum_switch_cases(
            code, {"mode": {0: "MODE_INIT", 2: "MODE_READY"}}
        )
        self.assertEqual(
            result,
            "switch (mode) { case MODE_INIT: init(); break; case MODE_READY: ready(); break; }",
        )

    def test_rewrites_field_access_switch_expression(self):
        code = "switch (param_2->mode) { case 2: ready(); break; }"
        result = _rewrite_typed_enum_switch_cases(
            code, {"param_2->mode": {2: "MODE_READY"}}
        )
        self.assertEqual(
            result, "switch (param_2->mode) { case MODE_READY: ready(); break; }"
        )

    def test_no_substitution_for_unknown_case_value(self):
        code = "switch (mode) { case 99: unknown(); break; }"
        result = _rewrite_typed_enum_switch_cases(code, {"mode": {2: "MODE_READY"}})
        self.assertEqual(result, code)

    def test_does_not_touch_case_labels_of_unrelated_switch(self):
        code = "switch (other) { case 2: x(); break; }"
        result = _rewrite_typed_enum_switch_cases(code, {"mode": {2: "MODE_READY"}})
        self.assertEqual(result, code)

    def test_handles_nested_braces_inside_switch_block(self):
        code = "switch (mode) { case 2: { do_ready(); } break; default: break; }"
        result = _rewrite_typed_enum_switch_cases(code, {"mode": {2: "MODE_READY"}})
        self.assertEqual(
            result,
            "switch (mode) { case MODE_READY: { do_ready(); } break; default: break; }",
        )

    def test_no_op_on_empty_map(self):
        code = "switch (mode) { case 2: ready(); break; }"
        self.assertEqual(_rewrite_typed_enum_switch_cases(code, {}), code)
        self.assertEqual(_rewrite_typed_enum_switch_cases(code, None), code)

    def test_no_op_on_empty_code(self):
        self.assertEqual(
            _rewrite_typed_enum_switch_cases("", {"mode": {2: "MODE_READY"}}), ""
        )


class TestPostprocessCodeTypedVarBindingsIntegration(unittest.TestCase):
    def test_field_access_and_enum_rewrite_run_after_stack_substitution(self):
        code = "int a = *(int *)(rbp - 0x8 + 8);"
        # Not a realistic combined case (stack subst only fires on the bare rbp
        # pattern), so verify field/enum rewrite independently applies once the
        # decompiler-facing variable name is already in the code.
        code = "if (*(int *)(param_2 + 8) == 2) { return; }"
        result = _postprocess_code(
            code,
            {},
            None,
            field_access_map={"param_2": {8: "mode"}},
            enum_literal_map={"param_2->mode": {2: "MODE_READY"}},
        )
        self.assertEqual(result, "if (param_2->mode == MODE_READY) { return; }")

    def test_switch_case_rewrite_runs_alongside_equality_rewrite(self):
        code = "switch (param_2->mode) { case 2: ready(); break; }"
        result = _postprocess_code(
            code,
            {},
            None,
            field_access_map={"param_2": {8: "mode"}},
            enum_literal_map={"param_2->mode": {2: "MODE_READY"}},
        )
        self.assertEqual(
            result, "switch (param_2->mode) { case MODE_READY: ready(); break; }"
        )

    def test_defaults_are_no_op(self):
        code = "if (*(int *)(param_2 + 8) == 2) { return; }"
        result = _postprocess_code(code, {}, None)
        self.assertEqual(result, code)


if __name__ == "__main__":
    unittest.main()
