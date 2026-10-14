# SPDX-License-Identifier: AGPL-3.0-only
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.typed_var_bindings import (
    _safe_int,
    build_typed_var_binding_index,
    build_typed_var_binding_map_by_func,
    format_typed_var_binding,
    list_typed_var_bindings,
    save_typed_var_binding,
    typed_var_binding_signature,
)

_BINARY = "/tmp/demo.bin"


def _seed_definitions(storage: str) -> None:
    database = StructDb(storage)
    database.replace_definitions(
        _BINARY,
        "manual",
        {
            "Mode": {
                "kind": "enum",
                "values": [
                    {"name": "MODE_INIT", "value": 0},
                    {"name": "MODE_READY", "value": 2},
                ],
            },
            "Point": {
                "kind": "struct",
                "fields": [
                    {"name": "x", "type": "int", "type_kind": "primitive"},
                    {"name": "y", "type": "int", "type_kind": "primitive"},
                ],
            },
            "Widget": {
                "kind": "struct",
                "fields": [
                    {"name": "origin", "type": "Point", "type_kind": "struct"},
                    {"name": "mode", "type": "Mode", "type_kind": "enum"},
                ],
            },
            "Inner": {
                "kind": "struct",
                "fields": [
                    {"name": "value", "type": "int", "type_kind": "primitive"},
                    {"name": "status", "type": "Mode", "type_kind": "enum"},
                ],
            },
            "Outer": {
                "kind": "struct",
                "fields": [
                    {"name": "tag", "type": "int", "type_kind": "primitive"},
                    {
                        "name": "inner",
                        "type": "Inner",
                        "type_kind": "pointer",
                        "pointer_level": 1,
                    },
                ],
            },
            "Node": {
                "kind": "struct",
                "fields": [
                    {
                        "name": "next",
                        "type": "Node",
                        "type_kind": "pointer",
                        "pointer_level": 1,
                    },
                    {"name": "val", "type": "int", "type_kind": "primitive"},
                ],
            },
            "Ghost": {
                "kind": "struct",
                "fields": [
                    {"name": "bad", "type": "MissingType", "type_kind": "struct"},
                ],
            },
            "GhostHolder": {
                "kind": "struct",
                "fields": [
                    {
                        "name": "ghost",
                        "type": "Ghost",
                        "type_kind": "pointer",
                        "pointer_level": 1,
                    },
                ],
            },
        },
    )


class TestTypedVarBindings(unittest.TestCase):
    def test_save_and_list_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "2",
                    "type_name": "Widget",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            listed = list_typed_var_bindings(
                _BINARY, "0x401000", workspace_root=storage
            )
            self.assertEqual(len(listed["entries"]), 1)
            self.assertEqual(listed["entries"][0]["type_name"], "Widget")

    def test_build_map_by_func_groups_raw_entries_by_func_then_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Widget",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "local",
                    "var_key": "-16",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )
            save_typed_var_binding(
                _BINARY,
                "0x402000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Point",
                    "type_kind": "struct",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )

            grouped = build_typed_var_binding_map_by_func(
                _BINARY, workspace_root=storage
            )

            self.assertEqual(set(grouped.keys()), {"0x401000", "0x402000"})
            self.assertEqual(set(grouped["0x401000"].keys()), {"param:1", "local:-16"})
            self.assertEqual(grouped["0x401000"]["param:1"]["type_name"], "Widget")
            self.assertEqual(grouped["0x401000"]["local:-16"]["type_name"], "Mode")
            self.assertEqual(set(grouped["0x402000"].keys()), {"param:1"})
            self.assertEqual(grouped["0x402000"]["param:1"]["type_name"], "Point")

    def test_build_map_by_func_empty_when_no_bindings(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            self.assertEqual(
                build_typed_var_binding_map_by_func(_BINARY, workspace_root=storage), {}
            )

    def test_build_index_resolves_struct_fields_and_nested_enum(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "2",
                    "type_name": "Widget",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage, ptr_size=8
            )
            field_access_map = index["field_access_map"]
            self.assertEqual(field_access_map["param:2"][0], "origin")
            self.assertEqual(field_access_map["param:2"][8], "mode")

            enum_literal_map = index["enum_literal_map"]
            self.assertEqual(enum_literal_map["param:2->mode"][2], "MODE_READY")
            self.assertEqual(enum_literal_map["param:2->mode"][0], "MODE_INIT")

    def test_build_index_resolves_local_enum_binding(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "local",
                    "var_key": "-16",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage
            )
            self.assertEqual(index["enum_literal_map"]["local:-16"][2], "MODE_READY")
            self.assertEqual(index["field_access_map"], {})

    def test_build_index_resolves_multilevel_pointer_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Outer",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage, ptr_size=8
            )
            field_access_map = index["field_access_map"]
            self.assertEqual(field_access_map["param:1"][0], "tag")
            self.assertEqual(field_access_map["param:1"][8], "inner")
            self.assertEqual(field_access_map["param:1->inner"][0], "value")
            self.assertEqual(field_access_map["param:1->inner"][4], "status")

            enum_literal_map = index["enum_literal_map"]
            self.assertEqual(
                enum_literal_map["param:1->inner->status"][2], "MODE_READY"
            )
            self.assertEqual(enum_literal_map["param:1->inner->status"][0], "MODE_INIT")

    def test_build_index_stops_recursion_on_self_referential_struct(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Node",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage, ptr_size=8
            )
            field_access_map = index["field_access_map"]
            self.assertEqual(field_access_map["param:1"][0], "next")
            self.assertNotIn("param:1->next", field_access_map)

    def test_expand_struct_fields_swallows_layout_error(self):
        # GhostHolder->ghost points at Ghost, whose own field type is unknown to
        # the catalog; compute_struct_layout("Ghost") raises internally and
        # _expand_struct_fields must swallow it rather than propagate, simply
        # stopping the recursion at that depth (while logging a warning so the
        # dropped type binding is diagnosable).
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "GhostHolder",
                    "type_kind": "struct",
                    "pointer_level": 1,
                },
                workspace_root=storage,
            )
            with self.assertLogs(
                "backends.static.annotations.typed_var_bindings", level="WARNING"
            ) as logs:
                index = build_typed_var_binding_index(
                    _BINARY, "0x401000", workspace_root=storage, ptr_size=8
                )
            self.assertTrue(
                any("Ghost" in record for record in logs.output),
                logs.output,
            )
            field_access_map = index["field_access_map"]
            self.assertEqual(field_access_map["param:1"][0], "ghost")
            self.assertNotIn("param:1->ghost", field_access_map)

    def test_safe_int_logs_debug_on_unparseable_value(self):
        with self.assertLogs(
            "backends.static.annotations.typed_var_bindings", level="DEBUG"
        ) as logs:
            result = _safe_int("not-a-number", default=-1)
        self.assertEqual(result, -1)
        self.assertTrue(any("not-a-number" in record for record in logs.output))

    def test_build_index_returns_empty_maps_when_no_entries(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage
            )
            self.assertEqual(index, {"field_access_map": {}, "enum_literal_map": {}})

    def test_build_index_skips_non_single_level_pointer(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Widget",
                    "type_kind": "struct",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )
            index = build_typed_var_binding_index(
                _BINARY, "0x401000", workspace_root=storage
            )
            self.assertEqual(index["field_access_map"], {})

    def test_sanitize_binding_rejects_invalid_var_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "bogus",
                        "var_key": "1",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_rejects_missing_var_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "param",
                        "var_key": "",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_rejects_non_positive_param_ordinal(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "param",
                        "var_key": "0",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_rejects_non_integer_local_offset(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "local",
                        "var_key": "not-an-offset",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_rejects_missing_type_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "param",
                        "var_key": "1",
                        "type_name": "",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_rejects_invalid_type_kind(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    _BINARY,
                    "0x401000",
                    {
                        "var_kind": "param",
                        "var_key": "1",
                        "type_name": "Mode",
                        "type_kind": "bogus",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_sanitize_binding_defaults_unparseable_pointer_level_to_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            result = save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": "not-a-number",
                },
                workspace_root=storage,
            )
            self.assertEqual(result["entry"]["pointer_level"], 0)

    def test_save_typed_var_binding_rejects_missing_binary_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            with self.assertRaises(ValueError):
                save_typed_var_binding(
                    "",
                    "0x401000",
                    {
                        "var_kind": "param",
                        "var_key": "1",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    },
                    workspace_root=storage,
                )

    def test_signature_changes_when_bindings_change(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            empty_sig = typed_var_binding_signature(
                _BINARY, func_addr="0x401000", workspace_root=storage
            )
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )
            after_sig = typed_var_binding_signature(
                _BINARY, func_addr="0x401000", workspace_root=storage
            )
            self.assertNotEqual(empty_sig, after_sig)

    def test_cascade_delete_on_type_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            _seed_definitions(storage)
            save_typed_var_binding(
                _BINARY,
                "0x401000",
                {
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": 0,
                },
                workspace_root=storage,
            )
            self.assertEqual(
                len(
                    list_typed_var_bindings(_BINARY, workspace_root=storage)["entries"]
                ),
                1,
            )
            StructDb(storage).replace_definitions(_BINARY, "manual", {})
            self.assertEqual(
                len(
                    list_typed_var_bindings(_BINARY, workspace_root=storage)["entries"]
                ),
                0,
            )


class TestFormatTypedVarBinding(unittest.TestCase):
    def test_formats_pointer_to_struct(self):
        self.assertEqual(
            format_typed_var_binding(
                {"type_name": "Widget", "type_kind": "struct", "pointer_level": 1}
            ),
            "Widget *",
        )

    def test_formats_double_pointer(self):
        self.assertEqual(
            format_typed_var_binding(
                {"type_name": "Widget", "type_kind": "struct", "pointer_level": 2}
            ),
            "Widget **",
        )

    def test_formats_bare_enum(self):
        self.assertEqual(
            format_typed_var_binding(
                {"type_name": "Mode", "type_kind": "enum", "pointer_level": 0}
            ),
            "Mode",
        )

    def test_empty_type_name_yields_empty_string(self):
        self.assertEqual(format_typed_var_binding({"type_name": ""}), "")
        self.assertEqual(format_typed_var_binding({}), "")


if __name__ == "__main__":
    unittest.main()
