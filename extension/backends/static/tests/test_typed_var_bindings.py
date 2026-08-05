# SPDX-License-Identifier: AGPL-3.0-only
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.typed_var_bindings import (
    build_typed_var_binding_index,
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


if __name__ == "__main__":
    unittest.main()
