# SPDX-License-Identifier: AGPL-3.0-only
import os
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.struct_db import (
    MAX_DEFINITIONS,
    MAX_FIELDS_PER_REF,
    MAX_TYPED_VAR_BINDINGS,
    MAX_TYPED_VAR_BINDINGS_PER_FUNCTION,
    StructDb,
    get_struct_db_path,
)


class TestStructDb(unittest.TestCase):
    def test_path_uses_explicit_root_then_storage_environment(self):
        with tempfile.TemporaryDirectory() as tmp:
            explicit = os.path.join(tmp, "explicit")
            storage = os.path.join(tmp, "storage")
            with patch.dict(os.environ, {"POF_STORAGE_DIR": storage}):
                self.assertEqual(
                    get_struct_db_path(), os.path.join(storage, "types.db")
                )
                self.assertEqual(
                    get_struct_db_path(explicit), os.path.join(explicit, "types.db")
                )

    def test_empty_read_has_no_side_effect_then_write_creates_normalized_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            self.assertEqual(
                database.load_definitions("/tmp/a.bin"),
                {"source": "", "definitions": {}},
            )
            self.assertEqual(database.list_typed_refs(), [])
            self.assertFalse(os.path.exists(database.path))
            database.replace_definitions("/tmp/a.bin", "", {})
            with sqlite3.connect(database.path) as connection:
                tables = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    )
                }
            self.assertTrue(
                {
                    "definitions",
                    "definition_fields",
                    "enum_values",
                    "typed_refs",
                    "typed_ref_fields",
                }
                <= tables
            )

    def test_definitions_round_trip_and_replace(self):
        definitions = {
            "Header": {
                "name": "Header",
                "kind": "struct",
                "fields": [
                    {
                        "name": "matrix",
                        "type": "uint8_t",
                        "type_kind": "primitive",
                        "pointer_level": 0,
                        "array_len": 6,
                        "array_dims": [2, 3],
                        "display_type": "uint8_t[2][3]",
                    }
                ],
            },
            "Mode": {
                "name": "Mode",
                "kind": "enum",
                "values": [{"name": "OFF", "value": 0}, {"name": "ON", "value": 1}],
                "value_map": {"OFF": 0, "ON": 1},
            },
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "first", definitions)
            self.assertEqual(
                database.load_definitions("/tmp/a.bin"),
                {"source": "first", "definitions": definitions},
            )
            database.replace_definitions("/tmp/a.bin", "", {})
            self.assertEqual(
                database.load_definitions("/tmp/a.bin"),
                {"source": "", "definitions": {}},
            )

    def test_invalid_replace_rolls_back_existing_definitions(self):
        original = {"One": {"name": "One", "kind": "enum", "values": []}}
        too_many = {
            f"Type{index}": {"name": f"Type{index}", "kind": "enum", "values": []}
            for index in range(MAX_DEFINITIONS + 1)
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "original", original)
            with self.assertRaisesRegex(ValueError, "Trop de types"):
                database.replace_definitions("/tmp/a.bin", "invalid", too_many)
            self.assertEqual(
                database.load_definitions("/tmp/a.bin")["source"], "original"
            )

    def test_typed_ref_upsert_replaces_fields_and_filters_binary(self):
        entry = {
            "binary": "/tmp/a.bin",
            "name": "Header",
            "kind": "struct",
            "addr": "0x1000",
            "section": ".data",
            "offset": 0,
            "size": 8,
            "align": 4,
            "fields": [self._field("magic", "0x1000")],
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.save_typed_ref(entry)
            entry["fields"] = [self._field("count", "0x1004")]
            database.save_typed_ref(entry)
            database.save_typed_ref({**entry, "binary": "/tmp/b.bin"})
            selected = database.list_typed_refs("/tmp/a.bin")
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]["fields"][0]["field_name"], "count")
            self.assertEqual(len(database.list_typed_refs()), 2)

    def test_typed_ref_field_limit_preserves_previous_value(self):
        entry = {
            "binary": "/tmp/a.bin",
            "name": "Header",
            "kind": "struct",
            "addr": "0x1000",
            "section": "",
            "offset": 0,
            "size": 4,
            "align": 4,
            "fields": [self._field("valid", "0x1000")],
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.save_typed_ref(entry)
            invalid = {
                **entry,
                "fields": [
                    self._field(str(i), "") for i in range(MAX_FIELDS_PER_REF + 1)
                ],
            }
            with self.assertRaisesRegex(ValueError, "Trop de champs appliqués"):
                database.save_typed_ref(invalid)
            self.assertEqual(
                database.list_typed_refs()[0]["fields"][0]["field_name"], "valid"
            )

    def test_typed_var_binding_upsert_and_binary_isolation(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions(
                "/tmp/a.bin",
                "manual",
                {"Mode": {"kind": "enum", "values": [{"name": "ON", "value": 1}]}},
            )
            database.replace_definitions(
                "/tmp/b.bin",
                "manual",
                {"Mode": {"kind": "enum", "values": [{"name": "ON", "value": 1}]}},
            )
            entry = {
                "binary": "/tmp/a.bin",
                "func_addr": "0x1000",
                "var_kind": "param",
                "var_key": "1",
                "type_name": "Mode",
                "type_kind": "enum",
                "pointer_level": 0,
            }
            database.save_typed_var_binding(entry)
            database.save_typed_var_binding({**entry, "pointer_level": 1})
            database.save_typed_var_binding({**entry, "binary": "/tmp/b.bin"})

            selected = database.list_typed_var_bindings("/tmp/a.bin")
            self.assertEqual(len(selected), 1)
            self.assertEqual(selected[0]["pointer_level"], 1)
            self.assertEqual(len(database.list_typed_var_bindings()), 2)

    def test_typed_var_binding_per_function_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions(
                "/tmp/a.bin",
                "manual",
                {"Mode": {"kind": "enum", "values": [{"name": "ON", "value": 1}]}},
            )
            for i in range(1, MAX_TYPED_VAR_BINDINGS_PER_FUNCTION + 1):
                database.save_typed_var_binding(
                    {
                        "binary": "/tmp/a.bin",
                        "func_addr": "0x1000",
                        "var_kind": "param",
                        "var_key": str(i),
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    }
                )
            with self.assertRaisesRegex(ValueError, "limite de"):
                database.save_typed_var_binding(
                    {
                        "binary": "/tmp/a.bin",
                        "func_addr": "0x1000",
                        "var_kind": "param",
                        "var_key": str(MAX_TYPED_VAR_BINDINGS_PER_FUNCTION + 1),
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    }
                )
            self.assertEqual(
                len(database.list_typed_var_bindings("/tmp/a.bin", "0x1000")),
                MAX_TYPED_VAR_BINDINGS_PER_FUNCTION,
            )

    def test_typed_var_binding_global_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions(
                "/tmp/a.bin",
                "manual",
                {"Mode": {"kind": "enum", "values": [{"name": "ON", "value": 1}]}},
            )
            for i in range(MAX_TYPED_VAR_BINDINGS):
                database.save_typed_var_binding(
                    {
                        "binary": "/tmp/a.bin",
                        "func_addr": hex(0x401000 + i),
                        "var_kind": "param",
                        "var_key": "1",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    }
                )
            with self.assertRaisesRegex(ValueError, "limite de"):
                database.save_typed_var_binding(
                    {
                        "binary": "/tmp/a.bin",
                        "func_addr": hex(0x401000 + MAX_TYPED_VAR_BINDINGS),
                        "var_kind": "param",
                        "var_key": "1",
                        "type_name": "Mode",
                        "type_kind": "enum",
                        "pointer_level": 0,
                    }
                )
            self.assertEqual(
                len(database.list_typed_var_bindings()), MAX_TYPED_VAR_BINDINGS
            )

    def test_typed_var_binding_cascade_delete_on_type_removal(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions(
                "/tmp/a.bin",
                "manual",
                {"Mode": {"kind": "enum", "values": [{"name": "ON", "value": 1}]}},
            )
            database.save_typed_var_binding(
                {
                    "binary": "/tmp/a.bin",
                    "func_addr": "0x1000",
                    "var_kind": "param",
                    "var_key": "1",
                    "type_name": "Mode",
                    "type_kind": "enum",
                    "pointer_level": 0,
                }
            )
            self.assertEqual(len(database.list_typed_var_bindings()), 1)
            database.replace_definitions("/tmp/a.bin", "manual", {})
            self.assertEqual(len(database.list_typed_var_bindings()), 0)

    def test_workspaces_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = StructDb(os.path.join(tmp, "first"))
            second = StructDb(os.path.join(tmp, "second"))
            first.replace_definitions("/tmp/a.bin", "one", {})
            self.assertEqual(second.load_definitions("/tmp/a.bin")["source"], "")
            self.assertNotEqual(first.path, second.path)

    def test_definitions_are_isolated_by_binary_in_one_workspace(self):
        first = {"First": {"name": "First", "kind": "enum", "values": []}}
        second = {"Second": {"name": "Second", "kind": "enum", "values": []}}
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "first", first)
            database.replace_definitions("/tmp/b.bin", "second", second)

            self.assertEqual(
                set(database.load_definitions("/tmp/a.bin")["definitions"]),
                {"First"},
            )
            self.assertEqual(
                set(database.load_definitions("/tmp/b.bin")["definitions"]),
                {"Second"},
            )

    def test_merge_definitions_upserts_without_wiping_existing_catalog(self):
        original = {"One": {"name": "One", "kind": "enum", "values": []}}
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "original", original)
            database.merge_definitions(
                "/tmp/a.bin",
                {"Two": {"name": "Two", "kind": "enum", "values": []}},
                "ai-import",
            )
            stored = database.load_definitions("/tmp/a.bin")["definitions"]
            self.assertEqual(set(stored), {"One", "Two"})

    def test_merge_definitions_overwrites_only_named_entries(self):
        original = {
            "One": {
                "name": "One",
                "kind": "enum",
                "values": [{"name": "A", "value": 0}],
            },
            "Two": {"name": "Two", "kind": "enum", "values": []},
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "original", original)
            database.merge_definitions(
                "/tmp/a.bin",
                {
                    "One": {
                        "name": "One",
                        "kind": "enum",
                        "values": [{"name": "B", "value": 1}],
                    }
                },
                "ai-import",
            )
            stored = database.load_definitions("/tmp/a.bin")["definitions"]
            self.assertEqual(stored["One"]["values"][0]["name"], "B")
            self.assertEqual(stored["Two"]["kind"], "enum")

    def test_merge_definitions_respects_max_definitions_limit(self):
        original = {"One": {"name": "One", "kind": "enum", "values": []}}
        too_many = {
            f"Type{index}": {"name": f"Type{index}", "kind": "enum", "values": []}
            for index in range(MAX_DEFINITIONS)
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("/tmp/a.bin", "original", original)
            with self.assertRaisesRegex(ValueError, "Trop de types"):
                database.merge_definitions("/tmp/a.bin", too_many, "ai-import")
            self.assertEqual(
                set(database.load_definitions("/tmp/a.bin")["definitions"]), {"One"}
            )

    def test_merge_definitions_noop_on_empty_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.merge_definitions("/tmp/a.bin", {}, "ai-import")
            self.assertFalse(os.path.exists(database.path))

    def test_merge_definitions_requires_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            with self.assertRaises(ValueError):
                database.merge_definitions(
                    "",
                    {"One": {"name": "One", "kind": "enum", "values": []}},
                    "ai-import",
                )

    @staticmethod
    def _field(name: str, addr: str) -> dict[str, object]:
        return {
            "field_name": name,
            "field_type": "uint32_t",
            "offset": 0,
            "absolute_offset": 0,
            "addr": addr,
            "tag": "u32",
            "size": 4,
        }


if __name__ == "__main__":
    unittest.main()
