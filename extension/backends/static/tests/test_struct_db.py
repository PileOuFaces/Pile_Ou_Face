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
                    get_struct_db_path(), os.path.join(storage, "structs.db")
                )
                self.assertEqual(
                    get_struct_db_path(explicit), os.path.join(explicit, "structs.db")
                )

    def test_empty_read_has_no_side_effect_then_write_creates_normalized_schema(self):
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            self.assertEqual(
                database.load_definitions(), {"source": "", "definitions": {}}
            )
            self.assertEqual(database.list_typed_refs(), [])
            self.assertFalse(os.path.exists(database.path))
            database.replace_definitions("", {})
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
            database.replace_definitions("first", definitions)
            self.assertEqual(
                database.load_definitions(),
                {"source": "first", "definitions": definitions},
            )
            database.replace_definitions("", {})
            self.assertEqual(
                database.load_definitions(), {"source": "", "definitions": {}}
            )

    def test_invalid_replace_rolls_back_existing_definitions(self):
        original = {"One": {"name": "One", "kind": "enum", "values": []}}
        too_many = {
            f"Type{index}": {"name": f"Type{index}", "kind": "enum", "values": []}
            for index in range(MAX_DEFINITIONS + 1)
        }
        with tempfile.TemporaryDirectory() as tmp:
            database = StructDb(tmp)
            database.replace_definitions("original", original)
            with self.assertRaisesRegex(ValueError, "Trop de types"):
                database.replace_definitions("invalid", too_many)
            self.assertEqual(database.load_definitions()["source"], "original")

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

    def test_workspaces_are_isolated(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = StructDb(os.path.join(tmp, "first"))
            second = StructDb(os.path.join(tmp, "second"))
            first.replace_definitions("one", {})
            self.assertEqual(second.load_definitions()["source"], "")
            self.assertNotEqual(first.path, second.path)

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
