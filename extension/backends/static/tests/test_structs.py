# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_structs.py
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.struct_db import get_struct_db_path
from backends.static.annotations.structs import (
    compute_struct_layout,
    import_type_definitions,
    list_struct_store,
    load_struct_store,
    parse_struct_definitions,
    save_struct_source,
)


class TestStructs(unittest.TestCase):
    def test_parse_typedef_struct_with_array(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint32_t magic;
              char name[8];
              uint16_t flags;
            } Demo;
            """
        )
        self.assertIn("Demo", definitions)
        self.assertEqual(len(definitions["Demo"]["fields"]), 3)
        self.assertEqual(definitions["Demo"]["fields"][1]["array_len"], 8)

    def test_compute_layout_with_padding(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint8_t tag;
              uint32_t value;
            } Demo;
            """
        )
        layout = compute_struct_layout(definitions, "Demo", 8)
        self.assertEqual(layout["fields"][0]["offset"], 0)
        self.assertEqual(layout["fields"][1]["offset"], 4)
        self.assertEqual(layout["size"], 8)

    def test_save_and_load_struct_store(self):
        with tempfile.TemporaryDirectory() as tmp:
            storage = os.path.join(tmp, "storage")
            save_struct_source(
                """
                typedef struct Header {
                  uint32_t magic;
                  uint16_t count;
                } Header;
                """,
                "/tmp/demo.bin",
                workspace_root=storage,
            )
            store = load_struct_store("/tmp/demo.bin", storage)
            self.assertIn("Header", store["definitions"])
            self.assertIn("typedef struct Header", store["source"])
            self.assertEqual(
                get_struct_db_path(storage), os.path.join(storage, "types.db")
            )
            self.assertTrue(os.path.isfile(os.path.join(storage, "types.db")))
            self.assertFalse(os.path.exists(os.path.join(tmp, ".pile-ou-face")))

    def test_parse_enum_and_union_definitions(self):
        definitions = parse_struct_definitions(
            """
            typedef enum Mode {
              MODE_NONE,
              MODE_READ = 1 << 0,
              MODE_WRITE = 1 << 1,
              MODE_RW = MODE_READ | MODE_WRITE
            } Mode;

            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;
            """
        )
        self.assertEqual(definitions["Mode"]["kind"], "enum")
        self.assertEqual(definitions["Mode"]["value_map"]["MODE_RW"], 3)
        self.assertEqual(definitions["Payload"]["kind"], "union")
        self.assertEqual(len(definitions["Payload"]["fields"]), 2)

    def test_parse_explicit_compound_field_kinds_and_qualifiers(self):
        definitions = parse_struct_definitions(
            """
            struct Child { uint32_t value; };
            union Choice { uint32_t number; char text[4]; };
            enum Mode { MODE_OFF, MODE_ON };
            struct Parent {
              const struct Child *child;
              volatile union Choice choice;
              enum Mode mode;
            };
            """
        )
        fields = definitions["Parent"]["fields"]
        self.assertEqual(
            [field["type_kind"] for field in fields], ["struct", "union", "enum"]
        )
        self.assertEqual(fields[0]["type"], "Child")

    def test_parse_enum_arithmetic_and_unary_expressions(self):
        definitions = parse_struct_definitions(
            """
            enum Numbers {
              NEG = -2,
              POS = +2,
              INV = ~0,
              SUM = POS + 3,
              DIFF = SUM - 1,
              PRODUCT = DIFF * 2,
              QUOTIENT = PRODUCT / 4,
              REMAINDER = PRODUCT % 3,
              MASKED = PRODUCT & 6,
              TOGGLED = MASKED ^ 3
            };
            """
        )
        values = definitions["Numbers"]["value_map"]
        self.assertEqual(values["NEG"], -2)
        self.assertEqual(values["QUOTIENT"], 2)
        self.assertEqual(values["TOGGLED"], 3)

    def test_rejects_unknown_enum_symbol_and_unsupported_source(self):
        with self.assertRaisesRegex(ValueError, "inconnu"):
            parse_struct_definitions("enum Broken { VALUE = UNKNOWN + 1 };")
        with self.assertRaisesRegex(ValueError, "Aucun type C reconnu"):
            parse_struct_definitions("int global_counter;")

    # ── C++ enum class ───────────────────────────────────────────────────────────

    def test_parse_enum_class(self):
        definitions = parse_struct_definitions("enum class Color { Red, Green, Blue };")
        self.assertIn("Color", definitions)
        self.assertEqual(definitions["Color"]["kind"], "enum")
        self.assertEqual(len(definitions["Color"]["values"]), 3)
        self.assertEqual(definitions["Color"]["value_map"]["Green"], 1)

    def test_parse_enum_class_with_underlying_type(self):
        definitions = parse_struct_definitions(
            "enum class Status : uint8_t { Ok = 0, Error = 1, Timeout = 2 };"
        )
        self.assertIn("Status", definitions)
        self.assertEqual(definitions["Status"]["kind"], "enum")
        self.assertEqual(definitions["Status"]["value_map"]["Error"], 1)
        self.assertEqual(definitions["Status"]["value_map"]["Timeout"], 2)

    def test_parse_typedef_enum_class_with_underlying_type(self):
        definitions = parse_struct_definitions(
            """
            typedef enum class Flags : uint32_t {
                None_ = 0,
                Read = 1 << 0,
                Write = 1 << 1,
                ReadWrite = Read | Write
            } Flags;
            """
        )
        self.assertIn("Flags", definitions)
        self.assertEqual(definitions["Flags"]["value_map"]["Write"], 2)
        self.assertEqual(definitions["Flags"]["value_map"]["ReadWrite"], 3)

    def test_parse_enum_class_in_struct_field(self):
        definitions = parse_struct_definitions(
            """
            enum class Mode { Off, On, Standby };
            typedef struct Device {
                Mode mode;
                uint32_t id;
            } Device;
            """
        )
        layout = compute_struct_layout(definitions, "Device", 8)
        self.assertEqual(layout["fields"][0]["type_kind"], "enum")
        self.assertEqual(layout["fields"][0]["offset"], 0)
        self.assertEqual(layout["fields"][1]["offset"], 4)

    # ── Multidimensional arrays ──────────────────────────────────────────────────

    def test_parse_multidim_array_2d(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Matrix {
                float data[4][4];
                int rows;
            } Matrix;
            """
        )
        self.assertIn("Matrix", definitions)
        field = definitions["Matrix"]["fields"][0]
        self.assertEqual(field["name"], "data")
        self.assertEqual(field["array_len"], 16)
        self.assertEqual(field["array_dims"], [4, 4])
        self.assertEqual(field["display_type"], "float[4][4]")

    def test_parse_multidim_array_3d(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Volume {
                uint8_t voxels[2][3][4];
            } Volume;
            """
        )
        field = definitions["Volume"]["fields"][0]
        self.assertEqual(field["array_len"], 24)  # 2*3*4
        self.assertEqual(field["array_dims"], [2, 3, 4])

    def test_compute_layout_multidim_array(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Grid {
                uint8_t cells[3][4];
                uint32_t tag;
            } Grid;
            """
        )
        layout = compute_struct_layout(definitions, "Grid", 8)
        cells = layout["fields"][0]
        self.assertEqual(cells["size"], 12)  # 3*4*1
        self.assertEqual(cells["array_dims"], [3, 4])
        self.assertEqual(cells["array_len"], 12)
        # tag is 4 bytes at aligned offset 12
        self.assertEqual(layout["fields"][1]["offset"], 12)
        self.assertEqual(layout["size"], 16)

    def test_compute_layout_multidim_float(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Transform {
                float mat[4][4];
            } Transform;
            """
        )
        layout = compute_struct_layout(definitions, "Transform", 8)
        self.assertEqual(layout["fields"][0]["size"], 64)  # 16 * 4 bytes
        self.assertEqual(layout["size"], 64)

    def test_1d_array_preserves_array_dims(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Buf {
                char data[16];
            } Buf;
            """
        )
        field = definitions["Buf"]["fields"][0]
        self.assertEqual(field["array_len"], 16)
        self.assertEqual(field["array_dims"], [16])
        self.assertEqual(field["display_type"], "char[16]")

    # ── Function pointers ────────────────────────────────────────────────────────

    def test_parse_function_pointer_field(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Handler {
                void *ctx;
                int (*on_event)(int type, void *data);
                void (*on_close)(void *ctx);
            } Handler;
            """
        )
        self.assertIn("Handler", definitions)
        self.assertEqual(len(definitions["Handler"]["fields"]), 3)
        fn_field = definitions["Handler"]["fields"][1]
        self.assertEqual(fn_field["name"], "on_event")
        self.assertEqual(fn_field["type_kind"], "fn_ptr")
        self.assertEqual(fn_field["pointer_level"], 1)
        self.assertEqual(fn_field["array_len"], None)
        self.assertIn("on_event", fn_field["display_type"])

    def test_compute_layout_function_pointers_64bit(self):
        definitions = parse_struct_definitions(
            """
            typedef struct VTable {
                void (*init)(void);
                int (*process)(const char *buf, int len);
                void (*destroy)(void);
            } VTable;
            """
        )
        layout = compute_struct_layout(definitions, "VTable", 8)
        for i, field in enumerate(layout["fields"]):
            self.assertEqual(field["size"], 8, f"field {i} size should be 8 on 64-bit")
        self.assertEqual(layout["size"], 24)

    def test_compute_layout_function_pointer_32bit(self):
        definitions = parse_struct_definitions(
            """
            typedef struct CB {
                void (*fn)(void);
                uint32_t tag;
            } CB;
            """
        )
        layout = compute_struct_layout(definitions, "CB", 4)
        self.assertEqual(layout["fields"][0]["size"], 4)
        self.assertEqual(layout["size"], 8)

    def test_function_pointer_tag_in_layout(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Ops {
                int (*run)(void);
            } Ops;
            """
        )
        layout = compute_struct_layout(definitions, "Ops", 8)
        self.assertEqual(layout["fields"][0]["tag"], "fn_ptr")

    def test_const_function_pointer_field(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Hooks {
                void (* const hook)(int);
            } Hooks;
            """
        )
        field = definitions["Hooks"]["fields"][0]
        self.assertEqual(field["name"], "hook")
        self.assertEqual(field["type_kind"], "fn_ptr")

    # ── enum struct (variante C++) ────────────────────────────────────────────────

    def test_parse_enum_struct(self):
        definitions = parse_struct_definitions(
            "enum struct Direction { North, South, East, West };"
        )
        self.assertIn("Direction", definitions)
        self.assertEqual(definitions["Direction"]["kind"], "enum")
        self.assertEqual(definitions["Direction"]["value_map"]["East"], 2)

    # ── Invariants champs scalaires ──────────────────────────────────────────────

    def test_scalar_field_has_no_array_dims(self):
        definitions = parse_struct_definitions("typedef struct S { uint32_t x; } S;")
        field = definitions["S"]["fields"][0]
        self.assertIsNone(field["array_len"])
        self.assertIsNone(field["array_dims"])

    def test_regular_pointer_tag_is_ptr_not_fn_ptr(self):
        definitions = parse_struct_definitions(
            "typedef struct S { void *buf; uint32_t len; } S;"
        )
        layout = compute_struct_layout(definitions, "S", 8)
        self.assertEqual(layout["fields"][0]["tag"], "ptr")
        self.assertNotEqual(layout["fields"][0]["tag"], "fn_ptr")

    def test_double_pointer_field(self):
        definitions = parse_struct_definitions(
            "typedef struct S { char **argv; int argc; } S;"
        )
        field = definitions["S"]["fields"][0]
        self.assertEqual(field["pointer_level"], 2)
        layout = compute_struct_layout(definitions, "S", 8)
        self.assertEqual(layout["fields"][0]["size"], 8)

    # ── Cas d'erreur — ce qui doit rejeter ──────────────────────────────────────

    def test_error_struct_without_name(self):
        with self.assertRaises(ValueError):
            parse_struct_definitions("struct { uint32_t x; };")

    def test_error_struct_without_fields(self):
        with self.assertRaises(ValueError):
            parse_struct_definitions("typedef struct Empty {} Empty;")

    def test_error_enum_without_members(self):
        with self.assertRaises(ValueError):
            parse_struct_definitions("typedef enum Empty {} Empty;")

    def test_error_bitfield_rejected(self):
        with self.assertRaises(ValueError):
            parse_struct_definitions(
                "typedef struct Bits { uint32_t flags : 3; } Bits;"
            )

    def test_error_field_missing_name(self):
        with self.assertRaises(ValueError):
            parse_struct_definitions("typedef struct S { int; } S;")

    def test_error_layout_unknown_type(self):
        definitions = parse_struct_definitions("typedef struct S { uint32_t x; } S;")
        with self.assertRaises(ValueError):
            compute_struct_layout(definitions, "DoesNotExist", 8)

    def test_error_layout_enum_cannot_be_applied_as_struct(self):
        definitions = parse_struct_definitions("enum Mode { OFF, ON };")
        with self.assertRaisesRegex(ValueError, "ne peut pas être appliqué"):
            compute_struct_layout(definitions, "Mode", 8)

    def test_pointer_sized_primitives_follow_target_architecture(self):
        definitions = parse_struct_definitions(
            "typedef struct Sizes { size_t size; uintptr_t address; } Sizes;"
        )
        layout = compute_struct_layout(definitions, "Sizes", 4)
        self.assertEqual([field["size"] for field in layout["fields"]], [4, 4])
        self.assertEqual(layout["size"], 8)

    def test_reused_nested_type_has_stable_cached_layout(self):
        definitions = parse_struct_definitions(
            """
            struct Child { uint32_t value; };
            struct Parent { struct Child first; struct Child second; };
            """
        )
        layout = compute_struct_layout(definitions, "Parent", 8)
        self.assertEqual([field["offset"] for field in layout["fields"]], [0, 4])

    def test_error_layout_unknown_field_type(self):
        definitions = parse_struct_definitions("typedef struct S { Phantom x; } S;")
        with self.assertRaises(ValueError):
            compute_struct_layout(definitions, "S", 8)

    def test_error_layout_recursive_struct(self):
        definitions = parse_struct_definitions(
            """
            typedef struct A { struct_B x; } A;
            typedef struct B { struct_A y; } B;
            """
        )
        # A references struct_B (unknown type) — should raise on compute
        with self.assertRaises(ValueError):
            compute_struct_layout(definitions, "A", 8)

    # ── Roundtrip save / load ────────────────────────────────────────────────────

    def test_roundtrip_enum_class(self):
        source = "enum class Color : uint8_t { Red = 0, Green = 1, Blue = 2 };"
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, "/tmp/demo.bin", workspace_root=tmp)
            store = load_struct_store("/tmp/demo.bin", tmp)
        color = store["definitions"]["Color"]
        self.assertEqual(color["kind"], "enum")
        self.assertEqual(color["value_map"]["Blue"], 2)

    def test_list_store_exposes_all_type_kinds_and_counts(self):
        source = """
        typedef struct Header { uint32_t magic; uint16_t count; } Header;
        typedef union Payload { uint32_t raw; char text[4]; } Payload;
        enum Mode { MODE_NONE, MODE_READ, MODE_WRITE };
        """
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, "/tmp/demo.bin", workspace_root=tmp)
            catalog = list_struct_store("/tmp/demo.bin", tmp)["structs"]

        by_name = {entry["name"]: entry for entry in catalog}
        self.assertEqual(by_name["Header"]["field_count"], 2)
        self.assertEqual(by_name["Payload"]["field_count"], 2)
        self.assertEqual(by_name["Mode"]["value_count"], 3)
        self.assertEqual(by_name["Mode"]["kind"], "enum")

    def test_roundtrip_fn_ptr_struct(self):
        source = """
        typedef struct Ops {
            int (*read)(void *buf, int len);
            int (*write)(const void *buf, int len);
        } Ops;
        """
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, "/tmp/demo.bin", workspace_root=tmp)
            store = load_struct_store("/tmp/demo.bin", tmp)
        ops = store["definitions"]["Ops"]
        self.assertEqual(ops["fields"][0]["type_kind"], "fn_ptr")
        self.assertEqual(ops["fields"][1]["name"], "write")

    def test_roundtrip_multidim_array(self):
        source = "typedef struct M { float mat[4][4]; } M;"
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, "/tmp/demo.bin", workspace_root=tmp)
            store = load_struct_store("/tmp/demo.bin", tmp)
        field = store["definitions"]["M"]["fields"][0]
        self.assertEqual(field["array_dims"], [4, 4])
        self.assertEqual(field["array_len"], 16)

    def test_type_catalogs_are_isolated_by_binary(self):
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source("struct Alpha { uint32_t value; };", "/tmp/a.bin", tmp)
            save_struct_source("struct Beta { uint32_t value; };", "/tmp/b.bin", tmp)

            self.assertEqual(
                [
                    item["name"]
                    for item in list_struct_store("/tmp/a.bin", tmp)["structs"]
                ],
                ["Alpha"],
            )
            self.assertEqual(
                [
                    item["name"]
                    for item in list_struct_store("/tmp/b.bin", tmp)["structs"]
                ],
                ["Beta"],
            )

    # ── Scénario mixte ───────────────────────────────────────────────────────────

    def test_mixed_fn_ptr_enum_class_multidim(self):
        """Struct réaliste combinant les 3 nouvelles fonctionnalités."""
        definitions = parse_struct_definitions(
            """
            enum class Mode : uint8_t { Idle = 0, Running = 1, Error = 2 };

            typedef struct Plugin {
                Mode state;
                uint8_t reserved[3];
                uint32_t version;
                float weights[2][4];
                int (*on_load)(void *ctx);
                void (*on_unload)(void);
            } Plugin;
            """
        )
        layout = compute_struct_layout(definitions, "Plugin", 8)
        fields = {f["name"]: f for f in layout["fields"]}

        self.assertEqual(fields["state"]["type_kind"], "enum")
        self.assertEqual(fields["state"]["offset"], 0)
        self.assertEqual(fields["state"]["size"], 4)

        self.assertEqual(fields["reserved"]["array_dims"], [3])
        self.assertEqual(fields["reserved"]["offset"], 4)

        self.assertEqual(fields["version"]["offset"], 8)

        self.assertEqual(fields["weights"]["array_dims"], [2, 4])
        self.assertEqual(fields["weights"]["size"], 32)  # 8 * 4 bytes

        self.assertEqual(fields["on_load"]["tag"], "fn_ptr")
        self.assertEqual(fields["on_load"]["size"], 8)
        self.assertEqual(fields["on_unload"]["tag"], "fn_ptr")

        # Total: state(4)+reserved(3+1pad)=8, version(4)+pad(4)=16,
        # weights(32)=48, on_load(8)=56, on_unload(8)=64
        self.assertEqual(layout["size"], 64)

    def test_compute_layout_with_nested_union_and_enum_alias(self):
        definitions = parse_struct_definitions(
            """
            typedef enum Mode {
              MODE_NONE,
              MODE_READY = 2
            } Mode;

            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;

            typedef struct Packet {
              Mode mode;
              Payload payload;
            } Packet;
            """
        )
        union_layout = compute_struct_layout(definitions, "Payload", 8)
        self.assertEqual(union_layout["kind"], "union")
        self.assertEqual(union_layout["size"], 4)
        self.assertTrue(all(field["offset"] == 0 for field in union_layout["fields"]))

        packet_layout = compute_struct_layout(definitions, "Packet", 8)
        self.assertEqual(packet_layout["fields"][0]["offset"], 0)
        self.assertEqual(packet_layout["fields"][0]["type_kind"], "enum")
        self.assertEqual(packet_layout["fields"][1]["offset"], 4)
        self.assertEqual(packet_layout["fields"][1]["type_kind"], "union")
        self.assertEqual(packet_layout["size"], 8)

    # ── Typedefs et prototypes (Lot 3, #129) ────────────────────────────────────

    def test_parse_simple_pointer_typedef(self):
        definitions = parse_struct_definitions("typedef char* PSTR;")
        self.assertIn("PSTR", definitions)
        self.assertEqual(definitions["PSTR"]["kind"], "typedef")
        self.assertEqual(definitions["PSTR"]["fields"][0]["type"], "char")
        self.assertEqual(definitions["PSTR"]["fields"][0]["pointer_level"], 1)

    def test_parse_typedef_alias_to_existing_struct(self):
        definitions = parse_struct_definitions(
            """
            struct Foo { uint32_t x; };
            typedef struct Foo Foo;
            """
        )
        self.assertEqual(definitions["Foo"]["kind"], "struct")
        layout = compute_struct_layout(definitions, "Foo", 8)
        self.assertEqual(layout["fields"][0]["name"], "x")

    def test_parse_typedef_function_pointer_as_function_kind(self):
        definitions = parse_struct_definitions("typedef void (*Callback)(int, void*);")
        self.assertIn("Callback", definitions)
        self.assertEqual(definitions["Callback"]["kind"], "function")

    def test_parse_bare_prototype_as_function_kind(self):
        definitions = parse_struct_definitions("int add(int a, int b);")
        self.assertIn("add", definitions)
        self.assertEqual(definitions["add"]["kind"], "function")
        self.assertEqual(len(definitions["add"]["fields"]), 3)  # ret + 2 params

    def test_compute_layout_resolves_typedef_indirection(self):
        definitions = parse_struct_definitions(
            """
            typedef char* PSTR;
            typedef struct Demo {
              uint32_t tag;
              PSTR name;
            } Demo;
            """
        )
        layout = compute_struct_layout(definitions, "Demo", 8)
        name_field = layout["fields"][1]
        self.assertEqual(name_field["offset"], 8)
        self.assertEqual(name_field["size"], 8)
        self.assertEqual(name_field["tag"], "ptr")

    def test_layout_rejects_typedef_not_pointing_to_struct(self):
        definitions = parse_struct_definitions("typedef char* PSTR;")
        with self.assertRaisesRegex(ValueError, "ne pointe pas vers un struct/union"):
            compute_struct_layout(definitions, "PSTR", 8)

    def test_import_type_definitions_merges_without_wiping_catalog(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = {
                "PSTR": {
                    "kind": "typedef",
                    "fields": [
                        {
                            "name": "",
                            "type": "char",
                            "type_kind": "primitive",
                            "pointer_level": 1,
                            "array_len": None,
                            "array_dims": None,
                            "display_type": "char*",
                        }
                    ],
                },
            }
            import_type_definitions(
                "/tmp/demo.bin", first, "ghidra", workspace_root=tmp
            )
            second = {
                "Color": {
                    "kind": "enum",
                    "values": [{"name": "RED", "value": 0}],
                    "value_map": {"RED": 0},
                },
            }
            result = import_type_definitions(
                "/tmp/demo.bin", second, "ai-proposal", workspace_root=tmp
            )
            names = {entry["name"] for entry in result["structs"]}
            self.assertEqual(names, {"PSTR", "Color"})

    def test_import_type_definitions_rejects_invalid_name(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                import_type_definitions(
                    "/tmp/demo.bin",
                    {"1Bad": {"kind": "typedef", "fields": []}},
                    "ai-proposal",
                    workspace_root=tmp,
                )

    def test_import_type_definitions_rejects_empty_source_label(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ValueError):
                import_type_definitions(
                    "/tmp/demo.bin",
                    {"Foo": {"kind": "typedef", "fields": []}},
                    "  ",
                    workspace_root=tmp,
                )


if __name__ == "__main__":
    unittest.main()
