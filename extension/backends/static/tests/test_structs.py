# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_structs.py
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.structs import (
    compute_struct_layout,
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
            save_struct_source(
                """
                typedef struct Header {
                  uint32_t magic;
                  uint16_t count;
                } Header;
                """,
                workspace_root=tmp,
            )
            store = load_struct_store(tmp)
            self.assertIn("Header", store["definitions"])
            self.assertIn("typedef struct Header", store["source"])

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
            save_struct_source(source, workspace_root=tmp)
            store = load_struct_store(tmp)
        color = store["definitions"]["Color"]
        self.assertEqual(color["kind"], "enum")
        self.assertEqual(color["value_map"]["Blue"], 2)

    def test_roundtrip_fn_ptr_struct(self):
        source = """
        typedef struct Ops {
            int (*read)(void *buf, int len);
            int (*write)(const void *buf, int len);
        } Ops;
        """
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, workspace_root=tmp)
            store = load_struct_store(tmp)
        ops = store["definitions"]["Ops"]
        self.assertEqual(ops["fields"][0]["type_kind"], "fn_ptr")
        self.assertEqual(ops["fields"][1]["name"], "write")

    def test_roundtrip_multidim_array(self):
        source = "typedef struct M { float mat[4][4]; } M;"
        with tempfile.TemporaryDirectory() as tmp:
            save_struct_source(source, workspace_root=tmp)
            store = load_struct_store(tmp)
        field = store["definitions"]["M"]["fields"][0]
        self.assertEqual(field["array_dims"], [4, 4])
        self.assertEqual(field["array_len"], 16)

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


if __name__ == "__main__":
    unittest.main()
