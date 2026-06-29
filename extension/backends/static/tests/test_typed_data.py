# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_typed_data.py
import json
import os
import subprocess
import sys
import tempfile
import unittest
from types import SimpleNamespace

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)
from backends.static.annotations.structs import parse_struct_definitions
from backends.static.annotations.typed_data import (
    _decode_struct_entries,
    _decode_struct_scalar,
    _detect_endian_and_ptr_size,
    _resolve_struct_location,
    _scan_pointers,
)
from backends.static.tests.fixtures.make_elf import make_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


def run_td(
    binary,
    section=None,
    type_=None,
    page=None,
    raw_base_addr=None,
    raw_arch=None,
    raw_endian=None,
):
    args = [
        sys.executable,
        "backends/static/annotations/typed_data.py",
        "--binary",
        binary,
    ]
    if section:
        args += ["--section", section]
    if type_:
        args += ["--type", type_]
    if page is not None:
        args += ["--page", str(page)]
    if raw_base_addr is not None:
        args += ["--raw-base-addr", str(raw_base_addr)]
    if raw_arch is not None:
        args += ["--raw-arch", str(raw_arch)]
    if raw_endian is not None:
        args += ["--raw-endian", str(raw_endian)]
    import os

    env = {**os.environ, "PYTHONPATH": ROOT}
    r = subprocess.run(args, capture_output=True, text=True, cwd=ROOT, env=env)
    return json.loads(r.stdout)


class TestTypedData(unittest.TestCase):
    def test_error_on_missing(self):
        result = run_td("/nonexistent")
        self.assertIsNotNone(result.get("error"))

    def test_lists_sections(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf)
            self.assertIn("sections", result)
            self.assertIsInstance(result["sections"], list)

    def test_u8_type_produces_entries(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf, type_="u8")
            self.assertIn("entries", result)
            self.assertIsInstance(result["entries"], list)
            if result["entries"]:
                entry = result["entries"][0]
                self.assertIn("offset", entry)
                self.assertIn("decoded", entry)
                self.assertIn("hex", entry)
                self.assertIn("addr", entry)

    def test_raw_blob_fallback_lists_raw_section_and_strings(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"\x00hello raw\x00\x01\x02")
            raw_path = f.name
        try:
            result = run_td(
                raw_path,
                section="raw",
                type_="str",
                raw_base_addr="0x417000",
                raw_arch="thumb",
                raw_endian="little",
            )
            self.assertIsNone(result.get("error"))
            self.assertEqual(result.get("source"), "raw")
            self.assertEqual(result.get("endianness"), "little")
            self.assertEqual(result.get("ptr_size"), 4)
            self.assertEqual(result.get("bits"), 32)
            self.assertEqual(result.get("arch"), "thumb")
            self.assertEqual(result.get("sections"), ["raw"])
            self.assertEqual(result.get("section"), "raw")
            self.assertEqual(result.get("base_addr"), "0x417000")
            self.assertTrue(
                any(
                    entry.get("decoded") == '"hello raw"'
                    for entry in result.get("entries", [])
                )
            )
            self.assertTrue(
                any(
                    entry.get("addr") == "0x417001"
                    for entry in result.get("entries", [])
                )
            )
        finally:
            os.unlink(raw_path)

    def test_raw_blob_fallback_uses_big_endian_profile_for_decoding(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(bytes.fromhex("00 00 00 01"))
            raw_path = f.name
        try:
            result = run_td(
                raw_path,
                section="raw",
                type_="u32",
                raw_base_addr="0x9000",
                raw_arch="mips32",
                raw_endian="big",
            )
            self.assertIsNone(result.get("error"))
            self.assertEqual(result.get("source"), "raw")
            self.assertEqual(result.get("base_addr"), "0x9000")
            self.assertEqual(result.get("arch"), "mips32")
            self.assertEqual(result.get("bits"), 32)
            self.assertEqual(result.get("ptr_size"), 4)
            self.assertEqual(result.get("endianness"), "big")
            self.assertEqual(result.get("entries", [])[0].get("decoded"), "1")
            self.assertEqual(result.get("entries", [])[0].get("addr"), "0x9000")
        finally:
            os.unlink(raw_path)

    def test_raw_blob_fallback_rejects_unknown_section(self):
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"abc")
            raw_path = f.name
        try:
            result = run_td(raw_path, section=".data", type_="u8")
            self.assertIsNotNone(result.get("error"))
            self.assertEqual(result.get("sections"), ["raw"])
        finally:
            os.unlink(raw_path)

    def test_output_has_pagination_fields_on_success(self):
        if not _LIEF_AVAILABLE:
            self.skipTest("lief non disponible")
        with tempfile.TemporaryDirectory() as tmp:
            elf = os.path.join(tmp, "test.elf")
            make_minimal_elf(elf)
            result = run_td(elf, page=0)
            if not result.get("error"):
                self.assertIn("page", result)
                self.assertIn("page_size", result)
                self.assertIn("total_entries", result)
                self.assertEqual(result.get("endianness"), "little")
                self.assertEqual(result.get("ptr_size"), 8)
                self.assertEqual(result.get("bits"), 64)
                self.assertTrue(result.get("arch"))

    def test_decode_struct_entries_renders_fields(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Demo {
              uint32_t magic;
              char name[4];
              uint16_t count;
            } Demo;
            """
        )
        data = bytes.fromhex("44 33 22 11 41 42 43 00 02 00 00 00")
        result = _decode_struct_entries(data, 0x401000, "Demo", 0, 8, definitions)
        self.assertEqual(result["name"], "Demo")
        self.assertEqual(result["fields"][0]["decoded"], "287454020")
        self.assertEqual(result["fields"][1]["decoded"], '"ABC"')
        self.assertEqual(result["fields"][2]["decoded"], "2")
        self.assertEqual(result["fields"][2]["addr"], "0x401008")

    def test_resolve_struct_location_from_vaddr(self):
        binary = SimpleNamespace(
            sections=[
                SimpleNamespace(
                    name=".text",
                    content=[0x90] * 16,
                    virtual_address=0x401000,
                    flags=0x4,
                ),
                SimpleNamespace(
                    name=".data", content=[0x00] * 32, virtual_address=0x402000, flags=0
                ),
            ]
        )
        section, offset = _resolve_struct_location(binary, None, 0, 0x40200C)
        self.assertEqual(section, ".data")
        self.assertEqual(offset, 0x0C)

    def test_resolve_struct_location_rejects_addr_outside_data_sections(self):
        binary = SimpleNamespace(
            sections=[
                SimpleNamespace(
                    name=".text",
                    content=[0x90] * 16,
                    virtual_address=0x401000,
                    flags=0x4,
                ),
                SimpleNamespace(
                    name=".data", content=[0x00] * 16, virtual_address=0x402000, flags=0
                ),
            ]
        )
        with self.assertRaises(ValueError):
            _resolve_struct_location(binary, None, 0, 0x403000)

    def test_decode_struct_entries_supports_enum_and_union(self):
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
        data = bytes.fromhex("02 00 00 00 41 42 43 00")
        result = _decode_struct_entries(data, 0x401000, "Packet", 0, 8, definitions)
        self.assertEqual(result["kind"], "struct")
        self.assertEqual(result["fields"][0]["decoded"], "MODE_READY (2)")
        self.assertEqual(result["fields"][0]["field_kind"], "enum")
        self.assertIn("union Payload", result["fields"][1]["decoded"])
        self.assertIn('text="ABC"', result["fields"][1]["decoded"])

    def test_decode_union_entries_reuses_same_address_for_members(self):
        definitions = parse_struct_definitions(
            """
            typedef union Payload {
              uint32_t raw;
              char text[4];
            } Payload;
            """
        )
        data = bytes.fromhex("41 42 43 00")
        result = _decode_struct_entries(data, 0x402000, "Payload", 0, 8, definitions)
        self.assertEqual(result["kind"], "union")
        self.assertEqual(result["fields"][0]["addr"], "0x402000")
        self.assertEqual(result["fields"][1]["addr"], "0x402000")

    def test_detect_endian_returns_defaults_for_none(self):
        endian, ptr_size = _detect_endian_and_ptr_size(None)
        self.assertEqual(endian, "little")
        self.assertEqual(ptr_size, 8)

    def test_decode_struct_scalar_big_endian_u32(self):
        # 0x00000001 in big-endian bytes
        data = bytes([0x00, 0x00, 0x00, 0x01])
        val_le, _ = _decode_struct_scalar(data, "u32", 4, "little")
        val_be, _ = _decode_struct_scalar(data, "u32", 4, "big")
        self.assertEqual(val_le, "16777216")  # 0x01000000
        self.assertEqual(val_be, "1")

    def test_decode_struct_scalar_big_endian_ptr(self):
        # pointer 0x00401000 in big-endian 4-byte form
        data = bytes([0x00, 0x40, 0x10, 0x00])
        val_be, tag = _decode_struct_scalar(data, "ptr", 4, "big")
        self.assertEqual(val_be, hex(0x00401000))
        self.assertEqual(tag, "ptr")

    def test_scan_pointers_big_endian(self):
        # 0x00001000 in big-endian 4-byte layout at offset 0
        data = bytes([0x00, 0x00, 0x10, 0x00])
        ptrs_be = _scan_pointers(data, 0, 0x20000, 4, "big")
        # big-endian: value is 0x1000 — equals lower bound, pointer is included
        self.assertTrue(any(v == 0x1000 for _, v in ptrs_be))
        ptrs_le = _scan_pointers(data, 0, 0x20000, 4, "little")
        # little-endian: value is 0x00100000 (different interpretation)
        self.assertFalse(any(v == 0x1000 for _, v in ptrs_le))

    def test_decode_struct_entries_big_endian(self):
        definitions = parse_struct_definitions(
            """
            typedef struct Header {
              uint32_t magic;
              uint16_t count;
            } Header;
            """
        )
        # magic = 0xDEADBEEF, count = 0x0002 in big-endian
        data = bytes.fromhex("DE AD BE EF 00 02 00 00")
        result = _decode_struct_entries(data, 0, "Header", 0, 4, definitions, "big")
        self.assertEqual(result["fields"][0]["decoded"], str(0xDEADBEEF))
        self.assertEqual(result["fields"][1]["decoded"], "2")


if __name__ == "__main__":
    unittest.main()
