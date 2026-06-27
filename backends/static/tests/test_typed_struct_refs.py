# SPDX-License-Identifier: AGPL-3.0-only
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.typed_struct_refs import (
    build_typed_struct_index,
    collect_typed_struct_hints,
    list_typed_struct_refs,
    save_typed_struct_ref,
    typed_struct_signature,
)


class TestTypedStructRefs(unittest.TestCase):
    def test_save_and_index_struct_ref(self):
        applied_struct = {
            "name": "Demo",
            "addr": "0x402000",
            "section": ".data",
            "offset": 0,
            "size": 8,
            "align": 4,
            "fields": [
                {
                    "field_name": "magic",
                    "field_type": "uint32_t",
                    "offset": 0,
                    "absolute_offset": 0,
                    "addr": "0x402000",
                    "size": 4,
                },
                {
                    "field_name": "count",
                    "field_type": "uint16_t",
                    "offset": 4,
                    "absolute_offset": 4,
                    "addr": "0x402004",
                    "size": 2,
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            save_typed_struct_ref("/tmp/demo.bin", applied_struct, workspace_root=tmp)
            listed = list_typed_struct_refs("/tmp/demo.bin", workspace_root=tmp)
            self.assertEqual(len(listed["entries"]), 1)
            index = build_typed_struct_index("/tmp/demo.bin", workspace_root=tmp)
            self.assertEqual(index["exact_by_addr"]["0x402000"]["label"], "Demo.magic")
            self.assertEqual(index["exact_by_addr"]["0x402004"]["label"], "Demo.count")
            hints = collect_typed_struct_hints(index, ["0x402004"])
            self.assertEqual(hints[0]["field_name"], "count")
            self.assertTrue(typed_struct_signature("/tmp/demo.bin", workspace_root=tmp))
