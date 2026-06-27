# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.disasm.import_xrefs."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm.import_xrefs import find_callsites


class TestImportXrefs(unittest.TestCase):
    def test_find_callsites_uses_cached_xref_map(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / "sample.elf"
            binary.write_bytes(b"\x7fELF" + b"\x00" * 60)

            with DisasmCache(default_cache_path(str(binary))) as cache:
                cache.save_xref_map(
                    str(binary),
                    {
                        "0x401020": [
                            {
                                "from_addr": "0x401000",
                                "from_line": 12,
                                "text": "call 0x401020",
                                "type": "call",
                                "type_info": None,
                            }
                        ]
                    },
                )

            with (
                mock.patch(
                    "backends.static.disasm.import_xrefs._get_plt_addr",
                    return_value="0x401020",
                ),
                mock.patch("backends.static.disasm.import_xrefs._load_disasm_lines") as load_disasm,
            ):
                result = find_callsites(str(binary), "puts")

            load_disasm.assert_not_called()
            self.assertEqual(result["plt_addr"], "0x401020")
            self.assertEqual(result["callsites"][0]["addr"], "0x401000")
            self.assertEqual(result["callsites"][0]["line"], 12)


if __name__ == "__main__":
    unittest.main()
