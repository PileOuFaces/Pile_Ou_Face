# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.cache.cache."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.cache.cache import DisasmCache, compute_sha256, default_cache_path

SAMPLE_LINES = [
    {"addr": "0x401000", "line": 1, "text": "push rbp"},
    {"addr": "0x401001", "line": 2, "text": "mov rbp, rsp"},
    {"addr": "0x401004", "line": 3, "text": "ret"},
]


class TestComputeSha256(unittest.TestCase):
    def test_returns_64_char_hex(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"\x00" * 64)
            path = f.name
        h = compute_sha256(path)
        self.assertEqual(len(h), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in h))

    def test_same_content_same_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f:
            f.write(b"hello world")
            path = f.name
        h1 = compute_sha256(path)
        h2 = compute_sha256(path)
        self.assertEqual(h1, h2)

    def test_different_content_different_hash(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f1:
            f1.write(b"content A")
            p1 = f1.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as f2:
            f2.write(b"content B")
            p2 = f2.name
        self.assertNotEqual(compute_sha256(p1), compute_sha256(p2))


class TestDefaultCachePath(unittest.TestCase):
    def test_uses_workspace_cache_dir_when_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".pile-ou-face").mkdir()
            examples_dir = root / "examples"
            examples_dir.mkdir()
            binary_path = examples_dir / "demo.elf"
            binary_path.write_bytes(b"\x7fELF" + b"\x00" * 32)

            cache_path = Path(default_cache_path(str(binary_path)))

            self.assertTrue(str(cache_path).endswith(".pfdb"))
            self.assertEqual(
                cache_path.parent, (root / ".pile-ou-face" / "pfdb").resolve()
            )
            self.assertNotIn("/examples/.pfdb/", str(cache_path))

    def test_falls_back_to_local_pof_dir_when_workspace_cache_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary_path = root / "demo.elf"
            binary_path.write_bytes(b"\x7fELF" + b"\x00" * 32)

            with mock.patch(
                "backends.static.cache.cache._find_pof_dir", return_value=None
            ):
                cache_path = Path(default_cache_path(str(binary_path)))

            self.assertTrue(str(cache_path).endswith(".pfdb"))
            self.assertEqual(
                cache_path.parent, (root / ".pile-ou-face" / "pfdb").resolve()
            )
            self.assertTrue(cache_path.parent.exists())

    def test_uses_unique_cache_name_per_binary_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / ".pile-ou-face").mkdir()
            left = root / "a"
            right = root / "b"
            left.mkdir()
            right.mkdir()
            binary_a = left / "demo.elf"
            binary_b = right / "demo.elf"
            binary_a.write_bytes(b"\x7fELF" + b"\x00" * 32)
            binary_b.write_bytes(b"\x7fELF" + b"\x01" * 32)

            cache_a = default_cache_path(str(binary_a))
            cache_b = default_cache_path(str(binary_b))

            self.assertNotEqual(cache_a, cache_b)


class TestDisasmCacheBasic(unittest.TestCase):
    def setUp(self):
        # Fichier temporaire comme "binaire"
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        # Cache temporaire
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def _make_cache(self) -> DisasmCache:
        return DisasmCache(self._db_path)

    def test_cache_miss_on_empty(self):
        with self._make_cache() as cache:
            result = cache.get_disasm(self._binary_path)
        self.assertIsNone(result)

    def test_save_and_load(self):
        with self._make_cache() as cache:
            binary_id = cache.save_disasm(self._binary_path, SAMPLE_LINES)
            self.assertIsInstance(binary_id, int)
            result = cache.get_disasm(self._binary_path)
        self.assertIsNotNone(result)
        assert result is not None
        _, lines = result
        self.assertEqual(len(lines), len(SAMPLE_LINES))
        self.assertEqual(lines[0]["addr"], "0x401000")
        self.assertEqual(lines[0]["text"], "push rbp")

    def test_cache_hit_preserves_order(self):
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, SAMPLE_LINES)
            _, lines = cache.get_disasm(self._binary_path)  # type: ignore
        addrs = [ln["addr"] for ln in lines]
        self.assertEqual(addrs, ["0x401000", "0x401001", "0x401004"])

    def test_invalidation_on_binary_change(self):
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, SAMPLE_LINES)
        # Modifier le binaire
        with open(self._binary_path, "wb") as f:
            f.write(b"\x7fELF" + b"\xff" * 60)
        with self._make_cache() as cache:
            result = cache.get_disasm(self._binary_path)
        self.assertIsNone(result)

    def test_resave_replaces_old(self):
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, SAMPLE_LINES)
        new_lines = [{"addr": "0x401000", "line": 1, "text": "nop"}]
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, new_lines)
            _, lines = cache.get_disasm(self._binary_path)  # type: ignore
        self.assertEqual(len(lines), 1)
        self.assertEqual(lines[0]["text"], "nop")

    def test_explicit_invalidate(self):
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, SAMPLE_LINES)
            cache.invalidate(self._binary_path)
            result = cache.get_disasm(self._binary_path)
        self.assertIsNone(result)

    def test_context_manager(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(self._binary_path, SAMPLE_LINES)
        # Rouvrir et vérifier
        with DisasmCache(self._db_path) as cache:
            result = cache.get_disasm(self._binary_path)
        self.assertIsNotNone(result)

    def test_structured_disasm_fields_roundtrip(self):
        lines = [
            {
                "addr": "0x401000",
                "line": 1,
                "text": "55                   push     rbp",
                "bytes": "55",
                "mnemonic": "push",
                "operands": "rbp",
            }
        ]
        with self._make_cache() as cache:
            cache.save_disasm(self._binary_path, lines)
            _, cached_lines = cache.get_disasm(self._binary_path)  # type: ignore
        self.assertEqual(cached_lines[0]["bytes"], "55")
        self.assertEqual(cached_lines[0]["mnemonic"], "push")
        self.assertEqual(cached_lines[0]["operands"], "rbp")


class TestDisasmCacheSymbols(unittest.TestCase):
    """Tests pour save_symbols / get_symbols."""

    SAMPLE_SYMBOLS = [
        {"name": "_main", "addr": "0x401000", "type": "T"},
        {"name": "_puts", "addr": "0x401100", "type": "U"},
    ]

    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def test_symbols_miss_on_empty(self):
        with DisasmCache(self._db_path) as cache:
            result = cache.get_symbols(self._binary_path)
        self.assertIsNone(result)

    def test_save_and_load_symbols(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_symbols(self._binary_path, self.SAMPLE_SYMBOLS)
            result = cache.get_symbols(self._binary_path)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["name"], "_main")
        self.assertEqual(result[0]["type"], "T")

    def test_symbols_independent_of_disasm(self):
        """Sauvegarder des symboles ne détruit pas le désassemblage existant."""
        disasm_lines = [{"addr": "0x401000", "line": 1, "text": "push rbp"}]
        with DisasmCache(self._db_path) as cache:
            cache.save_disasm(self._binary_path, disasm_lines)
            cache.save_symbols(self._binary_path, self.SAMPLE_SYMBOLS)
            disasm_result = cache.get_disasm(self._binary_path)
            sym_result = cache.get_symbols(self._binary_path)
        self.assertIsNotNone(disasm_result)
        self.assertIsNotNone(sym_result)

    def test_resave_symbols_replaces(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_symbols(self._binary_path, self.SAMPLE_SYMBOLS)
            cache.save_symbols(
                self._binary_path, [{"name": "_foo", "addr": "0x402000", "type": "T"}]
            )
            result = cache.get_symbols(self._binary_path)
        self.assertEqual(len(result), 1)  # type: ignore
        self.assertEqual(result[0]["name"], "_foo")  # type: ignore


class TestDisasmCacheStrings(unittest.TestCase):
    """Tests pour save_strings / get_strings."""

    SAMPLE_STRINGS = [
        {"addr": "0x402000", "value": "hello", "length": 5},
        {"addr": "0x402010", "value": "world", "length": 5},
    ]

    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def test_strings_miss_on_empty(self):
        with DisasmCache(self._db_path) as cache:
            result = cache.get_strings(self._binary_path)
        self.assertIsNone(result)

    def test_save_and_load_strings(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_strings(self._binary_path, self.SAMPLE_STRINGS)
            result = cache.get_strings(self._binary_path)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(len(result), 2)
        self.assertEqual(result[0]["value"], "hello")
        self.assertEqual(result[0]["length"], 5)

    def test_get_strings_for_addresses_loads_only_requested_rows(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_strings(self._binary_path, self.SAMPLE_STRINGS)
            result = cache.get_strings_for_addresses(
                self._binary_path, {"0x402010", "0x404000"}
            )
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x402010")
        self.assertEqual(result[0]["value"], "world")


class TestDisasmCacheAnnotations(unittest.TestCase):
    """Tests pour save_annotation / get_annotations / delete_annotation."""

    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def test_no_annotations_returns_empty(self):
        with DisasmCache(self._db_path) as cache:
            result = cache.get_annotations(self._binary_path)
        self.assertEqual(result, [])

    def test_save_and_get_annotation(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_annotation(
                self._binary_path, "0x401000", "comment", "entry point"
            )
            result = cache.get_annotations(self._binary_path)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["addr"], "0x401000")
        self.assertEqual(result[0]["kind"], "comment")
        self.assertEqual(result[0]["value"], "entry point")

    def test_filter_by_addr(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_annotation(self._binary_path, "0x401000", "comment", "A")
            cache.save_annotation(self._binary_path, "0x401010", "comment", "B")
            result = cache.get_annotations(self._binary_path, addr="0x401000")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "A")

    def test_replace_annotation_same_kind(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_annotation(self._binary_path, "0x401000", "rename", "old_name")
            cache.save_annotation(self._binary_path, "0x401000", "rename", "new_name")
            result = cache.get_annotations(self._binary_path, addr="0x401000")
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["value"], "new_name")

    def test_delete_annotation(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_annotation(self._binary_path, "0x401000", "comment", "test")
            deleted = cache.delete_annotation(
                self._binary_path, "0x401000", kind="comment"
            )
            result = cache.get_annotations(self._binary_path)
        self.assertEqual(deleted, 1)
        self.assertEqual(result, [])

    def test_delete_all_annotations_for_addr(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_annotation(self._binary_path, "0x401000", "comment", "c")
            cache.save_annotation(self._binary_path, "0x401000", "rename", "r")
            deleted = cache.delete_annotation(self._binary_path, "0x401000")
            result = cache.get_annotations(self._binary_path, addr="0x401000")
        self.assertEqual(deleted, 2)
        self.assertEqual(result, [])


class TestDisasmCacheAnalysisArtifacts(unittest.TestCase):
    SAMPLE_FUNCTIONS = [
        {
            "addr": "0x401000",
            "name": "main",
            "confidence": "high",
            "reason": "symbol",
            "size": 24,
        }
    ]
    SAMPLE_CFG = {
        "blocks": [
            {
                "addr": "0x401000",
                "lines": [{"addr": "0x401000", "text": "call 0x401020", "line": 1}],
                "successors": ["0x401020", "0x401005"],
                "is_call": True,
                "is_switch": False,
                "switch_cases": [],
            }
        ],
        "edges": [
            {"from": "0x401000", "to": "0x401020", "type": "call"},
            {"from": "0x401000", "to": "0x401005", "type": "fallthrough"},
        ],
    }
    SAMPLE_FUNC_CFG = {
        "func_addr": "0x401000",
        "blocks": [
            {
                "addr": "0x401000",
                "lines": [{"addr": "0x401000", "text": "ret", "line": 1}],
                "successors": [],
                "is_call": False,
                "is_switch": False,
                "switch_cases": [],
            }
        ],
        "edges": [],
    }
    SAMPLE_XREF_MAP = {
        "0x401020": [
            {
                "from_addr": "0x401000",
                "from_line": 1,
                "text": "call 0x401020",
                "type": "call",
                "type_info": None,
            }
        ]
    }
    SAMPLE_IMPORTS = {
        "imports": [{"dll": "libc.so.6", "functions": ["puts", "printf"], "count": 2}],
        "suspicious": [
            {
                "function": "system",
                "dll": "libc.so.6",
                "category": "EXECUTION",
                "description": "shell",
            }
        ],
        "score": 10,
        "error": None,
    }
    SAMPLE_STACK = {
        "func_addr": "0x401000",
        "frame_size": 32,
        "vars": [{"name": "var_8", "offset": -8, "size": 8, "source": "auto"}],
        "args": [{"name": "arg_0", "offset": 16, "size": 8, "source": "auto"}],
    }

    def setUp(self):
        self._bin_file = tempfile.NamedTemporaryFile(delete=False, suffix=".elf")
        self._bin_file.write(b"\x7fELF" + b"\x00" * 60)
        self._bin_file.flush()
        self._binary_path = self._bin_file.name
        self._db_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb")
        self._db_path = self._db_file.name
        self._db_file.close()

    def tearDown(self):
        self._bin_file.close()
        Path(self._binary_path).unlink(missing_ok=True)
        Path(self._db_path).unlink(missing_ok=True)

    def test_save_and_load_functions(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_functions(self._binary_path, self.SAMPLE_FUNCTIONS)
            result = cache.get_functions(self._binary_path)
        self.assertEqual(result, self.SAMPLE_FUNCTIONS)

    def test_save_and_load_cfg(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_cfg(self._binary_path, self.SAMPLE_CFG)
            result = cache.get_cfg(self._binary_path)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["blocks"][0]["addr"], "0x401000")
        self.assertTrue(any(edge["type"] == "call" for edge in result["edges"]))

    def test_save_and_load_function_scoped_cfg(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_cfg(self._binary_path, self.SAMPLE_FUNC_CFG)
            result = cache.get_cfg(self._binary_path, func_addr="0x401000")
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["func_addr"], "0x401000")
        self.assertEqual(len(result["blocks"]), 1)

    def test_save_and_load_xref_map(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_xref_map(self._binary_path, self.SAMPLE_XREF_MAP)
            result = cache.get_xref_map(self._binary_path)
        self.assertEqual(result, self.SAMPLE_XREF_MAP)

    def test_save_and_load_imports_analysis(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_imports_analysis(self._binary_path, self.SAMPLE_IMPORTS)
            result = cache.get_imports_analysis(self._binary_path)
        self.assertIsNotNone(result)
        assert result is not None
        self.assertEqual(result["imports"][0]["dll"], "libc.so.6")
        self.assertEqual(result["imports"][0]["functions"], ["printf", "puts"])
        self.assertEqual(result["score"], 10)

    def test_save_and_load_stack_frame(self):
        with DisasmCache(self._db_path) as cache:
            cache.save_stack_frame(self._binary_path, self.SAMPLE_STACK)
            result = cache.get_stack_frame(self._binary_path, "0x401000")
        self.assertEqual(result, self.SAMPLE_STACK)


if __name__ == "__main__":
    unittest.main()
