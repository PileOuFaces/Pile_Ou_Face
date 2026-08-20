# SPDX-License-Identifier: AGPL-3.0-only
import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.annotations import AnnotationStore
from backends.static.annotations.canonical_import import (
    FORMAT,
    CanonicalImportError,
    import_canonical_document,
)
from backends.static.annotations.structs import load_struct_store, save_struct_source


class TestCanonicalImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.tmp.name, "sample.bin")
        with open(self.binary, "wb") as stream:
            stream.write(b"canonical import fixture")
        self.cache = os.path.join(self.tmp.name, "annotations.db")
        self.storage = os.path.join(self.tmp.name, "storage")
        fixture = os.path.join(
            os.path.dirname(__file__), "fixtures", "ghidra_canonical_v1.json"
        )
        with open(fixture, encoding="utf-8") as stream:
            self.document = json.load(stream)
        self.document["binary_sha256"] = hashlib.sha256(
            b"canonical import fixture"
        ).hexdigest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_imports_annotations_types_and_is_idempotent(self):
        first = import_canonical_document(
            self.binary,
            copy.deepcopy(self.document),
            cache_path=self.cache,
            workspace_root=self.storage,
        )
        self.assertEqual(first["annotations"]["imported"], 4)
        self.assertEqual(first["types"]["imported"], 2)
        self.assertEqual(first["types"]["skipped"], 1)
        with AnnotationStore(self.binary, cache_path=self.cache) as store:
            self.assertEqual(store.get_name("0x401000"), "main")
            self.assertEqual(store.get_comment("0x401010"), "check")
        self.assertIn(
            "Mode", load_struct_store(self.binary, self.storage)["definitions"]
        )

        second = import_canonical_document(
            self.binary,
            copy.deepcopy(self.document),
            cache_path=self.cache,
            workspace_root=self.storage,
        )
        self.assertEqual(second["annotations"]["imported"], 0)
        self.assertEqual(second["annotations"]["skipped"], 4)
        self.assertEqual(second["types"]["imported"], 0)
        self.assertEqual(second["types"]["skipped"], 3)

    def test_preserves_manual_conflicts(self):
        with AnnotationStore(self.binary, cache_path=self.cache) as store:
            store.rename("0x401000", "human_main")
        save_struct_source("enum Mode { HUMAN = 7 };", self.binary, self.storage)
        result = import_canonical_document(
            self.binary,
            copy.deepcopy(self.document),
            cache_path=self.cache,
            workspace_root=self.storage,
        )
        self.assertEqual(result["annotations"]["conflicts"], 1)
        self.assertEqual(result["types"]["conflicts"], 1)
        with AnnotationStore(self.binary, cache_path=self.cache) as store:
            self.assertEqual(store.get_name("0x401000"), "human_main")

    def test_manual_type_edit_after_import_remains_authoritative(self):
        import_canonical_document(
            self.binary,
            copy.deepcopy(self.document),
            cache_path=self.cache,
            workspace_root=self.storage,
        )
        save_struct_source("enum Mode { HUMAN = 7 };", self.binary, self.storage)
        changed = copy.deepcopy(self.document)
        changed["types"][0]["values"] = [{"name": "GHIDRA_NEW", "value": 2}]
        result = import_canonical_document(
            self.binary,
            changed,
            cache_path=self.cache,
            workspace_root=self.storage,
        )
        self.assertEqual(result["types"]["conflicts"], 1)
        values = load_struct_store(self.binary, self.storage)["definitions"]["Mode"][
            "value_map"
        ]
        self.assertEqual(values, {"HUMAN": 7})

    def test_refuses_hash_mismatch(self):
        document = copy.deepcopy(self.document)
        document["binary_sha256"] = "0" * 64
        with self.assertRaisesRegex(CanonicalImportError, "SHA-256"):
            import_canonical_document(self.binary, document, cache_path=self.cache)


if __name__ == "__main__":
    unittest.main()
