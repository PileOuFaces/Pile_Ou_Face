# SPDX-License-Identifier: AGPL-3.0-only
import hashlib
import os
import sys
import tempfile
import unittest

ROOT = os.path.normpath(os.path.join(os.path.dirname(__file__), "../../.."))
sys.path.insert(0, ROOT)

from backends.static.annotations.canonical_import import (
    CanonicalImportError,
    import_canonical_document,
)
from backends.static.annotations.idb_import import IdbImportError, extract_idb_document


class _Context:
    def __init__(self, value):
        self.value = value

    def __enter__(self):
        return self.value

    def __exit__(self, *_args):
        return None


class _Idc:
    def GetFunctionName(self, address):
        return {0x401000: "main", 0x401100: "worker"}[address]

    def Comment(self, address):
        return "regular" if address == 0x401000 else None

    def RptCmt(self, address):
        return "repeatable" if address == 0x401000 else "worker note"


class _IdaNalt:
    def __init__(self, digest):
        self.digest = digest

    def retrieve_input_file_sha256(self):
        return self.digest


class _Api:
    def __init__(self, digest):
        self.idc = _Idc()
        self.ida_nalt = _IdaNalt(digest)
        self.idautils = type(
            "IdaUtils", (), {"Functions": lambda _self: [0x401000, 0x401100]}
        )()


class _IdbModule:
    def __init__(self, digest):
        self.digest = digest

    def from_file(self, path):
        if not path.endswith((".idb", ".i64")):
            raise ValueError("bad database")
        return _Context(object())

    def IDAPython(self, _database):
        return _Api(self.digest)


class TestIdbImport(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.binary = os.path.join(self.tmp.name, "sample.bin")
        with open(self.binary, "wb") as stream:
            stream.write(b"idb fixture")
        self.digest = hashlib.sha256(b"idb fixture").digest()

    def tearDown(self):
        self.tmp.cleanup()

    def test_direct_parser_extracts_names_comments_and_stored_hash(self):
        document = extract_idb_document(
            "sample.i64", self.binary, idb_module=_IdbModule(self.digest)
        )
        self.assertEqual(document["binary_sha256"], self.digest.hex())
        self.assertEqual(document["source"]["tool"], "idb")
        self.assertEqual(document["functions"][0]["name"], "main")
        self.assertEqual(document["functions"][0]["comment"], "regular\nrepeatable")

    def test_direct_parser_hash_is_enforced_by_shared_importer(self):
        wrong = b"x" * 32
        document = extract_idb_document(
            "sample.idb", self.binary, idb_module=_IdbModule(wrong)
        )
        with self.assertRaises(CanonicalImportError):
            import_canonical_document(self.binary, document)

    def test_direct_parser_requires_embedded_hash(self):
        with self.assertRaisesRegex(IdbImportError, "empreinte SHA-256"):
            extract_idb_document("sample.idb", self.binary, idb_module=_IdbModule(b""))


if __name__ == "__main__":
    unittest.main()
