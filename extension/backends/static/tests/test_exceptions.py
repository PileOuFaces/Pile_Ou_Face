# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.shared.exceptions — hiérarchie d'exceptions."""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.exceptions import (
    AnalysisError,
    BinaryError,
    BinaryNotFoundError,
    BinaryParseError,
    CacheCorruptedError,
    CacheError,
    CFGError,
    DisassemblyError,
    PileOuFaceError,
    XrefError,
)


class TestExceptionsHierarchy(unittest.TestCase):
    """Vérifie la hiérarchie d'héritage des exceptions."""

    def test_all_inherit_from_pile_ou_face_error(self):
        for cls in [
            BinaryError,
            BinaryNotFoundError,
            BinaryParseError,
            DisassemblyError,
            CacheError,
            CacheCorruptedError,
            AnalysisError,
            CFGError,
            XrefError,
        ]:
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, PileOuFaceError))

    def test_binary_hierarchy(self):
        self.assertTrue(issubclass(BinaryNotFoundError, BinaryError))
        self.assertTrue(issubclass(BinaryParseError, BinaryError))

    def test_cache_hierarchy(self):
        self.assertTrue(issubclass(CacheCorruptedError, CacheError))

    def test_analysis_hierarchy(self):
        self.assertTrue(issubclass(CFGError, AnalysisError))
        self.assertTrue(issubclass(XrefError, AnalysisError))

    def test_pile_ou_face_error_is_exception(self):
        self.assertTrue(issubclass(PileOuFaceError, Exception))


class TestExceptionsCanBeRaised(unittest.TestCase):
    """Vérifie que les exceptions peuvent être levées et attrapées."""

    def test_binary_not_found_raised_and_caught(self):
        with self.assertRaises(BinaryNotFoundError):
            raise BinaryNotFoundError("Binary not found: /no/such/file")

    def test_caught_as_base_class(self):
        with self.assertRaises(BinaryError):
            raise BinaryNotFoundError("not found")

    def test_caught_as_pile_ou_face_error(self):
        with self.assertRaises(PileOuFaceError):
            raise DisassemblyError("unsupported arch")

    def test_cache_corrupted_caught_as_cache_error(self):
        with self.assertRaises(CacheError):
            raise CacheCorruptedError("db corrupted")

    def test_exception_message_preserved(self):
        msg = "Binary not found: /tmp/test.elf"
        try:
            raise BinaryNotFoundError(msg)
        except BinaryNotFoundError as exc:
            self.assertEqual(str(exc), msg)

    def test_exception_chaining(self):
        original = OSError("file not found")
        try:
            raise BinaryNotFoundError("wrap") from original
        except BinaryNotFoundError as exc:
            self.assertIs(exc.__cause__, original)


class TestCacheExceptions(unittest.TestCase):
    """Vérifie que DisasmCache lève les bonnes exceptions."""

    def test_corrupted_db_raises_cache_corrupted_error(self):
        import tempfile

        from backends.static.cache.cache import DisasmCache

        # Créer un fichier SQLite corrompu
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pfdb") as f:
            f.write(b"not a sqlite database")
            corrupt_path = f.name
        try:
            with self.assertRaises(CacheCorruptedError):
                DisasmCache(corrupt_path)
        finally:
            Path(corrupt_path).unlink(missing_ok=True)


if __name__ == "__main__":
    unittest.main()
