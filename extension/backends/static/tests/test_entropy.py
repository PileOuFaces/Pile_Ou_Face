# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.entropy."""

import math
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.entropy import (
    entropy_of_bytes,
    entropy_of_file,
    high_entropy_regions,
)


class TestEntropyOfBytes(unittest.TestCase):
    def test_zero_bytes_returns_zero(self):
        self.assertEqual(entropy_of_bytes(b""), 0.0)

    def test_uniform_single_byte_returns_zero(self):
        # Tous les bytes identiques → entropie 0
        self.assertEqual(entropy_of_bytes(b"\x00" * 100), 0.0)

    def test_two_symbols_equal_probability(self):
        # 50% \x00 + 50% \xff → entropie = 1.0 bit (base 2)
        data = b"\x00\xff" * 50
        result = entropy_of_bytes(data)
        self.assertAlmostEqual(result, 1.0, places=5)

    def test_max_entropy_random_like(self):
        # 256 bytes distincts → entropie maximale = 8.0
        data = bytes(range(256))
        result = entropy_of_bytes(data)
        self.assertAlmostEqual(result, 8.0, places=5)

    def test_high_entropy_compressed(self):
        # Données pseudo-aléatoires → entropie > 7.0
        import os

        data = os.urandom(4096)
        result = entropy_of_bytes(data)
        self.assertGreater(result, 6.5)

    def test_low_entropy_text(self):
        # Texte ASCII → entropie modérée (< 6.0 pour texte court)
        data = b"hello world " * 100
        result = entropy_of_bytes(data)
        self.assertLess(result, 6.0)
        self.assertGreater(result, 0.0)

    def test_returns_float(self):
        self.assertIsInstance(entropy_of_bytes(b"abc"), float)


class TestEntropyOfFile(unittest.TestCase):
    def _write_tmp(self, data: bytes) -> str:
        import tempfile
        import os

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        self._tmpfiles = getattr(self, "_tmpfiles", [])
        self._tmpfiles.append(f.name)
        return f.name

    def tearDown(self):
        import os

        for p in getattr(self, "_tmpfiles", []):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_nonexistent_returns_error(self):
        result = entropy_of_file("/nonexistent/file.bin")
        self.assertIn("error", result)

    def test_returns_global_entropy(self):
        path = self._write_tmp(bytes(range(256)) * 4)
        result = entropy_of_file(path)
        self.assertIn("global", result)
        self.assertIsInstance(result["global"], float)
        self.assertAlmostEqual(result["global"], 8.0, places=4)

    def test_returns_sections_list(self):
        # Test sur un ELF réel si disponible, sinon fichier plat
        import os

        elf_paths = ["/bin/ls", "/usr/bin/python3", "/bin/sh"]
        elf = next((p for p in elf_paths if os.path.exists(p)), None)
        if elf:
            result = entropy_of_file(elf)
            self.assertIn("sections", result)
            self.assertIsInstance(result["sections"], list)
        else:
            path = self._write_tmp(bytes(range(256)) * 4)
            result = entropy_of_file(path)
            self.assertIn("sections", result)


class TestHighEntropyRegions(unittest.TestCase):
    def _write_tmp(self, data: bytes) -> str:
        import tempfile
        import os

        f = tempfile.NamedTemporaryFile(delete=False)
        f.write(data)
        f.close()
        self._tmpfiles = getattr(self, "_tmpfiles", [])
        self._tmpfiles.append(f.name)
        return f.name

    def tearDown(self):
        import os

        for p in getattr(self, "_tmpfiles", []):
            try:
                os.unlink(p)
            except OSError:
                pass

    def test_uniform_data_no_high_entropy(self):
        path = self._write_tmp(b"\x00" * 2048)
        regions = high_entropy_regions(path, threshold=7.0, window=256)
        self.assertEqual(regions, [])

    def test_random_data_detected(self):
        import os

        path = self._write_tmp(b"\x00" * 512 + os.urandom(512) + b"\x00" * 512)
        regions = high_entropy_regions(path, threshold=7.0, window=256)
        self.assertGreater(len(regions), 0)
        region = regions[0]
        self.assertIn("offset", region)
        self.assertIn("entropy", region)
        self.assertGreaterEqual(region["entropy"], 7.0)


if __name__ == "__main__":
    unittest.main()
