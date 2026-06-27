# SPDX-License-Identifier: AGPL-3.0-only
"""Tests des règles YARA packer — synthétiques + ELF réel packé upx."""

import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.headers import _scan_with_yara
from backends.static.tests.util import compile_minimal_elf

try:
    import yara as _yara

    _YARA_AVAILABLE = True
except ImportError:
    _YARA_AVAILABLE = False


def _write_tmp(data: bytes, suffix: str = ".bin") -> Path:
    """Écrit data dans un fichier temporaire et retourne son Path."""
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(data)
        return Path(f.name)


@unittest.skipUnless(_YARA_AVAILABLE, "yara-python not installed")
class TestYaraRulesSynthetic(unittest.TestCase):
    """Vérifie chaque règle YARA sur des bytes synthétiques minimaux."""

    def _scan(self, data: bytes, suffix: str = ".bin") -> list[str]:
        """Scan et retourne les familles matchées."""
        p = _write_tmp(data, suffix)
        try:
            return [m["family"] for m in _scan_with_yara(str(p))]
        finally:
            p.unlink(missing_ok=True)

    def test_upx_elf_synthetic(self):
        """ELF magic + UPX0 section + UPX! marker → famille UPX."""
        data = b"\x7fELF" + b"\x00" * 100 + b"UPX0" + b"\x00" * 100 + b"UPX!" + b"\x00" * 8
        self.assertIn("UPX", self._scan(data))

    def test_upx_pe_x86_synthetic(self):
        """UPX! magic + pushad stub x86 + trailing bytes → famille UPX."""
        stub = bytes(
            [
                0x60,
                0xBE,
                0x00,
                0x10,
                0x40,
                0x00,  # pushad; mov esi, addr
                0x8D,
                0xBE,
                0x00,
                0xF0,
                0xFF,
                0xFF,  # lea edi, [esi+...]
                0x57,
                0x83,
                0xCD,
                0xFF,  # push edi; or ebp,-1
            ]
        )
        data = b"MZ" + b"\x00" * 200 + stub + b"\x00" * 200 + b"UPX!" + b"\x00" * 4
        self.assertIn("UPX", self._scan(data))

    def test_upx_pe_x64_synthetic(self):
        """UPX! magic + push-sequence x64 v3 stub → famille UPX."""
        stub = bytes([0x53, 0x56, 0x57, 0x55, 0x48, 0x81, 0xEC, 0x80, 0x01, 0x00, 0x00])
        data = b"MZ" + b"\x00" * 200 + stub + b"\x00" * 200 + b"UPX!" + b"\x00" * 4
        self.assertIn("UPX", self._scan(data))

    def test_aspack_synthetic(self):
        """ASPack EP stub + section name .aspack → famille ASPack."""
        stub = bytes([0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x58, 0x83, 0xE8, 0x05])
        data = b"MZ" + b"\x00" * 100 + stub + b"\x00" * 50 + b".aspack" + b"\x00" * 100
        self.assertIn("ASPack", self._scan(data))

    def test_mpress_sections_synthetic(self):
        """MPRESS sections .MPRESS1 + .MPRESS2 → famille MPRESS."""
        data = b"MZ" + b"\x00" * 100 + b".MPRESS1" + b"\x00" * 50 + b".MPRESS2" + b"\x00" * 100
        self.assertIn("MPRESS", self._scan(data))

    def test_petite_synthetic(self):
        """Petite EP stub + section name .petite → famille Petite."""
        stub = bytes(
            [
                0xB8,
                0x00,
                0x10,
                0x40,
                0x00,  # mov eax, addr
                0x68,
                0x00,
                0x20,
                0x40,
                0x00,  # push addr
                0x64,
                0xFF,
                0x35,
                0x00,
                0x00,
                0x00,
                0x00,  # push fs:[0]
            ]
        )
        data = b"MZ" + b"\x00" * 100 + stub + b"\x00" * 50 + b".petite" + b"\x00" * 100
        self.assertIn("Petite", self._scan(data))

    def test_pecompact_sections_synthetic(self):
        """PECompact EP stub + section name pec1 → famille PECompact."""
        ep_stub = bytes([0xEB, 0x06, 0x68, 0x00, 0x10, 0x40, 0x00, 0xC3])
        data = b"MZ" + b"\x00" * 100 + ep_stub + b"\x00" * 50 + b"pec1" + b"\x00" * 100
        self.assertIn("PECompact", self._scan(data))

    def test_no_match_on_clean_bytes(self):
        """Bytes propres (données basse entropie uniformes) → aucune famille."""
        data = b"MZ" + b"\x41" * 1024
        self.assertEqual(self._scan(data), [], f"Faux positif inattendu sur données uniformes")

    def test_no_match_on_empty_file(self):
        """Fichier vide → aucune famille."""
        self.assertEqual(self._scan(b""), [])


@unittest.skipUnless(_YARA_AVAILABLE, "yara-python not installed")
class TestYaraRulesRealBinary(unittest.TestCase):
    """Tests avec un vrai ELF packé par upx CLI (skip si upx absent)."""

    def test_upx_elf_real_packed_binary(self):
        """ELF x64 compilé + packé avec upx → règle UPX_ELF match."""
        if not shutil.which("upx"):
            self.skipTest("upx not installed")

        with tempfile.TemporaryDirectory() as tmp:
            elf = compile_minimal_elf(Path(tmp))
            if not elf:
                self.skipTest("gcc not available")

            packed = Path(tmp) / "packed.elf"
            r = subprocess.run(
                ["upx", "-q", "-o", str(packed), str(elf)],
                capture_output=True,
                timeout=30,
            )
            if r.returncode != 0:
                self.skipTest(f"upx failed: {r.stderr.decode(errors='replace')}")

            families = [m["family"] for m in _scan_with_yara(str(packed))]
            self.assertIn("UPX", families)

    def test_clean_elf_no_match(self):
        """ELF x64 non packé → aucune famille YARA."""
        with tempfile.TemporaryDirectory() as tmp:
            elf = compile_minimal_elf(Path(tmp))
            if not elf:
                self.skipTest("gcc not available")

            families = [m["family"] for m in _scan_with_yara(str(elf))]
            self.assertEqual(families, [], f"Faux positif sur ELF propre : {families}")


if __name__ == "__main__":
    unittest.main()
