# SPDX-License-Identifier: AGPL-3.0-only
"""Tests pour backends.static.binary.headers."""

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.binary.headers import _build_packer_analysis, extract_binary_info
from backends.static.tests.util import compile_minimal_elf

try:
    import lief as _lief

    _LIEF_AVAILABLE = True
except ImportError:
    _LIEF_AVAILABLE = False


@unittest.skipUnless(_LIEF_AVAILABLE, "lief not installed")
class TestExtractBinaryInfo(unittest.TestCase):
    """Tests de extract_binary_info avec lief."""

    def test_real_binary(self):
        """Teste l'extraction d'infos sur un vrai binaire."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")

            info = extract_binary_info(str(binary))
            self.assertIsInstance(info, dict)
            self.assertIn("format", info)
            self.assertIn("machine", info)
            self.assertIn("entry", info)
            self.assertIn("bits", info)
            self.assertIn("arch", info)
            self.assertIn("endianness", info)
            self.assertIn("packer_analysis", info)
            self.assertNotIn("error", info)

            # Vérifier que les valeurs sont non vides
            self.assertTrue(info["format"])
            self.assertTrue(info["machine"])
            self.assertTrue(info["entry"])
            self.assertIn(info["bits"], ["32", "64"])
            self.assertIn("summary", info["packer_analysis"])

    def test_hash_fields_present(self):
        """extract_binary_info() retourne md5 et sha256."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary = compile_minimal_elf(tmp_path)
            if not binary:
                self.skipTest("gcc non disponible")
            info = extract_binary_info(str(binary))
            self.assertIn("md5", info)
            self.assertIn("sha256", info)
            self.assertRegex(info["md5"], r"^[0-9a-f]{32}$")
            self.assertRegex(info["sha256"], r"^[0-9a-f]{64}$")

    def test_pe_binary_info(self):
        """Vérifie que extract_binary_info() fonctionne sur un PE64 minimal."""
        import os

        sys.path.insert(0, str(Path(__file__).resolve().parent))
        from fixtures.pe_fixture import write_minimal_pe64

        with tempfile.NamedTemporaryFile(suffix=".exe", delete=False) as f:
            pe_path = f.name
        try:
            write_minimal_pe64(pe_path)
            result = extract_binary_info(pe_path)
            self.assertNotIn("error", result, result.get("error", ""))
            self.assertIn(
                "PE", result.get("format", ""), f"format={result.get('format')}"
            )
            self.assertEqual(result.get("bits"), "64")
            self.assertIn("x86", result.get("arch", ""), f"arch={result.get('arch')}")
            entry = result.get("entry", "")
            self.assertTrue(entry.startswith("0x"), f"entry={entry}")
            self.assertRegex(result.get("md5", ""), r"^[0-9a-f]{32}$")
            self.assertRegex(result.get("sha256", ""), r"^[0-9a-f]{64}$")
            # imphash peut être vide pour un PE sans imports
            self.assertIn("imphash", result)
        finally:
            os.unlink(pe_path)


class TestPackerAnalysis(unittest.TestCase):
    """Tests unitaires des heuristiques packer légères."""

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    def test_packer_analysis_flags_upx_like_binary(
        self,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        mock_sections.return_value = [
            {
                "name": "UPX0",
                "type": "DATA",
                "size": 4096,
                "size_hex": "0x1000",
                "offset": 512,
            },
            {
                "name": "UPX1",
                "type": "TEXT",
                "size": 8192,
                "size_hex": "0x2000",
                "offset": 4608,
            },
        ]
        mock_entropy.return_value = {
            "global": 7.48,
            "sections": [
                {"name": "UPX0", "entropy": 7.91, "offset_hex": "0x200"},
                {"name": "UPX1", "entropy": 7.63, "offset_hex": "0x1200"},
            ],
            "high_entropy_regions": [],
            "error": None,
        }
        mock_regions.return_value = [{"offset_hex": "0x1200", "entropy": 7.63}]
        mock_imports.return_value = {
            "imports": [
                {
                    "dll": "kernel32.dll",
                    "functions": ["LoadLibraryA", "GetProcAddress", "VirtualProtect"],
                },
            ]
        }
        mock_resources.return_value = {"applicable": True, "count": 0, "resources": []}

        analysis = _build_packer_analysis("/tmp/fake-packed.exe", "PE AMD64")
        self.assertEqual(analysis["verdict"], "high")
        self.assertGreaterEqual(analysis["score"], 55)
        self.assertIn("Suspicion forte", analysis["summary"])
        self.assertEqual(analysis["suspected_family"], "UPX")
        self.assertIn("UPX probable", analysis["summary"])
        self.assertTrue(any(family["name"] == "UPX" for family in analysis["families"]))
        self.assertGreaterEqual(len(analysis["suspicious_sections"]), 2)
        self.assertTrue(
            any(
                signal["kind"] == "dynamic_resolution" for signal in analysis["signals"]
            )
        )

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    def test_packer_analysis_stays_quiet_on_clean_layout(
        self,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        mock_sections.return_value = [
            {
                "name": ".text",
                "type": "TEXT",
                "size": 12288,
                "size_hex": "0x3000",
                "offset": 1024,
            },
            {
                "name": ".data",
                "type": "DATA",
                "size": 2048,
                "size_hex": "0x800",
                "offset": 13312,
            },
        ]
        mock_entropy.return_value = {
            "global": 5.31,
            "sections": [
                {"name": ".text", "entropy": 5.78, "offset_hex": "0x400"},
                {"name": ".data", "entropy": 3.21, "offset_hex": "0x3400"},
            ],
            "high_entropy_regions": [],
            "error": None,
        }
        mock_regions.return_value = []
        mock_imports.return_value = {
            "imports": [
                {
                    "dll": "kernel32.dll",
                    "functions": [
                        "CreateFileW",
                        "ReadFile",
                        "CloseHandle",
                        "ExitProcess",
                    ],
                },
                {
                    "dll": "user32.dll",
                    "functions": [
                        "MessageBoxW",
                        "DispatchMessageW",
                        "GetMessageW",
                        "TranslateMessage",
                        "PeekMessageW",
                    ],
                },
            ]
        }
        mock_resources.return_value = {
            "applicable": True,
            "count": 1,
            "resources": [{"type": "RT_VERSION", "size": 512}],
        }

        analysis = _build_packer_analysis("/tmp/fake-clean.exe", "PE AMD64")
        self.assertEqual(analysis["verdict"], "none")
        self.assertLess(analysis["score"], 10)
        self.assertIsNone(analysis["suspected_family"])
        self.assertEqual(analysis["suspicious_sections"], [])
        self.assertIn("Pas d'indice fort", analysis["summary"])

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    def test_packer_analysis_downranks_entropy_only_gui_binary(
        self,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        mock_sections.return_value = [
            {
                "name": ".text",
                "type": "TEXT",
                "size": 65536,
                "size_hex": "0x10000",
                "offset": 1024,
            },
            {
                "name": ".rdata",
                "type": "DATA",
                "size": 8192,
                "size_hex": "0x2000",
                "offset": 66560,
            },
        ]
        mock_entropy.return_value = {
            "global": 6.95,
            "sections": [
                {"name": ".text", "entropy": 7.11, "offset_hex": "0x400"},
                {"name": ".rdata", "entropy": 5.10, "offset_hex": "0x10400"},
            ],
            "high_entropy_regions": [],
            "error": None,
        }
        mock_regions.return_value = []
        many_imports = [
            "CreateFileW",
            "ReadFile",
            "WriteFile",
            "CloseHandle",
            "ExitProcess",
            "GetMessageW",
            "DispatchMessageW",
            "TranslateMessage",
            "PeekMessageW",
            "DefWindowProcW",
            "RegOpenKeyExW",
            "RegQueryValueExW",
            "HeapAlloc",
            "HeapFree",
            "GetLastError",
            "SetWindowTextW",
            "ShowWindow",
            "UpdateWindow",
            "CreateWindowExW",
            "LoadIconW",
        ]
        mock_imports.return_value = {
            "imports": [
                {"dll": "kernel32.dll", "functions": many_imports[:10]},
                {"dll": "user32.dll", "functions": many_imports[10:]},
            ]
        }
        mock_resources.return_value = {
            "applicable": True,
            "count": 2,
            "resources": [
                {"type": "RT_VERSION", "size": 1024},
                {"type": "RT_GROUP_ICON", "size": 2048},
            ],
        }

        analysis = _build_packer_analysis("/tmp/fake-gui.exe", "PE AMD64")
        self.assertLess(analysis["score"], 30)
        self.assertNotEqual(analysis["verdict"], "high")
        self.assertTrue(
            any(
                signal["kind"] == "benign_layout_bias" for signal in analysis["signals"]
            )
        )

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    @patch("backends.static.binary.headers._scan_with_yara")
    def test_packer_analysis_yara_match_adds_signal_and_boosts_family(
        self,
        mock_yara,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        """YARA match → signal yara_signature + famille détectée même sans entropie élevée."""
        mock_yara.return_value = [{"rule": "UPX_PE_x86", "family": "UPX"}]
        mock_sections.return_value = []
        mock_entropy.return_value = {"global": 4.5, "sections": [], "error": None}
        mock_regions.return_value = []
        mock_imports.return_value = {"imports": []}
        mock_resources.return_value = {"applicable": False}

        analysis = _build_packer_analysis("/tmp/fake.exe", "PE AMD64")

        self.assertTrue(
            any(s["kind"] == "yara_signature" for s in analysis["signals"]),
            "Signal yara_signature absent",
        )
        self.assertEqual(analysis["suspected_family"], "UPX")
        self.assertGreaterEqual(analysis["score"], 30)
        self.assertIn("yara_matches", analysis)
        self.assertEqual(
            analysis["yara_matches"], [{"rule": "UPX_PE_x86", "family": "UPX"}]
        )
        self.assertNotEqual(
            analysis["verdict"], "none", "YARA match doit produire un verdict non-nul"
        )

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    @patch("backends.static.binary.headers._scan_with_yara")
    def test_packer_analysis_yara_unavailable_graceful(
        self,
        mock_yara,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        """Si _scan_with_yara retourne [] (yara absent), l'analyse continue normalement."""
        mock_yara.return_value = []
        mock_sections.return_value = []
        mock_entropy.return_value = {"global": 4.5, "sections": [], "error": None}
        mock_regions.return_value = []
        mock_imports.return_value = {"imports": []}
        mock_resources.return_value = {"applicable": False}

        analysis = _build_packer_analysis("/tmp/fake.exe", "PE AMD64")

        self.assertEqual(analysis["verdict"], "none")
        self.assertFalse(
            any(s["kind"] == "yara_signature" for s in analysis["signals"]),
            "Signal yara_signature ne doit pas apparaître",
        )
        self.assertEqual(analysis.get("yara_matches", []), [])

    @patch("backends.static.binary.headers.get_pe_resources")
    @patch("backends.static.binary.headers.analyze_imports")
    @patch("backends.static.binary.headers.high_entropy_regions")
    @patch("backends.static.binary.headers.entropy_of_file")
    @patch("backends.static.binary.headers.extract_sections")
    @patch("backends.static.binary.headers._scan_with_yara")
    def test_packer_analysis_yara_two_rules_same_family_single_score_bonus(
        self,
        mock_yara,
        mock_sections,
        mock_entropy,
        mock_regions,
        mock_imports,
        mock_resources,
    ):
        """Deux règles YARA pour la même famille → un seul bonus de score (+30), un seul signal."""
        mock_yara.return_value = [
            {"rule": "UPX_PE_x86", "family": "UPX"},
            {"rule": "UPX_PE_x64", "family": "UPX"},
        ]
        mock_sections.return_value = []
        mock_entropy.return_value = {"global": 4.5, "sections": [], "error": None}
        mock_regions.return_value = []
        mock_imports.return_value = {"imports": []}
        mock_resources.return_value = {"applicable": False}

        analysis = _build_packer_analysis("/tmp/fake.exe", "PE AMD64")

        yara_signals = [s for s in analysis["signals"] if s["kind"] == "yara_signature"]
        self.assertEqual(
            len(yara_signals), 1, "Un seul signal yara_signature par famille"
        )
        self.assertLessEqual(
            analysis["score"], 30, "Un seul bonus +30 pour deux règles UPX"
        )
        self.assertEqual(analysis["suspected_family"], "UPX")


if __name__ == "__main__":
    unittest.main()
