# SPDX-License-Identifier: AGPL-3.0-only
"""Tests du radar de priorisation des fonctions."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.analysis.function_radar import build_function_radar
from backends.static.cache.cache import DisasmCache


class TestFunctionRadar(unittest.TestCase):
    def test_returns_error_for_missing_binary(self):
        result = build_function_radar("/tmp/does-not-exist.bin")
        self.assertEqual(result["error"], "Fichier introuvable")
        self.assertEqual(result["summary"]["function_count"], 0)

    def test_prioritizes_functions_with_entry_imports_strings_and_annotations(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            binary_path = tmp_path / "sample.bin"
            cache_db = tmp_path / "sample.pfdb"
            binary_path.write_bytes(b"\x90" * 128)

            with DisasmCache(str(cache_db)) as cache:
                cache.save_disasm(
                    str(binary_path),
                    [
                        {"addr": "0x401000", "line": 1, "text": "call 0x401030"},
                        {"addr": "0x401010", "line": 2, "text": "call 0x401050"},
                        {"addr": "0x401030", "line": 3, "text": "nop"},
                        {"addr": "0x401050", "line": 4, "text": "call 0x402000"},
                    ],
                )
                cache.save_symbols(
                    str(binary_path),
                    [
                        {
                            "name": "entry",
                            "addr": "0x401000",
                            "type": "T",
                            "size": 0x30,
                        },
                        {
                            "name": "decrypt_config",
                            "addr": "0x401030",
                            "type": "T",
                            "size": 0x20,
                        },
                        {
                            "name": "sendBeacon",
                            "addr": "0x401050",
                            "type": "T",
                            "size": 0x20,
                        },
                        {
                            "name": "connect",
                            "addr": "0x402000",
                            "type": "U",
                            "size": None,
                        },
                    ],
                )
                cache.save_functions(
                    str(binary_path),
                    [
                        {
                            "addr": "0x401000",
                            "name": "entry",
                            "confidence": "confirmed",
                            "reason": "entrypoint",
                            "size": 0x30,
                        },
                        {
                            "addr": "0x401030",
                            "name": "decrypt_config",
                            "confidence": "high",
                            "reason": "call_target",
                            "size": 0x20,
                        },
                        {
                            "addr": "0x401050",
                            "name": "sendBeacon",
                            "confidence": "high",
                            "reason": "call_target",
                            "size": 0x20,
                        },
                    ],
                )
                cache.save_cfg(
                    str(binary_path),
                    {
                        "blocks": [
                            {
                                "addr": "0x401000",
                                "lines": [
                                    {"addr": "0x401000", "text": "call 0x401030"}
                                ],
                                "successors": ["0x401010"],
                            },
                            {
                                "addr": "0x401010",
                                "lines": [
                                    {"addr": "0x401010", "text": "call 0x401050"}
                                ],
                                "successors": [],
                            },
                            {
                                "addr": "0x401030",
                                "lines": [{"addr": "0x401030", "text": "nop"}],
                                "successors": [],
                            },
                            {
                                "addr": "0x401050",
                                "lines": [
                                    {"addr": "0x401050", "text": "call 0x402000"}
                                ],
                                "successors": [],
                            },
                        ],
                        "edges": [
                            {"from": "0x401000", "to": "0x401030", "type": "call"},
                            {"from": "0x401010", "to": "0x401050", "type": "call"},
                            {"from": "0x401050", "to": "0x402000", "type": "call"},
                        ],
                    },
                )
                cache.save_xref_map(
                    str(binary_path),
                    {
                        "0x500000": [
                            {
                                "from_addr": "0x401050",
                                "from_line": 4,
                                "text": "lea rax, [0x500000]",
                                "type": "lea",
                            }
                        ]
                    },
                )
                cache.save_imports_analysis(
                    str(binary_path),
                    {
                        "imports": [
                            {"dll": "ws2_32.dll", "functions": ["connect"], "count": 1}
                        ],
                        "suspicious": [
                            {
                                "function": "connect",
                                "dll": "ws2_32.dll",
                                "category": "NETWORK",
                                "description": "Connexion TCP/UDP à un serveur distant",
                            }
                        ],
                        "score": 25,
                        "error": None,
                    },
                )
                cache.save_strings(
                    str(binary_path),
                    [
                        {
                            "addr": "0x500000",
                            "value": "https://c2.example/api",
                            "length": 22,
                        }
                    ],
                )
                cache.save_annotation(
                    str(binary_path), "0x401030", "comment", "decrypt routine"
                )

            with patch(
                "backends.static.analysis.function_radar.build_analysis_index"
            ) as mocked_index:
                mocked_index.return_value = {"binary": str(binary_path)}
                result = build_function_radar(
                    str(binary_path), cache_db=str(cache_db), hotspot_limit=6
                )

            self.assertIsNone(result["error"])
            self.assertGreaterEqual(result["summary"]["function_count"], 3)
            self.assertTrue(result["hotspots"])
            self.assertTrue(result["entry_candidates"])
            self.assertTrue(result["proof_dossiers"])

            by_addr = {entry["addr"]: entry for entry in result["functions"]}
            entry_fn = by_addr["0x401000"]
            decrypt_fn = by_addr["0x401030"]
            beacon_fn = by_addr["0x401050"]

            self.assertEqual(entry_fn["priority_level"], "high")
            self.assertIn("Entrée probable du binaire", entry_fn["reasons"])
            self.assertTrue(
                any(
                    item["label"] == "Entrypoint"
                    for item in entry_fn["score_breakdown"]
                )
            )

            self.assertGreaterEqual(decrypt_fn["annotation_count"], 1)
            self.assertTrue(
                any("annotee" in reason for reason in decrypt_fn["reasons"])
            )
            self.assertEqual(decrypt_fn["review_status"], "in_progress")
            self.assertTrue(
                any(
                    item["label"] == "Contexte analyste"
                    for item in decrypt_fn["score_breakdown"]
                )
            )

            self.assertIn("Reseau", beacon_fn["import_categories"])
            self.assertTrue(beacon_fn["string_signals"])
            self.assertIn("Reseau", beacon_fn["signal_tags"])
            self.assertGreater(beacon_fn["priority_score"], 40)
            self.assertEqual(beacon_fn["review_status"], "unreviewed")
            self.assertIn("callsites", beacon_fn["import_signals"][0])
            self.assertEqual(beacon_fn["import_signals"][0]["target_addr"], "0x402000")
            self.assertEqual(beacon_fn["string_signals"][0]["length"], 22)
            self.assertEqual(beacon_fn["confidence"], "HIGH")
            self.assertTrue(beacon_fn["needs_review"])
            self.assertTrue(beacon_fn["proof_dossiers"])
            self.assertEqual(beacon_fn["proof_dossiers"][0]["kind"], "FUNCTION_RADAR")
            self.assertTrue(beacon_fn["proof_dossiers"][0]["evidence"])
            self.assertTrue(
                any(
                    item["label"] == "Appels sensibles"
                    for item in beacon_fn["score_breakdown"]
                )
            )


if __name__ == "__main__":
    unittest.main()
