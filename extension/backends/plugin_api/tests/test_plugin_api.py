# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for backends.plugin_api — the stable import surface for plugins."""

import importlib
import logging
import unittest


class TestPluginApiImports(unittest.TestCase):
    """Every symbol plugins use must be importable from backends.plugin_api."""

    def test_get_logger_importable(self):
        from backends.plugin_api import get_logger

        logger = get_logger("test.plugin")
        self.assertIsInstance(logger, logging.Logger)

    def test_configure_logging_importable(self):
        from backends.plugin_api import configure_logging

        self.assertTrue(callable(configure_logging))

    def test_build_offset_to_vaddr_importable(self):
        from backends.plugin_api import build_offset_to_vaddr

        result = build_offset_to_vaddr("/nonexistent")
        self.assertIsInstance(result, dict)

    def test_arch_info_importable(self):
        from backends.plugin_api import ArchInfo

        self.assertTrue(hasattr(ArchInfo, "__dataclass_fields__"))

    def test_feature_support_importable(self):
        from backends.plugin_api import FeatureSupport

        self.assertTrue(hasattr(FeatureSupport, "__dataclass_fields__"))

    def test_detect_binary_arch_from_path_importable(self):
        from backends.plugin_api import detect_binary_arch_from_path

        result = detect_binary_arch_from_path("/nonexistent")
        self.assertIsNone(result)

    def test_get_feature_support_importable(self):
        from backends.plugin_api import get_feature_support

        self.assertTrue(callable(get_feature_support))

    def test_get_raw_arch_info_importable(self):
        from backends.plugin_api import get_raw_arch_info

        self.assertTrue(callable(get_raw_arch_info))

    def test_request_ai_followup_builds_versioned_envelope(self):
        from backends.plugin_api import request_ai_followup

        result = request_ai_followup(
            "Explain the suspicious decoder",
            {"function": "decode_config", "signals": ["xor-loop"]},
            "pof.malware-triage-pro.ai.deobfuscate",
        )

        self.assertEqual(
            result,
            {
                "ai_followup": {
                    "version": 1,
                    "prompt": "Explain the suspicious decoder",
                    "context": {"function": "decode_config", "signals": ["xor-loop"]},
                    "capability": "pof.malware-triage-pro.ai.deobfuscate",
                }
            },
        )

    def test_request_ai_followup_rejects_invalid_input(self):
        from backends.plugin_api import request_ai_followup

        with self.assertRaises(ValueError):
            request_ai_followup("", {}, "pof.demo.ai.summary")
        with self.assertRaises(ValueError):
            request_ai_followup("prompt", {}, "")
        with self.assertRaises(TypeError):
            request_ai_followup("prompt", [], "pof.demo.ai.summary")

    def test_all_declares_exact_symbol_set(self):
        """__all__ must contain exactly the expected stable symbols — no more, no less."""
        mod = importlib.import_module("backends.plugin_api")
        expected = {
            "get_logger",
            "configure_logging",
            "build_offset_to_vaddr",
            "ArchInfo",
            "FeatureSupport",
            "detect_binary_arch_from_path",
            "get_feature_support",
            "get_raw_arch_info",
            "AI_FOLLOWUP_VERSION",
            "request_ai_followup",
        }
        self.assertEqual(set(mod.__all__), expected)


if __name__ == "__main__":
    unittest.main()
