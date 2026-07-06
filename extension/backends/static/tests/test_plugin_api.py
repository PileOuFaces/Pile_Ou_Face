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

    def test_all_symbols_in_module(self):
        """Importing from plugin_api must expose all expected symbols."""
        mod = importlib.import_module("backends.plugin_api")
        for name in [
            "get_logger",
            "configure_logging",
            "build_offset_to_vaddr",
            "ArchInfo",
            "detect_binary_arch_from_path",
            "get_feature_support",
            "get_raw_arch_info",
        ]:
            self.assertTrue(hasattr(mod, name), f"Missing: {name}")


if __name__ == "__main__":
    unittest.main()
