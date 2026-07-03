# SPDX-License-Identifier: AGPL-3.0-only
"""Host runtime minimal pour plugins Pile Ou Face."""

from .manifest import PluginManifest, PluginManifestError, load_plugin_manifest
from .registry import PluginRecord, build_plugin_registry, discover_plugin_dirs

__all__ = [
    "PluginContext",
    "PluginManifest",
    "PluginManifestError",
    "PluginRecord",
    "attach_plugins",
    "build_plugin_registry",
    "default_plugin_search_paths",
    "discover_plugin_dirs",
    "invoke_plugin_command",
    "invoke_plugin_feature",
    "load_plugin_manifest",
]


def __getattr__(name: str):
    if name in {
        "PluginContext",
        "attach_plugins",
        "default_plugin_search_paths",
        "invoke_plugin_command",
        "invoke_plugin_feature",
    }:
        from .runtime import (
            PluginContext,
            attach_plugins,
            default_plugin_search_paths,
            invoke_plugin_command,
            invoke_plugin_feature,
        )

        runtime_exports = {
            "PluginContext": PluginContext,
            "attach_plugins": attach_plugins,
            "default_plugin_search_paths": default_plugin_search_paths,
            "invoke_plugin_command": invoke_plugin_command,
            "invoke_plugin_feature": invoke_plugin_feature,
        }
        return runtime_exports[name]
    raise AttributeError(name)
