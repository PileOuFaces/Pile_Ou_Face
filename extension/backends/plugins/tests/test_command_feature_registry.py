# SPDX-License-Identifier: AGPL-3.0-only
"""Generic contract tests for manifest-driven plugin command resolution.

The host must not know which plugins exist or snapshot their command ids.
These synthetic manifests exercise the public protocol accepted from any
compatible plugin while each plugin repository owns its concrete contracts.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backends.plugins.manifest import (
    PluginDistribution,
    PluginEntrypoints,
    PluginHostRequirements,
    PluginLicensing,
    PluginManifest,
    PluginPythonEntrypoint,
)
from backends.plugins.registry import PluginRecord
from backends.plugins.runtime import (
    HOST_API_VERSION,
    PluginContext,
    resolve_plugin_command_for_feature,
)

GENERIC_PLUGIN_CASES: list[tuple[str, list[tuple[str, str, list[str]]]]] = [
    (
        "example.analysis-one",
        [
            ("example.inspect.run", "inspect", ["inspect_legacy"]),
            ("example.report.run", "report", []),
        ],
    ),
    (
        "vendor.analysis-two",
        [("vendor.correlate.run", "correlate", ["correlate_legacy"])],
    ),
]


def _make_manifest(
    plugin_id: str, commands: list[tuple[str, str, list[str]]]
) -> PluginManifest:
    raw = {
        "id": plugin_id,
        "commands": [
            {"id": cid, "feature": feature, "aliases": aliases}
            for cid, feature, aliases in commands
        ],
    }
    return PluginManifest(
        plugin_id=plugin_id,
        name=plugin_id,
        version="0.1.0",
        kind="analysis-pack",
        host=PluginHostRequirements(api_version=HOST_API_VERSION),
        distribution=PluginDistribution(),
        licensing=PluginLicensing(),
        entrypoints=PluginEntrypoints(
            python=PluginPythonEntrypoint(module="plugin_main")
        ),
        capabilities={},
        dependencies={},
        manifest_path=Path("/dev/null"),
        root_path=Path("/dev/null"),
        raw=raw,
    )


def _make_record(plugin_id: str, manifest: PluginManifest) -> PluginRecord:
    return PluginRecord(
        plugin_id=plugin_id,
        state="active",
        root_path=Path("/dev/null"),
        manifest_path=Path("/dev/null"),
        manifest=manifest,
    )


def _make_context(command_ids: list[str]) -> PluginContext:
    context = PluginContext(
        host_version="0.1.0", api_version=HOST_API_VERSION, paths={}
    )
    for cid in command_ids:
        context.register_command(cid, lambda payload: {})
    return context


@pytest.fixture(
    params=GENERIC_PLUGIN_CASES, ids=[entry[0] for entry in GENERIC_PLUGIN_CASES]
)
def plugin_fixture(request):
    plugin_id, commands = request.param
    manifest = _make_manifest(plugin_id, commands)
    record = _make_record(plugin_id, manifest)
    context = _make_context([cid for cid, _feature, _aliases in commands])
    return plugin_id, commands, record, context


def test_every_manifest_feature_resolves_to_its_command(plugin_fixture):
    plugin_id, commands, record, context = plugin_fixture
    for command_id, feature, _aliases in commands:
        resolved = resolve_plugin_command_for_feature(context, [record], feature)
        assert resolved == command_id, (
            f"{plugin_id}: feature '{feature}' resolved to {resolved!r}, "
            f"expected {command_id!r}"
        )


def test_every_manifest_alias_resolves_to_its_command(plugin_fixture):
    plugin_id, commands, record, context = plugin_fixture
    for command_id, _feature, aliases in commands:
        for alias in aliases:
            resolved = resolve_plugin_command_for_feature(context, [record], alias)
            assert resolved == command_id, (
                f"{plugin_id}: alias '{alias}' resolved to {resolved!r}, "
                f"expected {command_id!r}"
            )


def test_raw_command_id_resolves_to_itself(plugin_fixture):
    plugin_id, commands, record, context = plugin_fixture
    for command_id, _feature, _aliases in commands:
        resolved = resolve_plugin_command_for_feature(context, [record], command_id)
        assert resolved == command_id, (
            f"{plugin_id}: command id {command_id!r} should resolve to itself"
        )


def test_no_cross_plugin_feature_collisions():
    """Features and aliases from arbitrary manifests resolve unambiguously.

    If two plugins declared the same feature name, whichever's context.commands
    happened to be checked first would win silently — this would be a real,
    hard-to-debug cross-plugin routing bug. Guard against it by checking all
    plugins' commands/features/aliases are attached to a single context and
    resolve to the correct manifest command every time.
    """
    all_records = []
    all_command_ids: list[str] = []
    for plugin_id, commands in GENERIC_PLUGIN_CASES:
        manifest = _make_manifest(plugin_id, commands)
        all_records.append(_make_record(plugin_id, manifest))
        all_command_ids.extend(cid for cid, _f, _a in commands)

    context = _make_context(all_command_ids)

    for plugin_id, commands in GENERIC_PLUGIN_CASES:
        for command_id, feature, aliases in commands:
            resolved = resolve_plugin_command_for_feature(context, all_records, feature)
            assert resolved == command_id, (
                f"{plugin_id}: feature '{feature}' collided with another "
                f"plugin's command — resolved to {resolved!r}, expected {command_id!r}"
            )
            for alias in aliases:
                resolved = resolve_plugin_command_for_feature(
                    context, all_records, alias
                )
                assert resolved == command_id, (
                    f"{plugin_id}: alias '{alias}' collided with another "
                    f"plugin's command — resolved to {resolved!r}, expected {command_id!r}"
                )
