# SPDX-License-Identifier: AGPL-3.0-only
"""Regression guard for the frozen plugin command/feature registry.

See CONTRACTS_SHARED.md (workspace root), section "Plugin Runtime Commands",
"Frozen registry" — this is the host-side half of that contract. It snapshots
the *real* command ids/features/aliases declared by the 4 in-house plugins
(Pile_ou_Face_plugins) and verifies resolve_plugin_command_for_feature()
still resolves every one of them correctly.

This intentionally does NOT read the plugins repo (private, not checked out
in this repo's CI) — the snapshot below is the source of truth on the host
side. If a plugin renames a feature/alias/id, this test won't catch it (that
guard lives in the plugins repo's own test suite) — what this test catches is
a regression in the host's *resolution algorithm* breaking a feature name
that used to resolve correctly.

If you deliberately change this registry (a plugin renamed something via the
XSYNC process), update this snapshot AND the CONTRACTS_SHARED.md table in the
same PR.
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

# Mirrors CONTRACTS_SHARED.md's "Frozen registry" table exactly.
# (plugin_id, family, [(command_id, feature, [aliases])])
FROZEN_REGISTRY: list[tuple[str, str, list[tuple[str, str, list[str]]]]] = [
    (
        "pof.malware-triage-pro",
        "malware",
        [
            ("malware.behavior.run", "behavior", []),
            ("malware.anti_analysis.run", "anti_analysis", []),
            ("malware.capa.run", "capa_scan", ["capa"]),
            ("malware.yara.run", "yara_scan", ["yara"]),
            ("malware.deobfuscate.run", "deobfuscate", ["string_deobfuscate"]),
            ("malware.attck.tag", "attck", []),
            ("malware.packer.run", "packer", ["packer_detect"]),
            ("malware.capa.delete_rules", "capa_rules_delete", []),
            ("malware.capa.check_rules", "capa_rules_check", []),
            ("malware.capa.download_rules", "capa_rules_download", []),
            ("malware.ioc_export.run", "ioc_export", []),
        ],
    ),
    (
        "pof.cross-analysis-pro",
        "croisee",
        [("croisee.cross_analyze.run", "cross_analysis", ["cross_analyze"])],
    ),
    (
        "pof.offensive-research-pro",
        "offensif",
        [
            ("offensive.flirt.run", "flirt", []),
            ("offensive.rop.run", "rop", ["rop_gadgets"]),
            ("offensive.rop.build", "rop_build", []),
            ("offensive.bindiff.run", "bindiff", []),
            ("offensive.func_similarity.run", "func_similarity", []),
        ],
    ),
    (
        "pof.vulnerability-audit-pro",
        "audit",
        [
            ("audit.vulns.run", "vulns", ["vuln_patterns"]),
            ("audit.taint.run", "taint", []),
        ],
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


@pytest.fixture(params=FROZEN_REGISTRY, ids=[entry[0] for entry in FROZEN_REGISTRY])
def plugin_fixture(request):
    plugin_id, family, commands = request.param
    manifest = _make_manifest(plugin_id, commands)
    record = _make_record(plugin_id, manifest)
    context = _make_context([cid for cid, _feature, _aliases in commands])
    return plugin_id, family, commands, record, context


def test_every_frozen_feature_resolves_to_its_command(plugin_fixture):
    plugin_id, _family, commands, record, context = plugin_fixture
    for command_id, feature, _aliases in commands:
        resolved = resolve_plugin_command_for_feature(context, [record], feature)
        assert resolved == command_id, (
            f"{plugin_id}: feature '{feature}' resolved to {resolved!r}, "
            f"expected {command_id!r} — resolution algorithm regressed for a "
            f"real, in-use feature name (see CONTRACTS_SHARED.md frozen registry)"
        )


def test_every_frozen_alias_resolves_to_its_command(plugin_fixture):
    plugin_id, _family, commands, record, context = plugin_fixture
    for command_id, _feature, aliases in commands:
        for alias in aliases:
            resolved = resolve_plugin_command_for_feature(context, [record], alias)
            assert resolved == command_id, (
                f"{plugin_id}: alias '{alias}' resolved to {resolved!r}, "
                f"expected {command_id!r}"
            )


def test_raw_command_id_resolves_to_itself(plugin_fixture):
    plugin_id, _family, commands, record, context = plugin_fixture
    for command_id, _feature, _aliases in commands:
        resolved = resolve_plugin_command_for_feature(context, [record], command_id)
        assert resolved == command_id, (
            f"{plugin_id}: command id {command_id!r} should resolve to itself"
        )


def test_no_cross_plugin_feature_collisions():
    """Every feature/alias across all 4 plugins must resolve unambiguously.

    If two plugins declared the same feature name, whichever's context.commands
    happened to be checked first would win silently — this would be a real,
    hard-to-debug cross-plugin routing bug. Guard against it by checking all
    4 plugins' commands/features/aliases are attached to a single context and
    resolve to the *correct* plugin's command every time.
    """
    all_records = []
    all_command_ids: list[str] = []
    for plugin_id, _family, commands in FROZEN_REGISTRY:
        manifest = _make_manifest(plugin_id, commands)
        all_records.append(_make_record(plugin_id, manifest))
        all_command_ids.extend(cid for cid, _f, _a in commands)

    context = _make_context(all_command_ids)

    for plugin_id, _family, commands in FROZEN_REGISTRY:
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
