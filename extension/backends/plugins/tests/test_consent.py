# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the plugin consent gate.

Addresses GitHub issue "[security] Désactiver les plugins tiers par défaut
en public" (was Azure DevOps #39): a discovered plugin's Python code must
not execute (register_plugin(context) must not run) until the user has
explicitly approved it, except for plugins already installed before this
gate existed (grandfathered on first run so existing users aren't broken).
"""

from __future__ import annotations

from backends.plugins.consent import (
    default_consent_path,
    ensure_consent_baseline,
    grant_plugin_consent,
    is_plugin_consented,
    load_consent_store,
    revoke_plugin_consent,
    save_consent_store,
)


def test_default_consent_path_prefers_workspace_root_when_present(tmp_path):
    project = tmp_path / "project"
    (project / ".pile-ou-face").mkdir(parents=True)
    path = default_consent_path(cwd=project, home=tmp_path / "home", env={})
    assert path == project / ".pile-ou-face" / "plugin_consent.json"


def test_default_consent_path_falls_back_to_home_without_workspace_root(tmp_path):
    path = default_consent_path(
        cwd=tmp_path / "project", home=tmp_path / "home", env={}
    )
    assert path == tmp_path / "home" / ".pile-ou-face" / "plugin_consent.json"


def test_default_consent_path_workspace_discovery_can_be_disabled(tmp_path):
    project = tmp_path / "project"
    (project / ".pile-ou-face").mkdir(parents=True)
    path = default_consent_path(
        cwd=project, home=tmp_path / "home", env={}, allow_workspace_discovery=False
    )
    assert path == tmp_path / "home" / ".pile-ou-face" / "plugin_consent.json"


def test_default_consent_path_env_override(tmp_path):
    override = tmp_path / "custom" / "consent.json"
    path = default_consent_path(env={"BINHOST_PLUGIN_CONSENT_PATH": str(override)})
    assert path == override


def test_is_plugin_consented_false_when_absent():
    assert is_plugin_consented("acme.demo", "1.0.0", {}) is False


def test_grant_then_is_consented(tmp_path):
    path = tmp_path / "consent.json"
    grant_plugin_consent("acme.demo", "1.0.0", path)
    store = load_consent_store(path)
    assert is_plugin_consented("acme.demo", "1.0.0", store) is True


def test_consent_does_not_carry_over_a_version_bump(tmp_path):
    path = tmp_path / "consent.json"
    grant_plugin_consent("acme.demo", "1.0.0", path)
    store = load_consent_store(path)
    # A version bump could introduce new capabilities — re-consent required.
    assert is_plugin_consented("acme.demo", "2.0.0", store) is False


def test_revoke_plugin_consent(tmp_path):
    path = tmp_path / "consent.json"
    grant_plugin_consent("acme.demo", "1.0.0", path)
    revoke_plugin_consent("acme.demo", path)
    store = load_consent_store(path)
    assert is_plugin_consented("acme.demo", "1.0.0", store) is False


def test_load_consent_store_returns_empty_dict_for_missing_file(tmp_path):
    assert load_consent_store(tmp_path / "does-not-exist.json") == {}


def test_load_consent_store_returns_empty_dict_for_corrupt_file(tmp_path):
    path = tmp_path / "consent.json"
    path.write_text("not json{{{", encoding="utf-8")
    assert load_consent_store(path) == {}


def test_save_consent_store_creates_parent_directories(tmp_path):
    path = tmp_path / "a" / "b" / "consent.json"
    save_consent_store(path, {"acme.demo": {"approved": True, "version": "1.0.0"}})
    assert path.exists()


class _FakeManifest:
    def __init__(self, version: str) -> None:
        self.version = version


class _FakeRecord:
    def __init__(self, plugin_id: str, version: str) -> None:
        self.plugin_id = plugin_id
        self.manifest = _FakeManifest(version)


def test_ensure_consent_baseline_grandfathers_existing_plugins_on_first_run(tmp_path):
    path = tmp_path / "consent.json"
    records = [_FakeRecord("acme.a", "1.0.0"), _FakeRecord("acme.b", "2.0.0")]

    ensure_consent_baseline(records, path)

    store = load_consent_store(path)
    assert is_plugin_consented("acme.a", "1.0.0", store) is True
    assert is_plugin_consented("acme.b", "2.0.0", store) is True


def test_ensure_consent_baseline_is_a_noop_once_the_store_exists(tmp_path):
    path = tmp_path / "consent.json"
    # Store already exists (e.g. from a previous run) without acme.c in it.
    save_consent_store(path, {"acme.a": {"approved": True, "version": "1.0.0"}})

    records = [_FakeRecord("acme.a", "1.0.0"), _FakeRecord("acme.c", "1.0.0")]
    ensure_consent_baseline(records, path)

    store = load_consent_store(path)
    # acme.c must NOT be silently grandfathered just by showing up later —
    # only plugins present before the consent store was first created are.
    assert is_plugin_consented("acme.c", "1.0.0", store) is False
