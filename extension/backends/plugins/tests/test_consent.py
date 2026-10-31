# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the plugin consent gate.

Addresses GitHub issue "[security] Désactiver les plugins tiers par défaut
en public" (was Azure DevOps #39): a discovered plugin's Python code must
not execute (register_plugin(context) must not run) until the user has
explicitly approved it. A checked-out repository can never approve anything.
"""

from __future__ import annotations

import json
import os
import stat
import threading

from backends.plugins.consent import (
    default_consent_path,
    grant_plugin_consent,
    is_plugin_consented,
    load_consent_store,
    revoke_plugin_consent,
    save_consent_store,
)


def test_default_consent_path_is_the_home_store(tmp_path):
    path = default_consent_path(home=tmp_path / "home", env={})
    assert path == tmp_path / "home" / ".pile-ou-face" / "plugin_consent.json"


def test_default_consent_path_ignores_a_workspace_store(tmp_path, monkeypatch):
    project = tmp_path / "project"
    (project / ".pile-ou-face").mkdir(parents=True)
    (project / ".pile-ou-face" / "plugin_consent.json").write_text(
        '{"acme.demo": {"approved": true, "version": "1.0.0"}}', encoding="utf-8"
    )
    monkeypatch.chdir(project)
    path = default_consent_path(home=tmp_path / "home", env={})
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


def test_save_consent_store_is_private_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "consent.json"
    save_consent_store(path, {"acme.demo": {"approved": True, "version": "1.0.0"}})
    if os.name != "nt":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert [item.name for item in tmp_path.iterdir()] == ["consent.json"]


def test_save_consent_store_keeps_previous_store_on_failure(tmp_path):
    path = tmp_path / "consent.json"
    save_consent_store(path, {"acme.a": {"approved": True, "version": "1.0.0"}})
    before = path.read_text(encoding="utf-8")
    try:
        save_consent_store(path, {"acme.b": {"bad": object()}})
    except TypeError:
        pass
    assert path.read_text(encoding="utf-8") == before


def test_first_run_baseline_entries_are_not_attested(tmp_path):
    store = {
        "acme.a": {
            "approved": True,
            "version": "1.0.0",
            "note": "grandfathered-on-first-run",
        }
    }
    assert is_plugin_consented("acme.a", "1.0.0", store) is False


def test_grant_is_bound_to_the_approved_location(tmp_path):
    path = tmp_path / "consent.json"
    installed = tmp_path / "home" / "plugins" / "demo"
    grant_plugin_consent("acme.demo", "1.0.0", path, plugin_root=installed)
    store = load_consent_store(path)
    assert is_plugin_consented("acme.demo", "1.0.0", store, plugin_root=installed)
    assert not is_plugin_consented(
        "acme.demo", "1.0.0", store, plugin_root=tmp_path / "repo" / "demo"
    )


def test_explicit_grant_without_location_survives_outside_the_workspace(tmp_path):
    store = {"acme.demo": {"approved": True, "version": "1.0.0"}}
    workspace = tmp_path / "repo"
    assert is_plugin_consented(
        "acme.demo",
        "1.0.0",
        store,
        plugin_root=tmp_path / "home" / "plugins" / "demo",
        workspace=workspace,
    )


def test_grant_without_location_cannot_vouch_for_a_workspace_copy(tmp_path):
    store = {"acme.demo": {"approved": True, "version": "1.0.0"}}
    workspace = tmp_path / "repo"
    assert not is_plugin_consented(
        "acme.demo",
        "1.0.0",
        store,
        plugin_root=workspace / ".pile-ou-face" / "plugins" / "demo",
        workspace=workspace,
    )


def test_store_is_valid_json_after_grant(tmp_path):
    path = tmp_path / "consent.json"
    grant_plugin_consent("acme.demo", "1.0.0", path)
    assert json.loads(path.read_text(encoding="utf-8"))["acme.demo"]["approved"]


def test_grant_waits_for_a_revoke_in_progress(tmp_path, monkeypatch):
    from backends.plugins import consent

    path = tmp_path / "consent.json"
    grant_plugin_consent("acme.a", "1.0.0", path)
    reading = threading.Event()
    original_load = consent.load_consent_store

    def slow_load(store_path):
        store = original_load(store_path)
        reading.set()
        threading.Event().wait(0.1)
        return store

    monkeypatch.setattr(consent, "load_consent_store", slow_load)
    revoke = threading.Thread(target=revoke_plugin_consent, args=("acme.a", path))
    revoke.start()
    reading.wait(5)
    grant_plugin_consent("acme.b", "1.0.0", path)
    revoke.join(5)

    store = original_load(path)
    assert is_plugin_consented("acme.a", "1.0.0", store) is False
    assert is_plugin_consented("acme.b", "1.0.0", store) is True
