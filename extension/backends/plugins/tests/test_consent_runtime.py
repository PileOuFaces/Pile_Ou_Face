# SPDX-License-Identifier: AGPL-3.0-only
"""End-to-end consent behaviour of the plugin runtime on a real plugin folder."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from backends.plugins import runtime
from backends.plugins.consent import default_consent_path, grant_plugin_consent

PLUGIN_ID = "acme.marker"
VERSION = "1.0.0"
MARKER_ENV = "POF_TEST_PLUGIN_MARKER"
PLUGIN_SOURCE = f"""
import os, pathlib
pathlib.Path(os.environ["{MARKER_ENV}"]).write_text("imported")
def register_plugin(context):
    pass
"""


def _write_plugin(parent: Path) -> Path:
    root = parent / "marker"
    (root / "python").mkdir(parents=True)
    (root / "python" / "plugin_main.py").write_text(PLUGIN_SOURCE, encoding="utf-8")
    manifest = {
        "id": PLUGIN_ID,
        "name": "Marker",
        "version": VERSION,
        "kind": "analysis-pack",
        "host": {"api_version": 1, "min_version": "0.0.1", "max_version": "99.0.0"},
        "entrypoints": {
            "python": {"module": "plugin_main", "register": "register_plugin"}
        },
    }
    (root / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    return root


@pytest.fixture
def sandbox(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    workspace = tmp_path / "repo"
    plugins = workspace / ".pile-ou-face" / "plugins"
    plugins.mkdir(parents=True)
    plugin_root = _write_plugin(plugins)
    marker = tmp_path / "marker.txt"
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.delenv("BINHOST_PLUGIN_PATH", raising=False)
    monkeypatch.delenv("BINHOST_PLUGIN_CONSENT_PATH", raising=False)
    monkeypatch.setenv(MARKER_ENV, str(marker))
    monkeypatch.chdir(workspace)
    return {
        "home": home,
        "workspace": workspace,
        "plugin_root": plugin_root,
        "marker": marker,
    }


def _states(capsys) -> list[str]:
    assert runtime.main(["list", "--json", "--attach"]) == 0
    return [item["state"] for item in json.loads(capsys.readouterr().out)["plugins"]]


def test_missing_store_approves_nothing_and_stays_missing(sandbox, capsys):
    assert _states(capsys) == ["pending_consent"]
    assert not sandbox["marker"].exists()
    assert not default_consent_path().exists()
    assert not (sandbox["workspace"] / ".pile-ou-face/plugin_consent.json").exists()


def test_repository_store_is_ignored(sandbox, capsys):
    store = {PLUGIN_ID: {"approved": True, "version": VERSION}}
    (sandbox["workspace"] / ".pile-ou-face/plugin_consent.json").write_text(
        json.dumps(store), encoding="utf-8"
    )
    assert _states(capsys) == ["pending_consent"]
    assert not sandbox["marker"].exists()


def test_user_grant_loads_the_plugin(sandbox, capsys):
    assert runtime.main(["consent-grant", PLUGIN_ID]) == 0
    capsys.readouterr()
    _states(capsys)
    assert sandbox["marker"].exists()


def test_grant_for_another_copy_does_not_run_a_repository_copy(sandbox, capsys):
    grant_plugin_consent(
        PLUGIN_ID,
        VERSION,
        default_consent_path(),
        plugin_root=sandbox["home"] / "plugins" / "marker",
    )
    assert _states(capsys) == ["pending_consent"]
    assert not sandbox["marker"].exists()


def test_legacy_grant_does_not_run_a_repository_copy(sandbox, capsys):
    path = default_consent_path()
    path.parent.mkdir(parents=True)
    path.write_text(
        json.dumps({PLUGIN_ID: {"approved": True, "version": VERSION}}),
        encoding="utf-8",
    )
    assert _states(capsys) == ["pending_consent"]
    assert not sandbox["marker"].exists()


def test_consent_status_never_imports_plugin_code(sandbox, capsys):
    assert runtime.main(["consent-grant", PLUGIN_ID]) == 0
    capsys.readouterr()
    assert runtime.main(["consent-status"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert [(p["plugin_id"], p["authorized"]) for p in payload["plugins"]] == [
        (PLUGIN_ID, True)
    ]
    assert not sandbox["marker"].exists()


def test_consent_status_reports_pending_and_revoked_plugins(sandbox, capsys):
    assert runtime.main(["consent-status"]) == 0
    assert not json.loads(capsys.readouterr().out)["plugins"][0]["authorized"]
    runtime.main(["consent-grant", PLUGIN_ID])
    runtime.main(["consent-revoke", PLUGIN_ID])
    capsys.readouterr()
    assert runtime.main(["consent-status"]) == 0
    assert not json.loads(capsys.readouterr().out)["plugins"][0]["authorized"]
