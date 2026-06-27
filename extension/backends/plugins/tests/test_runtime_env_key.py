# SPDX-License-Identifier: AGPL-3.0-only
import os
from types import SimpleNamespace
from unittest.mock import patch
from backends.plugins.license import evaluate_plugin_license


def _build_manifest(required=True):
    return SimpleNamespace(
        plugin_id="pof.test-plugin",
        licensing=SimpleNamespace(
            required=required,
            message="",
            public_key="",
            public_key_path="",
            license_filename="",
        ),
    )


def test_env_content_key_takes_priority(tmp_path):
    """POF_CONTENT_KEY_* env var overrides license file lookup."""
    manifest = _build_manifest()
    env_var = "POF_CONTENT_KEY_POF_TEST_PLUGIN"
    fake_key = "dGVzdGtleWFiY2RlZmc="

    with patch.dict(os.environ, {env_var: fake_key}):
        result = evaluate_plugin_license(manifest, search_paths=[tmp_path])

    assert result.content_key == fake_key
    assert result.status == "active"
    assert result.verified is True


def test_no_env_key_falls_back_to_file_lookup(tmp_path):
    """Sans env var, la fonction continue vers la recherche de fichier licence."""
    manifest = _build_manifest()

    # Sans licence et sans env var -> status non-active (pas d'erreur levee)
    result = evaluate_plugin_license(manifest, search_paths=[tmp_path])
    assert result.status != "active" or result.content_key == ""


def test_auth_strict_env_disables_license_file_fallback(tmp_path):
    manifest = _build_manifest()

    result = evaluate_plugin_license(
        manifest,
        env={"BINHOST_DISABLE_LICENSE_FALLBACK": "1"},
        search_paths=[tmp_path],
    )

    assert result.status == "locked"
    assert "Connexion requise" in result.message
