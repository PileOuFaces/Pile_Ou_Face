# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json

import pytest

from backends.plugins.manifest import load_plugin_manifest
from backends.plugins.scaffold import ScaffoldError, scaffold_plugin


def test_scaffold_backend_only_plugin(tmp_path):
    root = scaffold_plugin(
        tmp_path / "acme-plugin",
        plugin_id="acme.strings-enricher",
        name="Strings Enricher",
    )

    assert (root / "manifest.json").exists()
    assert (root / "python" / "plugin_main.py").exists()
    assert (root / "README.md").exists()
    assert not (root / "webview").exists()

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["id"] == "acme.strings-enricher"
    assert manifest["entrypoints"]["python"]["module"] == "plugin_main"
    assert "webview" not in manifest["entrypoints"]
    assert manifest["distribution"]["encrypted"] is False
    assert manifest["licensing"]["required"] is False


def test_scaffold_with_webview(tmp_path):
    root = scaffold_plugin(
        tmp_path / "acme-plugin",
        plugin_id="acme.strings-enricher",
        name="Strings Enricher",
        with_webview=True,
    )

    assert (root / "webview" / "tab.html").exists()
    assert (root / "webview" / "tab.js").exists()

    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["entrypoints"]["webview"]["tab_html"] == "webview/tab.html"
    assert manifest["minPoFVersion"]


def test_scaffold_output_loads_as_a_valid_manifest(tmp_path):
    root = scaffold_plugin(
        tmp_path / "acme-plugin",
        plugin_id="acme.strings-enricher",
        name="Strings Enricher",
        with_webview=True,
    )

    manifest = load_plugin_manifest(root)
    assert manifest.plugin_id == "acme.strings-enricher"
    assert manifest.entrypoints.python is not None
    assert manifest.entrypoints.python.module == "plugin_main"


def test_scaffold_rejects_invalid_id(tmp_path):
    with pytest.raises(ScaffoldError, match="id invalide"):
        scaffold_plugin(tmp_path / "x", plugin_id="not-namespaced", name="X")


def test_scaffold_refuses_to_overwrite_nonempty_dir_without_force(tmp_path):
    target = tmp_path / "acme-plugin"
    scaffold_plugin(target, plugin_id="acme.strings-enricher", name="Strings Enricher")

    with pytest.raises(ScaffoldError, match="existe déjà"):
        scaffold_plugin(
            target, plugin_id="acme.strings-enricher", name="Strings Enricher"
        )

    # --force allows re-generation
    root = scaffold_plugin(
        target, plugin_id="acme.strings-enricher", name="Strings Enricher", force=True
    )
    assert root == target.resolve()


def test_generated_plugin_main_is_valid_python(tmp_path):
    import ast

    root = scaffold_plugin(
        tmp_path / "acme-plugin",
        plugin_id="acme.strings-enricher",
        name="Strings Enricher",
    )
    source = (root / "python" / "plugin_main.py").read_text(encoding="utf-8")
    ast.parse(source)  # raises SyntaxError if invalid
