# SPDX-License-Identifier: AGPL-3.0-only
"""Malicious-ZIP regression tests for plugin bundle installation.

Addresses GitHub issue "[security] Valider extraction ZIP des plugins"
(was Azure DevOps #41): a plugin bundle (.pofplug/.zip) is untrusted input —
it may come from a third-party plugin author. These tests lock in that
_safe_members()/install_plugin() reject the well-known zip-based escape
vectors before anything is written to disk.
"""

from __future__ import annotations

import json
import stat
import zipfile
from pathlib import Path

import pytest

from backends.plugins.install_plugin import (
    PluginInstallError,
    _resolve_source_root,
    install_plugin,
)

_MANIFEST = json.dumps(
    {
        "id": "acme.evil-plugin",
        "name": "Evil Plugin",
        "version": "1.0.0",
        "kind": "analysis-pack",
        "host": {"api_version": 1},
        "entrypoints": {
            "python": {"module": "plugin_main", "register": "register_plugin"}
        },
    }
)


def _make_zip(
    path: Path, entries: dict[str, str], *, symlink: tuple[str, str] | None = None
) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
        if symlink is not None:
            link_name, link_target = symlink
            info = zipfile.ZipInfo(link_name)
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, link_target)
    return path


def test_rejects_absolute_path_entry(tmp_path):
    zip_path = _make_zip(
        tmp_path / "evil.zip",
        {"manifest.json": _MANIFEST, "/etc/evil.txt": "pwned"},
    )
    with pytest.raises(PluginInstallError, match="dangereuse|invalide"):
        _resolve_source_root(zip_path)


def test_rejects_forward_slash_path_traversal(tmp_path):
    zip_path = _make_zip(
        tmp_path / "evil.zip",
        {"manifest.json": _MANIFEST, "../../../tmp/evil_escaped.txt": "pwned"},
    )
    with pytest.raises(PluginInstallError, match="dangereuse"):
        _resolve_source_root(zip_path)


def test_rejects_backslash_path_traversal(tmp_path):
    """Backslashes aren't a path separator to pathlib.Path on POSIX, so a
    naive check (splitting on '/' only) would silently let this through as
    a harmless-looking single filename — safe by platform accident, not by
    design. The same bundle installed on Windows would actually traverse.
    """
    zip_path = _make_zip(
        tmp_path / "evil.zip",
        {"manifest.json": _MANIFEST, "..\\..\\..\\tmp\\evil_escaped.txt": "pwned"},
    )
    with pytest.raises(PluginInstallError, match="dangereuse"):
        _resolve_source_root(zip_path)


def test_rejects_symlink_member(tmp_path):
    zip_path = _make_zip(
        tmp_path / "evil.zip",
        {"manifest.json": _MANIFEST},
        symlink=("evil_link", "/etc/passwd"),
    )
    with pytest.raises(PluginInstallError, match="symlink"):
        _resolve_source_root(zip_path)


def test_rejects_bundle_with_too_many_members(tmp_path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("manifest.json", _MANIFEST)
        for i in range(5001):
            zf.writestr(f"file_{i}.txt", "x")
    with pytest.raises(PluginInstallError, match="trop d.entrées"):
        _resolve_source_root(zip_path)


def test_rejects_bundle_exceeding_uncompressed_size_cap(tmp_path):
    zip_path = tmp_path / "evil.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", _MANIFEST)
        # A single highly-compressible member whose *uncompressed* size
        # exceeds the cap — this is the classic zip-bomb shape.
        zf.writestr("bomb.bin", b"\x00" * (10 * 1024 * 1024))

    # Lower the cap for this test via monkeypatching the module constant
    # would require importing the module object; simplest robust check is
    # to assert the real cap (200 MiB) isn't exceeded by a reasonable
    # plugin bundle, and separately unit-test the guard logic directly.
    import backends.plugins.install_plugin as install_plugin_mod

    original_cap = install_plugin_mod._MAX_TOTAL_UNCOMPRESSED_BYTES
    install_plugin_mod._MAX_TOTAL_UNCOMPRESSED_BYTES = 1024  # 1 KiB, for this test only
    try:
        with pytest.raises(PluginInstallError, match="taille décompressée"):
            _resolve_source_root(zip_path)
    finally:
        install_plugin_mod._MAX_TOTAL_UNCOMPRESSED_BYTES = original_cap


def test_accepts_a_well_formed_bundle(tmp_path):
    zip_path = _make_zip(
        tmp_path / "good.zip",
        {
            "manifest.json": _MANIFEST,
            "python/plugin_main.py": "def register_plugin(context):\n    pass\n",
        },
    )
    root, kind, temp_dir = _resolve_source_root(zip_path)
    try:
        assert (root / "manifest.json").exists()
        assert kind == "bundle"
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def test_install_plugin_end_to_end_rejects_malicious_bundle(tmp_path):
    zip_path = _make_zip(
        tmp_path / "evil.zip",
        {"manifest.json": _MANIFEST, "../../../tmp/evil_escaped.txt": "pwned"},
    )
    target_root = tmp_path / "plugins"
    with pytest.raises(PluginInstallError):
        install_plugin(zip_path, target_root)
    # Nothing should have been installed.
    assert not target_root.exists() or not any(target_root.iterdir())


def test_install_plugin_end_to_end_installs_a_well_formed_bundle(tmp_path):
    zip_path = _make_zip(
        tmp_path / "good.zip",
        {
            "manifest.json": _MANIFEST,
            "python/plugin_main.py": "def register_plugin(context):\n    pass\n",
        },
    )
    target_root = tmp_path / "plugins"
    result = install_plugin(zip_path, target_root)
    assert result["ok"] is True
    assert result["plugin_id"] == "acme.evil-plugin"
    installed = Path(result["installed_to"])
    assert installed.exists()
    assert (installed / "manifest.json").exists()
    # The installed tree must stay confined to target_root.
    assert installed.resolve().is_relative_to(target_root.resolve())
