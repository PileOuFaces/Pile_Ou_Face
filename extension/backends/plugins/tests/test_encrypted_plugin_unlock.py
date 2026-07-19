# SPDX-License-Identifier: AGPL-3.0-only
"""Ferme le trou de couverture identifié le 2026-07-19 : aucun test existant ne va
jusqu'au déchiffrement réel d'un bundle .pofplug avec la content_key injectée via
stdin (XSYNC-LIC-001, Pile_Ou_Face#70). Les tests existants s'arrêtent soit à la
forme du payload stdin (côté JS), soit à evaluate_plugin_license isolément (sans
jamais toucher runtime.py ni un vrai bundle chiffré).

Ce test construit un mini bundle .pofplug synthétique (AES-256-GCM + HMAC, même
format que Pile_ou_Face_plugins/tooling/plugin_builder.py) et appelle directement
_resolve_effective_plugin_root — le même code que la prod utilise pour déverrouiller
un plugin premium — avec la content_key injectée exactement comme le host le fait
(env BINHOST_CONTENT_KEYS_STDIN=1 + JSON sur stdin).
"""

import base64
import hashlib
import hmac
import io
import json
import zipfile

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backends.plugins import license as license_module
from backends.plugins import runtime as runtime_module
from backends.plugins.manifest import (
    PluginDistribution,
    PluginEntrypoints,
    PluginHostRequirements,
    PluginLicensing,
    PluginManifest,
)

PLUGIN_ID = "pof.encrypted-unlock-test"


def _build_encrypted_bundle(root_path, content_key_b64: str) -> PluginManifest:
    """Fabrique un plugin chiffré sur disque, retourne son PluginManifest.

    Reproduit exactement le format produit par
    Pile_ou_Face_plugins/tooling/plugin_builder.py::build_encrypted_plugin
    (payload zip -> AES-256-GCM -> HMAC-SHA256(ciphertext) avec sha256(content_key)).
    """
    plugin_source = root_path / "plugin_source"
    plugin_source.mkdir()
    inner_manifest = {
        "id": PLUGIN_ID,
        "name": "Encrypted Unlock Test",
        "version": "1.0.0",
    }
    (plugin_source / "manifest.json").write_text(
        json.dumps(inner_manifest), encoding="utf-8"
    )
    (plugin_source / "hello.py").write_text("VALUE = 42\n", encoding="utf-8")

    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, "w") as archive:
        for path in plugin_source.rglob("*"):
            if path.is_file():
                archive.write(path, arcname=path.relative_to(plugin_source))
    plaintext = zip_buffer.getvalue()
    payload_sha256 = hashlib.sha256(plaintext).hexdigest()

    key_bytes = base64.b64decode(content_key_b64)
    nonce = b"\x00" * 12  # test fixe — jamais réutilisé en dehors de ce test
    ciphertext = AESGCM(key_bytes).encrypt(nonce, plaintext, None)

    hmac_key = hashlib.sha256(content_key_b64.encode("utf-8")).digest()
    hmac_hex = hmac.new(hmac_key, ciphertext, hashlib.sha256).hexdigest()

    bundle_root = root_path / "bundle"
    (bundle_root / "metadata").mkdir(parents=True)
    (bundle_root / "payload.enc").write_bytes(ciphertext)
    (bundle_root / "metadata" / "encryption.json").write_text(
        json.dumps(
            {
                "payload_file": "payload.enc",
                "nonce_b64": base64.b64encode(nonce).decode("ascii"),
                "algorithm": "aes-256-gcm",
                "payload_sha256": payload_sha256,
            }
        ),
        encoding="utf-8",
    )

    return PluginManifest(
        plugin_id=PLUGIN_ID,
        name="Encrypted Unlock Test",
        version="1.0.0",
        kind="feature",
        host=PluginHostRequirements(api_version=1),
        distribution=PluginDistribution(
            encrypted=True, bundle_format="pofplug", hmac_sha256=hmac_hex
        ),
        licensing=PluginLicensing(required=True),
        entrypoints=PluginEntrypoints(),
        capabilities={},
        dependencies={},
        manifest_path=bundle_root / "manifest.json",
        root_path=bundle_root,
        raw={},
    )


def test_stdin_content_key_actually_decrypts_the_real_bundle(tmp_path, monkeypatch):
    content_key_b64 = base64.b64encode(b"\x01" * 32).decode("ascii")
    manifest = _build_encrypted_bundle(tmp_path, content_key_b64)

    monkeypatch.setenv("BINHOST_CONTENT_KEYS_STDIN", "1")
    monkeypatch.setattr(license_module, "_STDIN_CONTENT_KEYS_CACHE", None)
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"content_keys": {PLUGIN_ID: content_key_b64}})),
    )

    plugin_root = runtime_module._resolve_effective_plugin_root(manifest)

    assert (plugin_root / "manifest.json").exists()
    decrypted_manifest = json.loads((plugin_root / "manifest.json").read_text())
    assert decrypted_manifest["id"] == PLUGIN_ID
    assert (plugin_root / "hello.py").read_text() == "VALUE = 42\n"


def test_wrong_content_key_is_refused(tmp_path, monkeypatch):
    real_key_b64 = base64.b64encode(b"\x02" * 32).decode("ascii")
    manifest = _build_encrypted_bundle(tmp_path, real_key_b64)

    wrong_key_b64 = base64.b64encode(b"\x03" * 32).decode("ascii")
    monkeypatch.setenv("BINHOST_CONTENT_KEYS_STDIN", "1")
    monkeypatch.setattr(license_module, "_STDIN_CONTENT_KEYS_CACHE", None)
    monkeypatch.setattr(
        "sys.stdin",
        io.StringIO(json.dumps({"content_keys": {PLUGIN_ID: wrong_key_b64}})),
    )

    # Le HMAC (calculé avec la mauvaise clé) ne correspond plus au premier
    # contrôle d'intégrité — échec attendu avant même de tenter l'AES-GCM.
    with pytest.raises(RuntimeError, match="Intégrité|déchiffrer"):
        runtime_module._resolve_effective_plugin_root(manifest)


def test_missing_content_key_is_refused(tmp_path, monkeypatch):
    content_key_b64 = base64.b64encode(b"\x04" * 32).decode("ascii")
    manifest = _build_encrypted_bundle(tmp_path, content_key_b64)

    monkeypatch.delenv("BINHOST_CONTENT_KEYS_STDIN", raising=False)
    monkeypatch.setattr(license_module, "_STDIN_CONTENT_KEYS_CACHE", None)
    monkeypatch.setattr("sys.stdin", io.StringIO(""))

    with pytest.raises(RuntimeError):
        runtime_module._resolve_effective_plugin_root(manifest)
