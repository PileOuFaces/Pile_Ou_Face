# SPDX-License-Identifier: AGPL-3.0-only
import base64
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from backends.plugins import license as license_module
from backends.plugins.license import evaluate_plugin_license
from backends.plugins.manifest import (
    PluginDistribution,
    PluginEntrypoints,
    PluginHostRequirements,
    PluginLicensing,
    PluginManifest,
)
from backends.plugins.runtime import (
    _cleanup_decrypted_plugin_cache,
    _resolve_effective_plugin_root,
    _verify_payload_hmac,
)


def _manifest(root: Path, *, encrypted: bool = False, required: bool = True):
    return PluginManifest(
        plugin_id="pof.test",
        name="Test",
        version="1.0.0",
        kind="python",
        host=PluginHostRequirements(api_version=1),
        distribution=PluginDistribution(
            encrypted=encrypted,
            bundle_format="pofplug-enc" if encrypted else "",
            profile="ONLINE_STANDARD" if encrypted else "",
        ),
        licensing=PluginLicensing(
            required=required,
            mode="signed-license" if encrypted else "",
            release_id="release-test-1" if encrypted else "",
        ),
        entrypoints=PluginEntrypoints(),
        capabilities={},
        dependencies={},
        manifest_path=root / "manifest.json",
        root_path=root,
        min_pof_version=None,
        raw={},
    )


class TestOnlineStandardLicense(unittest.TestCase):
    def tearDown(self):
        license_module._STDIN_CONTENT_KEYS_CACHE = None
        _cleanup_decrypted_plugin_cache()

    def test_auth_stdin_key_unlocks_exact_plugin(self):
        key = base64.b64encode(os.urandom(32)).decode()
        license_module._STDIN_CONTENT_KEYS_CACHE = None
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch(
                "sys.stdin",
                io.StringIO(json.dumps({"content_keys": {"pof.test": key}})),
            ),
        ):
            result = evaluate_plugin_license(
                _manifest(Path(tmp)), env={"BINHOST_CONTENT_KEYS_STDIN": "1"}
            )
        self.assertEqual(result.status, "active")
        self.assertEqual(result.content_key, key)
        self.assertTrue(result.verified)

    def test_local_license_files_and_old_env_keys_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "pof.test.license.json").write_text(
                json.dumps({"plugin_id": "pof.test", "content_key": "local-key"}),
                encoding="utf-8",
            )
            result = evaluate_plugin_license(
                _manifest(root), env={"POF_CONTENT_KEY_POF_TEST": "old-env-key"}
            )
        self.assertEqual(result.status, "locked")
        self.assertEqual(result.content_key, "")

    def test_unlicensed_open_plugin_remains_available(self):
        with tempfile.TemporaryDirectory() as tmp:
            result = evaluate_plugin_license(
                _manifest(Path(tmp), required=False), env={}
            )
        self.assertEqual(result.status, "unlocked")


class TestRuntimeEncryption(unittest.TestCase):
    def tearDown(self):
        _cleanup_decrypted_plugin_cache()

    def _bundle(self, root: Path, content_key: str) -> Path:
        import hashlib
        import zipfile

        payload = io.BytesIO()
        with zipfile.ZipFile(payload, "w") as archive:
            archive.writestr(
                "manifest.json",
                json.dumps(
                    {
                        "id": "pof.test",
                        "name": "Test",
                        "version": "1.0.0",
                        "kind": "python",
                        "host": {"api_version": 1},
                        "distribution": {
                            "encrypted": True,
                            "bundle_format": "pofplug-enc",
                            "profile": "ONLINE_STANDARD",
                        },
                        "licensing": {
                            "required": True,
                            "mode": "signed-license",
                            "release_id": "release-test-1",
                        },
                        "entrypoints": {},
                    }
                ),
            )
        plaintext = payload.getvalue()
        nonce = os.urandom(12)
        ciphertext = AESGCM(base64.b64decode(content_key)).encrypt(
            nonce, plaintext, None
        )
        bundle = root / "bundle"
        (bundle / "metadata").mkdir(parents=True)
        (bundle / "payload.enc").write_bytes(ciphertext)
        (bundle / "metadata" / "encryption.json").write_text(
            json.dumps(
                {
                    "algorithm": "aes-256-gcm",
                    "nonce_b64": base64.b64encode(nonce).decode(),
                    "payload_file": "payload.enc",
                    "payload_sha256": hashlib.sha256(plaintext).hexdigest(),
                    "content_format": "zip",
                    "license_id": "release-test-1",
                }
            ),
            encoding="utf-8",
        )
        return bundle

    def test_auth_key_decrypts_encrypted_bundle(self):
        key = base64.b64encode(os.urandom(32)).decode()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._bundle(Path(tmp), key)
            license_module._STDIN_CONTENT_KEYS_CACHE = {"pof.test": key}
            with mock.patch.dict(os.environ, {"BINHOST_CONTENT_KEYS_STDIN": "1"}):
                plugin_root = _resolve_effective_plugin_root(
                    _manifest(bundle, encrypted=True)
                )
            self.assertTrue((plugin_root / "manifest.json").exists())

    def test_wrong_auth_key_cannot_decrypt_bundle(self):
        key = base64.b64encode(os.urandom(32)).decode()
        wrong_key = base64.b64encode(os.urandom(32)).decode()
        with tempfile.TemporaryDirectory() as tmp:
            bundle = self._bundle(Path(tmp), key)
            license_module._STDIN_CONTENT_KEYS_CACHE = {"pof.test": wrong_key}
            with (
                mock.patch.dict(os.environ, {"BINHOST_CONTENT_KEYS_STDIN": "1"}),
                self.assertRaises(RuntimeError),
            ):
                _resolve_effective_plugin_root(_manifest(bundle, encrypted=True))

    def test_ciphertext_hmac_is_mandatory_when_declared(self):
        self.assertFalse(_verify_payload_hmac(b"payload", "key", "bad"))
