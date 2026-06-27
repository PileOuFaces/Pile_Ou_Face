# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations
import base64
import contextlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def _generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    public_pem = (
        private_key.public_key()
        .public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        .decode()
    )
    return private_key, private_pem, public_pem


def _sign_payload_pss(private_key, payload_bytes: bytes) -> str:
    sig = private_key.sign(
        payload_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )
    return base64.b64encode(sig).decode()


class TestVerifyLicenseSignatureCryptography(unittest.TestCase):
    def setUp(self):
        self.private_key, self.private_pem, self.public_pem = _generate_rsa_keypair()

    def test_valid_rsa_pss_signature_accepted(self):
        from backends.plugins.license import _verify_license_signature_pure

        payload = b'{"plugin_id":"test","licensee":"Alice"}'
        sig_b64 = _sign_payload_pss(self.private_key, payload)
        ok, msg = _verify_license_signature_pure(None, self.public_pem, payload, sig_b64)
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_tampered_payload_rejected(self):
        from backends.plugins.license import _verify_license_signature_pure

        payload = b'{"plugin_id":"test","licensee":"Alice"}'
        sig_b64 = _sign_payload_pss(self.private_key, payload)
        tampered = b'{"plugin_id":"test","licensee":"Mallory"}'
        ok, _ = _verify_license_signature_pure(None, self.public_pem, tampered, sig_b64)
        self.assertFalse(ok)

    def test_invalid_base64_signature_rejected(self):
        from backends.plugins.license import _verify_license_signature_pure

        ok, _ = _verify_license_signature_pure(None, self.public_pem, b"payload", "!!!notbase64!!!")
        self.assertFalse(ok)

    def test_no_public_key_rejected(self):
        from backends.plugins.license import _verify_license_signature_pure

        ok, _ = _verify_license_signature_pure(None, "", b"payload", "aGVsbG8=")
        self.assertFalse(ok)


class TestUnwrapContentKeyAesGcm(unittest.TestCase):
    def test_content_key_plain_returned_directly(self):
        from backends.plugins.license import _unwrap_content_key
        import os

        original = base64.b64encode(os.urandom(32)).decode()
        payload = {"content_key": original}
        result = _unwrap_content_key(payload)
        self.assertEqual(result, original)


class TestIssuedAtSeal(unittest.TestCase):
    def test_issued_at_in_future_beyond_tolerance_rejected(self):
        from backends.plugins.license import _check_issued_at_seal
        from datetime import datetime, timezone, timedelta

        future = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        ok, msg = _check_issued_at_seal(future)
        self.assertFalse(ok)
        self.assertIn("futur", msg.lower())

    def test_issued_at_within_tolerance_accepted(self):
        from backends.plugins.license import _check_issued_at_seal
        from datetime import datetime, timezone, timedelta

        slight_future = (datetime.now(timezone.utc) + timedelta(minutes=30)).isoformat()
        ok, _ = _check_issued_at_seal(slight_future)
        self.assertTrue(ok)

    def test_issued_at_absent_accepted(self):
        from backends.plugins.license import _check_issued_at_seal

        ok, _ = _check_issued_at_seal("")
        self.assertTrue(ok)

    def test_issued_at_past_accepted(self):
        from backends.plugins.license import _check_issued_at_seal
        from datetime import datetime, timezone, timedelta

        past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        ok, _ = _check_issued_at_seal(past)
        self.assertTrue(ok)


class TestGracePeriod(unittest.TestCase):
    def test_expires_yesterday_is_grace(self):
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        status, _ = _check_expiry_with_grace(yesterday)
        self.assertEqual(status, "grace")

    def test_expires_8_days_ago_is_expired(self):
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        old = (datetime.now(timezone.utc) - timedelta(days=8)).isoformat()
        status, _ = _check_expiry_with_grace(old)
        self.assertEqual(status, "expired")

    def test_not_yet_expired_is_none(self):
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        future = (datetime.now(timezone.utc) + timedelta(days=30)).isoformat()
        status, _ = _check_expiry_with_grace(future)
        self.assertIsNone(status)

    def test_absent_expires_at_is_none(self):
        from backends.plugins.license import _check_expiry_with_grace

        status, _ = _check_expiry_with_grace("")
        self.assertIsNone(status)


class TestLastVerifiedAntiClock(unittest.TestCase):
    def test_write_and_read_last_verified(self):
        import tempfile
        from unittest import mock
        from pathlib import Path
        from backends.plugins.license import _write_last_verified, _check_clock_skew

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch(
                "backends.plugins.license.compute_key_material", return_value=b"A" * 32
            ):
                _write_last_verified("pof.test", Path(tmp))
                status, _ = _check_clock_skew("pof.test", Path(tmp))
                self.assertIsNone(status)  # clock ok

    def test_clock_rolled_back_detected(self):
        import tempfile
        import json
        from unittest import mock
        from datetime import datetime, timezone, timedelta
        from pathlib import Path
        from backends.plugins.license import _check_clock_skew, _hmac_last_verified

        with tempfile.TemporaryDirectory() as tmp:
            km = b"B" * 32
            with mock.patch("backends.plugins.license.compute_key_material", return_value=km):
                future_ts = (datetime.now(timezone.utc) + timedelta(hours=2)).isoformat()
                plugin_id = "pof.test"
                data = {
                    "ts": future_ts,
                    "plugin_id": plugin_id,
                    "hmac": _hmac_last_verified(future_ts, plugin_id, km),
                }
                lv_path = Path(tmp) / f".last_verified_{plugin_id.replace('.', '_')}"
                lv_path.write_text(json.dumps(data), encoding="utf-8")
                status, _ = _check_clock_skew(plugin_id, Path(tmp))
                self.assertEqual(status, "clock_tampered")

    def test_corrupted_last_verified_ignored(self):
        import tempfile
        from pathlib import Path
        from backends.plugins.license import _check_clock_skew

        with tempfile.TemporaryDirectory() as tmp:
            lv_path = Path(tmp) / ".last_verified_pof_test"
            lv_path.write_text("not json", encoding="utf-8")
            status, _ = _check_clock_skew("pof.test", Path(tmp))
            self.assertIsNone(status)  # no false lock

    def test_hmac_mismatch_file_ignored(self):
        import tempfile
        import json
        from unittest import mock
        from datetime import datetime, timezone
        from pathlib import Path
        from backends.plugins.license import _check_clock_skew

        with tempfile.TemporaryDirectory() as tmp:
            ts = datetime.now(timezone.utc).isoformat()
            data = {"ts": ts, "plugin_id": "pof.test", "hmac": "badhmacsignature"}
            lv_path = Path(tmp) / ".last_verified_pof_test"
            lv_path.write_text(json.dumps(data), encoding="utf-8")
            with mock.patch(
                "backends.plugins.license.compute_key_material", return_value=b"C" * 32
            ):
                status, _ = _check_clock_skew("pof.test", Path(tmp))
                self.assertIsNone(status)  # ignored gracefully


class TestPayloadHmac(unittest.TestCase):
    def test_hmac_valid_accepted(self):
        import hmac as _hmac_mod
        import hashlib
        import os
        from backends.plugins.runtime import _verify_payload_hmac

        content_key = "dGVzdGtleTE="  # base64 of "testkey1"
        data = os.urandom(64)
        key_bytes = hashlib.sha256(content_key.encode()).digest()
        mac = _hmac_mod.new(key_bytes, data, hashlib.sha256).hexdigest()
        self.assertTrue(_verify_payload_hmac(data, content_key, mac))

    def test_hmac_mismatch_rejected(self):
        import os
        from backends.plugins.runtime import _verify_payload_hmac

        data = os.urandom(64)
        self.assertFalse(_verify_payload_hmac(data, "dGVzdA==", "badhmacsignature"))

    def test_hmac_absent_skipped(self):
        """No hmac_sha256 in manifest → True (backward compat)."""
        from backends.plugins.runtime import _verify_payload_hmac

        self.assertTrue(_verify_payload_hmac(b"data", "key", ""))


class TestHmacSha256InLicense(unittest.TestCase):
    """hmac_sha256 embedded in the RSA-signed license payload is read by evaluate_plugin_license."""

    def _make_evaluation_with_payload(self, extra_fields: dict):
        """Build a minimal PluginLicenseEvaluation by calling evaluate_plugin_license with a patched payload."""
        import json
        import tempfile
        from pathlib import Path
        from unittest import mock
        from backends.plugins.license import evaluate_plugin_license
        from backends.plugins.manifest import (
            PluginManifest,
            PluginDistribution,
            PluginEntrypoints,
            PluginHostRequirements,
            PluginLicensing,
        )

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest_path = tmp_path / "manifest.json"
            manifest_path.write_text("{}", encoding="utf-8")

            manifest = PluginManifest(
                plugin_id="pof.test",
                name="Test",
                version="1.0.0",
                kind="python",
                host=PluginHostRequirements(api_version=1),
                distribution=PluginDistribution(encrypted=False),
                licensing=PluginLicensing(
                    required=True,
                    public_key="-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBALRiMLAHudeSA/xKl1oWX8yXmkBPqg/P\nJpuFoO7PUWDL31LIpM0bXlrjQ7YoeFNi3bXM4RQ6R2DKmJYJVHbAVycCAwEAAQ==\n-----END PUBLIC KEY-----\n",
                ),
                entrypoints=PluginEntrypoints(),
                capabilities={},
                dependencies={},
                manifest_path=manifest_path,
                root_path=tmp_path,
                raw={},
            )

            license_payload = {
                "plugin_id": "pof.test",
                "license_id": "lic-test",
                "licensee": "Alice",
                "issued_at": "2020-01-01T00:00:00+00:00",
                "expires_at": "2099-01-01T00:00:00+00:00",
                "account_id": "",
                "features": [],
                "signature_algorithm": "rsa-sha256",
                "signature": base64.b64encode(b"dummy-sig").decode(),
                "content_key": base64.b64encode(b"A" * 32).decode(),
                **extra_fields,
            }
            license_path = tmp_path / "pof.test.license.json"
            license_path.write_text(json.dumps(license_payload), encoding="utf-8")

            with (
                mock.patch(
                    "backends.plugins.license._verify_license_signature_pure",
                    return_value=(True, ""),
                ),
                mock.patch("backends.plugins.license._write_last_verified"),
                mock.patch("backends.plugins.license._check_clock_skew", return_value=(None, "")),
            ):
                return evaluate_plugin_license(manifest, search_paths=[tmp_path])

    def test_hmac_sha256_present_in_license_propagated(self):
        evaluation = self._make_evaluation_with_payload({"hmac_sha256": "deadbeef"})
        self.assertEqual(evaluation.hmac_sha256, "deadbeef")

    def test_hmac_sha256_absent_defaults_to_empty(self):
        evaluation = self._make_evaluation_with_payload({})
        self.assertEqual(evaluation.hmac_sha256, "")

    def test_evaluation_dataclass_has_hmac_sha256_field(self):
        from backends.plugins.license import PluginLicenseEvaluation

        ev = PluginLicenseEvaluation(status="unlocked")
        self.assertEqual(ev.hmac_sha256, "")


class TestRuntimeAesGcmDecryption(unittest.TestCase):
    """Vérifie que _resolve_effective_plugin_root déchiffre un bundle AES-256-GCM."""

    def _make_gcm_bundle(self, tmp_path: Path, content_key: str) -> Path:
        import hashlib as _hashlib
        import io
        import zipfile as _zipfile
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        buf = io.BytesIO()
        with _zipfile.ZipFile(buf, "w") as zf:
            zf.writestr("manifest.json", '{"id": "pof.test", "version": "1.0.0"}')
        plaintext = buf.getvalue()

        key = base64.b64decode(content_key)
        nonce = os.urandom(12)
        ct_with_tag = AESGCM(key).encrypt(nonce, plaintext, None)

        bundle_dir = tmp_path / "bundle"
        bundle_dir.mkdir()
        (bundle_dir / "payload.enc").write_bytes(ct_with_tag)
        encryption_meta = {
            "algorithm": "aes-256-gcm",
            "nonce_b64": base64.b64encode(nonce).decode(),
            "payload_file": "payload.enc",
            "payload_sha256": _hashlib.sha256(plaintext).hexdigest(),
        }
        meta_dir = bundle_dir / "metadata"
        meta_dir.mkdir()
        (meta_dir / "encryption.json").write_text(json.dumps(encryption_meta), encoding="utf-8")
        return bundle_dir

    def _make_manifest(self, bundle_dir: Path):
        from backends.plugins.manifest import (
            PluginManifest,
            PluginDistribution,
            PluginEntrypoints,
            PluginHostRequirements,
            PluginLicensing,
        )

        return PluginManifest(
            plugin_id="pof.test",
            name="Test",
            version="1.0.0",
            kind="python",
            host=PluginHostRequirements(api_version=1),
            distribution=PluginDistribution(encrypted=True),
            licensing=PluginLicensing(required=True),
            entrypoints=PluginEntrypoints(),
            capabilities={},
            dependencies={},
            manifest_path=bundle_dir / "manifest.json",
            root_path=bundle_dir,
            raw={},
        )

    def test_aes_gcm_bundle_decrypts_successfully(self):
        from unittest import mock
        from backends.plugins.runtime import _resolve_effective_plugin_root
        from backends.plugins.license import PluginLicenseEvaluation

        content_key = base64.b64encode(os.urandom(32)).decode()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle_dir = self._make_gcm_bundle(tmp_path, content_key)
            manifest = self._make_manifest(bundle_dir)
            evaluation = PluginLicenseEvaluation(status="unlocked", content_key=content_key)
            with mock.patch(
                "backends.plugins.runtime.evaluate_plugin_license", return_value=evaluation
            ):
                plugin_root = _resolve_effective_plugin_root(manifest)
            assert (plugin_root / "manifest.json").exists()

    def test_aes_gcm_tampered_ciphertext_raises(self):
        from unittest import mock
        from backends.plugins.runtime import _resolve_effective_plugin_root
        from backends.plugins.license import PluginLicenseEvaluation

        content_key = base64.b64encode(os.urandom(32)).decode()

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            bundle_dir = self._make_gcm_bundle(tmp_path, content_key)
            enc_path = bundle_dir / "payload.enc"
            data = bytearray(enc_path.read_bytes())
            data[0] ^= 0xFF
            enc_path.write_bytes(bytes(data))
            manifest = self._make_manifest(bundle_dir)
            evaluation = PluginLicenseEvaluation(status="unlocked", content_key=content_key)
            with mock.patch(
                "backends.plugins.runtime.evaluate_plugin_license", return_value=evaluation
            ):
                with self.assertRaises(RuntimeError):
                    _resolve_effective_plugin_root(manifest)


# ---------------------------------------------------------------------------
# Shared base for tests that exercise evaluate_plugin_license end-to-end.
# ---------------------------------------------------------------------------


class _LicenseEvalBase(unittest.TestCase):
    """Helpers shared by security tests for evaluate_plugin_license."""

    def _make_manifest(
        self, tmp_path, *, plugin_id="pof.test", required=True, public_pem="", license_filename=""
    ):
        from backends.plugins.manifest import (
            PluginManifest,
            PluginDistribution,
            PluginEntrypoints,
            PluginHostRequirements,
            PluginLicensing,
        )

        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text("{}", encoding="utf-8")
        return PluginManifest(
            plugin_id=plugin_id,
            name="Test",
            version="1.0.0",
            kind="python",
            host=PluginHostRequirements(api_version=1),
            distribution=PluginDistribution(encrypted=False),
            licensing=PluginLicensing(
                required=required,
                public_key=public_pem,
                license_filename=license_filename,
            ),
            entrypoints=PluginEntrypoints(),
            capabilities={},
            dependencies={},
            manifest_path=manifest_path,
            root_path=tmp_path,
            raw={},
        )

    def _write_license(self, license_dir, plugin_id="pof.test", **overrides):
        payload = {
            "plugin_id": plugin_id,
            "license_id": "lic-test",
            "licensee": "Alice",
            "issued_at": "2020-01-01T00:00:00+00:00",
            "expires_at": "2099-01-01T00:00:00+00:00",
            "account_id": "acct-001",
            "features": ["feat.a"],
            "content_key": base64.b64encode(b"A" * 32).decode(),
            "signature": base64.b64encode(b"dummy").decode(),
        }
        payload.update(overrides)
        path = license_dir / f"{plugin_id}.license.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def _sig_clock_mocks(self):
        """ExitStack patching signature/clock/write for tests reaching the full eval path."""
        stack = contextlib.ExitStack()
        stack.enter_context(
            mock.patch(
                "backends.plugins.license._verify_license_signature_pure",
                return_value=(True, ""),
            )
        )
        stack.enter_context(mock.patch("backends.plugins.license._write_last_verified"))
        stack.enter_context(
            mock.patch(
                "backends.plugins.license._check_clock_skew",
                return_value=(None, ""),
            )
        )
        return stack


# ---------------------------------------------------------------------------
# evaluate_plugin_license — security paths
# ---------------------------------------------------------------------------


class TestEvaluatePluginLicenseSecurityPaths(_LicenseEvalBase):
    """End-to-end security tests covering every short-circuit path in evaluate_plugin_license."""

    def test_env_content_key_returns_active_bypassing_all_checks(self):
        """POF_CONTENT_KEY_POF_TEST env var → status=active, no license file needed."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp))
            result = evaluate_plugin_license(
                manifest, env={"POF_CONTENT_KEY_POF_TEST": "mycontentkey"}, search_paths=[]
            )
        self.assertEqual(result.status, "active")
        self.assertEqual(result.content_key, "mycontentkey")
        self.assertTrue(result.verified)

    def test_env_content_key_uses_plugin_id_format(self):
        """pof.vulnerability-audit-pro → POF_CONTENT_KEY_POF_VULNERABILITY_AUDIT_PRO."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp), plugin_id="pof.vulnerability-audit-pro")
            result = evaluate_plugin_license(
                manifest,
                env={"POF_CONTENT_KEY_POF_VULNERABILITY_AUDIT_PRO": "secretkey"},
                search_paths=[],
            )
        self.assertEqual(result.status, "active")
        self.assertEqual(result.content_key, "secretkey")

    def test_wrong_env_var_format_is_not_matched(self):
        """Env var with wrong name (hyphen instead of underscore) is not matched."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp), plugin_id="pof.test")
            # Hyphen: POF_CONTENT_KEY_POF-TEST — wrong, correct is POF_CONTENT_KEY_POF_TEST
            result = evaluate_plugin_license(
                manifest,
                env={"POF_CONTENT_KEY_POF-TEST": "mykey"},
                search_paths=[],
            )
        self.assertNotEqual(result.status, "active")

    def test_disable_license_fallback_env_returns_locked_immediately(self):
        """BINHOST_DISABLE_LICENSE_FALLBACK=1 → locked without reading any license file."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp), public_pem="placeholder")
            result = evaluate_plugin_license(
                manifest,
                env={"BINHOST_DISABLE_LICENSE_FALLBACK": "1"},
                search_paths=[],
            )
        self.assertEqual(result.status, "locked")

    def test_licensing_not_required_returns_unlocked(self):
        """licensing.required=False → unlocked without any further checks."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp), required=False)
            result = evaluate_plugin_license(manifest, env={}, search_paths=[])
        self.assertEqual(result.status, "unlocked")

    def test_no_public_key_returns_locked(self):
        """Both public_key and public_key_path absent → locked with informative message."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            manifest = self._make_manifest(Path(tmp), public_pem="")
            result = evaluate_plugin_license(manifest, env={}, search_paths=[])
        self.assertEqual(result.status, "locked")
        self.assertIn("publique", result.message.lower())

    def test_license_file_not_found_returns_locked(self):
        """No license file in search paths → locked with 'absent' message."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            result = evaluate_plugin_license(
                manifest, env={}, search_paths=[tmp_path / "nonexistent"]
            )
        self.assertEqual(result.status, "locked")
        self.assertIn("absente", result.message.lower())

    def test_license_malformed_json_returns_locked(self):
        """Malformed JSON license file → locked with 'illisible' message."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            (license_dir / "pof.test.license.json").write_text("not valid json{{", encoding="utf-8")
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")
        self.assertIn("illisible", result.message.lower())

    def test_license_not_dict_returns_locked(self):
        """License is a JSON array → locked."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            (license_dir / "pof.test.license.json").write_text(
                '["not", "a", "dict"]', encoding="utf-8"
            )
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")

    def test_plugin_id_mismatch_returns_locked(self):
        """License plugin_id does not match manifest.plugin_id → locked."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            (license_dir / "pof.test.license.json").write_text(
                json.dumps(
                    {
                        "plugin_id": "pof.other-plugin",  # mismatch
                        "license_id": "lic-test",
                        "signature": base64.b64encode(b"dummy").decode(),
                    }
                ),
                encoding="utf-8",
            )
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")
        self.assertIn("correspond", result.message.lower())

    def test_missing_signature_field_returns_locked(self):
        """License without signature field → locked with 'signature' in message."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            (license_dir / "pof.test.license.json").write_text(
                json.dumps({"plugin_id": "pof.test", "license_id": "lic-001"}),
                encoding="utf-8",
            )
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")
        self.assertIn("signature", result.message.lower())

    def test_invalid_signature_returns_locked(self):
        """Garbage signature bytes against a real RSA key → locked (real crypto path)."""
        from backends.plugins.license import evaluate_plugin_license

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_pem = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir)  # dummy sig = base64.b64encode(b"dummy")
            manifest = self._make_manifest(tmp_path, public_pem=public_pem)
            result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")

    def test_valid_license_returns_unlocked_with_content_key_and_features(self):
        """Full valid path (mocked sig) → unlocked with content_key and features."""
        from backends.plugins.license import evaluate_plugin_license

        expected_key = base64.b64encode(b"B" * 32).decode()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(
                license_dir, content_key=expected_key, features=["feat.a", "feat.b"]
            )
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with self._sig_clock_mocks():
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "unlocked")
        self.assertEqual(result.content_key, expected_key)
        self.assertEqual(result.features, ["feat.a", "feat.b"])
        self.assertTrue(result.verified)

    def test_expired_license_returns_expired_with_empty_content_key(self):
        """License expired > 7 days ago → status=expired, content_key=''."""
        from backends.plugins.license import evaluate_plugin_license
        from datetime import datetime, timezone, timedelta

        old = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir, expires_at=old)
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with self._sig_clock_mocks():
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "expired")
        self.assertEqual(result.content_key, "")
        self.assertTrue(result.verified)  # signature was valid

    def test_grace_period_returns_grace_status_with_content_key(self):
        """License expired 1 day ago → status=grace, content_key still provided."""
        from backends.plugins.license import evaluate_plugin_license
        from datetime import datetime, timezone, timedelta

        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
        expected_key = base64.b64encode(b"C" * 32).decode()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir, expires_at=yesterday, content_key=expected_key)
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with self._sig_clock_mocks():
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "grace")
        self.assertEqual(result.content_key, expected_key)

    def test_issued_at_in_future_returns_locked(self):
        """issued_at 48h in future → locked (seal check)."""
        from backends.plugins.license import evaluate_plugin_license
        from datetime import datetime, timezone, timedelta

        future = (datetime.now(timezone.utc) + timedelta(hours=48)).isoformat()
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir, issued_at=future)
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with (
                mock.patch(
                    "backends.plugins.license._verify_license_signature_pure",
                    return_value=(True, ""),
                ),
                mock.patch("backends.plugins.license._check_clock_skew", return_value=(None, "")),
            ):
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "locked")
        self.assertIn("futur", result.message.lower())

    def test_features_whitespace_only_strings_filtered(self):
        """features containing only whitespace strings are filtered out."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir, features=["  ", "valid.feature", ""])
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with self._sig_clock_mocks():
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.features, ["valid.feature"])

    def test_content_key_absent_in_license_returns_empty(self):
        """License without content_key → content_key='' in evaluation."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir, content_key="")
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with self._sig_clock_mocks():
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.content_key, "")

    def test_clock_tampered_returns_clock_tampered_status(self):
        """Clock rollback detected → status=clock_tampered."""
        from backends.plugins.license import evaluate_plugin_license

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            license_dir = tmp_path / "licenses"
            license_dir.mkdir()
            self._write_license(license_dir)
            manifest = self._make_manifest(tmp_path, public_pem="placeholder")
            with (
                mock.patch(
                    "backends.plugins.license._verify_license_signature_pure",
                    return_value=(True, ""),
                ),
                mock.patch(
                    "backends.plugins.license._check_clock_skew",
                    return_value=("clock_tampered", "Horloge modifiée."),
                ),
            ):
                result = evaluate_plugin_license(manifest, env={}, search_paths=[license_dir])
        self.assertEqual(result.status, "clock_tampered")


# ---------------------------------------------------------------------------
# _verify_license_signature_pure — edge cases
# ---------------------------------------------------------------------------


class TestVerifyLicenseSignaturePureEdgeCases(unittest.TestCase):
    def setUp(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.private_key = private_key
        self.public_pem = (
            private_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )

    def test_pkcs1v15_fallback_signature_accepted(self):
        """Legacy PKCS1v15 signature is accepted via fallback verification."""
        from backends.plugins.license import _verify_license_signature_pure

        payload = b'{"plugin_id":"pof.test","licensee":"Alice"}'
        sig = self.private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()
        ok, msg = _verify_license_signature_pure(None, self.public_pem, payload, sig_b64)
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_signature_from_different_keypair_rejected(self):
        """Signature created with key A, verified against key B → False."""
        from backends.plugins.license import _verify_license_signature_pure

        other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        payload = b'{"plugin_id":"pof.test"}'
        sig = other_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        sig_b64 = base64.b64encode(sig).decode()
        ok, _ = _verify_license_signature_pure(None, self.public_pem, payload, sig_b64)
        self.assertFalse(ok)

    def test_garbage_pem_public_key_rejected(self):
        """Invalid PEM content → False with 'invalide' in message."""
        from backends.plugins.license import _verify_license_signature_pure

        garbage_pem = "-----BEGIN PUBLIC KEY-----\ngarbage==\n-----END PUBLIC KEY-----\n"
        ok, msg = _verify_license_signature_pure(None, garbage_pem, b"payload", "aGVsbG8=")
        self.assertFalse(ok)
        self.assertIn("invalide", msg.lower())

    def test_non_rsa_ec_key_rejected(self):
        """EC public key (not RSA) → False with 'rsa' in message."""
        from backends.plugins.license import _verify_license_signature_pure
        from cryptography.hazmat.primitives.asymmetric import ec

        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pub_pem = (
            ec_key.public_key()
            .public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
            )
            .decode()
        )
        ok, msg = _verify_license_signature_pure(None, ec_pub_pem, b"payload", "aGVsbG8=")
        self.assertFalse(ok)
        self.assertIn("rsa", msg.lower())

    def test_public_key_read_from_file_path(self):
        """Public key supplied as file path instead of inline PEM → verification works."""
        from backends.plugins.license import _verify_license_signature_pure

        payload = b'{"plugin_id":"pof.test"}'
        sig = self.private_key.sign(
            payload,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        sig_b64 = base64.b64encode(sig).decode()
        with tempfile.TemporaryDirectory() as tmp:
            pub_path = Path(tmp) / "public.pem"
            pub_path.write_text(self.public_pem, encoding="utf-8")
            ok, msg = _verify_license_signature_pure(pub_path, "", payload, sig_b64)
        self.assertTrue(ok)
        self.assertEqual(msg, "")

    def test_nonexistent_public_key_file_returns_false(self):
        """Public key file path does not exist → False with 'illisible' in message."""
        from backends.plugins.license import _verify_license_signature_pure

        ok, msg = _verify_license_signature_pure(
            Path("/nonexistent/pub.pem"), "", b"payload", "aGVsbG8="
        )
        self.assertFalse(ok)
        self.assertIn("illisible", msg.lower())


# ---------------------------------------------------------------------------
# _parse_datetime — edge cases
# ---------------------------------------------------------------------------


class TestParseDatetimeEdgeCases(unittest.TestCase):
    def test_date_only_format_parsed_as_utc_midnight(self):
        """'2025-06-01' → UTC midnight datetime."""
        from backends.plugins.license import _parse_datetime
        from datetime import timezone

        result = _parse_datetime("2025-06-01")
        assert result is not None
        self.assertEqual(result.year, 2025)
        self.assertEqual(result.month, 6)
        self.assertEqual(result.day, 1)
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_z_suffix_parsed_as_utc(self):
        """'2025-01-01T00:00:00Z' → UTC datetime."""
        from backends.plugins.license import _parse_datetime
        from datetime import timezone

        result = _parse_datetime("2025-01-01T00:00:00Z")
        assert result is not None
        self.assertEqual(result.tzinfo, timezone.utc)

    def test_naive_datetime_assumed_utc(self):
        """'2025-01-01T12:00:00' (no tz) → UTC."""
        from backends.plugins.license import _parse_datetime
        from datetime import timezone

        result = _parse_datetime("2025-01-01T12:00:00")
        assert result is not None
        self.assertEqual(result.tzinfo, timezone.utc)
        self.assertEqual(result.hour, 12)

    def test_empty_string_returns_none(self):
        from backends.plugins.license import _parse_datetime

        self.assertIsNone(_parse_datetime(""))

    def test_garbage_string_returns_none(self):
        from backends.plugins.license import _parse_datetime

        self.assertIsNone(_parse_datetime("not-a-date"))

    def test_whitespace_only_returns_none(self):
        from backends.plugins.license import _parse_datetime

        self.assertIsNone(_parse_datetime("   "))


# ---------------------------------------------------------------------------
# _check_expiry_with_grace — boundary tests
# ---------------------------------------------------------------------------


class TestGracePeriodBoundaryEdgeCases(unittest.TestCase):
    def test_not_yet_expired_returns_none(self):
        """expires_at one second in the future → not expired (None)."""
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        future = (datetime.now(timezone.utc) + timedelta(seconds=1)).isoformat()
        status, _ = _check_expiry_with_grace(future)
        self.assertIsNone(status)

    def test_one_second_past_expiry_is_grace(self):
        """expires_at one second ago → grace period."""
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        just_expired = (datetime.now(timezone.utc) - timedelta(seconds=1)).isoformat()
        status, _ = _check_expiry_with_grace(just_expired)
        self.assertEqual(status, "grace")

    def test_six_days_past_expiry_is_still_grace(self):
        """expires_at 6 days ago → grace."""
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        six_days_ago = (datetime.now(timezone.utc) - timedelta(days=6)).isoformat()
        status, _ = _check_expiry_with_grace(six_days_ago)
        self.assertEqual(status, "grace")

    def test_past_grace_period_is_expired(self):
        """expires_at 7 days + 1 second ago → expired (past grace period)."""
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        past_grace = (datetime.now(timezone.utc) - timedelta(days=7, seconds=1)).isoformat()
        status, _ = _check_expiry_with_grace(past_grace)
        self.assertEqual(status, "expired")

    def test_unparseable_expires_at_returns_none(self):
        """Garbage expires_at format → None (no expiry enforced)."""
        from backends.plugins.license import _check_expiry_with_grace

        status, _ = _check_expiry_with_grace("not-a-date")
        self.assertIsNone(status)

    def test_grace_message_includes_days_remaining(self):
        """Grace message mentions how many days are left."""
        from backends.plugins.license import _check_expiry_with_grace
        from datetime import datetime, timezone, timedelta

        three_days_ago = (datetime.now(timezone.utc) - timedelta(days=3)).isoformat()
        status, msg = _check_expiry_with_grace(three_days_ago)
        self.assertEqual(status, "grace")
        self.assertIn("jour", msg.lower())


# ---------------------------------------------------------------------------
# _check_issued_at_seal — boundary tests
# ---------------------------------------------------------------------------


class TestIssuedAtSealEdgeCases(unittest.TestCase):
    def test_within_tolerance_is_accepted(self):
        """issued_at 23h 59m in the future → within 24h tolerance → accepted."""
        from backends.plugins.license import _check_issued_at_seal
        from datetime import datetime, timezone, timedelta

        within = (datetime.now(timezone.utc) + timedelta(hours=23, minutes=59)).isoformat()
        ok, _ = _check_issued_at_seal(within)
        self.assertTrue(ok)

    def test_beyond_tolerance_is_rejected(self):
        """issued_at 25h in the future → beyond 24h tolerance → rejected."""
        from backends.plugins.license import _check_issued_at_seal
        from datetime import datetime, timezone, timedelta

        beyond = (datetime.now(timezone.utc) + timedelta(hours=25)).isoformat()
        ok, msg = _check_issued_at_seal(beyond)
        self.assertFalse(ok)
        self.assertIn("futur", msg.lower())

    def test_unparseable_issued_at_accepted(self):
        """Garbage issued_at format → accepted (no rejection on unrecognised format)."""
        from backends.plugins.license import _check_issued_at_seal

        ok, _ = _check_issued_at_seal("not-a-date")
        self.assertTrue(ok)


# ---------------------------------------------------------------------------
# _env_flag_enabled — all truthy/falsy values
# ---------------------------------------------------------------------------


class TestEnvFlagEnabled(unittest.TestCase):
    def test_recognised_truthy_values(self):
        from backends.plugins.license import _env_flag_enabled

        for value in ("1", "true", "yes", "on"):
            with self.subTest(value=value):
                self.assertTrue(_env_flag_enabled(value))

    def test_truthy_values_are_case_insensitive(self):
        from backends.plugins.license import _env_flag_enabled

        for value in ("TRUE", "True", "YES", "Yes", "ON", "On"):
            with self.subTest(value=value):
                self.assertTrue(_env_flag_enabled(value))

    def test_recognised_falsy_values(self):
        from backends.plugins.license import _env_flag_enabled

        for value in ("0", "false", "no", "off", "", "random", "2"):
            with self.subTest(value=value):
                self.assertFalse(_env_flag_enabled(value))

    def test_none_is_falsy(self):
        from backends.plugins.license import _env_flag_enabled

        self.assertFalse(_env_flag_enabled(None))


# ---------------------------------------------------------------------------
# install_license — security validation
# ---------------------------------------------------------------------------


class TestInstallLicenseSecurity(unittest.TestCase):
    def test_source_file_not_found_raises(self):
        from backends.plugins.install_license import install_license, PluginLicenseInstallError

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(PluginLicenseInstallError):
                install_license(Path(tmp) / "nonexistent.json", Path(tmp) / "licenses")

    def test_invalid_json_raises(self):
        from backends.plugins.install_license import install_license, PluginLicenseInstallError

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "bad.json"
            src.write_text("not json{{", encoding="utf-8")
            with self.assertRaises(PluginLicenseInstallError):
                install_license(src, Path(tmp) / "licenses")

    def test_missing_plugin_id_raises(self):
        from backends.plugins.install_license import install_license, PluginLicenseInstallError

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "license.json"
            src.write_text(json.dumps({"signature": "ZmFrZQ=="}), encoding="utf-8")
            with self.assertRaises(PluginLicenseInstallError) as ctx:
                install_license(src, Path(tmp) / "licenses")
            self.assertIn("plugin_id", str(ctx.exception))

    def test_missing_signature_raises(self):
        from backends.plugins.install_license import install_license, PluginLicenseInstallError

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "license.json"
            src.write_text(json.dumps({"plugin_id": "pof.test"}), encoding="utf-8")
            with self.assertRaises(PluginLicenseInstallError) as ctx:
                install_license(src, Path(tmp) / "licenses")
            self.assertIn("signature", str(ctx.exception))

    def test_non_dict_json_raises(self):
        from backends.plugins.install_license import install_license, PluginLicenseInstallError

        with tempfile.TemporaryDirectory() as tmp:
            src = Path(tmp) / "license.json"
            src.write_text('["not", "a", "dict"]', encoding="utf-8")
            with self.assertRaises(PluginLicenseInstallError):
                install_license(src, Path(tmp) / "licenses")

    def test_reinstall_overwrites_existing_license(self):
        from backends.plugins.install_license import install_license

        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "licenses"
            src = Path(tmp) / "license.json"
            src.write_text(
                json.dumps(
                    {
                        "plugin_id": "pof.test",
                        "license_id": "v1",
                        "signature": "ZmFrZQ==",
                    }
                ),
                encoding="utf-8",
            )
            install_license(src, target)
            src.write_text(
                json.dumps(
                    {
                        "plugin_id": "pof.test",
                        "license_id": "v2",
                        "signature": "ZmFrZQ==",
                    }
                ),
                encoding="utf-8",
            )
            result = install_license(src, target)
            self.assertTrue(result["ok"])
            installed = json.loads((target / "pof.test.license.json").read_text())
            self.assertEqual(installed["license_id"], "v2")


# ---------------------------------------------------------------------------
# default_license_search_paths — env var behaviour
# ---------------------------------------------------------------------------


class TestDefaultLicenseSearchPathsEdgeCases(unittest.TestCase):
    def test_extra_path_from_env_appended(self):
        """BINHOST_LICENSE_PATH → path appended to default search paths."""
        from backends.plugins.license import default_license_search_paths

        with tempfile.TemporaryDirectory() as tmp:
            extra = Path(tmp) / "extra-licenses"
            env = {"BINHOST_LICENSE_PATH": str(extra)}
            paths = default_license_search_paths(cwd="/tmp/project", home="/tmp/home", env=env)
        self.assertIn(extra, paths)

    def test_multiple_extra_paths_via_os_pathsep(self):
        """Multiple paths separated by os.pathsep → all appended."""
        from backends.plugins.license import default_license_search_paths

        with tempfile.TemporaryDirectory() as tmp:
            dir_a = Path(tmp) / "dir_a"
            dir_b = Path(tmp) / "dir_b"
            env = {"BINHOST_LICENSE_PATH": f"{dir_a}{os.pathsep}{dir_b}"}
            paths = default_license_search_paths(cwd="/tmp/project", home="/tmp/home", env=env)
        self.assertIn(dir_a, paths)
        self.assertIn(dir_b, paths)

    def test_duplicate_env_path_not_added_twice(self):
        """Duplicate path in BINHOST_LICENSE_PATH → appears once."""
        from backends.plugins.license import default_license_search_paths

        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            cwd = Path(tmp) / "project"
            extra = home / ".pile-ou-face" / "licenses"  # same as default when no workspace
            env = {"BINHOST_LICENSE_PATH": f"{extra}{os.pathsep}{extra}"}
            paths = default_license_search_paths(cwd=cwd, home=home, env=env)
        path_strs = [str(p) for p in paths]
        self.assertEqual(path_strs.count(str(extra)), 1)
