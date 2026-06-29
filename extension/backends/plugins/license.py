# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import base64
import hashlib
import hmac as _hmac
import json
import os
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from backends.plugins.manifest import PluginManifest

SIGNATURE_FIELDS = {"signature", "signature_algorithm"}

# Prefix for environment variables — rename this constant when the product is renamed.
_ENV_PREFIX = "BINHOST"
_DISABLE_LICENSE_FALLBACK_ENV = f"{_ENV_PREFIX}_DISABLE_LICENSE_FALLBACK"

_KEY_MATERIAL_CONTEXT = b"binhost-key-material-v1"


@dataclass(frozen=True)
class PluginLicenseEvaluation:
    status: str
    message: str = ""
    license_path: str = ""
    license_id: str = ""
    licensee: str = ""
    expires_at: str = ""
    account_id: str = ""
    verified: bool = False
    content_key: str = ""
    hmac_sha256: str = ""
    features: list[str] = field(default_factory=list)


def default_license_search_paths(
    *,
    cwd: str | Path | None = None,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> list[Path]:
    env_map = env or os.environ
    cwd_path = Path(cwd or Path.cwd()).expanduser().resolve()
    home_path = Path(home or Path.home()).expanduser().resolve()
    workspace_root = cwd_path / ".pile-ou-face"
    if workspace_root.is_dir():
        paths = [workspace_root / "licenses"]
    else:
        paths = [home_path / ".pile-ou-face" / "licenses"]
    extra = str(env_map.get(f"{_ENV_PREFIX}_LICENSE_PATH", "") or "").strip()
    if extra:
        for raw_item in extra.split(os.pathsep):
            item = raw_item.strip()
            if item:
                paths.append(Path(item).expanduser())
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


def evaluate_plugin_license(
    manifest: PluginManifest,
    *,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
    search_paths: list[Path] | None = None,
) -> PluginLicenseEvaluation:
    env_map = env or os.environ
    # Priorité 1 : content_key injectée par l'extension via variable d'environnement
    _env_var = "POF_CONTENT_KEY_" + manifest.plugin_id.upper().replace(
        "-", "_"
    ).replace(".", "_")
    _env_key = str(env_map.get(_env_var, "") or "").strip()
    if _env_key:
        return PluginLicenseEvaluation(
            status="active",
            content_key=_env_key,
            verified=True,
            message="authenticated via server",
            license_path="",
            license_id="",
            licensee="",
            features=[],
        )

    licensing = manifest.licensing
    if licensing.required is not True:
        return PluginLicenseEvaluation(
            status="unlocked", message=licensing.message or ""
        )

    if _env_flag_enabled(env_map.get(_DISABLE_LICENSE_FALLBACK_ENV)):
        return PluginLicenseEvaluation(
            status="locked",
            message="Connexion requise pour récupérer la clé du plugin depuis le serveur.",
        )

    public_key_path, public_key_inline = _resolve_public_key(manifest)
    if public_key_path is None and not public_key_inline:
        return PluginLicenseEvaluation(
            status="locked",
            message="Clé publique de licence introuvable dans le plugin.",
        )

    license_path = _find_license_file(
        manifest,
        search_paths=search_paths or default_license_search_paths(home=home, env=env),
    )
    if license_path is None:
        return PluginLicenseEvaluation(
            status="locked",
            message="Licence absente. Installe un fichier de licence valide.",
        )

    try:
        payload = json.loads(license_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return PluginLicenseEvaluation(
            status="locked",
            message=f"Licence illisible: {exc}",
            license_path=str(license_path),
        )
    if not isinstance(payload, dict):
        return PluginLicenseEvaluation(
            status="locked",
            message="Format de licence invalide.",
            license_path=str(license_path),
        )

    plugin_id = str(payload.get("plugin_id", "") or "").strip()
    if plugin_id != manifest.plugin_id:
        return PluginLicenseEvaluation(
            status="locked",
            message="La licence ne correspond pas à ce plugin.",
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
        )

    signature_b64 = str(payload.get("signature", "") or "").strip()
    if not signature_b64:
        return PluginLicenseEvaluation(
            status="locked",
            message="Signature de licence absente.",
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
        )

    signature_ok, verify_message = _verify_license_signature_pure(
        public_key_path,
        public_key_inline,
        _canonicalize_license_payload(payload),
        signature_b64,
    )
    if not signature_ok:
        return PluginLicenseEvaluation(
            status="locked",
            message=verify_message or "Signature de licence invalide.",
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
            licensee=str(payload.get("licensee", "") or "").strip(),
            expires_at=str(payload.get("expires_at", "") or "").strip(),
            account_id=str(payload.get("account_id", "") or "").strip(),
            verified=False,
            content_key="",
        )

    issued_at_raw = str(payload.get("issued_at", "") or "").strip()
    seal_ok, seal_message = _check_issued_at_seal(issued_at_raw)
    if not seal_ok:
        return PluginLicenseEvaluation(
            status="locked",
            message=seal_message,
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
            licensee=str(payload.get("licensee", "") or "").strip(),
        )

    lv_dir = license_path.parent
    clock_status, clock_message = _check_clock_skew(manifest.plugin_id, lv_dir)
    if clock_status == "clock_tampered":
        return PluginLicenseEvaluation(
            status="clock_tampered",
            message=clock_message,
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
            licensee=str(payload.get("licensee", "") or "").strip(),
        )

    expires_at = str(payload.get("expires_at", "") or "").strip()
    expiry_status, expiry_message = _check_expiry_with_grace(expires_at)
    if expiry_status == "expired":
        return PluginLicenseEvaluation(
            status="expired",
            message=expiry_message,
            license_path=str(license_path),
            license_id=str(payload.get("license_id", "") or "").strip(),
            licensee=str(payload.get("licensee", "") or "").strip(),
            expires_at=expires_at,
            account_id=str(payload.get("account_id", "") or "").strip(),
            verified=True,
            content_key="",
        )

    content_key = _unwrap_content_key(payload)

    features = list(payload.get("features") or [])
    if not isinstance(features, list):
        features = []
    features = [str(f).strip() for f in features if str(f).strip()]

    hmac_sha256 = str(payload.get("hmac_sha256", "") or "").strip()

    final_status = expiry_status if expiry_status == "grace" else "unlocked"
    final_message = expiry_message if expiry_status == "grace" else "Licence valide."

    _write_last_verified(manifest.plugin_id, license_path.parent)

    return PluginLicenseEvaluation(
        status=final_status,
        message=final_message,
        license_path=str(license_path),
        license_id=str(payload.get("license_id", "") or "").strip(),
        licensee=str(payload.get("licensee", "") or "").strip(),
        expires_at=expires_at,
        account_id=str(payload.get("account_id", "") or "").strip(),
        verified=True,
        content_key=content_key,
        hmac_sha256=hmac_sha256,
        features=features,
    )


def _env_flag_enabled(raw_value: Any) -> bool:
    value = str(raw_value or "").strip().lower()
    return value in {"1", "true", "yes", "on"}


def _unwrap_content_key(payload: dict[str, Any]) -> str:
    # content_key_enc is no longer generated; skip it gracefully if present
    # (backward compat: ignore it, fall through to content_key)
    return str(payload.get("content_key", "") or "").strip()


def _find_license_file(
    manifest: PluginManifest,
    *,
    search_paths: list[Path],
) -> Path | None:
    filename_hint = str(manifest.licensing.license_filename or "").strip()
    candidates = [filename_hint] if filename_hint else []
    candidates.extend(
        [
            f"{manifest.plugin_id}.license.json",
            f"{manifest.plugin_id}.json",
            f"{manifest.plugin_id.replace('.', '_')}.license.json",
        ]
    )
    for raw_path in search_paths:
        path = Path(raw_path).expanduser()
        if path.is_file():
            return path
        if not path.exists() or not path.is_dir():
            continue
        for name in candidates:
            if not name:
                continue
            candidate = path / name
            if candidate.exists() and candidate.is_file():
                return candidate.resolve()
    return None


def _resolve_public_key(manifest: PluginManifest) -> tuple[Path | None, str]:
    inline = str(manifest.licensing.public_key or "").strip()
    if inline:
        return None, inline
    raw_path = str(manifest.licensing.public_key_path or "").strip()
    if not raw_path:
        return None, ""
    candidate = Path(raw_path).expanduser()
    if not candidate.is_absolute():
        candidate = manifest.root_path / candidate
    candidate = candidate.resolve()
    if candidate.exists() and candidate.is_file():
        return candidate, ""
    return None, ""


def _canonicalize_license_payload(payload: dict[str, Any]) -> bytes:
    filtered = {
        key: payload[key]
        for key in sorted(payload.keys())
        if key not in SIGNATURE_FIELDS
    }
    return json.dumps(
        filtered,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def _verify_license_signature_pure(
    public_key_path,
    public_key_inline: str,
    payload: bytes,
    signature_b64: str,
) -> tuple[bool, str]:
    """Vérifie signature RSA-PSS ou RSA-PKCS1v15 via cryptography (pas d'openssl subprocess)."""
    from cryptography.hazmat.primitives import (
        hashes as _crypto_hashes,
    )
    from cryptography.hazmat.primitives import (
        serialization as _crypto_serial,
    )
    from cryptography.hazmat.primitives.asymmetric import padding as _asym_padding
    from cryptography.hazmat.primitives.asymmetric.rsa import (
        RSAPublicKey as _RSAPublicKey,
    )

    try:
        sig = base64.b64decode(signature_b64, validate=True)
    except Exception:
        return False, "Signature de licence invalide (base64)."

    pem_text = public_key_inline
    if not pem_text and public_key_path is not None:
        try:
            pem_text = Path(public_key_path).read_text(encoding="utf-8")
        except OSError as exc:
            return False, f"Clé publique illisible: {exc}"
    if not pem_text:
        return False, "Clé publique de licence introuvable."

    try:
        public_key = _crypto_serial.load_pem_public_key(pem_text.encode("utf-8"))
    except Exception as exc:
        return False, f"Clé publique invalide: {exc}"

    if not isinstance(public_key, _RSAPublicKey):
        return False, "Clé publique invalide : type non supporté (RSA requis)."

    rsa_key: _RSAPublicKey = public_key
    for pad in [
        _asym_padding.PSS(
            mgf=_asym_padding.MGF1(_crypto_hashes.SHA256()),
            salt_length=_asym_padding.PSS.MAX_LENGTH,
        ),
        _asym_padding.PKCS1v15(),
    ]:
        try:
            rsa_key.verify(sig, payload, pad, _crypto_hashes.SHA256())
            return True, ""
        except Exception:
            continue
    return False, "Signature de licence invalide."


_ISSUED_AT_TOLERANCE = timedelta(hours=24)
_GRACE_PERIOD = timedelta(days=7)
_CLOCK_TOLERANCE = timedelta(seconds=60)


def _last_verified_path(plugin_id: str, base_dir: Path) -> Path:
    safe_id = plugin_id.replace(".", "_").replace("/", "_")
    return base_dir / f".last_verified_{safe_id}"


def _hmac_last_verified(ts: str, plugin_id: str, key_material: bytes) -> str:
    import hmac as _hmac_mod

    msg = f"{ts}|{plugin_id}".encode()
    return _hmac_mod.new(key_material, msg, hashlib.sha256).hexdigest()


def compute_key_material() -> bytes:
    """Derives a 32-byte key material. Uses a fixed context for the last-verified HMAC."""
    import platform
    import uuid as _uuid

    raw = "|".join(
        [platform.system(), platform.machine(), platform.node(), hex(_uuid.getnode())]
    )
    return _hmac.new(
        _KEY_MATERIAL_CONTEXT, raw.encode("utf-8"), hashlib.sha256
    ).digest()


def _write_last_verified(plugin_id: str, base_dir: Path) -> None:
    """Writes the timestamp of the last successful verification."""
    try:
        km = compute_key_material()
        ts = datetime.now(UTC).isoformat()
        mac = _hmac_last_verified(ts, plugin_id, km)
        data = {"ts": ts, "plugin_id": plugin_id, "hmac": mac}
        path = _last_verified_path(plugin_id, base_dir)
        path.write_text(json.dumps(data), encoding="utf-8")
    except Exception:
        pass  # non-critical


def _check_clock_skew(plugin_id: str, base_dir: Path) -> tuple[str | None, str]:
    """Detects if the clock was rolled back since the last verification.
    Returns ('clock_tampered', message) or (None, '').
    """
    path = _last_verified_path(plugin_id, base_dir)
    if not path.exists():
        return None, ""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None, ""
    if not isinstance(data, dict):
        return None, ""

    ts_raw = str(data.get("ts", "") or "").strip()
    stored_mac = str(data.get("hmac", "") or "").strip()
    stored_plugin_id = str(data.get("plugin_id", "") or "").strip()

    if not ts_raw or not stored_mac:
        return None, ""

    try:
        km = compute_key_material()
        expected_mac = _hmac_last_verified(ts_raw, stored_plugin_id, km)
        import hmac as _hmac_mod

        if not _hmac_mod.compare_digest(expected_mac, stored_mac):
            return None, ""  # invalid HMAC → ignore (no false lock)
    except Exception:
        return None, ""

    last_ts = _parse_datetime(ts_raw)
    if last_ts is None:
        return None, ""
    now = datetime.now(UTC)
    if now < last_ts - _CLOCK_TOLERANCE:
        return "clock_tampered", "Horloge système modifiée. Licence verrouillée."
    return None, ""


def _check_issued_at_seal(issued_at: str) -> tuple[bool, str]:
    """Rejette une licence dont issued_at est dans le futur au-delà de la tolérance."""
    if not issued_at:
        return True, ""
    moment = _parse_datetime(issued_at)
    if moment is None:
        return True, ""  # format inconnu → pas de rejet
    now = datetime.now(UTC)
    if moment > now + _ISSUED_AT_TOLERANCE:
        return False, "Licence invalide : date d'émission dans le futur."
    return True, ""


def _check_expiry_with_grace(expires_at: str) -> tuple[str | None, str]:
    """Returns (status, message) or (None, '') if not yet expired.
    status can be 'grace' or 'expired'.
    """
    if not expires_at:
        return None, ""
    moment = _parse_datetime(expires_at)
    if moment is None:
        return None, ""
    now = datetime.now(UTC)
    if now <= moment:
        return None, ""
    if now <= moment + _GRACE_PERIOD:
        days_left = (_GRACE_PERIOD - (now - moment)).days + 1
        return (
            "grace",
            f"Licence expirée. Période de grâce : {days_left} jour(s) restant(s).",
        )
    return "expired", "La licence a expiré."


def _parse_datetime(value: str) -> datetime | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    normalized = raw.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(raw, "%Y-%m-%d")
        except ValueError:
            return None
        parsed = parsed.replace(tzinfo=UTC)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)
