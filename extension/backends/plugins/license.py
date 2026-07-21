# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from typing import Any

from backends.plugins.manifest import PluginManifest

_ENV_PREFIX = "BINHOST"
_CONTENT_KEYS_STDIN_ENV = f"{_ENV_PREFIX}_CONTENT_KEYS_STDIN"
_STDIN_CONTENT_KEYS_CACHE: dict[str, str] | None = None


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


def evaluate_plugin_license(
    manifest: PluginManifest,
    *,
    env: dict[str, str] | None = None,
) -> PluginLicenseEvaluation:
    """Evaluate ONLINE_STANDARD licensing from Auth-injected stdin only."""
    content_key = _content_key_from_stdin_payload(manifest.plugin_id, env or os.environ)
    if content_key:
        return PluginLicenseEvaluation(
            status="active",
            content_key=content_key,
            verified=True,
            message="authenticated via server",
        )
    if manifest.licensing.required is not True:
        return PluginLicenseEvaluation(
            status="unlocked",
            message=manifest.licensing.message or "",
        )
    return PluginLicenseEvaluation(
        status="locked",
        message="Connexion Auth requise pour obtenir un lease valide pour cette release.",
    )


def _env_flag_enabled(raw_value: Any) -> bool:
    return str(raw_value or "").strip().lower() in {"1", "true", "yes", "on"}


def _content_key_from_stdin_payload(plugin_id: str, env_map: dict[str, str]) -> str:
    if not _env_flag_enabled(env_map.get(_CONTENT_KEYS_STDIN_ENV)):
        return ""
    keys = _load_stdin_content_keys()
    if not keys:
        return ""
    raw_id = str(plugin_id or "")
    normalized_id = raw_id.upper().replace("-", "_").replace(".", "_")
    return str(keys.get(raw_id) or keys.get(normalized_id) or "").strip()


def _load_stdin_content_keys() -> dict[str, str]:
    global _STDIN_CONTENT_KEYS_CACHE
    if _STDIN_CONTENT_KEYS_CACHE is not None:
        return _STDIN_CONTENT_KEYS_CACHE
    _STDIN_CONTENT_KEYS_CACHE = {}
    try:
        raw = sys.stdin.read()
    except Exception:
        return _STDIN_CONTENT_KEYS_CACHE
    if not raw:
        return _STDIN_CONTENT_KEYS_CACHE
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return _STDIN_CONTENT_KEYS_CACHE
    if not isinstance(payload, dict):
        return _STDIN_CONTENT_KEYS_CACHE
    raw_keys = payload.get("content_keys", {})
    if not isinstance(raw_keys, dict):
        return _STDIN_CONTENT_KEYS_CACHE
    _STDIN_CONTENT_KEYS_CACHE = {
        str(plugin_id): str(key)
        for plugin_id, key in raw_keys.items()
        if str(plugin_id or "").strip() and str(key or "").strip()
    }
    return _STDIN_CONTENT_KEYS_CACHE
