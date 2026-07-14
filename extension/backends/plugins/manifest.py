# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PluginManifestError(ValueError):
    """Manifest plugin invalide."""


@dataclass(frozen=True)
class PluginPythonEntrypoint:
    module: str
    register: str = "register_plugin"


@dataclass(frozen=True)
class PluginEntrypoints:
    python: PluginPythonEntrypoint | None = None
    ui: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class PluginHostRequirements:
    api_version: int
    min_version: str = ""
    max_version: str = ""


@dataclass(frozen=True)
class PluginDistribution:
    encrypted: bool = False
    bundle_format: str = ""
    hmac_sha256: str = ""  # HMAC-SHA256(ciphertext) with content_key


@dataclass(frozen=True)
class PluginLicensing:
    required: bool = False
    mode: str = ""
    status: str = "unlocked"
    message: str = ""
    public_key: str = ""
    public_key_path: str = ""
    license_filename: str = ""


@dataclass(frozen=True)
class PluginManifest:
    plugin_id: str
    name: str
    version: str
    kind: str
    host: PluginHostRequirements
    distribution: PluginDistribution
    licensing: PluginLicensing
    entrypoints: PluginEntrypoints
    capabilities: dict[str, list[str]]
    dependencies: dict[str, list[str]]
    manifest_path: Path
    root_path: Path
    raw: dict[str, Any]
    min_pof_version: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.plugin_id,
            "name": self.name,
            "version": self.version,
            "kind": self.kind,
            "host": {
                "api_version": self.host.api_version,
                "min_version": self.host.min_version,
                "max_version": self.host.max_version,
            },
            "distribution": {
                "encrypted": self.distribution.encrypted,
                "bundle_format": self.distribution.bundle_format,
                "hmac_sha256": self.distribution.hmac_sha256,
            },
            "licensing": {
                "required": self.licensing.required,
                "mode": self.licensing.mode,
                "status": self.licensing.status,
                "message": self.licensing.message,
                "public_key": self.licensing.public_key,
                "public_key_path": self.licensing.public_key_path,
                "license_filename": self.licensing.license_filename,
            },
            "entrypoints": {
                "python": (
                    {
                        "module": self.entrypoints.python.module,
                        "register": self.entrypoints.python.register,
                    }
                    if self.entrypoints.python
                    else None
                ),
                "ui": self.entrypoints.ui,
            },
            "capabilities": self.capabilities,
            "commands": self.raw.get("commands") or [],
            "dependencies": self.dependencies,
            "manifest_path": str(self.manifest_path),
            "root_path": str(self.root_path),
            "ui": self.raw.get("ui") or {},
            "min_pof_version": self.min_pof_version,
        }


def _required_string(data: dict[str, Any], key: str) -> str:
    value = str(data.get(key, "") or "").strip()
    if not value:
        raise PluginManifestError(f"Champ requis manquant: {key}")
    return value


def _optional_string(data: dict[str, Any], key: str) -> str:
    return str(data.get(key, "") or "").strip()


def _optional_bool(data: dict[str, Any], key: str) -> bool:
    return data.get(key) is True


def _coerce_str_list(value: Any, field_name: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise PluginManifestError(f"{field_name} doit être une liste")
    items: list[str] = []
    for item in value:
        text = str(item or "").strip()
        if text:
            items.append(text)
    return items


def _coerce_capabilities(raw: Any) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PluginManifestError("capabilities doit être un objet")
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        out[key_text] = _coerce_str_list(value, f"capabilities.{key_text}")
    return out


def _coerce_dependencies(raw: Any) -> dict[str, list[str]]:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise PluginManifestError("dependencies doit être un objet")
    out: dict[str, list[str]] = {}
    for key, value in raw.items():
        key_text = str(key or "").strip()
        if not key_text:
            continue
        out[key_text] = _coerce_str_list(value, f"dependencies.{key_text}")
    return out


def load_plugin_manifest(path: str | Path) -> PluginManifest:
    manifest_path = Path(path).expanduser().resolve()
    if manifest_path.is_dir():
        manifest_path = manifest_path / "manifest.json"
    if not manifest_path.exists():
        raise PluginManifestError(f"Manifest introuvable: {manifest_path}")

    try:
        raw = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PluginManifestError(f"Manifest JSON invalide: {exc}") from exc

    if not isinstance(raw, dict):
        raise PluginManifestError("Le manifest doit être un objet JSON")

    host_raw = raw.get("host")
    if not isinstance(host_raw, dict):
        raise PluginManifestError("Champ requis manquant: host")
    api_version = host_raw.get("api_version")
    if not isinstance(api_version, int):
        raise PluginManifestError("host.api_version doit être un entier")

    entrypoints_raw = raw.get("entrypoints")
    if not isinstance(entrypoints_raw, dict):
        raise PluginManifestError("Champ requis manquant: entrypoints")

    distribution_raw = raw.get("distribution")
    if distribution_raw is not None and not isinstance(distribution_raw, dict):
        raise PluginManifestError("distribution doit être un objet")

    licensing_raw = raw.get("licensing")
    if licensing_raw is not None and not isinstance(licensing_raw, dict):
        raise PluginManifestError("licensing doit être un objet")

    python_entrypoint = None
    python_raw = entrypoints_raw.get("python")
    if python_raw is not None:
        if not isinstance(python_raw, dict):
            raise PluginManifestError("entrypoints.python doit être un objet")
        python_entrypoint = PluginPythonEntrypoint(
            module=_required_string(python_raw, "module"),
            register=_optional_string(python_raw, "register") or "register_plugin",
        )

    ui_raw = entrypoints_raw.get("ui")
    if ui_raw is not None and not isinstance(ui_raw, dict):
        raise PluginManifestError("entrypoints.ui doit être un objet")

    return PluginManifest(
        plugin_id=_required_string(raw, "id"),
        name=_required_string(raw, "name"),
        version=_required_string(raw, "version"),
        kind=_required_string(raw, "kind"),
        host=PluginHostRequirements(
            api_version=api_version,
            min_version=_optional_string(host_raw, "min_version"),
            max_version=_optional_string(host_raw, "max_version"),
        ),
        distribution=PluginDistribution(
            encrypted=_optional_bool(dict(distribution_raw or {}), "encrypted"),
            bundle_format=_optional_string(
                dict(distribution_raw or {}), "bundle_format"
            ),
            hmac_sha256=_optional_string(dict(distribution_raw or {}), "hmac_sha256"),
        ),
        licensing=PluginLicensing(
            required=_optional_bool(dict(licensing_raw or {}), "required"),
            mode=_optional_string(dict(licensing_raw or {}), "mode"),
            status=_optional_string(dict(licensing_raw or {}), "status") or "unlocked",
            message=_optional_string(dict(licensing_raw or {}), "message"),
            public_key=_optional_string(dict(licensing_raw or {}), "public_key"),
            public_key_path=_optional_string(
                dict(licensing_raw or {}), "public_key_path"
            ),
            license_filename=_optional_string(
                dict(licensing_raw or {}), "license_filename"
            ),
        ),
        entrypoints=PluginEntrypoints(
            python=python_entrypoint,
            ui=dict(ui_raw or {}),
        ),
        capabilities=_coerce_capabilities(raw.get("capabilities")),
        dependencies=_coerce_dependencies(raw.get("dependencies")),
        manifest_path=manifest_path,
        root_path=manifest_path.parent,
        raw=raw,
        min_pof_version=_optional_string(raw, "minPoFVersion") or None,
    )
