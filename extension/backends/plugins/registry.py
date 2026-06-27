# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from backends.shared.log import get_logger

from .manifest import PluginManifest, PluginManifestError, load_plugin_manifest

_log = get_logger(__name__)


@dataclass
class PluginRecord:
    plugin_id: str
    state: str
    root_path: Path
    manifest_path: Path
    manifest: PluginManifest | None = None
    error: str = ""
    license_status: str = ""
    license_message: str = ""
    license_path: str = ""
    license_id: str = ""
    licensee: str = ""
    license_verified: bool = False
    license_features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        manifest_payload = self.manifest.to_dict() if self.manifest else None
        if manifest_payload and isinstance(manifest_payload, dict):
            licensing_payload = dict(manifest_payload.get("licensing") or {})
            if self.license_status:
                licensing_payload["status"] = self.license_status
            if self.license_message:
                licensing_payload["message"] = self.license_message
            if self.license_path:
                licensing_payload["license_path"] = self.license_path
            if self.license_id:
                licensing_payload["license_id"] = self.license_id
            if self.licensee:
                licensing_payload["licensee"] = self.licensee
            licensing_payload["verified"] = self.license_verified is True
            manifest_payload["licensing"] = licensing_payload
        return {
            "id": self.plugin_id,
            "state": self.state,
            "root_path": str(self.root_path),
            "manifest_path": str(self.manifest_path),
            "error": self.error,
            "manifest": manifest_payload,
        }


def discover_plugin_dirs(search_paths: Iterable[str | Path]) -> list[Path]:
    seen: set[Path] = set()
    discovered: list[Path] = []
    for raw_path in search_paths:
        base = Path(raw_path).expanduser()
        if not base.exists() or not base.is_dir():
            continue
        for child in sorted(base.iterdir()):
            if not child.is_dir():
                continue
            manifest_path = child / "manifest.json"
            if not manifest_path.exists():
                continue
            resolved = child.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            discovered.append(resolved)
    return discovered


def _parse_version(version: str) -> tuple[int, ...]:
    items: list[int] = []
    for chunk in str(version or "").strip().split("."):
        if chunk.lower() == "x":
            items.append(-1)
            continue
        if not chunk:
            items.append(0)
            continue
        try:
            items.append(int(chunk))
        except ValueError:
            digits = "".join(ch for ch in chunk if ch.isdigit())
            items.append(int(digits) if digits else 0)
    return tuple(items)


def _is_version_compatible(host_version: str, min_version: str, max_version: str) -> bool:
    host_tuple = _parse_version(host_version)
    if min_version and host_tuple < _parse_version(min_version):
        return False
    if max_version:
        max_parts = _parse_version(max_version)
        if -1 in max_parts:
            for index, value in enumerate(max_parts):
                if value == -1:
                    break
                if index >= len(host_tuple) or host_tuple[index] != value:
                    return False
        elif host_tuple > max_parts:
            return False
    return True


def build_plugin_registry(
    search_paths: Iterable[str | Path],
    *,
    host_version: str,
    api_version: int = 1,
    disabled_plugin_ids: Iterable[str] | None = None,
) -> list[PluginRecord]:
    disabled = {str(item).strip() for item in (disabled_plugin_ids or []) if str(item).strip()}
    records: list[PluginRecord] = []
    seen_ids: set[str] = set()

    for plugin_dir in discover_plugin_dirs(search_paths):
        manifest_path = plugin_dir / "manifest.json"
        try:
            manifest = load_plugin_manifest(manifest_path)
        except PluginManifestError as exc:
            records.append(
                PluginRecord(
                    plugin_id=plugin_dir.name,
                    state="invalid",
                    root_path=plugin_dir,
                    manifest_path=manifest_path,
                    error=str(exc),
                )
            )
            continue

        if manifest.plugin_id in seen_ids:
            records.append(
                PluginRecord(
                    plugin_id=manifest.plugin_id,
                    state="invalid",
                    root_path=plugin_dir,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    error=f"Plugin dupliqué: {manifest.plugin_id}",
                )
            )
            continue
        seen_ids.add(manifest.plugin_id)

        if manifest.host.api_version != api_version:
            records.append(
                PluginRecord(
                    plugin_id=manifest.plugin_id,
                    state="incompatible",
                    root_path=plugin_dir,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    error=f"api_version incompatible: {manifest.host.api_version} != {api_version}",
                )
            )
            continue

        if not _is_version_compatible(
            host_version,
            manifest.host.min_version,
            manifest.host.max_version,
        ):
            records.append(
                PluginRecord(
                    plugin_id=manifest.plugin_id,
                    state="incompatible",
                    root_path=plugin_dir,
                    manifest_path=manifest_path,
                    manifest=manifest,
                    error=(
                        f"Version host incompatible: {host_version} "
                        f"(attendu {manifest.host.min_version or '*'} -> {manifest.host.max_version or '*'})"
                    ),
                )
            )
            continue

        state = "disabled" if manifest.plugin_id in disabled else "active"
        records.append(
            PluginRecord(
                plugin_id=manifest.plugin_id,
                state=state,
                root_path=plugin_dir,
                manifest_path=manifest_path,
                manifest=manifest,
            )
        )
    return records


def get_plugin_record(records: Iterable[PluginRecord], plugin_id: str) -> PluginRecord | None:
    plugin_id = str(plugin_id or "").strip()
    for record in records:
        if record.plugin_id == plugin_id:
            return record
    return None
