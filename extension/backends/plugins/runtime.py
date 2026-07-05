# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import atexit
import base64 as _base64
import hashlib
import hmac as _hmac_mod
import importlib
import importlib.util
import inspect
import json
import os
import sys
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import contextlib

from backends.plugins.license import (
    _ENV_PREFIX as _LICENSE_ENV_PREFIX,
)
from backends.plugins.license import (
    default_license_search_paths,
    evaluate_plugin_license,
)
from backends.plugins.manifest import (
    PluginManifest,
    PluginManifestError,
    load_plugin_manifest,
)
from backends.plugins.registry import (
    PluginRecord,
    build_plugin_registry,
    get_plugin_record,
)
from backends.shared.log import configure_logging, get_logger

_log = get_logger(__name__)
HOST_API_VERSION = 1
DEFAULT_HOST_VERSION = "0.1.0"
# Must stay in sync with window.PoF.version in extension/front/shared/state.js
POF_VERSION = "1.0.0"
_DECRYPTED_PLUGIN_CACHE: dict[str, Path] = {}
_DECRYPTED_PLUGIN_TEMPS: list[tempfile.TemporaryDirectory[str]] = []


def _check_pof_compatibility(manifest: PluginManifest, pof_version: str) -> None:
    """Raise PluginManifestError if plugin requires a higher window.PoF version than the host provides."""
    min_ver = manifest.min_pof_version
    if not min_ver:
        return
    from packaging.version import InvalidVersion, Version

    try:
        required = Version(min_ver)
        provided = Version(pof_version)
    except InvalidVersion as exc:
        raise PluginManifestError(
            f"{manifest.plugin_id}: minPoFVersion invalide '{min_ver}': {exc}"
        ) from exc
    if provided < required:
        raise PluginManifestError(
            f"{manifest.plugin_id} requiert window.PoF >= {min_ver} "
            f"(cette version de l'extension fournit {pof_version}). "
            f"Mettez à jour l'extension."
        )


def _cleanup_decrypted_plugin_cache() -> None:
    while _DECRYPTED_PLUGIN_TEMPS:
        temp_dir = _DECRYPTED_PLUGIN_TEMPS.pop()
        try:
            temp_dir.cleanup()
        except Exception:  # pragma: no cover - defensive cleanup
            pass
    _DECRYPTED_PLUGIN_CACHE.clear()


atexit.register(_cleanup_decrypted_plugin_cache)


def _verify_payload_hmac(
    payload_bytes: bytes, content_key: str, expected_hex: str
) -> bool:
    """Verifies HMAC-SHA256 of the ciphertext with the content_key.
    Returns True if expected_hex is absent (backward compat).
    """
    if not expected_hex:
        return True  # field absent → skip
    if not content_key:
        return False
    try:
        key_bytes = hashlib.sha256(content_key.encode("utf-8")).digest()
        mac = _hmac_mod.new(key_bytes, payload_bytes, hashlib.sha256).hexdigest()
        return _hmac_mod.compare_digest(mac, expected_hex)
    except Exception:
        return False


def default_plugin_search_paths(
    *,
    cwd: str | Path | None = None,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> list[Path]:
    env_map = env or os.environ
    extra = str(env_map.get(f"{_LICENSE_ENV_PREFIX}_PLUGIN_PATH", "") or "").strip()
    if extra:
        paths = [
            Path(item.strip()).expanduser()
            for item in extra.split(os.pathsep)
            if item.strip()
        ]
    else:
        paths = []
    cwd_path = Path(cwd or Path.cwd()).expanduser().resolve()
    home_path = Path(home or Path.home()).expanduser().resolve()
    if not paths:
        workspace_root = cwd_path / ".pile-ou-face"
        if workspace_root.is_dir():
            paths = [workspace_root / "plugins"]
        else:
            paths = [home_path / ".pile-ou-face" / "plugins"]
    unique: list[Path] = []
    seen: set[Path] = set()
    for path in paths:
        resolved = path.resolve() if path.exists() else path
        if resolved in seen:
            continue
        seen.add(resolved)
        unique.append(path)
    return unique


@dataclass
class PluginContext:
    host_version: str
    api_version: int
    paths: dict[str, str]
    logger: Any = field(default_factory=lambda: _log)
    analysis_enrichers: dict[str, list[Any]] = field(default_factory=dict)
    ui_panels: dict[str, dict[str, Any]] = field(default_factory=dict)
    exporters: dict[str, Any] = field(default_factory=dict)
    commands: dict[str, Any] = field(default_factory=dict)
    command_sources: dict[str, str] = field(default_factory=dict)
    current_plugin_id: str = ""

    def register_analysis_enricher(self, target: str, callback: Any) -> None:
        target_name = str(target or "").strip()
        if not target_name:
            raise ValueError("target vide")
        self.analysis_enrichers.setdefault(target_name, []).append(callback)

    def register_ui_panel(self, panel_id: str, descriptor: dict[str, Any]) -> None:
        panel_name = str(panel_id or "").strip()
        if not panel_name:
            raise ValueError("panel_id vide")
        self.ui_panels[panel_name] = dict(descriptor or {})

    def register_exporter(self, exporter_id: str, callback: Any) -> None:
        exporter_name = str(exporter_id or "").strip()
        if not exporter_name:
            raise ValueError("exporter_id vide")
        self.exporters[exporter_name] = callback

    def register_command(self, command_id: str, callback: Any) -> None:
        command_name = str(command_id or "").strip()
        if not command_name:
            raise ValueError("command_id vide")
        self.commands[command_name] = callback
        if self.current_plugin_id:
            self.command_sources[command_name] = self.current_plugin_id

    def snapshot(self) -> dict[str, Any]:
        return {
            "analysis_enrichers": {
                key: len(value)
                for key, value in sorted(self.analysis_enrichers.items())
            },
            "ui_panels": sorted(self.ui_panels.keys()),
            "exporters": sorted(self.exporters.keys()),
            "commands": sorted(self.commands.keys()),
            "command_sources": dict(sorted(self.command_sources.items())),
        }


@contextlib.contextmanager
def _plugin_python_path(plugin_root: Path):
    python_root = plugin_root / "python"
    inserted = False
    if python_root.is_dir():
        python_root_text = str(python_root)
        if python_root_text not in sys.path:
            sys.path.insert(0, python_root_text)
            inserted = True
    try:
        yield
    finally:
        if inserted:
            with contextlib.suppress(ValueError):
                sys.path.remove(str(python_root))


def _load_plugin_module(
    manifest: PluginManifest, *, license_search_paths: list[Path] | None = None
):
    entrypoint = manifest.entrypoints.python
    if entrypoint is None:
        return None
    plugin_root = _resolve_effective_plugin_root(
        manifest, license_search_paths=license_search_paths
    )
    python_root = plugin_root / "python"
    unique_name = f"pof_plugin_{manifest.plugin_id.replace('.', '_').replace('-', '_')}"
    if python_root.is_dir():
        module_rel = entrypoint.module.replace(".", os.sep)
        for suffix in (".py", ".pyc"):
            module_path = python_root / f"{module_rel}{suffix}"
            if module_path.exists():
                spec = importlib.util.spec_from_file_location(unique_name, module_path)
                if spec is None or spec.loader is None:
                    raise ImportError(f"Spec introuvable pour {module_path}")
                module = importlib.util.module_from_spec(spec)
                sys.modules[unique_name] = module
                with _plugin_python_path(plugin_root):
                    spec.loader.exec_module(module)
                return module
    return importlib.import_module(entrypoint.module)


def _resolve_effective_plugin_root(
    manifest: PluginManifest,
    *,
    license_search_paths: list[Path] | None = None,
) -> Path:
    if manifest.distribution.encrypted is not True:
        return manifest.root_path
    cache_key = str(manifest.root_path)
    cached = _DECRYPTED_PLUGIN_CACHE.get(cache_key)
    if cached and cached.exists():
        return cached

    evaluation = evaluate_plugin_license(manifest, search_paths=license_search_paths)
    if evaluation.status not in ("unlocked", "grace", "active"):
        raise RuntimeError(
            evaluation.message
            or f"Le plugin {manifest.plugin_id} est chiffré et nécessite une licence valide."
        )
    content_key = str(evaluation.content_key or "").strip()
    if not content_key:
        raise RuntimeError("La licence valide ne contient pas de clé de déchiffrement.")

    metadata_path = manifest.root_path / "metadata" / "encryption.json"
    if not metadata_path.exists():
        raise RuntimeError("Bundle chiffré invalide: metadata/encryption.json absent.")
    try:
        encryption_meta = json.loads(metadata_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Metadata de chiffrement invalide: {exc}") from exc
    if not isinstance(encryption_meta, dict):
        raise RuntimeError("Metadata de chiffrement invalide.")

    payload_name = str(encryption_meta.get("payload_file", "") or "payload.enc").strip()
    payload_sha256 = str(encryption_meta.get("payload_sha256", "") or "").strip()
    algorithm = str(encryption_meta.get("algorithm", "") or "").strip()
    payload_path = manifest.root_path / payload_name
    if not payload_path.exists():
        raise RuntimeError(f"Bundle chiffré invalide: payload absent ({payload_name}).")
    if algorithm != "aes-256-gcm":
        raise RuntimeError(
            f"Algorithme de chiffrement non supporté: {algorithm or 'inconnu'!r}"
        )

    nonce_b64 = str(encryption_meta.get("nonce_b64", "") or "").strip()
    if not nonce_b64:
        raise RuntimeError(
            "Bundle chiffré invalide: nonce_b64 absent dans encryption.json."
        )

    raw_ciphertext = payload_path.read_bytes()

    # Prefer HMAC from RSA-signed license (tamper-proof); fall back to manifest for older bundles.
    hmac_expected = (
        str(getattr(evaluation, "hmac_sha256", "") or "").strip()
        or str(getattr(manifest.distribution, "hmac_sha256", "") or "").strip()
    )
    if not _verify_payload_hmac(raw_ciphertext, content_key, hmac_expected):
        raise RuntimeError("Intégrité du module compromise : HMAC ciphertext invalide.")

    try:
        key = _base64.b64decode(content_key)
        nonce = _base64.b64decode(nonce_b64)
        plaintext = _AESGCM(key).decrypt(nonce, raw_ciphertext, None)
    except Exception as exc:
        raise RuntimeError(
            f"Impossible de déchiffrer le plugin avec cette licence: {exc}"
        ) from exc

    temp_dir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="pof-plugin-runtime-"
    )
    temp_root = Path(temp_dir.name)
    with contextlib.suppress(OSError):
        temp_root.chmod(0o700)
    payload_zip = temp_root / "payload.zip"
    payload_zip.write_bytes(plaintext)

    if payload_sha256:
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != payload_sha256:
            temp_dir.cleanup()
            raise RuntimeError(
                "Le payload déchiffré ne correspond pas au checksum attendu."
            )
    plugin_root = temp_root / "plugin"
    with zipfile.ZipFile(payload_zip) as archive:
        archive.extractall(plugin_root)
    with contextlib.suppress(OSError):
        payload_zip.chmod(0o600)
    if not (plugin_root / "manifest.json").exists():
        temp_dir.cleanup()
        raise RuntimeError("Bundle déchiffré invalide: manifest.json absent.")
    try:
        for path in plugin_root.rglob("*"):
            if path.is_dir():
                path.chmod(0o700)
            elif path.is_file():
                path.chmod(0o600)
    except OSError:
        pass
    _DECRYPTED_PLUGIN_CACHE[cache_key] = plugin_root
    _DECRYPTED_PLUGIN_TEMPS.append(temp_dir)
    return plugin_root


def attach_plugins(
    records: list[PluginRecord],
    *,
    host_version: str = DEFAULT_HOST_VERSION,
    api_version: int = HOST_API_VERSION,
    license_search_paths: list[Path] | None = None,
) -> tuple[PluginContext, list[PluginRecord]]:
    context = PluginContext(
        host_version=host_version,
        api_version=api_version,
        paths={"cwd": str(Path.cwd()), "home": str(Path.home())},
    )
    for record in records:
        if record.state != "active" or record.manifest is None:
            continue
        try:
            _check_pof_compatibility(record.manifest, POF_VERSION)
        except Exception as exc:
            _log.warning("plugin attach failed for %s: %s", record.plugin_id, exc)
            record.state = "failed"
            record.error = str(exc)
            continue
        entrypoint = record.manifest.entrypoints.python
        if entrypoint is None:
            continue
        try:
            context.current_plugin_id = record.plugin_id
            module = _load_plugin_module(
                record.manifest, license_search_paths=license_search_paths
            )
            register = getattr(module, entrypoint.register)
            plugin_root = _resolve_effective_plugin_root(
                record.manifest, license_search_paths=license_search_paths
            )
            with _plugin_python_path(plugin_root):
                register(context)
        except Exception as exc:  # pragma: no cover - safety net
            _log.warning("plugin attach failed for %s: %s", record.plugin_id, exc)
            record.state = "failed"
            record.error = str(exc)
        finally:
            context.current_plugin_id = ""
    return context, records


def apply_plugin_licensing(
    records: list[PluginRecord],
    *,
    search_paths: list[Path] | None = None,
) -> list[PluginRecord]:
    for record in records:
        manifest = record.manifest
        if manifest is None:
            continue
        evaluation = evaluate_plugin_license(manifest, search_paths=search_paths)
        record.license_status = evaluation.status
        record.license_message = evaluation.message
        record.license_path = evaluation.license_path
        record.license_id = evaluation.license_id
        record.licensee = evaluation.licensee
        record.license_verified = evaluation.verified
        record.license_features = list(evaluation.features)
        if record.state == "active" and evaluation.status not in (
            "unlocked",
            "grace",
            "active",
        ):
            record.state = "locked"
            if not record.error and evaluation.message:
                record.error = evaluation.message
    return records


def invoke_plugin_command(
    records: list[PluginRecord],
    command_id: str,
    payload: dict[str, Any] | None = None,
    *,
    host_version: str = DEFAULT_HOST_VERSION,
    api_version: int = HOST_API_VERSION,
    license_search_paths: list[Path] | None = None,
) -> tuple[dict[str, Any], PluginContext, list[PluginRecord]]:
    context, attached_records = attach_plugins(
        records,
        host_version=host_version,
        api_version=api_version,
        license_search_paths=license_search_paths,
    )
    command_name = str(command_id or "").strip()
    if not command_name:
        return (
            {
                "ok": False,
                "error": "command_id vide",
                "command": "",
                "available_commands": sorted(context.commands.keys()),
            },
            context,
            attached_records,
        )
    callback = context.commands.get(command_name)
    if callback is None:
        return (
            {
                "ok": False,
                "error": f"Commande plugin introuvable: {command_name}",
                "command": command_name,
                "available_commands": sorted(context.commands.keys()),
            },
            context,
            attached_records,
        )

    # Feature enforcement: if the license restricts features, only allow listed commands.
    source_plugin_id = context.command_sources.get(command_name, "")
    for record in attached_records:
        if record.plugin_id == source_plugin_id and record.license_features:
            if command_name not in record.license_features:
                return (
                    {
                        "ok": False,
                        "error": f"Commande non autorisée par la licence: {command_name}",
                        "command": command_name,
                        "available_commands": sorted(context.commands.keys()),
                    },
                    context,
                    attached_records,
                )
            break

    def _invoke_fn(cmd: str, sub_payload: dict | None = None) -> dict:
        """Permet à un plugin d'invoquer une autre commande depuis le même contexte."""
        sub_cb = context.commands.get(str(cmd or "").strip())
        if sub_cb is None:
            return {"plugin_required": cmd, "error": f"Commande introuvable: {cmd}"}
        try:
            sub_sig = inspect.signature(sub_cb)
            if len(sub_sig.parameters) >= 2:
                return sub_cb(dict(sub_payload or {}), _invoke_fn)
            return sub_cb(dict(sub_payload or {}))
        except Exception as sub_exc:
            return {"error": str(sub_exc)}

    try:
        sig = inspect.signature(callback)
        if len(sig.parameters) >= 2:
            result = callback(dict(payload or {}), _invoke_fn)
        else:
            result = callback(dict(payload or {}))
        return (
            {
                "ok": True,
                "command": command_name,
                "result": result,
            },
            context,
            attached_records,
        )
    except Exception as exc:  # pragma: no cover - defensive boundary
        _log.warning("plugin command failed for %s: %s", command_name, exc)
        return (
            {
                "ok": False,
                "error": str(exc),
                "command": command_name,
                "available_commands": sorted(context.commands.keys()),
            },
            context,
            attached_records,
        )


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _normalize_feature_name(value: Any) -> str:
    text = str(value or "").strip().lower()
    out = []
    prev_sep = False
    for char in text:
        if char.isalnum():
            out.append(char)
            prev_sep = False
        elif not prev_sep:
            out.append("_")
            prev_sep = True
    return "".join(out).strip("_")


def _feature_tokens(value: Any) -> set[str]:
    text = str(value or "").strip()
    if not text:
        return set()
    tokens = {_normalize_feature_name(text)}
    parts = [part for part in text.replace("-", ".").split(".") if part]
    if parts:
        tokens.add(_normalize_feature_name(parts[0]))
        if len(parts) >= 2 and parts[-1] in {"run", "enrich", "build", "tag"}:
            tokens.add(_normalize_feature_name(".".join(parts[:-1])))
            tokens.add(_normalize_feature_name(parts[-2]))
    return {token for token in tokens if token}


def _iter_declared_command_specs(manifest: PluginManifest) -> list[dict[str, Any]]:
    raw = manifest.raw if isinstance(manifest.raw, dict) else {}
    specs: list[dict[str, Any]] = []

    for item in _as_list(raw.get("commands")):
        if isinstance(item, dict):
            specs.append(item)

    ui = raw.get("ui") if isinstance(raw.get("ui"), dict) else {}
    for tab in _as_list(ui.get("tabs")):
        if not isinstance(tab, dict):
            continue
        command = str(tab.get("command") or tab.get("command_id") or "").strip()
        if not command:
            continue
        feature = str(
            tab.get("feature") or tab.get("feature_id") or tab.get("tabId") or ""
        ).strip()
        aliases = _as_list(tab.get("aliases"))
        specs.append(
            {
                "id": command,
                "feature": feature,
                "aliases": aliases,
                "tabId": tab.get("tabId"),
                "label": tab.get("label"),
            }
        )

    capabilities = raw.get("capabilities")
    if isinstance(capabilities, dict):
        for entries in capabilities.values():
            for entry in _as_list(entries):
                if isinstance(entry, dict):
                    specs.append(entry)
                    continue
                command = str(entry or "").strip()
                if command.count(".") >= 2:
                    specs.append({"id": command, "feature": command})
    return specs


def _declared_command_matches_feature(spec: dict[str, Any], feature: str) -> bool:
    wanted = _feature_tokens(feature)
    if not wanted:
        return False
    candidates: set[str] = set()
    for key in (
        "feature",
        "feature_id",
        "id",
        "command",
        "command_id",
        "tabId",
        "label",
    ):
        candidates.update(_feature_tokens(spec.get(key)))
    for alias in _as_list(spec.get("aliases")):
        candidates.update(_feature_tokens(alias))
    return bool(wanted & candidates)


def _fallback_command_matches_feature(command_id: str, feature: str) -> bool:
    wanted = _feature_tokens(feature)
    command_tokens = _feature_tokens(command_id)
    return bool(wanted & command_tokens)


def resolve_plugin_command_for_feature(
    context: PluginContext,
    records: list[PluginRecord],
    feature: str,
) -> str | None:
    feature_name = str(feature or "").strip()
    if not feature_name:
        return None
    if feature_name in context.commands:
        return feature_name

    for record in records:
        if record.state != "active" or record.manifest is None:
            continue
        for spec in _iter_declared_command_specs(record.manifest):
            command = str(
                spec.get("id") or spec.get("command") or spec.get("command_id") or ""
            ).strip()
            if (
                command
                and command in context.commands
                and _declared_command_matches_feature(spec, feature_name)
            ):
                return command

    for command in sorted(context.commands.keys()):
        if _fallback_command_matches_feature(command, feature_name):
            return command
    return None


def invoke_plugin_feature(
    records: list[PluginRecord],
    feature: str,
    payload: dict[str, Any] | None = None,
    *,
    host_version: str = DEFAULT_HOST_VERSION,
    api_version: int = HOST_API_VERSION,
    license_search_paths: list[Path] | None = None,
) -> tuple[dict[str, Any], PluginContext, list[PluginRecord]]:
    context, attached_records = attach_plugins(
        records,
        host_version=host_version,
        api_version=api_version,
        license_search_paths=license_search_paths,
    )
    feature_name = str(feature or "").strip()
    command_name = resolve_plugin_command_for_feature(
        context, attached_records, feature_name
    )
    if not command_name:
        return (
            {
                "ok": False,
                "error": f"Feature plugin introuvable: {feature_name}",
                "feature": feature_name,
                "available_commands": sorted(context.commands.keys()),
            },
            context,
            attached_records,
        )
    response, _context, _records = invoke_plugin_command(
        attached_records,
        command_name,
        payload,
        host_version=host_version,
        api_version=api_version,
        license_search_paths=license_search_paths,
    )
    response["feature"] = feature_name
    return response, context, attached_records


def _build_registry_from_args(args: argparse.Namespace) -> list[PluginRecord]:
    search_paths = (
        [Path(item).expanduser() for item in args.paths]
        if getattr(args, "paths", None)
        else default_plugin_search_paths(cwd=Path.cwd())
    )
    disabled = [
        item.strip()
        for item in str(getattr(args, "disable", "") or "").split(",")
        if item.strip()
    ]
    return build_plugin_registry(
        search_paths,
        host_version=str(
            getattr(args, "host_version", DEFAULT_HOST_VERSION) or DEFAULT_HOST_VERSION
        ),
        api_version=int(
            getattr(args, "api_version", HOST_API_VERSION) or HOST_API_VERSION
        ),
        disabled_plugin_ids=disabled,
    )


def summarize_plugin_states(records: list[PluginRecord]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for record in records:
        counts[record.state] = counts.get(record.state, 0) + 1
    return dict(sorted(counts.items()))


def collect_runtime_state(
    *,
    host_version: str = DEFAULT_HOST_VERSION,
    api_version: int = HOST_API_VERSION,
    search_paths: list[Path] | None = None,
    license_search_paths: list[Path] | None = None,
    disabled_plugin_ids: list[str] | None = None,
    attach: bool = False,
) -> dict[str, Any]:
    effective_paths = search_paths or default_plugin_search_paths(cwd=Path.cwd())
    effective_license_paths = license_search_paths or default_license_search_paths(
        cwd=Path.cwd()
    )
    records = build_plugin_registry(
        effective_paths,
        host_version=host_version,
        api_version=api_version,
        disabled_plugin_ids=disabled_plugin_ids or [],
    )
    records = apply_plugin_licensing(records, search_paths=effective_license_paths)
    context = None
    if attach:
        context, records = attach_plugins(
            records,
            host_version=host_version,
            api_version=api_version,
            license_search_paths=effective_license_paths,
        )
    payload: dict[str, Any] = {
        "host_version": host_version,
        "api_version": api_version,
        "search_paths": [str(path) for path in effective_paths],
        "license_search_paths": [str(path) for path in effective_license_paths],
        "plugins": [record.to_dict() for record in records],
        "summary": summarize_plugin_states(records),
    }
    if context is not None:
        payload["attached"] = context.snapshot()
    return payload


def _cmd_list(args: argparse.Namespace) -> int:
    search_paths = (
        [Path(item).expanduser() for item in args.paths]
        if getattr(args, "paths", None)
        else default_plugin_search_paths(cwd=Path.cwd())
    )
    disabled = [
        item.strip()
        for item in str(getattr(args, "disable", "") or "").split(",")
        if item.strip()
    ]
    payload = collect_runtime_state(
        host_version=args.host_version,
        api_version=args.api_version,
        search_paths=search_paths,
        disabled_plugin_ids=disabled,
        attach=bool(args.attach),
    )
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def _cmd_inspect(args: argparse.Namespace) -> int:
    license_search_paths = default_license_search_paths(cwd=Path.cwd())
    records = apply_plugin_licensing(
        _build_registry_from_args(args), search_paths=license_search_paths
    )
    record = get_plugin_record(records, args.plugin_id)
    if record is None:
        print(
            json.dumps(
                {"error": f"Plugin introuvable: {args.plugin_id}"},
                indent=2,
                ensure_ascii=False,
            )
        )
        return 1
    print(json.dumps(record.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        manifest = load_plugin_manifest(args.path)
    except PluginManifestError as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False)
        )
        return 1
    print(
        json.dumps(
            {"ok": True, "manifest": manifest.to_dict()}, indent=2, ensure_ascii=False
        )
    )
    return 0


def _load_invoke_payload(args: argparse.Namespace) -> dict[str, Any]:
    payload_json = str(getattr(args, "payload_json", "") or "").strip()
    payload_file = str(getattr(args, "payload_file", "") or "").strip()
    if payload_json and payload_file:
        raise ValueError("Utilisez payload_json ou payload_file, pas les deux")
    raw = "{}"
    if payload_file:
        raw = Path(payload_file).expanduser().read_text(encoding="utf-8")
    elif payload_json:
        raw = payload_json
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Payload JSON invalide: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Le payload doit etre un objet JSON")
    return payload


def _cmd_invoke(args: argparse.Namespace) -> int:
    try:
        payload = _load_invoke_payload(args)
    except ValueError as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False)
        )
        return 0
    license_search_paths = default_license_search_paths(cwd=Path.cwd())
    records = apply_plugin_licensing(
        _build_registry_from_args(args), search_paths=license_search_paths
    )
    response, context, records = invoke_plugin_command(
        records,
        args.command_id,
        payload,
        host_version=args.host_version,
        api_version=args.api_version,
        license_search_paths=license_search_paths,
    )
    response["host_version"] = args.host_version
    response["api_version"] = args.api_version
    response["plugins"] = [record.to_dict() for record in records]
    response["attached"] = context.snapshot()
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def _cmd_invoke_feature(args: argparse.Namespace) -> int:
    try:
        payload = _load_invoke_payload(args)
    except ValueError as exc:
        print(
            json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False)
        )
        return 0
    license_search_paths = default_license_search_paths(cwd=Path.cwd())
    records = apply_plugin_licensing(
        _build_registry_from_args(args), search_paths=license_search_paths
    )
    response, context, records = invoke_plugin_feature(
        records,
        args.feature,
        payload,
        host_version=args.host_version,
        api_version=args.api_version,
        license_search_paths=license_search_paths,
    )
    response["host_version"] = args.host_version
    response["api_version"] = args.api_version
    response["plugins"] = [record.to_dict() for record in records]
    response["attached"] = context.snapshot()
    print(json.dumps(response, indent=2, ensure_ascii=False))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Runtime minimal des plugins Pile Ou Face"
    )
    parser.add_argument("--host-version", default=DEFAULT_HOST_VERSION)
    parser.add_argument("--api-version", type=int, default=HOST_API_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="Lister les plugins découverts")
    list_parser.add_argument("--paths", nargs="*", default=[])
    list_parser.add_argument("--disable", default="")
    list_parser.add_argument("--attach", action="store_true")
    list_parser.add_argument("--json", action="store_true")
    list_parser.set_defaults(func=_cmd_list)

    inspect_parser = sub.add_parser("inspect", help="Inspecter un plugin par id")
    inspect_parser.add_argument("plugin_id")
    inspect_parser.add_argument("--paths", nargs="*", default=[])
    inspect_parser.add_argument("--disable", default="")
    inspect_parser.set_defaults(func=_cmd_inspect)

    validate_parser = sub.add_parser(
        "validate", help="Valider un manifest ou un dossier plugin"
    )
    validate_parser.add_argument("path")
    validate_parser.set_defaults(func=_cmd_validate)

    invoke_parser = sub.add_parser(
        "invoke", help="Executer une commande exposee par un plugin actif"
    )
    invoke_parser.add_argument("command_id")
    invoke_parser.add_argument("--payload-json", default="")
    invoke_parser.add_argument("--payload-file", default="")
    invoke_parser.add_argument("--paths", nargs="*", default=[])
    invoke_parser.add_argument("--disable", default="")
    invoke_parser.set_defaults(func=_cmd_invoke)

    invoke_feature_parser = sub.add_parser(
        "invoke-feature", help="Executer une feature exposee par un plugin actif"
    )
    invoke_feature_parser.add_argument("feature")
    invoke_feature_parser.add_argument("--payload-json", default="")
    invoke_feature_parser.add_argument("--payload-file", default="")
    invoke_feature_parser.add_argument("--paths", nargs="*", default=[])
    invoke_feature_parser.add_argument("--disable", default="")
    invoke_feature_parser.set_defaults(func=_cmd_invoke_feature)

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
