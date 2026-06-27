# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import atexit
import argparse
import hashlib
import hmac as _hmac_mod
import importlib
import importlib.util
import json
import os
import sys
import inspect
import tempfile
import zipfile
import base64 as _base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.shared.log import configure_logging, get_logger
from backends.plugins.manifest import (
    PluginManifest,
    PluginManifestError,
    load_plugin_manifest,
)
from backends.plugins.license import (
    _ENV_PREFIX as _LICENSE_ENV_PREFIX,
    default_license_search_paths,
    evaluate_plugin_license,
)
from backends.plugins.registry import (
    PluginRecord,
    build_plugin_registry,
    get_plugin_record,
)

_log = get_logger(__name__)
HOST_API_VERSION = 1
DEFAULT_HOST_VERSION = "0.1.0"
_DECRYPTED_PLUGIN_CACHE: dict[str, Path] = {}
_DECRYPTED_PLUGIN_TEMPS: list[tempfile.TemporaryDirectory[str]] = []


def _cleanup_decrypted_plugin_cache() -> None:
    while _DECRYPTED_PLUGIN_TEMPS:
        temp_dir = _DECRYPTED_PLUGIN_TEMPS.pop()
        try:
            temp_dir.cleanup()
        except Exception:  # pragma: no cover - defensive cleanup
            pass
    _DECRYPTED_PLUGIN_CACHE.clear()


atexit.register(_cleanup_decrypted_plugin_cache)


def _verify_payload_hmac(payload_bytes: bytes, content_key: str, expected_hex: str) -> bool:
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
    cwd_path = Path(cwd or Path.cwd()).expanduser().resolve()
    home_path = Path(home or Path.home()).expanduser().resolve()
    workspace_root = cwd_path / ".pile-ou-face"
    if workspace_root.is_dir():
        paths = [workspace_root / "plugins"]
    else:
        paths = [home_path / ".pile-ou-face" / "plugins"]
    extra = str(env_map.get(f"{_LICENSE_ENV_PREFIX}_PLUGIN_PATH", "") or "").strip()
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
                key: len(value) for key, value in sorted(self.analysis_enrichers.items())
            },
            "ui_panels": sorted(self.ui_panels.keys()),
            "exporters": sorted(self.exporters.keys()),
            "commands": sorted(self.commands.keys()),
            "command_sources": dict(sorted(self.command_sources.items())),
        }


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
        raise RuntimeError(f"Algorithme de chiffrement non supporté: {algorithm or 'inconnu'!r}")

    nonce_b64 = str(encryption_meta.get("nonce_b64", "") or "").strip()
    if not nonce_b64:
        raise RuntimeError("Bundle chiffré invalide: nonce_b64 absent dans encryption.json.")

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
        raise RuntimeError(f"Impossible de déchiffrer le plugin avec cette licence: {exc}") from exc

    temp_dir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="pof-plugin-runtime-"
    )
    temp_root = Path(temp_dir.name)
    try:
        temp_root.chmod(0o700)
    except OSError:
        pass
    payload_zip = temp_root / "payload.zip"
    payload_zip.write_bytes(plaintext)

    if payload_sha256:
        digest = hashlib.sha256(plaintext).hexdigest()
        if digest != payload_sha256:
            temp_dir.cleanup()
            raise RuntimeError("Le payload déchiffré ne correspond pas au checksum attendu.")
    plugin_root = temp_root / "plugin"
    with zipfile.ZipFile(payload_zip) as archive:
        archive.extractall(plugin_root)
    try:
        payload_zip.chmod(0o600)
    except OSError:
        pass
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
        entrypoint = record.manifest.entrypoints.python
        if entrypoint is None:
            continue
        try:
            context.current_plugin_id = record.plugin_id
            module = _load_plugin_module(record.manifest, license_search_paths=license_search_paths)
            register = getattr(module, entrypoint.register)
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
        if record.state == "active" and evaluation.status not in ("unlocked", "grace", "active"):
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


def _build_registry_from_args(args: argparse.Namespace) -> list[PluginRecord]:
    search_paths = (
        [Path(item).expanduser() for item in args.paths]
        if getattr(args, "paths", None)
        else default_plugin_search_paths(cwd=Path.cwd())
    )
    disabled = [
        item.strip() for item in str(getattr(args, "disable", "") or "").split(",") if item.strip()
    ]
    return build_plugin_registry(
        search_paths,
        host_version=str(
            getattr(args, "host_version", DEFAULT_HOST_VERSION) or DEFAULT_HOST_VERSION
        ),
        api_version=int(getattr(args, "api_version", HOST_API_VERSION) or HOST_API_VERSION),
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
    effective_license_paths = license_search_paths or default_license_search_paths(cwd=Path.cwd())
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
        item.strip() for item in str(getattr(args, "disable", "") or "").split(",") if item.strip()
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
                {"error": f"Plugin introuvable: {args.plugin_id}"}, indent=2, ensure_ascii=False
            )
        )
        return 1
    print(json.dumps(record.to_dict(), indent=2, ensure_ascii=False))
    return 0


def _cmd_validate(args: argparse.Namespace) -> int:
    try:
        manifest = load_plugin_manifest(args.path)
    except PluginManifestError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
        return 1
    print(json.dumps({"ok": True, "manifest": manifest.to_dict()}, indent=2, ensure_ascii=False))
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
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Runtime minimal des plugins Pile Ou Face")
    parser.add_argument("--host-version", default=DEFAULT_HOST_VERSION)
    parser.add_argument("--api-version", type=int, default=HOST_API_VERSION)
    sub = parser.add_subparsers(dest="command", required=True)

    list_parser = sub.add_parser("list", help="Lister les plugins découverts")
    list_parser.add_argument("--paths", nargs="*", default=[])
    list_parser.add_argument("--disable", default="")
    list_parser.add_argument("--attach", action="store_true")
    list_parser.set_defaults(func=_cmd_list)

    inspect_parser = sub.add_parser("inspect", help="Inspecter un plugin par id")
    inspect_parser.add_argument("plugin_id")
    inspect_parser.add_argument("--paths", nargs="*", default=[])
    inspect_parser.add_argument("--disable", default="")
    inspect_parser.set_defaults(func=_cmd_inspect)

    validate_parser = sub.add_parser("validate", help="Valider un manifest ou un dossier plugin")
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

    return parser


def main(argv: list[str] | None = None) -> int:
    configure_logging()
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
