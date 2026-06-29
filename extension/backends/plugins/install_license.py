# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any


class PluginLicenseInstallError(ValueError):
    """License install error."""


def install_license(
    source: str | Path, target_root: str | Path, *, workspace: str | Path | None = None
) -> dict[str, Any]:
    source_path = Path(source).expanduser()
    if not source_path.is_absolute() and workspace:
        source_path = Path(workspace).expanduser() / source_path
    source_path = source_path.resolve()
    if not source_path.exists() or not source_path.is_file():
        raise PluginLicenseInstallError(
            f"Fichier de licence introuvable: {source_path}"
        )

    target_root_path = Path(target_root).expanduser()
    if not target_root_path.is_absolute() and workspace:
        target_root_path = Path(workspace).expanduser() / target_root_path
    target_root_path = target_root_path.resolve()
    target_root_path.mkdir(parents=True, exist_ok=True)

    try:
        payload = json.loads(source_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PluginLicenseInstallError(f"Licence JSON invalide: {exc}") from exc
    if not isinstance(payload, dict):
        raise PluginLicenseInstallError(
            "Le fichier de licence doit contenir un objet JSON."
        )

    plugin_id = str(payload.get("plugin_id", "") or "").strip()
    signature = str(payload.get("signature", "") or "").strip()
    if not plugin_id:
        raise PluginLicenseInstallError("Champ plugin_id manquant dans la licence.")
    if not signature:
        raise PluginLicenseInstallError("Champ signature manquant dans la licence.")

    destination = target_root_path / f"{plugin_id}.license.json"
    shutil.copy2(source_path, destination)
    return {
        "ok": True,
        "plugin_id": plugin_id,
        "installed_to": str(destination),
        "target_root": str(target_root_path),
        "source": str(source_path),
    }


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        payload = install_license(
            args.source, args.target_root, workspace=args.workspace
        )
    except PluginLicenseInstallError as exc:
        payload = {
            "ok": False,
            "error": str(exc),
            "source": str(args.source),
            "target_root": str(args.target_root),
        }
    except Exception as exc:  # pragma: no cover - defensive
        payload = {
            "ok": False,
            "error": f"Installation de licence impossible: {exc}",
            "source": str(args.source),
            "target_root": str(args.target_root),
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Installer une licence plugin Pile Ou Face"
    )
    parser.add_argument("--source", required=True, help="Fichier de licence JSON signé")
    parser.add_argument(
        "--target-root", required=True, help="Dossier cible ~/.pile-ou-face/licenses"
    )
    parser.add_argument(
        "--workspace",
        default="",
        help="Racine optionnelle pour résoudre des chemins relatifs",
    )
    parser.set_defaults(func=_cmd_install)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
