# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import argparse
import json
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any
from zipfile import ZipFile, ZipInfo

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.plugins.manifest import PluginManifestError, load_plugin_manifest

# Defense-in-depth cap against decompression-bomb bundles — a legitimate
# plugin bundle (source + small data files) has no business being this large.
_MAX_TOTAL_UNCOMPRESSED_BYTES = 200 * 1024 * 1024  # 200 MiB
_MAX_MEMBER_COUNT = 5000


class PluginInstallError(ValueError):
    """Plugin install error."""


def _is_symlink_member(member: ZipInfo) -> bool:
    # external_attr's high 16 bits hold the Unix file mode when the archive
    # was created on a Unix system (create_system == 3). A symlink member's
    # "content" is its target path, and naively recreating it (or anything
    # that follows it later) could point outside the extraction root.
    mode = member.external_attr >> 16
    return stat.S_ISLNK(mode)


def _safe_members(members: list[ZipInfo]) -> None:
    if len(members) > _MAX_MEMBER_COUNT:
        raise PluginInstallError(
            f"Bundle invalide: trop d'entrées ({len(members)} > {_MAX_MEMBER_COUNT})."
        )
    total_size = 0
    for member in members:
        name = member.filename
        if not name or name.startswith("/"):
            raise PluginInstallError(f"Entrée archive invalide: {name!r}")
        # Reject backslashes explicitly rather than relying on Path() only
        # splitting on the current platform's separator — a POSIX host
        # parses "..\\..\\evil" as a single (harmless) literal filename, but
        # the same bundle installed on Windows would traverse directories.
        # Don't rely on platform quirks to keep you safe by accident.
        if "\\" in name:
            raise PluginInstallError(f"Entrée archive dangereuse: {name!r}")
        target = Path(name)
        if target.is_absolute() or any(part == ".." for part in target.parts):
            raise PluginInstallError(f"Entrée archive dangereuse: {name!r}")
        if _is_symlink_member(member):
            raise PluginInstallError(f"Entrée archive dangereuse (symlink): {name!r}")
        total_size += member.file_size
        if total_size > _MAX_TOTAL_UNCOMPRESSED_BYTES:
            raise PluginInstallError(
                "Bundle invalide: taille décompressée totale dépasse "
                f"{_MAX_TOTAL_UNCOMPRESSED_BYTES // (1024 * 1024)} MiB."
            )


def _resolve_source_root(
    source: str | Path, workspace: str | Path | None = None
) -> tuple[Path, str, tempfile.TemporaryDirectory[str] | None]:
    source_path = Path(source).expanduser()
    if not source_path.is_absolute() and workspace:
        source_path = Path(workspace).expanduser() / source_path
    source_path = source_path.resolve()
    if not source_path.exists():
        raise PluginInstallError(f"Source introuvable: {source_path}")

    if source_path.is_dir():
        if not (source_path / "manifest.json").exists():
            raise PluginInstallError(
                "Le dossier sélectionné ne contient pas de manifest.json. "
                "Installe un plugin extrait ou un bundle .pofplug."
            )
        return source_path, "directory", None

    suffix = source_path.suffix.lower()
    if suffix not in {".pofplug", ".zip"}:
        raise PluginInstallError(
            f"Format non supporté: {source_path.name}. "
            "Sélectionne un dossier plugin ou un bundle .pofplug."
        )

    temp_dir: tempfile.TemporaryDirectory[str] = tempfile.TemporaryDirectory(
        prefix="pof-plugin-install-"
    )
    extract_root = Path(temp_dir.name)
    with ZipFile(source_path) as archive:
        members = archive.infolist()
        _safe_members(members)
        archive.extractall(extract_root)
    if not (extract_root / "manifest.json").exists():
        temp_dir.cleanup()
        raise PluginInstallError("Bundle invalide: manifest.json absent à la racine.")
    manifest = load_plugin_manifest(extract_root)
    return (
        extract_root,
        ("encrypted_bundle" if manifest.distribution.encrypted is True else "bundle"),
        temp_dir,
    )


def install_plugin(
    source: str | Path, target_root: str | Path, *, workspace: str | Path | None = None
) -> dict[str, Any]:
    target_root_path = Path(target_root).expanduser()
    if not target_root_path.is_absolute() and workspace:
        target_root_path = Path(workspace).expanduser() / target_root_path
    target_root_path = target_root_path.resolve()
    target_root_path.mkdir(parents=True, exist_ok=True)

    source_root, source_kind, temp_dir = _resolve_source_root(
        source, workspace=workspace
    )
    try:
        manifest = load_plugin_manifest(source_root)
        destination = target_root_path / manifest.plugin_id
        staging_parent = destination.parent
        with tempfile.TemporaryDirectory(
            prefix=f"{manifest.plugin_id.replace('.', '_')}-", dir=staging_parent
        ) as tmp:
            staging_dir = Path(tmp) / manifest.plugin_id
            shutil.copytree(source_root, staging_dir)
            if destination.exists():
                shutil.rmtree(destination)
            shutil.move(str(staging_dir), str(destination))
        return {
            "ok": True,
            "plugin_id": manifest.plugin_id,
            "name": manifest.name,
            "version": manifest.version,
            "installed_to": str(destination),
            "target_root": str(target_root_path),
            "source": str(Path(source).expanduser()),
            "source_kind": source_kind,
        }
    finally:
        if temp_dir is not None:
            temp_dir.cleanup()


def _cmd_install(args: argparse.Namespace) -> int:
    try:
        payload = install_plugin(
            args.source, args.target_root, workspace=args.workspace
        )
    except (PluginInstallError, PluginManifestError) as exc:
        payload = {
            "ok": False,
            "error": str(exc),
            "source": str(args.source),
            "target_root": str(args.target_root),
        }
    except Exception as exc:  # pragma: no cover - defensive
        payload = {
            "ok": False,
            "error": f"Installation impossible: {exc}",
            "source": str(args.source),
            "target_root": str(args.target_root),
        }
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Installer un plugin Pile Ou Face dans un dossier plugins du host"
    )
    parser.add_argument(
        "--source", required=True, help="Dossier plugin extrait ou bundle .pofplug"
    )
    parser.add_argument(
        "--target-root", required=True, help="Dossier cible context.storageUri/plugins"
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
