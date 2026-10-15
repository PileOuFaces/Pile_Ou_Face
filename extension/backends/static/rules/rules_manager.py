# SPDX-License-Identifier: AGPL-3.0-only
"""Gestionnaire centralisé des règles YARA et CAPA.

CLI:
  python rules_manager.py list   --cwd <root> [--global-config <path>]
  python rules_manager.py get    --rule-id <id> --cwd <root>
  python rules_manager.py toggle --rule-id <id> --enabled true|false --cwd <root>
  python rules_manager.py add    --name <name> --type yara|capa --content <content> --cwd <root> [--scope project|global]
  python rules_manager.py update --rule-id <id> --name <name> --content <content> --cwd <root>
  python rules_manager.py delete --rule-id <id> --cwd <root>
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Any


class RulesManager:
    """Gère les règles custom YARA et CAPA par projet et au niveau global."""

    _PROJECT_SCOPE = "project"
    _GLOBAL_SCOPE = "global"

    def __init__(
        self, project_root: str, global_config_path: str | None = None
    ) -> None:
        self._root = Path(project_root)
        project_storage = Path(
            os.environ.get("POF_STORAGE_DIR", "").strip() or self._root
        )
        self._project_rules_dir = project_storage / "rules"
        self._project_config = project_storage / "rules-config.json"
        self._global_config = Path(global_config_path) if global_config_path else None
        self._global_root = self._global_config.parent if self._global_config else None
        self._global_rules_dir = (
            self._global_root / "rules" if self._global_root else None
        )

    def _iter_rule_files(self, rule_type: str) -> list[tuple[str, str, Path]]:
        exts = {
            "yara": ("*.yar", "*.yara"),
            "capa": ("*.yml", "*.yaml"),
        }.get(rule_type, ())
        entries: list[tuple[str, str, Path]] = []
        search_roots: list[tuple[str, Path | None]] = [
            (self._GLOBAL_SCOPE, self._global_rules_dir),
            (self._PROJECT_SCOPE, self._project_rules_dir),
        ]
        for scope, base_dir in search_roots:
            if base_dir is None:
                continue
            rule_dir = base_dir / rule_type
            if not rule_dir.exists():
                continue
            for ext in exts:
                for file_path in sorted(rule_dir.glob(ext)):
                    entries.append(
                        (
                            scope,
                            self._rule_id(scope, rule_type, file_path.name),
                            file_path,
                        )
                    )
        return entries

    @staticmethod
    def _rule_id(scope: str, rule_type: str, name: str) -> str:
        if scope == RulesManager._GLOBAL_SCOPE:
            return f"global:{rule_type}:{name}"
        return f"user:{rule_type}:{name}"

    @staticmethod
    def _validate_rule_name(name: str) -> str:
        clean = str(name or "").strip()
        if not clean:
            raise ValueError("Nom de règle vide.")
        if clean != Path(clean).name or clean in {".", ".."}:
            raise ValueError(f"Nom de règle invalide : {name!r}")
        return clean

    @staticmethod
    def _parse_rule_id(rule_id: str) -> tuple[str, str, str]:
        parts = rule_id.split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"rule_id invalide : {rule_id!r}")
        prefix, rule_type, name = parts
        name = RulesManager._validate_rule_name(name)
        if prefix == "global":
            return RulesManager._GLOBAL_SCOPE, rule_type, name
        if prefix == "user":
            return RulesManager._PROJECT_SCOPE, rule_type, name
        raise ValueError(f"rule_id invalide : {rule_id!r}")

    def list_rules(self) -> list[dict[str, Any]]:
        """Retourne toutes les règles avec état fusionné global + projet."""
        config = self._merged_config()
        rules: list[dict[str, Any]] = []
        for rule_type in ("yara", "capa"):
            for scope, rule_id, file_path in self._iter_rule_files(rule_type):
                enabled = config.get(rule_id, {}).get("enabled", True)
                rules.append(
                    {
                        "id": rule_id,
                        "name": file_path.name,
                        "type": rule_type,
                        "source": scope,
                        "scope": scope,
                        "enabled": enabled,
                        "path": str(file_path),
                    }
                )
        return rules

    def get_active_yara_paths(self, extra_path: Path | None = None) -> list[Path]:
        """Retourne les chemins des fichiers .yar actifs (enabled)."""
        config = self._merged_config()
        active: list[Path] = []
        for _, rule_id, file_path in self._iter_rule_files("yara"):
            if config.get(rule_id, {}).get("enabled", True):
                active.append(file_path)
        if extra_path is not None:
            active.append(extra_path)
        return active

    def inject_active_capa_rules(self, capa_rules_path: Path) -> None:
        """Copie les règles CAPA custom actives dans capa_rules_path/custom/."""
        config = self._merged_config()
        dest = capa_rules_path / "custom"
        dest.mkdir(exist_ok=True)
        for scope, rule_id, file_path in self._iter_rule_files("capa"):
            if config.get(rule_id, {}).get("enabled", True):
                target_name = (
                    file_path.name
                    if scope == self._PROJECT_SCOPE
                    else f"global__{file_path.name}"
                )
                shutil.copy2(file_path, dest / target_name)

    def toggle_rule(self, rule_id: str, enabled: bool) -> None:
        """Active ou désactive une règle dans la config projet."""
        scope, _, _ = self._parse_rule_id(rule_id)
        cfg = (
            self._load_global_config()
            if scope == self._GLOBAL_SCOPE
            else self._load_project_config()
        )
        cfg.setdefault("rules", {})[rule_id] = {"enabled": enabled}
        if scope == self._GLOBAL_SCOPE:
            self._save_global_config(cfg)
        else:
            self._save_project_config(cfg)

    def add_user_rule(
        self,
        name: str,
        content: str,
        rule_type: str,
        scope: str = _PROJECT_SCOPE,
    ) -> str:
        """Crée un fichier dans le stockage des règles projet/global. Retourne rule_id."""
        if rule_type not in ("yara", "capa"):
            raise ValueError(f"Type inconnu : {rule_type!r} (attendu: yara ou capa)")
        if scope not in (self._PROJECT_SCOPE, self._GLOBAL_SCOPE):
            raise ValueError(f"Scope inconnu : {scope!r} (attendu: project ou global)")
        base_dir = (
            self._global_rules_dir
            if scope == self._GLOBAL_SCOPE
            else self._project_rules_dir
        )
        if base_dir is None:
            raise ValueError("Le stockage global des règles n'est pas configuré.")
        name = self._validate_rule_name(name)
        d = base_dir / rule_type
        d.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(content, encoding="utf-8")
        return self._rule_id(scope, rule_type, name)

    def delete_user_rule(self, rule_id: str) -> None:
        """Supprime le fichier et nettoie la config projet."""
        scope, rule_type, name = self._parse_rule_id(rule_id)
        base_dir = (
            self._global_rules_dir
            if scope == self._GLOBAL_SCOPE
            else self._project_rules_dir
        )
        if base_dir is None:
            raise ValueError("Le stockage global des règles n'est pas configuré.")
        f = base_dir / rule_type / name
        if not f.exists():
            raise FileNotFoundError(f"Règle introuvable : {f}")
        f.unlink()
        cfg = (
            self._load_global_config()
            if scope == self._GLOBAL_SCOPE
            else self._load_project_config()
        )
        cfg.get("rules", {}).pop(rule_id, None)
        if scope == self._GLOBAL_SCOPE:
            self._save_global_config(cfg)
        else:
            self._save_project_config(cfg)

    def get_rule(self, rule_id: str) -> dict[str, Any]:
        """Retourne le contenu brut d'une règle pour édition."""
        scope, rule_type, name = self._parse_rule_id(rule_id)
        base_dir = (
            self._global_rules_dir
            if scope == self._GLOBAL_SCOPE
            else self._project_rules_dir
        )
        if base_dir is None:
            raise ValueError("Le stockage global des règles n'est pas configuré.")
        file_path = base_dir / rule_type / name
        if not file_path.exists():
            raise FileNotFoundError(f"Règle introuvable : {file_path}")
        return {
            "id": rule_id,
            "name": name,
            "type": rule_type,
            "scope": scope,
            "path": str(file_path),
            "content": file_path.read_text(encoding="utf-8"),
        }

    def update_user_rule(self, rule_id: str, name: str, content: str) -> str:
        """Met à jour le contenu d'une règle et renomme le fichier si besoin."""
        scope, rule_type, old_name = self._parse_rule_id(rule_id)
        base_dir = (
            self._global_rules_dir
            if scope == self._GLOBAL_SCOPE
            else self._project_rules_dir
        )
        if base_dir is None:
            raise ValueError("Le stockage global des règles n'est pas configuré.")
        rule_dir = base_dir / rule_type
        source_path = rule_dir / old_name
        if not source_path.exists():
            raise FileNotFoundError(f"Règle introuvable : {source_path}")
        target_name = self._validate_rule_name(name or old_name)
        target_path = rule_dir / target_name
        if target_path != source_path and target_path.exists():
            raise FileExistsError(f"Une règle existe déjà : {target_path.name}")
        target_path.write_text(content, encoding="utf-8")
        if target_path != source_path:
            source_path.unlink()
            old_rule_id = self._rule_id(scope, rule_type, old_name)
            new_rule_id = self._rule_id(scope, rule_type, target_name)
            cfg = (
                self._load_global_config()
                if scope == self._GLOBAL_SCOPE
                else self._load_project_config()
            )
            rule_state = cfg.get("rules", {}).pop(old_rule_id, None)
            if rule_state is not None:
                cfg.setdefault("rules", {})[new_rule_id] = rule_state
                if scope == self._GLOBAL_SCOPE:
                    self._save_global_config(cfg)
                else:
                    self._save_project_config(cfg)
            return new_rule_id
        return rule_id

    def _merged_config(self) -> dict[str, Any]:
        """Merge global (défauts) + projet (overrides)."""
        global_rules = self._load_global_config().get("rules", {})
        project_rules = self._load_project_config().get("rules", {})
        return {**global_rules, **project_rules}

    def _load_global_config(self) -> dict[str, Any]:
        if self._global_config and self._global_config.exists():
            try:
                return json.loads(self._global_config.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"version": 1, "rules": {}}

    def _load_project_config(self) -> dict[str, Any]:
        if self._project_config.exists():
            try:
                return json.loads(self._project_config.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                pass
        return {"version": 1, "rules": {}}

    def _save_project_config(self, config: dict[str, Any]) -> None:
        self._project_config.parent.mkdir(parents=True, exist_ok=True)
        self._project_config.write_text(
            json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
        )

    def _save_global_config(self, config: dict[str, Any]) -> None:
        if self._global_config is None:
            raise ValueError("Le fichier de configuration global est manquant.")
        self._global_config.parent.mkdir(parents=True, exist_ok=True)
        self._global_config.write_text(
            json.dumps(config, indent=2, ensure_ascii=False), encoding="utf-8"
        )


def main() -> int:
    """Point d'entrée CLI."""
    import argparse
    import os

    parser = argparse.ArgumentParser(description="Rules manager for YARA/CAPA")
    sub = parser.add_subparsers(dest="cmd")

    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--cwd", default=os.getcwd())
        p.add_argument("--global-config", dest="global_config")

    p_list = sub.add_parser("list")
    _add_common(p_list)

    p_get = sub.add_parser("get")
    p_get.add_argument("--rule-id", required=True)
    _add_common(p_get)

    p_toggle = sub.add_parser("toggle")
    p_toggle.add_argument("--rule-id", required=True)
    p_toggle.add_argument("--enabled", required=True, choices=("true", "false"))
    _add_common(p_toggle)

    p_add = sub.add_parser("add")
    p_add.add_argument("--name", required=True)
    p_add.add_argument(
        "--type", dest="rule_type", required=True, choices=("yara", "capa")
    )
    p_add.add_argument("--content", required=True)
    p_add.add_argument("--scope", default="project", choices=("project", "global"))
    _add_common(p_add)

    p_update = sub.add_parser("update")
    p_update.add_argument("--rule-id", required=True)
    p_update.add_argument("--name", required=True)
    p_update.add_argument("--content", required=True)
    _add_common(p_update)

    p_del = sub.add_parser("delete")
    p_del.add_argument("--rule-id", required=True)
    _add_common(p_del)

    args = parser.parse_args()
    if not args.cmd:
        parser.print_help()
        return 1

    mgr = RulesManager(args.cwd, getattr(args, "global_config", None))
    try:
        if args.cmd == "list":
            print(
                json.dumps(
                    {"rules": mgr.list_rules(), "error": None}, ensure_ascii=False
                )
            )
        elif args.cmd == "get":
            print(
                json.dumps(
                    {"rule": mgr.get_rule(args.rule_id), "error": None},
                    ensure_ascii=False,
                )
            )
        elif args.cmd == "toggle":
            mgr.toggle_rule(args.rule_id, args.enabled == "true")
            print(json.dumps({"success": True, "error": None}))
        elif args.cmd == "add":
            rule_id = mgr.add_user_rule(
                args.name, args.content, args.rule_type, args.scope
            )
            print(json.dumps({"rule_id": rule_id, "error": None}))
        elif args.cmd == "update":
            rule_id = mgr.update_user_rule(args.rule_id, args.name, args.content)
            print(json.dumps({"rule_id": rule_id, "error": None}))
        elif args.cmd == "delete":
            mgr.delete_user_rule(args.rule_id)
            print(json.dumps({"success": True, "error": None}))
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        return 1
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
