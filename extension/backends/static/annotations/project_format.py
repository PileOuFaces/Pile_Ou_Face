# SPDX-License-Identifier: AGPL-3.0-only
"""Portable, deterministic project format for reverse-engineering state."""

from __future__ import annotations

import argparse
import copy
import json
from pathlib import Path
from typing import Any

from backends.shared.utils import parse_addr
from backends.static.annotations.annotation_db import hash_binary_content
from backends.static.annotations.annotations import AnnotationStore
from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.structs import (
    _normalize_binary_key,
    import_type_definitions,
)
from backends.static.annotations.typed_struct_refs import save_typed_struct_ref
from backends.static.annotations.typed_var_bindings import save_typed_var_binding

FORMAT = "pile-ou-face.project/v1"
IMPORT_SOURCE = "project"


class ProjectFormatError(ValueError):
    """Raised when a project document cannot be imported safely."""


def _address(value: Any) -> str:
    parsed = parse_addr(value)
    if parsed is None or parsed < 0:
        raise ProjectFormatError(f"Adresse invalide: {value!r}")
    return f"0x{parsed:x}"


def _stable_key(binary_sha256: str, addr: Any) -> str:
    return f"{binary_sha256}:{_address(addr)}"


def _without_local_binary(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        key: copy.deepcopy(value) for key, value in entry.items() if key != "binary"
    }


def export_project(
    binary_path: str,
    *,
    cache_path: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Export all user state without local paths or volatile timestamps."""
    digest = hash_binary_content(binary_path)
    with AnnotationStore(binary_path, cache_path=cache_path) as store:
        annotations = [
            {
                "key": _stable_key(digest, row["addr"]),
                "addr": _address(row["addr"]),
                "kind": str(row["kind"]),
                "value": str(row["value"]),
                "source": str(row.get("source") or "user"),
            }
            for row in store.list()
        ]
    annotations.sort(key=lambda item: (int(item["addr"], 16), item["kind"]))

    binary_key = _normalize_binary_key(binary_path)
    database = StructDb(workspace_root)
    definitions = database.load_definitions(binary_key)["definitions"]
    types = [copy.deepcopy(definitions[name]) for name in sorted(definitions)]
    typed_refs = [
        _without_local_binary(item) for item in database.list_typed_refs(binary_key)
    ]
    typed_var_bindings = [
        _without_local_binary(item)
        for item in database.list_typed_var_bindings(binary_key)
    ]
    for entry in typed_refs:
        entry["key"] = _stable_key(digest, entry["addr"])
    for entry in typed_var_bindings:
        entry["function_key"] = _stable_key(digest, entry["func_addr"])

    return {
        "format": FORMAT,
        "binary": {"sha256": digest},
        "annotations": annotations,
        "types": types,
        "typed_refs": typed_refs,
        "typed_var_bindings": typed_var_bindings,
    }


def _validate_document(binary_path: str, document: dict[str, Any]) -> str:
    if document.get("format") != FORMAT:
        raise ProjectFormatError(f"Format non supporté: {document.get('format')!r}")
    expected = str((document.get("binary") or {}).get("sha256") or "").lower()
    actual = hash_binary_content(binary_path)
    if expected != actual:
        raise ProjectFormatError(
            f"Empreinte SHA-256 différente (projet={expected or '<absente>'}, binaire={actual})."
        )
    return actual


def import_project(
    binary_path: str,
    document: dict[str, Any],
    *,
    cache_path: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Merge a project into local stores while preserving manual conflicts."""
    digest = _validate_document(binary_path, document)
    report = {
        "imported": 0,
        "skipped": 0,
        "conflicts": 0,
        "annotations": {"imported": 0, "skipped": 0, "conflicts": 0},
        "types": 0,
        "typed_refs": 0,
        "typed_var_bindings": 0,
        "diagnostics": [],
    }

    with AnnotationStore(binary_path, cache_path=cache_path) as store:
        existing = {(row["addr"], row["kind"]): row for row in store.list()}
        for item in document.get("annotations") or []:
            if not isinstance(item, dict):
                raise ProjectFormatError("Annotation invalide dans le projet.")
            addr = _address(item.get("addr"))
            if item.get("key") != _stable_key(digest, addr):
                raise ProjectFormatError(
                    f"Clé d'annotation incohérente: {item.get('key')!r}"
                )
            kind = str(item.get("kind") or "")
            value = str(item.get("value") or "")
            current = existing.get((addr, kind))
            if current and current["value"] == value:
                report["skipped"] += 1
                report["annotations"]["skipped"] += 1
                continue
            if current and current.get("source") not in {IMPORT_SOURCE, "ai"}:
                report["conflicts"] += 1
                report["annotations"]["conflicts"] += 1
                report["diagnostics"].append(
                    f"Annotation locale conservée: {addr} ({kind})"
                )
                continue
            store.import_annotation(addr, kind, value, source=IMPORT_SOURCE)
            existing[(addr, kind)] = {
                "addr": addr,
                "kind": kind,
                "value": value,
                "source": IMPORT_SOURCE,
            }
            report["imported"] += 1
            report["annotations"]["imported"] += 1

    raw_types = document.get("types") or []
    definitions: dict[str, dict[str, Any]] = {}
    for definition in raw_types:
        if not isinstance(definition, dict) or not definition.get("name"):
            raise ProjectFormatError("Définition de type invalide dans le projet.")
        definitions[str(definition["name"])] = copy.deepcopy(definition)
    if definitions:
        import_type_definitions(binary_path, definitions, IMPORT_SOURCE, workspace_root)
        report["types"] = len(definitions)
        report["imported"] += len(definitions)

    for item in document.get("typed_refs") or []:
        if not isinstance(item, dict):
            raise ProjectFormatError("Référence typée invalide dans le projet.")
        entry = copy.deepcopy(item)
        if entry.pop("key", None) != _stable_key(digest, entry.get("addr")):
            raise ProjectFormatError("Clé de référence typée incohérente.")
        save_typed_struct_ref(binary_path, entry, workspace_root)
        report["typed_refs"] += 1
        report["imported"] += 1

    for item in document.get("typed_var_bindings") or []:
        if not isinstance(item, dict):
            raise ProjectFormatError("Binding de variable invalide dans le projet.")
        entry = copy.deepcopy(item)
        func_addr = _address(entry.pop("func_addr", ""))
        if entry.pop("function_key", None) != _stable_key(digest, func_addr):
            raise ProjectFormatError(
                "Clé de fonction incohérente pour un binding typé."
            )
        save_typed_var_binding(binary_path, func_addr, entry, workspace_root)
        report["typed_var_bindings"] += 1
        report["imported"] += 1
    return report


def dumps_project(document: dict[str, Any]) -> str:
    """Return the canonical diff-friendly serialization."""
    return json.dumps(document, indent=2, ensure_ascii=False, sort_keys=True) + "\n"


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Export or import a portable Pile ou Face project"
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--cache-db")
    parser.add_argument("--workspace-root")
    sub = parser.add_subparsers(dest="command", required=True)
    export_parser = sub.add_parser("export")
    export_parser.add_argument("--output", required=True)
    import_parser = sub.add_parser("import")
    import_parser.add_argument("--input", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    try:
        if args.command == "export":
            document = export_project(
                args.binary,
                cache_path=args.cache_db,
                workspace_root=args.workspace_root,
            )
            Path(args.output).write_text(dumps_project(document), encoding="utf-8")
            print(json.dumps({"ok": True, "output": str(Path(args.output))}))
        else:
            document = json.loads(Path(args.input).read_text(encoding="utf-8"))
            report = import_project(
                args.binary,
                document,
                cache_path=args.cache_db,
                workspace_root=args.workspace_root,
            )
            print(json.dumps({"ok": True, "report": report}, ensure_ascii=False))
        return 0
    except (OSError, json.JSONDecodeError, ProjectFormatError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
