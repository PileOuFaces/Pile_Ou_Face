# SPDX-License-Identifier: AGPL-3.0-only
"""Import versioned reverse-engineering metadata into Host persistence stores."""

from __future__ import annotations

import argparse
import copy
import json
import re
from typing import Any

from backends.static.annotations.annotation_db import hash_binary_content
from backends.static.annotations.annotations import (
    KIND_BOOKMARK,
    KIND_BOOKMARK_COLOR,
    KIND_COMMENT,
    KIND_RENAME,
    AnnotationStore,
)
from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.structs import (
    _normalize_binary_key,
    _validate_definition,
    import_type_definitions,
)

FORMAT = "pile-ou-face.canonical-import/v1"
IMPORT_SOURCE = "ghidra"
_TYPE_NAME = re.compile(r"^[A-Za-z_]\w*$")


class CanonicalImportError(ValueError):
    """Raised when the canonical document cannot safely be imported."""


def _address(value: Any) -> str:
    if isinstance(value, int) and value >= 0:
        return hex(value)
    text = str(value or "").strip().lower()
    try:
        return hex(int(text, 0))
    except (TypeError, ValueError) as exc:
        raise CanonicalImportError(f"Adresse invalide: {value!r}") from exc


def _report() -> dict[str, Any]:
    return {
        "imported": 0,
        "skipped": 0,
        "conflicts": 0,
        "annotations": {"imported": 0, "skipped": 0, "conflicts": 0},
        "types": {"imported": 0, "skipped": 0, "conflicts": 0},
        "diagnostics": [],
    }


def _count(report: dict[str, Any], section: str, outcome: str) -> None:
    report[outcome] += 1
    report[section][outcome] += 1


def _annotation_candidates(document: dict[str, Any]) -> list[tuple[str, str, str]]:
    candidates: list[tuple[str, str, str]] = []
    for function in document.get("functions") or []:
        addr = _address(function.get("addr"))
        if function.get("name"):
            candidates.append((addr, KIND_RENAME, str(function["name"])))
        if function.get("comment"):
            candidates.append((addr, KIND_COMMENT, str(function["comment"])))
    for comment in document.get("comments") or []:
        candidates.append(
            (
                _address(comment.get("addr")),
                KIND_COMMENT,
                str(comment.get("text") or ""),
            )
        )
    for bookmark in document.get("bookmarks") or []:
        addr = _address(bookmark.get("addr"))
        candidates.append((addr, KIND_BOOKMARK, str(bookmark.get("label") or addr)))
        if bookmark.get("color"):
            candidates.append((addr, KIND_BOOKMARK_COLOR, str(bookmark["color"])))
    return candidates


def _collect_types(
    document: dict[str, Any], report: dict[str, Any]
) -> dict[str, dict[str, Any]]:
    definitions: dict[str, dict[str, Any]] = {}
    raw_types = document.get("types") or []
    if isinstance(raw_types, dict):
        raw_types = [dict(value, name=name) for name, value in raw_types.items()]
    for item in raw_types:
        if not isinstance(item, dict):
            _count(report, "types", "skipped")
            report["diagnostics"].append("Type Ghidra invalide ignoré")
            continue
        name = str((item or {}).get("name") or "")
        kind = str((item or {}).get("kind") or "")
        if not _TYPE_NAME.fullmatch(name) or kind not in {
            "struct",
            "union",
            "enum",
            "typedef",
            "function",
        }:
            _count(report, "types", "skipped")
            report["diagnostics"].append(
                f"Type Ghidra non supporté ignoré: {name or '<sans nom>'}"
            )
            continue
        candidate = copy.deepcopy(dict(item))
        try:
            _validate_definition(name, candidate)
        except ValueError as exc:
            _count(report, "types", "skipped")
            report["diagnostics"].append(f"Type Ghidra {name} ignoré: {exc}")
            continue
        candidate["name"] = name
        definitions[name] = candidate
    for function in document.get("functions") or []:
        prototype = function.get("prototype")
        name = str(function.get("name") or "")
        if prototype and _TYPE_NAME.fullmatch(name) and isinstance(prototype, dict):
            candidate = {**copy.deepcopy(prototype), "name": name, "kind": "function"}
            try:
                _validate_definition(name, candidate)
            except ValueError as exc:
                _count(report, "types", "skipped")
                report["diagnostics"].append(f"Prototype Ghidra {name} ignoré: {exc}")
            else:
                definitions.setdefault(name, candidate)
    return definitions


def _type_signature(definition: dict[str, Any]) -> dict[str, Any]:
    """Strip derived fields so persisted and freshly exported types compare equally."""
    result = copy.deepcopy(definition)
    result.pop("name", None)
    result.pop("value_map", None)
    return result


def import_canonical_document(
    binary_path: str,
    document: dict[str, Any],
    *,
    cache_path: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    """Validate and conservatively merge one canonical metadata document."""
    if document.get("format") != FORMAT:
        raise CanonicalImportError(f"Format non supporté: {document.get('format')!r}")
    expected_hash = str(document.get("binary_sha256") or "").lower()
    actual_hash = hash_binary_content(binary_path)
    if expected_hash != actual_hash:
        raise CanonicalImportError(
            f"Empreinte SHA-256 différente (export={expected_hash or '<absente>'}, binaire={actual_hash})."
        )

    report = _report()
    with AnnotationStore(binary_path, cache_path=cache_path) as store:
        existing = {(row["addr"], row["kind"]): row for row in store.list()}
        for addr, kind, value in _annotation_candidates(document):
            current = existing.get((addr, kind))
            if current and current["value"] == value:
                _count(report, "annotations", "skipped")
                continue
            if current and current.get("source") != IMPORT_SOURCE:
                _count(report, "annotations", "conflicts")
                report["diagnostics"].append(
                    f"Annotation manuelle conservée: {addr} ({kind})"
                )
                continue
            store.import_annotation(addr, kind, value, source=IMPORT_SOURCE)
            existing[(addr, kind)] = {
                "addr": addr,
                "kind": kind,
                "value": value,
                "source": IMPORT_SOURCE,
            }
            _count(report, "annotations", "imported")

    definitions = _collect_types(document, report)
    if definitions:
        binary_key = _normalize_binary_key(binary_path)
        database = StructDb(workspace_root)
        current = database.load_definitions(binary_key)["definitions"]
        sources = database.load_import_sources(binary_key)
        accepted: dict[str, dict[str, Any]] = {}
        for name, definition in definitions.items():
            if name in current and _type_signature(current[name]) == _type_signature(
                definition
            ):
                _count(report, "types", "skipped")
            elif name in current and sources.get(name) != IMPORT_SOURCE:
                _count(report, "types", "conflicts")
                report["diagnostics"].append(f"Type manuel conservé: {name}")
            else:
                accepted[name] = definition
        if accepted:
            try:
                import_type_definitions(
                    binary_path, accepted, IMPORT_SOURCE, workspace_root
                )
            except ValueError as exc:
                for _name in accepted:
                    _count(report, "types", "skipped")
                report["diagnostics"].append(f"Types Ghidra ignorés: {exc}")
            else:
                for _name in accepted:
                    _count(report, "types", "imported")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Import canonical reverse-engineering metadata"
    )
    parser.add_argument("--binary", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--cache-db")
    parser.add_argument("--workspace-root")
    args = parser.parse_args()
    try:
        with open(args.input, encoding="utf-8") as stream:
            document = json.load(stream)
        result = import_canonical_document(
            args.binary,
            document,
            cache_path=args.cache_db,
            workspace_root=args.workspace_root,
        )
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except (OSError, json.JSONDecodeError, CanonicalImportError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
