# SPDX-License-Identifier: AGPL-3.0-only
"""Bridge SQLite pour les annotations du Hub.

Le Hub manipule un objet JSON par adresse :

    {"0x401000": {"comment": "...", "name": "...", "bookmark": true}}

Le stockage persistant vit dans la table SQLite ``annotations`` des fichiers
``.pfdb``. Ce bridge garde le format UI stable tout en remplaçant le JSON comme
source de vérité.
"""

from __future__ import annotations

import argparse
import json
from typing import Any

from backends.static.cache.cache import DisasmCache

FIELD_TO_KIND = {
    "comment": "comment",
    "name": "rename",
    "bookmark": "bookmark",
    "bookmarkLabel": "bookmarkLabel",
    "bookmarkColor": "bookmarkColor",
    "updated": "updated",
    "bookmarkUpdated": "bookmarkUpdated",
    "reviewStatus": "reviewStatus",
    "reviewNotes": "reviewNotes",
    "reviewUpdated": "reviewUpdated",
}

KIND_TO_FIELD = {kind: field for field, kind in FIELD_TO_KIND.items()}


def _decode_value(raw: str) -> Any:
    try:
        return json.loads(raw)
    except Exception:
        return raw


def _encode_value(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def export_annotations(binary_path: str, cache_db: str) -> dict[str, dict[str, Any]]:
    with DisasmCache(cache_db) as cache:
        rows = cache.get_annotations(binary_path)

    annotations: dict[str, dict[str, Any]] = {}
    for row in rows:
        addr = str(row.get("addr") or "").strip()
        kind = str(row.get("kind") or "").strip()
        if not addr or kind not in KIND_TO_FIELD:
            continue
        field = KIND_TO_FIELD[kind]
        annotations.setdefault(addr, {})[field] = _decode_value(
            str(row.get("value", ""))
        )
    return annotations


def replace_annotations(
    binary_path: str,
    cache_db: str,
    annotations: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    normalized: dict[str, dict[str, Any]] = {}
    for raw_addr, raw_entry in (annotations or {}).items():
        addr = str(raw_addr or "").strip()
        if not addr:
            continue
        if not addr.startswith("0x"):
            addr = f"0x{addr}"
        if not isinstance(raw_entry, dict):
            continue
        entry: dict[str, Any] = {}
        for field in FIELD_TO_KIND:
            value = raw_entry.get(field)
            if value in (None, ""):
                continue
            entry[field] = value
        if entry:
            normalized[addr] = entry

    with DisasmCache(cache_db) as cache:
        existing_addrs = {
            str(row.get("addr") or "")
            for row in cache.get_annotations(binary_path)
            if row.get("addr")
        }
        for addr in existing_addrs:
            cache.delete_annotation(binary_path, addr)
        for addr, entry in normalized.items():
            for field, value in entry.items():
                kind = FIELD_TO_KIND[field]
                cache.save_annotation(binary_path, addr, kind, _encode_value(value))

    return export_annotations(binary_path, cache_db)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage Hub annotations in SQLite")
    parser.add_argument("command", choices=["export", "replace"])
    parser.add_argument("--binary", required=True)
    parser.add_argument("--cache-db", required=True)
    parser.add_argument("--input-json", help="Hub annotations JSON for replace")
    args = parser.parse_args()

    if args.command == "export":
        result = export_annotations(args.binary, args.cache_db)
    else:
        if not args.input_json:
            parser.error("--input-json is required for replace")
        with open(args.input_json, encoding="utf-8") as handle:
            payload = json.load(handle)
        result = replace_annotations(args.binary, args.cache_db, payload)

    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
