# SPDX-License-Identifier: AGPL-3.0-only
"""Persist applied typed C references and expose cross-view lookup helpers."""

from __future__ import annotations

import argparse
import json
import os
import sys
from hashlib import sha256
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.shared.utils import normalize_addr as _normalize_addr

TYPED_STRUCT_REFS_REL_PATH = os.path.join(".pile-ou-face", "typed_struct_refs.json")


def get_typed_struct_refs_path(workspace_root: str | None = None) -> str:
    root = workspace_root or os.getcwd()
    return os.path.join(root, TYPED_STRUCT_REFS_REL_PATH)


def _normalize_binary_key(binary_path: str | None) -> str:
    if not binary_path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(str(binary_path)))
    except Exception:
        return str(binary_path or "")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        return default


def _sanitize_field(field: dict[str, Any]) -> dict[str, Any]:
    addr = _normalize_addr(field.get("addr", ""))
    return {
        "field_name": str(field.get("field_name") or field.get("name") or "").strip(),
        "field_type": str(field.get("field_type") or field.get("type") or "").strip(),
        "offset": _safe_int(field.get("offset"), 0),
        "absolute_offset": _safe_int(field.get("absolute_offset"), 0),
        "addr": addr or str(field.get("addr") or "").strip(),
        "tag": str(field.get("tag") or "").strip(),
        "size": max(0, _safe_int(field.get("size"), 0)),
    }


def _sanitize_applied_struct(applied_struct: dict[str, Any]) -> dict[str, Any]:
    name = str(applied_struct.get("name") or "").strip()
    if not name:
        raise ValueError("Nom de type manquant.")
    kind = str(applied_struct.get("kind") or "struct").strip() or "struct"
    addr = _normalize_addr(applied_struct.get("addr", ""))
    if not addr:
        raise ValueError("Adresse de type manquante.")
    fields = [
        _sanitize_field(field)
        for field in (applied_struct.get("fields") or [])
        if isinstance(field, dict)
    ]
    return {
        "name": name,
        "kind": kind,
        "addr": addr,
        "section": str(applied_struct.get("section") or "").strip(),
        "offset": _safe_int(applied_struct.get("offset"), 0),
        "size": max(0, _safe_int(applied_struct.get("size"), 0)),
        "align": max(1, _safe_int(applied_struct.get("align"), 1)),
        "fields": fields,
    }


def load_typed_struct_ref_store(workspace_root: str | None = None) -> dict[str, Any]:
    store_path = get_typed_struct_refs_path(workspace_root)
    if not os.path.isfile(store_path):
        return {"entries": []}
    try:
        with open(store_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return {"entries": []}
    entries = payload.get("entries") if isinstance(payload, dict) else []
    if not isinstance(entries, list):
        entries = []
    return {"entries": entries}


def _write_store(
    entries: list[dict[str, Any]], workspace_root: str | None = None
) -> None:
    store_path = get_typed_struct_refs_path(workspace_root)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    with open(store_path, "w", encoding="utf-8") as fh:
        json.dump({"entries": entries}, fh, indent=2, sort_keys=True)


def save_typed_struct_ref(
    binary_path: str,
    applied_struct: dict[str, Any],
    workspace_root: str | None = None,
) -> dict[str, Any]:
    binary_key = _normalize_binary_key(binary_path)
    if not binary_key:
        raise ValueError("Chemin binaire manquant.")
    sanitized = _sanitize_applied_struct(applied_struct)
    store = load_typed_struct_ref_store(workspace_root)
    entry = {
        "binary": binary_key,
        "name": sanitized["name"],
        "kind": sanitized["kind"],
        "addr": sanitized["addr"],
        "section": sanitized["section"],
        "offset": sanitized["offset"],
        "size": sanitized["size"],
        "align": sanitized["align"],
        "fields": sanitized["fields"],
    }
    deduped = [
        current
        for current in store["entries"]
        if not (
            _normalize_binary_key(current.get("binary")) == binary_key
            and _normalize_addr(current.get("addr", "")) == sanitized["addr"]
            and str(current.get("name") or "").strip() == sanitized["name"]
        )
    ]
    deduped.append(entry)
    deduped.sort(
        key=lambda item: (
            _normalize_binary_key(item.get("binary")),
            _safe_int(item.get("addr"), 0),
            str(item.get("name") or ""),
        )
    )
    _write_store(deduped, workspace_root)
    return {"error": None, "entry": entry, "entries": deduped}


def list_typed_struct_refs(
    binary_path: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    binary_key = _normalize_binary_key(binary_path) if binary_path else ""
    store = load_typed_struct_ref_store(workspace_root)
    entries = store["entries"]
    if binary_key:
        entries = [
            entry
            for entry in entries
            if _normalize_binary_key(entry.get("binary")) == binary_key
        ]
    return {"error": None, "entries": entries}


def _field_label(entry: dict[str, Any], field: dict[str, Any]) -> str:
    struct_name = str(entry.get("name") or "").strip()
    field_name = str(field.get("field_name") or "").strip()
    return f"{struct_name}.{field_name}" if field_name else struct_name


def _field_comment(entry: dict[str, Any], field: dict[str, Any]) -> str:
    struct_name = str(entry.get("name") or "").strip()
    type_kind = str(entry.get("kind") or "struct").strip() or "struct"
    field_name = str(field.get("field_name") or "").strip()
    field_type = str(field.get("field_type") or "").strip()
    pieces = [f"{type_kind} {struct_name}"]
    if field_name:
        pieces.append(f"champ {field_name}")
    if field_type:
        pieces.append(field_type)
    addr = _normalize_addr(field.get("addr", "")) or _normalize_addr(
        entry.get("addr", "")
    )
    if addr:
        pieces.append(f"@ {addr}")
    return " • ".join(pieces)


def build_typed_struct_index(
    binary_path: str | None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    entries = list_typed_struct_refs(binary_path, workspace_root).get("entries", [])
    exact_by_addr: dict[str, dict[str, Any]] = {}
    struct_ranges: list[dict[str, Any]] = []
    for entry in entries:
        struct_addr = _normalize_addr(entry.get("addr", ""))
        size = max(0, _safe_int(entry.get("size"), 0))
        start = _safe_int(struct_addr, -1)
        if struct_addr and start >= 0 and size > 0:
            struct_ranges.append(
                {
                    "name": str(entry.get("name") or "").strip(),
                    "addr": struct_addr,
                    "end_addr": f"0x{start + size:x}",
                    "size": size,
                    "section": str(entry.get("section") or "").strip(),
                }
            )
        if struct_addr and struct_addr not in exact_by_addr:
            entry_kind = str(entry.get("kind") or "struct").strip() or "struct"
            exact_by_addr[struct_addr] = {
                "kind": entry_kind,
                "label": str(entry.get("name") or "").strip(),
                "comment": f"{entry_kind} {entry.get('name') or ''} @ {struct_addr}".strip(),
                "addr": struct_addr,
                "struct_name": str(entry.get("name") or "").strip(),
                "struct_kind": entry_kind,
                "section": str(entry.get("section") or "").strip(),
            }
        for field in entry.get("fields") or []:
            field_addr = _normalize_addr(field.get("addr", ""))
            if not field_addr:
                continue
            exact_by_addr[field_addr] = {
                "kind": "field",
                "label": _field_label(entry, field),
                "comment": _field_comment(entry, field),
                "addr": field_addr,
                "struct_addr": struct_addr,
                "struct_name": str(entry.get("name") or "").strip(),
                "struct_kind": str(entry.get("kind") or "struct").strip() or "struct",
                "field_name": str(field.get("field_name") or "").strip(),
                "field_type": str(field.get("field_type") or "").strip(),
                "field_offset": _safe_int(field.get("offset"), 0),
                "field_size": max(0, _safe_int(field.get("size"), 0)),
                "section": str(entry.get("section") or "").strip(),
            }
    return {"entries": entries, "exact_by_addr": exact_by_addr, "ranges": struct_ranges}


def typed_struct_signature(
    binary_path: str | None, workspace_root: str | None = None
) -> str:
    entries = list_typed_struct_refs(binary_path, workspace_root).get("entries", [])
    payload = json.dumps(entries, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return sha256(payload).hexdigest()[:16]


def collect_typed_struct_hints(
    index: dict[str, Any] | None,
    addresses: list[str] | tuple[str, ...] | set[str],
) -> list[dict[str, Any]]:
    exact_by_addr = (index or {}).get("exact_by_addr") or {}
    hints: list[dict[str, Any]] = []
    seen: set[str] = set()
    for addr in addresses or []:
        normalized = _normalize_addr(addr)
        if not normalized:
            continue
        hit = exact_by_addr.get(normalized)
        if not hit:
            continue
        key = f"{hit.get('kind')}:{normalized}:{hit.get('label')}"
        if key in seen:
            continue
        seen.add(key)
        hints.append(dict(hit))
    return hints


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Persist applied typed C references for cross-view hints"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    save_parser = sub.add_parser("save")
    save_parser.add_argument("--binary", required=True)
    save_parser.add_argument("--struct-json", required=True)

    list_parser = sub.add_parser("list")
    list_parser.add_argument("--binary", default=None)

    args = parser.parse_args()
    try:
        if args.command == "save":
            with open(args.struct_json, encoding="utf-8") as fh:
                applied_struct = json.load(fh)
            result = save_typed_struct_ref(args.binary, applied_struct)
        else:
            result = list_typed_struct_refs(args.binary)
    except Exception as exc:
        result = {"error": str(exc), "entries": []}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
