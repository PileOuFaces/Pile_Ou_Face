# SPDX-License-Identifier: AGPL-3.0-only
"""Bind function parameters/locals to catalog types (struct/union/enum) for pseudocode rendering."""

from __future__ import annotations

import argparse
import json
import os
import sys
from hashlib import sha256
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import normalize_addr as _normalize_addr
from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.structs import (
    _resolve_typedef_chain,
    compute_struct_layout,
)

logger = get_logger(__name__)

_VAR_KINDS = {"param", "local"}
_TYPE_KINDS = {"struct", "union", "enum"}
_MAX_FIELD_CHAIN_DEPTH = 3


def _normalize_binary_key(binary_path: str | None) -> str:
    if not binary_path:
        return ""
    try:
        return os.path.normcase(os.path.abspath(str(binary_path)))
    except Exception:
        logger.debug(
            "Failed to normalize binary path %r, using raw value",
            binary_path,
            exc_info=True,
        )
        return str(binary_path or "")


def _safe_int(value: Any, default: int = 0) -> int:
    try:
        return int(str(value), 0) if isinstance(value, str) else int(value)
    except Exception:
        logger.debug(
            "Failed to parse %r as int, falling back to default=%r",
            value,
            default,
            exc_info=True,
        )
        return default


def _sanitize_binding(binding: dict[str, Any]) -> dict[str, Any]:
    var_kind = str(binding.get("var_kind") or "").strip()
    if var_kind not in _VAR_KINDS:
        raise ValueError(f"var_kind invalide: {var_kind!r} (attendu param/local).")
    var_key = str(binding.get("var_key") or "").strip()
    if not var_key:
        raise ValueError("var_key manquant.")
    if var_kind == "param":
        if _safe_int(var_key, -1) <= 0:
            raise ValueError("var_key pour un param doit être un ordinal >= 1.")
    else:
        if not var_key.lstrip("-").isdigit():
            raise ValueError("var_key pour un local doit être un offset entier signé.")
    type_name = str(binding.get("type_name") or "").strip()
    if not type_name:
        raise ValueError("type_name manquant.")
    type_kind = str(binding.get("type_kind") or "").strip()
    if type_kind not in _TYPE_KINDS:
        raise ValueError(
            f"type_kind invalide: {type_kind!r} (attendu struct/union/enum)."
        )
    return {
        "var_kind": var_kind,
        "var_key": var_key,
        "type_name": type_name,
        "type_kind": type_kind,
        "pointer_level": max(0, _safe_int(binding.get("pointer_level"), 0)),
    }


def save_typed_var_binding(
    binary_path: str,
    func_addr: str,
    binding: dict[str, Any],
    workspace_root: str | None = None,
) -> dict[str, Any]:
    binary_key = _normalize_binary_key(binary_path)
    if not binary_key:
        raise ValueError("Chemin binaire manquant.")
    normalized_func_addr = _normalize_addr(func_addr)
    if not normalized_func_addr:
        raise ValueError("Adresse de fonction manquante.")
    sanitized = _sanitize_binding(binding)
    entry = {
        "binary": binary_key,
        "func_addr": normalized_func_addr,
        **sanitized,
    }
    database = StructDb(workspace_root)
    database.save_typed_var_binding(entry)
    return {
        "error": None,
        "entry": entry,
        "entries": database.list_typed_var_bindings(binary_key, normalized_func_addr),
    }


def list_typed_var_bindings(
    binary_path: str | None = None,
    func_addr: str | None = None,
    workspace_root: str | None = None,
) -> dict[str, Any]:
    binary_key = _normalize_binary_key(binary_path) if binary_path else ""
    normalized_func_addr = _normalize_addr(func_addr) if func_addr else ""
    entries = StructDb(workspace_root).list_typed_var_bindings(
        binary_key or None, normalized_func_addr or None
    )
    return {"error": None, "entries": entries}


def _var_identity(var_kind: str, var_key: str) -> str:
    return f"{var_kind}:{var_key}"


def _expand_struct_fields(
    identity: str,
    type_name: str,
    definitions: dict[str, dict[str, Any]],
    ptr_size: int,
    field_access_map: dict[str, dict[int, str]],
    enum_literal_map: dict[str, dict[int, str]],
    visited_types: frozenset[str],
    depth: int,
) -> None:
    """Populate field_access_map/enum_literal_map for `identity` and, for any
    field that is itself a single-level pointer-to-struct/union, recurse to
    build a chained identity ("base->inner->field") up to `_MAX_FIELD_CHAIN_DEPTH`.

    `visited_types` guards against self-referential chains (e.g. a linked-list
    `struct Node *next` field) expanding indefinitely.
    """
    if depth > _MAX_FIELD_CHAIN_DEPTH or type_name in visited_types:
        return
    try:
        layout = compute_struct_layout(definitions, type_name, ptr_size)
    except Exception:
        logger.warning(
            "Failed to compute struct layout for type %r (identity=%r), "
            "type binding will not be applied",
            type_name,
            identity,
            exc_info=True,
        )
        return
    next_visited = visited_types | {type_name}
    for field in layout.get("fields") or []:
        offset = int(field["offset"])
        field_name = str(field["name"])
        field_access_map.setdefault(identity, {})[offset] = field_name
        if field.get("type_kind") == "enum" and field.get("enum_values"):
            enum_identity = f"{identity}->{field_name}"
            enum_literal_map.setdefault(enum_identity, {}).update(
                {int(item["value"]): str(item["name"]) for item in field["enum_values"]}
            )
        elif (
            field.get("type_kind") == "pointer"
            and int(field.get("pointer_level") or 0) == 1
        ):
            nested_name, nested_definition, _ = _resolve_typedef_chain(
                definitions, str(field.get("type") or "")
            )
            if nested_definition and str(nested_definition.get("kind") or "") in {
                "struct",
                "union",
            }:
                _expand_struct_fields(
                    f"{identity}->{field_name}",
                    nested_name,
                    definitions,
                    ptr_size,
                    field_access_map,
                    enum_literal_map,
                    next_visited,
                    depth + 1,
                )


def build_typed_var_binding_index(
    binary_path: str,
    func_addr: str,
    workspace_root: str | None = None,
    ptr_size: int = 8,
) -> dict[str, Any]:
    """Resolve each binding for a function into field-access and enum-literal maps.

    Maps are keyed by the binding's stable identity ("param:1", "local:-16"),
    NOT by the decompiler's final display name — the caller (decompile.py) owns
    the var_kind/var_key -> display-name resolution since it has the renamed
    args/stack_vars.
    """
    entries = list_typed_var_bindings(binary_path, func_addr, workspace_root).get(
        "entries", []
    )
    field_access_map: dict[str, dict[int, str]] = {}
    enum_literal_map: dict[str, dict[int, str]] = {}
    if not entries:
        return {
            "field_access_map": field_access_map,
            "enum_literal_map": enum_literal_map,
        }

    definitions = (
        StructDb(workspace_root)
        .load_definitions(_normalize_binary_key(binary_path))
        .get("definitions", {})
    )

    for entry in entries:
        identity = _var_identity(entry["var_kind"], entry["var_key"])
        type_name = entry["type_name"]
        type_kind = entry["type_kind"]
        pointer_level = _safe_int(entry.get("pointer_level"), 0)
        definition = definitions.get(type_name)
        if not definition:
            continue
        if type_kind == "enum":
            value_map = definition.get("value_map") or {}
            enum_literal_map.setdefault(identity, {}).update(
                {int(value): name for name, value in value_map.items()}
            )
            continue
        if pointer_level != 1:
            # Only single-level pointer-to-struct is rewritten as base->field;
            # deeper chains from there are expanded by _expand_struct_fields.
            continue
        _expand_struct_fields(
            identity,
            type_name,
            definitions,
            ptr_size,
            field_access_map,
            enum_literal_map,
            frozenset(),
            0,
        )

    return {"field_access_map": field_access_map, "enum_literal_map": enum_literal_map}


def typed_var_binding_signature(
    binary_path: str | None,
    func_addr: str | None = None,
    workspace_root: str | None = None,
) -> str:
    entries = list_typed_var_bindings(binary_path, func_addr, workspace_root).get(
        "entries", []
    )
    payload = json.dumps(entries, sort_keys=True, ensure_ascii=True).encode("utf-8")
    return sha256(payload).hexdigest()[:16]


def main() -> int:
    configure_logging()
    parser = argparse.ArgumentParser(
        description="Bind function parameters/locals to catalog types for pseudocode rendering"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    bind_parser = sub.add_parser("bind")
    bind_parser.add_argument("--binary", required=True)
    bind_parser.add_argument("--func-addr", required=True)
    bind_parser.add_argument("--var-kind", required=True, choices=sorted(_VAR_KINDS))
    bind_parser.add_argument("--var-key", required=True)
    bind_parser.add_argument("--type-name", required=True)
    bind_parser.add_argument("--type-kind", required=True, choices=sorted(_TYPE_KINDS))
    bind_parser.add_argument("--pointer-level", type=int, default=0)

    list_parser = sub.add_parser("list")
    list_parser.add_argument("--binary", default=None)
    list_parser.add_argument("--func-addr", default=None)

    args = parser.parse_args()
    try:
        if args.command == "bind":
            result = save_typed_var_binding(
                args.binary,
                args.func_addr,
                {
                    "var_kind": args.var_kind,
                    "var_key": args.var_key,
                    "type_name": args.type_name,
                    "type_kind": args.type_kind,
                    "pointer_level": args.pointer_level,
                },
            )
        else:
            result = list_typed_var_bindings(args.binary, args.func_addr)
    except Exception as exc:
        result = {"error": str(exc), "entries": []}
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
