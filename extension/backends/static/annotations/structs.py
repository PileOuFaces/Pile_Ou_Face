# SPDX-License-Identifier: AGPL-3.0-only
"""Persist and parse simple user-defined C types for static analysis."""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import ast
import json
import os
import re
import sys
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

STRUCTS_FILE_NAME = "structs.json"

_COMPOUND_RE = re.compile(
    r"(?:(?:typedef)\s+)?(?P<kind>struct|union)(?:\s+(?P<tag>[A-Za-z_]\w*))?\s*\{(?P<body>.*?)\}\s*(?P<alias>[A-Za-z_]\w*)?\s*;",
    re.DOTALL,
)
# Supports C enum and C++ scoped enum (enum class / enum struct) with optional underlying type.
# Examples: enum Mode { A, B };  enum class Color { Red };  enum class S : uint8_t { Ok = 0 };
_ENUM_RE = re.compile(
    r"(?:(?:typedef)\s+)?"
    r"enum(?:\s+(?:class|struct))?"
    r"(?:\s+(?P<tag>[A-Za-z_]\w*))?"
    r"(?:\s*:[^{;]*)?"
    r"\s*\{(?P<body>.*?)\}"
    r"\s*(?P<alias>[A-Za-z_]\w*)?\s*;",
    re.DOTALL,
)
_COMMENT_RE = re.compile(r"/\*.*?\*/|//[^\n]*", re.DOTALL)
# Multidimensional array suffix: matches [N], [M][N], [L][M][N], etc.
_ARRAY_DIMS_RE = re.compile(r"(\[\s*\d+\s*\])+$")
_ARRAY_DIM_RE = re.compile(r"\[\s*(\d+)\s*\]")
# Function pointer field: void (*name)(args) — captures the pointer name
_FUNC_PTR_RE = re.compile(r"\(\s*\*\s*(?:const\s+)?([A-Za-z_]\w*)\s*\)")
_QUALIFIERS = {"const", "volatile", "restrict"}
_PRIMITIVE_TYPES = {
    "_Bool",
    "bool",
    "char",
    "double",
    "float",
    "int",
    "int8_t",
    "int16_t",
    "int32_t",
    "int64_t",
    "long",
    "long long",
    "short",
    "signed char",
    "signed int",
    "signed short",
    "size_t",
    "ssize_t",
    "uint8_t",
    "uint16_t",
    "uint32_t",
    "uint64_t",
    "unsigned char",
    "unsigned int",
    "unsigned long",
    "unsigned long long",
    "unsigned short",
    "uintptr_t",
    "void",
}


def get_struct_store_path(workspace_root: str | None = None) -> str:
    """Return the filesystem path where struct definitions are stored."""
    root = (
        workspace_root or os.environ.get("POF_STORAGE_DIR", "").strip() or os.getcwd()
    )
    return os.path.join(root, STRUCTS_FILE_NAME)


def _strip_comments(source_text: str) -> str:
    return _COMMENT_RE.sub("", source_text or "")


def _normalize_type_name(type_name: str) -> tuple[str, str]:
    cleaned = " ".join(
        part for part in type_name.replace("\n", " ").split() if part not in _QUALIFIERS
    ).strip()
    if cleaned.startswith("struct "):
        return cleaned.split(" ", 1)[1].strip(), "struct"
    if cleaned.startswith("union "):
        return cleaned.split(" ", 1)[1].strip(), "union"
    if cleaned.startswith("enum "):
        return cleaned.split(" ", 1)[1].strip(), "enum"
    return cleaned, "primitive" if cleaned in _PRIMITIVE_TYPES else "struct"


def _parse_field(field_spec: str) -> dict[str, Any]:
    text = " ".join(field_spec.strip().split())
    if not text:
        raise ValueError("Champ vide dans une définition de type.")

    # Function pointer: type (*name)(args) — must be checked before bitfield test
    # Handles: void (*on_event)(int, void*), int (* const transform)(char*, size_t)
    fn_match = _FUNC_PTR_RE.search(text)
    if fn_match:
        name = fn_match.group(1)
        return {
            "name": name,
            "type": "fn_ptr",
            "type_kind": "fn_ptr",
            "pointer_level": 1,
            "array_len": None,
            "array_dims": None,
            "display_type": f"(*{name})(...)",
        }

    if ":" in text:
        raise ValueError(f"Bitfields non supportés: {text}")

    # Multidimensional arrays: char grid[3][4] → array_dims=[3,4], array_len=12
    array_dims: list[int] | None = None
    array_len: int | None = None
    dims_match = _ARRAY_DIMS_RE.search(text)
    if dims_match:
        dims = [int(m.group(1)) for m in _ARRAY_DIM_RE.finditer(dims_match.group(0))]
        array_dims = dims
        array_len = 1
        for d in dims:
            array_len *= d
        text = text[: dims_match.start()].strip()

    name_match = re.search(r"([A-Za-z_]\w*)\s*$", text)
    if not name_match:
        raise ValueError(f"Impossible d'analyser le champ: {field_spec.strip()}")
    name = name_match.group(1)
    left = text[: name_match.start()].strip()
    if not left:
        raise ValueError(f"Type manquant pour le champ: {field_spec.strip()}")

    pointer_level = left.count("*")
    type_name = " ".join(left.replace("*", " ").split())
    if not type_name:
        raise ValueError(f"Type manquant pour le champ: {field_spec.strip()}")
    normalized_type, type_kind = _normalize_type_name(type_name)
    display_array = (
        "".join(f"[{d}]" for d in array_dims)
        if array_dims
        else (f"[{array_len}]" if array_len is not None else "")
    )
    return {
        "name": name,
        "type": normalized_type,
        "type_kind": type_kind,
        "pointer_level": pointer_level,
        "array_len": array_len,
        "array_dims": array_dims,
        "display_type": normalized_type + ("*" * pointer_level) + display_array,
    }


def _eval_enum_expr(expr: str, symbols: dict[str, int]) -> int:
    tree = ast.parse(expr, mode="eval")

    def visit(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return visit(node.body)
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return int(node.value)
        if isinstance(node, ast.Name):
            if node.id not in symbols:
                raise ValueError(f"Identifiant d'enum inconnu: {node.id}")
            return int(symbols[node.id])
        if isinstance(node, ast.UnaryOp) and isinstance(
            node.op, (ast.UAdd, ast.USub, ast.Invert)
        ):
            value = visit(node.operand)
            if isinstance(node.op, ast.UAdd):
                return +value
            if isinstance(node.op, ast.USub):
                return -value
            return ~value
        if isinstance(node, ast.BinOp):
            left = visit(node.left)
            right = visit(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Sub):
                return left - right
            if isinstance(node.op, ast.Mult):
                return left * right
            if isinstance(node.op, ast.Div):
                return left // right
            if isinstance(node.op, ast.Mod):
                return left % right
            if isinstance(node.op, ast.LShift):
                return left << right
            if isinstance(node.op, ast.RShift):
                return left >> right
            if isinstance(node.op, ast.BitOr):
                return left | right
            if isinstance(node.op, ast.BitAnd):
                return left & right
            if isinstance(node.op, ast.BitXor):
                return left ^ right
        raise ValueError(f"Expression d'enum non supportée: {expr}")

    return visit(tree)


def _parse_enum_members(body: str) -> list[dict[str, Any]]:
    members: list[dict[str, Any]] = []
    current_value = -1
    known: dict[str, int] = {}
    for raw_member in body.split(","):
        candidate = raw_member.strip()
        if not candidate:
            continue
        if "=" in candidate:
            name, expr = candidate.split("=", 1)
            member_name = name.strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", member_name):
                raise ValueError(f"Membre d'enum invalide: {candidate}")
            current_value = _eval_enum_expr(expr.strip(), known)
        else:
            member_name = candidate.strip()
            if not re.fullmatch(r"[A-Za-z_]\w*", member_name):
                raise ValueError(f"Membre d'enum invalide: {candidate}")
            current_value += 1
        known[member_name] = current_value
        members.append({"name": member_name, "value": current_value})
    return members


def parse_struct_definitions(source_text: str) -> dict[str, dict[str, Any]]:
    """Parse C-style struct/union/enum definitions from source text and return a dict of type definitions."""
    cleaned = _strip_comments(source_text)
    definitions: dict[str, dict[str, Any]] = {}
    for match in _COMPOUND_RE.finditer(cleaned):
        body = match.group("body") or ""
        tag = match.group("tag")
        alias = match.group("alias")
        struct_name = (alias or tag or "").strip()
        kind = str(match.group("kind") or "struct").strip() or "struct"
        if not struct_name:
            raise ValueError(f"{kind.title()} sans nom non supportée.")
        fields: list[dict[str, Any]] = []
        for raw_field in body.split(";"):
            candidate = raw_field.strip()
            if not candidate:
                continue
            fields.append(_parse_field(candidate))
        if not fields:
            raise ValueError(
                f"Le type {kind} {struct_name} ne contient aucun champ reconnu."
            )
        definitions[struct_name] = {
            "name": struct_name,
            "kind": kind,
            "fields": fields,
        }
    for match in _ENUM_RE.finditer(cleaned):
        body = match.group("body") or ""
        tag = match.group("tag")
        alias = match.group("alias")
        enum_name = (alias or tag or "").strip()
        if not enum_name:
            raise ValueError("Enum sans nom non supportée.")
        members = _parse_enum_members(body)
        if not members:
            raise ValueError(f"L'enum {enum_name} ne contient aucun membre reconnu.")
        definitions[enum_name] = {
            "name": enum_name,
            "kind": "enum",
            "values": members,
            "value_map": {member["name"]: member["value"] for member in members},
        }
    if source_text.strip() and not definitions:
        raise ValueError("Aucun type C reconnu dans la définition fournie.")
    return definitions


def load_struct_store(workspace_root: str | None = None) -> dict[str, Any]:
    """Load the full struct store with all type definitions and source."""
    store_path = get_struct_store_path(workspace_root)
    if not os.path.isfile(store_path):
        return {"source": "", "definitions": {}}
    try:
        with open(store_path, encoding="utf-8") as fh:
            payload = json.load(fh)
    except Exception:
        return {"source": "", "definitions": {}}
    source = payload.get("source") if isinstance(payload, dict) else ""
    definitions = payload.get("definitions") if isinstance(payload, dict) else {}
    if not isinstance(source, str):
        source = ""
    if not isinstance(definitions, dict):
        definitions = {}
    return {"source": source, "definitions": definitions}


def list_struct_store(workspace_root: str | None = None) -> dict[str, Any]:
    """List all user-defined struct/union/enum types currently saved in the workspace."""
    store = load_struct_store(workspace_root)
    structs = [
        {
            "name": name,
            "kind": str((definition or {}).get("kind") or "struct"),
            "field_count": len((definition or {}).get("fields") or []),
        }
        for name, definition in sorted(store["definitions"].items())
        if str((definition or {}).get("kind") or "struct") in {"struct", "union"}
    ]
    return {"structs": structs, "source": store["source"], "error": None}


def save_struct_source(
    source_text: str, workspace_root: str | None = None
) -> dict[str, Any]:
    """Save C-style struct/union/enum definitions so they can be applied to binary data."""
    definitions = parse_struct_definitions(source_text)
    store_path = get_struct_store_path(workspace_root)
    os.makedirs(os.path.dirname(store_path), exist_ok=True)
    payload = {
        "source": source_text,
        "definitions": definitions,
    }
    with open(store_path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    return list_struct_store(workspace_root)


_PRIMITIVE_LAYOUTS: dict[str, tuple[int, int, str]] = {
    "_Bool": (1, 1, "bool"),
    "bool": (1, 1, "bool"),
    "char": (1, 1, "char"),
    "double": (8, 8, "f64"),
    "float": (4, 4, "f32"),
    "int": (4, 4, "i32"),
    "int8_t": (1, 1, "i8"),
    "int16_t": (2, 2, "i16"),
    "int32_t": (4, 4, "i32"),
    "int64_t": (8, 8, "i64"),
    "long": (8, 8, "i64"),
    "long long": (8, 8, "i64"),
    "short": (2, 2, "i16"),
    "signed char": (1, 1, "i8"),
    "signed int": (4, 4, "i32"),
    "signed short": (2, 2, "i16"),
    "size_t": (8, 8, "usize"),
    "ssize_t": (8, 8, "isize"),
    "uint8_t": (1, 1, "u8"),
    "uint16_t": (2, 2, "u16"),
    "uint32_t": (4, 4, "u32"),
    "uint64_t": (8, 8, "u64"),
    "unsigned char": (1, 1, "u8"),
    "unsigned int": (4, 4, "u32"),
    "unsigned long": (8, 8, "u64"),
    "unsigned long long": (8, 8, "u64"),
    "unsigned short": (2, 2, "u16"),
    "uintptr_t": (8, 8, "usize"),
}


def _align_up(value: int, alignment: int) -> int:
    if alignment <= 1:
        return value
    return (value + alignment - 1) // alignment * alignment


def _primitive_layout(type_name: str, ptr_size: int) -> tuple[int, int, str] | None:
    if type_name in {"size_t", "ssize_t", "uintptr_t"}:
        tag = {"size_t": "usize", "ssize_t": "isize", "uintptr_t": "usize"}[type_name]
        return ptr_size, ptr_size, tag
    return _PRIMITIVE_LAYOUTS.get(type_name)


def compute_struct_layout(
    definitions: dict[str, dict[str, Any]],
    struct_name: str,
    ptr_size: int,
) -> dict[str, Any]:
    """Compute the memory layout (offsets, sizes, alignment) of a named struct from a definitions dict."""
    cache: dict[str, dict[str, Any]] = {}

    def build(name: str, stack: set[str]) -> dict[str, Any]:
        if name in cache:
            return cache[name]
        if name in stack:
            raise ValueError(f"Type récursif non supporté: {name}")
        definition = definitions.get(name)
        if not definition:
            raise ValueError(f"Type inconnu: {name}")
        definition_kind = str(definition.get("kind") or "struct")
        if definition_kind == "enum":
            raise ValueError(f"Un enum ne peut pas être appliqué comme struct: {name}")
        offset = 0
        max_align = 1
        fields_out: list[dict[str, Any]] = []
        next_stack = set(stack)
        next_stack.add(name)
        for field in definition.get("fields") or []:
            field_kind = field.get("type_kind") or "primitive"
            pointer_level = int(field.get("pointer_level") or 0)
            array_len = field.get("array_len")
            array_len = int(array_len) if array_len is not None else None
            base_type = str(field.get("type") or "")
            named_definition = definitions.get(base_type) if base_type else None
            if pointer_level > 0:
                elem_size = ptr_size
                elem_align = ptr_size
                tag = "fn_ptr" if field_kind == "fn_ptr" else "ptr"
                resolved_kind = "pointer"
            elif (
                named_definition
                and str(named_definition.get("kind") or "") == "enum"
                or field_kind == "enum"
            ):
                elem_size = 4
                elem_align = 4
                tag = "enum"
                resolved_kind = "enum"
            elif named_definition and str(named_definition.get("kind") or "") in {
                "struct",
                "union",
            }:
                nested = build(base_type, next_stack)
                elem_size = int(nested["size"])
                elem_align = int(nested["align"])
                tag = str(nested.get("kind") or field_kind)
                resolved_kind = str(nested.get("kind") or field_kind)
            else:
                primitive = _primitive_layout(base_type, ptr_size)
                if primitive is None:
                    raise ValueError(f"Type de champ non supporté: {base_type}")
                elem_size, elem_align, tag = primitive
                resolved_kind = "primitive"

            count = array_len or 1
            field_align = elem_align
            field_size = elem_size * count
            field_offset = (
                0 if definition_kind == "union" else _align_up(offset, field_align)
            )
            fields_out.append(
                {
                    "name": field["name"],
                    "type": base_type,
                    "type_kind": resolved_kind,
                    "tag": tag,
                    "offset": field_offset,
                    "size": field_size,
                    "align": field_align,
                    "elem_size": elem_size,
                    "elem_align": elem_align,
                    "pointer_level": pointer_level,
                    "array_len": array_len,
                    "array_dims": field.get("array_dims"),
                    "display_type": field.get("display_type") or base_type,
                    "enum_values": list((named_definition or {}).get("values") or [])
                    if resolved_kind == "enum"
                    else [],
                }
            )
            if definition_kind == "union":
                offset = max(offset, field_size)
            else:
                offset = field_offset + field_size
            max_align = max(max_align, field_align)

        size = _align_up(offset, max_align)
        layout = {
            "name": name,
            "kind": definition_kind,
            "size": size,
            "align": max_align,
            "fields": fields_out,
        }
        cache[name] = layout
        return layout

    return build(struct_name, set())


def _load_source_text(args: argparse.Namespace) -> str:
    if args.source_file:
        with open(args.source_file, encoding="utf-8") as fh:
            return fh.read()
    return args.source_text or ""


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage user-defined C types")
    parser.add_argument("action", choices=["list", "save"])
    parser.add_argument("--source-text", default="")
    parser.add_argument("--source-file")
    parser.add_argument("--workspace-root")
    args = parser.parse_args()

    try:
        if args.action == "list":
            result = list_struct_store(args.workspace_root)
        else:
            result = save_struct_source(_load_source_text(args), args.workspace_root)
    except Exception as exc:
        result = {"error": str(exc), "structs": [], "source": ""}

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
