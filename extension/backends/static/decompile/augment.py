#!/usr/bin/env python3
"""Structured, semantics-preserving AI augmentation for decompiled C code."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp.ai_provider import (  # noqa: E402
    call_provider_result,
    resolve_provider_model,
)
from backends.static.cache.cache_store import get_payload, put_payload  # noqa: E402

SCHEMA_VERSION = 1
IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
RESERVED = {
    "auto",
    "break",
    "case",
    "char",
    "const",
    "continue",
    "default",
    "do",
    "double",
    "else",
    "enum",
    "extern",
    "float",
    "for",
    "goto",
    "if",
    "inline",
    "int",
    "long",
    "register",
    "restrict",
    "return",
    "short",
    "signed",
    "sizeof",
    "static",
    "struct",
    "switch",
    "typedef",
    "union",
    "unsigned",
    "void",
    "volatile",
    "while",
    "_Bool",
    "_Complex",
    "_Imaginary",
}
TYPE_RE = re.compile(
    r"^(?:const\s+)?(?:unsigned\s+|signed\s+)?(?:void|char|short|int|long|float|double|"
    r"size_t|ssize_t|u?int(?:8|16|32|64)_t|bool|struct\s+[A-Za-z_]\w*)\s*\*{0,3}$"
)


def extract_json_object(text: str) -> dict[str, Any] | None:
    candidate = re.sub(r"^```(?:json)?\s*|\s*```$", "", text.strip(), flags=re.I | re.S)
    start, end = candidate.find("{"), candidate.rfind("}")
    if start < 0 or end < start:
        return None
    try:
        value = json.loads(candidate[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _clean_text(value: Any, limit: int) -> str:
    return " ".join(str(value or "").replace("*/", "* /").split())[:limit]


def normalize_proposal(raw: dict[str, Any], code: str) -> dict[str, Any]:
    """Allow only metadata that can be applied deterministically to the raw code."""
    renames: list[dict[str, str]] = []
    used_names: set[str] = set()
    for item in raw.get("renames", []) if isinstance(raw.get("renames"), list) else []:
        if not isinstance(item, dict):
            continue
        old, new = str(item.get("from", "")).strip(), str(item.get("to", "")).strip()
        reason = _clean_text(item.get("reason"), 240)
        if (
            IDENTIFIER_RE.fullmatch(old)
            and IDENTIFIER_RE.fullmatch(new)
            and new not in RESERVED
            and old != new
            and new not in used_names
            and re.search(rf"\b{re.escape(old)}\b", code)
        ):
            used_names.add(new)
            renames.append(
                {"id": f"rename:{old}", "from": old, "to": new, "reason": reason}
            )

    comments: list[dict[str, str]] = []
    for index, item in enumerate(
        raw.get("comments", []) if isinstance(raw.get("comments"), list) else []
    ):
        if not isinstance(item, dict):
            continue
        anchor = str(item.get("anchor", "")).strip()
        text = _clean_text(item.get("text"), 400)
        if anchor and text and anchor in code:
            comments.append(
                {"id": f"comment:{index}", "anchor": anchor[:240], "text": text}
            )

    types: list[dict[str, str]] = []
    for item in raw.get("types", []) if isinstance(raw.get("types"), list) else []:
        if not isinstance(item, dict):
            continue
        name, suggested = (
            str(item.get("name", "")).strip(),
            " ".join(str(item.get("type", "")).split()),
        )
        reason = _clean_text(item.get("reason"), 240)
        if (
            IDENTIFIER_RE.fullmatch(name)
            and TYPE_RE.fullmatch(suggested)
            and re.search(rf"\b{re.escape(name)}\b", code)
        ):
            types.append(
                {
                    "id": f"type:{name}",
                    "name": name,
                    "type": suggested,
                    "reason": reason,
                }
            )

    prototype = raw.get("prototype") if isinstance(raw.get("prototype"), dict) else {}
    prototype_value = _clean_text(prototype.get("value"), 300)
    normalized_prototype = None
    if (
        prototype_value
        and prototype_value.endswith(";")
        and "{" not in prototype_value
        and "}" not in prototype_value
    ):
        normalized_prototype = {
            "id": "prototype",
            "value": prototype_value,
            "reason": _clean_text(prototype.get("reason"), 240),
        }

    return {
        "summary": _clean_text(raw.get("summary"), 600),
        "renames": renames[:24],
        "comments": comments[:24],
        "types": types[:24],
        "prototype": normalized_prototype,
    }


def apply_proposal(
    code: str, proposal: dict[str, Any], selected_ids: list[str] | None = None
) -> str:
    selected = set(selected_ids) if selected_ids is not None else None

    def enabled(item: dict[str, Any]) -> bool:
        return selected is None or item.get("id") in selected

    output = code
    summary = str(proposal.get("summary", "")).strip()
    if summary and (selected is None or "summary" in selected):
        output = f"/* {summary} */\n{output}"
    for item in proposal.get("comments", []):
        if not enabled(item):
            continue
        anchor = item["anchor"]
        output = output.replace(anchor, f"/* {item['text']} */\n{anchor}", 1)
    for item in proposal.get("renames", []):
        if enabled(item):
            output = re.sub(rf"\b{re.escape(item['from'])}\b", item["to"], output)
    annotations = []
    for item in proposal.get("types", []):
        if enabled(item):
            annotations.append(f"/* type proposé: {item['type']} {item['name']} */")
    prototype = proposal.get("prototype")
    if prototype and enabled(prototype):
        annotations.append(f"/* prototype proposé: {prototype['value']} */")
    return "\n".join(annotations + [output]) if annotations else output


def semantic_guard(raw_code: str, augmented_code: str) -> bool:
    """Ensure augmentation changed identifiers/comments only, never operators or literals."""

    def skeleton(value: str) -> list[str]:
        value = re.sub(r"/\*.*?\*/|//[^\n]*", "", value, flags=re.S)
        value = re.sub(r"\b[A-Za-z_]\w*\b", "ID", value)
        return re.findall(
            r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'|0x[0-9A-Fa-f]+|\d+(?:\.\d+)?|[^\sA-Za-z_]',
            value,
        )

    return skeleton(raw_code) == skeleton(augmented_code)


def cache_key(binary_path: str, addr: str, code: str, provider: str, model: str) -> str:
    digest = hashlib.sha256()
    path = Path(binary_path)
    if path.is_file():
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    else:
        digest.update(binary_path.encode())
    digest.update(
        json.dumps(
            [SCHEMA_VERSION, addr, code, provider, model], ensure_ascii=False
        ).encode()
    )
    return digest.hexdigest()


def build_prompt(code: str, function_name: str, language: str) -> str:
    return (
        "You improve the readability of decompiled C without rewriting it. Return STRICT JSON only. "
        "Schema: {summary:string, renames:[{from,to,reason}], comments:[{anchor,text}], "
        "types:[{name,type,reason}], prototype:{value,reason}|null}. "
        "Every rename must target an identifier present in the input. Every comment anchor must be an exact "
        "substring from the input. Use conservative C types. Do not return modified C code. "
        f"Write explanations in {language}. Function: {function_name or 'unknown'}."
    )


def suggest(payload: dict[str, Any]) -> dict[str, Any]:
    code = str(payload.get("code", ""))[:32000]
    if not code.strip():
        raise ValueError("Pseudo-code vide")
    provider = str(payload.get("provider") or "ollama")
    model = resolve_provider_model(provider, str(payload.get("model") or "") or None)
    key = cache_key(
        str(payload.get("binary_path", "")),
        str(payload.get("addr", "")),
        code,
        provider,
        model,
    )
    cache_dir = str(payload["cache_dir"])
    cached = (
        get_payload(cache_dir, "ai-decompile", key)
        if payload.get("use_cache", True)
        else None
    )
    if isinstance(cached, dict):
        result = cached
        result["cached"] = True
        return result
    response = call_provider_result(
        provider,
        build_prompt(
            code,
            str(payload.get("function_name", "")),
            str(payload.get("language") or "French"),
        ),
        code,
        model or None,
        None,
        {"max_tokens": 1800, "temperature": 0.1},
    )
    raw = extract_json_object(str(response.get("text", "")))
    if raw is None:
        raise ValueError("Réponse IA non structurée")
    proposal = normalize_proposal(raw, code)
    augmented = apply_proposal(code, proposal)
    if not semantic_guard(code, augmented):
        raise ValueError("Le garde-fou sémantique a rejeté la proposition")
    result = {
        "ok": True,
        "schema_version": SCHEMA_VERSION,
        "cache_key": key,
        "cached": False,
        "provider": provider,
        "model": model,
        "raw_code": code,
        "augmented_code": augmented,
        "proposal": proposal,
        "usage": response.get("usage", {}),
        "accepted_ids": [],
        "versions": [],
    }
    binary_path = str(payload.get("binary_path", ""))
    try:
        stat = Path(binary_path).stat()
        metadata = (
            str(Path(binary_path).resolve()),
            stat.st_mtime_ns / 1_000_000,
            stat.st_size,
        )
    except OSError:
        metadata = (binary_path, 0, 0)
    result["_cache_meta"] = {
        "binary_path": metadata[0],
        "binary_mtime_ms": metadata[1],
        "binary_size": metadata[2],
    }
    put_payload(
        cache_dir,
        "ai-decompile",
        key,
        result,
        binary_path=metadata[0],
        binary_mtime_ms=metadata[1],
        binary_size=metadata[2],
    )
    return result


def accept(payload: dict[str, Any]) -> dict[str, Any]:
    key = str(payload.get("cache_key", ""))
    if not re.fullmatch(r"[a-f0-9]{64}", key):
        raise ValueError("Proposition introuvable ou expirée")
    result = get_payload(str(payload["cache_dir"]), "ai-decompile", key)
    if not isinstance(result, dict):
        raise ValueError("Proposition introuvable ou expirée")
    selected = [str(value) for value in payload.get("selected_ids", [])]
    augmented = apply_proposal(result["raw_code"], result["proposal"], selected)
    if not semantic_guard(result["raw_code"], augmented):
        raise ValueError("Le garde-fou sémantique a rejeté la sélection")
    versions = (
        result.get("versions", []) if isinstance(result.get("versions"), list) else []
    )
    versions.append(
        {
            "version": len(versions) + 1,
            "accepted_at": datetime.now(UTC).isoformat(),
            "selected_ids": selected,
            "augmented_code": augmented,
        }
    )
    result.update(
        {
            "accepted_ids": selected,
            "augmented_code": augmented,
            "accepted": True,
            "versions": versions[-20:],
        }
    )
    meta = result.get("_cache_meta", {})
    put_payload(
        str(payload["cache_dir"]),
        "ai-decompile",
        key,
        result,
        binary_path=str(meta.get("binary_path", "")),
        binary_mtime_ms=float(meta.get("binary_mtime_ms", 0)),
        binary_size=int(meta.get("binary_size", 0)),
    )
    return result


def lookup(payload: dict[str, Any]) -> dict[str, Any]:
    """Return an accepted augmentation from the local cache without calling AI."""
    code = str(payload.get("code", ""))[:32000]
    if not code.strip():
        return {"ok": True, "found": False}
    provider = str(payload.get("provider") or "ollama")
    model = resolve_provider_model(provider, str(payload.get("model") or "") or None)
    key = cache_key(
        str(payload.get("binary_path", "")),
        str(payload.get("addr", "")),
        code,
        provider,
        model,
    )
    result = get_payload(str(payload["cache_dir"]), "ai-decompile", key)
    if not isinstance(result, dict):
        return {"ok": True, "found": False, "cache_key": key}
    if result.get("accepted") is not True or not result.get("accepted_ids"):
        return {"ok": True, "found": False, "cache_key": key}
    result.update({"ok": True, "found": True, "cached": True})
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument(
        "--action", choices=("suggest", "accept", "lookup"), default="suggest"
    )
    args = parser.parse_args()
    try:
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        if args.action == "suggest":
            result = suggest(payload)
        elif args.action == "accept":
            result = accept(payload)
        else:
            result = lookup(payload)
        print(json.dumps(result, ensure_ascii=False))
        return 0
    except Exception as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
