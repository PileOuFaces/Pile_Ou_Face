# SPDX-License-Identifier: AGPL-3.0-only
"""Provider-agnostic natural-language search over indexed binary functions."""

from __future__ import annotations

import argparse
import json
import re
from typing import Any

from backends.mcp.ai_provider import call_provider
from backends.shared.utils import normalize_addr
from backends.static.analysis.function_radar import build_function_radar

MAX_CANDIDATES = 200
MAX_QUERY_CHARS = 500
_JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class NaturalLanguageSearchError(ValueError):
    """Raised when a search request or provider response is invalid."""


def _compact_candidate(entry: dict[str, Any]) -> dict[str, Any]:
    strings = [
        str(item.get("preview") or item.get("value") or item.get("summary") or "")[:160]
        for item in entry.get("string_signals", [])
        if isinstance(item, dict)
    ]
    imports = [
        str(item.get("function") or item.get("summary") or "")[:120]
        for item in entry.get("import_signals", [])
        if isinstance(item, dict)
    ]
    annotations = [
        str(item.get("value") or item.get("summary") or item)[:160]
        if isinstance(item, dict)
        else str(item)[:160]
        for item in entry.get("annotation_preview", [])
    ]
    return {
        "addr": normalize_addr(entry.get("addr", "")),
        "name": str(entry.get("name") or "")[:160],
        "summary": str(entry.get("focus_summary") or "")[:300],
        "tags": [str(tag)[:80] for tag in entry.get("signal_tags", [])[:12]],
        "imports": imports[:8],
        "strings": strings[:8],
        "annotations": annotations[:6],
        "incoming_calls": int(entry.get("incoming_calls") or 0),
        "outgoing_calls": int(entry.get("outgoing_calls") or 0),
    }


def _extract_json(text: str) -> dict[str, Any]:
    match = _JSON_FENCE_RE.search(text)
    candidate = match.group(1) if match else text.strip()
    start, end = candidate.find("{"), candidate.rfind("}")
    if start < 0 or end < start:
        raise NaturalLanguageSearchError("Réponse IA sans objet JSON.")
    try:
        parsed = json.loads(candidate[start : end + 1])
    except json.JSONDecodeError as exc:
        raise NaturalLanguageSearchError("Réponse IA JSON invalide.") from exc
    if not isinstance(parsed, dict):
        raise NaturalLanguageSearchError("Réponse IA invalide.")
    return parsed


def search_functions(
    binary_path: str,
    query: str,
    provider: str,
    model: str | None = None,
    *,
    limit: int = 8,
    cache_db: str | None = None,
    radar: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Rank indexed functions for a natural-language investigation question."""
    clean_query = str(query or "").strip()
    if not clean_query:
        raise NaturalLanguageSearchError("Question de recherche manquante.")
    if len(clean_query) > MAX_QUERY_CHARS:
        raise NaturalLanguageSearchError(
            f"Question trop longue (limite: {MAX_QUERY_CHARS} caractères)."
        )
    result_limit = max(1, min(int(limit or 8), 20))
    analysis = radar or build_function_radar(binary_path, cache_db=cache_db)
    if analysis.get("error"):
        raise NaturalLanguageSearchError(str(analysis["error"]))
    candidates = [
        _compact_candidate(item)
        for item in (analysis.get("functions") or [])[:MAX_CANDIDATES]
        if isinstance(item, dict) and item.get("addr")
    ]
    if not candidates:
        return {"ok": True, "query": clean_query, "results": [], "candidate_count": 0}

    prompt = (
        "You rank reverse-engineering function candidates for a user's natural-language "
        "question. Use only the supplied evidence. Return strict JSON as "
        f'{{"results":[{{"addr":"0x...","score":0-100,"reason":"short explanation"}}]}}. '
        f"Return at most {result_limit} results, best first. Never invent an address."
    )
    context = json.dumps(
        {"question": clean_query, "candidates": candidates},
        ensure_ascii=False,
        separators=(",", ":"),
    )
    parsed = _extract_json(call_provider(provider, prompt, context, model))
    by_addr = {item["addr"]: item for item in candidates}
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for raw in parsed.get("results") or []:
        if not isinstance(raw, dict):
            continue
        addr = normalize_addr(raw.get("addr", ""))
        candidate = by_addr.get(addr)
        if candidate is None or addr in seen:
            continue
        try:
            score = max(0, min(100, int(raw.get("score") or 0)))
        except (TypeError, ValueError):
            score = 0
        results.append(
            {
                "addr": addr,
                "name": candidate["name"],
                "score": score,
                "reason": str(raw.get("reason") or "")[:500],
                "evidence": {
                    key: candidate[key]
                    for key in ("summary", "tags", "imports", "strings", "annotations")
                    if candidate[key]
                },
            }
        )
        seen.add(addr)
        if len(results) >= result_limit:
            break
    results.sort(key=lambda item: (-item["score"], int(item["addr"], 16)))
    return {
        "ok": True,
        "query": clean_query,
        "provider": provider,
        "model": model,
        "candidate_count": len(candidates),
        "results": results,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Natural-language function search")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--query", required=True)
    parser.add_argument("--provider", required=True)
    parser.add_argument("--model")
    parser.add_argument("--limit", type=int, default=8)
    parser.add_argument("--cache-db")
    args = parser.parse_args(argv)
    try:
        result = search_functions(
            args.binary,
            args.query,
            args.provider,
            args.model,
            limit=args.limit,
            cache_db=args.cache_db,
        )
    except (OSError, NaturalLanguageSearchError, ValueError) as exc:
        result = {"ok": False, "error": str(exc)}
        print(json.dumps(result, ensure_ascii=False))
        return 2
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
