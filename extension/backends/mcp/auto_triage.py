#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Standalone CLI orchestrator for AI-assisted binary auto-triage (#124).

Not an MCP JSON-RPC tool: this is a long-running, cancellable job whose
progress must be streamed, which the stdio tool-per-call protocol used by
server.py cannot express. Instead this script is spawned as its own
process and emits one JSON event per line on stdout (never accumulating
the full trace in memory), mirroring the pattern already used for
`hubPullDecompilerImage` (docker pull via cp.spawn + line-by-line stdout).

It reuses `server._call_tool` for all static-analysis primitives
(call graph, function discovery, xrefs, strings, decompilation) instead
of re-implementing mapping-file loading, and writes suggestions through
`AnnotationStore.ai_rename`/`ai_comment` (Phase 0), which never overwrite
a human-authored annotation.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.mcp.ai_provider import call_provider_result
from backends.mcp.server import _call_tool
from backends.static.annotations.annotations import AnnotationStore

# Keep in sync with src/dynamic/pedagogy.ts:IGNORE_FOCUS_FUNCTIONS
IGNORE_FOCUS_FUNCTIONS = {
    "_start",
    "start",
    "__libc_start_main",
    "__libc_start_call_main",
    "__libc_csu_init",
    "__libc_csu_fini",
    "frame_dummy",
    "register_tm_clones",
    "deregister_tm_clones",
    "init",
    "fini",
}

SENSITIVE_KEYWORDS = (
    "socket",
    "connect",
    "send",
    "recv",
    "fopen",
    "open",
    "system",
    "exec",
    "aes",
    "md5",
    "sha",
    "license",
    "crypt",
)

OnEvent = Callable[[dict[str, Any]], None]
CancelCheck = Callable[[], bool]


@dataclass
class TriageBudget:
    max_functions: int = 200
    max_seconds: float = 600.0
    max_tokens: int | None = None


@dataclass
class FunctionCandidate:
    addr: str
    name: str
    score: float
    reasons: list[str] = field(default_factory=list)


@dataclass
class FunctionAnalysis:
    addr: str
    name: str
    generated_name: str
    docstring: str
    tags: list[str] = field(default_factory=list)
    error: str | None = None


def _addr_to_int(addr: str) -> int:
    try:
        return int(str(addr), 16) if str(addr).lower().startswith("0x") else int(addr)
    except (TypeError, ValueError):
        return -1


def _matches_sensitive(text: str) -> str | None:
    lowered = text.lower()
    for keyword in SENSITIVE_KEYWORDS:
        if keyword in lowered:
            return keyword
    return None


def _build_function_ranges(addrs: list[str]) -> list[tuple[int, int, str]]:
    """Approximate each function's address range as [addr_i, addr_{i+1}).

    This is a heuristic (compiled functions are usually contiguous) used
    only to attribute nearby strings to the function that likely
    references them; it is not an exact disassembly boundary.
    """
    ordered = sorted({a for a in addrs if _addr_to_int(a) >= 0}, key=_addr_to_int)
    ranges: list[tuple[int, int, str]] = []
    for i, addr in enumerate(ordered):
        start = _addr_to_int(addr)
        end = (
            _addr_to_int(ordered[i + 1]) if i + 1 < len(ordered) else start + (1 << 32)
        )
        ranges.append((start, end, addr))
    return ranges


def _strings_by_function(
    strings: list[dict], xrefs_by_addr: dict[str, list[dict]], addrs: list[str]
) -> dict[str, list[str]]:
    ranges = _build_function_ranges(addrs)
    result: dict[str, list[str]] = {}

    def _owner(offset: int) -> str | None:
        for start, end, addr in ranges:
            if start <= offset < end:
                return addr
        return None

    for entry in strings:
        str_addr = str(entry.get("addr", ""))
        value = str(entry.get("value", ""))
        if not str_addr or not value:
            continue
        for xref in xrefs_by_addr.get(str_addr, []):
            from_addr = str(xref.get("from_addr", ""))
            offset = _addr_to_int(from_addr)
            if offset < 0:
                continue
            owner = _owner(offset)
            if owner is not None:
                result.setdefault(owner, []).append(value)
    return result


def select_candidate_functions(
    call_graph: dict,
    discovered_functions: list[dict],
    xrefs_by_addr: dict[str, list[dict]],
    strings_by_addr: dict[str, list[str]],
    existing_annotations: list[dict],
    budget: TriageBudget,
) -> list[FunctionCandidate]:
    """Rank and truncate candidate functions to analyze.

    Excludes ignored runtime-startup symbols and any address already
    carrying a human-authored ("user") annotation.
    """
    user_annotated_addrs = {
        row["addr"] for row in existing_annotations if row.get("source") == "user"
    }

    by_addr: dict[str, str] = {}
    for node in call_graph.get("nodes", []):
        addr = str(node.get("addr", ""))
        if addr:
            by_addr[addr] = str(node.get("name", "") or addr)
    for func in discovered_functions:
        addr = str(func.get("addr", ""))
        if addr and addr not in by_addr:
            by_addr[addr] = str(func.get("name", "") or addr)

    out_edges: dict[str, list[str]] = {}
    for edge in call_graph.get("edges", []):
        src = str(edge.get("from", ""))
        out_edges.setdefault(src, []).append(str(edge.get("to_name", "")))

    # strings_by_addr is pre-correlated (function addr -> nearby string values)
    # by run_auto_triage via _strings_by_function before this is called.
    strings_map = strings_by_addr

    candidates: list[FunctionCandidate] = []
    for addr, name in by_addr.items():
        if name in IGNORE_FOCUS_FUNCTIONS or addr in user_annotated_addrs:
            continue

        reasons: list[str] = []
        xref_count = len(xrefs_by_addr.get(addr, []))
        callee_names = out_edges.get(addr, [])
        score = float(xref_count) + float(len(callee_names))

        for callee in callee_names:
            keyword = _matches_sensitive(callee)
            if keyword:
                score += 5.0
                reasons.append(f"appelle une fonction liée à '{keyword}' ({callee})")

        for string_value in strings_map.get(addr, []):
            keyword = _matches_sensitive(string_value)
            if keyword:
                score += 3.0
                reasons.append(f"référence une chaîne liée à '{keyword}'")

        if xref_count > 3:
            reasons.append(f"{xref_count} sites d'appel")

        candidates.append(
            FunctionCandidate(addr=addr, name=name, score=score, reasons=reasons)
        )

    candidates.sort(key=lambda c: c.score, reverse=True)
    return candidates[: budget.max_functions]


_JSON_FENCE_RE = None


def _extract_json_object(text: str) -> dict[str, Any] | None:
    global _JSON_FENCE_RE
    if _JSON_FENCE_RE is None:
        import re

        _JSON_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)

    match = _JSON_FENCE_RE.search(text)
    candidate = match.group(1) if match else text.strip()
    start = candidate.find("{")
    end = candidate.rfind("}")
    if start == -1 or end == -1 or end < start:
        return None
    try:
        parsed = json.loads(candidate[start : end + 1])
    except (json.JSONDecodeError, ValueError):
        return None
    return parsed if isinstance(parsed, dict) else None


def analyze_function(
    candidate: FunctionCandidate,
    binary_path: str,
    provider: str,
    model: str | None,
    budget: TriageBudget,
) -> FunctionAnalysis:
    """Ask the configured AI provider to name/document one function.

    Never raises: on decompilation failure or a malformed LLM response,
    returns a FunctionAnalysis with `error` set and a heuristic fallback
    so a single bad function cannot abort the whole triage loop.
    """
    code = ""
    decompiled = _call_tool(
        "decompile_function", {"binary_path": binary_path, "addr": candidate.addr}
    )
    if decompiled.get("ok") and decompiled.get("code"):
        code = str(decompiled["code"])
    else:
        disasm = _call_tool(
            "disassemble",
            {"binary_path": binary_path, "addr": candidate.addr, "max_lines": 200},
        )
        lines = disasm.get("lines", []) if isinstance(disasm, dict) else []
        code = "\n".join(
            str(line.get("text", "")) for line in lines if isinstance(line, dict)
        )

    prompt = (
        "Tu analyses une fonction binaire pour un outil de reverse engineering.\n"
        "Réponds STRICTEMENT en JSON avec les clés: name (identifiant C valide, court), "
        "docstring (1-3 phrases en français), tags (liste de mots-clés parmi: "
        "network, crypto, filesystem, license, input, other).\n"
        f"Adresse: {candidate.addr}\nRaisons de sélection: {', '.join(candidate.reasons) or 'aucune'}\n"
        "Code:\n" + code[:8000]
    )

    generation_options: dict[str, Any] = {}
    if budget.max_tokens is not None:
        generation_options["max_tokens"] = budget.max_tokens

    try:
        result = call_provider_result(
            provider, prompt, code[:8000], model, None, generation_options or None
        )
        parsed = _extract_json_object(str(result.get("text", "")))
    except Exception as exc:  # provider/network failure must not abort the loop
        return FunctionAnalysis(
            addr=candidate.addr,
            name=candidate.name,
            generated_name="",
            docstring="",
            tags=[],
            error=f"provider_error: {exc}",
        )

    if parsed is None:
        return FunctionAnalysis(
            addr=candidate.addr,
            name=candidate.name,
            generated_name="",
            docstring="Fonction non analysée (réponse IA invalide).",
            tags=[],
            error="malformed_llm_response",
        )

    generated_name = str(parsed.get("name", "") or "").strip()
    docstring = str(parsed.get("docstring", "") or "").strip()
    tags_raw = parsed.get("tags", [])
    tags = [str(t) for t in tags_raw] if isinstance(tags_raw, list) else []

    return FunctionAnalysis(
        addr=candidate.addr,
        name=candidate.name,
        generated_name=generated_name,
        docstring=docstring,
        tags=tags,
    )


def write_function_annotations(
    store: AnnotationStore, analysis: FunctionAnalysis
) -> dict[str, bool]:
    """Write both suggestions for one function without an intervening
    cancellation check, so a function is never left half-annotated.
    """
    name_written = False
    comment_written = False
    if analysis.generated_name:
        name_written = store.ai_rename(analysis.addr, analysis.generated_name)
    if analysis.docstring:
        comment_written = store.ai_comment(analysis.addr, analysis.docstring)
    return {"name_written": name_written, "comment_written": comment_written}


def synthesize_binary_summary(
    analyses: list[FunctionAnalysis],
    provider: str,
    model: str | None,
) -> dict[str, Any]:
    """Classify the binary from facts already extracted (heuristic tags),
    then make a single LLM call to phrase the summary — this bounds
    hallucination and cost to one call regardless of function count.
    """
    tag_counts: dict[str, int] = {}
    for analysis in analyses:
        for tag in analysis.tags:
            tag_counts[tag] = tag_counts.get(tag, 0) + 1

    categories = sorted(tag_counts, key=lambda t: tag_counts[t], reverse=True)
    facts = "\n".join(
        f"- {a.name} -> {a.generated_name or '?'}: {a.docstring or '(non documentée)'}"
        for a in analyses
        if not a.error
    )
    if not facts:
        return {
            "text": "Aucune fonction n'a pu être analysée avec succès.",
            "categories": categories,
        }

    prompt = (
        "Voici les fonctions annotées automatiquement d'un binaire, avec leurs "
        f"catégories dominantes détectées: {', '.join(categories) or 'aucune'}.\n"
        "Rédige un résumé exécutif de 3-5 phrases en français, sans inventer de "
        "détail non présent ci-dessous:\n" + facts[:8000]
    )
    try:
        result = call_provider_result(provider, prompt, facts[:8000], model)
        text = str(result.get("text", "")).strip()
    except Exception as exc:
        text = f"(résumé indisponible: {exc})"
    return {"text": text, "categories": categories}


def render_markdown_report(
    binary_path: str,
    analyses: list[FunctionAnalysis],
    summary: dict[str, Any],
    stats: dict[str, Any],
) -> str:
    lines = [
        f"# Rapport d'auto-triage IA — {Path(binary_path).name}",
        "",
        "> Généré automatiquement par IA. Toutes les annotations sont réversibles "
        "et n'écrasent jamais une annotation manuelle — à vérifier avant usage.",
        "",
        "## Résumé exécutif",
        "",
        summary.get("text", ""),
        "",
        "## Classification",
        "",
        ", ".join(summary.get("categories", [])) or "Aucune catégorie détectée.",
        "",
        "## Fonctions prioritaires",
        "",
        "| Adresse | Nom original | Nom suggéré | Statut |",
        "|---|---|---|---|",
    ]
    for analysis in analyses:
        status = "erreur" if analysis.error else "ok"
        lines.append(
            f"| {analysis.addr} | {analysis.name} | {analysis.generated_name or '-'} | {status} |"
        )

    lines += ["", "## Détail par fonction", ""]
    for analysis in analyses:
        lines.append(f"### {analysis.name} ({analysis.addr})")
        if analysis.error:
            lines.append(f"_Erreur: {analysis.error}_")
        else:
            lines.append(analysis.docstring or "_(pas de description)_")
        lines.append("")

    lines += [
        "## Statistiques",
        "",
        f"- Fonctions traitées: {stats.get('processed', 0)}",
        f"- Fonctions annotées: {stats.get('annotated', 0)}",
        f"- Durée: {stats.get('elapsed_s', 0):.1f}s",
    ]
    return "\n".join(lines)


def run_auto_triage(
    binary_path: str,
    mapping_path: str,
    provider: str,
    model: str | None,
    budget: TriageBudget,
    on_event: OnEvent,
    cancel_check: CancelCheck,
    cache_path: str | None = None,
) -> dict[str, Any]:
    start = time.monotonic()

    call_graph = _call_tool(
        "build_call_graph", {"mapping_path": mapping_path, "binary_path": binary_path}
    )
    discovered = _call_tool(
        "discover_functions", {"mapping_path": mapping_path, "binary_path": binary_path}
    ).get("functions", [])
    xref_map = _call_tool(
        "get_xrefs", {"mapping_path": mapping_path, "addr": "0x0", "mode": "map"}
    ).get("xref_map", {})
    strings = _call_tool("extract_strings", {"binary_path": binary_path}).get(
        "strings", []
    )

    all_addrs = [str(n.get("addr", "")) for n in call_graph.get("nodes", [])]
    all_addrs += [str(f.get("addr", "")) for f in discovered]
    strings_by_addr = _strings_by_function(strings, xref_map, all_addrs)

    with AnnotationStore(binary_path, cache_path=cache_path) as store:
        existing_annotations = store.list()
        candidates = select_candidate_functions(
            call_graph,
            discovered,
            xref_map,
            strings_by_addr,
            existing_annotations,
            budget,
        )
        on_event({"type": "selection_done", "total": len(candidates)})

        analyses: list[FunctionAnalysis] = []
        annotated_count = 0
        cancelled = False

        for index, candidate in enumerate(candidates):
            if cancel_check():
                cancelled = True
                on_event(
                    {"type": "cancelled", "processed": index, "total": len(candidates)}
                )
                break
            elapsed = time.monotonic() - start
            if elapsed > budget.max_seconds:
                on_event(
                    {
                        "type": "budget_warning",
                        "reason": "max_seconds",
                        "elapsed_s": elapsed,
                    }
                )
                break

            on_event(
                {
                    "type": "function_start",
                    "index": index,
                    "total": len(candidates),
                    "addr": candidate.addr,
                    "name": candidate.name,
                }
            )
            analysis = analyze_function(candidate, binary_path, provider, model, budget)
            analyses.append(analysis)

            if cancel_check():
                cancelled = True
                on_event(
                    {"type": "cancelled", "processed": index, "total": len(candidates)}
                )
                break

            if analysis.error:
                on_event(
                    {
                        "type": "function_error",
                        "addr": candidate.addr,
                        "error": analysis.error,
                    }
                )
            else:
                write_result = write_function_annotations(store, analysis)
                if write_result["name_written"] or write_result["comment_written"]:
                    annotated_count += 1
                on_event(
                    {
                        "type": "function_done",
                        "index": index,
                        "addr": candidate.addr,
                        **write_result,
                    }
                )

        summary = synthesize_binary_summary(analyses, provider, model)
        stats = {
            "processed": len(analyses),
            "annotated": annotated_count,
            "elapsed_s": time.monotonic() - start,
            "cancelled": cancelled,
        }
        report = render_markdown_report(binary_path, analyses, summary, stats)

    on_event({"type": "summary", "summary": summary})
    done_event = {"type": "done", "report_markdown": report, "stats": stats}
    on_event(done_event)
    return done_event


def _default_cancel_check(flag_path: str | None) -> CancelCheck:
    if not flag_path:
        return lambda: False
    return lambda: os.path.isfile(flag_path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Pile ou Face auto-triage IA orchestrator"
    )
    parser.add_argument("--binary-path", required=True)
    parser.add_argument("--mapping-path", required=True)
    parser.add_argument(
        "--provider", default=os.environ.get("POF_DEFAULT_AI_PROVIDER", "ollama")
    )
    parser.add_argument("--model", default=None)
    parser.add_argument("--max-functions", type=int, default=200)
    parser.add_argument("--max-seconds", type=float, default=600.0)
    parser.add_argument("--max-tokens", type=int, default=None)
    parser.add_argument("--cancel-flag-path", default=None)
    parser.add_argument("--report-out", default=None)
    parser.add_argument("--cache-db", default=None)
    args = parser.parse_args(argv)

    budget = TriageBudget(
        max_functions=args.max_functions,
        max_seconds=args.max_seconds,
        max_tokens=args.max_tokens,
    )

    def on_event(event: dict[str, Any]) -> None:
        print(json.dumps(event), flush=True)

    result = run_auto_triage(
        args.binary_path,
        args.mapping_path,
        args.provider,
        args.model,
        budget,
        on_event,
        _default_cancel_check(args.cancel_flag_path),
        cache_path=args.cache_db,
    )

    if args.report_out:
        Path(args.report_out).write_text(result["report_markdown"], encoding="utf-8")

    return 0


if __name__ == "__main__":
    sys.exit(main())
