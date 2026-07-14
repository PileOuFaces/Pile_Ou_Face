# SPDX-License-Identifier: AGPL-3.0-only
"""Radar de priorisation des fonctions pour l'analyse statique.

L'objectif n'est pas de "prouver" qu'une fonction est malveillante ou
vulnérable, mais de guider rapidement l'analyste vers les meilleurs points
d'entrée à partir de signaux publics déjà disponibles dans le host.
"""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import normalize_addr
from backends.shared.utils import parse_addr as _addr_to_int
from backends.static.analysis.analysis_index import build_analysis_index
from backends.static.binary.imports_analysis import analyze_imports
from backends.static.binary.symbols import extract_symbols
from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.static.disasm.call_graph import build_call_graph
from backends.static.disasm.cfg import build_cfg
from backends.static.disasm.disasm import disassemble_with_capstone
from backends.static.disasm.discover_functions import discover_functions
from backends.static.disasm.xrefs import build_xref_map
from backends.static.search.strings import extract_strings

logger = get_logger(__name__)

_NAME_BONUS_RULES = (
    (
        re.compile(r"^(main|_start|start|entry)$", re.IGNORECASE),
        18,
        "Entrée probable du binaire",
    ),
    (
        re.compile(r"(auth|login|check|verify|guard|password|token)", re.IGNORECASE),
        10,
        "Nom orienté validation ou authentification",
    ),
    (
        re.compile(r"(decrypt|decode|unpack|deob|cipher|aes|rc4|xor)", re.IGNORECASE),
        11,
        "Nom orienté déchiffrement ou déobfuscation",
    ),
    (
        re.compile(
            r"(http|net|sock|connect|send|recv|request|upload|download)", re.IGNORECASE
        ),
        9,
        "Nom orienté réseau",
    ),
    (
        re.compile(
            r"(parse|load|handle|dispatch|process|command|shell|exec)", re.IGNORECASE
        ),
        7,
        "Nom orienté orchestration ou exécution",
    ),
)

_STRING_SIGNAL_RULES = (
    (
        "network",
        "Chaîne réseau",
        re.compile(
            r"(https?://|ftp://|api[_-]?key|user-agent|/api/|socket|connect)",
            re.IGNORECASE,
        ),
    ),
    (
        "execution",
        "Chaîne d'exécution",
        re.compile(
            r"(cmd\.exe|powershell|/bin/sh|bash -c|execve|createprocess|shellexecute)",
            re.IGNORECASE,
        ),
    ),
    (
        "persistence",
        "Chaîne de persistance",
        re.compile(
            r"(runonce|currentversion\\\\run|startup|service|scheduled task)",
            re.IGNORECASE,
        ),
    ),
    (
        "crypto",
        "Chaîne crypto",
        re.compile(
            r"(aes|rsa|rc4|sha1|sha256|base64|decrypt|encrypt|public key|private key)",
            re.IGNORECASE,
        ),
    ),
    (
        "credential",
        "Chaîne sensible",
        re.compile(
            r"(password|passwd|secret|token|bearer|authorization|cookie|session)",
            re.IGNORECASE,
        ),
    ),
    (
        "anti_debug",
        "Chaîne anti-debug",
        re.compile(
            r"(isdebuggerpresent|debugger|ollydbg|x64dbg|frida|sandbox|vmware|virtualbox)",
            re.IGNORECASE,
        ),
    ),
)

_IMPORT_CATEGORY_WEIGHTS = {
    "INJECTION": 18,
    "SHELLCODE": 16,
    "EXECUTION": 11,
    "ANTI_DEBUG": 14,
    "NETWORK": 9,
    "CRYPTO": 8,
    "PERSISTENCE": 15,
    "PRIVILEGE": 13,
}

_CATEGORY_LABELS = {
    "INJECTION": "Injection",
    "SHELLCODE": "Shellcode",
    "EXECUTION": "Execution",
    "ANTI_DEBUG": "Anti-debug",
    "NETWORK": "Reseau",
    "CRYPTO": "Crypto",
    "PERSISTENCE": "Persistance",
    "PRIVILEGE": "Privileges",
    "network": "Reseau",
    "execution": "Execution",
    "persistence": "Persistance",
    "crypto": "Crypto",
    "credential": "Secrets",
    "anti_debug": "Anti-debug",
}


def _normalize_symbol_name(name: str) -> str:
    raw = str(name or "").strip()
    if not raw:
        return ""
    normalized = raw.split("@plt", 1)[0]
    normalized = normalized.lstrip("_")
    normalized = re.sub(r"@@.*$", "", normalized)
    return normalized.lower()


def _load_or_compute_disasm(cache: DisasmCache, binary_path: str) -> list[dict]:
    cached = cache.get_disasm(binary_path)
    if cached is not None:
        _, lines = cached
        if lines:
            return lines
    lines = disassemble_with_capstone(binary_path) or []
    if lines:
        cache.save_disasm(binary_path, lines)
    return lines


def _load_or_compute_symbols(cache: DisasmCache, binary_path: str) -> list[dict]:
    cached = cache.get_symbols(binary_path)
    if cached:
        return cached
    symbols = extract_symbols(binary_path, defined_only=False)
    if symbols:
        cache.save_symbols(binary_path, symbols)
    return symbols


def _load_or_compute_strings(
    cache: DisasmCache,
    binary_path: str,
    target_addrs: set[str] | None = None,
) -> list[dict]:
    cached = (
        cache.get_strings_for_addresses(binary_path, target_addrs)
        if target_addrs is not None
        else cache.get_strings(binary_path)
    )
    if cached:
        return cached
    if cached == []:
        return []
    strings = extract_strings(binary_path, min_len=4, encoding="auto")
    if strings:
        cache.save_strings(binary_path, strings)
    return strings


def _load_or_compute_imports(cache: DisasmCache, binary_path: str) -> dict[str, Any]:
    cached = cache.get_imports_analysis(binary_path)
    if cached:
        return cached
    analysis = analyze_imports(binary_path)
    if not analysis.get("error"):
        cache.save_imports_analysis(binary_path, analysis)
    return analysis


def _load_or_compute_functions(
    cache: DisasmCache,
    binary_path: str,
    lines: list[dict],
    symbols: list[dict],
) -> list[dict]:
    cached = cache.get_functions(binary_path)
    if cached:
        return cached
    known_addrs = {
        normalize_addr(symbol.get("addr", ""))
        for symbol in symbols
        if symbol.get("addr")
    }
    functions = discover_functions(
        lines, known_addrs=known_addrs, binary_path=binary_path
    )
    if functions:
        cache.save_functions(binary_path, functions)
    return functions


def _load_or_compute_cfg(
    cache: DisasmCache, binary_path: str, lines: list[dict]
) -> dict[str, Any]:
    cached = cache.get_cfg(binary_path)
    if cached:
        return cached
    cfg = build_cfg(lines, binary_path=binary_path)
    cache.save_cfg(binary_path, cfg)
    return cfg


def _load_or_compute_xrefs(
    cache: DisasmCache, binary_path: str, lines: list[dict]
) -> dict[str, list[dict]]:
    cached = cache.get_xref_map(binary_path)
    if cached:
        return cached
    xref_map = build_xref_map(lines, binary_path=binary_path)
    cache.save_xref_map(binary_path, xref_map)
    return xref_map


def _iter_symbol_functions(symbols: list[dict]) -> list[dict]:
    result = []
    for symbol in symbols:
        addr = normalize_addr(symbol.get("addr", ""))
        sym_type = str(symbol.get("type") or "").strip()
        if not addr or addr == "0x0":
            continue
        if sym_type not in {"T", "t", "U"}:
            continue
        result.append(
            {
                "addr": addr,
                "name": str(symbol.get("name") or addr).strip() or addr,
                "size": symbol.get("size"),
                "kind": "import" if sym_type == "U" else "function",
                "symbol_type": sym_type,
            }
        )
    return result


def _merge_function_catalog(
    symbols: list[dict], discovered: list[dict], annotations: list[dict]
) -> list[dict]:
    rename_map = {
        normalize_addr(entry.get("addr", "")): str(entry.get("value") or "").strip()
        for entry in annotations
        if entry.get("kind") == "rename" and entry.get("addr")
    }
    merged: dict[str, dict[str, Any]] = {}

    for entry in _iter_symbol_functions(symbols):
        merged[entry["addr"]] = dict(entry)

    for fn in discovered:
        addr = normalize_addr(fn.get("addr", ""))
        if not addr:
            continue
        current = merged.get(addr, {"addr": addr})
        if (
            not current.get("name")
            or current.get("name") == addr
            or current.get("kind") == "import"
        ):
            current["name"] = (
                str(fn.get("name") or current.get("name") or addr).strip() or addr
            )
        current.setdefault(
            "kind", str(fn.get("kind") or "function").strip() or "function"
        )
        current["confidence"] = str(
            fn.get("confidence") or current.get("confidence") or ""
        ).strip()
        current["reason"] = str(fn.get("reason") or current.get("reason") or "").strip()
        current["confidence_score"] = fn.get(
            "confidence_score", current.get("confidence_score")
        )
        if fn.get("size"):
            current["size"] = fn.get("size")
        merged[addr] = current

    for addr, entry in list(merged.items()):
        renamed = rename_map.get(addr)
        if renamed:
            entry["name"] = renamed
        if not entry.get("name"):
            entry["name"] = f"sub_{addr[2:]}"

    catalog = list(merged.values())
    catalog.sort(
        key=lambda item: (
            _addr_to_int(item.get("addr")) or 0,
            str(item.get("name") or ""),
        )
    )
    return catalog


def _build_function_ranges(
    functions: list[dict],
) -> list[tuple[int, int | None, dict[str, Any]]]:
    ordered: list[tuple[int, dict[str, Any]]] = []
    for fn in functions:
        start = _addr_to_int(fn.get("addr"))
        if start is None:
            continue
        ordered.append((start, fn))
    ordered.sort(key=lambda item: item[0])

    ranges: list[tuple[int, int | None, dict[str, Any]]] = []
    for idx, (start, fn) in enumerate(ordered):
        next_start = ordered[idx + 1][0] if idx + 1 < len(ordered) else None
        size = _addr_to_int(fn.get("size"))
        end = start + size if size and size > 0 else None
        if next_start is not None:
            end = min(end, next_start) if end is not None else next_start
        ranges.append((start, end, fn))
    return ranges


def _find_function_for_addr(
    function_ranges: list[tuple[int, int | None, dict[str, Any]]],
    addr: str | int | None,
) -> dict[str, Any] | None:
    target = _addr_to_int(addr)
    if target is None:
        return None
    for start, end, fn in function_ranges:
        if target < start:
            break
        if end is None or target < end:
            return fn
    return None


def _classify_string_signal(value: str) -> tuple[str, str] | None:
    text = str(value or "").strip()
    if not text:
        return None
    for signal_id, label, pattern in _STRING_SIGNAL_RULES:
        if pattern.search(text):
            return signal_id, label
    return None


def _preview_text(value: str, max_len: int = 72) -> str:
    text = str(value or "").strip().replace("\n", " ")
    if len(text) <= max_len:
        return text
    return f"{text[: max_len - 1].rstrip()}…"


def _make_signal_tag(raw: str) -> str:
    label = _CATEGORY_LABELS.get(raw, raw)
    return str(label or raw).strip() or raw


def _priority_level(score: int) -> str:
    if score >= 72:
        return "critical"
    if score >= 52:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _build_focus_summary(entry: dict[str, Any]) -> str:
    reasons = list(entry.get("reasons") or [])
    if reasons:
        return reasons[0]
    if entry.get("annotation_count"):
        return "Fonction deja annotee dans la session"
    if entry.get("block_count", 0) >= 8:
        return "Fonction structurellement complexe"
    return "Signal faible, a garder en reserve"


def _append_score_breakdown(
    items: list[dict[str, Any]], points: int, label: str, detail: str = ""
) -> None:
    if not points:
        return
    items.append(
        {
            "points": int(points),
            "label": label,
            "detail": str(detail or "").strip(),
        }
    )


def _confidence_level_for_entry(entry: dict[str, Any]) -> str:
    score = int(entry.get("priority_score") or 0)
    has_signal_convergence = bool(entry.get("import_signals")) and bool(
        entry.get("string_signals")
    )
    if (
        score >= 60
        or has_signal_convergence
        or int(entry.get("annotation_count") or 0) >= 2
    ):
        return "HIGH"
    if score >= 36 or entry.get("import_signals") or entry.get("string_signals"):
        return "MEDIUM"
    return "LOW"


def _severity_level_for_entry(entry: dict[str, Any]) -> str:
    score = int(entry.get("priority_score") or 0)
    if score >= 72:
        return "HIGH"
    if score >= 52:
        return "MEDIUM"
    return "LOW"


def _build_function_evidence(entry: dict[str, Any]) -> list[dict[str, Any]]:
    evidence: list[dict[str, Any]] = []
    for item in entry.get("score_breakdown", []) or []:
        summary = str(item.get("detail") or item.get("label") or "").strip()
        if not summary:
            continue
        evidence.append(
            {
                "kind": "radar_score",
                "summary": summary,
                "label": str(item.get("label") or "Signal"),
                "points": int(item.get("points") or 0),
                "addr": entry.get("addr"),
            }
        )
    for signal in entry.get("import_signals", []) or []:
        summary = f"{signal.get('function') or signal.get('category') or 'Import'}"
        desc = str(signal.get("description") or "").strip()
        if desc:
            summary = f"{summary}: {desc}"
        evidence.append(
            {
                "kind": "import_signal",
                "summary": summary,
                "addr": signal.get("target_addr") or entry.get("addr"),
                "function": signal.get("function") or "",
                "category": signal.get("category") or "",
            }
        )
    for signal in entry.get("string_signals", []) or []:
        preview = str(signal.get("preview") or signal.get("label") or "").strip()
        if not preview:
            continue
        evidence.append(
            {
                "kind": "string_signal",
                "summary": preview,
                "addr": signal.get("target_addr") or entry.get("addr"),
                "source_addr": signal.get("source_addr") or "",
                "category": signal.get("category") or "",
                "span_length": int(signal.get("length") or 1),
            }
        )
    for preview in entry.get("annotation_preview", []) or []:
        evidence.append(
            {
                "kind": "annotation",
                "summary": str(preview),
                "addr": entry.get("addr"),
            }
        )
    unique: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for item in evidence:
        key = (
            str(item.get("kind") or ""),
            str(item.get("summary") or ""),
            str(item.get("addr") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique[:8]


def _build_function_next_steps(entry: dict[str, Any]) -> list[str]:
    steps: list[str] = []
    if entry.get("import_signals"):
        steps.append(
            "Suivre les callsites sensibles dans le désassemblage et le call graph."
        )
    if entry.get("string_signals"):
        steps.append(
            "Ouvrir la chaîne corrélée dans Hex pour confirmer sa portée exacte."
        )
    if int(entry.get("block_count") or 0) >= 6:
        steps.append(
            "Passer par le CFG pour cartographier les branches avant la décompilation."
        )
    if int(entry.get("incoming_calls") or 0) >= 3:
        steps.append(
            "Identifier les principaux appelants pour comprendre le rôle de pivot."
        )
    if int(entry.get("annotation_count") or 0) == 0:
        steps.append(
            "Ajouter une annotation locale pour capturer l'hypothèse principale."
        )
    if not steps:
        steps.append(
            "Valider rapidement en pseudo-C puis revenir aux xrefs si le contexte reste ambigu."
        )
    return steps[:4]


def _build_function_proof_dossier(entry: dict[str, Any]) -> dict[str, Any]:
    evidence = _build_function_evidence(entry)
    callsites = []
    for signal in entry.get("import_signals", []) or []:
        for site in signal.get("callsites", []) or []:
            addr = normalize_addr(
                site.get("callsite_addr", "") or site.get("source_addr", "")
            )
            if not addr:
                continue
            callsites.append(
                {
                    "addr": addr,
                    "text": _preview_text(site.get("text", ""), max_len=96),
                }
            )
    unique_callsites: list[dict[str, Any]] = []
    seen_callsites: set[str] = set()
    for item in callsites:
        if item["addr"] in seen_callsites:
            continue
        seen_callsites.add(item["addr"])
        unique_callsites.append(item)
    confidence = _confidence_level_for_entry(entry)
    severity = _severity_level_for_entry(entry)
    needs_review = str(entry.get("review_status") or "") != "reviewed"
    return {
        "kind": "FUNCTION_RADAR",
        "function": entry.get("name") or entry.get("addr") or "?",
        "addr": entry.get("addr") or "",
        "confidence": confidence,
        "severity": severity,
        "needs_review": needs_review,
        "finding_count": len(evidence),
        "evidence": evidence,
        "next_steps": _build_function_next_steps(entry),
        "related": {
            "apis": [
                signal.get("function")
                for signal in entry.get("import_signals", []) or []
                if signal.get("function")
            ],
            "callsites": unique_callsites[:6],
            "strings": [
                {
                    "addr": signal.get("target_addr") or "",
                    "preview": signal.get("preview") or "",
                    "length": int(signal.get("length") or 1),
                }
                for signal in entry.get("string_signals", []) or []
            ][:6],
            "annotations": list(entry.get("annotation_preview") or [])[:4],
        },
        "review_hint": entry.get("review_hint") or "",
    }


def build_function_radar(
    binary_path: str,
    cache_db: str | None = None,
    *,
    hotspot_limit: int = 8,
) -> dict[str, Any]:
    """Build a function complexity radar: cyclomatic complexity, hotspots, call depth and risk scores per function."""
    if not Path(binary_path).exists():
        return {
            "binary": binary_path,
            "cache_db": cache_db or "",
            "summary": {"function_count": 0, "hotspot_count": 0},
            "entry_candidates": [],
            "hotspots": [],
            "quick_wins": [],
            "clusters": [],
            "functions": [],
            "error": "Fichier introuvable",
        }

    build_analysis_index(binary_path, cache_db=cache_db, force=False)
    db_path = cache_db or default_cache_path(binary_path)

    with DisasmCache(db_path) as cache:
        lines = _load_or_compute_disasm(cache, binary_path)
        symbols = _load_or_compute_symbols(cache, binary_path)
        discovered = _load_or_compute_functions(cache, binary_path, lines, symbols)
        cfg = _load_or_compute_cfg(cache, binary_path, lines)
        xref_map = _load_or_compute_xrefs(cache, binary_path, lines)
        imports = _load_or_compute_imports(cache, binary_path)
        string_target_addrs = {
            normalize_addr(target_addr) for target_addr in xref_map or {}
        }
        strings = _load_or_compute_strings(cache, binary_path, string_target_addrs)
        annotations = cache.get_annotations(binary_path)

    catalog = _merge_function_catalog(symbols, discovered, annotations)
    function_ranges = _build_function_ranges(catalog)
    if not catalog:
        return {
            "binary": binary_path,
            "cache_db": db_path,
            "summary": {"function_count": 0, "hotspot_count": 0},
            "entry_candidates": [],
            "hotspots": [],
            "quick_wins": [],
            "clusters": [],
            "functions": [],
            "error": None,
        }

    metrics: dict[str, dict[str, Any]] = {}
    for fn in catalog:
        addr = normalize_addr(fn.get("addr", ""))
        size_num = _addr_to_int(fn.get("size")) or 0
        metrics[addr] = {
            "addr": addr,
            "name": str(fn.get("name") or addr).strip() or addr,
            "kind": str(fn.get("kind") or "function").strip() or "function",
            "symbol_type": str(fn.get("symbol_type") or "").strip(),
            "size": size_num,
            "confidence": str(fn.get("confidence") or "").strip(),
            "reason": str(fn.get("reason") or "").strip(),
            "confidence_score": fn.get("confidence_score"),
            "instruction_count": 0,
            "block_count": 0,
            "branch_count": 0,
            "incoming_calls": 0,
            "outgoing_calls": 0,
            "string_refs": 0,
            "annotation_count": 0,
            "annotation_preview": [],
            "import_categories": [],
            "import_signals": [],
            "string_signals": [],
            "signal_tags": set(),
            "reasons": [],
            "priority_score": 0,
            "score_breakdown": [],
            "review_status": "unreviewed",
            "review_hint": "",
        }

    for block in cfg.get("blocks", []) or []:
        owner = _find_function_for_addr(function_ranges, block.get("addr"))
        if owner is None:
            continue
        entry = metrics.get(normalize_addr(owner.get("addr", "")))
        if entry is None:
            continue
        entry["block_count"] += 1
        entry["instruction_count"] += len(block.get("lines", []) or [])
        successor_count = len(block.get("successors", []) or [])
        if successor_count > 1 or block.get("is_switch"):
            entry["branch_count"] += max(1, successor_count)

    imported_name_to_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for finding in imports.get("suspicious", []) or []:
        imported_name_to_findings[
            _normalize_symbol_name(finding.get("function", ""))
        ].append(
            {
                "function": str(finding.get("function") or "").strip(),
                "category": str(finding.get("category") or "").strip(),
                "description": str(finding.get("description") or "").strip(),
            }
        )

    import_target_to_callsites: dict[str, list[dict[str, str]]] = defaultdict(list)
    for target_addr, refs in (xref_map or {}).items():
        normalized_target = normalize_addr(target_addr)
        if not normalized_target:
            continue
        for ref in refs or []:
            if str(ref.get("type") or "").strip() != "call":
                continue
            import_target_to_callsites[normalized_target].append(
                {
                    "source_addr": normalize_addr(ref.get("from_addr", "")),
                    "callsite_addr": normalize_addr(ref.get("from_addr", "")),
                    "text": _preview_text(ref.get("text", ""), max_len=96),
                }
            )

    call_graph = build_call_graph(cfg, symbols, lines=lines, binary_path=binary_path)
    for edge in call_graph.get("edges", []) or []:
        from_addr = normalize_addr(edge.get("from", ""))
        to_addr = normalize_addr(edge.get("to", ""))
        source = metrics.get(from_addr)
        if source is not None:
            source["outgoing_calls"] += 1
        target = metrics.get(to_addr)
        if target is not None:
            target["incoming_calls"] += 1
        if source is None:
            continue
        imported_hits = (
            imported_name_to_findings.get(
                _normalize_symbol_name(edge.get("to_name", ""))
            )
            or imported_name_to_findings.get(_normalize_symbol_name(edge.get("to", "")))
            or []
        )
        for hit in imported_hits:
            signal = {
                "function": hit["function"],
                "category": hit["category"],
                "description": hit["description"],
                "target_addr": to_addr,
                "callsites": import_target_to_callsites.get(to_addr, [])[:4],
            }
            if signal not in source["import_signals"]:
                source["import_signals"].append(signal)

    string_addr_map = {
        normalize_addr(entry.get("addr", "")): {
            "value": str(entry.get("value") or ""),
            "length": int(entry.get("length") or 0)
            or len(str(entry.get("value") or "")),
        }
        for entry in strings
        if entry.get("addr")
    }
    for target_addr, refs in (xref_map or {}).items():
        normalized_target = normalize_addr(target_addr)
        string_entry = string_addr_map.get(normalized_target)
        if not string_entry:
            continue
        string_value = string_entry["value"]
        signal = _classify_string_signal(string_value)
        for ref in refs or []:
            owner = _find_function_for_addr(function_ranges, ref.get("from_addr"))
            if owner is None:
                continue
            entry = metrics.get(normalize_addr(owner.get("addr", "")))
            if entry is None:
                continue
            entry["string_refs"] += 1
            if signal is None:
                continue
            signal_id, label = signal
            payload = {
                "category": signal_id,
                "label": label,
                "target_addr": normalized_target,
                "preview": _preview_text(string_value),
                "length": int(string_entry.get("length") or 1),
                "source_addr": normalize_addr(ref.get("from_addr", "")),
            }
            if payload not in entry["string_signals"]:
                entry["string_signals"].append(payload)

    for ann in annotations:
        owner = _find_function_for_addr(function_ranges, ann.get("addr"))
        if owner is None:
            continue
        entry = metrics.get(normalize_addr(owner.get("addr", "")))
        if entry is None:
            continue
        entry["annotation_count"] += 1
        preview = str(ann.get("value") or "").strip()
        if preview:
            entry["annotation_preview"].append(_preview_text(preview, max_len=48))

    for _addr, entry in metrics.items():
        score = 0
        reasons: list[str] = []
        signal_tags: set[str] = set()
        score_breakdown: list[dict[str, Any]] = []

        name = entry["name"]
        normalized_name = str(name).strip()
        for pattern, bonus, reason in _NAME_BONUS_RULES:
            if pattern.search(normalized_name):
                score += bonus
                reasons.append(reason)
                _append_score_breakdown(score_breakdown, bonus, "Nom parlant", reason)
                break

        if entry["reason"] == "entrypoint":
            score += 22
            reasons.append("Seed binaire fort: entrypoint")
            _append_score_breakdown(
                score_breakdown,
                22,
                "Entrypoint",
                "Point d'entrée déclaré par le binaire",
            )

        if entry["kind"] == "import" or entry["symbol_type"] == "U":
            score = max(0, score - 12)
            reasons.append("Stub d'import ou PLT, utile surtout comme pivot")
            _append_score_breakdown(
                score_breakdown, -12, "Import externe", "Stub d'import ou fonction PLT"
            )

        incoming_bonus = min(18, entry["incoming_calls"] * 2)
        outgoing_bonus = min(10, entry["outgoing_calls"])
        if incoming_bonus:
            score += incoming_bonus
            if entry["incoming_calls"] >= 3:
                reasons.append(
                    f"Point chaud: {entry['incoming_calls']} appels entrants"
                )
            _append_score_breakdown(
                score_breakdown,
                incoming_bonus,
                "Centralité entrante",
                f"{entry['incoming_calls']} appel(s) entrant(s)",
            )
        if outgoing_bonus and entry["outgoing_calls"] >= 4:
            score += outgoing_bonus
            reasons.append(f"Orchestre {entry['outgoing_calls']} appels sortants")
            _append_score_breakdown(
                score_breakdown,
                outgoing_bonus,
                "Orchestration",
                f"{entry['outgoing_calls']} appel(s) sortant(s)",
            )

        block_bonus = min(14, entry["block_count"] * 2)
        branch_bonus = min(10, entry["branch_count"] * 2)
        if block_bonus:
            score += block_bonus
            _append_score_breakdown(
                score_breakdown,
                block_bonus,
                "Taille structurelle",
                f"{entry['block_count']} bloc(s)",
            )
        if branch_bonus:
            score += branch_bonus
            _append_score_breakdown(
                score_breakdown,
                branch_bonus,
                "Complexité de flux",
                f"{entry['branch_count']} branche(s)",
            )
        if entry["block_count"] >= 6 or entry["branch_count"] >= 3:
            reasons.append("Structure de controle non triviale")

        import_weight = 0
        for signal in entry["import_signals"]:
            category = str(signal.get("category") or "").strip().upper()
            import_weight += _IMPORT_CATEGORY_WEIGHTS.get(category, 0)
            signal_tags.add(_make_signal_tag(category))
        import_weight = min(import_weight, 32)
        if import_weight:
            score += import_weight
            categories = sorted(
                {
                    _make_signal_tag(signal.get("category", ""))
                    for signal in entry["import_signals"]
                }
            )
            entry["import_categories"] = categories
            reasons.append(f"Appels sensibles: {', '.join(categories[:3])}")
            _append_score_breakdown(
                score_breakdown,
                import_weight,
                "Appels sensibles",
                ", ".join(categories[:3]),
            )

        string_weight = min(
            22, len(entry["string_signals"]) * 7 + min(entry["string_refs"], 4)
        )
        if string_weight:
            score += string_weight
            for signal in entry["string_signals"]:
                signal_tags.add(_make_signal_tag(signal.get("category", "")))
            labels = sorted(
                {
                    _make_signal_tag(signal.get("category", ""))
                    for signal in entry["string_signals"]
                }
            )
            reasons.append(f"Xrefs vers chaines parlantes: {', '.join(labels[:3])}")
            _append_score_breakdown(
                score_breakdown,
                string_weight,
                "Chaînes parlantes",
                ", ".join(labels[:3]),
            )

        if entry["annotation_count"]:
            ann_bonus = min(12, entry["annotation_count"] * 3)
            score += ann_bonus
            reasons.append("Fonction deja annotee dans la session")
            _append_score_breakdown(
                score_breakdown,
                ann_bonus,
                "Contexte analyste",
                f"{entry['annotation_count']} annotation(s)",
            )

        if entry["import_signals"] and entry["string_signals"]:
            score += 8
            reasons.append("Convergence entre appels sensibles et données parlantes")
            _append_score_breakdown(
                score_breakdown,
                8,
                "Convergence",
                "Appels sensibles + chaînes parlantes",
            )

        if entry["size"] >= 96:
            score += 6
            _append_score_breakdown(
                score_breakdown,
                6,
                "Fonction volumineuse",
                f"{entry['size']} octets estimés",
            )
        elif entry["size"] >= 32:
            score += 3
            _append_score_breakdown(
                score_breakdown,
                3,
                "Fonction notable",
                f"{entry['size']} octets estimés",
            )

        if entry["confidence"] == "confirmed":
            score += 6
            _append_score_breakdown(
                score_breakdown,
                6,
                "Découverte confirmée",
                "Seed ou reconstruction forte",
            )
        elif entry["confidence"] == "high":
            score += 3
            _append_score_breakdown(
                score_breakdown, 3, "Découverte fiable", "Confiance high"
            )

        score = max(0, min(100, int(score)))
        level = _priority_level(score)
        entry["priority_score"] = score
        entry["priority_level"] = level
        entry["reasons"] = reasons[:4]
        entry["signal_tags"] = sorted(signal_tags)
        entry["focus_summary"] = _build_focus_summary(entry)
        entry["annotation_preview"] = entry["annotation_preview"][:3]
        entry["string_signals"] = entry["string_signals"][:4]
        entry["import_signals"] = entry["import_signals"][:4]
        entry["score_breakdown"] = score_breakdown[:8]
        if entry["annotation_count"] >= 2:
            entry["review_status"] = "reviewed"
            entry["review_hint"] = "Fonction déjà bien annotée dans la session."
        elif entry["annotation_count"] == 1:
            entry["review_status"] = "in_progress"
            entry["review_hint"] = (
                "Une annotation existe, mais la revue reste partielle."
            )
        elif score >= 52:
            entry["review_status"] = "todo"
            entry["review_hint"] = "Hotspot prioritaire encore non revu."
        else:
            entry["review_status"] = "unreviewed"
            entry["review_hint"] = "Pas encore de trace de revue locale."
        entry["confidence"] = _confidence_level_for_entry(entry)
        entry["needs_review"] = entry["review_status"] != "reviewed"
        entry["evidence"] = _build_function_evidence(entry)
        entry["next_steps"] = _build_function_next_steps(entry)
        entry["proof_dossiers"] = [_build_function_proof_dossier(entry)]

    functions = list(metrics.values())
    functions.sort(
        key=lambda item: (
            -int(item.get("priority_score") or 0),
            -int(item.get("incoming_calls") or 0),
            -int(item.get("block_count") or 0),
            _addr_to_int(item.get("addr")) or 0,
        )
    )

    hotspots = [
        entry
        for entry in functions
        if entry.get("priority_score", 0) >= 40 and entry.get("kind") != "import"
    ][:hotspot_limit]
    quick_wins = [
        entry
        for entry in functions
        if entry.get("priority_score", 0) >= 38
        and entry.get("kind") != "import"
        and (entry.get("block_count", 0) <= 4 or entry.get("size", 0) <= 24)
    ][:hotspot_limit]
    entry_candidates = [
        entry
        for entry in functions
        if entry.get("priority_score", 0) >= 24
        and (
            entry.get("reason") == "entrypoint"
            or re.search(
                r"^(main|_start|start|entry)$",
                str(entry.get("name") or ""),
                re.IGNORECASE,
            )
            or entry.get("incoming_calls", 0) == 0
        )
    ][:hotspot_limit]

    cluster_counts: dict[str, int] = defaultdict(int)
    for entry in functions:
        for tag in entry.get("signal_tags", []):
            cluster_counts[tag] += 1

    clusters = [
        {"name": name, "count": count}
        for name, count in sorted(
            cluster_counts.items(), key=lambda item: (-item[1], item[0])
        )
    ][:6]

    annotated_functions = sum(1 for entry in functions if entry.get("annotation_count"))
    suspicious_import_sites = sum(
        len(entry.get("import_signals", [])) for entry in functions
    )
    suspicious_string_sites = sum(
        len(entry.get("string_signals", [])) for entry in functions
    )

    return {
        "binary": binary_path,
        "cache_db": db_path,
        "summary": {
            "function_count": len(functions),
            "hotspot_count": len(
                [entry for entry in functions if entry.get("priority_score", 0) >= 52]
            ),
            "annotated_functions": annotated_functions,
            "suspicious_import_sites": suspicious_import_sites,
            "suspicious_string_sites": suspicious_string_sites,
            "cluster_count": len(clusters),
        },
        "entry_candidates": entry_candidates,
        "hotspots": hotspots,
        "quick_wins": quick_wins,
        "clusters": clusters,
        "proof_dossiers": [
            entry["proof_dossiers"][0]
            for entry in functions
            if entry.get("proof_dossiers")
        ][:hotspot_limit],
        "functions": functions,
        "error": None,
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a prioritization radar for binary functions"
    )
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument(
        "--cache-db", default=None, help="Optional SQLite cache path (.pfdb)"
    )
    parser.add_argument(
        "--hotspot-limit", type=int, default=8, help="Maximum hotspots to keep"
    )
    args = parser.parse_args()

    configure_logging()
    result = build_function_radar(
        args.binary,
        cache_db=args.cache_db,
        hotspot_limit=max(1, int(args.hotspot_limit or 8)),
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
