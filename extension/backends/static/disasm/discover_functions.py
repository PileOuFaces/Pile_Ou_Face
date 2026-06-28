# SPDX-License-Identifier: AGPL-3.0-only
"""Découverte de fonctions non référencées avec seeds binaires + analyse récursive."""

from __future__ import annotations

import re
import struct
from collections import deque
from dataclasses import dataclass

from backends.shared.log import configure_logging, get_logger
from backends.shared.utils import (
    addr_to_int as _addr_to_int,
)
from backends.shared.utils import (
    normalize_addr as _normalize_addr,
)
from backends.static.binary.arch import (
    ArchAdapter,
    detect_binary_arch_from_path,
    iter_supported_adapters,
)
from backends.static.disasm.cfg import _extract_jump_target, _get_mnemonic

logger = get_logger(__name__)


FILLER_MNEMONICS = frozenset({"nop", "int3", "ud2", "nopw", "align", "data16", "repz"})
RETURN_MNEMONICS = frozenset({"ret", "retq", "retn", "retl"})
EPILOGUE_HINT_MNEMONICS = frozenset({"leave", "ret", "retq", "retn", "retl"})
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2, "confirmed": 3}
REASON_RANK = {
    "flirt": 90,
    "dwarf": 80,
    "pe_pdata": 80,
    "entrypoint": 70,
    "plt_stub": 63,
    "trampoline": 62,
    "call_target_thunk": 65,
    "call_target": 60,
    "tail_call": 55,
    "push rbp": 40,
    "push ebp": 40,
    "endbr64": 40,
    "stp": 40,
    "sub rsp": 30,
    "sub esp": 30,
    "sub sp": 30,
    "str preindex": 30,
}
CONFIDENCE_SCORE_BASE = {
    "low": 0.42,
    "medium": 0.6,
    "high": 0.82,
    "confirmed": 1.0,
}
REASON_SCORE_FLOOR = {
    "flirt": 1.0,
    "dwarf": 0.96,
    "pe_pdata": 0.93,
    "entrypoint": 0.9,
    "plt_stub": 0.88,
    "trampoline": 0.84,
    "call_target_thunk": 0.86,
    "call_target": 0.72,
    "tail_call": 0.7,
    "push rbp": 0.68,
    "push ebp": 0.68,
    "endbr64": 0.68,
    "stp": 0.68,
    "sub rsp": 0.6,
    "sub esp": 0.6,
    "sub sp": 0.6,
    "str preindex": 0.58,
}


@dataclass(frozen=True)
class ThunkDispatch:
    start_idx: int
    dispatch_idx: int
    reason: str
    target_int: int = 0
    pattern: str = ""


def _extract_pe_functions(binary_path: str) -> dict[int, str]:
    """Extrait les adresses de fonctions depuis la table d'exceptions PE (.pdata)."""
    try:
        import lief  # type: ignore[import-untyped]

        binary = lief.parse(binary_path)
        if not isinstance(binary, lief.PE.Binary):
            return {}
        base = binary.optional_header.imagebase
        addrs: dict[int, str] = {}
        for section in binary.sections:
            if section.name != ".pdata":
                continue
            content = bytes(section.content)
            for i in range(0, len(content) - 11, 12):
                begin_rva = struct.unpack_from("<I", content, i)[0]
                if begin_rva:
                    addrs[base + begin_rva] = "pe_pdata"
            break
        return addrs
    except Exception:
        return {}


def _extract_dwarf_functions(binary_path: str) -> dict[int, str]:
    """Retourne {low_pc_int: function_name} depuis DWARF si disponible."""
    try:
        from backends.static.binary.dwarf import extract_dwarf_info

        dwarf_info = extract_dwarf_info(binary_path)
        if dwarf_info.get("error"):
            return {}
        addrs: dict[int, str] = {}
        for fn in dwarf_info.get("functions", []):
            addr = _addr_to_int(fn.get("low_pc", ""))
            if addr:
                addrs[addr] = fn.get("name", "") or f"sub_{addr:x}"
        return addrs
    except Exception:
        return {}


def _candidate_adapters(binary_path: str | None) -> tuple[ArchAdapter, ...]:
    info = detect_binary_arch_from_path(binary_path) if binary_path else None
    if info is not None:
        return (info.adapter,)
    return tuple(iter_supported_adapters())


def _collect_binary_function_hints(
    binary_path: str | None,
) -> tuple[dict[int, str], dict[int, str]]:
    """Retourne (reasons, names) pour les seeds de fonctions connues du binaire."""
    if not binary_path:
        return {}, {}

    reasons: dict[int, str] = {}
    names: dict[int, str] = {}

    try:
        import lief  # type: ignore[import-untyped]

        binary = lief.parse(binary_path)
        if binary is not None:
            entrypoint = int(getattr(binary, "entrypoint", 0) or 0)
            if entrypoint:
                reasons.setdefault(entrypoint, "entrypoint")
                names.setdefault(entrypoint, "entry")
    except Exception:
        pass

    for addr, reason in _extract_pe_functions(binary_path).items():
        reasons.setdefault(addr, reason)

    for addr, name in _extract_dwarf_functions(binary_path).items():
        reasons.setdefault(addr, "dwarf")
        names.setdefault(addr, name)

    return reasons, names


def _matches_prologue(
    text: str,
    custom_preludes: list[tuple[str, str]] | None = None,
    adapters: tuple[ArchAdapter, ...] | None = None,
) -> str | None:
    """Vérifie si l'instruction ressemble à un prologue de fonction."""
    t = text.strip()
    for pattern, name in custom_preludes or []:
        if re.search(pattern, t, re.IGNORECASE):
            return name
    for adapter in adapters or tuple(iter_supported_adapters()):
        matched = adapter.matches_prologue(t)
        if matched:
            return matched
    return None


def _is_filler(text: str) -> bool:
    """Vérifie si l'instruction est un filler (nop, etc.)."""
    parts = text.split()
    mnem = parts[0].lower() if parts else ""
    return mnem in FILLER_MNEMONICS or mnem.startswith("nop")


def _line_text(line: dict) -> str:
    return str(line.get("text", "") or "").strip()


def _line_mnemonic(line: dict) -> str:
    mnem = str(line.get("mnemonic", "") or "").strip().lower()
    if mnem:
        return mnem
    return _get_mnemonic(_line_text(line))


def _line_operands(line: dict) -> str:
    operands = str(line.get("operands", "") or "").strip()
    if operands:
        return operands
    text = _line_text(line)
    mnem = _line_mnemonic(line)
    if not text or not mnem:
        return ""
    pattern = re.compile(rf"^(?:[0-9a-f]{{2}}\s+)*{re.escape(mnem)}\s*", re.IGNORECASE)
    return pattern.sub("", text).strip()


def _instruction_size(line: dict) -> int:
    raw = str(line.get("bytes", "") or "").strip()
    if raw:
        return max(1, len([part for part in raw.split() if part]))
    return 1


def _extract_direct_target_int(line: dict) -> int:
    operands = _line_operands(line)
    text = _line_text(line)
    if ("[" in operands and "]" in operands) or ("[" in text and "]" in text):
        return 0
    for candidate in (operands, text):
        target = _extract_jump_target(candidate)
        if target:
            return _addr_to_int(target)
    return 0


def _is_conditional_branch_mnemonic(mnem: str) -> bool:
    for adapter in iter_supported_adapters():
        if adapter.is_conditional_branch_mnemonic(mnem):
            return True
    return False


def _is_return_like(line: dict, adapters: tuple[ArchAdapter, ...]) -> bool:
    mnem = _line_mnemonic(line)
    operands = _line_operands(line)
    return bool(
        mnem in RETURN_MNEMONICS
        or any(adapter.is_return_instruction(mnem, operands) for adapter in adapters)
    )


def _is_call_mnemonic(mnem: str, adapters: tuple[ArchAdapter, ...]) -> bool:
    return any(adapter.is_call_mnemonic(mnem) for adapter in adapters)


def _is_unconditional_jump_mnemonic(
    mnem: str, adapters: tuple[ArchAdapter, ...]
) -> bool:
    return any(adapter.is_unconditional_jump_mnemonic(mnem) for adapter in adapters)


def _looks_like_thunk_start(line: dict, adapters: tuple[ArchAdapter, ...]) -> bool:
    mnem = _line_mnemonic(line)
    if not _is_unconditional_jump_mnemonic(mnem, adapters):
        return False
    if _extract_direct_target_int(line):
        return True
    operands = _line_operands(line).lower()
    if not operands:
        return False
    if any(scale in operands for scale in ("*4", "*8")):
        return False
    if any(token in operands for token in ("@plt", "@got", ".plt", ".got")):
        return True
    return (
        "[" in operands
        and "]" in operands
        and any(base in operands for base in ("rip", "eip"))
    )


def _split_operands(operands: str) -> list[str]:
    return [part.strip() for part in str(operands or "").split(",") if part.strip()]


def _normalize_register_token(token: str) -> str:
    cleaned = re.sub(
        r"\b(?:byte|word|dword|qword|xword|oword|ptr|offset|short|near|far)\b",
        "",
        str(token or "").lower(),
    )
    cleaned = cleaned.replace("{", "").replace("}", "").replace("!", "").strip()
    match = re.match(r"^([a-z][a-z0-9]*)\b", cleaned)
    return match.group(1) if match else ""


def _extract_written_register(line: dict) -> tuple[str, int, bool]:
    mnem = _line_mnemonic(line)
    if mnem not in {"mov", "lea", "adr", "adrp", "ldr", "ldrsw", "ldur", "add"}:
        return "", 0, False
    operands = _split_operands(_line_operands(line))
    if len(operands) < 2:
        return "", 0, False
    dst = _normalize_register_token(operands[0])
    if not dst:
        return "", 0, False
    src = ",".join(operands[1:]).strip()
    if not src:
        return dst, 0, False
    if "[" in src and "]" in src:
        return dst, 0, True
    if mnem == "add":
        return dst, 0, False
    target = _extract_jump_target(src)
    return dst, _addr_to_int(target) if target else 0, False


def _is_register_jump(
    line: dict, expected_reg: str, adapters: tuple[ArchAdapter, ...]
) -> bool:
    mnem = _line_mnemonic(line)
    if not _is_unconditional_jump_mnemonic(mnem, adapters):
        return False
    if _extract_direct_target_int(line):
        return False
    operands = _split_operands(_line_operands(line))
    if not operands:
        return False
    return _normalize_register_token(operands[0]) == expected_reg


def _meaningful_line_indexes(
    lines: list[dict], start_idx: int, lookahead: int = 4
) -> list[int]:
    indexes: list[int] = []
    for idx in range(start_idx, min(len(lines), start_idx + 1 + lookahead)):
        text = _line_text(lines[idx])
        if not text or _is_filler(text):
            continue
        indexes.append(idx)
    return indexes


def _find_thunk_dispatch(
    lines: list[dict],
    start_idx: int,
    adapters: tuple[ArchAdapter, ...],
    lookahead: int = 4,
) -> ThunkDispatch | None:
    """Trouve l'instruction de dispatch d'un thunk depuis son adresse de départ."""
    if start_idx < 0 or start_idx >= len(lines):
        return None

    indexes = _meaningful_line_indexes(lines, start_idx, lookahead=lookahead)
    if not indexes:
        return None

    base_pos = 0
    if _line_mnemonic(lines[indexes[0]]) == "endbr64" and len(indexes) > 1:
        base_pos = 1

    base_idx = indexes[base_pos]
    base_line = lines[base_idx]
    if _looks_like_thunk_start(base_line, adapters):
        return ThunkDispatch(
            start_idx=start_idx,
            dispatch_idx=base_idx,
            reason="trampoline"
            if _extract_direct_target_int(base_line)
            else "plt_stub",
            target_int=_extract_direct_target_int(base_line),
            pattern="jump",
        )

    if base_pos + 1 < len(indexes):
        next_idx = indexes[base_pos + 1]
        next_line = lines[next_idx]
        if _line_mnemonic(base_line) == "push" and _is_return_like(next_line, adapters):
            target_int = _extract_direct_target_int(base_line)
            if target_int:
                return ThunkDispatch(
                    start_idx=start_idx,
                    dispatch_idx=next_idx,
                    reason="trampoline",
                    target_int=target_int,
                    pattern="push_ret",
                )

    current_reg = ""
    current_target = 0
    current_indirect = False
    for idx in indexes[base_pos:]:
        line = lines[idx]
        if not current_reg:
            reg, target_int, indirect = _extract_written_register(line)
            if not reg:
                break
            current_reg = reg
            current_target = target_int
            current_indirect = indirect or not bool(target_int)
            continue
        if _is_register_jump(line, current_reg, adapters):
            return ThunkDispatch(
                start_idx=start_idx,
                dispatch_idx=idx,
                reason="plt_stub"
                if current_indirect or not current_target
                else "trampoline",
                target_int=current_target,
                pattern="register_jump",
            )
        reg, target_int, indirect = _extract_written_register(line)
        if reg and reg == current_reg:
            if target_int:
                current_target = target_int
            current_indirect = current_indirect or indirect or not bool(target_int)
            continue
        break

    return None


def _resolve_thunk_target(
    start_addr: int,
    lines: list[dict],
    line_index_by_addr: dict[int, int],
    adapters: tuple[ArchAdapter, ...],
    max_depth: int = 6,
) -> int:
    """Suit une courte chaîne de thunks/trampolines pour identifier la vraie cible."""
    current = start_addr
    final_target = 0
    seen: set[int] = set()

    for _ in range(max_depth):
        if current in seen:
            break
        seen.add(current)
        idx = line_index_by_addr.get(current)
        if idx is None:
            break
        dispatch = _find_thunk_dispatch(lines, idx, adapters)
        if not dispatch or not dispatch.target_int:
            break
        final_target = dispatch.target_int
        current = dispatch.target_int

    return final_target


def _looks_like_function_start(
    line: dict | None,
    addr_int: int,
    hint_reasons: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> bool:
    if addr_int in hint_reasons:
        return True
    if not line:
        return False
    if _matches_prologue(_line_text(line), custom_preludes, adapters=adapters):
        return True
    return _looks_like_thunk_start(line, adapters)


def _has_epilogue_before(lines: list[dict], idx: int) -> bool:
    """Détecte un épilogue juste avant un jmp direct (tail-call probable)."""
    seen_meaningful = 0
    for back_idx in range(idx - 1, -1, -1):
        text = _line_text(lines[back_idx])
        if not text or _is_filler(text):
            continue
        seen_meaningful += 1
        mnem = _line_mnemonic(lines[back_idx])
        operands = _line_operands(lines[back_idx]).lower()
        if mnem in EPILOGUE_HINT_MNEMONICS:
            return True
        if mnem == "pop" and ("rbp" in operands or "ebp" in operands):
            return True
        if mnem == "mov" and ("rsp, rbp" in operands or "esp, ebp" in operands):
            return True
        if mnem == "add" and (
            "rsp" in operands or "esp" in operands or operands.startswith("sp,")
        ):
            return True
        if mnem == "ldp" and "x29" in operands and "x30" in operands:
            return True
        if seen_meaningful >= 3:
            break
    return False


def _is_tail_call_candidate(
    lines: list[dict],
    idx: int,
    target_int: int,
    line_by_addr: dict[int, dict],
    line_index_by_addr: dict[int, int],
    hint_reasons: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> bool:
    target_line = line_by_addr.get(target_int)
    if not target_line:
        return False
    if _has_epilogue_before(lines, idx):
        target_idx = line_index_by_addr.get(target_int, -1)
        if target_idx >= 0 and _find_thunk_dispatch(lines, target_idx, adapters):
            return True
        return _looks_like_function_start(
            target_line,
            target_int,
            hint_reasons,
            adapters,
            custom_preludes=custom_preludes,
        )
    return target_int in hint_reasons and _looks_like_function_start(
        target_line,
        target_int,
        hint_reasons,
        adapters,
        custom_preludes=custom_preludes,
    )


def _function_name_for(
    addr_int: int,
    flirt_map: dict[int, str],
    hint_names: dict[int, str],
) -> str:
    return flirt_map.get(addr_int) or hint_names.get(addr_int) or f"sub_{addr_int:x}"


def _confidence_for(
    addr_int: int,
    reason: str,
    line: dict | None,
    hint_reasons: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> str:
    if addr_int in hint_reasons:
        return "high"
    if reason in {"plt_stub", "trampoline"}:
        return "high"
    if reason == "call_target_thunk":
        return "high"
    if line and _matches_prologue(_line_text(line), custom_preludes, adapters=adapters):
        return "high"
    if line and _looks_like_thunk_start(line, adapters):
        return "high"
    return "medium"


def _kind_for(reason: str, line: dict | None, adapters: tuple[ArchAdapter, ...]) -> str:
    if reason in {"call_target_thunk", "plt_stub", "trampoline"}:
        return "thunk"
    if line and _looks_like_thunk_start(line, adapters):
        return "thunk"
    return "function"


def _confidence_score_for(
    addr_int: int,
    confidence: str,
    reason: str,
    line: dict | None,
    hint_reasons: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> float:
    score = CONFIDENCE_SCORE_BASE.get(confidence, 0.4)
    score = max(score, REASON_SCORE_FLOOR.get(reason, 0.0))

    if addr_int in hint_reasons:
        score = max(score, 0.9)
    if line and _matches_prologue(_line_text(line), custom_preludes, adapters=adapters):
        score += 0.04
    if line and _looks_like_thunk_start(line, adapters):
        score += 0.05

    return round(min(1.0, score), 2)


def _record_candidate(
    candidates: dict[int, dict],
    addr_int: int,
    *,
    name: str,
    confidence: str,
    reason: str,
    kind: str | None = None,
    confidence_score: float | None = None,
    target_addr: str | None = None,
) -> None:
    record = {
        "addr": _normalize_addr(f"0x{addr_int:x}"),
        "name": name,
        "confidence": confidence,
        "reason": reason,
    }
    if kind:
        record["kind"] = kind
    if confidence_score is not None:
        record["confidence_score"] = confidence_score
    if target_addr:
        record["target_addr"] = target_addr
    current = candidates.get(addr_int)
    if current is None:
        candidates[addr_int] = record
        return
    current_conf = CONFIDENCE_RANK.get(current.get("confidence", "low"), 0)
    new_conf = CONFIDENCE_RANK.get(confidence, 0)
    current_reason = REASON_RANK.get(str(current.get("reason", "")), 0)
    new_reason = REASON_RANK.get(reason, 0)
    current_named = not str(current.get("name", "")).startswith("sub_")
    new_named = not name.startswith("sub_")
    if (
        new_conf > current_conf
        or (new_conf == current_conf and new_reason > current_reason)
        or (
            new_conf == current_conf
            and new_reason == current_reason
            and new_named
            and not current_named
        )
    ):
        candidates[addr_int] = record
        return

    for key in ("kind", "target_addr"):
        if record.get(key) and not current.get(key):
            current[key] = record[key]
    if record.get("confidence_score") is not None:
        current["confidence_score"] = max(
            float(current.get("confidence_score", 0.0) or 0.0),
            float(record["confidence_score"]),
        )


def _candidate_priority(record: dict) -> int:
    confidence = CONFIDENCE_RANK.get(str(record.get("confidence", "low")), 0)
    reason = REASON_RANK.get(str(record.get("reason", "")), 0)
    score = int(round(float(record.get("confidence_score", 0.0) or 0.0) * 100))
    named = 1 if not str(record.get("name", "")).startswith("sub_") else 0
    thunk = 1 if record.get("kind") == "thunk" else 0
    return confidence * 10000 + reason * 100 + score + named * 5 + thunk


def _candidate_is_protected(record: dict) -> bool:
    reason = str(record.get("reason", ""))
    return reason in {
        "flirt",
        "dwarf",
        "pe_pdata",
        "entrypoint",
        "call_target",
        "call_target_thunk",
        "tail_call",
        "plt_stub",
        "trampoline",
    }


def _estimate_candidate_bounds_map(
    lines: list[dict],
    starts: list[int],
    coverage: dict[int, set[int]],
) -> dict[int, tuple[int | None, int | None, str | None]]:
    bounds: dict[int, tuple[int | None, int | None, str | None]] = {}
    for addr in starts:
        bounds[addr] = _estimate_function_bounds(
            lines,
            addr,
            starts,
            visited_addrs=coverage.get(addr),
        )
    return bounds


def _resolve_candidate_overlaps(
    lines: list[dict],
    candidates: dict[int, dict],
    coverage: dict[int, set[int]],
) -> dict[int, dict]:
    if len(candidates) < 2:
        return dict(candidates)

    accepted = dict(candidates)

    while True:
        starts = sorted(accepted)
        bounds_map = _estimate_candidate_bounds_map(lines, starts, coverage)
        removed = False

        for outer_idx, outer_start in enumerate(starts):
            outer_record = accepted.get(outer_start)
            if outer_record is None:
                continue
            outer_end, _, _ = bounds_map.get(outer_start, (None, None, None))
            if outer_end is None or outer_end <= outer_start:
                continue

            outer_coverage = coverage.get(outer_start, set())
            outer_priority = _candidate_priority(outer_record)
            outer_protected = _candidate_is_protected(outer_record)

            for inner_start in starts[outer_idx + 1 :]:
                if inner_start >= outer_end:
                    break
                inner_record = accepted.get(inner_start)
                if inner_record is None:
                    continue

                inner_end, _, _ = bounds_map.get(inner_start, (None, None, None))
                inner_coverage = coverage.get(inner_start, set())
                inner_priority = _candidate_priority(inner_record)
                inner_protected = _candidate_is_protected(inner_record)

                nested_in_coverage = (
                    bool(outer_coverage) and inner_start in outer_coverage
                )
                inner_subset = (
                    bool(inner_coverage)
                    and bool(outer_coverage)
                    and inner_coverage.issubset(outer_coverage | {outer_start})
                )
                inner_nested = nested_in_coverage or inner_subset

                if (
                    inner_nested
                    and not inner_protected
                    and outer_priority >= inner_priority + 15
                ):
                    del accepted[inner_start]
                    removed = True
                    break

                outer_subset = (
                    bool(inner_coverage)
                    and bool(outer_coverage)
                    and outer_coverage.issubset(inner_coverage | {inner_start})
                )
                if (
                    inner_start == outer_start
                    or (
                        outer_subset
                        and not outer_protected
                        and inner_priority >= outer_priority + 15
                    )
                    or (
                        inner_end is not None
                        and inner_end >= outer_end
                        and not outer_protected
                        and inner_priority >= outer_priority + 25
                    )
                ):
                    del accepted[outer_start]
                    removed = True
                    break

            if removed:
                break

        if not removed:
            return accepted


def _scan_heuristic_starts(
    lines: list[dict],
    known: set[int],
    hint_reasons: dict[int, str],
    flirt_map: dict[int, str],
    hint_names: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> dict[int, dict]:
    """Fallback historique : prologues + gaps + hints binaires."""
    discovered: dict[int, dict] = {}
    prev_was_terminator = True
    line_index_by_addr = {
        _addr_to_int(line.get("addr", "")): idx
        for idx, line in enumerate(lines)
        if line.get("addr")
    }

    sorted_known = sorted(known | set(hint_reasons))
    gap_ranges = [
        (sorted_known[i], sorted_known[i + 1]) for i in range(len(sorted_known) - 1)
    ]

    for i, line in enumerate(lines):
        addr = line.get("addr", "")
        text = _line_text(line)
        if not addr or not text:
            continue

        addr_int = _addr_to_int(addr)
        if addr_int in known:
            prev_was_terminator = False
            continue

        prologue = _matches_prologue(text, custom_preludes, adapters=adapters)
        thunk_dispatch = _find_thunk_dispatch(lines, i, adapters)
        thunk_start = thunk_dispatch is not None
        in_gap = any(lo < addr_int < hi for lo, hi in gap_ranges)
        in_hint = addr_int in hint_reasons
        can_start = prev_was_terminator or i == 0 or in_gap or in_hint

        if ((prologue or thunk_start) and can_start) or in_hint:
            if addr_int in flirt_map:
                confidence = "confirmed"
            elif (
                in_hint
                or thunk_start
                or prologue in ("endbr64", "push rbp", "push ebp", "stp")
            ):
                confidence = "high"
            else:
                confidence = "medium"
            reason = (
                "flirt"
                if addr_int in flirt_map
                else (
                    hint_reasons.get(addr_int)
                    or (
                        thunk_dispatch.reason
                        if thunk_dispatch
                        else prologue or "prologue"
                    )
                )
            )
            thunk_target = 0
            if thunk_dispatch:
                thunk_target = _resolve_thunk_target(
                    addr_int, lines, line_index_by_addr, adapters
                )
            _record_candidate(
                discovered,
                addr_int,
                name=_function_name_for(addr_int, flirt_map, hint_names),
                confidence=confidence,
                reason=reason,
                kind="thunk" if thunk_dispatch else _kind_for(reason, line, adapters),
                confidence_score=_confidence_score_for(
                    addr_int,
                    confidence,
                    reason,
                    line,
                    hint_reasons,
                    adapters,
                    custom_preludes=custom_preludes,
                ),
                target_addr=_normalize_addr(f"0x{thunk_target:x}")
                if thunk_target and thunk_target != addr_int
                else None,
            )
            prev_was_terminator = False
            continue

        mnem = _line_mnemonic(line)
        if _is_return_like(line, adapters) or _is_unconditional_jump_mnemonic(
            mnem, adapters
        ):
            prev_was_terminator = True
        elif _is_filler(text):
            pass
        else:
            prev_was_terminator = False

    return discovered


def _walk_seed_functions(
    lines: list[dict],
    analysis_seeds: set[int],
    known_boundaries: set[int],
    candidates: dict[int, dict],
    hint_reasons: dict[int, str],
    hint_names: dict[int, str],
    flirt_map: dict[int, str],
    adapters: tuple[ArchAdapter, ...],
    custom_preludes: list[tuple[str, str]] | None = None,
) -> dict[int, set[int]]:
    """Parcourt récursivement le code à partir de seeds et découvre des cibles d'appels."""
    line_by_addr = {
        _addr_to_int(line.get("addr", "")): line for line in lines if line.get("addr")
    }
    line_index_by_addr = {
        _addr_to_int(line.get("addr", "")): idx
        for idx, line in enumerate(lines)
        if line.get("addr")
    }
    sorted_addrs = [
        _addr_to_int(line.get("addr", "")) for line in lines if line.get("addr")
    ]
    next_addr: dict[int, int] = {}
    for cur, nxt in zip(sorted_addrs, sorted_addrs[1:], strict=False):
        next_addr[cur] = nxt

    queued = deque(addr for addr in sorted(analysis_seeds) if addr in line_by_addr)
    analysed_seeds: set[int] = set()
    coverage: dict[int, set[int]] = {}

    while queued:
        start = queued.popleft()
        if start in analysed_seeds or start not in line_by_addr:
            continue
        analysed_seeds.add(start)

        visited: set[int] = set()
        coverage.setdefault(start, set())
        worklist = deque([start])

        while worklist:
            addr = worklist.popleft()
            if addr in visited or addr not in line_by_addr:
                continue
            if addr != start and addr in known_boundaries:
                continue
            visited.add(addr)
            coverage[start].add(addr)

            line = line_by_addr[addr]
            idx = line_index_by_addr.get(addr, -1)
            mnem = _line_mnemonic(line)
            target_int = _extract_direct_target_int(line)
            fallthrough = next_addr.get(addr)

            if _is_call_mnemonic(mnem, adapters):
                if target_int and target_int in line_by_addr:
                    target_line = line_by_addr[target_int]
                    target_idx = line_index_by_addr.get(target_int, -1)
                    thunk_dispatch = (
                        _find_thunk_dispatch(lines, target_idx, adapters)
                        if target_idx >= 0
                        else None
                    )
                    resolved_target = (
                        _resolve_thunk_target(
                            target_int, lines, line_index_by_addr, adapters
                        )
                        if thunk_dispatch
                        else 0
                    )
                    reason = "call_target_thunk" if thunk_dispatch else "call_target"
                    confidence = (
                        "confirmed"
                        if target_int in flirt_map
                        else _confidence_for(
                            target_int,
                            reason,
                            target_line,
                            hint_reasons,
                            adapters,
                            custom_preludes=custom_preludes,
                        )
                    )
                    _record_candidate(
                        candidates,
                        target_int,
                        name=_function_name_for(target_int, flirt_map, hint_names),
                        confidence=confidence,
                        reason=reason,
                        kind="thunk"
                        if thunk_dispatch
                        else _kind_for(reason, target_line, adapters),
                        confidence_score=_confidence_score_for(
                            target_int,
                            confidence,
                            reason,
                            target_line,
                            hint_reasons,
                            adapters,
                            custom_preludes=custom_preludes,
                        ),
                        target_addr=_normalize_addr(f"0x{resolved_target:x}")
                        if resolved_target and resolved_target != target_int
                        else None,
                    )
                    if target_int not in known_boundaries:
                        known_boundaries.add(target_int)
                        queued.append(target_int)
                if fallthrough and fallthrough not in visited:
                    worklist.append(fallthrough)
                continue

            if _is_return_like(line, adapters):
                continue

            if _is_unconditional_jump_mnemonic(mnem, adapters):
                if target_int and target_int in line_by_addr:
                    if idx >= 0 and _is_tail_call_candidate(
                        lines,
                        idx,
                        target_int,
                        line_by_addr,
                        line_index_by_addr,
                        hint_reasons,
                        adapters,
                        custom_preludes=custom_preludes,
                    ):
                        target_dispatch = _find_thunk_dispatch(
                            lines, line_index_by_addr.get(target_int, -1), adapters
                        )
                        resolved_target = (
                            _resolve_thunk_target(
                                target_int, lines, line_index_by_addr, adapters
                            )
                            if target_dispatch
                            else 0
                        )
                        confidence = (
                            "confirmed"
                            if target_int in flirt_map
                            else _confidence_for(
                                target_int,
                                "tail_call",
                                line_by_addr[target_int],
                                hint_reasons,
                                adapters,
                                custom_preludes=custom_preludes,
                            )
                        )
                        _record_candidate(
                            candidates,
                            target_int,
                            name=_function_name_for(target_int, flirt_map, hint_names),
                            confidence=confidence,
                            reason="tail_call",
                            kind="thunk"
                            if target_dispatch
                            else _kind_for(
                                "tail_call", line_by_addr[target_int], adapters
                            ),
                            confidence_score=_confidence_score_for(
                                target_int,
                                confidence,
                                "tail_call",
                                line_by_addr[target_int],
                                hint_reasons,
                                adapters,
                                custom_preludes=custom_preludes,
                            ),
                            target_addr=_normalize_addr(f"0x{resolved_target:x}")
                            if resolved_target and resolved_target != target_int
                            else None,
                        )
                        if target_int not in known_boundaries:
                            known_boundaries.add(target_int)
                            queued.append(target_int)
                    elif target_int not in visited:
                        worklist.append(target_int)
                continue

            if _is_conditional_branch_mnemonic(mnem):
                if target_int and target_int not in visited:
                    worklist.append(target_int)
                if fallthrough and fallthrough not in visited:
                    worklist.append(fallthrough)
                continue

            if fallthrough and fallthrough not in visited:
                worklist.append(fallthrough)

    return coverage


def _estimate_function_bounds(
    lines: list[dict],
    start_addr: int,
    all_starts: list[int],
    visited_addrs: set[int] | None = None,
) -> tuple[int | None, int | None, str | None]:
    """Estime la taille en s'arrêtant au prochain start ou à un terminator fort."""
    start_indices = {
        _addr_to_int(line.get("addr", "")): idx
        for idx, line in enumerate(lines)
        if line.get("addr")
    }
    start_idx = start_indices.get(start_addr)
    if start_idx is None:
        return None, None

    next_start = next((addr for addr in all_starts if addr > start_addr), None)
    end_addr = start_addr

    if visited_addrs:
        for line in lines:
            addr = _addr_to_int(line.get("addr", ""))
            if addr and addr in visited_addrs:
                end_addr = max(end_addr, addr + _instruction_size(line))
        if next_start is not None and end_addr > next_start:
            end_addr = next_start
            return end_addr, max(1, end_addr - start_addr), "next_start"
        if end_addr > start_addr:
            return end_addr, max(1, end_addr - start_addr), "coverage"

    for idx in range(start_idx, len(lines)):
        line = lines[idx]
        addr = _addr_to_int(line.get("addr", ""))
        if next_start is not None and idx > start_idx and addr >= next_start:
            break
        end_addr = addr + _instruction_size(line)
        mnem = _line_mnemonic(line)
        if _is_return_like(line, tuple(iter_supported_adapters())):
            return end_addr, max(1, end_addr - start_addr), "terminator"
        if _is_unconditional_jump_mnemonic(
            mnem, tuple(iter_supported_adapters())
        ) and _extract_direct_target_int(line):
            return end_addr, max(1, end_addr - start_addr), "terminator"

    if next_start is not None:
        end_addr = next_start
        return end_addr, max(1, end_addr - start_addr), "next_start"
    if end_addr > start_addr:
        return end_addr, end_addr - start_addr, "linear"
    return None, None, None


def evaluate_function_discovery(
    discovered: list[dict],
    expected_addrs: list[str] | set[str] | list[int] | set[int],
    *,
    known_addrs: set[str] | set[int] | None = None,
) -> dict:
    """Calcule des métriques de précision/rappel pour un corpus synthétique."""
    expected = {_addr_to_int(addr) for addr in expected_addrs if _addr_to_int(addr)}
    known = {
        _addr_to_int(addr) for addr in (known_addrs or set()) if _addr_to_int(addr)
    }
    found = {
        _addr_to_int(fn.get("addr", ""))
        for fn in discovered
        if _addr_to_int(fn.get("addr", ""))
        and _addr_to_int(fn.get("addr", "")) not in known
    }

    true_positive = sorted(found & expected)
    false_positive = sorted(found - expected)
    missed = sorted(expected - found)

    intervals: list[tuple[int, int]] = []
    for fn in discovered:
        start = _addr_to_int(fn.get("addr", ""))
        end = _addr_to_int(fn.get("end_addr", "")) if fn.get("end_addr") else 0
        if start and end and end > start:
            intervals.append((start, end))
    intervals.sort()
    overlap_pairs: list[dict[str, str]] = []
    previous: tuple[int, int] | None = None
    for interval in intervals:
        if previous and interval[0] < previous[1]:
            overlap_pairs.append(
                {
                    "left": _normalize_addr(f"0x{previous[0]:x}"),
                    "right": _normalize_addr(f"0x{interval[0]:x}"),
                }
            )
        if previous is None or interval[1] > previous[1]:
            previous = interval

    precision = (
        round(len(true_positive) / len(found), 3)
        if found
        else (1.0 if not expected else 0.0)
    )
    recall = round(len(true_positive) / len(expected), 3) if expected else 1.0

    return {
        "expected_count": len(expected),
        "discovered_count": len(found),
        "true_positive_count": len(true_positive),
        "false_positive_count": len(false_positive),
        "missed_count": len(missed),
        "precision": precision,
        "recall": recall,
        "overlap_count": len(overlap_pairs),
        "true_positive": [_normalize_addr(f"0x{addr:x}") for addr in true_positive],
        "false_positive": [_normalize_addr(f"0x{addr:x}") for addr in false_positive],
        "missed": [_normalize_addr(f"0x{addr:x}") for addr in missed],
        "overlaps": overlap_pairs,
    }


def discover_functions(
    lines: list[dict],
    known_addrs: set[str],
    custom_preludes: list[tuple[str, str]] | None = None,
    binary_path: str | None = None,
    flirt_matches: list[dict] | None = None,
) -> list[dict]:
    """Découvre les fonctions non référencées avec seeds binaires + analyse récursive."""
    if not lines:
        return []

    known = {_addr_to_int(a) for a in known_addrs if a}

    flirt_map: dict[int, str] = {}
    if flirt_matches:
        for match in flirt_matches:
            addr = _addr_to_int(match.get("addr", ""))
            if addr and match.get("name"):
                flirt_map[addr] = match["name"]

    hint_reasons, hint_names = _collect_binary_function_hints(binary_path)
    adapters = _candidate_adapters(binary_path)

    heuristic_candidates = _scan_heuristic_starts(
        lines,
        known,
        hint_reasons,
        flirt_map,
        hint_names,
        adapters,
        custom_preludes=custom_preludes,
    )
    candidates = dict(heuristic_candidates)

    analysis_seeds = set(hint_reasons)
    analysis_seeds.update(heuristic_candidates)
    first_addr = (
        _addr_to_int(lines[0].get("addr", "")) if lines and lines[0].get("addr") else 0
    )
    if first_addr:
        analysis_seeds.add(first_addr)

    known_boundaries = {addr for addr in known if addr}
    known_boundaries.update(hint_reasons)
    known_boundaries.update(heuristic_candidates)

    coverage = _walk_seed_functions(
        lines,
        analysis_seeds,
        known_boundaries,
        candidates,
        hint_reasons,
        hint_names,
        flirt_map,
        adapters,
        custom_preludes=custom_preludes,
    )
    candidates = _resolve_candidate_overlaps(lines, candidates, coverage)

    result = []
    for addr_int, record in sorted(candidates.items(), key=lambda item: item[0]):
        if addr_int in known:
            continue
        result.append(dict(record))

    all_starts = sorted(
        set(known)
        | set(hint_reasons)
        | {addr_int for addr_int, _ in candidates.items()}
    )
    for fn in result:
        fn_addr = _addr_to_int(fn["addr"])
        end_addr, size, boundary_reason = _estimate_function_bounds(
            lines,
            fn_addr,
            all_starts,
            visited_addrs=coverage.get(fn_addr),
        )
        if end_addr:
            fn["end_addr"] = _normalize_addr(f"0x{end_addr:x}")
        if size:
            fn["size"] = size
        if boundary_reason:
            fn["boundary_reason"] = boundary_reason

    return result


def _load_expected_addrs(raw: str) -> list[str]:
    import json
    import os

    try:
        if "[" in raw:
            parsed = json.loads(raw)
            if isinstance(parsed, list):
                return [str(item) for item in parsed if str(item).strip()]
    except Exception:
        pass

    if os.path.exists(raw):
        with open(raw, encoding="utf-8") as handle:
            parsed = json.load(handle)
        if isinstance(parsed, list):
            return [str(item) for item in parsed if str(item).strip()]
        return []

    return [part.strip() for part in raw.split(",") if part.strip()]


def main() -> int:
    """Point d'entrée CLI : découvre les fonctions non référencées."""
    import argparse
    import json
    import os

    from backends.static.binary.symbols import extract_symbols

    parser = argparse.ArgumentParser(
        description="Discover functions by recursive seeds + heuristics"
    )
    parser.add_argument("--mapping", required=True, help="Path to disasm mapping JSON")
    parser.add_argument("--binary", help="Binary path (for known symbols)")
    parser.add_argument(
        "--expected",
        help="Expected function addresses (JSON list path, JSON string or comma-separated list)",
    )
    parser.add_argument(
        "--prelude", help='JSON custom preludes: [{"pattern": "regex", "name": "id"}]'
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    if not os.path.exists(args.mapping):
        logger.error("Mapping file not found: %s", args.mapping)
        return 1

    with open(args.mapping, encoding="utf-8") as f:
        data = json.load(f)

    lines = data.get("lines", [])
    known_addrs = set()
    if args.binary and os.path.exists(args.binary):
        symbols = extract_symbols(args.binary)
        for sym in symbols:
            addr = sym.get("addr", "")
            if addr:
                known_addrs.add(addr if addr.startswith("0x") else f"0x{addr}")

    custom_preludes = None
    if args.prelude:
        try:
            prelude_data = json.loads(args.prelude)
            if isinstance(prelude_data, list):
                custom_preludes = [
                    (p["pattern"], p.get("name", "custom"))
                    for p in prelude_data
                    if isinstance(p, dict) and p.get("pattern")
                ]
        except json.JSONDecodeError:
            pass

    discovered = discover_functions(
        lines,
        known_addrs,
        custom_preludes=custom_preludes,
        binary_path=args.binary if args.binary else None,
    )
    payload: list[dict] | dict = discovered
    if args.expected:
        expected = _load_expected_addrs(args.expected)
        payload = {
            "functions": discovered,
            "metrics": evaluate_function_discovery(
                discovered,
                expected,
                known_addrs=known_addrs,
            ),
        }
    out = json.dumps(payload, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Discovered {len(discovered)} functions written to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
