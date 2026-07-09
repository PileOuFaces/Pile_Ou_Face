# SPDX-License-Identifier: AGPL-3.0-only
"""Deterministic enrichment for dynamic stack traces.

Builds a semantic stack model per step from enriched Unicorn snapshots and
reuses static metadata when available.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

try:
    from backends.static.binary.symbols import extract_symbols
except Exception:  # pragma: no cover - optional dependency path
    try:
        from backends.static.symbols import extract_symbols
    except Exception:
        extract_symbols = None

try:
    from backends.static.disasm.stack_frame import analyse_stack_frame
except Exception:  # pragma: no cover - optional dependency path
    try:
        from backends.static.stack_frame import analyse_stack_frame
    except Exception:
        analyse_stack_frame = None

try:
    from backends.static.disasm.calling_convention import analyze_calling_conventions
except Exception:  # pragma: no cover - optional dependency path
    try:
        from backends.static.calling_convention import analyze_calling_conventions
    except Exception:
        analyze_calling_conventions = None


HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F]+$")
SIGNED_HEX_RE = re.compile(r"^[+-]?0x[0-9a-fA-F]+$")
SIGNED_DEC_RE = re.compile(r"^[+-]?\d+$")


def _parse_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    text = str(value).strip()
    if not text:
        return None
    try:
        if SIGNED_HEX_RE.match(text):
            return int(text, 16)
        if HEX_RE.match(text):
            return int(text, 16)
        if SIGNED_DEC_RE.match(text):
            return int(text, 10)
    except ValueError:
        return None
    return None


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    if value < 0:
        return f"-0x{abs(value):x}"
    return f"0x{value:x}"


def _signed_hex(value: int | None) -> str | None:
    if value is None:
        return None
    if value == 0:
        return "+0x0"
    sign = "-" if value < 0 else "+"
    return f"{sign}0x{abs(value):x}"


def _parse_hex_bytes(raw: Any) -> list[int]:
    if raw is None:
        return []
    if isinstance(raw, list):
        out = []
        for value in raw:
            iv = _parse_int(value)
            if iv is None:
                continue
            out.append(iv & 0xFF)
        return out
    text = str(raw).strip()
    if not text:
        return []
    out = []
    for part in text.split():
        try:
            out.append(int(part, 16) & 0xFF)
        except ValueError:
            continue
    return out


def _bytes_to_hex(data: list[int]) -> str:
    return " ".join(f"{byte:02x}" for byte in data)


def _bytes_to_ascii(data: list[int]) -> str:
    return "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in data)


def _little_int(data: list[int]) -> int:
    value = 0
    for index, byte in enumerate(data):
        value |= (byte & 0xFF) << (index * 8)
    return value


def _is_ascii_candidate(data: list[int]) -> bool:
    if len(data) < 4:
        return False
    printable = sum(1 for byte in data if 32 <= byte <= 126 or byte == 0)
    return printable >= max(4, int(len(data) * 0.85))


def _safe_name(name: str, fallback: str) -> str:
    text = (name or "").strip()
    return text if text else fallback


def _normalize_reg_map(snapshot: dict, stage: str = "after") -> dict[str, int]:
    cpu = snapshot.get("cpu") if isinstance(snapshot.get("cpu"), dict) else {}
    stage_data = cpu.get(stage) if isinstance(cpu.get(stage), dict) else {}
    registers = (
        stage_data.get("registers")
        if isinstance(stage_data.get("registers"), dict)
        else {}
    )
    if registers:
        out = {}
        for key, value in registers.items():
            iv = _parse_int(value)
            if iv is not None:
                out[str(key).lower()] = iv
        return out

    legacy = (
        snapshot.get("registers") if isinstance(snapshot.get("registers"), list) else []
    )
    out = {}
    for entry in legacy:
        name = str(entry.get("name") or "").lower()
        if not name:
            continue
        iv = _parse_int(entry.get("value"))
        if iv is not None:
            out[name] = iv
    return out


def _memory_window(snapshot: dict) -> tuple[int | None, list[int]]:
    memory = snapshot.get("memory") if isinstance(snapshot.get("memory"), dict) else {}
    start = _parse_int(memory.get("window_start"))
    data = _parse_hex_bytes(memory.get("window_bytes"))
    if start is not None and data:
        return start, data

    stack_items = (
        snapshot.get("stack") if isinstance(snapshot.get("stack"), list) else []
    )
    if not stack_items:
        return None, []
    first_addr = _parse_int(stack_items[0].get("addr"))
    if first_addr is None:
        return None, []
    byte_map: dict[int, int] = {}
    for item in stack_items:
        addr = _parse_int(item.get("addr"))
        size = _parse_int(item.get("size")) or 0
        value = _parse_int(item.get("value"))
        if addr is None or size <= 0 or value is None:
            continue
        masked = value & ((1 << (size * 8)) - 1)
        for offset in range(size):
            byte_map[addr + offset] = masked & 0xFF
            masked >>= 8
    if not byte_map:
        return None, []
    start = min(byte_map)
    end = max(byte_map) + 1
    return start, [byte_map.get(address, 0) for address in range(start, end)]


def _window_byte_map(snapshot: dict) -> dict[int, int]:
    start, data = _memory_window(snapshot)
    if start is None or not data:
        return {}
    return {start + index: byte for index, byte in enumerate(data)}


def _access_list(snapshot: dict, key: str) -> list[dict]:
    memory = snapshot.get("memory") if isinstance(snapshot.get("memory"), dict) else {}
    items = memory.get(key)
    return items if isinstance(items, list) else []


def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
    return start_a < end_b and end_a > start_b


def _aligned_down(value: int, align: int) -> int:
    if align <= 1:
        return value
    return value & ~(align - 1)


def _aligned_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) & ~(align - 1)


# Functions known to write user-controlled data into a buffer destination.
_BUFFER_SINK_FUNCS: frozenset[str] = frozenset(
    {
        "strcpy",
        "strncpy",
        "gets",
        "fgets",
        "read",
        "scanf",
        "sscanf",
        "fscanf",
        "memcpy",
        "memset",
        "sprintf",
        "snprintf",
        "recv",
        "recvfrom",
    }
)


def _has_buffer_evidence(snapshot: dict, bp: int | None, meta: dict) -> bool:
    """Return True when there is strong evidence that a stack region is a writable buffer."""
    if meta.get("buffer_offset") is not None:
        return True
    effects = (
        snapshot.get("effects") if isinstance(snapshot.get("effects"), dict) else {}
    )
    if str(effects.get("external_symbol") or "").lower() in _BUFFER_SINK_FUNCS:
        return True
    if bp is None:
        return False
    for access in _access_list(snapshot, "writes"):
        addr = _parse_int(access.get("addr"))
        size = _parse_int(access.get("size")) or 0
        if addr is not None and addr < bp and size >= 16:
            return True
    return False


def _stack_evidence_summary(meta: dict) -> dict | None:
    summary = meta.get("_stack_evidence")
    if not isinstance(summary, dict):
        return None
    if summary.get("available") is False:
        return None
    if not isinstance(summary.get("buffers"), list):
        return None
    return summary


def _function_matches_evidence_buffer(function_info: dict | None, evidence_buffer: dict) -> bool:
    if not isinstance(evidence_buffer, dict):
        return False
    expected_name = str(evidence_buffer.get("function") or "").strip()
    expected_addr = _parse_int(evidence_buffer.get("function_addr"))
    if not function_info:
        return not expected_name and expected_addr is None
    function_name = str(function_info.get("name") or "").strip()
    function_addr = _parse_int(function_info.get("addr"))
    if expected_name and function_name and expected_name == function_name:
        return True
    if expected_addr is not None and function_addr is not None and expected_addr == function_addr:
        return True
    return not expected_name and expected_addr is None


def _evidence_buffers_for_function(meta: dict, function_info: dict | None) -> list[dict]:
    summary = _stack_evidence_summary(meta)
    if summary is None:
        return []
    buffers = [item for item in summary.get("buffers", []) if isinstance(item, dict)]
    matched = [item for item in buffers if _function_matches_evidence_buffer(function_info, item)]
    if matched:
        return matched
    if not function_info and len(buffers) == 1:
        return buffers
    return []


def _evidence_slots_for_function(meta: dict, function_info: dict | None) -> list[dict]:
    """All Evidence-scored slots for a function: probable_local, stack_argument,
    register_argument, stack_slot, and buffer. Superset of `_evidence_buffers_for_function`,
    used to type non-buffer slots (including rejected buffer candidates)."""
    summary = _stack_evidence_summary(meta)
    if summary is None:
        return []
    slots = [item for item in summary.get("slots", []) if isinstance(item, dict)]
    matched = [item for item in slots if _function_matches_evidence_buffer(function_info, item)]
    if matched:
        return matched
    if not function_info and len(slots) == 1:
        return slots
    return []


def _is_prologue_push_bp(instr_text: str) -> bool:
    """True when the instruction is `push rbp` / `push ebp`."""
    parts = instr_text.lower().split(None, 1)
    if not parts or parts[0] != "push":
        return False
    operand = parts[1].strip() if len(parts) > 1 else ""
    return operand in ("rbp", "ebp")


def _is_prologue_mov_bp_sp(instr_text: str) -> bool:
    """True when the instruction is `mov rbp, rsp` / `mov ebp, esp`."""
    parts = instr_text.lower().split(None, 1)
    if not parts or parts[0] != "mov":
        return False
    operand = parts[1].strip() if len(parts) > 1 else ""
    return operand in ("rbp, rsp", "ebp, esp")


def _is_stack_alloc_instruction(instr_text: str) -> bool:
    """True when the instruction reserves stack space for locals/buffers
    (`sub rsp, N` / `sub esp, N`), regardless of the immediate value."""
    parts = instr_text.lower().split(None, 1)
    if not parts or parts[0] != "sub":
        return False
    operand = parts[1].strip() if len(parts) > 1 else ""
    register = operand.split(",", 1)[0].strip()
    return register in ("rsp", "esp")


def _instruction_text(snapshot: dict) -> str:
    if isinstance(snapshot.get("instruction"), dict):
        return str(snapshot["instruction"].get("text") or "").strip()
    return str(snapshot.get("instr") or "").strip()


def _function_cache_key(function_info: dict | None, snapshot: dict) -> str | None:
    addr = (
        _parse_int(function_info.get("addr"))
        if isinstance(function_info, dict)
        else None
    )
    if addr is not None:
        return f"addr:{addr:x}"
    name = ""
    if isinstance(function_info, dict):
        name = str(function_info.get("name") or "").strip()
    if not name:
        name = str(snapshot.get("func") or "").strip()
    return f"name:{name}" if name else None


def _is_plausible_frame_bp(
    bp: int | None,
    snapshot: dict,
    meta: dict,
    word_size: int,
) -> bool:
    if bp is None or bp < 0:
        return False
    if word_size > 1 and bp % word_size != 0:
        return False

    stack_base = _parse_int(meta.get("stack_base"))
    stack_size = _parse_int(meta.get("stack_size")) or 0
    if stack_base is not None and stack_size > 0:
        stack_end = stack_base + stack_size
        if stack_base <= bp < stack_end:
            return True

    window_start, window_data = _memory_window(snapshot)
    if window_start is None or not window_data:
        return False
    window_end = window_start + len(window_data)
    margin = max(0x100, word_size * 8)
    return (window_start - margin) <= bp < (window_end + margin)


def _select_frame_base_pointer(
    snapshot: dict,
    meta: dict,
    arch_bits: int,
    word_size: int,
    stable_bp: int | None,
) -> int | None:
    regs_after = _normalize_reg_map(snapshot, "after")
    regs_before = _normalize_reg_map(snapshot, "before")
    aliases = _register_aliases(regs_after or regs_before, arch_bits)
    bp_name = aliases.get("bp")
    bp_after = regs_after.get(bp_name) if bp_name else None
    bp_before = regs_before.get(bp_name) if bp_name else None
    mnemonic = _instruction_text(snapshot).split(" ", 1)[0].strip().lower()

    candidates = (
        [bp_before, bp_after, stable_bp]
        if mnemonic == "leave"
        else [bp_after, bp_before, stable_bp]
    )
    for candidate in candidates:
        if _is_plausible_frame_bp(candidate, snapshot, meta, word_size):
            return candidate
    for candidate in candidates:
        if candidate is not None:
            return candidate
    return None


def _instruction_mnemonic(snapshot: dict) -> str:
    if isinstance(snapshot.get("instruction"), dict):
        return str(snapshot["instruction"].get("mnemonic") or "").strip().lower()
    text = _instruction_text(snapshot)
    return text.split(" ", 1)[0].lower() if text else ""


def _access_summary(accesses: list[dict]) -> str | None:
    if not accesses:
        return None
    starts = [_parse_int(access.get("addr")) for access in accesses]
    sizes = [_parse_int(access.get("size")) or 0 for access in accesses]
    valid = [
        (start, size)
        for start, size in zip(starts, sizes, strict=False)
        if start is not None
    ]
    if not valid:
        return None
    first = min(start for start, _ in valid)
    last = max(start + max(1, size) for start, size in valid)
    total = sum(max(1, size) for _, size in valid)
    return f"{len(valid)} access / {total} byte(s) [{_hex(first)}..{_hex(last - 1)}]"


class StaticTraceResolver:
    """Lazy view over static metadata reused by the dynamic model."""

    def __init__(self, binary_path: str, meta: dict, disasm_lines: list[dict]) -> None:
        self.binary_path = binary_path
        self.meta = meta
        self.disasm_lines = disasm_lines
        self._symbols: list[dict] | None = None
        self._function_ranges: list[tuple[int, int | None, dict]] | None = None
        self._stack_frames: dict[int, dict] = {}
        self._conventions: dict[int, dict] = {}
        self._annotation_names: dict[int, str] | None = None
        self._annotation_comments: dict[int, str] | None = None
        addresses = [_parse_int(line.get("addr")) for line in disasm_lines]
        valid = [addr for addr in addresses if addr is not None]
        self.code_min = min(valid) if valid else None
        self.code_max = max(valid) if valid else None
        self.stack_base = _parse_int(meta.get("stack_base"))
        stack_size = _parse_int(meta.get("stack_size")) or 0
        self.stack_end = (
            self.stack_base + stack_size
            if self.stack_base is not None and stack_size > 0
            else None
        )
        # For PIE binaries, snapshot RIP values include the load base but symbol
        # addresses from extract_symbols are ELF-relative. Subtract the base before
        # any range lookup so that a rebased address like 0x401d4d is compared as
        # 0x1d4d against the ELF-relative symbol table.
        self.load_base = _parse_int(meta.get("base")) or 0

    def _load_annotations(self) -> tuple[dict[int, str], dict[int, str]]:
        if self._annotation_names is not None and self._annotation_comments is not None:
            return self._annotation_names, self._annotation_comments

        names: dict[int, str] = {}
        comments: dict[int, str] = {}
        try:
            binary_abs = os.path.abspath(self.binary_path)
            stat = os.stat(binary_abs)
            digest = hashlib.sha256()
            digest.update(binary_abs.encode("utf-8", errors="ignore"))
            digest.update(str(stat.st_mtime_ns).encode("utf-8"))
            ann_path = (
                Path(os.getcwd())
                / ".pile-ou-face"
                / "annotations"
                / f"{digest.hexdigest()[:16]}.json"
            )
            if ann_path.exists():
                raw = json.loads(ann_path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    for addr_text, payload in raw.items():
                        addr = _parse_int(addr_text)
                        if addr is None or not isinstance(payload, dict):
                            continue
                        name = str(payload.get("name") or "").strip()
                        comment = str(payload.get("comment") or "").strip()
                        if name:
                            names[addr] = name
                        if comment:
                            comments[addr] = comment
        except Exception:
            pass

        self._annotation_names = names
        self._annotation_comments = comments
        return names, comments

    def _load_symbols(self) -> list[dict]:
        if self._symbols is not None:
            return self._symbols
        if extract_symbols is None:
            self._symbols = []
            return self._symbols
        try:
            raw = extract_symbols(self.binary_path, defined_only=True)
            self._symbols = raw if isinstance(raw, list) else []
        except Exception:
            self._symbols = []
        return self._symbols

    def _load_function_ranges(self) -> list[tuple[int, int | None, dict]]:
        if self._function_ranges is not None:
            return self._function_ranges
        functions = []
        for symbol in self._load_symbols():
            sym_type = str(symbol.get("type") or "")
            if sym_type.lower() != "t":
                continue
            addr = _parse_int(symbol.get("addr"))
            if addr is None:
                continue
            size = _parse_int(symbol.get("size"))
            functions.append((addr, size if size and size > 0 else None, symbol))
        functions.sort(key=lambda item: item[0])
        ranges: list[tuple[int, int | None, dict]] = []
        for index, (addr, size, symbol) in enumerate(functions):
            next_addr = functions[index + 1][0] if index + 1 < len(functions) else None
            end = addr + size if size is not None else next_addr
            if next_addr is not None:
                end = min(end, next_addr) if end is not None else next_addr
            ranges.append((addr, end, symbol))
        self._function_ranges = ranges
        return ranges

    def resolve_function(
        self, ip: int | None, fallback_name: str | None = None
    ) -> dict | None:
        if ip is None:
            return None
        # Normalize PIE-rebased runtime addresses to ELF-relative before lookup.
        # Symbol ranges come from extract_symbols which returns ELF-relative addresses.
        # Without this, a rebased address like 0x401d4d always falls past every known
        # symbol range, causing _fini (the last symbol, end=None) to match everything.
        normalized = (
            ip - self.load_base if self.load_base > 0 and ip >= self.load_base else ip
        )
        for start, end, symbol in self._load_function_ranges():
            if normalized < start:
                break
            if end is None or normalized < end:
                result = dict(symbol)
                result.setdefault("range_start", _hex(start))
                result.setdefault("range_end", _hex(end) if end is not None else None)
                return result
        if fallback_name:
            for symbol in self._load_symbols():
                if str(symbol.get("name") or "") == fallback_name:
                    return dict(symbol)
        return None

    def frame_for_function(self, func_addr: int | None) -> dict:
        if func_addr is None:
            return {}
        if func_addr in self._stack_frames:
            return self._stack_frames[func_addr]
        if analyse_stack_frame is None:
            self._stack_frames[func_addr] = {}
            return {}
        try:
            frame = analyse_stack_frame(self.binary_path, func_addr)
            self._stack_frames[func_addr] = frame if isinstance(frame, dict) else {}
        except Exception:
            self._stack_frames[func_addr] = {}
        return self._stack_frames[func_addr]

    def convention_for_function(self, func_addr: int | None) -> dict | None:
        if func_addr is None:
            return None
        if func_addr in self._conventions:
            return self._conventions[func_addr]
        if analyze_calling_conventions is None:
            self._conventions[func_addr] = {}
            return None
        try:
            payload = analyze_calling_conventions(self.binary_path, [func_addr])
            conventions = (
                payload.get("conventions") if isinstance(payload, dict) else {}
            )
            entry = (
                conventions.get(_hex(func_addr) or "")
                if isinstance(conventions, dict)
                else {}
            )
            self._conventions[func_addr] = entry if isinstance(entry, dict) else {}
        except Exception:
            self._conventions[func_addr] = {}
        return self._conventions[func_addr] or None

    def rename_for(self, addr: int | None) -> str | None:
        if addr is None:
            return None
        names, _ = self._load_annotations()
        return names.get(addr)

    def comment_for(self, addr: int | None) -> str | None:
        if addr is None:
            return None
        _, comments = self._load_annotations()
        return comments.get(addr)

    def pointer_kind(self, value: int | None) -> str | None:
        if value is None:
            return None
        if self.stack_base is not None and self.stack_end is not None:
            if self.stack_base <= value < self.stack_end:
                return "stack"
        if self.code_min is not None and self.code_max is not None:
            if self.code_min <= value <= self.code_max + 0x40:
                return "code"
        return None


def _register_aliases(regs: dict[str, int], arch_bits: int) -> dict[str, str | None]:
    if arch_bits == 32:
        return {"sp": "esp", "bp": "ebp", "ip": "eip", "fp": "ebp", "lr": None}
    sp = "rsp" if "rsp" in regs else "sp" if "sp" in regs else None
    bp = "rbp" if "rbp" in regs else "ebp" if "ebp" in regs else None
    ip = "rip" if "rip" in regs else "eip" if "eip" in regs else None
    return {"sp": sp, "bp": bp, "ip": ip, "fp": bp, "lr": None}


def _region_entry(
    *,
    start: int,
    end: int,
    role: str,
    label: str,
    source: str,
    offset: int | None = None,
    size: int | None = None,
    confidence: float = 0.9,
    size_exact: bool = True,
) -> dict:
    return {
        "start": start,
        "end": end,
        "role": role,
        "label": label,
        "source": source,
        "offset": offset,
        "size": size if size is not None else max(1, end - start),
        "confidence": confidence,
        "size_exact": size_exact,
    }


def _guess_buffer_region(frame: dict, bp: int | None, meta: dict) -> dict | None:
    if bp is None:
        return None
    buffer_offset = _parse_int(meta.get("buffer_offset"))
    buffer_size = _parse_int(meta.get("buffer_size")) or 0
    frame_vars = frame.get("vars", []) if isinstance(frame.get("vars"), list) else []
    if buffer_offset is not None:
        matched_entry = None
        for entry in frame_vars:
            offset = _parse_int(entry.get("offset"))
            size = _parse_int(entry.get("size")) or 0
            if offset == buffer_offset and size > 0:
                matched_entry = entry
                buffer_size = size
                break
        can_trust_trace_offset = matched_entry is not None or not frame_vars
        if (
            can_trust_trace_offset
            and buffer_size > 0
            and (buffer_offset + buffer_size) <= 0
        ):
            start = bp + buffer_offset
            label = f"local_buf_{buffer_size:x}h"
            if isinstance(matched_entry, dict):
                label = _safe_name(str(matched_entry.get("name") or ""), label)
            source = "trace"
            confidence = 0.98
            if isinstance(matched_entry, dict):
                source = str(matched_entry.get("source") or "static")
                confidence = 0.97 if matched_entry.get("source") == "dwarf" else 0.9
            return _region_entry(
                start=start,
                end=start + buffer_size,
                role="buffer",
                label=label,
                source=source,
                offset=buffer_offset,
                size=buffer_size,
                confidence=confidence,
                size_exact=True,
            )

    best = None
    for entry in frame_vars:
        offset = _parse_int(entry.get("offset"))
        size = _parse_int(entry.get("size")) or 0
        if offset is None or size < 16:
            continue
        candidate = (
            size,
            abs(offset),
            _region_entry(
                start=bp + offset,
                end=bp + offset + size,
                role="buffer",
                label=_safe_name(str(entry.get("name") or ""), f"local_buf_{size:x}h"),
                source="heuristic",
                offset=offset,
                size=size,
                confidence=0.7,
                size_exact=bool(entry.get("size_is_exact", True)),
            ),
        )
        if best is None or candidate > best:
            best = candidate
    return best[2] if best else None


_EVIDENCE_CONFIDENCE_VALUES: dict[str, float] = {
    "exact": 0.97,
    "high": 0.85,
    "medium": 0.7,
    "low": 0.5,
}


def _evidence_confidence_value(confidence) -> float:
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        return max(0.0, min(1.0, float(confidence)))
    return _EVIDENCE_CONFIDENCE_VALUES.get(str(confidence or "").lower(), 0.5)


# Evidence "kind" values that map onto an existing output role. Buffers are
# deliberately excluded: buffer regions are only ever created by
# `_evidence_buffer_regions` / `_guess_buffer_region`, never by this promotion.
_EVIDENCE_KIND_ROLE: dict[str, str] = {
    "probable_local": "local",
    "stack_argument": "argument",
}


def _evidence_typed_regions(
    bp: int | None,
    meta: dict,
    function_info: dict | None,
    existing_regions: list[dict],
) -> list[dict]:
    """Promote evidence-only local/argument slots that the static frame analysis
    missed (e.g. compiler-spilled or ASM-only stack slots) into real regions.

    A slot already covered by an existing region (static var/arg, buffer, or
    control) is left alone -- this only fills gaps, it never overrides or
    duplicates a region that's already there. Evidence classified as a buffer
    is skipped entirely: this function must never create a buffer role.
    """
    if bp is None:
        return []
    covered = [(region["start"], region["end"]) for region in existing_regions]
    added: list[dict] = []
    for item in _evidence_slots_for_function(meta, function_info):
        if str(item.get("classification") or "") == "buffer":
            continue
        role = _EVIDENCE_KIND_ROLE.get(str(item.get("kind") or ""))
        if role is None:
            continue
        if str(item.get("base") or "rbp").lower() != "rbp":
            continue
        offset = _parse_int(item.get("offset"))
        if offset is None:
            continue
        size = _parse_int(item.get("size"))
        size_exact = size is not None and size > 0
        if not size_exact:
            size = _parse_int(item.get("estimated_bound"))
        if size is None or size <= 0:
            continue
        start = bp + offset
        end = start + size
        if any(_overlaps(start, end, cstart, cend) for cstart, cend in covered):
            continue
        label = f"local_{abs(offset):x}h" if role == "local" else f"arg_{offset:x}"
        added.append(
            _region_entry(
                start=start,
                end=end,
                role=role,
                label=label,
                source="evidence",
                offset=offset,
                size=size,
                confidence=_evidence_confidence_value(item.get("confidence")),
                size_exact=size_exact,
            )
        )
        covered.append((start, end))
    return added


def _evidence_buffer_regions(bp: int | None, meta: dict, function_info: dict | None) -> list[dict]:
    if bp is None:
        return []
    regions = []
    for item in _evidence_buffers_for_function(meta, function_info):
        if str(item.get("base") or "rbp").lower() != "rbp":
            continue
        offset = _parse_int(item.get("offset"))
        if offset is None:
            continue
        size = _parse_int(item.get("size"))
        size_exact = True
        confidence = 0.9
        if size is None or size <= 0:
            # Buffer proven (call-argument sink / payload write), but no
            # exact size (source/DWARF) pins its length. estimated_bound is
            # an UPPER bound (distance to the next slot / saved rbp) -- the
            # real object may be much smaller -- so it is used only to give
            # the region *some* drawable extent, never presented as a size.
            size = _parse_int(item.get("estimated_bound"))
            if size is None or size <= 0:
                continue
            size_exact = False
            confidence = 0.5
        start = bp + offset
        label = f"local_buf_{size:x}h" if size_exact else "local_buf_unknown"
        regions.append(
            _region_entry(
                start=start,
                end=start + size,
                role="buffer",
                label=label,
                source="evidence",
                offset=offset,
                size=size,
                confidence=confidence,
                size_exact=size_exact,
            )
        )
    return regions


def _static_regions(
    frame: dict,
    bp: int | None,
    word_size: int,
    meta: dict,
    function_info: dict | None = None,
    frame_allocated: bool = True,
) -> list[dict]:
    if bp is None:
        return []
    regions: list[dict] = []
    # Locals/args/buffer only exist once this invocation's own frame has
    # actually reserved stack space for them (`sub rsp, N`). Before that,
    # `bp` may be set up (or even still be the caller's) but nothing below
    # it belongs to this call yet -- saved_bp/return_address stay
    # unconditional below since they don't depend on allocation.
    if frame_allocated:
        for entry in frame.get("vars", []) if isinstance(frame.get("vars"), list) else []:
            offset = _parse_int(entry.get("offset"))
            size = _parse_int(entry.get("size")) or 1
            if offset is None:
                continue
            role = "local"
            label = _safe_name(str(entry.get("name") or ""), f"local_{abs(offset):x}h")
            regions.append(
                _region_entry(
                    start=bp + offset,
                    end=bp + offset + max(1, size),
                    role=role,
                    label=label,
                    source=str(entry.get("source") or "static"),
                    offset=offset,
                    size=size,
                    confidence=0.92 if entry.get("source") == "dwarf" else 0.85,
                    size_exact=bool(entry.get("size_is_exact", True)),
                )
            )
        for entry in frame.get("args", []) if isinstance(frame.get("args"), list) else []:
            offset = _parse_int(entry.get("offset"))
            size = _parse_int(entry.get("size")) or word_size
            if offset is None:
                continue
            label = _safe_name(str(entry.get("name") or ""), f"arg_{offset:x}")
            regions.append(
                _region_entry(
                    start=bp + offset,
                    end=bp + offset + max(1, size),
                    role="argument",
                    label=label,
                    source=str(entry.get("source") or "static"),
                    offset=offset,
                    size=size,
                    confidence=0.82,
                    size_exact=bool(entry.get("size_is_exact", True)),
                )
            )

    regions.append(
        _region_entry(
            start=bp,
            end=bp + word_size,
            role="saved_bp",
            label="saved_rbp" if word_size == 8 else "saved_ebp",
            source="control",
            offset=0,
            size=word_size,
            confidence=0.99,
        )
    )
    regions.append(
        _region_entry(
            start=bp + word_size,
            end=bp + (2 * word_size),
            role="return_address",
            label="ret_addr",
            source="control",
            offset=word_size,
            size=word_size,
            confidence=0.99,
        )
    )

    if frame_allocated:
        evidence_regions = _evidence_buffer_regions(bp, meta, function_info)
        if evidence_regions:
            regions.extend(evidence_regions)
        elif _stack_evidence_summary(meta) is None:
            buffer_region = _guess_buffer_region(frame, bp, meta)
            if buffer_region is not None:
                regions.append(buffer_region)

        regions.extend(_evidence_typed_regions(bp, meta, function_info, regions))
    return regions


def _runtime_buffer_region(
    snapshot: dict,
    bp: int | None,
    word_size: int,
    existing_buffer: dict | None,
    frame_allocated: bool = True,
) -> dict | None:
    if bp is None or not frame_allocated:
        return existing_buffer
    writes = _access_list(snapshot, "writes")
    best = None
    for access in writes:
        addr = _parse_int(access.get("addr"))
        size = _parse_int(access.get("size")) or 0
        if addr is None or size < max(16, word_size * 2):
            continue
        if addr >= bp:
            continue
        distance_to_bp = bp - addr
        buffer_size = min(distance_to_bp, size) if distance_to_bp > 0 else size
        if buffer_size < max(16, word_size * 2):
            continue
        candidate = (
            buffer_size,
            _region_entry(
                start=addr,
                end=addr + buffer_size,
                role="buffer",
                label=f"local_buf_{buffer_size:x}h",
                source="runtime",
                offset=addr - bp,
                size=buffer_size,
                confidence=0.76,
                size_exact=False,
            ),
        )
        if best is None or candidate[0] > best[0]:
            best = candidate

    candidate_region = best[1] if best else None
    if candidate_region is None:
        return existing_buffer
    if existing_buffer is None:
        return candidate_region
    existing_size = _parse_int(existing_buffer.get("size")) or 0
    if existing_size < max(16, word_size * 2):
        return candidate_region
    return existing_buffer


def _window_bounds(
    snapshot: dict,
    prev_snapshot: dict | None,
    frame_regions: list[dict],
    regs_after: dict[str, int],
    regs_before: dict[str, int],
    word_size: int,
    meta: dict,
) -> tuple[int | None, int | None]:
    start, data = _memory_window(snapshot)
    if start is not None and data:
        return start, start + len(data)

    points = []
    for reg_name in ("rsp", "rbp", "esp", "ebp"):
        if reg_name in regs_after:
            points.append(regs_after[reg_name])
        if reg_name in regs_before:
            points.append(regs_before[reg_name])
    for region in frame_regions:
        points.extend([region["start"], region["end"]])
    for key in ("writes", "reads"):
        for access in _access_list(snapshot, key):
            addr = _parse_int(access.get("addr"))
            size = _parse_int(access.get("size")) or 1
            if addr is None:
                continue
            points.extend([addr, addr + size])
    if not points:
        prev_start, prev_data = _memory_window(prev_snapshot or {})
        if prev_start is None or not prev_data:
            return None, None
        return prev_start, prev_start + len(prev_data)
    margin = max(32, word_size * 4)
    start = _aligned_down(min(points) - margin, word_size)
    end = _aligned_up(max(points) + margin, word_size)
    stack_base = _parse_int(meta.get("stack_base"))
    stack_size = _parse_int(meta.get("stack_size")) or 0
    stack_end = (
        stack_base + stack_size if stack_base is not None and stack_size > 0 else None
    )
    if stack_base is not None:
        start = max(stack_base, start)
    if stack_end is not None:
        end = min(stack_end, end)
    if end <= start:
        return None, None
    return start, end


def _value_display(data: list[int], pointer_kind: str | None) -> str:
    if _is_ascii_candidate(data):
        text = _bytes_to_ascii(data).rstrip(".")
        return f'"{text[:24]}"'
    if pointer_kind is not None and len(data) in (4, 8):
        return _hex(_little_int(data)) or "0x0"
    if len(data) <= 8:
        return _hex(_little_int(data)) or "0x0"
    return _bytes_to_hex(data)


def _slot_flags(
    role: str,
    start: int,
    end: int,
    data: list[int],
    prev_map: dict[int, int],
    resolver: StaticTraceResolver,
    writes: list[dict],
    reads: list[dict],
    buffer_region: dict | None,
) -> tuple[list[str], bool, bool, bool, str | None]:
    recent_write = any(
        (addr := _parse_int(access.get("addr"))) is not None
        and _overlaps(
            start, end, addr, addr + max(1, _parse_int(access.get("size")) or 1)
        )
        for access in writes
    )
    recent_read = any(
        (addr := _parse_int(access.get("addr"))) is not None
        and _overlaps(
            start, end, addr, addr + max(1, _parse_int(access.get("size")) or 1)
        )
        for access in reads
    )
    changed = bool(prev_map) and any(
        prev_map.get(address) != byte
        for address, byte in zip(range(start, end), data, strict=False)
    )
    flags: list[str] = []
    if recent_write:
        flags.append("recent_write")
    if recent_read:
        flags.append("recent_read")
    if changed:
        flags.append("changed")
    if role == "unknown" and all(byte == 0 for byte in data):
        flags.append("uninitialized")

    pointer_kind = None
    if len(data) in (4, 8):
        pointer_kind = resolver.pointer_kind(_little_int(data))
        if pointer_kind is not None:
            flags.append("pointer_probable")
    if _is_ascii_candidate(data):
        flags.append("ascii_probable")
    elif len(data) <= 8 and any(byte != 0 for byte in data):
        flags.append("scalar_probable")

    corrupted = False
    if role == "saved_bp":
        pointer = _little_int(data) if len(data) in (4, 8) else None
        # Only flag corruption when the slot was actually touched — avoids false
        # positives before the frame prologue is complete or when the initial
        # saved-RBP value happens to be out of the stack window.
        corrupted = (recent_write or changed) and resolver.pointer_kind(
            pointer
        ) != "stack"
    elif role == "return_address":
        pointer = _little_int(data) if len(data) in (4, 8) else None
        corrupted = (recent_write or changed) and resolver.pointer_kind(
            pointer
        ) != "code"
    elif buffer_region is not None and start >= buffer_region["end"]:
        corrupted = recent_write or changed
    if corrupted:
        flags.append("corrupted")

    return flags, recent_write, recent_read, corrupted, pointer_kind


def _slot_role_label(
    start: int,
    end: int,
    regions: list[dict],
    bp: int | None,
    buffer_region: dict | None,
    frame_allocated: bool = True,
) -> tuple[str | None, str, int | None, float, str, bool]:
    matches = [
        region
        for region in regions
        if _overlaps(start, end, region["start"], region["end"])
    ]
    if matches:
        matches.sort(
            key=lambda region: (
                {
                    "buffer": 0,
                    "saved_bp": 1,
                    "return_address": 2,
                    "local": 3,
                    "argument": 4,
                }.get(region["role"], 9),
                region["start"],
            )
        )
        best = matches[0]
        return (
            best["role"],
            best["label"],
            best.get("offset"),
            float(best.get("confidence") or 0.75),
            best.get("source") or "static",
            bool(best.get("size_exact", True)),
        )

    # No known region covers this segment. Before the frame is fully
    # allocated (`sub rsp, N` observed), this fallback is a pure guess about
    # raw memory content -- `bp` may not even be this invocation's real
    # frame base yet, so a "gap" found here is frequently just unrelated
    # caller-frame content. A None role tells the caller to skip the slot
    # entirely rather than manufacture unknown/argument/padding noise this
    # early.
    if not frame_allocated:
        return None, "", None, 0.0, "unknown", False

    # These are all heuristic guesses about a memory range with no static/
    # evidence backing -- never claim size_exact here (reserved for source/
    # DWARF/config-declared sizes).
    if bp is not None and start < bp:
        if buffer_region is not None and start >= buffer_region["end"]:
            return "padding", f"padding_{bp - start:x}h", start - bp, 0.55, "heuristic", False
        return "unknown", f"stack_{bp - start:x}h", start - bp, 0.4, "heuristic", False
    if bp is not None and start >= bp + (
        8 if any(region["size"] == 8 for region in regions) else 4
    ):
        return "argument", f"arg_{start - bp:x}", start - bp, 0.45, "heuristic", False
    return (
        "unknown",
        f"slot_{start:x}",
        start - bp if bp is not None else None,
        0.25,
        "memory",
        False,
    )


def _assign_display_labels(slots: list[dict]) -> None:
    """Add a displayLabel field with simplified user-facing names.

    Internal label is preserved unchanged; displayLabel carries the
    pedagogical form: buffer_0, local_0, arg_0, unknown_0.
    Counters are assigned in address order (low → high).
    """
    counters: dict[str, int] = {}
    _role_key = {
        "buffer": "buffer",
        "local": "local",
        "argument": "arg",
        "unknown": "unknown",
        "padding": "unknown",
    }
    for slot in slots:
        role = slot.get("role", "unknown")
        if role in ("saved_bp", "return_address"):
            slot["displayLabel"] = slot.get("label", role)
            continue
        key = _role_key.get(role)
        if key is None:
            slot["displayLabel"] = slot.get("label", role)
            continue
        idx = counters.get(key, 0)
        slot["displayLabel"] = f"{key}_{idx}"
        counters[key] = idx + 1


def _build_slots(
    snapshot: dict,
    prev_snapshot: dict | None,
    meta: dict,
    resolver: StaticTraceResolver,
    function_info: dict | None,
    frame_bp: int | None = None,
    frame_allocated: bool = True,
) -> dict:
    arch_bits = _parse_int(meta.get("arch_bits")) or 64
    word_size = _parse_int(meta.get("word_size")) or (8 if arch_bits == 64 else 4)
    regs_after = _normalize_reg_map(snapshot, "after")
    regs_before = _normalize_reg_map(snapshot, "before")
    aliases = _register_aliases(regs_after or regs_before, arch_bits)
    sp_name = aliases.get("sp")
    bp_name = aliases.get("bp")
    sp = regs_after.get(sp_name) if sp_name else None
    bp_actual = regs_after.get(bp_name) if bp_name else None
    bp = frame_bp if frame_bp is not None else bp_actual
    func_addr = _parse_int(function_info.get("addr")) if function_info else None
    frame = resolver.frame_for_function(func_addr)
    convention = resolver.convention_for_function(func_addr) or {}
    regions = _static_regions(frame, bp, word_size, meta, function_info=function_info, frame_allocated=frame_allocated)

    # Validate heuristic buffer: only keep "buffer" role when there is real evidence.
    # Without evidence, reclassify as local to avoid misleading the user.
    heuristic_buf = next(
        (
            r
            for r in regions
            if r["role"] == "buffer" and r.get("source") == "heuristic"
        ),
        None,
    )
    if heuristic_buf is not None and not _has_buffer_evidence(snapshot, bp, meta):
        heuristic_buf["role"] = "local"

    buffer_region = next(
        (region for region in regions if region["role"] == "buffer"), None
    )
    runtime_buffer = _runtime_buffer_region(
        snapshot, bp, word_size, buffer_region, frame_allocated=frame_allocated
    )
    if runtime_buffer is not None and runtime_buffer is not buffer_region:
        regions = [region for region in regions if region["role"] != "buffer"]
        regions.append(runtime_buffer)
        buffer_region = runtime_buffer

    window_start, window_end = _window_bounds(
        snapshot,
        prev_snapshot,
        regions,
        regs_after,
        regs_before,
        word_size,
        meta,
    )
    if window_start is None or window_end is None:
        return {
            "function": function_info or {},
            "frame": {
                "slots": [],
                "viewport": None,
                "savedBpAddr": _hex(bp),
                "retAddrAddr": _hex(bp + word_size) if bp is not None else None,
                "registerArguments": [
                    entry
                    for entry in frame.get("args", [])
                    if isinstance(entry, dict) and entry.get("offset") is None
                ],
            },
            "buffer": None,
            "control": {
                "savedBpAddr": _hex(bp),
                "retAddrAddr": _hex(bp + word_size) if bp is not None else None,
            },
            "highlights": {"stack": {"rolesByAddr": {}}},
        }

    curr_map = _window_byte_map(snapshot)
    prev_map = _window_byte_map(prev_snapshot or {})
    [curr_map.get(address, 0) for address in range(window_start, window_end)]
    writes = _access_list(snapshot, "writes")
    reads = _access_list(snapshot, "reads")

    boundaries = {window_start, window_end}
    if sp is not None:
        boundaries.add(sp)
        boundaries.add(sp + word_size)
    if bp is not None:
        boundaries.add(bp)
        boundaries.add(bp + word_size)
        boundaries.add(bp + (2 * word_size))
    for region in regions:
        boundaries.add(region["start"])
        boundaries.add(region["end"])
    for access in writes + reads:
        addr = _parse_int(access.get("addr"))
        size = _parse_int(access.get("size")) or 1
        if addr is None:
            continue
        boundaries.add(addr)
        boundaries.add(addr + size)

    ordered = sorted(
        boundary for boundary in boundaries if window_start <= boundary <= window_end
    )
    slots = []
    roles_by_addr: dict[str, str] = {}
    for left, right in zip(ordered, ordered[1:], strict=False):
        if right <= left:
            continue
        data = [curr_map.get(address, 0) for address in range(left, right)]
        if not data:
            continue
        role, label, bp_offset, confidence, source, size_exact = _slot_role_label(
            left, right, regions, bp, buffer_region, frame_allocated=frame_allocated
        )
        # No known region and the frame isn't allocated yet -- _slot_role_label
        # refused to guess (see its own docstring); nothing to show here, not
        # even as unknown/padding noise.
        if role is None:
            continue
        # Skip unknown/padding gaps that have no writes and no changes from the
        # previous step — they are just alignment filler with no signal value.
        if role in ("unknown", "padding"):
            has_writes_here = any(
                (wa := _parse_int(w.get("addr"))) is not None
                and _overlaps(
                    left, right, wa, wa + max(1, _parse_int(w.get("size")) or 1)
                )
                for w in writes
            )
            has_changes_here = bool(prev_map) and any(
                prev_map.get(addr) != curr_map.get(addr, 0)
                for addr in range(left, right)
            )
            if not has_writes_here and not has_changes_here:
                continue
        flags, recent_write, recent_read, corrupted, pointer_kind = _slot_flags(
            role,
            left,
            right,
            data,
            prev_map,
            resolver,
            writes,
            reads,
            buffer_region,
        )
        value_int = _little_int(data) if len(data) <= 8 else None
        comment = resolver.comment_for(left)
        slot = {
            "key": f"0x{left:x}:0x{right:x}",
            "start": _hex(left),
            "end": _hex(right),
            "size": right - left,
            "size_exact": size_exact,
            "role": role,
            "label": resolver.rename_for(left) or label,
            "source": source,
            "confidence": round(confidence, 3),
            "offsetFromBp": bp_offset,
            "offsetFromBpHex": _signed_hex(bp_offset),
            "offsetFromSp": (left - sp) if sp is not None else None,
            "offsetFromSpHex": _signed_hex((left - sp) if sp is not None else None),
            "bytesHex": _bytes_to_hex(data),
            "ascii": _bytes_to_ascii(data),
            "valueHex": _hex(value_int) if value_int is not None else None,
            "valueDisplay": _value_display(data, pointer_kind),
            "flags": flags,
            "recentWrite": recent_write,
            "recentRead": recent_read,
            "changed": "changed" in flags,
            "corrupted": corrupted,
            "pointerKind": pointer_kind,
            "comment": comment,
            "activePointers": [
                pointer_name
                for pointer_name, pointer_addr in (("sp", sp), ("bp", bp_actual))
                if pointer_addr is not None and left <= pointer_addr < right
            ],
        }
        slots.append(slot)
        roles_by_addr[_hex(left) or ""] = role

    _assign_display_labels(slots)

    viewport_points = []
    for point in (sp, bp, bp + word_size if bp is not None else None):
        if point is not None and window_start <= point < window_end:
            viewport_points.append(point)
    for region in regions:
        if region["role"] in {"buffer", "saved_bp", "return_address"}:
            viewport_points.extend([region["start"], region["end"]])
    for access in writes:
        addr = _parse_int(access.get("addr"))
        if addr is None:
            continue
        viewport_points.append(addr)
        viewport_points.append(addr + max(1, _parse_int(access.get("size")) or 1))
    if not viewport_points:
        viewport_points = [window_start, window_end]

    viewport_margin = max(24, word_size * 3)
    viewport_start = max(window_start, min(viewport_points) - viewport_margin)
    viewport_end = min(window_end, max(viewport_points) + viewport_margin)

    return {
        "function": {
            **(function_info or {}),
            "convention": convention.get("convention"),
            "conventionConfidence": convention.get("confidence"),
        },
        "frame": {
            "slots": slots,
            "viewport": {"start": _hex(viewport_start), "end": _hex(viewport_end)},
            "savedBpAddr": _hex(bp),
            "retAddrAddr": _hex(bp + word_size) if bp is not None else None,
            "basePointer": _hex(bp),
            "registerBasePointer": _hex(bp_actual),
            "stackPointer": _hex(sp),
            "frameSize": _parse_int(frame.get("frame_size")) or 0,
            "registerArguments": [
                entry
                for entry in frame.get("args", [])
                if isinstance(entry, dict) and entry.get("offset") is None
            ],
        },
        "buffer": {
            "name": buffer_region["label"],
            "start": _hex(buffer_region["start"]),
            "end": _hex(buffer_region["end"]),
            "size": buffer_region["size"],
            "size_exact": bool(buffer_region.get("size_exact", True)),
        }
        if buffer_region is not None
        else None,
        "control": {
            "savedBpAddr": _hex(bp),
            "retAddrAddr": _hex(bp + word_size) if bp is not None else None,
            "savedBpValue": next(
                (slot["valueHex"] for slot in slots if slot["role"] == "saved_bp"), None
            ),
            "retValue": next(
                (
                    slot["valueHex"]
                    for slot in slots
                    if slot["role"] == "return_address"
                ),
                None,
            ),
        },
        "delta": {
            "writes": writes,
            "reads": reads,
            "changedSlots": [slot["key"] for slot in slots if slot["changed"]],
        },
        "highlights": {"stack": {"rolesByAddr": roles_by_addr}},
    }


def _overflow_summary(analysis: dict) -> dict | None:
    frame = analysis.get("frame") if isinstance(analysis.get("frame"), dict) else {}
    slots = frame.get("slots") if isinstance(frame.get("slots"), list) else []
    buffer = (
        analysis.get("buffer") if isinstance(analysis.get("buffer"), dict) else None
    )
    control = (
        analysis.get("control") if isinstance(analysis.get("control"), dict) else {}
    )
    delta = analysis.get("delta") if isinstance(analysis.get("delta"), dict) else {}
    if not buffer:
        return None

    buffer_end = _parse_int(buffer.get("end"))
    buffer_start = _parse_int(buffer.get("start"))
    saved_bp = _parse_int(control.get("savedBpAddr"))
    ret_addr = _parse_int(control.get("retAddrAddr"))
    if buffer_end is None:
        return None

    writes = delta.get("writes") if isinstance(delta.get("writes"), list) else []
    has_runtime_writes = bool(writes)
    buffer_touched = any(
        slot.get("role") == "buffer"
        and (slot.get("recentWrite") or slot.get("changed"))
        for slot in slots
    )
    crossing_write = False
    if buffer_start is not None:
        for access in writes:
            addr = _parse_int(access.get("addr"))
            size = _parse_int(access.get("size")) or 1
            if addr is None:
                continue
            end = addr + max(1, size)
            if addr < buffer_end and end > buffer_end and end > buffer_start:
                crossing_write = True
                break

    touched = []
    frontier = buffer_end
    for slot in slots:
        start = _parse_int(slot.get("start"))
        end = _parse_int(slot.get("end"))
        if start is None or end is None or end <= buffer_end:
            continue
        if slot.get("recentWrite") or (has_runtime_writes and slot.get("changed")):
            touched.append(slot)
            frontier = max(frontier, end)

    if not touched:
        control_corruption = [
            slot
            for slot in slots
            if (
                slot.get("role") in {"saved_bp", "return_address"}
                and (
                    slot.get("recentWrite") or (crossing_write and slot.get("changed"))
                )
            )
        ]
        if control_corruption and crossing_write:
            touched = control_corruption
            frontier = max(
                _parse_int(slot.get("end")) or buffer_end for slot in touched
            )

    if not touched or not (buffer_touched or crossing_write):
        return {
            "active": False,
            "bufferName": buffer.get("name"),
            "distanceToSavedBp": saved_bp - buffer_end
            if saved_bp is not None
            else None,
            "distanceToRet": ret_addr - buffer_end if ret_addr is not None else None,
            "reached": [],
            "frontier": _hex(buffer_end),
            "progressBytes": 0,
            "overwrittenSlots": [],
            "controlRisk": None,
        }

    reached = []
    control_risk = None
    if saved_bp is not None and frontier > saved_bp:
        reached.append("saved_bp")
        control_risk = "saved_bp"
    if ret_addr is not None and frontier > ret_addr:
        reached.append("return_address")
        control_risk = "return_address"

    return {
        "active": True,
        "bufferName": buffer.get("name"),
        "distanceToSavedBp": saved_bp - buffer_end if saved_bp is not None else None,
        "distanceToRet": ret_addr - buffer_end if ret_addr is not None else None,
        "reached": reached,
        "frontier": _hex(frontier),
        "progressBytes": max(0, frontier - buffer_end),
        "overwrittenSlots": [slot.get("label") for slot in touched],
        "controlRisk": control_risk,
    }


def _build_explanation(snapshot: dict, analysis: dict) -> list[str]:
    instruction = (
        snapshot.get("instruction")
        if isinstance(snapshot.get("instruction"), dict)
        else {}
    )
    effects = (
        snapshot.get("effects") if isinstance(snapshot.get("effects"), dict) else {}
    )
    cpu = snapshot.get("cpu") if isinstance(snapshot.get("cpu"), dict) else {}
    aliases = cpu.get("aliases") if isinstance(cpu.get("aliases"), dict) else {}
    sp_name = aliases.get("sp") or "sp"
    bullets = []

    text = str(
        instruction.get("text") or snapshot.get("instr") or "(instruction inconnue)"
    )
    bullets.append(f"Instruction: {text}")

    effect_kind = str(effects.get("kind") or "instruction")
    sp_delta = _parse_int(effects.get("sp_delta"))
    frame_delta = _parse_int(effects.get("frame_delta"))
    branch_taken = effects.get("branch_taken")
    external = effects.get("external_simulated")
    external_symbol = effects.get("external_symbol")

    effect_bits = [effect_kind.replace("_", " ")]
    if sp_delta:
        effect_bits.append(f"{sp_name.upper()} {_signed_hex(sp_delta)}")
    if frame_delta:
        effect_bits.append(f"frame {_signed_hex(frame_delta)}")
    if branch_taken is True:
        effect_bits.append("branche prise")
    elif branch_taken is False:
        effect_bits.append("branche non prise")
    if external:
        effect_bits.append(f"call simulé: {external_symbol or 'externe'}")
    bullets.append("Effet: " + " • ".join(bit for bit in effect_bits if bit))

    writes = _access_summary(analysis.get("delta", {}).get("writes", []))
    if writes:
        bullets.append(f"Écritures stack: {writes}")
    reads = _access_summary(analysis.get("delta", {}).get("reads", []))
    if reads:
        bullets.append(f"Lectures stack: {reads}")

    changed_slots = analysis.get("delta", {}).get("changedSlots", [])
    if changed_slots:
        bullets.append(f"Slots modifiés: {len(changed_slots)}")

    overflow = (
        analysis.get("overflow") if isinstance(analysis.get("overflow"), dict) else None
    )
    if overflow and overflow.get("active"):
        reached = ", ".join(overflow.get("reached") or []) or "données adjacentes"
        distance_saved = overflow.get("distanceToSavedBp")
        distance_ret = overflow.get("distanceToRet")
        distance_bits = []
        if distance_saved is not None:
            distance_bits.append(f"saved_bp à {distance_saved} byte(s)")
        if distance_ret is not None:
            distance_bits.append(f"ret à {distance_ret} byte(s)")
        bullets.append(
            f"Overflow: {overflow.get('bufferName') or 'buffer'} déborde vers {reached}"
            + (f" ({', '.join(distance_bits)})" if distance_bits else "")
        )

    control = (
        analysis.get("control") if isinstance(analysis.get("control"), dict) else {}
    )
    if control.get("savedBpValue"):
        bullets.append(
            f"Contrôle: saved BP={control.get('savedBpValue')} • RET={control.get('retValue') or 'n/a'}"
        )
    return bullets


def _normalize_legacy_analysis(analysis: dict) -> dict:
    frame = analysis.get("frame") if isinstance(analysis.get("frame"), dict) else {}
    slots = frame.get("slots") if isinstance(frame.get("slots"), list) else []
    return {
        **analysis,
        "slots": slots,
    }


def build_dynamic_analysis(
    snapshots: list[dict],
    meta: dict,
    binary_path: str | None,
    disasm_lines: list[dict] | None = None,
) -> dict[str, dict]:
    """Build per-step deterministic analysis for the dynamic visualizer."""
    if not binary_path or not snapshots:
        return {}

    resolver = StaticTraceResolver(binary_path, meta, disasm_lines or [])
    analysis_by_step: dict[str, dict] = {}
    stable_frame_bp_by_function: dict[str, int] = {}
    # Frame-readiness state machine, per function invocation (function_key):
    # frame_pointer_ready = mov rbp,rsp has executed (bp is this call's own).
    # frame_allocated = frame_pointer_ready AND sub rsp,N has executed (locals/
    # buffers actually reserved). Locals/buffers must wait for the latter;
    # saved_bp/return_address never depend on either.
    frame_pointer_ready_by_function: dict[str, bool] = {}
    frame_allocated_by_function: dict[str, bool] = {}

    for index, snapshot in enumerate(snapshots):
        prev_snapshot = snapshots[index - 1] if index > 0 else None
        regs_after = _normalize_reg_map(snapshot, "after")
        arch_bits = _parse_int(meta.get("arch_bits")) or 64
        word_size = _parse_int(meta.get("word_size")) or (8 if arch_bits == 64 else 4)
        ip = (
            regs_after.get("rip")
            or regs_after.get("eip")
            or _parse_int(snapshot.get("rip"))
            or _parse_int(snapshot.get("eip"))
        )
        function_info = resolver.resolve_function(
            ip, fallback_name=snapshot.get("func")
        )
        function_key = _function_cache_key(function_info, snapshot)
        stable_bp = (
            stable_frame_bp_by_function.get(function_key) if function_key else None
        )
        frame_bp = _select_frame_base_pointer(
            snapshot, meta, arch_bits, word_size, stable_bp
        )
        if function_key and _is_plausible_frame_bp(frame_bp, snapshot, meta, word_size):
            stable_frame_bp_by_function[function_key] = int(frame_bp)

        if function_key:
            instr_text = _instruction_text(snapshot)
            if function_key not in frame_pointer_ready_by_function:
                function_addr = (
                    _parse_int(function_info.get("addr"))
                    if isinstance(function_info, dict)
                    else None
                )
                normalized_ip = (
                    ip - resolver.load_base
                    if ip is not None and resolver.load_base > 0 and ip >= resolver.load_base
                    else ip
                )
                # True only when we can PROVE this is the function's entry
                # instruction (address match) -- default to "not ready".
                # Otherwise (unresolved, or trace genuinely starts mid-
                # function) keep the historical permissive default so a
                # trace that never observes a prologue still works.
                is_function_entry_instruction = (
                    function_addr is not None
                    and normalized_ip is not None
                    and normalized_ip == function_addr
                )
                default_ready = not is_function_entry_instruction
                frame_pointer_ready_by_function[function_key] = default_ready
                frame_allocated_by_function[function_key] = default_ready
            if _is_prologue_push_bp(instr_text):
                frame_pointer_ready_by_function[function_key] = False
                frame_allocated_by_function[function_key] = False
            elif _is_prologue_mov_bp_sp(instr_text):
                frame_pointer_ready_by_function[function_key] = True
            elif (
                frame_pointer_ready_by_function.get(function_key)
                and _is_stack_alloc_instruction(instr_text)
            ):
                frame_allocated_by_function[function_key] = True
        frame_allocated = (
            frame_allocated_by_function.get(function_key, True) if function_key else True
        )

        analysis = _build_slots(
            snapshot,
            prev_snapshot,
            meta,
            resolver,
            function_info,
            frame_bp=frame_bp,
            frame_allocated=frame_allocated,
        )
        analysis["overflow"] = _overflow_summary(analysis)
        analysis["explanationBullets"] = _build_explanation(snapshot, analysis)
        analysis["function"].setdefault("name", snapshot.get("func"))
        analysis["function"].setdefault("file", snapshot.get("file"))
        analysis["function"].setdefault("line", snapshot.get("line"))
        analysis_by_step[str(snapshot.get("step") or index + 1)] = (
            _normalize_legacy_analysis(analysis)
        )

    return analysis_by_step
