# SPDX-License-Identifier: AGPL-3.0-only
"""Crash and runtime error diagnostics for dynamic traces."""

from __future__ import annotations

from typing import Any, Optional

from backends.dynamic.pipeline.stack_model import (
    _bytes_to_hex,
    _hex,
    _parse_hex_bytes,
    _parse_int,
)


CONTROL_FLOW_MNEMONICS = {"ret", "jmp", "call"}

_WIN_NAMES = frozenset({
    "win", "pwn", "pwn_func", "get_flag", "getflag", "shell", "print_flag",
    "cat_flag", "exploit", "victory", "flag",
})


def _is_win_addr(addr: int | None, meta: dict) -> bool:
    if addr is None:
        return False
    functions = meta.get("functions") if isinstance(meta.get("functions"), list) else []
    for fn in functions:
        if not isinstance(fn, dict):
            continue
        fn_addr = _parse_int(fn.get("addr"))
        if fn_addr != addr:
            continue
        name = str(fn.get("name") or "").lower().strip().lstrip("_")
        if any(w in name for w in _WIN_NAMES):
            return True
    return False


def build_diagnostics(
    snapshots: list[dict],
    analysis_by_step: dict[str, dict],
    meta: dict,
    disasm_lines: Optional[list[dict]] = None,
    crash: Optional[dict] = None,
) -> list[dict]:
    """Build deterministic crash/error diagnostics from trace enrichment."""
    diagnostics: list[dict] = []
    code_ranges = _build_code_ranges(meta, disasm_lines or [])
    initial_control_values: dict[str, int] = {}

    for index, snapshot in enumerate(snapshots if isinstance(snapshots, list) else []):
        step = _step_number(snapshot, index)
        analysis = (
            analysis_by_step.get(str(step))
            if isinstance(analysis_by_step, dict)
            else None
        )
        if not isinstance(analysis, dict):
            continue

        diagnostics.extend(
            _diagnose_overflow(
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
            )
        )
        diagnostics.extend(
            _diagnose_control_slots(
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
                code_ranges=code_ranges,
                initial_control_values=initial_control_values,
            )
        )
        diagnostics.extend(
            _diagnose_invalid_control_flow(
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
                code_ranges=code_ranges,
            )
        )

    diagnostics.extend(
        _diagnose_crash(
            crash=crash,
            analysis_by_step=analysis_by_step,
            meta=meta,
            code_ranges=code_ranges,
        )
    )

    deduped = _dedupe_diagnostics(diagnostics)
    _attach_to_analysis(analysis_by_step, deduped)
    return deduped


def _diagnose_overflow(
    *,
    snapshot: dict,
    analysis: dict,
    meta: dict,
    step: int,
) -> list[dict]:
    overflow = analysis.get("overflow") if isinstance(analysis.get("overflow"), dict) else {}
    if not _overflow_has_runtime_evidence(analysis):
        return []

    diagnostics: list[dict] = []
    source = _probable_source(snapshot, meta)
    instruction_addr = _instruction_address(snapshot)
    function_name = _function_name(snapshot, analysis)
    responsible = _responsible_instruction_address(snapshot)
    writes = _analysis_writes(analysis)
    reached = {str(value) for value in overflow.get("reached") or []}

    diagnostics.append(
        _clean_diag(
            {
                "severity": "warning",
                "kind": "buffer_overflow",
                "step": step,
                "function": function_name,
                "instructionAddress": instruction_addr,
                "responsibleInstructionAddress": responsible,
                "message": _overflow_message(overflow, reached),
                "slot": _buffer_slot(analysis),
                "before": None,
                "after": overflow.get("frontier"),
                "bytes": _write_bytes(writes),
                "probableSource": source,
                "payloadOffset": _payload_offset(meta, _write_bytes(writes)),
                "confidence": 0.82,
            }
        )
    )

    if "saved_bp" in reached:
        diagnostics.append(
            _slot_corruption_diag(
                kind="saved_bp_corrupted",
                severity="warning",
                message="Le saved BP a ete ecrase par une ecriture hors limites",
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
                slot_kind="saved_bp",
                confidence=0.86,
            )
        )

    if "return_address" in reached:
        diagnostics.append(
            _slot_corruption_diag(
                kind="return_address_corrupted",
                severity="error",
                message="L'adresse de retour a ete ecrasee par le payload",
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
                slot_kind="return_address",
                confidence=0.92,
            )
        )

    return diagnostics


def _diagnose_control_slots(
    *,
    snapshot: dict,
    analysis: dict,
    meta: dict,
    step: int,
    code_ranges: list[tuple[int, int]],
    initial_control_values: dict[str, int],
) -> list[dict]:
    diagnostics: list[dict] = []
    function_name = _function_name(snapshot, analysis)
    for slot_kind in ("saved_bp", "return_address"):
        slot = _slot_for_kind(analysis, slot_kind)
        value_text = _slot_value(slot, analysis, slot_kind)
        value = _parse_int(value_text)
        addr = _parse_int(_slot_address(slot, analysis, slot_kind))
        if value is None or addr is None:
            continue

        key = f"{function_name}:{slot_kind}:{addr:x}"
        if slot_kind == "return_address" and _is_code_address(value, code_ranges) and not _looks_like_user_pattern(value):
            initial_control_values.setdefault(key, value)
        if slot_kind == "saved_bp" and not _looks_like_user_pattern(value):
            initial_control_values.setdefault(key, value)

        initial = initial_control_values.get(key)
        changed = initial is not None and value != initial
        invalid_ret = slot_kind == "return_address" and not _is_code_address(value, code_ranges)
        pattern = _looks_like_user_pattern(value)
        slot_write_signal = _slot_has_write_signal(slot, analysis)
        overflow_signal = _overflow_reaches(analysis, slot_kind)
        evidence = slot_write_signal or overflow_signal

        if slot_kind == "return_address":
            if not (evidence and (pattern or changed or invalid_ret)):
                continue
            confidence = 0.9 if overflow_signal else 0.84 if slot_write_signal else 0.72
            diagnostics.append(
                _slot_corruption_diag(
                    kind="return_address_corrupted",
                    severity="error" if confidence >= 0.8 else "warning",
                    message="L'adresse de retour n'est plus un pointeur de code valide",
                    snapshot=snapshot,
                    analysis=analysis,
                    meta=meta,
                    step=step,
                    slot_kind=slot_kind,
                    before=_hex(initial) if initial is not None else None,
                    confidence=confidence,
                )
            )
            continue

        if not (evidence and (pattern or changed or slot_write_signal)):
            continue
        diagnostics.append(
            _slot_corruption_diag(
                kind="saved_bp_corrupted",
                severity="warning",
                message="Le saved BP a change apres une ecriture dans la pile",
                snapshot=snapshot,
                analysis=analysis,
                meta=meta,
                step=step,
                slot_kind=slot_kind,
                before=_hex(initial) if initial is not None else None,
                confidence=0.78,
            )
        )

    return diagnostics


def _diagnose_invalid_control_flow(
    *,
    snapshot: dict,
    analysis: dict,
    meta: dict,
    step: int,
    code_ranges: list[tuple[int, int]],
) -> list[dict]:
    mnemonic = _instruction_mnemonic(snapshot)
    if mnemonic not in CONTROL_FLOW_MNEMONICS:
        return []

    before_regs = _register_map(snapshot, "before")
    after_regs = _register_map(snapshot, "after")
    ip_name = "eip" if "eip" in after_regs or "eip" in before_regs else "rip"
    target = after_regs.get(ip_name)
    before_ip = before_regs.get(ip_name)
    if target is None:
        return []
    if target == before_ip and mnemonic != "ret":
        return []
    if _is_code_address(target, code_ranges) and not _looks_like_user_pattern(target):
        if _overflow_reaches(analysis, "return_address"):
            if _is_win_addr(target, meta):
                kind = "ret2win_success"
                severity = "success"
                msg = f"Retour vers {_hex(target)} — adresse de retour detournee vers la fonction cible"
                conf = 0.97
            else:
                kind = "control_hijack"
                severity = "warning"
                msg = f"{ip_name.upper()} detourne vers une adresse executable apres {mnemonic}"
                conf = 0.90
            bytes_hex = _value_bytes_hex(target, _word_size(meta))
            regs_inner = {
                name: _hex(after_regs.get(name))
                for name in ("rip", "eip", "rsp", "esp", "rbp", "ebp")
                if after_regs.get(name) is not None
            }
            return [_clean_diag({
                "severity": severity,
                "kind": kind,
                "step": step,
                "function": _function_name(snapshot, analysis),
                "instructionAddress": _instruction_address(snapshot),
                "responsibleInstructionAddress": _instruction_address(snapshot),
                "message": msg,
                "slot": _slot_for_invalid_flow(analysis, target),
                "before": _hex(before_ip),
                "after": _hex(target),
                "bytes": bytes_hex,
                "probableSource": _probable_source(snapshot, meta),
                "payloadOffset": _payload_offset(meta, bytes_hex),
                "confidence": conf,
                "registers": regs_inner,
            })]
        return []

    regs = {
        name: _hex(after_regs.get(name))
        for name in ("rip", "eip", "rsp", "esp", "rbp", "ebp")
        if after_regs.get(name) is not None
    }
    bytes_hex = _value_bytes_hex(target, _word_size(meta))
    diag = {
        "severity": "error",
        "kind": "fatal_crash",
        "classification": "fatal_crash",
        "step": step,
        "function": _function_name(snapshot, analysis),
        "instructionAddress": _instruction_address(snapshot),
        "responsibleInstructionAddress": _instruction_address(snapshot),
        "message": f"{ip_name.upper()} devient non executable apres {mnemonic}",
        "slot": _slot_for_invalid_flow(analysis, target),
        "before": _hex(before_ip),
        "after": _hex(target),
        "bytes": bytes_hex,
        "probableSource": _probable_source(snapshot, meta),
        "payloadOffset": _payload_offset(meta, bytes_hex),
        "confidence": 0.9 if _looks_like_user_pattern(target) else 0.78,
        "registers": regs,
    }
    return [_clean_diag(diag)]


def _diagnose_crash(
    *,
    crash: Optional[dict],
    analysis_by_step: dict[str, dict],
    meta: dict,
    code_ranges: list[tuple[int, int]],
) -> list[dict]:
    if not isinstance(crash, dict):
        return []
    step = _parse_int(crash.get("step"))
    if step is None or step <= 0:
        return []
    analysis = (
        analysis_by_step.get(str(step))
        if isinstance(analysis_by_step, dict)
        else None
    )
    if not isinstance(analysis, dict):
        return []
    crash_type = str(crash.get("type") or "").strip().lower()
    instruction_text = str(crash.get("instructionText") or "").strip().lower()
    registers = crash.get("registers") if isinstance(crash.get("registers"), dict) else {}
    ip_name = "eip" if "eip" in registers or _parse_int(crash.get("eip")) is not None else "rip"
    ip_value = _parse_int(crash.get(ip_name) or registers.get(ip_name))
    slot = crash.get("suspectOverwrittenSlot") if isinstance(crash.get("suspectOverwrittenSlot"), dict) else None
    slot_kind = str(slot.get("kind") or "").strip().lower() if isinstance(slot, dict) else ""
    function_meta = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
    classification = str(crash.get("classification") or "").strip().lower()

    if classification == "ret2win_success":
        kind = "ret2win_success"
        severity = "success"
        confidence = 0.99
        ret_target = str(crash.get("retTarget") or crash.get("memoryAddress") or crash.get(ip_name) or "").strip() or None
        message = f"Acces a la fonction cible ({ret_target or 'adresse inconnue'}) via detournement de l'adresse de retour"
    elif classification == "control_hijack":
        kind = "control_hijack"
        severity = "warning"
        confidence = 0.92
        ret_target = str(crash.get("retTarget") or crash.get("memoryAddress") or crash.get(ip_name) or "").strip() or None
        message = f"Adresse de retour detournee vers une zone executable ({ret_target or 'adresse inconnue'})"
    elif classification == "fatal_crash":
        kind = "fatal_crash"
        severity = "error"
        confidence = 0.96
        ret_target = None
        message = str(crash.get("reason") or "Crash fatal Unicorn.").strip()
    else:
        kind = (
            "fatal_crash"
            if crash_type == "unmapped_fetch"
            or instruction_text.startswith("ret")
            or instruction_text.startswith("jmp")
            or instruction_text.startswith("call")
            or (ip_value is not None and not _is_code_address(ip_value, code_ranges))
            else "runtime_crash"
        )
        if slot_kind == "return_address" and kind != "fatal_crash":
            kind = "runtime_crash"
        severity = "error"
        confidence = 0.96 if kind == "fatal_crash" else 0.88
        ret_target = None
        message = str(crash.get("reason") or "Crash runtime Unicorn.").strip()

    bytes_hex = str(crash.get("suspectBytes") or "").strip()
    if not bytes_hex and ip_value is not None and kind in ("invalid_control_flow", "fatal_crash"):
        bytes_hex = _value_bytes_hex(ip_value, _word_size(meta))

    after_value = (
        str(crash.get("retTarget") or "").strip() or None
        if classification in ("ret2win_success", "control_hijack")
        else str(crash.get("memoryAddress") or crash.get(ip_name) or registers.get(ip_name) or "").strip() or None
    )

    diag = {
        "severity": severity,
        "kind": kind,
        "classification": classification or None,
        "step": step,
        "function": str(
            crash.get("function")
            or function_meta.get("name")
            or ""
        ).strip()
        or None,
        "instructionAddress": str(crash.get("instructionAddress") or "").strip() or None,
        "responsibleInstructionAddress": str(crash.get("instructionAddress") or "").strip() or None,
        "message": message,
        "slot": slot,
        "before": None,
        "after": after_value,
        "bytes": bytes_hex,
        "probableSource": str(crash.get("probableSource") or _probable_source({}, meta)).strip() or None,
        "payloadOffset": crash.get("payloadOffset"),
        "confidence": confidence,
        "registers": registers,
        "crashType": crash_type or None,
    }
    return [_clean_diag(diag)]


def _slot_corruption_diag(
    *,
    kind: str,
    severity: str,
    message: str,
    snapshot: dict,
    analysis: dict,
    meta: dict,
    step: int,
    slot_kind: str,
    before: Optional[str] = None,
    confidence: float = 0.8,
) -> dict:
    slot = _slot_for_kind(analysis, slot_kind)
    after = _slot_value(slot, analysis, slot_kind)
    bytes_hex = str(slot.get("bytesHex") or "").strip() if isinstance(slot, dict) else ""
    if not bytes_hex and after:
        bytes_hex = _value_bytes_hex(_parse_int(after), _word_size(meta))
    before_value = before or _initial_slot_value(analysis, slot_kind)
    return _clean_diag(
        {
            "severity": severity,
            "kind": kind,
            "step": step,
            "function": _function_name(snapshot, analysis),
            "instructionAddress": _instruction_address(snapshot),
            "responsibleInstructionAddress": _responsible_instruction_address(snapshot),
            "message": message,
            "slot": _control_slot_payload(slot, analysis, slot_kind),
            "before": before_value,
            "after": after,
            "bytes": bytes_hex,
            "probableSource": _probable_source(snapshot, meta),
            "payloadOffset": _payload_offset(meta, bytes_hex),
            "confidence": confidence,
        }
    )


def _build_code_ranges(meta: dict, disasm_lines: list[dict]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    functions = meta.get("functions") if isinstance(meta.get("functions"), list) else []
    for function in functions:
        addr = _parse_int(function.get("addr")) if isinstance(function, dict) else None
        size = _parse_int(function.get("size")) if isinstance(function, dict) else None
        if addr is not None and size and size > 0:
            ranges.append((addr, addr + size))

    addresses = [
        _parse_int(line.get("addr")) for line in disasm_lines if isinstance(line, dict)
    ]
    valid = [addr for addr in addresses if addr is not None]
    if valid:
        ranges.append((min(valid), max(valid) + 0x40))

    base = _parse_int(meta.get("base"))
    if base is not None and not ranges:
        ranges.append((base, base + 0x100000))
    return _merge_ranges(ranges)


def _merge_ranges(ranges: list[tuple[int, int]]) -> list[tuple[int, int]]:
    ordered = sorted((start, end) for start, end in ranges if end > start)
    if not ordered:
        return []
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            merged[-1] = (prev_start, max(prev_end, end))
        else:
            merged.append((start, end))
    return merged


def _is_code_address(value: Optional[int], ranges: list[tuple[int, int]]) -> bool:
    if value is None:
        return False
    return any(start <= value < end for start, end in ranges)


def _looks_like_user_pattern(value: Optional[int]) -> bool:
    if value is None:
        return False
    masked = value & 0xFFFFFFFFFFFFFFFF
    if masked in {
        0x41414141,
        0x4141414141414141,
        0x42424242,
        0x4242424242424242,
        0x43434343,
        0x4343434343434343,
        0x6161616B,
        0x6161616C,
        0x6B616161,
        0x6C616161,
    }:
        return True
    data = [(masked >> shift) & 0xFF for shift in range(0, 64, 8)]
    trimmed = [byte for byte in data if byte != 0]
    if len(trimmed) >= 4 and len(set(trimmed[:4])) == 1 and 0x20 <= trimmed[0] <= 0x7E:
        return True
    printable = sum(1 for byte in trimmed if 0x20 <= byte <= 0x7E)
    return len(trimmed) >= 4 and printable >= max(4, int(len(trimmed) * 0.85))


def _slot_for_kind(analysis: dict, kind: str) -> dict:
    frame = analysis.get("frame") if isinstance(analysis.get("frame"), dict) else {}
    slots = frame.get("slots") if isinstance(frame.get("slots"), list) else []
    for slot in slots:
        if not isinstance(slot, dict):
            continue
        role = str(slot.get("role") or slot.get("kind") or "").strip().lower()
        if role == kind:
            return slot
    return {}


def _slot_value(slot: dict, analysis: dict, slot_kind: str) -> Optional[str]:
    if isinstance(slot, dict):
        for key in ("valueHex", "rawValue", "valueDisplay"):
            value = str(slot.get(key) or "").strip()
            if value.startswith("0x"):
                return value
    control = analysis.get("control") if isinstance(analysis.get("control"), dict) else {}
    key = "retValue" if slot_kind == "return_address" else "savedBpValue"
    value = str(control.get(key) or "").strip()
    return value or None


def _slot_address(slot: dict, analysis: dict, slot_kind: str) -> Optional[str]:
    if isinstance(slot, dict):
        value = str(slot.get("start") or slot.get("address") or "").strip()
        if value:
            return value
    control = analysis.get("control") if isinstance(analysis.get("control"), dict) else {}
    key = "retAddrAddr" if slot_kind == "return_address" else "savedBpAddr"
    value = str(control.get(key) or "").strip()
    return value or None


def _control_slot_payload(slot: dict, analysis: dict, slot_kind: str) -> dict:
    address = _slot_address(slot, analysis, slot_kind)
    offset = None
    if isinstance(slot, dict):
        offset = slot.get("offsetFromBpHex") or slot.get("offsetFromBp")
    if offset is None:
        offset = "rbp+0x8" if slot_kind == "return_address" else "rbp+0x0"
    return {
        "kind": slot_kind,
        "offset": str(offset),
        "address": address,
    }


def _slot_for_invalid_flow(analysis: dict, target: int) -> Optional[dict]:
    ret_slot = _slot_for_kind(analysis, "return_address")
    ret_value = _parse_int(_slot_value(ret_slot, analysis, "return_address"))
    if ret_value == target:
        return _control_slot_payload(ret_slot, analysis, "return_address")
    return None


def _buffer_slot(analysis: dict) -> Optional[dict]:
    buffer = analysis.get("buffer") if isinstance(analysis.get("buffer"), dict) else {}
    if not buffer:
        return None
    return {
        "kind": "buffer",
        "offset": None,
        "address": buffer.get("start"),
    }


def _slot_has_write_signal(slot: dict, analysis: dict) -> bool:
    if not isinstance(slot, dict):
        return False
    flags = slot.get("flags") if isinstance(slot.get("flags"), list) else []
    has_writes = _analysis_has_writes(analysis)
    return bool(
        slot.get("recentWrite")
        or "recent_write" in flags
        or (has_writes and (slot.get("changed") or "changed" in flags))
    )


def _overflow_reaches(analysis: dict, slot_kind: str) -> bool:
    overflow = analysis.get("overflow") if isinstance(analysis.get("overflow"), dict) else {}
    reached = {str(value) for value in overflow.get("reached") or []}
    return bool(_overflow_has_runtime_evidence(analysis) and slot_kind in reached)


def _analysis_writes(analysis: dict) -> list[dict]:
    delta = analysis.get("delta") if isinstance(analysis.get("delta"), dict) else {}
    writes = delta.get("writes") if isinstance(delta.get("writes"), list) else []
    return [write for write in writes if isinstance(write, dict)]


def _analysis_has_writes(analysis: Any) -> bool:
    return bool(_analysis_writes(analysis if isinstance(analysis, dict) else {}))


def _overflow_has_runtime_evidence(analysis: dict) -> bool:
    overflow = analysis.get("overflow") if isinstance(analysis.get("overflow"), dict) else {}
    if not overflow.get("active"):
        return False
    progress = _parse_int(overflow.get("progressBytes"))
    if progress is not None and progress <= 0:
        return False
    return _write_crosses_buffer(analysis)


def _write_crosses_buffer(analysis: dict) -> bool:
    buffer = analysis.get("buffer") if isinstance(analysis.get("buffer"), dict) else {}
    buffer_start = _parse_int(buffer.get("start"))
    buffer_end = _parse_int(buffer.get("end"))
    if buffer_end is None:
        return False
    for write in _analysis_writes(analysis):
        addr = _parse_int(write.get("addr"))
        size = max(1, _parse_int(write.get("size")) or 1)
        if addr is None:
            continue
        end = addr + size
        if addr < buffer_end and end > buffer_end and (buffer_start is None or end > buffer_start):
            return True
    return False


def _write_bytes(writes: list[dict]) -> str:
    for write in writes:
        text = str(write.get("bytes") or "").strip()
        if text:
            return text
    return ""


def _initial_slot_value(analysis: dict, slot_kind: str) -> Optional[str]:
    # Current analysis has no historical field yet; this hook keeps the output schema stable.
    del analysis, slot_kind
    return None


def _payload_offset(meta: dict, bytes_hex: Optional[str]) -> Optional[int]:
    target = _parse_bytes_any(bytes_hex)
    if not target:
        return None
    payload_hex = _payload_hex(meta)
    if not payload_hex:
        return None
    haystack = _parse_bytes_any(payload_hex)
    if not haystack or len(target) > len(haystack):
        return None
    max_len = min(len(target), 16)
    for size in range(max_len, 3, -1):
        needle = target[:size]
        for index in range(0, len(haystack) - size + 1):
            if haystack[index : index + size] == needle:
                return index
    return None


def _parse_bytes_any(raw: Any) -> list[int]:
    if raw is None:
        return []
    if isinstance(raw, (bytes, bytearray)):
        return [int(byte) & 0xFF for byte in raw]
    text = str(raw).strip()
    if not text:
        return []
    compact = text.replace(" ", "").replace("\n", "").replace("\t", "")
    if compact.startswith("0x"):
        compact = compact[2:]
    if len(compact) % 2 == 0 and compact and all(ch in "0123456789abcdefABCDEF" for ch in compact):
        try:
            return [int(compact[index : index + 2], 16) for index in range(0, len(compact), 2)]
        except ValueError:
            return []
    return _parse_hex_bytes(raw)


def _payload_hex(meta: dict) -> str:
    for value in (
        meta.get("payload_hex"),
        (meta.get("input") or {}).get("payloadBytesHex")
        if isinstance(meta.get("input"), dict)
        else "",
        (meta.get("input") or {}).get("previewHex")
        if isinstance(meta.get("input"), dict)
        else "",
    ):
        text = str(value or "").strip()
        if text:
            return text
    payload_text = str(meta.get("payload_text") or meta.get("argv1") or "")
    if payload_text:
        return _bytes_to_hex(list(payload_text.encode("latin1", errors="ignore")))
    return ""


def _probable_source(snapshot: dict, meta: dict) -> str:
    input_meta = meta.get("input") if isinstance(meta.get("input"), dict) else {}
    input_mode = str(input_meta.get("mode") or "").strip().lower()
    symbol = _external_symbol(snapshot)
    target = str(meta.get("payload_target") or input_meta.get("targetMode") or "").lower()

    if symbol in {"fscanf", "__isoc99_fscanf", "__isoc23_fscanf", "fgetc", "fgets"} and input_mode == "file":
        return "file"
    if symbol in {"read", "gets", "fgets", "scanf", "__isoc99_scanf", "__isoc23_scanf"}:
        return "stdin"
    if target == "stdin":
        return "stdin"
    if target == "both":
        return "stdin + argv[1]"
    if input_mode == "file":
        return "file"
    if target == "argv1" or meta.get("argv1") is not None or meta.get("payload_text"):
        return "argv[1]"
    return "payload"


def _external_symbol(snapshot: dict) -> str:
    effects = snapshot.get("effects") if isinstance(snapshot.get("effects"), dict) else {}
    symbol = str(effects.get("external_symbol") or "").split("@", 1)[0]
    for prefix in ("__isoc99_", "__isoc23_"):
        if symbol.startswith(prefix):
            return symbol
    return symbol


def _instruction_mnemonic(snapshot: dict) -> str:
    instruction = snapshot.get("instruction") if isinstance(snapshot.get("instruction"), dict) else {}
    mnemonic = str(instruction.get("mnemonic") or "").strip().lower()
    if mnemonic:
        return mnemonic
    text = str(instruction.get("text") or snapshot.get("instr") or "").strip()
    return text.split(None, 1)[0].lower() if text else ""


def _instruction_address(snapshot: dict) -> Optional[str]:
    instruction = snapshot.get("instruction") if isinstance(snapshot.get("instruction"), dict) else {}
    addr = _parse_int(instruction.get("address"))
    if addr is None:
        addr = _parse_int(snapshot.get("rip")) or _parse_int(snapshot.get("eip"))
    return _hex(addr)


def _responsible_instruction_address(snapshot: dict) -> Optional[str]:
    return _instruction_address(snapshot)


def _function_name(snapshot: dict, analysis: dict) -> Optional[str]:
    function = analysis.get("function") if isinstance(analysis.get("function"), dict) else {}
    name = str(function.get("name") or snapshot.get("func") or "").strip()
    return name or None


def _register_map(snapshot: dict, stage: str) -> dict[str, int]:
    cpu = snapshot.get("cpu") if isinstance(snapshot.get("cpu"), dict) else {}
    stage_data = cpu.get(stage) if isinstance(cpu.get(stage), dict) else {}
    registers = stage_data.get("registers") if isinstance(stage_data.get("registers"), dict) else {}
    out = {}
    for key, value in registers.items():
        parsed = _parse_int(value)
        if parsed is not None:
            out[str(key).lower()] = parsed
    return out


def _word_size(meta: dict) -> int:
    value = _parse_int(meta.get("word_size"))
    if value in (4, 8):
        return int(value)
    arch = _parse_int(meta.get("arch_bits")) or 64
    return 4 if arch == 32 else 8


def _value_bytes_hex(value: Optional[int], word_size: int) -> str:
    if value is None:
        return ""
    width = 4 if word_size == 4 else 8
    masked = int(value) & ((1 << (width * 8)) - 1)
    return _bytes_to_hex([(masked >> (index * 8)) & 0xFF for index in range(width)])


def _overflow_message(overflow: dict, reached: set[str]) -> str:
    buffer_name = str(overflow.get("bufferName") or "buffer")
    if "return_address" in reached:
        return f"Le debordement de {buffer_name} atteint l'adresse de retour"
    if "saved_bp" in reached:
        return f"Le debordement de {buffer_name} atteint le saved BP"
    return f"Le debordement de {buffer_name} depasse ses bornes connues"


def _step_number(snapshot: dict, index: int) -> int:
    step = _parse_int(snapshot.get("step"))
    return int(step) if step is not None else index + 1


def _dedupe_diagnostics(diagnostics: list[dict]) -> list[dict]:
    order = {"error": 0, "warning": 1, "info": 2}
    selected: dict[tuple[Any, ...], dict] = {}
    for diag in diagnostics:
        if not diag:
            continue
        key = (
            diag.get("kind"),
            diag.get("step"),
            (diag.get("slot") or {}).get("address")
            if isinstance(diag.get("slot"), dict)
            else None,
            diag.get("instructionAddress"),
        )
        previous = selected.get(key)
        if previous is None:
            selected[key] = diag
            continue
        previous_score = (order.get(previous.get("severity"), 9), -float(previous.get("confidence") or 0))
        next_score = (order.get(diag.get("severity"), 9), -float(diag.get("confidence") or 0))
        if next_score < previous_score:
            selected[key] = _merge_diagnostic(diag, previous)
        else:
            selected[key] = _merge_diagnostic(previous, diag)
    return sorted(
        selected.values(),
        key=lambda item: (
            _parse_int(item.get("step")) or 0,
            order.get(item.get("severity"), 9),
            str(item.get("kind") or ""),
        ),
    )


def _merge_diagnostic(primary: dict, fallback: dict) -> dict:
    merged = dict(primary)
    for key, value in fallback.items():
        if key not in merged or merged.get(key) in (None, "", []):
            merged[key] = value
    primary_slot = merged.get("slot") if isinstance(merged.get("slot"), dict) else {}
    fallback_slot = fallback.get("slot") if isinstance(fallback.get("slot"), dict) else {}
    if primary_slot or fallback_slot:
        slot = dict(fallback_slot)
        slot.update({key: value for key, value in primary_slot.items() if value not in (None, "")})
        merged["slot"] = slot
    return merged


def _attach_to_analysis(analysis_by_step: dict[str, dict], diagnostics: list[dict]) -> None:
    if not isinstance(analysis_by_step, dict):
        return
    for diag in diagnostics:
        step_key = str(diag.get("step") or "")
        if not step_key:
            continue
        analysis = analysis_by_step.get(step_key)
        if not isinstance(analysis, dict):
            continue
        bucket = analysis.setdefault("diagnostics", [])
        if isinstance(bucket, list):
            bucket.append(diag)


def _clean_diag(diag: dict) -> dict:
    clean = {}
    for key, value in diag.items():
        if value is None:
            continue
        if key == "slot" and value is None:
            continue
        clean[key] = value
    return clean
