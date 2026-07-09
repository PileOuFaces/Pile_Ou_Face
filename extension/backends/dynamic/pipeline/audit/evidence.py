# SPDX-License-Identifier: AGPL-3.0-only
"""Evidence model for Run Trace stack-slot audits."""

from __future__ import annotations

import os
from typing import Optional

from backends.dynamic.core.interfaces import TraceConfigLike

from .asm_analysis import (
    BUFFER_PROOF_SINKS,
    X86_64_ARG_REGS,
    audit_plt_symbols,
    call_target_name,
    dest_reg_from_operands,
    function_ranges,
    instruction_kind,
    line_addr,
    safe_hex,
    safe_int,
    source_reg_from_mov,
    stack_accesses_from_operands,
)

try:
    from backends.static.disasm.stack_frame import analyse_stack_frame
except Exception:
    analyse_stack_frame = None


def _normalize_path(path: str) -> str:
    cwd = os.getcwd()
    if path.startswith(cwd + os.sep):
        return os.path.relpath(path, cwd)
    return path


def _slot_confidence(source: str) -> float:
    if source == "dwarf":
        return 0.95
    if source in {"source", "source_c"}:
        return 0.9
    if source in {"auto", "static"}:
        return 0.68
    return 0.5


def _frame_audit_for_function(binary_path: str, function: dict, relevant: list[dict]) -> Optional[dict]:
    addr = safe_int(function.get("addr"))
    if addr is None or analyse_stack_frame is None:
        return None
    try:
        frame = analyse_stack_frame(binary_path, addr)
    except Exception as exc:
        return {
            "function": function,
            "error": str(exc),
            "frame_size": 0,
            "rbp_based_accesses": [],
            "rsp_based_accesses": [],
            "probable_stack_slots": [],
            "confidence": 0.0,
            "evidence": [],
        }
    fn_name = str(function.get("name") or "")
    rbp_accesses = []
    rsp_accesses = []
    evidence = []
    for item in relevant:
        if item.get("function") != fn_name:
            continue
        evidence.append(item)
        for access in item.get("stack_accesses", []):
            base = str(access.get("base") or "")
            enriched = {**access, "addr": item.get("addr"), "kind": item.get("kind")}
            if base.endswith("bp"):
                rbp_accesses.append(enriched)
            elif base.endswith("sp"):
                rsp_accesses.append(enriched)

    slots = []
    for entry in frame.get("vars", []) if isinstance(frame, dict) else []:
        source = str(entry.get("source") or "auto")
        slots.append(
            {
                "name": str(entry.get("name") or ""),
                "kind": "probable_local",
                "offset": safe_int(entry.get("offset")),
                "size": safe_int(entry.get("size")),
                "source": source,
                "confidence": _slot_confidence(source),
                "evidence": {
                    "location": entry.get("location"),
                    "method": "asm_stack_access" if source == "auto" else source,
                },
            }
        )
    for entry in frame.get("args", []) if isinstance(frame, dict) else []:
        source = str(entry.get("source") or "auto")
        slots.append(
            {
                "name": str(entry.get("name") or ""),
                "kind": "stack_argument" if entry.get("offset") is not None else "register_argument",
                "offset": safe_int(entry.get("offset")),
                "size": safe_int(entry.get("size")),
                "source": source,
                "confidence": _slot_confidence(source),
                "evidence": {
                    "location": entry.get("location"),
                    "method": "asm_stack_access" if source == "auto" else source,
                },
            }
        )

    frame_size = safe_int(frame.get("frame_size")) if isinstance(frame, dict) else 0
    if slots:
        confidence = 0.68
    elif frame_size and frame_size > 0:
        confidence = 0.55
    else:
        confidence = 0.0
    return {
        "function": function,
        "frame_size": frame_size or 0,
        "rbp_based_accesses": rbp_accesses,
        "rsp_based_accesses": rsp_accesses,
        "probable_stack_slots": slots,
        "confidence": confidence,
        "evidence": evidence,
    }


def build_inferred_frame_audit(
    binary_path: str,
    functions: list[dict],
    relevant: list[dict],
    start_symbol: Optional[str],
) -> dict:
    frames = []
    for function in functions:
        frame = _frame_audit_for_function(binary_path, function, relevant)
        if frame is not None:
            frames.append(frame)
    selected = None
    if start_symbol:
        selected = next((frame for frame in frames if frame.get("function", {}).get("name") == start_symbol), None)
    if selected is None:
        selected = next((frame for frame in frames if frame.get("function", {}).get("name") == "main"), None)
    if selected is None and frames:
        selected = frames[0]
    selected = selected or {
        "frame_size": 0,
        "rbp_based_accesses": [],
        "rsp_based_accesses": [],
        "probable_stack_slots": [],
        "confidence": 0.0,
        "evidence": [],
    }
    return {
        "target_function": selected.get("function"),
        "frame_size": selected.get("frame_size", 0),
        "rbp_based_accesses": selected.get("rbp_based_accesses", []),
        "rsp_based_accesses": selected.get("rsp_based_accesses", []),
        "probable_stack_slots": selected.get("probable_stack_slots", []),
        "confidence": selected.get("confidence", 0.0),
        "evidence": selected.get("evidence", []),
        "by_function": frames,
    }


def _slot_label(slot: dict | None = None, base: str | None = None, offset: Optional[int] = None) -> str:
    if slot is not None:
        base = str(slot.get("base") or base or "stack")
        offset = safe_int(slot.get("offset"))
    base = str(base or "stack")
    if offset is None:
        return f"{base}:unknown"
    sign = "-" if offset < 0 else "+"
    return f"{base}{sign}0x{abs(offset):x}"


def _evidence_entry(
    *,
    kind: str,
    confidence: float,
    function: str,
    slot: str | None,
    claim: str,
    evidence: dict,
    reason: str,
) -> dict:
    subject = {"function": function}
    if slot:
        subject["slot"] = slot
    return {
        "kind": kind,
        "confidence": max(0.0, min(1.0, float(confidence))),
        "subject": subject,
        "claim": claim,
        "evidence": evidence,
        "reason": reason,
    }


def _stack_access_payload(access: dict, line: dict, kind: str) -> dict:
    return {
        "addr": safe_hex(line_addr(line)),
        "kind": kind,
        "mnemonic": str(line.get("mnemonic") or "").strip(),
        "operands": str(line.get("operands") or "").strip(),
        "base": access.get("base"),
        "offset": access.get("offset"),
        "expression": access.get("expression"),
        "text": str(line.get("text") or "").strip(),
    }


def _slot_key(base: str, offset: Optional[int]) -> str:
    if offset is None:
        return f"{base}:unknown"
    return f"{base}:{offset:+d}"


_EXACT_SIZE_SOURCES = frozenset({"dwarf", "source", "source_c", "abi"})


def _slot_from_frame_entry(entry: dict, kind: str) -> dict:
    offset = safe_int(entry.get("offset"))
    # `size` is only ever populated here from a source that is inherently
    # unambiguous: DWARF/enriched-C types, or a hardware register width for
    # an ABI argument (a register has no such thing as a partial access). A
    # genuinely sized ASM access (e.g. `mov byte ptr [rbp-0x60], al`,
    # size_is_exact=True in stack_frame.py) is real evidence but NOT proof of
    # the whole object's size -- one byte written by one instruction doesn't
    # mean the object is one byte long. That evidence is not lost: it stays
    # available on this slot's asm_instructions/lea_instructions for manual
    # inspection, but never becomes the reported `size`. Resolved for real by
    # _finalize_slot_size, which is the only place allowed to set `size`.
    source = str(entry.get("source") or "auto").lower()
    exact_size_source = source in _EXACT_SIZE_SOURCES
    size = safe_int(entry.get("size")) if exact_size_source else None
    base = "rbp" if offset is not None else "register"
    return {
        "key": _slot_key(base, offset),
        "base": base,
        "offset": offset,
        "offset_label": f"{base}{offset:+#x}" if offset is not None and base != "register" else None,
        "size": size,
        "size_source": source if size is not None else "unknown",
        "observed_write_size": None,
        "estimated_bound": None,
        "size_confidence": None,
        "size_reason": "",
        "name": str(entry.get("name") or ""),
        "kind": kind,
        "source": str(entry.get("source") or "auto"),
        "location": entry.get("location"),
        "type": entry.get("type") or entry.get("cType"),
        "asm_instructions": [],
        "lea_instructions": [],
        "register_address_assignments": [],
        "passed_as_call_argument": [],
        "runtime_writes": [],
        "runtime_reads": [],
        "payload_overlap": False,
        "evidence_sources": [],
        "classification": kind,
        "confidence": "low",
        "reason": "",
    }


def _slot_from_access(access: dict) -> dict:
    base = str(access.get("base") or "stack")
    offset = safe_int(access.get("offset"))
    return {
        "key": _slot_key(base, offset),
        "base": base,
        "offset": offset,
        "offset_label": f"{base}{offset:+#x}" if offset is not None else None,
        "size": None,
        "size_source": "unknown",
        "observed_write_size": None,
        "estimated_bound": None,
        "size_confidence": None,
        "size_reason": "",
        "name": _slot_key(base, offset),
        "kind": "stack_slot",
        "source": "asm",
        "location": access.get("expression"),
        "type": None,
        "asm_instructions": [],
        "lea_instructions": [],
        "register_address_assignments": [],
        "passed_as_call_argument": [],
        "runtime_writes": [],
        "runtime_reads": [],
        "payload_overlap": False,
        "evidence_sources": [],
        "classification": "stack_slot",
        "confidence": "low",
        "reason": "",
    }


def _merge_slot(slots: dict[str, dict], slot: dict) -> dict:
    existing = slots.get(slot["key"])
    if existing is None:
        slots[slot["key"]] = slot
        return slot
    if existing.get("size") in {None, 0} and slot.get("size"):
        existing["size"] = slot.get("size")
        existing["size_source"] = slot.get("size_source")
    if not existing.get("name") and slot.get("name"):
        existing["name"] = slot.get("name")
    if existing.get("kind") == "stack_slot" and slot.get("kind") != "stack_slot":
        existing["kind"] = slot.get("kind")
        existing["classification"] = slot.get("kind")
    return existing


def _frame_slots(binary_path: str, function: dict) -> tuple[dict, list[dict]]:
    addr = safe_int(function.get("addr"))
    if addr is None or analyse_stack_frame is None:
        return {}, []
    try:
        frame = analyse_stack_frame(binary_path, addr)
    except Exception:
        return {}, []
    slots: dict[str, dict] = {}
    for entry in frame.get("vars", []) if isinstance(frame, dict) else []:
        _merge_slot(slots, _slot_from_frame_entry(entry, "probable_local"))
    for entry in frame.get("args", []) if isinstance(frame, dict) else []:
        kind = "stack_argument" if entry.get("offset") is not None else "register_argument"
        _merge_slot(slots, _slot_from_frame_entry(entry, kind))
    return frame, list(slots.values())


def _line_in_function_ranges(disassembly: list[dict], function: dict, ranges: list[dict]) -> list[dict]:
    start = safe_int(function.get("addr"))
    if start is None:
        return []
    range_entry = next(
        (entry for entry in ranges if entry.get("function", {}).get("addr") == function.get("addr")),
        None,
    )
    end = range_entry.get("end") if range_entry else None
    out = []
    for line in disassembly if isinstance(disassembly, list) else []:
        addr = line_addr(line)
        if addr is None or addr < start:
            continue
        if end is not None and addr >= end:
            continue
        out.append(line)
    return out


def _track_static_slot_evidence(
    function_name: str,
    function_lines: list[dict],
    slots: dict[str, dict],
    plt_symbols: dict[int, str],
    evidence_entries: list[dict],
) -> tuple[list[dict], list[dict], list[dict], list[dict]]:
    frame_allocations = []
    rbp_accesses = []
    rsp_accesses = []
    call_sites = []
    reg_state: dict[str, dict] = {}
    for line in function_lines:
        mnemonic = str(line.get("mnemonic") or "").strip().lower()
        operands = str(line.get("operands") or "").strip()
        accesses = stack_accesses_from_operands(operands)
        kind = instruction_kind(line, plt_symbols) or mnemonic
        if kind == "sub_sp":
            allocation = {
                "addr": safe_hex(line_addr(line)),
                "instruction": str(line.get("text") or "").strip(),
                "operands": operands,
            }
            frame_allocations.append(allocation)
            evidence_entries.append(
                _evidence_entry(
                    kind="frame_allocation",
                    confidence=0.75,
                    function=function_name,
                    slot=None,
                    claim="frame_allocation",
                    evidence=allocation,
                    reason="Stack pointer subtraction allocates frame space.",
                )
            )
        for access in accesses:
            slot = _merge_slot(slots, _slot_from_access(access))
            evidence = _stack_access_payload(access, line, kind)
            slot["asm_instructions"].append(evidence)
            base = str(access.get("base") or "")
            slot_name = _slot_label(base=base, offset=safe_int(access.get("offset")))
            evidence_entries.append(
                _evidence_entry(
                    kind="stack_access",
                    confidence=0.65,
                    function=function_name,
                    slot=slot_name,
                    claim="local_slot" if base.endswith("bp") and safe_int(access.get("offset")) is not None and safe_int(access.get("offset")) < 0 else "stack_slot",
                    evidence=evidence,
                    reason="Instruction references a stack-relative address.",
                )
            )
            if base.endswith("bp"):
                rbp_accesses.append(evidence)
            elif base.endswith("sp"):
                rsp_accesses.append(evidence)

        if mnemonic == "lea" and accesses:
            dest = dest_reg_from_operands(operands)
            if dest:
                access = accesses[0]
                slot = _merge_slot(slots, _slot_from_access(access))
                assignment = {
                    "addr": safe_hex(line_addr(line)),
                    "register": dest,
                    "slot_key": slot["key"],
                    "base": access.get("base"),
                    "offset": access.get("offset"),
                    "instruction": str(line.get("text") or "").strip(),
                }
                slot["lea_instructions"].append(assignment)
                slot["register_address_assignments"].append(assignment)
                reg_state[dest] = {"slot_key": slot["key"], **assignment}
                evidence_entries.append(
                    _evidence_entry(
                        kind="stack_access",
                        confidence=0.72,
                        function=function_name,
                        slot=_slot_label(slot),
                        claim="slot_address_materialized",
                        evidence=assignment,
                        reason="LEA materializes the stack slot address into a register.",
                    )
                )
                continue

        if mnemonic == "mov":
            dest = dest_reg_from_operands(operands)
            source = source_reg_from_mov(operands)
            if dest and source and source in reg_state:
                reg_state[dest] = {**reg_state[source], "register": dest}
            elif dest:
                reg_state.pop(dest, None)
            continue

        if mnemonic == "call":
            call_target = call_target_name(operands, plt_symbols)
            args = []
            for index, reg in enumerate(X86_64_ARG_REGS):
                state = reg_state.get(reg)
                args.append(
                    {
                        "index": index,
                        "register": reg,
                        "slot_key": state.get("slot_key") if state else None,
                        "base": state.get("base") if state else None,
                        "offset": state.get("offset") if state else None,
                    }
                )
            call_site = {
                "addr": safe_hex(line_addr(line)),
                "target": call_target,
                "instruction": str(line.get("text") or "").strip(),
                "argument_registers_before_call": args,
            }
            dest_index = BUFFER_PROOF_SINKS.get(str(call_target or "").lower())
            if dest_index is not None and dest_index < len(X86_64_ARG_REGS):
                dest_reg = X86_64_ARG_REGS[dest_index]
                dest_state = reg_state.get(dest_reg)
                if dest_state and dest_state.get("slot_key") in slots:
                    slot = slots[dest_state["slot_key"]]
                    proof = {
                        "call_addr": call_site["addr"],
                        "target": call_target,
                        "argument_index": dest_index,
                        "register": dest_reg,
                        "instruction": call_site["instruction"],
                    }
                    slot["passed_as_call_argument"].append(proof)
                    call_site["destination_slot"] = {
                        "slot_key": slot["key"],
                        "base": slot.get("base"),
                        "offset": slot.get("offset"),
                    }
                    evidence_entries.append(
                        _evidence_entry(
                            kind="call_argument",
                            confidence=0.88,
                            function=function_name,
                            slot=_slot_label(slot),
                            claim="call_destination",
                            evidence=proof,
                            reason=f"Slot address is passed as destination argument to {call_target}.",
                        )
                    )
            call_sites.append(call_site)
            continue

        dest = dest_reg_from_operands(operands)
        if dest and mnemonic not in {"cmp", "test"}:
            reg_state.pop(dest, None)
    return frame_allocations, rbp_accesses, rsp_accesses, call_sites


def _config_payload_sources(config: TraceConfigLike) -> list[dict]:
    sources = []
    stdin_data = getattr(config, "stdin_data", b"") or b""
    if stdin_data:
        sources.append({"source": "stdin", "bytes": stdin_data})
    argv1_data = getattr(config, "argv1_data", None)
    if argv1_data:
        sources.append({"source": "argv1_data", "bytes": argv1_data})
    argv1 = getattr(config, "argv1", None)
    if argv1 is not None:
        sources.append({"source": "argv1", "bytes": str(argv1).encode("utf-8", errors="ignore")})
    stack_payload = getattr(config, "stack_payload", None)
    if stack_payload:
        try:
            _offset, payload = stack_payload
            if payload:
                sources.append({"source": "stack_payload", "bytes": payload})
        except Exception:
            pass
    return sources


def _payload_overlap(write_bytes: bytes, payload_sources: list[dict]) -> bool:
    if not write_bytes:
        return False
    stripped = write_bytes.rstrip(b"\x00")
    candidates = [write_bytes]
    if stripped and stripped != write_bytes:
        candidates.append(stripped)
    for source in payload_sources:
        payload = source.get("bytes") or b""
        if not payload:
            continue
        for candidate in candidates:
            if candidate and (candidate in payload or payload in candidate):
                return True
    return False


def _access_bytes(access: dict) -> bytes:
    text = str(access.get("bytes") or "").strip()
    if not text:
        return b""
    try:
        return bytes.fromhex(text.replace(" ", ""))
    except ValueError:
        return b""


def _snapshot_registers(snapshot: dict, stage: str) -> dict:
    cpu = snapshot.get("cpu") if isinstance(snapshot.get("cpu"), dict) else {}
    payload = cpu.get(stage) if isinstance(cpu.get(stage), dict) else {}
    registers = payload.get("registers") if isinstance(payload.get("registers"), dict) else {}
    return {str(key).lower(): safe_int(value) for key, value in registers.items()}


def _slot_overlaps_access(slot: dict, offset: Optional[int], size: int, base: str = "rbp") -> bool:
    if offset is None or slot.get("base") != base:
        return False
    slot_offset = safe_int(slot.get("offset"))
    slot_size = safe_int(slot.get("size")) or 1
    if slot_offset is None:
        return False
    return offset < slot_offset + slot_size and offset + max(1, size) > slot_offset


def _attach_runtime_accesses(
    function_name: str,
    snapshots: list[dict],
    slots: dict[str, dict],
    payload_sources: list[dict],
    evidence_entries: list[dict],
) -> list[dict]:
    runtime_calls = []
    for snapshot in snapshots if isinstance(snapshots, list) else []:
        if function_name and snapshot.get("func") != function_name:
            continue
        before = _snapshot_registers(snapshot, "before")
        after = _snapshot_registers(snapshot, "after")
        rbp = after.get("rbp") or before.get("rbp") or after.get("ebp") or before.get("ebp")
        rsp = after.get("rsp") or before.get("rsp") or after.get("esp") or before.get("esp")
        effects = snapshot.get("effects") if isinstance(snapshot.get("effects"), dict) else {}
        if str(effects.get("kind") or "") == "call" or effects.get("external_symbol"):
            runtime_calls.append(
                {
                    "step": snapshot.get("step"),
                    "addr": snapshot.get("rip") or snapshot.get("eip"),
                    "target": effects.get("external_symbol") or effects.get("call_target"),
                    "instruction": snapshot.get("instr"),
                    "argument_registers_before_call": {
                        reg: safe_hex(before.get(reg)) for reg in X86_64_ARG_REGS if before.get(reg) is not None
                    },
                    "external_simulated": bool(effects.get("external_simulated")),
                }
            )
        memory = snapshot.get("memory") if isinstance(snapshot.get("memory"), dict) else {}
        for access_kind in ("writes", "reads"):
            for access in memory.get(access_kind, []) if isinstance(memory.get(access_kind), list) else []:
                addr = safe_int(access.get("addr"))
                size = safe_int(access.get("size")) or 1
                offset_rbp = addr - rbp if addr is not None and rbp is not None else None
                offset_rsp = addr - rsp if addr is not None and rsp is not None else None
                write_bytes = _access_bytes(access)
                payload_hit = _payload_overlap(write_bytes, payload_sources)
                runtime_entry = {
                    "step": snapshot.get("step"),
                    "instruction": snapshot.get("instr"),
                    "addr": safe_hex(addr),
                    "size": size,
                    "bytes": access.get("bytes"),
                    "source": access.get("source"),
                    "offset_rbp": offset_rbp,
                    "offset_rsp": offset_rsp,
                    "payload_overlap": payload_hit,
                    "external_symbol": effects.get("external_symbol"),
                }
                matched = False
                for slot in slots.values():
                    if _slot_overlaps_access(slot, offset_rbp, size, "rbp"):
                        target = "runtime_writes" if access_kind == "writes" else "runtime_reads"
                        slot[target].append(runtime_entry)
                        if payload_hit:
                            slot["payload_overlap"] = True
                            evidence_entries.append(
                                _evidence_entry(
                                    kind="runtime_write",
                                    confidence=0.86,
                                    function=function_name,
                                    slot=_slot_label(slot),
                                    claim="payload_overlap",
                                    evidence=runtime_entry,
                                    reason="Runtime write overlaps the configured payload in a local stack slot.",
                                )
                            )
                        matched = True
                if not matched and offset_rbp is not None and offset_rbp < 0:
                    slot = _merge_slot(
                        slots,
                        {
                            **_slot_from_access({"base": "rbp", "offset": offset_rbp, "expression": f"[rbp{offset_rbp:+#x}]"}),
                            "size": size,
                            "size_source": "observed_write",
                        },
                    )
                    target = "runtime_writes" if access_kind == "writes" else "runtime_reads"
                    slot[target].append(runtime_entry)
                    if payload_hit:
                        slot["payload_overlap"] = True
                        evidence_entries.append(
                            _evidence_entry(
                                kind="runtime_write",
                                confidence=0.82,
                                function=function_name,
                                slot=_slot_label(slot),
                                claim="payload_overlap",
                                evidence=runtime_entry,
                                reason="Runtime write creates and overlaps a local stack slot with payload bytes.",
                            )
                        )
    return runtime_calls


def _observed_write_size(slot: dict) -> Optional[int]:
    """Aggregate span of runtime writes landing in this slot, from its lowest
    write offset to its highest write end. Reflects bytes actually observed
    written at runtime (e.g. a strcpy source string + NUL, or a read() of N
    bytes) -- it is evidence of what happened during this trace, not a proof
    of the slot's declared/exact size."""
    writes = [w for w in slot.get("runtime_writes", []) if safe_int(w.get("offset_rbp")) is not None]
    if not writes:
        return None
    starts = [safe_int(w["offset_rbp"]) for w in writes]
    ends = [safe_int(w["offset_rbp"]) + max(1, safe_int(w.get("size")) or 1) for w in writes]
    span = max(ends) - min(starts)
    return span if span > 0 else None


def _estimate_slot_bound(slot: dict, rbp_offsets: list[int]) -> Optional[int]:
    """Distance from this slot's start to the next known rbp-relative offset
    (another slot, or the saved rbp at offset 0) -- an upper bound only, never
    a proven size."""
    offset = safe_int(slot.get("offset"))
    if offset is None or str(slot.get("base") or "") != "rbp":
        return None
    higher = sorted(o for o in rbp_offsets if o > offset)
    return higher[0] - offset if higher else None


def _finalize_slot_size(slot: dict, rbp_offsets: list[int]) -> None:
    """Resolve the slot's size-reporting fields under one hard rule: `size`
    is populated only when it is exact (source/DWARF, or an ABI register
    width -- see `_EXACT_SIZE_SOURCES`). Every other kind of evidence is real
    but not proof of the *whole* object's size, so it is kept in its own
    field and never substituted for `size`:

    - observed_write_size: bytes actually written into this slot during this
      trace (e.g. strcpy's source string + NUL, or a read() call). This is
      what happened during the run, not a declared/exact size -- a strcpy
      that writes 44 bytes into an 84-byte buffer must not report size=44.
    - estimated_bound: an UPPER bound only (distance to the next slot / the
      saved rbp) -- the object cannot be larger than this, but the true size
      could be much smaller. Never a lower bound, never treated as a size.
    """
    if str(slot.get("size_source") or "") in _EXACT_SIZE_SOURCES:
        slot["size_confidence"] = "exact"
        slot["size_reason"] = "size confirmed by source/DWARF type or ABI register width"
        slot["observed_write_size"] = _observed_write_size(slot)
        return

    slot["size"] = None
    slot["size_source"] = "unknown"
    slot["size_confidence"] = "low"
    observed = _observed_write_size(slot)
    slot["observed_write_size"] = observed
    bound = _estimate_slot_bound(slot, rbp_offsets)
    slot["estimated_bound"] = bound

    reasons = ["no exact size available (no source/DWARF, no ABI register)"]
    if observed is not None:
        reasons.append(f"observed_write_size={observed} (bytes written during this trace, not a declared size)")
    if bound is not None:
        reasons.append(f"estimated_bound<={bound} (upper bound to the next slot/saved-rbp, not a size)")
    slot["size_reason"] = "; ".join(reasons)


def _finalize_function_slot_sizes(slots: dict[str, dict]) -> None:
    rbp_offsets = sorted(
        {0}
        | {
            safe_int(item.get("offset"))
            for item in slots.values()
            if str(item.get("base") or "") == "rbp" and safe_int(item.get("offset")) is not None
        }
    )
    for slot in slots.values():
        _finalize_slot_size(slot, rbp_offsets)


def _looks_like_char_array_slot(slot: dict) -> bool:
    type_name = str(slot.get("type") or "").lower()
    name = str(slot.get("name") or "").lower()
    return (
        ("char" in type_name or "byte" in type_name or "uint8" in type_name)
        and ("[" in type_name or "array" in type_name or slot.get("size"))
    ) or name in {"buf", "buff", "buffer"} or name.startswith(("buf_", "buffer_"))


def _score_slot(slot: dict, function_name: str, evidence_entries: list[dict]) -> dict:
    sources: list[str] = []
    reasons: list[str] = []
    is_buffer = False
    confidence = "low"

    if str(slot.get("source") or "").lower() in {"dwarf", "source", "source_c"} and _looks_like_char_array_slot(slot):
        is_buffer = True
        confidence = "exact"
        sources.append(str(slot.get("source")))
        reasons.append("source/DWARF declares a byte/char array")
        evidence_entries.append(
            _evidence_entry(
                kind=str(slot.get("source") or "source"),
                confidence=0.95,
                function=function_name,
                slot=_slot_label(slot),
                claim="buffer_candidate",
                evidence={"type": slot.get("type"), "name": slot.get("name")},
                reason="Source or DWARF type names this slot as a byte/char array.",
            )
        )

    if slot.get("passed_as_call_argument"):
        is_buffer = True
        confidence = "high" if confidence != "exact" else confidence
        sources.append("libc_call")
        targets = sorted({str(item.get("target")) for item in slot["passed_as_call_argument"] if item.get("target")})
        reasons.append(f"slot address is passed as destination to {', '.join(targets)}")
        for proof in slot["passed_as_call_argument"]:
            evidence_entries.append(
                _evidence_entry(
                    kind="call_argument",
                    confidence=0.9,
                    function=function_name,
                    slot=_slot_label(slot),
                    claim="buffer_candidate",
                    evidence=proof,
                    reason="Known buffer-writing call receives this slot as destination.",
                )
            )

    payload_writes = [
        item for item in slot.get("runtime_writes", [])
        if item.get("payload_overlap") and item.get("offset_rbp") is not None and item.get("offset_rbp") < 0
    ]
    if payload_writes:
        is_buffer = True
        if confidence not in {"exact", "high"}:
            confidence = "medium"
        sources.extend(["runtime", "payload"])
        reasons.append("runtime observes payload bytes written to a local stack slot")
        for write in payload_writes:
            evidence_entries.append(
                _evidence_entry(
                    kind="runtime_write",
                    confidence=0.86,
                    function=function_name,
                    slot=_slot_label(slot),
                    claim="buffer_candidate",
                    evidence=write,
                    reason="Payload bytes are written into this local slot at runtime.",
                )
            )

    if slot.get("asm_instructions"):
        sources.append("asm")
    if slot.get("runtime_writes") or slot.get("runtime_reads"):
        sources.append("runtime")

    if not reasons:
        if slot.get("size") and safe_int(slot.get("size")) >= 16:
            reasons.append("rejected: size >= 16 is not enough without source/libc/runtime payload proof")
        elif slot.get("asm_instructions"):
            reasons.append("ASM stack access only; no buffer destination proof")
        else:
            reasons.append("no buffer proof")

    slot["evidence_sources"] = sorted(set(filter(None, sources)))
    slot["confidence"] = confidence
    slot["classification"] = "buffer" if is_buffer else ("probable_local" if slot.get("kind") == "probable_local" else "stack_slot")
    slot["reason"] = "; ".join(reasons)
    return slot


def build_stack_evidence_audit(
    binary_path: str,
    config: TraceConfigLike,
    snapshots: list[dict],
    functions: list[dict],
    disassembly: list[dict],
) -> dict:
    plt_symbols = audit_plt_symbols(binary_path)
    ranges = function_ranges(functions)
    payload_sources = _config_payload_sources(config)
    output = {
        "binary": _normalize_path(binary_path),
        "payload_sources": [
            {"source": item["source"], "byteLength": len(item.get("bytes") or b""), "hex": (item.get("bytes") or b"").hex()}
            for item in payload_sources
        ],
        "functions": [],
        "rules": {
            "buffer_allowed_when": [
                "source_or_dwarf_char_byte_array",
                "slot_address_passed_as_destination_to_known_buffer_sink",
                "runtime_payload_write_to_clear_local_destination",
            ],
            "size_only": "rejected",
        },
    }
    for function in functions if isinstance(functions, list) else []:
        function_name = str(function.get("name") or "")
        evidence_entries: list[dict] = []
        frame, frame_slots = _frame_slots(binary_path, function)
        slots = {slot["key"]: slot for slot in frame_slots}
        function_lines = _line_in_function_ranges(disassembly, function, ranges)
        frame_allocations, rbp_accesses, rsp_accesses, static_call_sites = _track_static_slot_evidence(
            function_name,
            function_lines,
            slots,
            plt_symbols,
            evidence_entries,
        )
        runtime_call_sites = _attach_runtime_accesses(
            function_name,
            snapshots,
            slots,
            payload_sources,
            evidence_entries,
        )
        _finalize_function_slot_sizes(slots)
        scored = [_score_slot(slot, function_name, evidence_entries) for slot in slots.values()]
        scored.sort(key=lambda slot: (safe_int(slot.get("offset")) is None, safe_int(slot.get("offset")) or 0, slot.get("key")))
        inferred_buffers = [slot for slot in scored if slot.get("classification") == "buffer"]
        rejected = [
            {
                "key": slot.get("key"),
                "offset": slot.get("offset"),
                "size": slot.get("size"),
                "classification": slot.get("classification"),
                "confidence": slot.get("confidence"),
                "reason": slot.get("reason"),
                "evidence_sources": slot.get("evidence_sources"),
            }
            for slot in scored
            if slot.get("classification") != "buffer"
        ]
        call_sites = static_call_sites
        runtime_by_addr = {str(item.get("addr") or ""): item for item in runtime_call_sites}
        for call_site in call_sites:
            runtime = runtime_by_addr.get(str(call_site.get("addr") or ""))
            if runtime:
                call_site["runtime"] = runtime
        known_static_addrs = {str(item.get("addr") or "") for item in call_sites}
        call_sites.extend(
            item for item in runtime_call_sites
            if str(item.get("addr") or "") not in known_static_addrs
        )
        output["functions"].append(
            {
                "name": function.get("name"),
                "addr": function.get("addr"),
                "frame_size": safe_int(frame.get("frame_size")) if isinstance(frame, dict) else 0,
                "frame_allocations": frame_allocations,
                "rbp_accesses": rbp_accesses,
                "rsp_accesses": rsp_accesses,
                "stack_accesses": rbp_accesses + rsp_accesses,
                "local_slots": scored,
                "call_sites": call_sites,
                "argument_registers_before_call": [
                    {
                        "call_addr": call.get("addr"),
                        "target": call.get("target"),
                        "registers": call.get("argument_registers_before_call"),
                    }
                    for call in call_sites
                ],
                "evidence_entries": evidence_entries,
                "inferred_buffer_candidates": inferred_buffers,
                "inferred_buffers": inferred_buffers,
                "rejected_candidates": rejected,
                "rejected_buffer_candidates": rejected,
            }
        )
    return output
