#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Lance la pipeline dynamique et genere output.json.

Orchestration trace runtime, disasm optionnel, et payload unifie.
Voir backends/dynamic/README.md.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys

# ROOT: backends/dynamic/pipeline/ -> project root (three levels up)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.dynamic.core.interfaces import ExecutionEngine, TraceConfigLike
from backends.dynamic.pipeline.audit import (
    audit_enabled,
    build_elf_layout_audit,
    build_stack_evidence_audit,
    write_audit_json,
)
from backends.dynamic.pipeline.diagnostics import (
    _has_control_corruption_evidence,
    _is_win_addr,
    build_diagnostics,
)
from backends.dynamic.pipeline.stack_model import _hex, build_dynamic_analysis

try:
    from backends.static.disasm.disasm import disassemble_with_capstone
except Exception:  # pragma: no cover - compatibility with flat v0.1.0 layout
    from backends.static.disasm import disassemble_with_capstone

try:
    from backends.static.binary.symbols import extract_symbols
except Exception:
    try:
        from backends.static.symbols import extract_symbols
    except Exception:
        extract_symbols = None


def _default_engine() -> ExecutionEngine:
    from backends.dynamic.engine.unicorn import create_engine

    return create_engine()


def _expand_payload_expression(text: str | None) -> str:
    if text is None:
        return ""
    value = text.strip()
    if not value:
        return ""
    if "+" not in value and "*" not in value:
        return value
    parts = [p.strip() for p in value.split("+") if p.strip()]
    out: list[str] = []
    for part in parts:
        m = re.match(r"^(.+?)\*(\d+)$", part)
        if m:
            out.append(m.group(1) * int(m.group(2)))
        else:
            out.append(part)
    return "".join(out)


def _normalize_path(path: str) -> str:
    cwd = os.getcwd()
    if path.startswith(cwd + os.sep):
        return os.path.relpath(path, cwd)
    return path


def _load_binary(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _load_function_symbols(binary_path: str) -> list[dict]:
    if extract_symbols is None:
        return []
    try:
        raw = extract_symbols(binary_path, defined_only=True)
    except Exception:
        return []
    out = []
    for symbol in raw if isinstance(raw, list) else []:
        if str(symbol.get("type") or "").lower() != "t":
            continue
        addr = str(symbol.get("addr") or "").strip()
        if not addr or addr == "0x0":
            continue
        out.append(
            {
                "name": str(symbol.get("name") or "").strip(),
                "addr": addr,
                "size": symbol.get("size"),
                "type": str(symbol.get("type") or "T"),
            }
        )
    return out


def _parse_int(value) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return int(value)
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        if re.fullmatch(r"[0-9a-f]+", text):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _stack_evidence_summary(stack_evidence: dict | None) -> dict | None:
    if not isinstance(stack_evidence, dict):
        return None
    functions_payload = stack_evidence.get("functions", [])
    functions_available = isinstance(functions_payload, list) and bool(functions_payload)
    buffers = []
    slots = []
    local_slots = []
    stack_arguments = []
    register_arguments = []
    rejected_candidates = []
    for function in functions_payload if functions_available else []:
        if not isinstance(function, dict):
            continue
        function_name = function.get("name")
        function_addr = function.get("addr")
        # local_slots (the evidence function key, not the summary bucket below) holds
        # every scored candidate: probable_local, stack_argument, register_argument,
        # stack_slot, buffer. It is the single source stack_model.py types slots from,
        # including confirmed buffers and rejected buffer candidates.
        for slot in function.get("local_slots", []) if isinstance(function.get("local_slots"), list) else []:
            if not isinstance(slot, dict):
                continue
            kind = str(slot.get("kind") or "")
            offset = _parse_int(slot.get("offset"))
            if offset is None and kind != "register_argument":
                continue
            entry = {
                "function": function_name,
                "function_addr": function_addr,
                "key": slot.get("key"),
                "base": slot.get("base") or "rbp",
                "offset": offset,
                "offset_label": slot.get("offset_label"),
                "size": _parse_int(slot.get("size")),
                "size_source": slot.get("size_source"),
                "observed_write_size": _parse_int(slot.get("observed_write_size")),
                "estimated_bound": _parse_int(slot.get("estimated_bound")),
                "size_confidence": slot.get("size_confidence"),
                "size_reason": slot.get("size_reason"),
                "kind": slot.get("kind"),
                "classification": slot.get("classification"),
                "confidence": slot.get("confidence"),
                "evidence_sources": slot.get("evidence_sources") or [],
                "reason": slot.get("reason"),
            }
            slots.append(entry)
            classification = str(entry["classification"] or "")
            if classification == "buffer" and offset is not None:
                buffers.append(entry)
            else:
                rejected_candidates.append(entry)
            if kind == "probable_local":
                local_slots.append(entry)
            elif kind == "stack_argument":
                stack_arguments.append(entry)
            elif kind == "register_argument":
                register_arguments.append(entry)
    return {
        "available": functions_available,
        "buffer_count": len(buffers),
        "buffer_offsets": [
            item.get("offset_label") or f"{item.get('base') or 'rbp'}{int(item['offset']):+#x}"
            for item in buffers
        ],
        "buffers": buffers,
        "slots": slots,
        "local_slots": local_slots,
        "stack_arguments": stack_arguments,
        "register_arguments": register_arguments,
        "rejected_candidates": rejected_candidates,
    }


def _trace_probable_source(meta: dict) -> str:
    input_meta = meta.get("input") if isinstance(meta.get("input"), dict) else {}
    input_mode = str(input_meta.get("mode") or "").strip().lower()
    if input_mode == "file":
        return "file"
    target = str(meta.get("payload_target") or "").strip().lower()
    if target == "stdin":
        return "stdin"
    if target == "both":
        return "stdin + argv[1]"
    if target == "argv1":
        return "argv[1]"
    return "payload"


def _payload_offset_from_bytes(meta: dict, bytes_hex: str) -> int | None:
    needle = str(bytes_hex or "").replace(" ", "").lower()
    if not needle:
        return None
    payload_hex = str(meta.get("payload_hex") or "").replace(" ", "").lower()
    if not payload_hex:
        return None
    index = payload_hex.find(needle)
    return index // 2 if index >= 0 and index % 2 == 0 else None


def _build_code_ranges(meta: dict, disasm_lines: list[dict]) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    for function in (
        meta.get("functions") if isinstance(meta.get("functions"), list) else []
    ):
        if not isinstance(function, dict):
            continue
        addr = _parse_int(function.get("addr"))
        size = _parse_int(function.get("size"))
        if addr is not None and size and size > 0:
            ranges.append((addr, addr + size))
    addrs = [
        _parse_int(line.get("addr"))
        for line in disasm_lines
        if isinstance(line, dict) and line.get("addr") is not None
    ]
    addrs = [addr for addr in addrs if addr is not None]
    if addrs:
        ranges.append((min(addrs), max(addrs) + 0x10))
    return ranges


def _is_code_address(value: int | None, code_ranges: list[tuple[int, int]]) -> bool:
    if value is None:
        return False
    return any(start <= value < end for start, end in code_ranges)


def _analysis_slot(analysis: dict, slot_kind: str) -> dict | None:
    slots = (
        analysis.get("frame", {}).get("slots") if isinstance(analysis, dict) else None
    )
    if not isinstance(slots, list):
        return None
    for slot in slots:
        if not isinstance(slot, dict):
            continue
        role = str(slot.get("role") or slot.get("kind") or "").strip().lower()
        if role == slot_kind:
            return slot
    return None


def _slot_offset_label(slot: dict) -> str | None:
    if not isinstance(slot, dict):
        return None
    return (
        str(
            slot.get("offsetFromBpHex")
            or slot.get("offset")
            or slot.get("offsetLabel")
            or ""
        ).strip()
        or None
    )


def _slot_address_label(slot: dict) -> str | None:
    if not isinstance(slot, dict):
        return None
    for key in ("start", "address", "addr"):
        value = str(slot.get(key) or "").strip()
        if value:
            return value
    return None


def _slot_value_text(slot: dict, analysis: dict, slot_kind: str) -> str | None:
    if isinstance(slot, dict):
        for key in ("valueHex", "valueDisplay", "value"):
            value = str(slot.get(key) or "").strip()
            if value:
                return value
    control = (
        analysis.get("control") if isinstance(analysis.get("control"), dict) else {}
    )
    if slot_kind == "return_address":
        return str(control.get("retValue") or "").strip() or None
    if slot_kind == "saved_bp":
        return str(control.get("savedBpValue") or "").strip() or None
    return None


def _guess_crash_slot(
    crash: dict, analysis: dict, meta: dict, disasm_lines: list[dict]
) -> tuple[dict | None, str | None, int | None]:
    if not isinstance(crash, dict) or not isinstance(analysis, dict):
        return None, None, None
    code_ranges = _build_code_ranges(meta, disasm_lines)
    registers = (
        crash.get("registers") if isinstance(crash.get("registers"), dict) else {}
    )
    arch_bits = 32 if int(meta.get("arch_bits") or 64) == 32 else 64
    ip_name = "eip" if arch_bits == 32 else "rip"
    bp_name = "ebp" if arch_bits == 32 else "rbp"
    ip_value = _parse_int(
        crash.get(ip_name) or registers.get(ip_name) or crash.get("faultAddress")
    )
    bp_value = _parse_int(crash.get(bp_name) or registers.get(bp_name))
    crash_type = str(crash.get("type") or "").strip().lower()
    instruction = str(crash.get("instructionText") or "").strip().lower()

    ret_slot = _analysis_slot(analysis, "return_address")
    if ret_slot is not None:
        ret_value = _parse_int(_slot_value_text(ret_slot, analysis, "return_address"))
        if (
            crash_type == "unmapped_fetch"
            or instruction.startswith("ret")
            or instruction.startswith("jmp")
            or instruction.startswith("call")
        ) and (
            ret_value is None
            or ip_value is None
            or ret_value == ip_value
            or not _is_code_address(ip_value, code_ranges)
        ):
            bytes_hex = str(ret_slot.get("bytesHex") or "").strip()
            return (
                {
                    "kind": "return_address",
                    "offset": _slot_offset_label(ret_slot),
                    "address": _slot_address_label(ret_slot),
                },
                bytes_hex or None,
                _payload_offset_from_bytes(meta, bytes_hex),
            )

    saved_bp_slot = _analysis_slot(analysis, "saved_bp")
    if saved_bp_slot is not None and (
        instruction.startswith("leave")
        or crash_type in {"unmapped_read", "unmapped_write"}
    ):
        saved_bp_value = _parse_int(
            _slot_value_text(saved_bp_slot, analysis, "saved_bp")
        )
        if (
            saved_bp_value is None
            or bp_value is None
            or saved_bp_value == bp_value
            or not _is_code_address(bp_value, code_ranges)
        ):
            bytes_hex = str(saved_bp_slot.get("bytesHex") or "").strip()
            return (
                {
                    "kind": "saved_bp",
                    "offset": _slot_offset_label(saved_bp_slot),
                    "address": _slot_address_label(saved_bp_slot),
                },
                bytes_hex or None,
                _payload_offset_from_bytes(meta, bytes_hex),
            )

    return None, None, None


def _classify_crash(
    fault_addr: int | None,
    ret_target: int | None,
    ip_after: int | None,
    meta: dict,
    code_ranges: list[tuple[int, int]],
) -> str:
    target = (
        ret_target
        if ret_target is not None
        else (fault_addr if fault_addr is not None else ip_after)
    )
    if target is None:
        return "fatal_crash"
    if _is_win_addr(target, meta):
        return "ret2win_success"
    if _is_code_address(target, code_ranges):
        return "control_hijack"
    return "fatal_crash"


def _build_crash_report(
    raw_crash: dict | None,
    snapshots: list[dict],
    analysis_by_step: dict[str, dict],
    meta: dict,
    disasm_lines: list[dict] | None = None,
) -> dict | None:
    if not isinstance(raw_crash, dict):
        return None
    step = int(raw_crash.get("step") or 0)
    snapshot = snapshots[step - 1] if step > 0 and step <= len(snapshots) else None
    analysis = (
        analysis_by_step.get(str(step))
        if step > 0 and isinstance(analysis_by_step, dict)
        else None
    )
    registers = (
        raw_crash.get("registers")
        if isinstance(raw_crash.get("registers"), dict)
        else {}
    )
    arch_bits = 32 if int(meta.get("arch_bits") or 64) == 32 else 64
    ip_name = "eip" if arch_bits == 32 else "rip"
    sp_name = "esp" if arch_bits == 32 else "rsp"
    bp_name = "ebp" if arch_bits == 32 else "rbp"
    instruction_address = str(
        raw_crash.get("instructionAddress")
        or (snapshot.get(ip_name) if isinstance(snapshot, dict) else "")
        or ""
    ).strip()
    instruction_text = str(
        raw_crash.get("instructionText")
        or (snapshot.get("instr") if isinstance(snapshot, dict) else "")
        or ""
    ).strip()
    suspect_slot, suspect_bytes, payload_offset = _guess_crash_slot(
        raw_crash,
        analysis or {},
        meta,
        disasm_lines or [],
    )
    crash_type = (
        str(raw_crash.get("type") or "runtime_error").strip() or "runtime_error"
    )
    fault_address = _parse_int(raw_crash.get("faultAddress"))
    ip_after = _parse_int(raw_crash.get(ip_name) or registers.get(ip_name))
    if (
        crash_type == "unmapped_fetch"
        and instruction_text.lower().startswith("ret")
        and (fault_address == 0 or ip_after == 0)
        and payload_offset is None
    ):
        return None
    # Determine what the return slot was overwritten to (for classification).
    ret_target: int | None = None
    if (
        suspect_slot
        and str(suspect_slot.get("kind") or "").strip().lower() == "return_address"
        and analysis
    ):
        ret_slot_data = _analysis_slot(analysis, "return_address")
        if ret_slot_data:
            ret_target = _parse_int(
                _slot_value_text(ret_slot_data, analysis, "return_address")
            )
    code_ranges = _build_code_ranges(meta, disasm_lines or [])
    classification = _classify_crash(
        fault_addr=fault_address,
        ret_target=ret_target,
        ip_after=ip_after,
        meta=meta,
        code_ranges=code_ranges,
    )
    if classification == "fatal_crash" and not _has_control_corruption_evidence(analysis or {}, payload_offset):
        # No overflow reached a control slot, no write was flagged on one, and
        # the faulting bytes don't match the configured payload: this isn't a
        # vulnerability, it's execution running past a boundary the emulator
        # doesn't model (classic hello-world/printf-only: main returns into
        # un-emulated libc and Unicorn faults on the fetch).
        classification = "benign_termination" if instruction_text.lower().startswith("ret") else "emulator_stop"
    function_meta = (
        analysis.get("function")
        if isinstance(analysis, dict) and isinstance(analysis.get("function"), dict)
        else {}
    )
    return {
        "type": crash_type,
        "step": step,
        "function": str(
            raw_crash.get("function")
            or function_meta.get("name")
            or (snapshot.get("func") if isinstance(snapshot, dict) else "")
            or ""
        ).strip(),
        "instructionAddress": instruction_address,
        "instructionText": instruction_text,
        "registers": registers,
        ip_name: raw_crash.get(ip_name) or registers.get(ip_name),
        sp_name: raw_crash.get(sp_name) or registers.get(sp_name),
        bp_name: raw_crash.get(bp_name) or registers.get(bp_name),
        "memoryAddress": str(raw_crash.get("faultAddress") or "").strip() or None,
        "memoryAccess": str(raw_crash.get("memoryAccess") or "").strip() or None,
        "unicornError": str(raw_crash.get("unicornError") or "").strip(),
        "reason": str(raw_crash.get("reason") or "").strip()
        or "Crash runtime Unicorn.",
        "suspectOverwrittenSlot": suspect_slot,
        "suspectBytes": suspect_bytes,
        # Never assert a payload/input link without evidence: benign_termination
        # and emulator_stop are, by construction, the no-evidence outcomes.
        "payloadOffset": None if classification in ("benign_termination", "emulator_stop") else payload_offset,
        "probableSource": (
            None
            if classification in ("benign_termination", "emulator_stop")
            else _trace_probable_source(meta)
        ),
        "classification": classification,
        "retTarget": _hex(ret_target) if ret_target is not None else None,
    }


def run_pipeline(
    binary_path: str,
    source_path: str | None,
    config: TraceConfigLike,
    output_path: str | None,
    engine: ExecutionEngine | None = None,
) -> dict:
    code = _load_binary(binary_path)
    runtime = engine if engine is not None else _default_engine()
    write_audit_json(output_path, "02-trace-config.json", config)
    trace = runtime.trace_binary(code, config, binary_path)
    write_audit_json(output_path, "03-unicorn-raw-result.json", trace)
    risks: list[dict] = []
    disasm = None
    if output_path:
        disasm_path = _derive_disasm_path(output_path)
        disasm = _build_disasm(binary_path, output_path=disasm_path)
    functions = _load_function_symbols(binary_path)
    if audit_enabled():
        write_audit_json(
            output_path,
            "03a-elf-layout-and-analysis.json",
            build_elf_layout_audit(
                binary_path,
                code,
                config,
                trace,
                disasm.get("lines") if disasm else None,
                functions,
            ),
        )
    meta = {
        **trace.get("meta", {}),
        "dynamic_model_version": 2,
        "binary": _normalize_path(binary_path),
        "source": _normalize_path(source_path) if source_path else None,
        "functions": functions,
        "disasm_path": os.path.abspath(disasm.get("path")) if disasm else None,
        "disasm": disasm.get("lines") if disasm else None,
    }
    snapshots = trace.get("snapshots", [])
    stack_evidence_audit = build_stack_evidence_audit(
        binary_path,
        config,
        snapshots,
        functions,
        disasm.get("lines") if disasm else [],
    )
    stack_evidence_summary = _stack_evidence_summary(stack_evidence_audit)
    analysis_meta = dict(meta)
    if stack_evidence_summary is not None:
        analysis_meta["_stack_evidence"] = stack_evidence_summary
    if audit_enabled():
        meta["debug"] = {
            **(meta.get("debug") if isinstance(meta.get("debug"), dict) else {}),
            "evidence_buffer_count": (stack_evidence_summary or {}).get("buffer_count", 0),
            "evidence_buffer_offsets": (stack_evidence_summary or {}).get("buffer_offsets", []),
        }
        analysis_meta["debug"] = meta["debug"]
        write_audit_json(
            output_path,
            "03b-stack-evidence.json",
            stack_evidence_audit,
        )
    write_audit_json(output_path, "04-snapshots-raw.json", snapshots)
    write_audit_json(
        output_path,
        "05-stack-model-input.json",
        {
            "snapshots": snapshots,
            "meta": analysis_meta,
            "binary_path": binary_path,
            "disasm_lines": disasm.get("lines") if disasm else None,
        },
    )
    analysis_by_step = build_dynamic_analysis(
        snapshots,
        analysis_meta,
        binary_path,
        disasm_lines=disasm.get("lines") if disasm else None,
    )
    write_audit_json(output_path, "06-analysis-by-step.json", analysis_by_step)
    if getattr(config, "buffer_offset", None) is not None and getattr(config, "buffer_size", None) is not None:
        meta["buffer_source"] = "user"
    elif any(
        isinstance(step_analysis, dict) and step_analysis.get("buffer") is not None
        for step_analysis in analysis_by_step.values()
    ):
        meta["buffer_source"] = "detected"
    else:
        meta["buffer_source"] = "none"
    crash = _build_crash_report(
        trace.get("crash") if isinstance(trace, dict) else None,
        snapshots,
        analysis_by_step,
        meta,
        disasm_lines=disasm.get("lines") if disasm else None,
    )
    trace_meta = trace.get("meta") if isinstance(trace, dict) and isinstance(trace.get("meta"), dict) else {}
    steps_executed = _parse_int(trace_meta.get("steps"))
    configured_max_steps = _parse_int(getattr(config, "max_steps", None))
    max_steps_reached = bool(
        crash is None
        and steps_executed is not None
        and configured_max_steps
        and steps_executed >= configured_max_steps
    )
    diagnostics = build_diagnostics(
        snapshots,
        analysis_by_step,
        meta,
        disasm_lines=disasm.get("lines") if disasm else None,
        crash=crash,
        max_steps_reached=max_steps_reached,
    )
    write_audit_json(
        output_path,
        "07-diagnostics-input-output.json",
        {
            "input": {
                "snapshots": snapshots,
                "analysis_by_step": analysis_by_step,
                "meta": meta,
                "disasm_lines": disasm.get("lines") if disasm else None,
                "crash": crash,
                "max_steps_reached": max_steps_reached,
            },
            "output": diagnostics,
        },
    )
    return {
        "snapshots": snapshots,
        "risks": risks,
        "analysisByStep": analysis_by_step,
        "diagnostics": diagnostics,
        "crash": crash,
        "meta": meta,
    }


def _build_disasm(binary_path: str, output_path: str) -> dict | None:
    structured = _build_disasm_with_capstone(binary_path, output_path)
    if structured is not None:
        return structured
    return _build_disasm_with_objdump(binary_path, output_path)


def _build_disasm_with_capstone(binary_path: str, output_path: str) -> dict | None:
    try:
        lines = disassemble_with_capstone(binary_path)
    except Exception:
        return None
    if not isinstance(lines, list) or not lines:
        return None

    rendered_lines = []
    output_lines = []
    for idx, entry in enumerate(lines, start=1):
        if not isinstance(entry, dict):
            continue
        addr = str(entry.get("addr") or "").strip().lower()
        if not addr:
            continue
        addr_text = addr[2:] if addr.startswith("0x") else addr
        bytes_text = str(entry.get("bytes") or "").strip()
        mnemonic = str(entry.get("mnemonic") or "").strip()
        operands = str(entry.get("operands") or "").strip()
        asm_text = f"{mnemonic} {operands}".strip()
        raw = f"{addr_text}:\t{bytes_text}\t{asm_text}".rstrip()
        output_lines.append(raw)
        rendered_lines.append(
            {
                "addr": addr,
                "text": str(entry.get("text") or asm_text),
                "raw": raw,
                "bytes": bytes_text,
                "mnemonic": mnemonic,
                "operands": operands,
                "line": idx,
            }
        )

    if not rendered_lines:
        return None
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(output_lines) + "\n")
    return {"path": output_path, "lines": rendered_lines}


def _build_disasm_with_objdump(binary_path: str, output_path: str) -> dict | None:
    if not shutil.which("objdump"):
        return None
    try:
        result = subprocess.run(
            ["objdump", "-d", "-M", "intel", binary_path],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if result.returncode != 0:
        return None
    lines = []
    for idx, line in enumerate(result.stdout.splitlines(), start=1):
        match = re.match(r"^\s*([0-9a-fA-F]+):\s*(.*)$", line)
        if not match:
            continue
        addr = f"0x{match.group(1).lower()}"
        text_line = match.group(2).strip()
        lines.append({"addr": addr, "text": text_line, "raw": line, "line": idx})
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(result.stdout)
    return {"path": output_path, "lines": lines}


def _derive_disasm_path(output_path: str) -> str:
    if output_path.endswith(".json"):
        return output_path[: -len(".json")] + ".disasm.asm"
    return output_path + ".disasm.asm"


def _main(argv: list[str] | None = None) -> int:
    from backends.dynamic.engine.unicorn.config import TraceConfig

    parser = argparse.ArgumentParser(description="Generate a trace JSON with Unicorn")
    parser.add_argument("--binary", required=True, help="Raw x86_64 binary")
    parser.add_argument("--output", default="output.json", help="Output JSON path")
    parser.add_argument(
        "--base", default="0x400000", help="Base address for raw/PIE binaries"
    )
    parser.add_argument("--stack-base", default="0x7ffffffde000", help="Stack base")
    parser.add_argument(
        "--stack-size", type=int, default=0x100000, help="Stack size bytes"
    )
    parser.add_argument("--max-steps", type=int, default=200, help="Max instructions")
    parser.add_argument("--stack-entries", type=int, default=24, help="Stack entries")
    parser.add_argument(
        "--arch-bits", type=int, default=64, choices=[32, 64], help="Architecture bits"
    )
    parser.add_argument(
        "--start-interp", action="store_true", help="Start at ELF interpreter"
    )
    parser.add_argument("--stdin", default="", help="Inject data for read(0, ...)")
    parser.add_argument("--stdin-hex", default=None, help="Inject raw bytes (hex)")
    parser.add_argument(
        "--buffer-offset", type=int, default=None, help="Buffer offset from RBP"
    )
    parser.add_argument(
        "--buffer-size", type=int, default=None, help="Buffer size in bytes"
    )
    parser.add_argument(
        "--start-symbol", default=None, help="Start at symbol (e.g. main)"
    )
    parser.add_argument("--stop-symbol", default=None, help="Stop at symbol")
    parser.add_argument(
        "--no-capture-binary", action="store_true", help="Capture outside binary"
    )
    parser.add_argument("--argv1", default=None, help="Set argv[1]")
    parser.add_argument(
        "--argv1-hex", default=None, help="Set argv[1] from raw bytes (hex, no NUL)"
    )
    parser.add_argument(
        "--virtual-file",
        action="append",
        default=[],
        metavar="GUEST=HOST",
        help="Expose HOST bytes as guest path for simulated fopen/fscanf/fgetc",
    )
    parser.add_argument("--patch-at-rip", default=None, metavar="HEX")
    parser.add_argument("--patch-rbp-offset", default=None, metavar="INT")
    parser.add_argument("--patch-value", default=None, metavar="HEX")
    parser.add_argument("--patch-payload", default=None, metavar="HEX")
    parser.add_argument("--inject-at-start", action="store_true")
    args = parser.parse_args(argv)

    stdin_text = _expand_payload_expression(args.stdin)
    stdin_data = stdin_text.encode("utf-8", errors="ignore")
    if args.stdin_hex:
        cleaned = args.stdin_hex.replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        try:
            stdin_data = bytes.fromhex(cleaned)
        except ValueError as err:
            raise SystemExit("Invalid --stdin-hex") from err

    argv1_data = None
    if args.argv1_hex:
        cleaned = args.argv1_hex.replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        try:
            argv1_data = bytes.fromhex(cleaned)
        except ValueError as err:
            raise SystemExit("Invalid --argv1-hex") from err
        if b"\x00" in argv1_data:
            raise SystemExit(
                "Invalid --argv1-hex: NUL bytes cannot be passed through argv"
            )

    virtual_files = {}
    for spec in args.virtual_file or []:
        if "=" not in spec:
            raise SystemExit("Invalid --virtual-file, expected guest=host")
        guest, host = spec.split("=", 1)
        guest = guest.strip()
        host = host.strip()
        if not guest or not host:
            raise SystemExit("Invalid --virtual-file, expected guest=host")
        try:
            with open(host, "rb") as handle:
                virtual_files[guest] = handle.read()
        except OSError as exc:
            raise SystemExit(f"Invalid --virtual-file host: {exc}") from exc

    memory_patches = None
    stack_payload = None
    if (
        args.inject_at_start
        and args.patch_rbp_offset is not None
        and args.patch_payload is not None
    ):
        offset = int(args.patch_rbp_offset, 0)
        cleaned = args.patch_payload.strip().replace(" ", "").replace("\n", "")
        if cleaned.startswith("0x"):
            cleaned = cleaned[2:]
        payload_bytes = bytes.fromhex(cleaned)
        stack_payload = (offset, payload_bytes)
    elif args.patch_at_rip is not None and args.patch_rbp_offset is not None:
        rip = int(args.patch_at_rip, 16)
        offset = int(args.patch_rbp_offset, 0)
        if args.patch_payload is not None:
            cleaned = args.patch_payload.strip().replace(" ", "").replace("\n", "")
            if cleaned.startswith("0x"):
                cleaned = cleaned[2:]
            payload_bytes = bytes.fromhex(cleaned)
            memory_patches = [(rip, offset, payload_bytes)]
        elif args.patch_value is not None:
            val = int(args.patch_value, 16)
            if val < 0 or val > 0xFFFFFFFF:
                val = val & 0xFFFFFFFF
            memory_patches = [(rip, offset, val)]

    config = TraceConfig(
        base=int(args.base, 16),
        stack_base=int(args.stack_base, 16),
        stack_size=args.stack_size,
        max_steps=args.max_steps,
        stack_entries=args.stack_entries,
        arch_bits=args.arch_bits,
        interp_base=0x70000000 if args.arch_bits == 32 else 0x7F0000000000,
        start_interp=args.start_interp,
        stdin_data=stdin_data,
        buffer_offset=args.buffer_offset,
        buffer_size=args.buffer_size,
        start_symbol=args.start_symbol,
        stop_symbol=args.stop_symbol,
        argv1=(
            None
            if argv1_data is not None
            else (
                _expand_payload_expression(args.argv1)
                if args.argv1 is not None
                else None
            )
        ),
        argv1_data=argv1_data,
        capture_start_addr=None,
        loader_max_steps=None,
        capture_ranges=None if args.no_capture_binary else [],
        stop_addr=None,
        memory_patches=memory_patches,
        stack_payload=stack_payload,
        virtual_files=virtual_files or None,
    )

    payload = run_pipeline(args.binary, None, config, args.output)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2)
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())
