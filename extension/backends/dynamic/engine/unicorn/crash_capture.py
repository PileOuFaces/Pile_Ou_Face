# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

from .memory_mapping import _hex_opt, _read_register_dump, _read_snapshot_registers


def _build_crash_reason(kind: str, error: str, instruction_text: str = "") -> str:
    instr = str(instruction_text or "").strip().lower()
    if kind == "unmapped_read":
        return "Lecture sur une adresse non mappee pendant l'execution."
    if kind == "unmapped_write":
        return "Ecriture sur une adresse non mappee pendant l'execution."
    if kind == "unmapped_fetch":
        if instr.startswith("ret"):
            return "Retour vers une adresse non executable ou non mappee."
        if instr.startswith("jmp") or instr.startswith("call"):
            return "Saut vers une adresse non executable ou non mappee."
        return "Execution sur une adresse non executable ou non mappee."
    if "UC_ERR_FETCH_UNMAPPED" in error:
        return "Execution sur une adresse non mappee."
    if "UC_ERR_READ_UNMAPPED" in error:
        return "Lecture sur une adresse non mappee."
    if "UC_ERR_WRITE_UNMAPPED" in error:
        return "Ecriture sur une adresse non mappee."
    return f"Erreur Unicorn: {error}"


def _finalize_crash_report(
    collector,
    uc,
    arch_bits: int,
    error: str,
    state: dict | None = None,
) -> dict | None:
    crash_ctx = state.get("crash_context") if isinstance(state, dict) else None
    last_snapshot = (
        collector.snapshots[-1] if getattr(collector, "snapshots", None) else None
    )
    fallback_regs = _read_register_dump(uc, arch_bits)
    snapshot_regs = (
        _read_snapshot_registers(last_snapshot, "after")
        if isinstance(last_snapshot, dict)
        else {}
    )
    registers = dict(snapshot_regs or fallback_regs)
    if not registers:
        registers = fallback_regs
    ip_name = "eip" if arch_bits == 32 else "rip"
    sp_name = "esp" if arch_bits == 32 else "rsp"
    bp_name = "ebp" if arch_bits == 32 else "rbp"
    instruction_address = None
    instruction_text = ""
    if isinstance(last_snapshot, dict):
        instruction_address = (
            last_snapshot.get(ip_name)
            or last_snapshot.get("eip")
            or last_snapshot.get("rip")
        )
        instruction_text = str(last_snapshot.get("instr") or "").strip()
    if not instruction_address:
        instruction_address = registers.get(ip_name)
    crash_type = (
        str(
            (crash_ctx or {}).get("type")
            or (
                "unmapped_fetch"
                if "FETCH_UNMAPPED" in error
                else "unmapped_write"
                if "WRITE_UNMAPPED" in error
                else "unmapped_read"
                if "READ_UNMAPPED" in error
                else "runtime_error"
            )
        ).strip()
        or "runtime_error"
    )
    fault_address = (crash_ctx or {}).get("faultAddress")
    if not fault_address and crash_type == "unmapped_fetch":
        fault_address = registers.get(ip_name)
    return {
        "type": crash_type,
        "step": int(getattr(collector, "step", 0) or 0),
        "instructionAddress": str(instruction_address or ""),
        "instructionText": instruction_text,
        "registers": registers,
        ip_name: registers.get(ip_name),
        sp_name: registers.get(sp_name),
        bp_name: registers.get(bp_name),
        "faultAddress": fault_address,
        "faultSize": (crash_ctx or {}).get("faultSize"),
        "faultValue": (crash_ctx or {}).get("faultValue"),
        "memoryAccess": (crash_ctx or {}).get("memoryAccess"),
        "reason": _build_crash_reason(crash_type, error, instruction_text),
        "unicornError": str(error or ""),
    }


def _record_crash_context(
    state: dict,
    kind: str,
    uc_engine,
    address: int | None = None,
    size: int | None = None,
    value: int | None = None,
) -> None:
    if not isinstance(state, dict):
        return
    try:
        pc = int(uc_engine.reg_read(state["pc_reg"]))
    except Exception:
        pc = None
    state["crash_context"] = {
        "type": kind,
        "faultAddress": _hex_opt(address),
        "faultSize": int(size) if isinstance(size, int) else None,
        "faultValue": _hex_opt(value),
        "memoryAccess": kind.replace("unmapped_", ""),
        "pc": _hex_opt(pc),
    }
