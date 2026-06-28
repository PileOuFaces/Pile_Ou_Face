# SPDX-License-Identifier: AGPL-3.0-only
# -----------------------------------------------------------------------------
# Instruction and memory hooks that collect coherent per-step snapshots.
# Captures structured instruction data, CPU before/after, stack accesses, and
# a byte-level stack window. Legacy fields remain derived for UI compatibility.
# -----------------------------------------------------------------------------

"""@file hooks.py
@brief Hooks Unicorn pour collecter des snapshots enrichis.

@details
Capture un modele d'execution coherent par step:
- instruction structuree,
- etat CPU before/after,
- acces memoire stack,
- fenetre stack byte-level,
- effets semantiques derives.
"""

from __future__ import annotations

import re
from typing import Any

from unicorn import UcError

from .disasm import decode_instruction

DIRECT_ADDR_RE = re.compile(r"(?<![\w])(?:0x[0-9a-fA-F]+|\d+)(?![\w])")


def _hex(value: int | None) -> str | None:
    if value is None:
        return None
    return hex(int(value))


def _bytes_to_hex(data: bytes | list[int]) -> str:
    blob = bytes(data)
    return " ".join(f"{byte:02x}" for byte in blob)


def _align_down(value: int, align: int) -> int:
    if align <= 1:
        return value
    return value & ~(align - 1)


def _align_up(value: int, align: int) -> int:
    if align <= 1:
        return value
    return (value + align - 1) & ~(align - 1)


def _safe_read_bytes(uc_engine, addr: int, size: int) -> bytes:
    if size <= 0:
        return b""
    try:
        return bytes(uc_engine.mem_read(addr, size))
    except UcError:
        return b""


class SnapshotCollector:
    """Collecte des snapshots enrichis pendant l'emulation Unicorn."""

    def __init__(
        self,
        config,
        reg_order,
        sp_reg: int,
        rbp_reg: int,
        pc_reg: int,
        external_state: dict | None = None,
    ) -> None:
        self._config = config
        self._reg_order = reg_order
        self._sp_reg = sp_reg
        self._rbp_reg = rbp_reg
        self._pc_reg = pc_reg
        self._word_size = 8 if config.arch_bits == 64 else 4
        self._stack_start = int(config.stack_base)
        self._stack_end = int(config.stack_base + config.stack_size)
        self._external_state = external_state if external_state is not None else {}
        self.snapshots: list[dict] = []
        self.step = 0
        self._pending: dict[str, Any] | None = None

    def _in_capture_ranges(self, addr: int) -> bool:
        ranges = self._config.capture_ranges
        if not ranges:
            return True
        return any(start <= addr < end for start, end in ranges)

    def _read_registers(self, uc_engine) -> dict[str, int]:
        regs = {}
        for name, reg_id in self._reg_order:
            try:
                regs[name] = int(uc_engine.reg_read(reg_id))
            except UcError:
                continue
        return regs

    def _register_aliases(self) -> dict[str, str | None]:
        if self._config.arch_bits == 32:
            return {"sp": "esp", "bp": "ebp", "fp": "ebp", "ip": "eip", "lr": None}
        return {"sp": "rsp", "bp": "rbp", "fp": "rbp", "ip": "rip", "lr": None}

    def _register_stage_payload(self, regs: dict[str, int]) -> dict[str, Any]:
        return {
            "registers": {name: hex(value) for name, value in regs.items()},
        }

    def _legacy_register_items(
        self, regs: dict[str, int], instruction_addr: int | None
    ) -> list[dict]:
        items = []
        for idx, (name, _reg_id) in enumerate(self._reg_order):
            value = regs.get(name)
            if value is None:
                continue
            if instruction_addr is not None and name in {"rip", "eip"}:
                items.append({"name": name, "value": hex(instruction_addr), "pos": idx})
                continue
            items.append({"name": name, "value": hex(value), "pos": idx})
        return items

    def _apply_memory_patches(self, uc_engine, addr: int) -> None:
        if not self._config.memory_patches:
            return
        for trigger_rip, rbp_offset, value_or_payload in self._config.memory_patches:
            if addr != trigger_rip:
                continue
            try:
                rbp = int(uc_engine.reg_read(self._rbp_reg))
                target_addr = rbp + rbp_offset
                if isinstance(value_or_payload, int):
                    data = int(value_or_payload).to_bytes(4, "little", signed=False)
                else:
                    data = bytes(value_or_payload)
                uc_engine.mem_write(target_addr, data)
            except UcError:
                pass
            break

    def _is_stack_access(self, addr: int, size: int) -> bool:
        if size <= 0:
            return False
        return addr < self._stack_end and (addr + size) > self._stack_start

    def _normalize_access(
        self,
        kind: str,
        addr: int,
        size: int,
        data: bytes | None = None,
        *,
        source: str = "runtime",
    ) -> dict | None:
        if size <= 0 or not self._is_stack_access(addr, size):
            return None
        clipped_start = max(addr, self._stack_start)
        clipped_end = min(addr + size, self._stack_end)
        clipped_size = clipped_end - clipped_start
        if clipped_size <= 0:
            return None
        if data is None:
            clipped = b""
        elif addr < clipped_start:
            offset = clipped_start - addr
            clipped = bytes(data[offset : offset + clipped_size])
        else:
            clipped = bytes(data[:clipped_size])
        return {
            "kind": kind,
            "addr": hex(clipped_start),
            "size": clipped_size,
            "bytes": _bytes_to_hex(clipped),
            "source": source,
        }

    def _record_access(
        self,
        kind: str,
        addr: int,
        size: int,
        data: bytes | None = None,
        *,
        source: str = "runtime",
    ) -> None:
        if self._pending is None:
            return
        entry = self._normalize_access(kind, addr, size, data, source=source)
        if entry is None:
            return
        self._pending[kind].append(entry)

    def hook_mem_read(
        self,
        uc_engine,
        _access,
        address: int,
        size: int,
        _value: int,
        _user_data: object,
    ) -> bool:
        if self._pending is None:
            return True
        data = _safe_read_bytes(uc_engine, address, size)
        self._record_access("reads", address, size, data)
        return True

    def hook_mem_write(
        self,
        _uc_engine,
        _access,
        address: int,
        size: int,
        value: int,
        _user_data: object,
    ) -> bool:
        if self._pending is None:
            return True
        if size <= 0:
            return True
        try:
            data = int(value).to_bytes(size, "little", signed=False)
        except OverflowError:
            masked = int(value) & ((1 << (size * 8)) - 1)
            data = masked.to_bytes(size, "little", signed=False)
        self._record_access("writes", address, size, data)
        return True

    def _consume_external_event(self, addr: int) -> dict | None:
        events = self._external_state.get("events_by_addr")
        if not isinstance(events, dict):
            return None
        queue = events.get(addr)
        if not isinstance(queue, list) or not queue:
            return None
        event = queue.pop(0)
        if not queue:
            events.pop(addr, None)
        return event if isinstance(event, dict) else None

    def _merge_access_lists(
        self, runtime: list[dict], synthetic: list[dict], kind: str
    ) -> list[dict]:
        merged = list(runtime)
        for entry in synthetic:
            if not isinstance(entry, dict):
                continue
            merged.append(
                {
                    "kind": kind,
                    "addr": entry.get("addr"),
                    "size": entry.get("size"),
                    "bytes": entry.get("bytes", ""),
                    "source": entry.get("source", "external"),
                }
            )
        return merged

    def _parse_direct_target(self, instruction: dict) -> int | None:
        mnemonic = str(instruction.get("mnemonic") or "").lower()
        if mnemonic not in {"call", "jmp"} and not mnemonic.startswith("j"):
            return None
        operands = str(instruction.get("operands") or "").strip()
        match = DIRECT_ADDR_RE.search(operands)
        if not match:
            return None
        token = match.group(0)
        try:
            return int(token, 16) if token.lower().startswith("0x") else int(token, 10)
        except ValueError:
            return None

    def _effect_kind(
        self, instruction: dict, writes: list[dict], reads: list[dict]
    ) -> str:
        mnemonic = str(instruction.get("mnemonic") or "").lower()
        operands = str(instruction.get("operands") or "").lower()
        if mnemonic == "push":
            return "push"
        if mnemonic == "pop":
            return "pop"
        if mnemonic == "call":
            return "call"
        if mnemonic in {"ret", "retn"}:
            return "ret"
        if mnemonic == "leave":
            return "leave"
        if mnemonic == "sub" and ("rsp" in operands or "esp" in operands):
            return "frame_alloc"
        if mnemonic == "add" and ("rsp" in operands or "esp" in operands):
            return "frame_free"
        if mnemonic == "mov" and ("rbp" in operands or "ebp" in operands):
            return "frame_setup"
        if writes:
            return "stack_write"
        if reads:
            return "stack_read"
        return "instruction"

    def _capture_window(
        self,
        uc_engine,
        before_regs: dict[str, int],
        after_regs: dict[str, int],
        accesses: list[dict],
    ) -> tuple[int | None, bytes]:
        points: list[int] = []
        default_size = max(
            self._config.stack_entries * self._word_size, self._word_size * 16
        )
        margin = max(self._word_size * 4, 0x20)

        for reg_name in ("rsp", "rbp", "esp", "ebp"):
            if reg_name in before_regs:
                points.extend(
                    [before_regs[reg_name], before_regs[reg_name] + self._word_size]
                )
            if reg_name in after_regs:
                points.extend(
                    [after_regs[reg_name], after_regs[reg_name] + self._word_size]
                )

        bp_after = after_regs.get("rbp") or after_regs.get("ebp")
        bp_before = before_regs.get("rbp") or before_regs.get("ebp")
        buffer_offset = self._config.buffer_offset
        buffer_size = int(self._config.buffer_size or 0)
        if buffer_offset is not None and buffer_size > 0:
            frame_bp = bp_after if bp_after is not None else bp_before
            if frame_bp is not None:
                points.extend(
                    [
                        frame_bp + int(buffer_offset),
                        frame_bp + int(buffer_offset) + buffer_size,
                    ]
                )

        for access in accesses:
            try:
                addr = int(str(access.get("addr")), 16)
            except (TypeError, ValueError):
                continue
            size = int(access.get("size") or 0)
            points.extend([addr, addr + max(1, size)])

        if not points:
            anchor = (
                after_regs.get("rsp")
                or after_regs.get("esp")
                or before_regs.get("rsp")
                or before_regs.get("esp")
                or self._stack_start
            )
            start = _align_down(anchor, self._word_size)
            end = start + default_size
        else:
            start = _align_down(min(points) - margin, self._word_size)
            end = _align_up(max(points) + margin, self._word_size)
            if end - start < default_size:
                center = (start + end) // 2
                half = default_size // 2
                start = _align_down(center - half, self._word_size)
                end = start + default_size

        start = max(self._stack_start, start)
        end = min(self._stack_end, end)
        if end <= start:
            return None, b""
        return start, _safe_read_bytes(uc_engine, start, end - start)

    def _legacy_stack_items(
        self, window_start: int | None, window_bytes: bytes, active_sp: int | None
    ) -> list[dict]:
        if window_start is None or not window_bytes:
            return []
        items = []
        for index in range(0, len(window_bytes), self._word_size):
            chunk = window_bytes[index : index + self._word_size]
            if not chunk:
                continue
            addr = window_start + index
            value = int.from_bytes(chunk, "little", signed=False)
            pos = addr - active_sp if active_sp is not None else index
            items.append(
                {
                    "id": index // self._word_size,
                    "addr": hex(addr),
                    "pos": pos,
                    "size": len(chunk),
                    "value": hex(value),
                }
            )
        return items

    def _build_effects(
        self,
        pending: dict[str, Any],
        after_regs: dict[str, int],
        reads: list[dict],
        writes: list[dict],
        external_event: dict | None,
    ) -> dict[str, Any]:
        before_regs = pending["before_regs"]
        instruction = pending["instruction"]
        aliases = self._register_aliases()
        sp_name = aliases.get("sp")
        bp_name = aliases.get("bp")
        ip_name = aliases.get("ip")
        before_sp = before_regs.get(sp_name) if sp_name else None
        after_sp = after_regs.get(sp_name) if sp_name else None
        before_bp = before_regs.get(bp_name) if bp_name else None
        after_bp = after_regs.get(bp_name) if bp_name else None
        after_ip = after_regs.get(ip_name) if ip_name else None
        fallthrough = pending["addr"] + int(pending["size"] or 0)
        mnemonic = str(instruction.get("mnemonic") or "").lower()
        direct_target = self._parse_direct_target(instruction)
        external_target = None
        if external_event and external_event.get("call_target"):
            try:
                external_target = int(str(external_event["call_target"]), 16)
            except (TypeError, ValueError):
                external_target = None

        branch_taken = None
        if mnemonic == "jmp" or mnemonic.startswith("j"):
            branch_taken = after_ip != fallthrough if after_ip is not None else None

        return {
            "kind": self._effect_kind(instruction, writes, reads),
            "sp_delta": (after_sp - before_sp)
            if after_sp is not None and before_sp is not None
            else None,
            "frame_delta": (after_bp - before_bp)
            if after_bp is not None and before_bp is not None
            else None,
            "branch_taken": branch_taken,
            "call_target": _hex(
                external_target if external_target is not None else direct_target
            ),
            "external_simulated": bool(
                external_event and external_event.get("external_simulated")
            ),
            "external_symbol": external_event.get("external_symbol")
            if external_event
            else None,
        }

    def _start_pending(self, uc_engine, addr: int, size: int) -> None:
        instr_bytes = _safe_read_bytes(uc_engine, addr, size)
        instruction = decode_instruction(instr_bytes, addr, self._config.arch_bits)
        self._pending = {
            "step": len(self.snapshots) + 1,
            "addr": addr,
            "size": size,
            "instruction": instruction,
            "before_regs": self._read_registers(uc_engine),
            "reads": [],
            "writes": [],
        }

    def finalize_pending(self, uc_engine) -> None:
        if self._pending is None:
            return

        pending = self._pending
        after_regs = self._read_registers(uc_engine)
        external_event = self._consume_external_event(int(pending["addr"]))
        reads = self._merge_access_lists(
            pending["reads"],
            external_event.get("reads", []) if external_event else [],
            "reads",
        )
        writes = self._merge_access_lists(
            pending["writes"],
            external_event.get("writes", []) if external_event else [],
            "writes",
        )
        window_start, window_bytes = self._capture_window(
            uc_engine,
            pending["before_regs"],
            after_regs,
            reads + writes,
        )
        aliases = self._register_aliases()
        sp_name = aliases.get("sp")
        active_sp = after_regs.get(sp_name) if sp_name else None
        if active_sp is None and sp_name:
            active_sp = pending["before_regs"].get(sp_name)

        effects = self._build_effects(
            pending, after_regs, reads, writes, external_event
        )
        instruction_addr = int(pending["addr"])
        snapshot = {
            "step": pending["step"],
            "instr": str(pending["instruction"].get("text") or "").strip(),
            "instruction": pending["instruction"],
            "cpu": {
                "arch": "x86_64" if self._config.arch_bits == 64 else "x86",
                "word_size": self._word_size,
                "endian": "little",
                "aliases": aliases,
                "before": self._register_stage_payload(pending["before_regs"]),
                "after": self._register_stage_payload(after_regs),
            },
            "memory": {
                "window_start": _hex(window_start),
                "window_end": _hex(window_start + len(window_bytes))
                if window_start is not None
                else None,
                "window_bytes": _bytes_to_hex(window_bytes),
                "stack_window_bytes": len(window_bytes),
                "reads": reads,
                "writes": writes,
            },
            "effects": effects,
            "registers": self._legacy_register_items(after_regs, instruction_addr),
            "stack": self._legacy_stack_items(window_start, window_bytes, active_sp),
        }

        if self._config.arch_bits == 64:
            snapshot["rip"] = hex(instruction_addr)
            snapshot["rsp"] = _hex(active_sp)
        else:
            snapshot["eip"] = hex(instruction_addr)
            snapshot["esp"] = _hex(active_sp)

        self.snapshots.append(snapshot)
        self.step = len(self.snapshots)
        self._pending = None

    def hook_code(self, uc_engine, addr: int, size: int, _user_data: object) -> None:
        # Finalize the previous instruction when Unicorn is about to execute the next one.
        if self._pending is not None:
            self.finalize_pending(uc_engine)

        stop_here = (
            self._config.stop_addr is not None and addr == self._config.stop_addr
        )

        # Memory patches apply to the new instruction context, not to the previous step.
        self._apply_memory_patches(uc_engine, addr)

        if not self._in_capture_ranges(addr):
            if stop_here:
                uc_engine.emu_stop()
            return

        if len(self.snapshots) >= self._config.max_steps:
            uc_engine.emu_stop()
            return

        self._start_pending(uc_engine, addr, size)

        if stop_here:
            uc_engine.emu_stop()
