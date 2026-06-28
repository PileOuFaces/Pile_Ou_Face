# SPDX-License-Identifier: AGPL-3.0-only
"""Stable contracts between the dynamic pipeline and runtime engines."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import (
    Protocol,
    runtime_checkable,
)

from .types import TraceResult


@runtime_checkable
class TraceConfigLike(Protocol):
    """Structural config contract consumed by runtime engines."""

    base: int
    stack_base: int
    stack_size: int
    max_steps: int
    stack_entries: int
    arch_bits: int
    interp_base: int
    start_interp: bool
    stdin_data: bytes
    buffer_offset: int | None
    buffer_size: int
    start_symbol: str | None
    argv1: str | None
    argv1_data: bytes | None
    stop_symbol: str | None
    capture_start_addr: int | None
    loader_max_steps: int | None
    capture_ranges: Sequence[tuple[int, int]] | None
    stop_addr: int | None
    memory_patches: Sequence[tuple[int, int, int | bytes]] | None
    stack_payload: tuple[int, bytes] | None
    virtual_files: Mapping[str, bytes] | None


@runtime_checkable
class ExecutionEngine(Protocol):
    """Runtime engine contract used by the dynamic pipeline."""

    name: str

    def trace_binary(
        self,
        code_bytes: bytes,
        config: TraceConfigLike,
        binary_path: str | None,
    ) -> TraceResult:
        """Trace a binary blob and return snapshots plus engine metadata."""
