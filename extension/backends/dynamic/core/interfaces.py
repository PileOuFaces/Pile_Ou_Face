# SPDX-License-Identifier: AGPL-3.0-only
"""Stable contracts between the dynamic pipeline and runtime engines."""

from __future__ import annotations

from typing import Mapping, Optional, Protocol, Sequence, Tuple, Union, runtime_checkable

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
    buffer_offset: Optional[int]
    buffer_size: int
    start_symbol: Optional[str]
    argv1: Optional[str]
    argv1_data: Optional[bytes]
    stop_symbol: Optional[str]
    capture_start_addr: Optional[int]
    loader_max_steps: Optional[int]
    capture_ranges: Optional[Sequence[Tuple[int, int]]]
    stop_addr: Optional[int]
    memory_patches: Optional[Sequence[Tuple[int, int, Union[int, bytes]]]]
    stack_payload: Optional[Tuple[int, bytes]]
    virtual_files: Optional[Mapping[str, bytes]]


@runtime_checkable
class ExecutionEngine(Protocol):
    """Runtime engine contract used by the dynamic pipeline."""

    name: str

    def trace_binary(
        self,
        code_bytes: bytes,
        config: TraceConfigLike,
        binary_path: Optional[str],
    ) -> TraceResult:
        """Trace a binary blob and return snapshots plus engine metadata."""
