# SPDX-License-Identifier: AGPL-3.0-only
"""ExecutionEngine adapter for the Unicorn runtime implementation."""

from __future__ import annotations

from backends.dynamic.core.interfaces import ExecutionEngine, TraceConfigLike
from backends.dynamic.core.types import TraceResult


class UnicornExecutionEngine:
    """Concrete runtime engine backed by Unicorn."""

    name = "unicorn"

    def trace_binary(
        self,
        code_bytes: bytes,
        config: TraceConfigLike,
        binary_path: str | None,
    ) -> TraceResult:
        from .tracer import trace_binary

        return trace_binary(code_bytes, config, binary_path)


def create_engine() -> ExecutionEngine:
    """Create the default Unicorn execution engine."""

    return UnicornExecutionEngine()
