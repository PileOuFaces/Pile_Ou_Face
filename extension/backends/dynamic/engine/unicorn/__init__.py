# SPDX-License-Identifier: AGPL-3.0-only
"""Runtime Unicorn concret pour la trace dynamique."""

from .config import TraceConfig
from .engine import UnicornExecutionEngine, create_engine

__all__ = [
    "TraceConfig",
    "UnicornExecutionEngine",
    "create_engine",
    "trace_binary",
    "trace_raw",
    "trace_elf",
]


def __getattr__(name: str):
    if name in {"trace_binary", "trace_raw", "trace_elf"}:
        from .tracer import trace_binary, trace_elf, trace_raw

        exports = {
            "trace_binary": trace_binary,
            "trace_raw": trace_raw,
            "trace_elf": trace_elf,
        }
        return exports[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
