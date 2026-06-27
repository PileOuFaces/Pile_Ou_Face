#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""DEPRECATED compatibility wrapper for the dynamic pipeline CLI.

New code should import from ``backends.dynamic.pipeline.run_pipeline``.
TODO(dynamic-api): remove after downstream callers migrate to the canonical path.
"""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.dynamic.engine.unicorn.config import TraceConfig
from backends.dynamic.pipeline.run_pipeline import _main, run_pipeline

__all__ = ["TraceConfig", "run_pipeline"]


if __name__ == "__main__":
    raise SystemExit(_main())
