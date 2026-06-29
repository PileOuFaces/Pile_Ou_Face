#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Compatibility wrapper for the MCP server.

The MCP implementation now lives in:
    backends/mcp/server.py
"""

import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.mcp.server import *  # noqa: F401,F403
from backends.mcp.server import main

if __name__ == "__main__":
    raise SystemExit(main())
