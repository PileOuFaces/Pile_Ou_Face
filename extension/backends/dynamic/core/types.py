# SPDX-License-Identifier: AGPL-3.0-only
"""Shared dynamic trace type aliases."""

from __future__ import annotations

from typing import Any, TypeAlias

TraceSnapshot: TypeAlias = dict[str, Any]
TraceMeta: TypeAlias = dict[str, Any]
TraceResult: TypeAlias = dict[str, Any]
