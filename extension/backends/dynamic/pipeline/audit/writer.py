# SPDX-License-Identifier: AGPL-3.0-only
"""JSON writer for opt-in Run Trace audit files."""

from __future__ import annotations

import dataclasses
import json
import os
from typing import Optional


def audit_enabled() -> bool:
    return os.environ.get("POF_RUNTRACE_AUDIT") == "1"


def audit_dir(output_path: Optional[str]) -> Optional[str]:
    if not audit_enabled():
        return None
    configured = os.environ.get("POF_RUNTRACE_AUDIT_DIR")
    if configured:
        return os.path.abspath(configured)
    if output_path:
        return os.path.dirname(os.path.abspath(output_path)) or os.getcwd()
    return os.getcwd()


def jsonable(value):
    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "byteLength": len(value),
            "hex": value.hex(),
        }
    if dataclasses.is_dataclass(value):
        return jsonable(dataclasses.asdict(value))
    if isinstance(value, dict):
        return {str(key): jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [jsonable(item) for item in value]
    return value


def write_audit_json(output_path: Optional[str], name: str, payload) -> None:
    directory = audit_dir(output_path)
    if not directory:
        return
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, name), "w", encoding="utf-8") as handle:
        json.dump(jsonable(payload), handle, indent=2)
        handle.write("\n")
