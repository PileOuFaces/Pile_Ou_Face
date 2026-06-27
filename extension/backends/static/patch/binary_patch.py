# SPDX-License-Identifier: AGPL-3.0-only
"""Patch bytes dans un binaire (modifie le fichier en place)."""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running as a script directly (not only via `python -m`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from backends.shared.log import configure_logging, get_logger, make_meta

logger = get_logger(__name__)


def patch_bytes(binary_path: str, offset: int, bytes_hex: str) -> dict:
    """Writes bytes at offset into binary file (in-place).

    Returns:
        {'ok': True, 'written': N, 'offset': offset} or {'ok': False, 'error': '...'}
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "ok": False,
            "error": f"File not found: {binary_path}",
            "meta": make_meta("binary_patch"),
        }

    try:
        raw = bytes(int(b, 16) for b in bytes_hex.strip().split())
    except ValueError as e:
        return {
            "ok": False,
            "error": f"Invalid hex bytes: {e}",
            "meta": make_meta("binary_patch"),
        }

    file_size = path.stat().st_size
    if offset < 0 or offset + len(raw) > file_size:
        return {
            "ok": False,
            "error": f"Out of range: offset={offset} len={len(raw)} size={file_size}",
            "meta": make_meta("binary_patch"),
        }

    with open(path, "r+b") as f:
        f.seek(offset)
        f.write(raw)

    logger.info("Patched %d bytes at offset 0x%x in %s", len(raw), offset, path.name)
    return {
        "ok": True,
        "written": len(raw),
        "offset": offset,
        "meta": make_meta("binary_patch"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Patch bytes in binary")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--offset", type=lambda x: int(x, 0), required=True)
    parser.add_argument(
        "--bytes", required=True, dest="bytes_hex", help='Hex bytes ex: "90 90 eb 0a"'
    )
    args = parser.parse_args()
    configure_logging()
    result = patch_bytes(args.binary, args.offset, args.bytes_hex)
    print(json.dumps(result))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    import sys

    sys.exit(main())
