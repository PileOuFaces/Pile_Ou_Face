# SPDX-License-Identifier: AGPL-3.0-only
"""Gestion persistante des patches binaires avec undo.

CLI:
  patch_manager.py list       --binary <path>
  patch_manager.py apply      --binary <path> --offset <int> --bytes <hex> [--comment <str>]
  patch_manager.py revert     --binary <path> --id <uuid>
  patch_manager.py redo       --binary <path> [--id <uuid>]
  patch_manager.py revert-all --binary <path>
"""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import hashlib
import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

# Allow running as a script directly (not only via `python -m`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))


# ---------------------------------------------------------------------------
# Storage helpers
# ---------------------------------------------------------------------------


def _patches_dir(binary_path: str) -> Path:
    """Return the patch storage directory for a binary."""
    storage_dir = os.environ.get("POF_STORAGE_DIR", "").strip()
    if storage_dir:
        return Path(storage_dir) / "patches"

    binary_abs = os.path.abspath(binary_path)
    start = os.path.dirname(binary_abs)
    return Path(start) / "patches"


def _patch_file(binary_path: str) -> Path:
    """Return the JSON patch file path for this binary (does not create dirs)."""
    binary_abs = os.path.abspath(binary_path)
    key = hashlib.sha256(binary_abs.encode()).hexdigest()[:16]
    patches_dir = _patches_dir(binary_path)
    return patches_dir / f"{key}.json"


def _load(binary_path: str) -> dict:
    """Load patch data from JSON file, or return empty structure."""
    patch_file = _patch_file(binary_path)
    if not patch_file.exists():
        return {
            "binary": os.path.abspath(binary_path),
            "patches": [],
            "redo_patches": [],
        }
    with open(patch_file, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        data = {}
    data.setdefault("binary", os.path.abspath(binary_path))
    data.setdefault("patches", [])
    data.setdefault("redo_patches", [])
    return data


def _save(binary_path: str, data: dict) -> None:
    """Write patch data to JSON file, creating parent dirs as needed."""
    f = _patch_file(binary_path)
    f.parent.mkdir(parents=True, exist_ok=True)
    with open(f, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)


def _decode_hex_bytes(
    bytes_hex: str, error_prefix: str
) -> tuple[bytes | None, str | None]:
    try:
        return bytes(int(b, 16) for b in bytes_hex.strip().split()), None
    except ValueError as exc:
        return None, f"{error_prefix}: {exc}"


def _write_bytes(binary_path: str, offset: int, raw: bytes) -> None:
    with open(binary_path, "r+b") as f:
        f.seek(offset)
        f.write(raw)


def _replace_bytes(binary_path: str, offset: int, raw: bytes) -> bytes:
    with open(binary_path, "r+b") as f:
        f.seek(offset)
        original_raw = f.read(len(raw))
        f.seek(offset)
        f.write(raw)
    return original_raw


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def list_patches(binary_path: str) -> dict:
    """Return all patches for the given binary."""
    return _load(binary_path)


def apply_patch(
    binary_path: str, offset: int, bytes_hex: str, comment: str = ""
) -> dict:
    """Apply bytes at offset, recording original bytes for undo.

    Returns {'ok': True, 'patch': entry} or {'ok': False, 'error': '...'}.
    """
    binary_abs = os.path.abspath(binary_path)

    if not os.path.isfile(binary_abs):
        return {"ok": False, "error": f"File not found: {binary_path}"}

    raw, error = _decode_hex_bytes(bytes_hex, "Invalid hex bytes")
    if error:
        return {"ok": False, "error": error}
    assert raw is not None

    file_size = os.path.getsize(binary_abs)
    if offset < 0 or offset + len(raw) > file_size:
        return {
            "ok": False,
            "error": (f"Out of range: offset={offset} len={len(raw)} size={file_size}"),
        }

    original_raw = _replace_bytes(binary_abs, offset, raw)
    original_hex = " ".join(f"{b:02x}" for b in original_raw)

    entry = {
        "id": str(uuid4()),
        "offset": offset,
        "original_bytes": original_hex,
        "patched_bytes": bytes_hex.strip(),
        "timestamp": datetime.now(UTC).isoformat(),
        "comment": comment,
    }

    data = _load(binary_path)
    data["patches"].append(entry)
    data["redo_patches"] = []
    _save(binary_path, data)

    return {"ok": True, "patch": entry}


def revert_patch(binary_path: str, patch_id: str) -> dict:
    """Revert a single patch by id, restoring original bytes.

    Returns {'ok': True} or {'ok': False, 'error': '...'}.
    """
    binary_abs = os.path.abspath(binary_path)
    if not os.path.isfile(binary_abs):
        return {"ok": False, "error": f"Fichier introuvable : {binary_abs}"}
    data = _load(binary_path)

    target = next((p for p in data["patches"] if p["id"] == patch_id), None)
    if target is None:
        return {"ok": False, "error": f"Patch id not found: {patch_id}"}

    raw, error = _decode_hex_bytes(
        target["original_bytes"], "Invalid stored original_bytes"
    )
    if error:
        return {"ok": False, "error": error}
    assert raw is not None
    _write_bytes(binary_abs, target["offset"], raw)

    data["patches"] = [p for p in data["patches"] if p["id"] != patch_id]
    data.setdefault("redo_patches", []).append(target)
    _save(binary_path, data)

    return {"ok": True, "patch": target}


def redo_patch(binary_path: str, patch_id: str | None = None) -> dict:
    """Reapply a reverted patch from redo history.

    If patch_id is omitted, reapplies the most recently reverted patch.
    Returns {'ok': True, 'patch': entry} or {'ok': False, 'error': '...'}.
    """
    binary_abs = os.path.abspath(binary_path)
    if not os.path.isfile(binary_abs):
        return {"ok": False, "error": f"Fichier introuvable : {binary_abs}"}

    data = _load(binary_path)
    redo_entries = data.setdefault("redo_patches", [])
    if not redo_entries:
        return {"ok": False, "error": "Aucun patch à refaire."}

    if patch_id:
        target = next((p for p in redo_entries if p["id"] == patch_id), None)
    else:
        target = redo_entries[-1]
    if target is None:
        return {"ok": False, "error": f"Patch redo introuvable : {patch_id}"}

    raw, error = _decode_hex_bytes(
        target["patched_bytes"], "Invalid stored patched_bytes"
    )
    if error:
        return {"ok": False, "error": error}
    assert raw is not None
    _write_bytes(binary_abs, target["offset"], raw)

    data["redo_patches"] = [p for p in redo_entries if p["id"] != target["id"]]
    data.setdefault("patches", []).append(target)
    _save(binary_path, data)

    return {"ok": True, "patch": target}


def revert_all(binary_path: str) -> dict:
    """Revert all patches in reverse order (last applied first).

    Returns {'ok': True} or {'ok': False, 'error': '...'}.
    """
    binary_abs = os.path.abspath(binary_path)
    if not os.path.isfile(binary_abs):
        return {"ok": False, "error": f"Fichier introuvable : {binary_abs}"}
    data = _load(binary_path)

    for patch in reversed(data["patches"]):
        raw, error = _decode_hex_bytes(
            patch["original_bytes"], "Invalid stored original_bytes"
        )
        if error:
            return {"ok": False, "error": error}
        assert raw is not None
        _write_bytes(binary_abs, patch["offset"], raw)
        data.setdefault("redo_patches", []).append(patch)

    data["patches"] = []
    _save(binary_path, data)

    return {"ok": True}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description="Persistent binary patch manager")
    sub = parser.add_subparsers(dest="command", required=True)

    # list
    p_list = sub.add_parser("list")
    p_list.add_argument("--binary", required=True)

    # apply
    p_apply = sub.add_parser("apply")
    p_apply.add_argument("--binary", required=True)
    p_apply.add_argument("--offset", type=lambda x: int(x, 0), required=True)
    p_apply.add_argument("--bytes", required=True, dest="bytes_hex")
    p_apply.add_argument("--comment", default="")

    # revert
    p_revert = sub.add_parser("revert")
    p_revert.add_argument("--binary", required=True)
    p_revert.add_argument("--id", required=True, dest="patch_id")

    # redo
    p_redo = sub.add_parser("redo")
    p_redo.add_argument("--binary", required=True)
    p_redo.add_argument("--id", dest="patch_id")

    # revert-all
    p_revert_all = sub.add_parser("revert-all")
    p_revert_all.add_argument("--binary", required=True)

    args = parser.parse_args()

    if args.command == "list":
        result = list_patches(args.binary)
    elif args.command == "apply":
        result = apply_patch(args.binary, args.offset, args.bytes_hex, args.comment)
    elif args.command == "revert":
        result = revert_patch(args.binary, args.patch_id)
    elif args.command == "redo":
        result = redo_patch(args.binary, getattr(args, "patch_id", None))
    elif args.command == "revert-all":
        result = revert_all(args.binary)
    else:
        result = {"ok": False, "error": f"Unknown command: {args.command}"}

    print(json.dumps(result))
    return 0 if result.get("ok") is not False else 1


if __name__ == "__main__":
    sys.exit(main())
