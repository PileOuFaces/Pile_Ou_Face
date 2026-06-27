# SPDX-License-Identifier: AGPL-3.0-only
"""Hex View — dump hexadecimal d'un binaire avec metadonnees de sections."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

# Allow running as a script directly (not only via `python -m`)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import lief
except ImportError:
    lief = None

from backends.static.binary.arch import detect_binary_arch, get_raw_arch_info
from backends.shared.log import configure_logging, get_logger, make_meta

logger = get_logger(__name__)
BYTES_PER_ROW = 16


def _section_type(name: str) -> str:
    if name in (".text", "__text", "CODE"):
        return "code"
    if name in (".data", "__data", ".rodata", "__const", ".rdata", ".idata", ".edata"):
        return "data"
    if name in (".bss", "__bss"):
        return "bss"
    return "other"


def _sections_from_binary(binary) -> list[dict]:
    sections = []
    src = []
    if isinstance(binary, lief.ELF.Binary):
        src = [
            (s.name, s.file_offset, s.virtual_address, s.size) for s in binary.sections if s.size
        ]
    elif isinstance(binary, lief.MachO.Binary):
        src = [(s.name, s.offset, s.virtual_address, s.size) for s in binary.sections if s.size]
    elif isinstance(binary, lief.PE.Binary):
        ib = binary.optional_header.imagebase
        src = [
            (s.name, s.offset, s.virtual_address + ib, s.size) for s in binary.sections if s.size
        ]

    for name, offset, vaddr, size in src:
        sections.append(
            {
                "name": name,
                "offset": offset,
                "virtual_address": vaddr,
                "size": size,
                "type": _section_type(name),
            }
        )
    return sections


def _inspect_binary(
    binary_path: str, raw_arch: str | None = None, raw_endian: str | None = None
) -> dict:
    info = {
        "sections": [],
        "endianness": "little",
        "ptr_size": 8,
        "bits": 64,
        "arch": "",
    }
    raw_arch_info = get_raw_arch_info(str(raw_arch or ""), raw_endian) if raw_arch else None
    if raw_arch_info is not None:
        info["endianness"] = str(getattr(raw_arch_info, "endian", "little") or "little")
        info["ptr_size"] = int(getattr(raw_arch_info, "ptr_size", 8) or 8)
        info["bits"] = int(
            getattr(raw_arch_info, "bits", info["ptr_size"] * 8) or (info["ptr_size"] * 8)
        )
        info["arch"] = str(
            getattr(raw_arch_info, "raw_name", "") or getattr(raw_arch_info, "key", "") or ""
        )
    if not lief:
        return info
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            return info
    except Exception:
        return info

    info["sections"] = _sections_from_binary(binary)
    try:
        arch_info = detect_binary_arch(binary)
    except Exception:
        arch_info = None
    if arch_info is not None:
        info["endianness"] = str(getattr(arch_info, "endian", "little") or "little")
        info["ptr_size"] = int(getattr(arch_info, "ptr_size", 8) or 8)
        info["bits"] = int(
            getattr(arch_info, "bits", info["ptr_size"] * 8) or (info["ptr_size"] * 8)
        )
        info["arch"] = str(getattr(arch_info, "key", "") or "")
    return info


def _inject_raw_section(
    binary_info: dict, file_size: int, raw_base_addr: int | str | None = None
) -> dict:
    info = dict(binary_info or {})
    if info.get("sections"):
        return info
    base_addr = 0
    try:
        base_addr = int(str(raw_base_addr or "0x0"), 0)
    except Exception:
        base_addr = 0
    if file_size > 0:
        info["sections"] = [
            {
                "name": "raw",
                "offset": 0,
                "virtual_address": base_addr,
                "size": file_size,
                "type": "other",
            }
        ]
    return info


def hex_dump(
    binary_path: str,
    offset: int = 0,
    length: int = 512,
    raw_base_addr: int | str | None = None,
    raw_arch: str | None = None,
    raw_endian: str | None = None,
) -> dict:
    """Returns hexdump rows from a binary file.

    Returns:
        {rows: [{offset, hex, ascii}], sections: [...], file_size: N, meta: {...}}
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "rows": [],
            "sections": [],
            "file_size": 0,
            "endianness": "little",
            "ptr_size": 8,
            "bits": 64,
            "arch": "",
            "meta": make_meta("hex_view"),
            "error": f"File not found: {binary_path}",
        }

    file_size = path.stat().st_size
    binary_info = _inspect_binary(binary_path, raw_arch=raw_arch, raw_endian=raw_endian)
    if raw_arch:
        binary_info = _inject_raw_section(binary_info, file_size, raw_base_addr)
    if offset >= file_size:
        return {
            "rows": [],
            "sections": binary_info["sections"],
            "file_size": file_size,
            "endianness": binary_info["endianness"],
            "ptr_size": binary_info["ptr_size"],
            "bits": binary_info["bits"],
            "arch": binary_info["arch"],
            "meta": make_meta("hex_view"),
        }

    length = min(length, file_size - offset, 65536)

    with open(path, "rb") as f:
        f.seek(offset)
        raw = f.read(length)

    rows = []
    for i in range(0, len(raw), BYTES_PER_ROW):
        chunk = raw[i : i + BYTES_PER_ROW]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(
            {
                "offset": f"0x{(offset + i):08x}",
                "hex": hex_str,
                "ascii": ascii_str,
            }
        )

    return {
        "rows": rows,
        "sections": binary_info["sections"],
        "file_size": file_size,
        "endianness": binary_info["endianness"],
        "ptr_size": binary_info["ptr_size"],
        "bits": binary_info["bits"],
        "arch": binary_info["arch"],
        "meta": make_meta("hex_view"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Hex View")
    parser.add_argument("--binary", required=True)
    parser.add_argument("--offset", type=lambda x: int(x, 0), default=0)
    parser.add_argument("--length", type=int, default=512)
    parser.add_argument("--raw-base-addr", default=None)
    parser.add_argument("--raw-arch", default=None)
    parser.add_argument("--raw-endian", default=None)
    args = parser.parse_args()
    configure_logging()
    print(
        json.dumps(
            hex_dump(
                args.binary,
                args.offset,
                args.length,
                args.raw_base_addr,
                args.raw_arch,
                args.raw_endian,
            )
        )
    )
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
