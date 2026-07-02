# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction des infos binaires (ELF/Mach-O/PE).

Utilise lief pour extraire les métadonnées du binaire (robuste, multi-format).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

try:
    import lief
except ImportError:
    lief = None

from backends.shared.log import configure_logging, get_logger, make_meta
from backends.static.binary.arch import detect_binary_arch

logger = get_logger(__name__)


def extract_binary_info(binary_path: str) -> dict:
    """Extrait les infos de base (type, machine, entry, etc.).

    Args:
        binary_path: Chemin vers le binaire

    Returns:
        Dict avec path, format, machine, entry, type, bits, arch, stripped
    """
    if not lief:
        return {"error": "lief not installed"}

    path = Path(binary_path)
    if not path.exists():
        return {"error": "Fichier introuvable"}

    try:
        binary = lief.parse(str(path))
        if binary is None:
            return {"error": "Format de binaire non supporté"}
    except Exception as e:
        return {"error": f"Erreur parsing: {str(e)}"}

    raw = path.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()

    info = {
        "path": str(path),
        "format": "",
        "machine": "",
        "entry": "",
        "type": "",
        "bits": "",
        "arch": "",
        "endianness": "",
        "stripped": "—",
        "interp": "",
        "md5": md5,
        "sha256": sha256,
        "imphash": "",
    }
    arch_info = detect_binary_arch(binary)

    if isinstance(binary, lief.ELF.Binary):
        info["format"] = f"ELF {binary.header.file_type.name}"
        info["machine"] = binary.header.machine_type.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = binary.header.file_type.name
        info["bits"] = (
            str(arch_info.bits)
            if arch_info is not None
            else (
                "64"
                if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64
                else "32"
            )
        )
        info["arch"] = (
            arch_info.raw_name
            if arch_info is not None
            else binary.header.machine_type.name.lower()
        )
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        sym_count = len(
            [
                s
                for s in binary.symtab_symbols
                if s.name and s.type == lief.ELF.Symbol.TYPE.FUNC
            ]
        )
        info["stripped"] = "oui" if sym_count <= 1 else "non"
        if binary.interpreter:
            info["interp"] = binary.interpreter

    elif isinstance(binary, lief.MachO.Binary):
        info["format"] = f"Mach-O {binary.header.file_type.name}"
        info["machine"] = binary.header.cpu_type.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = binary.header.file_type.name
        info["bits"] = (
            str(arch_info.bits)
            if arch_info is not None
            else ("64" if binary.header.is_64bit else "32")
        )
        info["arch"] = (
            arch_info.raw_name
            if arch_info is not None
            else binary.header.cpu_type.name.lower()
        )
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        sym_count = len(
            [s for s in binary.symbols if s.name and not s.name.startswith("_mh_")]
        )
        info["stripped"] = "oui" if sym_count <= 1 else "non"

    elif isinstance(binary, lief.PE.Binary):
        info["format"] = f"PE {binary.header.machine.name}"
        info["machine"] = binary.header.machine.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = "EXECUTABLE"
        machine = binary.header.machine
        info["bits"] = str(arch_info.bits) if arch_info is not None else "?"
        info["arch"] = (
            arch_info.raw_name if arch_info is not None else machine.name.lower()
        )
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        export_count = 0
        if hasattr(binary, "exported_functions"):
            export_count = len([f for f in binary.exported_functions if f.name])
        info["stripped"] = "oui" if export_count == 0 else "non"
        info["imphash"] = _compute_imphash(binary)

    return info


def _compute_imphash(binary: Any) -> str:
    """Calcule l'imphash d'un PE : MD5(dll.func,dll.func,...) normalisé.
    Compatible avec la convention VirusTotal / pefile.
    """
    try:
        entries = []
        for imp in binary.imports:
            dll = imp.name.lower().removesuffix(".dll")
            for entry in imp.entries:
                func = entry.name.lower() if entry.name else f"ord{entry.ordinal}"
                entries.append(f"{dll}.{func}")
        if not entries:
            return ""
        return hashlib.md5(",".join(entries).encode()).hexdigest()
    except Exception:
        return ""


def main() -> int:
    """Point d'entrée CLI : extrait les infos binaires (type, machine, entry, etc.)."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract binary header info (LIEF)")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    if not lief:
        logger.error("lief not installed. Install with: pip install lief")
        return 1

    info = extract_binary_info(args.binary)
    info["meta"] = make_meta("headers")
    out = json.dumps(info, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Info written to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
