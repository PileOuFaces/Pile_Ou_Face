# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction des strings d'un binaire."""

from __future__ import annotations

import re
from pathlib import Path

from backends.shared.utils import build_offset_to_vaddr

SUPPORTED_ENCODINGS = ("auto", "utf-8", "utf-16-le", "utf-16-be")


def _load_data_slice(binary_path: str, section: str | None) -> tuple[bytes, int] | None:
    try:
        data = Path(binary_path).read_bytes()
    except OSError:
        return None

    if not section:
        return data, 0

    from backends.static.binary.sections import get_section_file_ranges

    ranges = get_section_file_ranges(binary_path)
    for name, start, end in ranges:
        if name == section:
            return data[start:end], start
    return None


def _pattern_for_encoding(encoding: str, min_len: int) -> bytes:
    if encoding == "utf-16-le":
        return rb"(?:[\x20-\x7e]\x00){" + str(min_len).encode() + rb",}"
    if encoding == "utf-16-be":
        return rb"(?:\x00[\x20-\x7e]){" + str(min_len).encode() + rb",}"
    return rb"[\x20-\x7e]{" + str(min_len).encode() + rb",}"


def _extract_strings_for_encoding(
    data_slice: bytes,
    *,
    encoding: str,
    min_len: int,
    offset_base: int,
    offset_map: dict[int, int],
) -> list[dict]:
    strings: list[dict] = []
    pattern = _pattern_for_encoding(encoding, min_len)
    for match in re.finditer(pattern, data_slice):
        raw = match.group(0)
        try:
            value = raw.decode(encoding)
        except UnicodeDecodeError:
            continue
        file_off = match.start() + offset_base
        addr = offset_map.get(file_off, file_off)
        strings.append(
            {
                "addr": f"0x{addr:x}",
                "value": value,
                "length": len(value),
                "encoding": encoding,
            }
        )
    return strings


def _extract_from_pe_imports(binary_path: str, min_len: int = 4) -> list[dict]:
    """Extrait noms DLL et fonctions depuis la table d'imports PE via lief.

    Fonctionne même sur un binaire packé : le loader PE doit pouvoir lire
    la table d'imports pour résoudre les adresses au démarrage.
    Retourne [] si lief est indisponible, si le binaire n'est pas un PE,
    ou en cas d'erreur.
    """
    try:
        import lief  # type: ignore[import-untyped]

        binary = lief.parse(binary_path)
        if binary is None or not isinstance(binary, lief.PE.Binary):
            return []
        base = binary.optional_header.imagebase
        results: list[dict] = []
        seen: set[str] = set()
        for imp in binary.imports:
            raw_dll = imp.name or ""
            dll = (raw_dll.decode() if isinstance(raw_dll, bytes) else raw_dll).strip()
            if dll and len(dll) >= min_len and dll not in seen:
                seen.add(dll)
                results.append(
                    {
                        "addr": "0x0",
                        "value": dll,
                        "length": len(dll),
                        "encoding": "utf-8",
                        "source": "pe_import",
                    }
                )
            for entry in imp.entries:
                raw_fn = entry.name or ""
                fn = (raw_fn.decode() if isinstance(raw_fn, bytes) else raw_fn).strip()
                if not fn or len(fn) < min_len:
                    continue
                iat_va = (base + entry.iat_address) if entry.iat_address else 0
                addr_str = f"0x{iat_va:x}" if iat_va else "0x0"
                key = f"{addr_str}:{fn}"
                if key in seen:
                    continue
                seen.add(key)
                results.append(
                    {
                        "addr": addr_str,
                        "value": fn,
                        "length": len(fn),
                        "encoding": "utf-8",
                        "source": "pe_import",
                    }
                )
        return results
    except Exception:
        return []


def extract_strings(
    binary_path: str,
    min_len: int = 4,
    encoding: str = "utf-8",
    section: str | None = None,
) -> list[dict]:
    """Extrait les chaînes lisibles d'un binaire.

    encoding: "auto", "utf-8", "utf-16-le", "utf-16-be"
    section: si fourni, limite aux octets de cette section (ELF/PE/Mach-O via lief).
             Si la section n'existe pas dans le binaire, retourne [].
    Returns [{addr, value, length, encoding}, ...].
    Les entrées issues de la table d'imports PE ont en plus un champ source="pe_import".
    """
    if encoding not in SUPPORTED_ENCODINGS:
        raise ValueError(f"unsupported encoding: {encoding}")

    loaded = _load_data_slice(binary_path, section)
    if loaded is None:
        return []
    data_slice, offset_base = loaded
    offset_map = build_offset_to_vaddr(binary_path)

    selected_encodings = (
        ("utf-8", "utf-16-le", "utf-16-be") if encoding == "auto" else (encoding,)
    )

    merged: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    for current_encoding in selected_encodings:
        for entry in _extract_strings_for_encoding(
            data_slice,
            encoding=current_encoding,
            min_len=min_len,
            offset_base=offset_base,
            offset_map=offset_map,
        ):
            key = (
                entry["addr"],
                entry["value"],
                entry["encoding"],
            )
            if key in seen:
                continue
            seen.add(key)
            merged.append(entry)

    # Augmente avec la table d'imports PE — fonctionne même si le binaire est packé,
    # car le loader PE doit pouvoir lire les imports au démarrage.
    # Appliqué uniquement sans filtre de section et pour encodages ASCII-compatibles.
    if section is None and encoding in ("auto", "utf-8"):
        for entry in _extract_from_pe_imports(binary_path, min_len=min_len):
            key = (entry["addr"], entry["value"], entry["encoding"])
            if key not in seen:
                seen.add(key)
                merged.append(entry)

    merged.sort(
        key=lambda entry: (
            int(str(entry.get("addr", "0")).replace("0x", ""), 16)
            if str(entry.get("addr", "")).startswith("0x")
            else 0,
            str(entry.get("encoding", "")),
            str(entry.get("value", "")),
        )
    )
    return merged


def extract_strings_system(binary_path: str, min_len: int = 4) -> list[dict]:
    """Utilise la commande `strings` du système si disponible."""
    import subprocess

    try:
        result = subprocess.run(
            ["strings", "-n", str(min_len), "-t", "x", binary_path],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0:
        return []

    offset_map = build_offset_to_vaddr(binary_path)

    strings = []
    for line in result.stdout.splitlines():
        # Format: "    1234 string content"
        match = re.match(r"^\s*([0-9a-fA-F]+)\s+(.+)$", line)
        if match:
            file_off = int(match.group(1), 16)
            addr = offset_map.get(file_off, file_off)
            value = match.group(2)
            strings.append(
                {
                    "addr": f"0x{addr:x}",
                    "value": value,
                    "length": len(value),
                    "encoding": "utf-8",
                }
            )
    return strings


def main() -> int:
    """Point d'entrée CLI : extrait les chaînes lisibles d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract strings from binary")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument("--min-len", type=int, default=4, help="Minimum string length")
    parser.add_argument(
        "--encoding",
        choices=list(SUPPORTED_ENCODINGS),
        default="auto",
        help="String encoding (auto = ASCII + wide strings)",
    )
    parser.add_argument(
        "--section", help="Limit to section (ELF/PE/Mach-O, e.g. .rodata, .rdata)"
    )
    parser.add_argument(
        "--no-system",
        action="store_true",
        help="Use Python impl instead of system strings",
    )
    args = parser.parse_args()

    if args.no_system or args.encoding != "utf-8" or args.section:
        strings = extract_strings(
            args.binary,
            min_len=args.min_len,
            encoding=args.encoding,
            section=args.section,
        )
    else:
        strings = extract_strings_system(args.binary, min_len=args.min_len)
        if not strings:
            strings = extract_strings(
                args.binary, min_len=args.min_len, encoding=args.encoding
            )

    out = json.dumps(strings, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Strings written to {args.output} ({len(strings)} strings)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
