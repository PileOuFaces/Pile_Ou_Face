# SPDX-License-Identifier: AGPL-3.0-only
"""Recherche dans un binaire (hex, texte ou regex)."""

from __future__ import annotations

import re
from pathlib import Path


def _parse_int_literal(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text, 10)
    except ValueError:
        return None


def _enrich_with_raw_vaddr(result: dict, raw_base_addr: int | None) -> dict:
    if raw_base_addr is None:
        return result
    offset = result.get("offset")
    if not isinstance(offset, int):
        return result
    vaddr = raw_base_addr + offset
    enriched = dict(result)
    enriched["vaddr"] = vaddr
    enriched["vaddr_hex"] = f"0x{vaddr:x}"
    return enriched


def search_in_binary(
    binary_path: str,
    pattern: str,
    mode: str = "text",
    section: str | None = None,
    max_results: int | None = None,
    min_length: int | None = None,
    max_length: int | None = None,
    case_sensitive: bool = True,
    offset_start: int | None = None,
    offset_end: int | None = None,
    raw_base_addr: int | str | None = None,
) -> list[dict]:
    """Recherche un pattern dans un binaire.
    mode: "text" (ASCII/UTF-8), "hex" ou "regex"
    pattern: pour hex, chaîne sans espaces (ex: 43434343)
             pour regex, pattern Python (ex: \\x41{4} ou [A-Z]+)
    section: si fourni, limite la recherche à cette section (ELF uniquement)
    max_results: nombre maximum de résultats (None = illimité)
    min_length: longueur minimale du match (filtrage)
    max_length: longueur maximale du match (filtrage)
    case_sensitive: si False, recherche insensible à la casse (mode text uniquement)
    offset_start: offset de début (inclus) pour filtrer les résultats
    offset_end: offset de fin (inclus) pour filtrer les résultats
    raw_base_addr: adresse virtuelle de base pour un blob brut.
    Returns [{offset, offset_hex, value, context, length, vaddr?, vaddr_hex?}, ...]
    """
    path = Path(binary_path)
    if not path.exists():
        return []

    try:
        data = path.read_bytes()
    except OSError:
        return []

    data_slice = data
    offset_base = 0
    if section:
        from backends.static.binary.sections import get_section_file_ranges

        ranges = get_section_file_ranges(binary_path)
        for name, start, end in ranges:
            if name == section:
                data_slice = data[start:end]
                offset_base = start
                break
        else:
            return []

    raw_base = _parse_int_literal(raw_base_addr)
    results = []
    if mode == "regex":
        # Regex sur les bytes : décoder en latin-1 pour préserver chaque octet
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            regex = re.compile(pattern, flags)
            text = data_slice.decode("latin-1")
        except (re.error, UnicodeDecodeError):
            return []
        for match in regex.finditer(text):
            start = match.start()
            matched = match.group(0)
            matched_bytes = matched.encode("latin-1")
            match_len = len(matched_bytes)
            abs_offset = start + offset_base
            # Filtrage offset
            if offset_start is not None and abs_offset < offset_start:
                continue
            if offset_end is not None and abs_offset > offset_end:
                continue
            # Filtrage longueur
            if min_length is not None and match_len < min_length:
                continue
            if max_length is not None and match_len > max_length:
                continue
            ctx_before = data_slice[max(0, start - 8) : start]
            ctx_after = data_slice[start + match_len : start + match_len + 8]
            context = (ctx_before + matched_bytes + ctx_after).hex()
            val_hex = matched_bytes.hex()
            value = val_hex if len(val_hex) <= 64 else val_hex[:32] + "..." + val_hex[-16:]
            results.append(
                _enrich_with_raw_vaddr(
                    {
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:x}",
                        "value": value,
                        "context": context,
                        "length": match_len,
                    },
                    raw_base,
                )
            )
            if max_results is not None and len(results) >= max_results:
                break
    elif mode == "hex":
        # Nettoyer le pattern hex
        hex_clean = re.sub(r"\s|0x", "", pattern, flags=re.IGNORECASE)
        if not re.match(r"^[0-9a-fA-F]*$", hex_clean) or len(hex_clean) % 2:
            return []
        try:
            needle = bytes.fromhex(hex_clean)
        except ValueError:
            return []
        if not needle:
            return []
        needle_len = len(needle)
        # min/max_length en mode hex : longueur fixe = len(needle)
        if min_length is not None and needle_len < min_length:
            return []
        if max_length is not None and needle_len > max_length:
            return []
        start = 0
        while True:
            pos = data_slice.find(needle, start)
            if pos < 0:
                break
            abs_offset = pos + offset_base
            if offset_start is not None and abs_offset < offset_start:
                start = pos + 1
                continue
            if offset_end is not None and abs_offset > offset_end:
                break
            context = data_slice[max(0, pos - 8) : pos + needle_len + 8].hex()
            results.append(
                _enrich_with_raw_vaddr(
                    {
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:x}",
                        "value": hex_clean,
                        "context": context,
                        "length": needle_len,
                    },
                    raw_base,
                )
            )
            start = pos + 1
            if max_results is not None and len(results) >= max_results:
                break
    else:
        # Mode texte
        try:
            pattern_bytes = pattern.encode("utf-8")
        except UnicodeEncodeError:
            return []
        if not pattern_bytes:
            return []
        pat_len = len(pattern_bytes)
        # min/max_length en mode text : longueur fixe = len(pattern_bytes)
        if min_length is not None and pat_len < min_length:
            return []
        if max_length is not None and pat_len > max_length:
            return []
        start = 0
        if case_sensitive:
            search_data = data_slice
            search_pat = pattern_bytes
        else:
            search_data = data_slice.lower()
            search_pat = pattern_bytes.lower()
        while True:
            pos = search_data.find(search_pat, start)
            if pos < 0:
                break
            abs_offset = pos + offset_base
            if offset_start is not None and abs_offset < offset_start:
                start = pos + 1
                continue
            if offset_end is not None and abs_offset > offset_end:
                break
            ctx_before = data_slice[max(0, pos - 8) : pos]
            match_bytes = data_slice[pos : pos + pat_len]
            ctx_after = data_slice[pos + pat_len : pos + pat_len + 8]
            context = (ctx_before + match_bytes + ctx_after).hex()
            # Valeur réelle des bytes trouvés (insensible à la casse = bytes originaux)
            actual_value = data_slice[pos : pos + pat_len].decode("utf-8", errors="replace")
            results.append(
                _enrich_with_raw_vaddr(
                    {
                        "offset": abs_offset,
                        "offset_hex": f"0x{abs_offset:x}",
                        "value": actual_value,
                        "context": context,
                        "length": pat_len,
                    },
                    raw_base,
                )
            )
            start = pos + 1
            if max_results is not None and len(results) >= max_results:
                break

    return results


def main() -> int:
    """Point d'entrée CLI : recherche un pattern (hex ou texte) dans un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Search in binary (hex or text)")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--pattern", required=True, help="Pattern to search (hex or text)")
    parser.add_argument(
        "--mode", choices=["text", "hex", "regex"], default="text", help="Search mode"
    )
    parser.add_argument("--section", help="Limit to section (ELF only)")
    parser.add_argument(
        "--max-results",
        type=int,
        default=None,
        help="Maximum number of results to return (default: unlimited)",
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    parser.add_argument("--min-length", type=int, default=None, dest="min_length")
    parser.add_argument("--max-length", type=int, default=None, dest="max_length")
    parser.add_argument("--case-insensitive", action="store_true")
    parser.add_argument(
        "--offset-start", type=lambda x: int(x, 0), default=None, dest="offset_start"
    )
    parser.add_argument("--offset-end", type=lambda x: int(x, 0), default=None, dest="offset_end")
    parser.add_argument("--raw-base-addr", default=None, dest="raw_base_addr")
    args = parser.parse_args()

    case_sensitive = not args.case_insensitive
    results = search_in_binary(
        args.binary,
        args.pattern,
        mode=args.mode,
        section=args.section or None,
        max_results=getattr(args, "max_results", None),
        min_length=args.min_length,
        max_length=args.max_length,
        case_sensitive=case_sensitive,
        offset_start=args.offset_start,
        offset_end=args.offset_end,
        raw_base_addr=args.raw_base_addr,
    )
    out = json.dumps(results, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Search results written to {args.output} ({len(results)} matches)")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
