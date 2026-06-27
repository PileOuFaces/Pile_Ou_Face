# SPDX-License-Identifier: AGPL-3.0-only
"""Analyse d'entropie Shannon pour binaires.

CLI:
  python entropy.py --binary <path> [--threshold 7.0] [--window 256]

Output JSON:
  {
    "global": float,
    "sections": [{"name": str, "entropy": float, "size": int}],
    "high_entropy_regions": [{"offset": int, "offset_hex": str, "entropy": float}],
    "error": null
  }
"""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any


def entropy_of_bytes(data: bytes) -> float:
    """Calcule l'entropie de Shannon en bits/byte (0.0–8.0).

    0.0 = données uniformes (tous identiques)
    8.0 = entropie maximale (distribution parfaitement uniforme sur 256 valeurs)
    """
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    length = len(data)
    entropy = 0.0
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return entropy


def entropy_of_file(binary_path: str) -> dict[str, Any]:
    """Calcule l'entropie globale et par section d'un binaire.

    Returns:
        {"global": float, "sections": [...], "high_entropy_regions": [], "error": null}
        ou {"error": "...", "global": 0.0, "sections": [], "high_entropy_regions": []}
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "error": f"Fichier introuvable : {binary_path}",
            "global": 0.0,
            "sections": [],
            "high_entropy_regions": [],
        }

    try:
        data = path.read_bytes()
    except OSError as e:
        return {
            "error": str(e),
            "global": 0.0,
            "sections": [],
            "high_entropy_regions": [],
        }

    global_entropy = entropy_of_bytes(data)
    sections = _entropy_by_section(binary_path, data)

    return {
        "global": round(global_entropy, 4),
        "sections": sections,
        "high_entropy_regions": [],
        "error": None,
    }


def high_entropy_regions(
    binary_path: str,
    threshold: float = 7.0,
    window: int = 256,
    step: int | None = None,
) -> list[dict]:
    """Détecte les zones à haute entropie par sliding window.

    Args:
        threshold: seuil d'entropie (défaut 7.0 bits/byte)
        window: taille de la fenêtre en bytes (défaut 256)
        step: pas de déplacement (défaut = window // 4)

    Returns:
        [{"offset": int, "offset_hex": str, "entropy": float}, ...]
    """
    path = Path(binary_path)
    if not path.exists():
        return []
    try:
        data = path.read_bytes()
    except OSError:
        return []

    if step is None:
        step = max(1, window // 4)

    regions: list[dict] = []
    in_region = False
    region_start = 0
    region_max_entropy = 0.0

    for offset in range(0, len(data) - window + 1, step):
        chunk = data[offset : offset + window]
        e = entropy_of_bytes(chunk)
        if e >= threshold:
            if not in_region:
                in_region = True
                region_start = offset
                region_max_entropy = e
            else:
                region_max_entropy = max(region_max_entropy, e)
        else:
            if in_region:
                regions.append(
                    {
                        "offset": region_start,
                        "offset_hex": f"0x{region_start:x}",
                        "entropy": round(region_max_entropy, 4),
                    }
                )
                in_region = False

    if in_region:
        regions.append(
            {
                "offset": region_start,
                "offset_hex": f"0x{region_start:x}",
                "entropy": round(region_max_entropy, 4),
            }
        )

    return regions


def _entropy_by_section(binary_path: str, data: bytes) -> list[dict]:
    """Calcule l'entropie pour chaque section du binaire via lief."""
    try:
        import lief

        binary = lief.parse(binary_path)
        if binary is None:
            return []
        sections = []
        for sec in binary.sections:
            name = sec.name or "<unnamed>"
            offset = sec.offset
            size = sec.size
            if size == 0:
                continue
            chunk = data[offset : offset + size]
            if not chunk:
                continue
            e = entropy_of_bytes(chunk)
            sections.append(
                {
                    "name": name,
                    "entropy": round(e, 4),
                    "size": size,
                    "offset": offset,
                    "offset_hex": f"0x{offset:x}",
                }
            )
        return sections
    except Exception:
        return []


def main() -> int:
    """CLI : calcule l'entropie d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Compute Shannon entropy of a binary")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument(
        "--threshold",
        type=float,
        default=7.0,
        help="Entropy threshold for high-entropy regions (default: 7.0)",
    )
    parser.add_argument(
        "--window",
        type=int,
        default=256,
        help="Sliding window size in bytes (default: 256)",
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    result = entropy_of_file(args.binary)
    if not result.get("error"):
        result["high_entropy_regions"] = high_entropy_regions(
            args.binary, threshold=args.threshold, window=args.window
        )

    out = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        n = len(result.get("high_entropy_regions", []))
        print(f"Entropy written to {args.output} ({n} high-entropy region(s))")
    else:
        print(out)

    return 1 if result.get("error") else 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
