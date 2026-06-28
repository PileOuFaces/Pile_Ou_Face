# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction et décodage des ressources PE (.rsrc).

CLI:
  python pe_resources.py --binary <path>

Output JSON:
  {
    "format": "PE",
    "resources": [
      {"type": "RT_STRING", "id": "1", "lang": "0", "size": 128,
       "decoded": {"strings": ["Hello"]}, "hex_preview": "48 65 6c 6c 6f"}
    ],
    "count": N,
    "error": null
  }
"""

from __future__ import annotations

__mcp_enabled__ = True

import argparse
import contextlib
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

try:
    import lief

    _LIEF_AVAILABLE = True
except ImportError:
    lief = None
    _LIEF_AVAILABLE = False

_RT_NAMES = {
    1: "RT_CURSOR",
    2: "RT_BITMAP",
    3: "RT_ICON",
    4: "RT_MENU",
    5: "RT_DIALOG",
    6: "RT_STRING",
    7: "RT_FONTDIR",
    8: "RT_FONT",
    9: "RT_ACCELERATOR",
    10: "RT_RCDATA",
    11: "RT_MESSAGETABLE",
    14: "RT_GROUP_ICON",
    16: "RT_VERSION",
    23: "RT_HTML",
    24: "RT_MANIFEST",
}


def _hex_preview(data: bytes, max_bytes: int = 24) -> str:
    return " ".join(f"{b:02x}" for b in data[:max_bytes])


def _decode_rt_string(data: bytes) -> dict:
    strings, pos = [], 0
    while pos + 2 <= len(data):
        length = int.from_bytes(data[pos : pos + 2], "little")
        pos += 2
        if length > 0 and pos + length * 2 <= len(data):
            with contextlib.suppress(Exception):
                strings.append(
                    data[pos : pos + length * 2].decode("utf-16-le", errors="replace")
                )
            pos += length * 2
    return {"strings": strings}


def _decode_rt_manifest(data: bytes) -> dict:
    return {"xml": data.decode("utf-8", errors="replace")[:2000]}


def _decode_rt_version(data: bytes) -> dict:
    magic = b"\xbd\x04\xef\xfe"
    idx = data.find(magic)
    if idx < 0:
        return {"raw": True}
    try:
        ms = int.from_bytes(data[idx + 8 : idx + 12], "little")
        ls = int.from_bytes(data[idx + 12 : idx + 16], "little")
        ms2 = int.from_bytes(data[idx + 16 : idx + 20], "little")
        ls2 = int.from_bytes(data[idx + 20 : idx + 24], "little")
        return {
            "file_version": f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}",
            "product_version": f"{ms2 >> 16}.{ms2 & 0xFFFF}.{ls2 >> 16}.{ls2 & 0xFFFF}",
        }
    except Exception:
        return {"raw": True}


def _decode_rt_bitmap_icon(data: bytes, rtype: str) -> dict:
    if len(data) < 16:
        return {}
    try:
        w = int.from_bytes(data[4:8], "little", signed=True)
        h = int.from_bytes(data[8:12], "little", signed=True)
        bpp = int.from_bytes(data[14:16], "little")
        height = abs(h) // 2 if rtype == "RT_ICON" else abs(h)
        return {"width": abs(w), "height": height, "bpp": bpp}
    except Exception:
        return {}


def _decode_resource(rtype_name: str, data: bytes) -> dict | None:
    if rtype_name == "RT_STRING":
        return _decode_rt_string(data)
    if rtype_name == "RT_MANIFEST":
        return _decode_rt_manifest(data)
    if rtype_name == "RT_VERSION":
        return _decode_rt_version(data)
    if rtype_name in ("RT_BITMAP", "RT_ICON"):
        return _decode_rt_bitmap_icon(data, rtype_name)
    if rtype_name == "RT_RCDATA":
        return {"hex": _hex_preview(data, 64), "size": len(data)}
    return None


def get_pe_resources(binary_path: str) -> dict:
    """Extract PE resources (.rsrc section): icons, manifests, version info, dialogs, strings tables."""
    if not _LIEF_AVAILABLE:
        return {
            "error": "lief non disponible",
            "format": "unknown",
            "resources": [],
            "count": 0,
            "applicable": False,
        }
    if not os.path.isfile(binary_path):
        return {
            "error": f"Fichier introuvable : {binary_path}",
            "format": "unknown",
            "resources": [],
            "count": 0,
            "applicable": False,
        }

    binary = lief.parse(binary_path)
    if binary is None:
        return {
            "error": "Parsing échoué",
            "format": "unknown",
            "resources": [],
            "count": 0,
            "applicable": False,
        }
    if not isinstance(binary, lief.PE.Binary):
        fmt = type(binary).__module__.split(".")[-1].upper()
        return {
            "error": None,
            "format": fmt,
            "resources": [],
            "count": 0,
            "applicable": False,
            "message": f"Les ressources embarquées sont spécifiques au format PE. Ce binaire est de type {fmt}.",
        }

    root = getattr(binary, "resources", None)
    if root is None:
        return {
            "format": "PE",
            "resources": [],
            "count": 0,
            "error": None,
            "applicable": True,
        }

    resources = []
    try:
        for type_node in root.childs:
            rtype_id = type_node.id
            rtype_name = _RT_NAMES.get(rtype_id, f"RT_{rtype_id}")
            for name_node in type_node.childs:
                rid = name_node.name if name_node.is_named else name_node.id
                for lang_node in name_node.childs:
                    try:
                        data = bytes(lang_node.content)
                        resources.append(
                            {
                                "type": rtype_name,
                                "id": str(rid),
                                "lang": str(lang_node.id),
                                "size": len(data),
                                "decoded": _decode_resource(rtype_name, data),
                                "hex_preview": _hex_preview(data),
                            }
                        )
                    except Exception:
                        pass
    except Exception as e:
        return {
            "format": "PE",
            "resources": resources,
            "count": len(resources),
            "error": str(e),
            "applicable": True,
        }

    return {
        "format": "PE",
        "resources": resources,
        "count": len(resources),
        "error": None,
        "applicable": True,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Extract PE resources")
    parser.add_argument("--binary", required=True)
    args = parser.parse_args()
    print(json.dumps(get_pe_resources(args.binary), indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
