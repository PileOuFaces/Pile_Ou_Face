# SPDX-License-Identifier: AGPL-3.0-only
"""Best-effort direct IDB/i64 adapter backed by the optional python-idb package."""

from __future__ import annotations

import argparse
import binascii
import json
from contextlib import nullcontext
from typing import Any

from backends.static.annotations.canonical_import import (
    FORMAT,
    import_canonical_document,
)


class IdbImportError(ValueError):
    """Raised when an IDB cannot be converted to canonical metadata."""


def _call_first(target: Any, names: tuple[str, ...], *args: Any) -> Any:
    for name in names:
        method = getattr(target, name, None)
        if callable(method):
            try:
                return method(*args)
            except (KeyError, TypeError, ValueError):
                continue
    return None


def extract_idb_document(
    idb_path: str, binary_path: str, *, idb_module: Any | None = None
) -> dict[str, Any]:
    """Extract reliable function names/comments through python-idb's emulated API."""
    if idb_module is None:
        try:
            import idb as idb_module
        except ImportError as exc:
            raise IdbImportError(
                "Le parsing direct requiert python-idb 0.8 (`pip install python-idb`)."
            ) from exc
    try:
        database_context = idb_module.from_file(idb_path)
    except Exception as exc:
        raise IdbImportError(f"IDB illisible: {exc}") from exc
    if not hasattr(database_context, "__enter__"):
        database_context = nullcontext(database_context)
    functions: list[dict[str, Any]] = []
    diagnostics: list[str] = []
    stored_hash = ""
    try:
        with database_context as database:
            api = idb_module.IDAPython(database)
            digest = _call_first(
                api.ida_nalt, ("retrieve_input_file_sha256",)
            ) or _call_first(api.idc, ("GetInputSHA256",))
            if isinstance(digest, bytes):
                stored_hash = binascii.hexlify(digest).decode("ascii")
            elif digest:
                stored_hash = str(digest)
            addresses = api.idautils.Functions()
            for address in addresses:
                name = _call_first(
                    api.idc, ("get_func_name", "GetFunctionName"), address
                )
                regular = _call_first(
                    api.idc, ("get_func_cmt",), address, False
                ) or _call_first(api.idc, ("Comment",), address)
                repeatable = _call_first(
                    api.idc, ("get_func_cmt",), address, True
                ) or _call_first(api.idc, ("RptCmt",), address)
                comments = [str(value) for value in (regular, repeatable) if value]
                functions.append(
                    {
                        "addr": hex(int(address)),
                        "name": str(name or f"sub_{int(address):x}"),
                        "comment": "\n".join(dict.fromkeys(comments)),
                    }
                )
    except Exception as exc:
        raise IdbImportError(f"Échec du parsing IDB: {exc}") from exc
    if not functions:
        diagnostics.append("Aucune fonction exploitable trouvée dans l’IDB.")
    if not stored_hash:
        raise IdbImportError(
            "L’IDB ne contient pas l’empreinte SHA-256 du binaire source."
        )
    return {
        "format": FORMAT,
        "source": {"tool": "idb", "adapter": "python-idb", "path": idb_path},
        "binary_sha256": stored_hash.lower(),
        "functions": functions,
        "comments": [],
        "types": [],
        "bookmarks": [],
        "diagnostics": diagnostics,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import IDB/i64 metadata")
    parser.add_argument("--idb", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--cache-db")
    parser.add_argument("--workspace-root")
    args = parser.parse_args()
    try:
        document = extract_idb_document(args.idb, args.binary)
        report = import_canonical_document(
            args.binary,
            document,
            cache_path=args.cache_db,
            workspace_root=args.workspace_root,
        )
        report["diagnostics"] = document["diagnostics"] + report["diagnostics"]
        print(json.dumps(report, ensure_ascii=False))
        return 0
    except (OSError, IdbImportError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
