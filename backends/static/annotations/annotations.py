# SPDX-License-Identifier: AGPL-3.0-only
"""Annotations persistantes sur les adresses d'un binaire.

Stocke commentaires et renommages dans le cache SQLite (.pfdb).
Façade de haut niveau sur DisasmCache.annotations.

Usage:
    from backends.static.annotations.annotations import AnnotationStore

    store = AnnotationStore("/path/to/binary.elf")
    store.comment("0x401000", "entry point — initialise le stack frame")
    store.rename("0x401000", "my_main")
    for ann in store.list():
        print(ann)
    store.close()

    # Ou avec context manager
    with AnnotationStore("/path/to/binary.elf") as store:
        store.comment("0x401050", "checks argc")
"""

from __future__ import annotations

from typing import List, Optional  # List needed: 'list' method name shadows builtin

from backends.static.cache.cache import DisasmCache, default_cache_path
from backends.shared.log import configure_logging, get_logger

logger = get_logger(__name__)

# Kinds standardisés
KIND_COMMENT = "comment"
KIND_RENAME = "rename"


class AnnotationStore:
    """Façade pour les annotations persistantes d'un binaire.

    Gère commentaires et renommages via le cache SQLite.
    """

    def __init__(self, binary_path: str, cache_path: Optional[str] = None) -> None:
        """Initialise le store.

        Args:
            binary_path: Chemin absolu vers le binaire analysé.
            cache_path: Chemin vers le fichier cache SQLite (None = chemin auto).
        """
        self._binary_path = binary_path
        db_path = cache_path or default_cache_path(binary_path)
        self._cache = DisasmCache(db_path)

    def comment(self, addr: str, text: str) -> None:
        """Ajoute ou remplace un commentaire sur une adresse.

        Args:
            addr: Adresse (ex: "0x401000")
            text: Texte du commentaire
        """
        self._cache.save_annotation(self._binary_path, addr, KIND_COMMENT, text)
        logger.debug("Comment set: %s → %r", addr, text)

    def rename(self, addr: str, name: str) -> None:
        """Renomme la fonction ou le symbole à une adresse.

        Args:
            addr: Adresse (ex: "0x401000")
            name: Nouveau nom (ex: "my_main")
        """
        self._cache.save_annotation(self._binary_path, addr, KIND_RENAME, name)
        logger.debug("Rename set: %s → %r", addr, name)

    def get(self, addr: str) -> List[dict]:
        """Retourne toutes les annotations pour une adresse.

        Args:
            addr: Adresse cible

        Returns:
            [{addr, kind, value}, ...]
        """
        return self._cache.get_annotations(self._binary_path, addr=addr)

    def get_comment(self, addr: str) -> Optional[str]:
        """Retourne le commentaire d'une adresse, ou None si absent."""
        for ann in self._cache.get_annotations(self._binary_path, addr=addr):
            if ann["kind"] == KIND_COMMENT:
                return str(ann["value"])
        return None

    def get_name(self, addr: str) -> Optional[str]:
        """Retourne le nom renommé d'une adresse, ou None si absent."""
        for ann in self._cache.get_annotations(self._binary_path, addr=addr):
            if ann["kind"] == KIND_RENAME:
                return str(ann["value"])
        return None

    def list(self, addr: Optional[str] = None) -> List[dict]:  # type: ignore[override]
        """Liste toutes les annotations (ou filtrées par adresse).

        Returns:
            [{addr, kind, value}, ...]
        """
        return self._cache.get_annotations(self._binary_path, addr=addr)

    def delete(self, addr: str, kind: Optional[str] = None) -> int:
        """Supprime les annotations d'une adresse.

        Args:
            addr: Adresse cible
            kind: Type spécifique (None = tout supprimer)

        Returns:
            Nombre d'annotations supprimées.
        """
        n = self._cache.delete_annotation(self._binary_path, addr, kind=kind)
        logger.debug("Deleted %d annotation(s) at %s (kind=%s)", n, addr, kind)
        return n

    def export_json(self) -> List[dict]:
        """Retourne toutes les annotations au format JSON-serializable."""
        return self._cache.get_annotations(self._binary_path)

    def close(self) -> None:
        self._cache.close()

    def __enter__(self) -> "AnnotationStore":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def main() -> int:
    """Point d'entrée CLI : gérer les annotations d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Manage binary annotations (comments, renames)")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--cache-db", help="Cache DB path (default: auto)")
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List all annotations")
    p_list.add_argument("--addr", help="Filter by address")
    p_list.add_argument("--output", help="Output JSON path (default: stdout)")

    # comment
    p_comment = sub.add_parser("comment", help="Add a comment")
    p_comment.add_argument("--addr", required=True, help="Target address")
    p_comment.add_argument("--text", required=True, help="Comment text")

    # rename
    p_rename = sub.add_parser("rename", help="Rename a function/symbol")
    p_rename.add_argument("--addr", required=True, help="Target address")
    p_rename.add_argument("--name", required=True, help="New name")

    # delete
    p_del = sub.add_parser("delete", help="Delete annotations")
    p_del.add_argument("--addr", required=True, help="Target address")
    p_del.add_argument(
        "--kind",
        choices=[KIND_COMMENT, KIND_RENAME],
        help="Specific kind to delete (default: all)",
    )

    args = parser.parse_args()
    configure_logging()

    with AnnotationStore(args.binary, cache_path=getattr(args, "cache_db", None)) as store:
        if args.cmd == "list":
            annotations = store.list(addr=getattr(args, "addr", None))
            out = json.dumps(annotations, indent=2, ensure_ascii=False)
            if getattr(args, "output", None):
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out)
                print(f"Annotations written to {args.output} ({len(annotations)} entries)")
            else:
                print(out)

        elif args.cmd == "comment":
            store.comment(args.addr, args.text)
            print(f"Comment set at {args.addr}")

        elif args.cmd == "rename":
            store.rename(args.addr, args.name)
            print(f"Renamed {args.addr} → {args.name}")

        elif args.cmd == "delete":
            n = store.delete(args.addr, kind=getattr(args, "kind", None))
            print(f"Deleted {n} annotation(s) at {args.addr}")

    return 0


import json as _json
from pathlib import Path as _Path
import time as _time


def get_annotations_path(workspace: str) -> "_Path":
    return _Path(workspace) / ".pof" / "annotations.json"


def load_annotations(workspace: str, binary_sha256: str) -> dict:
    """Load annotations for a specific binary from workspace storage."""
    path = get_annotations_path(workspace)
    if not path.exists():
        return {}
    try:
        data = _json.loads(path.read_text())
        return data.get(binary_sha256, {})
    except Exception:
        return {}


def save_annotation(
    workspace: str, binary_sha256: str, addr: str, note: str, color: str = "#4ec9b0"
) -> None:
    """Persist a note for a specific address in the workspace annotations file."""
    path = get_annotations_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        data = _json.loads(path.read_text()) if path.exists() else {}
    except Exception:
        data = {}
    if binary_sha256 not in data:
        data[binary_sha256] = {}
    data[binary_sha256][addr] = {
        "note": note,
        "color": color,
        "timestamp": _time.time(),
    }
    path.write_text(_json.dumps(data, indent=2))


if __name__ == "__main__":
    import sys
    import argparse as _argparse
    import hashlib as _hashlib

    # If the first argument is --save or --load, use the new persistence CLI
    if len(sys.argv) > 1 and sys.argv[1] in ("--save", "--load"):
        parser = _argparse.ArgumentParser()
        parser.add_argument("--save", action="store_true")
        parser.add_argument("--load", action="store_true")
        parser.add_argument("--workspace", required=True)
        parser.add_argument("--binary", default=None)
        parser.add_argument("--addr", default=None)
        parser.add_argument("--note", default="")
        parser.add_argument("--color", default="#4ec9b0")
        args = parser.parse_args()

        binary_sha256 = "unknown"
        if args.binary:
            try:
                binary_sha256 = _hashlib.sha256(open(args.binary, "rb").read()).hexdigest()
            except Exception:
                pass

        if args.save and args.addr:
            save_annotation(args.workspace, binary_sha256, args.addr, args.note, args.color)
            print('{"saved": true}')
        elif args.load:
            result = load_annotations(args.workspace, binary_sha256)
            print(_json.dumps(result))
    else:
        sys.exit(main())
