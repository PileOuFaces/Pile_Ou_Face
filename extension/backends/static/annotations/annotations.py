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

import builtins

from backends.shared.log import configure_logging, get_logger
from backends.static.annotations import overlay_patch
from backends.static.annotations.annotation_db import AnnotationDb

logger = get_logger(__name__)

# Kinds standardisés
KIND_COMMENT = "comment"
KIND_RENAME = "rename"
KIND_REVIEW_STATUS = "review_status"
KIND_REVIEW_NOTES = "review_notes"
KIND_BOOKMARK = "bookmark"  # value = label
KIND_BOOKMARK_COLOR = "bookmark_color"


class AnnotationStore:
    """Façade pour les annotations persistantes d'un binaire.

    Gère commentaires et renommages via le cache SQLite.
    """

    def __init__(self, binary_path: str, cache_path: str | None = None) -> None:
        """Initialise le store.

        Args:
            binary_path: Chemin absolu vers le binaire analysé.
            cache_path: Chemin vers le fichier cache SQLite (None = chemin auto).
        """
        self._binary_path = binary_path
        self._cache = AnnotationDb(cache_path)

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

    def ai_comment(self, addr: str, text: str) -> bool:
        """Suggère un commentaire au nom de l'IA, sans écraser une note humaine.

        Returns:
            True si écrit, False si une annotation manuelle occupait déjà
            ce (addr, kind) et a été préservée.
        """
        written = self._cache.save_ai_annotation(
            self._binary_path, addr, KIND_COMMENT, text
        )
        logger.debug(
            "AI comment %s: %s → %r", "set" if written else "skipped (user)", addr, text
        )
        return written

    def ai_rename(self, addr: str, name: str) -> bool:
        """Suggère un renommage au nom de l'IA, sans écraser un renommage humain.

        Returns:
            True si écrit, False si une annotation manuelle occupait déjà
            ce (addr, kind) et a été préservée.
        """
        written = self._cache.save_ai_annotation(
            self._binary_path, addr, KIND_RENAME, name
        )
        logger.debug(
            "AI rename %s: %s → %r", "set" if written else "skipped (user)", addr, name
        )
        return written

    def get(self, addr: str) -> builtins.list[dict]:
        """Retourne toutes les annotations pour une adresse.

        Args:
            addr: Adresse cible

        Returns:
            [{addr, kind, value}, ...]
        """
        return self._cache.get_annotations(self._binary_path, addr=addr)

    def get_comment(self, addr: str) -> str | None:
        """Retourne le commentaire d'une adresse, ou None si absent."""
        for ann in self._cache.get_annotations(self._binary_path, addr=addr):
            if ann["kind"] == KIND_COMMENT:
                return str(ann["value"])
        return None

    def get_name(self, addr: str) -> str | None:
        """Retourne le nom renommé d'une adresse, ou None si absent."""
        for ann in self._cache.get_annotations(self._binary_path, addr=addr):
            if ann["kind"] == KIND_RENAME:
                return str(ann["value"])
        return None

    def list(self, addr: str | None = None) -> builtins.list[dict]:  # type: ignore[override]
        """Liste toutes les annotations (ou filtrées par adresse).

        Returns:
            [{addr, kind, value}, ...]
        """
        return self._cache.get_annotations(self._binary_path, addr=addr)

    def delete(self, addr: str, kind: str | None = None) -> int:
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

    def set_review(self, addr: str, status: str = "", notes: str = "") -> None:
        """Définit le statut de revue et/ou les notes sur une adresse.

        Args:
            addr: Adresse cible
            status: Statut de revue (ex: "reviewed"), vide pour supprimer
            notes: Notes de revue, vide pour supprimer
        """
        if status:
            self._cache.save_annotation(
                self._binary_path, addr, KIND_REVIEW_STATUS, status
            )
        else:
            self._cache.delete_annotation(
                self._binary_path, addr, kind=KIND_REVIEW_STATUS
            )
        if notes:
            self._cache.save_annotation(
                self._binary_path, addr, KIND_REVIEW_NOTES, notes
            )
        else:
            self._cache.delete_annotation(
                self._binary_path, addr, kind=KIND_REVIEW_NOTES
            )

    def get_review(self, addr: str) -> dict:
        """Retourne le statut et les notes de revue d'une adresse.

        Returns:
            {"status": str, "notes": str} (chaînes vides si absents)
        """
        rows = self._cache.get_annotations(self._binary_path, addr=addr)
        by_kind = {r["kind"]: r["value"] for r in rows}
        return {
            "status": by_kind.get(KIND_REVIEW_STATUS, ""),
            "notes": by_kind.get(KIND_REVIEW_NOTES, ""),
        }

    def set_bookmark(self, addr: str, label: str = "", color: str = "#4ec9b0") -> None:
        """Ajoute ou remplace un bookmark sur une adresse.

        Args:
            addr: Adresse cible
            label: Libellé du bookmark (défaut: l'adresse elle-même)
            color: Couleur du bookmark (hex)
        """
        self._cache.save_annotation(
            self._binary_path, addr, KIND_BOOKMARK, label or addr
        )
        self._cache.save_annotation(self._binary_path, addr, KIND_BOOKMARK_COLOR, color)

    def delete_bookmark(self, addr: str) -> None:
        """Supprime le bookmark d'une adresse."""
        self._cache.delete_annotation(self._binary_path, addr, kind=KIND_BOOKMARK)
        self._cache.delete_annotation(self._binary_path, addr, kind=KIND_BOOKMARK_COLOR)

    def clear_bookmarks(self) -> None:
        """Supprime tous les bookmarks du binaire (sans toucher aux autres kinds)."""
        for row in self.list():
            if row["kind"] in (KIND_BOOKMARK, KIND_BOOKMARK_COLOR):
                self._cache.delete_annotation(
                    self._binary_path, row["addr"], kind=row["kind"]
                )

    def list_bookmarks(self) -> builtins.list[dict]:
        """Liste tous les bookmarks du binaire.

        Returns:
            [{addr, label, color}, ...]
        """
        rows = self.list()
        by_addr: dict[str, dict] = {}
        for r in rows:
            if r["kind"] == KIND_BOOKMARK:
                by_addr.setdefault(r["addr"], {})["label"] = r["value"]
            elif r["kind"] == KIND_BOOKMARK_COLOR:
                by_addr.setdefault(r["addr"], {})["color"] = r["value"]
        return [
            {
                "addr": addr,
                "label": v.get("label", addr),
                "color": v.get("color", "#4ec9b0"),
            }
            for addr, v in by_addr.items()
            if "label" in v
        ]

    def export_json(self) -> builtins.list[dict]:
        """Retourne toutes les annotations au format JSON-serializable."""
        return self._cache.get_annotations(self._binary_path)

    def close(self) -> None:
        self._cache.close()

    def __enter__(self) -> AnnotationStore:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def _grouped_export(store: AnnotationStore) -> dict:
    """Construit le dict groupé par adresse attendu côté extension VS Code."""
    out: dict = {}
    for row in store.list():
        entry = out.setdefault(row["addr"], {})
        if row["kind"] == KIND_COMMENT:
            entry["comment"] = row["value"]
            entry["commentSource"] = row["source"]
            entry["updated"] = row["updated_at"]
        elif row["kind"] == KIND_RENAME:
            entry["name"] = row["value"]
            entry["nameSource"] = row["source"]
            entry["updated"] = row["updated_at"]
        elif row["kind"] == KIND_REVIEW_STATUS:
            entry["reviewStatus"] = row["value"]
            entry["reviewUpdated"] = row["updated_at"]
        elif row["kind"] == KIND_REVIEW_NOTES:
            entry["reviewNotes"] = row["value"]
            entry["reviewUpdated"] = row["updated_at"]
        elif row["kind"] == KIND_BOOKMARK:
            entry["bookmark"] = True
            entry["bookmarkLabel"] = row["value"]
            entry["bookmarkUpdated"] = row["updated_at"]
        elif row["kind"] == KIND_BOOKMARK_COLOR:
            entry["bookmarkColor"] = row["value"]
    return out


def main() -> int:
    """Point d'entrée CLI : gérer les annotations d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(
        description="Manage binary annotations (comments, renames)"
    )
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument("--cache-db", help="Cache DB path (default: auto)")
    parser.add_argument(
        "--overlay-mapping",
        help=(
            "Chemin du mapping JSON allégé du désassemblage. Si fourni, les "
            "commandes de mutation arbitrent l'overlay du .asm (patch en "
            "place des commentaires) et la sortie devient "
            '{"annotations": ..., "overlay": verdict}.'
        ),
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List all annotations")
    p_list.add_argument("--addr", help="Filter by address")
    p_list.add_argument("--output", help="Output JSON path (default: stdout)")
    p_list.add_argument(
        "--grouped",
        action="store_true",
        help="Group output by address in the webview-facing shape",
    )

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

    # delete-annotation: clears only comment+rename (not bookmark/review),
    # used by the VS Code extension bridge for the webview's "delete
    # comment" action — narrower than `delete` (which wipes every kind).
    p_del_annotation = sub.add_parser(
        "delete-annotation",
        help="Delete comment and rename only (preserves bookmark/review)",
    )
    p_del_annotation.add_argument("--addr", required=True)

    # annotate (comment + rename in one call, used by the VS Code extension bridge)
    p_annotate = sub.add_parser(
        "annotate", help="Set comment and/or rename in one call"
    )
    p_annotate.add_argument("--addr", required=True)
    p_annotate.add_argument("--comment")
    p_annotate.add_argument("--name")

    # review
    p_review = sub.add_parser("review", help="Set review status/notes")
    p_review.add_argument("--addr", required=True)
    p_review.add_argument("--status", default="")
    p_review.add_argument("--notes", default="")

    # bookmark
    p_bookmark = sub.add_parser("bookmark", help="Set a bookmark")
    p_bookmark.add_argument("--addr", required=True)
    p_bookmark.add_argument("--label", default="")
    p_bookmark.add_argument("--color", default="#4ec9b0")

    # delete-bookmark
    p_del_bookmark = sub.add_parser("delete-bookmark", help="Delete a bookmark")
    p_del_bookmark.add_argument("--addr", required=True)

    # clear-bookmarks
    sub.add_parser("clear-bookmarks", help="Clear all bookmarks")

    args = parser.parse_args()
    configure_logging()

    with AnnotationStore(
        args.binary, cache_path=getattr(args, "cache_db", None)
    ) as store:
        if args.cmd == "list":
            if getattr(args, "grouped", False):
                annotations = _grouped_export(store)
            else:
                annotations = store.list(addr=getattr(args, "addr", None))
            out = json.dumps(annotations, indent=2, ensure_ascii=False)
            if getattr(args, "output", None):
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(out)
                print(
                    f"Annotations written to {args.output} ({len(annotations)} entries)"
                )
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

        elif args.cmd == "delete-annotation":
            store.delete(args.addr, kind=KIND_COMMENT)
            store.delete(args.addr, kind=KIND_RENAME)
            _print_grouped(store, args, overlay_mutation={"deleted": True})

        elif args.cmd == "annotate":
            if args.comment is not None:
                store.comment(args.addr, args.comment)
            if args.name is not None:
                store.rename(args.addr, args.name)
            _print_grouped(
                store,
                args,
                overlay_mutation={"name": args.name, "comment": args.comment},
            )

        elif args.cmd == "review":
            store.set_review(args.addr, status=args.status, notes=args.notes)
            _print_grouped(store, args, overlay_mutation=None)

        elif args.cmd == "bookmark":
            store.set_bookmark(args.addr, label=args.label, color=args.color)
            _print_grouped(store, args, overlay_mutation=None)

        elif args.cmd == "delete-bookmark":
            store.delete_bookmark(args.addr)
            _print_grouped(store, args, overlay_mutation=None)

        elif args.cmd == "clear-bookmarks":
            store.clear_bookmarks()
            _print_grouped(store, args, overlay_mutation=None)

    return 0


def _print_grouped(store, args, *, overlay_mutation: dict | None) -> None:
    """Sortie des commandes de mutation.

    Sans --overlay-mapping : export groupé brut (compat historique). Avec :
    enveloppe {"annotations", "overlay"} — les mutations sans effet sur le
    .asm (review/bookmark) portent le verdict 'unchanged' sans rien tenter.
    """
    import json

    grouped = _grouped_export(store)
    mapping_path = getattr(args, "overlay_mapping", None)
    if not mapping_path:
        print(json.dumps(grouped, indent=2, ensure_ascii=False))
        return
    if overlay_mutation is None:
        verdict = overlay_patch.VERDICT_UNCHANGED
    else:
        verdict = overlay_patch.apply_overlay_mutation(
            mapping_path,
            args.addr,
            name=overlay_mutation.get("name"),
            comment=overlay_mutation.get("comment"),
            deleted=bool(overlay_mutation.get("deleted")),
        )
    print(
        json.dumps(
            {"annotations": grouped, "overlay": verdict},
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    import sys

    sys.exit(main())
