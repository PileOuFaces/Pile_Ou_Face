# SPDX-License-Identifier: AGPL-3.0-only
"""CLI de gestion du cache SQLite (.pfdb).

Commandes :
    list    — liste les binaires présents dans le cache
    stats   — statistiques détaillées (taille DB, nombre lignes, etc.)
    purge   — vide le cache (tous les binaires, ou un binaire précis)

Usage :
    python -m backends.static.cache.cache_admin list   --db output.pfdb
    python -m backends.static.cache.cache_admin stats  --db output.pfdb
    python -m backends.static.cache.cache_admin purge  --db output.pfdb [--binary /path/to/bin]
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from backends.shared.log import configure_logging, get_logger

logger = get_logger(__name__)


def _open(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def list_binaries(db_path: str) -> list[dict]:
    """Liste les binaires présents dans le cache.

    Returns:
        [{id, path, hash, created_at, disasm_lines, symbols, strings, annotations}, ...]
    """
    if not Path(db_path).exists():
        return []

    with _open(db_path) as conn:
        rows = conn.execute(
            """
            SELECT
                b.id, b.path, b.hash, b.created_at,
                COUNT(DISTINCT dl.id) AS disasm_lines,
                COUNT(DISTINCT s.id)  AS symbols,
                COUNT(DISTINCT st.id) AS strings,
                COUNT(DISTINCT a.id)  AS annotations
            FROM binary b
            LEFT JOIN disasm_lines dl ON dl.binary_id = b.id
            LEFT JOIN symbols      s  ON s.binary_id  = b.id
            LEFT JOIN strings_data st ON st.binary_id = b.id
            LEFT JOIN annotations  a  ON a.binary_id  = b.id
            GROUP BY b.id
            ORDER BY b.created_at
            """
        ).fetchall()
        result = [
            {
                "id": row["id"],
                "path": row["path"],
                "hash": row["hash"][:12] + "…",
                "created_at": row["created_at"],
                "disasm_lines": row["disasm_lines"],
                "symbols": row["symbols"],
                "strings": row["strings"],
                "annotations": row["annotations"],
            }
            for row in rows
        ]
    return result


def db_stats(db_path: str) -> dict:
    """Retourne les statistiques globales du cache.

    Returns:
        {db_path, size_bytes, binaries, total_disasm_lines, total_symbols,
         total_strings, total_annotations, schema_version}
    """
    p = Path(db_path)
    if not p.exists():
        return {"db_path": db_path, "error": "Database not found"}

    size = p.stat().st_size
    with _open(db_path) as conn:
        n_bin = conn.execute("SELECT COUNT(*) FROM binary").fetchone()[0]
        n_dis = conn.execute("SELECT COUNT(*) FROM disasm_lines").fetchone()[0]
        n_sym = conn.execute("SELECT COUNT(*) FROM symbols").fetchone()[0]
        n_str = conn.execute("SELECT COUNT(*) FROM strings_data").fetchone()[0]
        n_ann = conn.execute("SELECT COUNT(*) FROM annotations").fetchone()[0]
        ver_row = conn.execute(
            "SELECT value FROM schema_meta WHERE key='version'"
        ).fetchone()
        schema_ver = ver_row["value"] if ver_row else "unknown"

    return {
        "db_path": str(p.resolve()),
        "size_bytes": size,
        "size_human": _human_size(size),
        "schema_version": schema_ver,
        "binaries": n_bin,
        "total_disasm_lines": n_dis,
        "total_symbols": n_sym,
        "total_strings": n_str,
        "total_annotations": n_ann,
    }


def purge_binary(db_path: str, binary_path: str | None = None) -> int:
    """Supprime un ou tous les binaires du cache.

    Args:
        db_path: Chemin vers la base de données
        binary_path: Chemin du binaire à supprimer (None = purge complète)

    Returns:
        Nombre de binaires supprimés.
    """
    if not Path(db_path).exists():
        return 0

    with _open(db_path) as conn:
        conn.execute("PRAGMA foreign_keys=ON")
        if binary_path:
            cur = conn.execute("DELETE FROM binary WHERE path=?", (str(binary_path),))
        else:
            cur = conn.execute("DELETE FROM binary")
        conn.commit()
        return cur.rowcount


def _human_size(size: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if size < 1024:
            return f"{size:.1f} {unit}"
        size //= 1024
    return f"{size:.1f} TB"


def main() -> int:
    """Point d'entrée CLI."""
    import argparse

    parser = argparse.ArgumentParser(description="Manage pile-ou-face cache (.pfdb)")
    parser.add_argument("--db", required=True, help="Path to .pfdb cache database")

    sub = parser.add_subparsers(dest="cmd", required=True)

    # list
    p_list = sub.add_parser("list", help="List cached binaries")
    p_list.add_argument("--json", action="store_true", help="Output as JSON")

    # stats
    p_stats = sub.add_parser("stats", help="Show cache statistics")
    p_stats.add_argument("--json", action="store_true", help="Output as JSON")

    # purge
    p_purge = sub.add_parser("purge", help="Remove binaries from cache")
    p_purge.add_argument("--binary", help="Remove a specific binary (default: all)")
    p_purge.add_argument("--yes", action="store_true", help="Skip confirmation")

    args = parser.parse_args()
    configure_logging()

    if args.cmd == "list":
        binaries = list_binaries(args.db)
        if getattr(args, "json", False):
            print(json.dumps(binaries, indent=2))
        else:
            if not binaries:
                print("Cache empty.")
            else:
                print(
                    f"{'ID':>4}  {'Path':<50}  {'Hash':>14}  {'Disasm':>8}  {'Syms':>6}  {'Strs':>6}  {'Ann':>4}"
                )
                print("-" * 100)
                for b in binaries:
                    path_short = b["path"][-50:] if len(b["path"]) > 50 else b["path"]
                    print(
                        f"{b['id']:>4}  {path_short:<50}  {b['hash']:>14}  "
                        f"{b['disasm_lines']:>8}  {b['symbols']:>6}  "
                        f"{b['strings']:>6}  {b['annotations']:>4}"
                    )
                print(f"\nTotal: {len(binaries)} binary(ies)")

    elif args.cmd == "stats":
        stats = db_stats(args.db)
        if getattr(args, "json", False):
            print(json.dumps(stats, indent=2))
        else:
            if "error" in stats:
                print(f"Error: {stats['error']}")
                return 1
            print(f"Database  : {stats['db_path']}")
            print(f"Size      : {stats['size_human']} ({stats['size_bytes']} bytes)")
            print(f"Schema v  : {stats['schema_version']}")
            print(f"Binaries  : {stats['binaries']}")
            print(f"Disasm    : {stats['total_disasm_lines']} lines")
            print(f"Symbols   : {stats['total_symbols']}")
            print(f"Strings   : {stats['total_strings']}")
            print(f"Annotations: {stats['total_annotations']}")

    elif args.cmd == "purge":
        target = getattr(args, "binary", None)
        if not getattr(args, "yes", False):
            if target:
                confirm = input(f"Remove cache for '{target}'? [y/N] ").strip().lower()
            else:
                confirm = (
                    input(f"Purge ALL binaries from '{args.db}'? [y/N] ")
                    .strip()
                    .lower()
                )
            if confirm != "y":
                print("Aborted.")
                return 0
        n = purge_binary(args.db, binary_path=target)
        if target:
            print(f"Removed {n} entry(ies) for '{target}'")
        else:
            print(f"Purged {n} binary(ies) from cache")

    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
