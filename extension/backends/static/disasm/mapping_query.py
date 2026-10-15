# SPDX-License-Identifier: AGPL-3.0-only
"""CLI de requête du mapping SQLite (repli quand node:sqlite est absent)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.disasm import mapping_db  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Query the disasm mapping SQLite")
    parser.add_argument("--db", required=True, help="Chemin du .disasm.mapping.db")
    parser.add_argument(
        "--mode", choices=["entry", "window", "function-addrs"], default="entry"
    )
    parser.add_argument("--addr")
    parser.add_argument("--limit", type=int, default=256)
    args = parser.parse_args()

    if args.mode == "entry":
        entries = mapping_db.query_lines_by_addr(args.db, args.addr or "")
        print(json.dumps({"entry": entries[0] if entries else None}))
    elif args.mode == "window":
        lines, total = mapping_db.query_window(args.db, args.addr, args.limit)
        print(json.dumps({"lines": lines, "total": total}))
    else:
        print(json.dumps({"function_addrs": mapping_db.query_function_addrs(args.db)}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
