# SPDX-License-Identifier: AGPL-3.0-only
"""CLI bridge for the SQLite-only static analysis cache."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.cache.cache_store import (  # noqa: E402
    clear_entries,
    delete_binary,
    get_payload,
    list_entries,
    prune_entries,
    put_payload,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Manage the SQLite static cache")
    parser.add_argument("--db", required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    for command in ("get", "put"):
        target = sub.add_parser(command)
        target.add_argument("--namespace", required=True)
        target.add_argument("--cache-key", required=True)
        target.add_argument("--variant", default="")
    put = sub.choices["put"]
    put.add_argument("--binary-path", default="")
    put.add_argument("--binary-mtime-ms", type=float, default=0)
    put.add_argument("--binary-size", type=int, default=0)
    sub.add_parser("list")
    sub.add_parser("prune")
    sub.add_parser("clear")
    delete = sub.add_parser("delete-binary")
    delete.add_argument("--binary-path", required=True)
    args = parser.parse_args()

    if args.command == "get":
        payload = get_payload(args.db, args.namespace, args.cache_key, args.variant)
        print(json.dumps({"found": payload is not None, "payload": payload}))
    elif args.command == "put":
        payload = json.load(sys.stdin)
        size = put_payload(
            args.db,
            args.namespace,
            args.cache_key,
            payload,
            variant=args.variant,
            binary_path=args.binary_path,
            binary_mtime_ms=args.binary_mtime_ms,
            binary_size=args.binary_size,
        )
        print(json.dumps({"stored": True, "payloadBytes": size}))
    elif args.command == "list":
        print(json.dumps({"entries": list_entries(args.db)}))
    elif args.command == "prune":
        print(json.dumps({"removed": prune_entries(args.db)}))
    elif args.command == "clear":
        print(json.dumps({"removed": clear_entries(args.db)}))
    else:
        print(json.dumps({"removed": delete_binary(args.db, args.binary_path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
