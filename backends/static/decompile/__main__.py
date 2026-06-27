# SPDX-License-Identifier: AGPL-3.0-only
"""Point d'entrée pour `python -m backends.static.decompile`.

Permet d'invoquer le CLI depuis une image Docker ou le terminal :
    python -m backends.static.decompile --binary /path/to/bin --addr 0x401000
    python -m backends.static.decompile --list --provider local
"""

import argparse
import json
import sys
from pathlib import Path

from backends.static.decompile.decompile import (
    list_available_decompilers,
    decompile_binary,
    decompile_function,
)

parser = argparse.ArgumentParser(
    prog="python -m backends.static.decompile",
    description="Décompilateur Pile ou Face — CLI",
)
parser.add_argument("--binary", default=None)
parser.add_argument("--addr", default=None)
parser.add_argument("--full", action="store_true")
parser.add_argument("--func-name", default="")
parser.add_argument("--decompiler", default="")
parser.add_argument("--provider", default="auto", choices=["auto", "local", "docker"])
parser.add_argument("--list", action="store_true", dest="list_decompilers")
parser.add_argument("--annotations-json", default=None)
parser.add_argument("--cache-dir", default=None)

args = parser.parse_args()

if args.list_decompilers:
    print(
        json.dumps(
            list_available_decompilers(
                provider=args.provider,
                binary_path=args.binary,
                full=args.full,
            ),
            indent=2,
        )
    )
    sys.exit(0)

if not args.binary:
    parser.error("--binary est requis")

if args.full or not args.addr:
    print(
        json.dumps(
            decompile_binary(
                args.binary,
                decompiler=args.decompiler,
                provider=args.provider,
            ),
            indent=2,
        )
    )
else:
    print(
        json.dumps(
            decompile_function(
                args.binary,
                args.addr,
                func_name=args.func_name,
                decompiler=args.decompiler,
                annotations_json=args.annotations_json,
                cache_dir=Path(args.cache_dir) if args.cache_dir else None,
                provider=args.provider,
            ),
            indent=2,
        )
    )
