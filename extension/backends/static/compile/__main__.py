# SPDX-License-Identifier: AGPL-3.0-only
import argparse
import json
import sys

from backends.static.compile.compile import compile_source, list_available_compilers


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Moteur de compilation multi-toolchain"
    )
    parser.add_argument("--src", help="Fichier source à compiler")
    parser.add_argument("--lang", help="Langage source (c, cpp, rust, go)")
    parser.add_argument("--target", help="Target (elf-x64, pe-x64, macho-arm64, ...)")
    parser.add_argument("--output", help="Chemin du binaire de sortie (optionnel)")
    parser.add_argument(
        "--flags",
        default="[]",
        help='Flags extra encodés en JSON (ex: \'["-O2","-g"]\')',
    )
    parser.add_argument(
        "--list", action="store_true", help="Liste les toolchains disponibles"
    )
    args = parser.parse_args()

    if args.list:
        result = list_available_compilers()
        print(json.dumps(result, indent=2))
        return

    if not args.src or not args.lang or not args.target:
        parser.error("--src, --lang et --target sont requis")

    try:
        flags = json.loads(args.flags) if args.flags and args.flags != "[]" else None
    except json.JSONDecodeError:
        flags = None

    result = compile_source(args.src, args.lang, args.target, args.output, flags=flags)
    print(json.dumps(result))
    sys.exit(0)  # exit_code in JSON carries the result; caller parses stdout


if __name__ == "__main__":
    main()
