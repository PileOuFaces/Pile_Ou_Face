"""CLI entry point for the normalized binary metadata model."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

if __package__ in {None, ""}:  # Allow direct `python build_binary_metadata.py ./bin`.
    sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from backends.static.binary.binary_metadata_model import emit_binary_metadata_json


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build normalized binary metadata JSON")
    parser.add_argument("binary", help="Path to ELF/Mach-O/PE binary")
    args = parser.parse_args(argv)
    sys.stdout.write(emit_binary_metadata_json(args.binary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
