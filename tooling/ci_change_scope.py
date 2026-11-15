"""Classify a pull request's changed files for the CI workflow (fail-closed).

Reads ``git diff --name-status -z --no-renames <base>...<head>`` on stdin and prints
``docs_only=true`` only when every change is documentation that no build, test or
packaging step reads: files under ``docs/`` and Markdown files at the repository root.
Anything else, an empty diff, an unexpected status or an unusual path prints
``docs_only=false``, which runs every CI suite. The output is meant for
``$GITHUB_OUTPUT``.
"""

from __future__ import annotations

import sys
from pathlib import PurePosixPath

DOC_PREFIXES = ("docs/",)
ROOT_DOC_SUFFIXES = (".md",)
KNOWN_STATUSES = {"A", "M", "D"}


def is_documentation(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if not path or path.startswith("/") or ".." in parts or any(ord(c) < 32 for c in path):
        return False
    if path.startswith(DOC_PREFIXES):
        return True
    return len(parts) == 1 and path.endswith(ROOT_DOC_SUFFIXES)


def parse_name_status(raw: str) -> list[tuple[str, str]] | None:
    """Pairs (status, path) of a -z --no-renames name-status listing, or None if malformed."""
    fields = raw.split("\0")
    if fields and fields[-1] == "":
        fields.pop()
    if len(fields) % 2:
        return None
    return list(zip(fields[0::2], fields[1::2]))


def docs_only(raw: str) -> bool:
    changes = parse_name_status(raw)
    if not changes:
        return False
    return all(status in KNOWN_STATUSES and is_documentation(path) for status, path in changes)


def main() -> int:
    raw = sys.stdin.buffer.read().decode("utf-8", errors="strict")
    result = docs_only(raw)
    print(f"docs_only={'true' if result else 'false'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
