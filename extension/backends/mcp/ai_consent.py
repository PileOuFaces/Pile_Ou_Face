# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit user consent gate for sending binary code to an AI provider.

Auto-triage (#124) sends decompiled/disassembled function bodies to an AI
provider (local or remote) for analysis. This module gates that on explicit,
per-provider opt-in consent, checked before any HTTP call leaves the machine.

Deliberately duplicated from backends/plugins/consent.py rather than shared:
plugin consent and AI-provider consent answer different questions ("do you
trust this plugin's code to run" vs "do you agree to send this binary's code
to this provider") and coupling them would make either concept harder to
reason about for a one-field difference.

V1 requires consent for every provider, including local ones (e.g. ollama):
even a local model still receives the binary's decompiled/disassembled code,
and the user should be asked once regardless of where that code ends up.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ENV_PREFIX = "BINHOST"


# Windows refuses to replace or open a file another process has open: the store
# is only busy for an instant, so wait rather than lose a grant or a revocation.
_BUSY_RETRIES = 100
_BUSY_DELAY_S = 0.02


def _retry_while_busy(operation: Callable[[], Any]) -> Any:
    for _ in range(_BUSY_RETRIES - 1):
        try:
            return operation()
        except PermissionError:
            time.sleep(_BUSY_DELAY_S)
    return operation()


def default_ai_consent_path(
    *,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    env_map = env or os.environ
    override = str(env_map.get(f"{_ENV_PREFIX}_AI_CONSENT_PATH", "") or "").strip()
    if override:
        return Path(override).expanduser()
    # Never the workspace: a checked-out repository must not be able to
    # approve sending the user's binaries to a provider.
    home_path = Path(home or Path.home()).expanduser().resolve()
    return home_path / ".pile-ou-face" / "ai_consent.json"


def load_ai_consent(path: str | Path) -> dict[str, dict[str, Any]]:
    consent_path = Path(path)
    if not consent_path.exists():
        return {}
    try:
        raw = json.loads(
            _retry_while_busy(lambda: consent_path.read_text(encoding="utf-8"))
        )
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def save_ai_consent(path: str | Path, store: dict[str, dict[str, Any]]) -> None:
    consent_path = Path(path)
    consent_path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(store, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    fd, tmp_name = tempfile.mkstemp(
        dir=consent_path.parent, prefix=f".{consent_path.name}."
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
        _retry_while_busy(lambda: os.replace(tmp_name, consent_path))
    except BaseException:
        Path(tmp_name).unlink(missing_ok=True)
        raise


@contextmanager
def _store_lock(store_path: Path) -> Iterator[None]:
    """Serialize a whole read-modify-replace across processes.

    Without it a grant working from an older read can restore an entry that a
    concurrent revoke just removed. The lock file stays in place on purpose:
    deleting it would let two processes hold different locks.
    """
    store_path.parent.mkdir(parents=True, exist_ok=True)
    with open(store_path.with_name(f".{store_path.name}.lock"), "a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file, fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock_file, fcntl.LOCK_UN)


def is_provider_consented(provider: str, store: dict[str, dict[str, Any]]) -> bool:
    entry = store.get(provider)
    return bool(isinstance(entry, dict) and entry.get("approved"))


def grant_ai_consent(provider: str, path: str | Path) -> dict[str, dict[str, Any]]:
    with _store_lock(Path(path)):
        store = load_ai_consent(path)
        store[provider] = {
            "approved": True,
            "approved_at": datetime.now(UTC).isoformat(),
        }
        save_ai_consent(path, store)
    return store


def revoke_ai_consent(provider: str, path: str | Path) -> dict[str, dict[str, Any]]:
    with _store_lock(Path(path)):
        store = load_ai_consent(path)
        store.pop(provider, None)
        save_ai_consent(path, store)
    return store


def main(argv: list[str] | None = None) -> int:
    """CLI used by the VS Code host so the JSON file stays the single
    source of truth — no consent logic is duplicated on the TS side."""
    parser = argparse.ArgumentParser(description="AI-provider consent gate")
    parser.add_argument("--provider", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--grant", action="store_true")
    action.add_argument("--revoke", action="store_true")
    args = parser.parse_args(argv)

    path = default_ai_consent_path()
    if args.grant:
        grant_ai_consent(args.provider, path)
        print(json.dumps({"consented": True}))
        return 0
    if args.revoke:
        revoke_ai_consent(args.provider, path)
        print(json.dumps({"consented": False}))
        return 0
    consented = is_provider_consented(args.provider, load_ai_consent(path))
    print(json.dumps({"consented": consented}))
    return 0 if consented else 1


if __name__ == "__main__":
    sys.exit(main())
