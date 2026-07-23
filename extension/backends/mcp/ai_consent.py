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
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

_ENV_PREFIX = "BINHOST"


def default_ai_consent_path(
    *,
    cwd: str | Path | None = None,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
    allow_workspace_discovery: bool = True,
) -> Path:
    env_map = env or os.environ
    override = str(env_map.get(f"{_ENV_PREFIX}_AI_CONSENT_PATH", "") or "").strip()
    if override:
        return Path(override).expanduser()
    home_path = Path(home or Path.home()).expanduser().resolve()
    if allow_workspace_discovery:
        cwd_path = Path(cwd or Path.cwd()).expanduser().resolve()
        workspace_root = cwd_path / ".pile-ou-face"
        if workspace_root.is_dir():
            return workspace_root / "ai_consent.json"
    return home_path / ".pile-ou-face" / "ai_consent.json"


def load_ai_consent(path: str | Path) -> dict[str, dict[str, Any]]:
    consent_path = Path(path)
    if not consent_path.exists():
        return {}
    try:
        raw = json.loads(consent_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def save_ai_consent(path: str | Path, store: dict[str, dict[str, Any]]) -> None:
    consent_path = Path(path)
    consent_path.parent.mkdir(parents=True, exist_ok=True)
    consent_path.write_text(
        json.dumps(store, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def is_provider_consented(provider: str, store: dict[str, dict[str, Any]]) -> bool:
    entry = store.get(provider)
    return bool(isinstance(entry, dict) and entry.get("approved"))


def grant_ai_consent(provider: str, path: str | Path) -> dict[str, dict[str, Any]]:
    store = load_ai_consent(path)
    store[provider] = {
        "approved": True,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    save_ai_consent(path, store)
    return store


def revoke_ai_consent(provider: str, path: str | Path) -> dict[str, dict[str, Any]]:
    store = load_ai_consent(path)
    store.pop(provider, None)
    save_ai_consent(path, store)
    return store


def main(argv: list[str] | None = None) -> int:
    """CLI used by the VS Code host so the JSON file stays the single
    source of truth — no consent logic is duplicated on the TS side."""
    parser = argparse.ArgumentParser(description="AI-provider consent gate")
    parser.add_argument("--provider", required=True)
    parser.add_argument("--cwd", default=None)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--check", action="store_true")
    action.add_argument("--grant", action="store_true")
    action.add_argument("--revoke", action="store_true")
    args = parser.parse_args(argv)

    path = default_ai_consent_path(cwd=args.cwd)
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
