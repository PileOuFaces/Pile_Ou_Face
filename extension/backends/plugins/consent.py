# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit user consent gate for plugin execution.

Plugins are Python modules loaded via importlib and executed immediately on
attach (attach_plugins() calls register_plugin(context) unconditionally).
This module adds a consent store so a plugin the user hasn't explicitly
approved is held in a "pending_consent" state instead of being attached —
see attach_plugins()'s consent_path parameter in runtime.py.

Storage follows the same convention as plugin/license search paths
(default_plugin_search_paths): a workspace-
local .pile-ou-face/ directory if present, else the user's home directory.
"""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Matches backends.plugins.license._ENV_PREFIX — kept as a separate literal
# to avoid a cross-module import for a single constant.
_ENV_PREFIX = "BINHOST"


def default_consent_path(
    *,
    cwd: str | Path | None = None,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
    allow_workspace_discovery: bool = True,
) -> Path:
    env_map = env or os.environ
    override = str(env_map.get(f"{_ENV_PREFIX}_PLUGIN_CONSENT_PATH", "") or "").strip()
    if override:
        return Path(override).expanduser()
    home_path = Path(home or Path.home()).expanduser().resolve()
    if allow_workspace_discovery:
        # Same caveat as default_plugin_search_paths: a caller whose cwd is
        # an arbitrary checked-out repo (e.g. an MCP server) must pass
        # allow_workspace_discovery=False, or a repo could ship its own
        # pre-approved .pile-ou-face/plugin_consent.json and self-consent.
        cwd_path = Path(cwd or Path.cwd()).expanduser().resolve()
        workspace_root = cwd_path / ".pile-ou-face"
        if workspace_root.is_dir():
            return workspace_root / "plugin_consent.json"
    return home_path / ".pile-ou-face" / "plugin_consent.json"


def load_consent_store(path: str | Path) -> dict[str, dict[str, Any]]:
    consent_path = Path(path)
    if not consent_path.exists():
        return {}
    try:
        raw = json.loads(consent_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return raw if isinstance(raw, dict) else {}


def save_consent_store(path: str | Path, store: dict[str, dict[str, Any]]) -> None:
    consent_path = Path(path)
    consent_path.parent.mkdir(parents=True, exist_ok=True)
    consent_path.write_text(
        json.dumps(store, indent=2, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def is_plugin_consented(
    plugin_id: str, version: str, store: dict[str, dict[str, Any]]
) -> bool:
    entry = store.get(plugin_id)
    if not isinstance(entry, dict):
        return False
    # Re-consent is required on version bump: an update could add new
    # capabilities the user never agreed to.
    return bool(entry.get("approved")) and str(entry.get("version") or "") == str(
        version
    )


def grant_plugin_consent(
    plugin_id: str, version: str, path: str | Path
) -> dict[str, dict[str, Any]]:
    store = load_consent_store(path)
    store[plugin_id] = {
        "approved": True,
        "version": version,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    save_consent_store(path, store)
    return store


def revoke_plugin_consent(
    plugin_id: str, path: str | Path
) -> dict[str, dict[str, Any]]:
    store = load_consent_store(path)
    store.pop(plugin_id, None)
    save_consent_store(path, store)
    return store


def ensure_consent_baseline(records: list[Any], path: str | Path) -> None:
    """Grandfather already-installed plugins into the consent store the
    first time it's created, so existing users aren't locked out of plugins
    they already installed deliberately (via the extension's own install
    flow) before this gate existed. Only plugins installed AFTER the store
    already exists go through the normal consent check.
    """
    consent_path = Path(path)
    if consent_path.exists():
        return
    store: dict[str, dict[str, Any]] = {}
    now = datetime.now(UTC).isoformat()
    for record in records:
        manifest = getattr(record, "manifest", None)
        if manifest is None:
            continue
        store[record.plugin_id] = {
            "approved": True,
            "version": manifest.version,
            "approved_at": now,
            "note": "grandfathered-on-first-run",
        }
    save_consent_store(consent_path, store)
