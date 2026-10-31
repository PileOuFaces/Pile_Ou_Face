# SPDX-License-Identifier: AGPL-3.0-only
"""Explicit user consent gate for plugin execution.

Plugins are Python modules loaded via importlib and executed immediately on
attach (attach_plugins() calls register_plugin(context) unconditionally).
This module adds a consent store so a plugin the user hasn't explicitly
approved is held in a "pending_consent" state instead of being attached —
see attach_plugins()'s consent_path parameter in runtime.py.

The store only lives in the user's home directory (or an explicit environment
override). A checked-out repository is untrusted input, so it can neither
provide the store nor receive it, and a missing store approves nothing.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Matches backends.plugins.license._ENV_PREFIX — kept as a separate literal
# to avoid a cross-module import for a single constant.
_ENV_PREFIX = "BINHOST"
# Written by the removed first-run baseline, which approved whatever was
# discoverable at that moment: the user never agreed to those entries.
_UNATTESTED_NOTE = "grandfathered-on-first-run"


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


def default_consent_path(
    *,
    home: str | Path | None = None,
    env: dict[str, str] | None = None,
) -> Path:
    env_map = env or os.environ
    override = str(env_map.get(f"{_ENV_PREFIX}_PLUGIN_CONSENT_PATH", "") or "").strip()
    if override:
        return Path(override).expanduser()
    home_path = Path(home or Path.home()).expanduser().resolve()
    return home_path / ".pile-ou-face" / "plugin_consent.json"


def load_consent_store(path: str | Path) -> dict[str, dict[str, Any]]:
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


def save_consent_store(path: str | Path, store: dict[str, dict[str, Any]]) -> None:
    consent_path = Path(path)
    consent_path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(store, indent=2, ensure_ascii=False, sort_keys=True) + "\n"
    # mkstemp creates the file 0600; replace() keeps a reader from seeing a
    # truncated store, which would read as "nothing approved".
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


def _resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve()


def is_plugin_consented(
    plugin_id: str,
    version: str,
    store: dict[str, dict[str, Any]],
    *,
    plugin_root: str | Path | None = None,
    workspace: str | Path | None = None,
) -> bool:
    entry = store.get(plugin_id)
    if not isinstance(entry, dict):
        return False
    if entry.get("note") == _UNATTESTED_NOTE:
        return False
    # Re-consent is required on version bump: an update could add new
    # capabilities the user never agreed to.
    if not entry.get("approved") or str(entry.get("version") or "") != str(version):
        return False
    if plugin_root is None:
        return True
    root = _resolved(plugin_root)
    recorded = str(entry.get("plugin_root") or "")
    if recorded:
        # An id and version are self-declared: without this, a repository
        # could ship its own copy under the id of an approved plugin.
        return _resolved(recorded) == root
    if workspace is None:
        return True
    # Grants written before plugin_root existed cannot vouch for a plugin
    # sitting inside the current workspace.
    return not root.is_relative_to(_resolved(workspace))


def grant_plugin_consent(
    plugin_id: str,
    version: str,
    path: str | Path,
    *,
    plugin_root: str | Path | None = None,
) -> dict[str, dict[str, Any]]:
    entry: dict[str, Any] = {
        "approved": True,
        "version": version,
        "approved_at": datetime.now(UTC).isoformat(),
    }
    if plugin_root is not None:
        entry["plugin_root"] = str(_resolved(plugin_root))
    with _store_lock(Path(path)):
        store = load_consent_store(path)
        store[plugin_id] = entry
        save_consent_store(path, store)
    return store


def revoke_plugin_consent(
    plugin_id: str, path: str | Path
) -> dict[str, dict[str, Any]]:
    with _store_lock(Path(path)):
        store = load_consent_store(path)
        store.pop(plugin_id, None)
        save_consent_store(path, store)
    return store
