from __future__ import annotations

import json
from datetime import date
from pathlib import Path

import pytest

from tooling.security_baseline import (
    BaselineValidationError,
    DEFAULT_INVENTORY,
    DEFAULT_SUPPRESSIONS,
    REPOSITORY_ROOT,
    validate_inventory,
    validate_suppressions,
)


def _read(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_repository_security_files_are_valid():
    validate_inventory(_read(DEFAULT_INVENTORY), repository_root=REPOSITORY_ROOT)
    validate_suppressions(_read(DEFAULT_SUPPRESSIONS), today=date(2026, 9, 12))


def test_inventory_rejects_duplicate_controls():
    inventory = _read(DEFAULT_INVENTORY)
    inventory["controls"].append(dict(inventory["controls"][0]))
    with pytest.raises(BaselineValidationError, match="duplicate control"):
        validate_inventory(inventory, repository_root=REPOSITORY_ROOT)


@pytest.mark.parametrize("expires", ["2026-09-11", "2026-12-12", "not-a-date"])
def test_suppressions_reject_expired_excessive_or_invalid_expiry(expires: str):
    value = _read(DEFAULT_SUPPRESSIONS)
    value["suppressions"] = [
        {
            "id": "semgrep.example",
            "scanner": "semgrep",
            "rule": "example-rule",
            "path": "extension/src/example.ts",
            "reason": "Tracked false positive with constrained input.",
            "owner": "@PileOuFaces/security",
            "expires": expires,
        }
    ]
    with pytest.raises(BaselineValidationError, match="expires|expire"):
        validate_suppressions(value, today=date(2026, 9, 12))


def test_suppressions_require_narrow_path():
    value = _read(DEFAULT_SUPPRESSIONS)
    value["suppressions"] = [
        {
            "id": "gitleaks.example",
            "scanner": "gitleaks",
            "rule": "generic-api-key",
            "path": "**",
            "reason": "Fixture contains a documented fake value.",
            "owner": "@PileOuFaces/security",
            "expires": "2026-10-01",
        }
    ]
    with pytest.raises(BaselineValidationError, match="repository-wide"):
        validate_suppressions(value, today=date(2026, 9, 12))
