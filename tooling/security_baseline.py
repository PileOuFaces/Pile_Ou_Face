"""Validate the repository security-control inventory and governed suppressions."""

from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path
from typing import Any

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INVENTORY = REPOSITORY_ROOT / "security" / "control-inventory.json"
DEFAULT_SUPPRESSIONS = REPOSITORY_ROOT / "security" / "suppressions.json"
MAX_SUPPRESSION_DAYS = 90
_ID_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._-]{2,127}$")
_OWNER_PATTERN = re.compile(
    r"^@[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})(?:/[A-Za-z0-9_.-]+)?$"
)
_CONTROL_STATUSES = {"enabled", "enabled-informational", "missing", "planned"}
_CONTROL_CATEGORIES = {
    "quality",
    "sast",
    "secrets",
    "dependencies",
    "containers",
    "supply-chain",
}


class BaselineValidationError(ValueError):
    """Raised when security governance files violate their schema or policy."""


def _load_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise BaselineValidationError(f"cannot read valid JSON: {path}") from exc
    if not isinstance(value, dict):
        raise BaselineValidationError(f"expected a JSON object: {path}")
    return value


def validate_inventory(value: dict[str, Any], *, repository_root: Path) -> None:
    if set(value) != {"schema_version", "repository", "reviewed_at", "controls"}:
        raise BaselineValidationError(
            "inventory has missing or unknown top-level fields"
        )
    if (
        value["schema_version"] != 1
        or value["repository"] != "PileOuFaces/Pile_Ou_Face"
    ):
        raise BaselineValidationError(
            "inventory schema_version or repository is invalid"
        )
    try:
        date.fromisoformat(str(value["reviewed_at"]))
    except ValueError as exc:
        raise BaselineValidationError(
            "inventory reviewed_at must be an ISO date"
        ) from exc
    controls = value["controls"]
    if not isinstance(controls, list) or not controls:
        raise BaselineValidationError("inventory controls must be a non-empty array")
    identifiers: set[str] = set()
    required = {"id", "category", "status", "scope", "workflow", "blocking"}
    for control in controls:
        if not isinstance(control, dict) or set(control) != required:
            raise BaselineValidationError(
                "each control must contain only the required fields"
            )
        identifier = str(control["id"])
        if not _ID_PATTERN.fullmatch(identifier) or identifier in identifiers:
            raise BaselineValidationError(
                f"invalid or duplicate control id: {identifier}"
            )
        identifiers.add(identifier)
        if (
            control["category"] not in _CONTROL_CATEGORIES
            or control["status"] not in _CONTROL_STATUSES
        ):
            raise BaselineValidationError(
                f"invalid category or status for {identifier}"
            )
        if not isinstance(control["scope"], str) or not control["scope"].strip():
            raise BaselineValidationError(f"scope is required for {identifier}")
        if not isinstance(control["blocking"], bool):
            raise BaselineValidationError(f"blocking must be boolean for {identifier}")
        workflow = control["workflow"]
        if control["status"].startswith("enabled"):
            if (
                not isinstance(workflow, str)
                or not (repository_root / workflow).is_file()
            ):
                raise BaselineValidationError(
                    f"enabled control references a missing workflow: {identifier}"
                )
        elif workflow is not None:
            raise BaselineValidationError(
                f"non-enabled control must not claim a workflow: {identifier}"
            )


def validate_suppressions(value: dict[str, Any], *, today: date) -> None:
    if (
        set(value) != {"schema_version", "policy", "suppressions"}
        or value["schema_version"] != 1
    ):
        raise BaselineValidationError("suppressions has an invalid schema")
    policy = value["policy"]
    expected_fields = ["id", "scanner", "rule", "path", "reason", "owner", "expires"]
    if (
        not isinstance(policy, dict)
        or policy.get("maximum_lifetime_days") != MAX_SUPPRESSION_DAYS
    ):
        raise BaselineValidationError(
            "suppression maximum lifetime must remain 90 days"
        )
    if policy.get("required_fields") != expected_fields:
        raise BaselineValidationError("suppression required_fields policy is invalid")
    suppressions = value["suppressions"]
    if not isinstance(suppressions, list):
        raise BaselineValidationError("suppressions must be an array")
    identifiers: set[str] = set()
    for suppression in suppressions:
        if not isinstance(suppression, dict) or set(suppression) != set(
            expected_fields
        ):
            raise BaselineValidationError(
                "each suppression must contain only the required fields"
            )
        identifier = str(suppression["id"])
        if not _ID_PATTERN.fullmatch(identifier) or identifier in identifiers:
            raise BaselineValidationError(
                f"invalid or duplicate suppression id: {identifier}"
            )
        identifiers.add(identifier)
        for field in ("scanner", "rule", "path", "reason"):
            if (
                not isinstance(suppression[field], str)
                or not suppression[field].strip()
            ):
                raise BaselineValidationError(f"{field} is required for {identifier}")
        if suppression["path"].strip() in {"*", "**", ".", "/"}:
            raise BaselineValidationError(
                f"repository-wide suppression is forbidden: {identifier}"
            )
        if not _OWNER_PATTERN.fullmatch(str(suppression["owner"])):
            raise BaselineValidationError(
                f"owner must be a GitHub user or team for {identifier}"
            )
        try:
            expires = date.fromisoformat(str(suppression["expires"]))
        except ValueError as exc:
            raise BaselineValidationError(
                f"expires must be an ISO date for {identifier}"
            ) from exc
        lifetime = (expires - today).days
        if lifetime < 0 or lifetime > MAX_SUPPRESSION_DAYS:
            raise BaselineValidationError(
                f"suppression must expire within {MAX_SUPPRESSION_DAYS} days: {identifier}"
            )


def validate_files(
    inventory_path: Path, suppressions_path: Path, *, today: date | None = None
) -> None:
    validate_inventory(_load_object(inventory_path), repository_root=REPOSITORY_ROOT)
    validate_suppressions(_load_object(suppressions_path), today=today or date.today())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=DEFAULT_INVENTORY)
    parser.add_argument("--suppressions", type=Path, default=DEFAULT_SUPPRESSIONS)
    args = parser.parse_args(argv)
    try:
        validate_files(args.inventory, args.suppressions)
    except BaselineValidationError as exc:
        parser.error(str(exc))
    print("Security control inventory and suppressions: valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
