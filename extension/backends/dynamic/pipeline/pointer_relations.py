# SPDX-License-Identifier: AGPL-3.0-only
"""Conservative pointer-to-slot relations for the active stack frame."""

from __future__ import annotations

from typing import Any

_TRUSTED_TARGET_ROLES = {"argument", "buffer", "local"}
_MIN_TARGET_CONFIDENCE = 0.7


def _address(value: Any) -> int | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def _confidence(value: Any) -> float:
    try:
        return max(0.0, min(1.0, float(value)))
    except (TypeError, ValueError):
        return 0.0


def attach_active_frame_pointer_relations(slots: list[dict]) -> None:
    """Attach one-level relations without looking outside ``slots``.

    ``slots`` is the already-resolved active frame. Register-only values and
    slots from returned/caller frames are therefore outside this function's
    input by construction.
    """
    starts: dict[int, list[dict]] = {}
    for candidate in slots:
        start = _address(candidate.get("start"))
        if start is not None:
            starts.setdefault(start, []).append(candidate)

    for pointer in slots:
        if pointer.get("pointerKind") != "stack":
            continue
        target_address = _address(pointer.get("valueHex"))
        relation = {
            "status": "unresolved",
            "scope": "active_frame",
            "depth": 1,
            "targetAddress": pointer.get("valueHex"),
            "confidence": 0.0,
        }
        if target_address is None:
            relation["reason"] = "invalid_target_address"
            pointer["pointerRelation"] = relation
            continue

        candidates = [
            candidate
            for candidate in starts.get(target_address, [])
            if candidate is not pointer
        ]
        if not candidates:
            relation["reason"] = "no_active_frame_target"
            pointer["pointerRelation"] = relation
            continue
        if len(candidates) != 1:
            relation["reason"] = "ambiguous_target"
            pointer["pointerRelation"] = relation
            continue

        target = candidates[0]
        target_confidence = _confidence(target.get("confidence"))
        if (
            target.get("role") not in _TRUSTED_TARGET_ROLES
            or target.get("source") == "heuristic"
            or target_confidence < _MIN_TARGET_CONFIDENCE
        ):
            relation["reason"] = "untrusted_target"
            pointer["pointerRelation"] = relation
            continue

        pointer_confidence = _confidence(pointer.get("confidence"))
        relation.update(
            {
                "status": "resolved",
                "targetSlotKey": target.get("key"),
                "targetLabel": target.get("displayLabel") or target.get("label"),
                "targetRole": target.get("role"),
                "confidence": round(min(pointer_confidence, target_confidence), 3),
                "basis": "exact_slot_start",
            }
        )
        pointer["pointerRelation"] = relation
