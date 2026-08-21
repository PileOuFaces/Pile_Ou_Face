# SPDX-License-Identifier: AGPL-3.0-only

from backends.dynamic.pipeline.pointer_relations import (
    attach_active_frame_pointer_relations,
)


def _slot(key, start, *, role="local", source="static", confidence=0.9, **extra):
    return {
        "key": key,
        "start": start,
        "role": role,
        "source": source,
        "confidence": confidence,
        "displayLabel": key,
        **extra,
    }


def test_resolves_one_level_pointer_to_unique_trusted_active_slot():
    pointer = _slot(
        "p",
        "0x1080",
        role="argument",
        pointerKind="stack",
        valueHex="0x1000",
    )
    target = _slot("x", "0x1000", role="buffer", confidence=0.8)

    attach_active_frame_pointer_relations([target, pointer])

    assert pointer["pointerRelation"] == {
        "status": "resolved",
        "scope": "active_frame",
        "depth": 1,
        "targetAddress": "0x1000",
        "targetSlotKey": "x",
        "targetLabel": "x",
        "targetRole": "buffer",
        "confidence": 0.8,
        "basis": "exact_slot_start",
    }


def test_marks_pointer_outside_active_frame_unresolved():
    pointer = _slot("p", "0x1080", pointerKind="stack", valueHex="0x2000")

    attach_active_frame_pointer_relations([pointer])

    assert pointer["pointerRelation"]["status"] == "unresolved"
    assert pointer["pointerRelation"]["reason"] == "no_active_frame_target"


def test_rejects_ambiguous_alias_for_same_target_address():
    pointer = _slot("p", "0x1080", pointerKind="stack", valueHex="0x1000")
    first = _slot("x", "0x1000")
    alias = _slot("alias", "0x1000", role="buffer")

    attach_active_frame_pointer_relations([pointer, first, alias])

    assert pointer["pointerRelation"]["reason"] == "ambiguous_target"


def test_rejects_heuristic_or_low_confidence_target():
    for target in (
        _slot("heuristic", "0x1000", source="heuristic"),
        _slot("weak", "0x1000", confidence=0.69),
        _slot("control", "0x1000", role="saved_bp"),
    ):
        pointer = _slot("p", "0x1080", pointerKind="stack", valueHex="0x1000")
        attach_active_frame_pointer_relations([pointer, target])
        assert pointer["pointerRelation"]["reason"] == "untrusted_target"


def test_does_not_infer_relation_from_scalar_or_register_only_value():
    scalar = _slot("scalar", "0x1080", valueHex="0x1000")
    target = _slot("x", "0x1000")

    attach_active_frame_pointer_relations([scalar, target])

    assert "pointerRelation" not in scalar
