import json
from pathlib import Path
from unittest.mock import patch

import pytest
from backends.static.decompile import augment

CODE = """int sub_1000(int a1) {
  int v1 = a1 + 1;
  if (v1 > 2) return v1;
  return 0;
}"""


def raw_proposal():
    return {
        "summary": "Incrémente et vérifie une valeur.",
        "renames": [
            {"from": "v1", "to": "incremented_value", "reason": "Valeur calculée"},
            {"from": "missing", "to": "ignored", "reason": "Absent"},
            {"from": "a1", "to": "int", "reason": "Mot réservé"},
        ],
        "comments": [
            {"anchor": "if (v1 > 2)", "text": "Vérifie le seuil */ sûr"},
            {"anchor": "not present", "text": "Ignoré"},
        ],
        "types": [
            {"name": "v1", "type": "uint32_t", "reason": "Non négatif"},
            {"name": "v1", "type": "evil();", "reason": "Invalide"},
        ],
        "prototype": {
            "value": "int increment_and_check(int input);",
            "reason": "Signature",
        },
    }


def test_extract_json_object_accepts_fence_and_rejects_invalid():
    assert augment.extract_json_object('```json\n{"summary":"ok"}\n```') == {
        "summary": "ok"
    }
    assert augment.extract_json_object("not json") is None
    assert augment.extract_json_object("[]") is None


def test_normalize_filters_unsafe_or_unanchored_metadata():
    proposal = augment.normalize_proposal(raw_proposal(), CODE)
    assert [item["id"] for item in proposal["renames"]] == ["rename:v1"]
    assert proposal["comments"][0]["text"] == "Vérifie le seuil * / sûr"
    assert [item["type"] for item in proposal["types"]] == ["uint32_t"]
    assert proposal["prototype"]["id"] == "prototype"


def test_apply_selected_and_semantic_guard():
    proposal = augment.normalize_proposal(raw_proposal(), CODE)
    output = augment.apply_proposal(CODE, proposal, ["rename:v1", "comment:0"])
    assert "incremented_value" in output
    assert "Vérifie le seuil" in output
    assert "type proposé" not in output
    assert "Incrémente" not in output
    assert augment.semantic_guard(CODE, output)
    assert not augment.semantic_guard(CODE, CODE.replace("+ 1", "+ 2"))


def test_cache_key_uses_binary_contents(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"abc")
    first = augment.cache_key(str(binary), "0x1", CODE, "ollama", "model")
    binary.write_bytes(b"abd")
    second = augment.cache_key(str(binary), "0x1", CODE, "ollama", "model")
    assert first != second


def test_suggest_caches_structured_result(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"binary")
    payload = {
        "binary_path": str(binary),
        "addr": "0x1000",
        "code": CODE,
        "provider": "ollama",
        "model": "unit-model",
        "cache_dir": str(tmp_path),
        "function_name": "sub_1000",
        "language": "French",
        "use_cache": True,
    }
    provider_result = {
        "text": json.dumps(raw_proposal()),
        "usage": {"total_tokens": 42},
    }
    with patch.object(
        augment, "call_provider_result", return_value=provider_result
    ) as call:
        first = augment.suggest(payload)
        second = augment.suggest(payload)
    assert first["ok"] and not first["cached"]
    assert second["cached"]
    assert call.call_count == 1
    assert first["usage"]["total_tokens"] == 42


def test_suggest_rejects_empty_or_unstructured_response(tmp_path):
    with pytest.raises(ValueError, match="vide"):
        augment.suggest({"code": "", "cache_dir": str(tmp_path)})
    payload = {
        "binary_path": "missing",
        "addr": "0x1",
        "code": CODE,
        "provider": "ollama",
        "model": "unit",
        "cache_dir": str(tmp_path),
        "use_cache": False,
    }
    with patch.object(augment, "call_provider_result", return_value={"text": "oops"}):
        with pytest.raises(ValueError, match="non structurée"):
            augment.suggest(payload)


def test_accept_persists_selected_version(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"binary")
    payload = {
        "binary_path": str(binary),
        "addr": "0x1000",
        "code": CODE,
        "provider": "ollama",
        "model": "unit-model",
        "cache_dir": str(tmp_path),
        "use_cache": False,
    }
    with patch.object(
        augment,
        "call_provider_result",
        return_value={"text": json.dumps(raw_proposal())},
    ):
        proposed = augment.suggest(payload)
    accepted = augment.accept(
        {
            "cache_dir": str(tmp_path),
            "cache_key": proposed["cache_key"],
            "selected_ids": ["rename:v1"],
        }
    )
    assert accepted["accepted"] is True
    assert accepted["accepted_ids"] == ["rename:v1"]
    assert "incremented_value" in accepted["augmented_code"]
    assert accepted["versions"][0]["version"] == 1
    assert accepted["versions"][0]["selected_ids"] == ["rename:v1"]
    with pytest.raises(ValueError, match="introuvable"):
        augment.accept(
            {"cache_dir": str(tmp_path), "cache_key": "bad", "selected_ids": []}
        )
