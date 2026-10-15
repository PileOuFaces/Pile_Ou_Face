# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json

import pytest

from backends.static.annotations.annotations import AnnotationStore
from backends.static.annotations.project_format import (
    FORMAT,
    ProjectFormatError,
    dumps_project,
    export_project,
    import_project,
)
from backends.static.annotations.struct_db import StructDb
from backends.static.annotations.structs import import_type_definitions
from backends.static.annotations.typed_struct_refs import save_typed_struct_ref
from backends.static.annotations.typed_var_bindings import save_typed_var_binding


def _definition():
    return {
        "name": "Header",
        "kind": "struct",
        "fields": [
            {
                "name": "flags",
                "type": "uint32_t",
                "type_kind": "primitive",
                "pointer_level": 0,
                "array_len": None,
                "array_dims": None,
                "display_type": "uint32_t",
            }
        ],
    }


def test_project_round_trip_between_paths_and_databases(tmp_path):
    source_binary = tmp_path / "machine-a" / "sample.bin"
    target_binary = tmp_path / "machine-b" / "renamed.bin"
    source_binary.parent.mkdir()
    target_binary.parent.mkdir()
    source_binary.write_bytes(b"portable-binary")
    target_binary.write_bytes(source_binary.read_bytes())
    source_db = tmp_path / "source-annotations.db"
    target_db = tmp_path / "target-annotations.db"
    source_workspace = tmp_path / "source-workspace"
    target_workspace = tmp_path / "target-workspace"

    with AnnotationStore(str(source_binary), cache_path=str(source_db)) as store:
        store.rename("0x401000", "decrypt_payload")
        store.comment("0x401000", "reviewed crypto routine")
        store.set_review("0x401000", status="reviewed", notes="confirmed")
    import_type_definitions(
        str(source_binary), {"Header": _definition()}, "user", str(source_workspace)
    )
    save_typed_struct_ref(
        str(source_binary),
        {
            "name": "Header",
            "kind": "struct",
            "addr": "0x402000",
            "section": ".data",
            "offset": 0,
            "size": 4,
            "align": 4,
            "fields": [],
        },
        str(source_workspace),
    )
    save_typed_var_binding(
        str(source_binary),
        "0x401000",
        {
            "var_kind": "param",
            "var_key": "1",
            "type_name": "Header",
            "type_kind": "struct",
            "pointer_level": 1,
        },
        str(source_workspace),
    )

    document = export_project(
        str(source_binary),
        cache_path=str(source_db),
        workspace_root=str(source_workspace),
    )
    assert document["format"] == FORMAT
    assert "machine-a" not in dumps_project(document)
    assert "updated_at" not in dumps_project(document)

    report = import_project(
        str(target_binary),
        json.loads(dumps_project(document)),
        cache_path=str(target_db),
        workspace_root=str(target_workspace),
    )
    assert report["conflicts"] == 0
    with AnnotationStore(str(target_binary), cache_path=str(target_db)) as store:
        assert store.get_name("0x401000") == "decrypt_payload"
        assert store.get_review("0x401000") == {
            "status": "reviewed",
            "notes": "confirmed",
        }
    target_key = str(target_binary.resolve())
    database = StructDb(str(target_workspace))
    assert "Header" in database.load_definitions(target_key)["definitions"]
    assert database.list_typed_refs(target_key)[0]["addr"] == "0x402000"
    assert database.list_typed_var_bindings(target_key)[0]["func_addr"] == "0x401000"


def test_serialization_is_deterministic(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"stable")
    document = export_project(
        str(binary),
        cache_path=str(tmp_path / "annotations.db"),
        workspace_root=str(tmp_path / "workspace"),
    )
    assert dumps_project(document) == dumps_project(document)
    assert dumps_project(document).endswith("\n")


def test_stable_key_uses_canonical_address(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"stable")
    cache = tmp_path / "annotations.db"
    with AnnotationStore(str(binary), cache_path=str(cache)) as store:
        store.comment("0x00401000", "canonical")

    document = export_project(
        str(binary),
        cache_path=str(cache),
        workspace_root=str(tmp_path / "workspace"),
    )

    annotation = document["annotations"][0]
    assert annotation["addr"] == "0x401000"
    assert annotation["key"].endswith(":0x401000")


def test_import_rejects_different_binary(tmp_path):
    source = tmp_path / "source.bin"
    target = tmp_path / "target.bin"
    source.write_bytes(b"source")
    target.write_bytes(b"target")
    document = export_project(
        str(source),
        cache_path=str(tmp_path / "source.db"),
        workspace_root=str(tmp_path / "source-workspace"),
    )
    with pytest.raises(ProjectFormatError, match="SHA-256"):
        import_project(
            str(target),
            document,
            cache_path=str(tmp_path / "target.db"),
            workspace_root=str(tmp_path / "target-workspace"),
        )


def test_import_preserves_local_annotation_conflict(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"same")
    source_db = tmp_path / "source.db"
    target_db = tmp_path / "target.db"
    with AnnotationStore(str(binary), cache_path=str(source_db)) as store:
        store.rename("0x1000", "from_project")
    document = export_project(
        str(binary), cache_path=str(source_db), workspace_root=str(tmp_path / "source")
    )
    with AnnotationStore(str(binary), cache_path=str(target_db)) as store:
        store.rename("0x1000", "local_name")
    report = import_project(
        str(binary),
        document,
        cache_path=str(target_db),
        workspace_root=str(tmp_path / "target"),
    )
    assert report["conflicts"] == 1
    with AnnotationStore(str(binary), cache_path=str(target_db)) as store:
        assert store.get_name("0x1000") == "local_name"
