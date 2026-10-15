# SPDX-License-Identifier: AGPL-3.0-only
import os
import sqlite3

import pytest

from backends.static.patch.patch_db import PatchDb, default_db_path


def _entry(patch_id="patch-1", *, offset=4):
    return {
        "id": patch_id,
        "offset": offset,
        "original_bytes": "01 02",
        "patched_bytes": "90 90",
        "timestamp": "2026-08-01T10:00:00+00:00",
        "comment": "NOP",
    }


def test_default_path_uses_dedicated_home_database(monkeypatch, tmp_path):
    monkeypatch.delenv("POF_PATCHES_DB", raising=False)
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

    assert default_db_path() == tmp_path / ".pile-ou-face" / "patches.db"


def test_environment_can_override_database_for_isolated_runtimes(monkeypatch, tmp_path):
    expected = tmp_path / "custom.db"
    monkeypatch.setenv("POF_PATCHES_DB", str(expected))

    assert default_db_path() == expected


def test_round_trip_preserves_active_and_redo_order(tmp_path):
    binary = str(tmp_path / "sample.bin")
    data = {
        "patches": [_entry("active-1"), _entry("active-2", offset=8)],
        "redo_patches": [_entry("redo-1", offset=12)],
    }

    with PatchDb(tmp_path / "patches.db") as db:
        db.save(binary, data)
        loaded = db.load(binary)

    assert [item["id"] for item in loaded["patches"]] == ["active-1", "active-2"]
    assert [item["id"] for item in loaded["redo_patches"]] == ["redo-1"]
    assert loaded["patches"][0]["patched_bytes"] == "90 90"


def test_invalid_snapshot_rolls_back_without_losing_previous_history(tmp_path):
    binary = str(tmp_path / "sample.bin")
    with PatchDb(tmp_path / "patches.db") as db:
        db.save(binary, {"patches": [_entry()], "redo_patches": []})
        invalid = _entry("invalid")
        invalid["patched_bytes"] = ""

        with pytest.raises(ValueError, match="Invalid or oversized"):
            db.save(binary, {"patches": [invalid], "redo_patches": []})

        assert [item["id"] for item in db.load(binary)["patches"]] == ["patch-1"]


def test_delete_cascades_patch_rows(tmp_path):
    db_path = tmp_path / "patches.db"
    binary = str(tmp_path / "sample.bin")
    with PatchDb(db_path) as db:
        db.save(binary, {"patches": [_entry()], "redo_patches": []})
        assert db.delete(binary) == 1
        assert db.delete(binary) == 0

    with sqlite3.connect(db_path) as conn:
        assert conn.execute("SELECT COUNT(*) FROM binary_patches").fetchone()[0] == 0


def test_purge_missing_is_limited_to_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    missing_inside = str(workspace / "missing.bin")
    missing_outside = str(tmp_path / "outside.bin")
    data = {"patches": [_entry()], "redo_patches": []}

    with PatchDb(tmp_path / "patches.db") as db:
        db.save(missing_inside, data)
        db.save(missing_outside, data)

        assert db.purge_missing(str(workspace)) == 1
        assert db.load(missing_inside)["patches"] == []
        assert db.load(missing_outside)["patches"] != []


def test_purge_keeps_existing_binary(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    binary = workspace / "existing.bin"
    binary.write_bytes(b"ok")

    with PatchDb(tmp_path / "patches.db") as db:
        db.save(str(binary), {"patches": [_entry()], "redo_patches": []})

        assert db.purge_missing(str(workspace)) == 0
        assert db.load(str(binary))["patches"] != []
