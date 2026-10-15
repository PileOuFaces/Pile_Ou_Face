# SPDX-License-Identifier: AGPL-3.0-only
import json
import sqlite3

from backends.shared.chat_history import (
    MAX_CONVERSATIONS,
    MAX_MESSAGES,
    ChatHistoryDb,
    main,
)


def _conversation(conversation_id="conv-1", *, message_count=2, updated_at=10):
    return {
        "id": conversation_id,
        "title": "Analyse du binaire",
        "customTitle": True,
        "model": "gpt-5",
        "binaryPath": "/tmp/sample.elf",
        "generationSettings": {"temperature": 0.2},
        "updatedAt": updated_at,
        "messages": [
            {
                "role": "user" if index % 2 == 0 else "assistant",
                "content": f"message {index}",
                "ts": index + 1,
                "model": "gpt-5" if index % 2 else "",
                "usage": {"totalTokens": 12} if index % 2 else None,
            }
            for index in range(message_count)
        ],
    }


def test_round_trip_preserves_conversation_and_messages(tmp_path):
    db_path = tmp_path / "chat.db"
    with ChatHistoryDb(db_path) as db:
        saved = db.save(str(tmp_path / "workspace"), [_conversation()], "conv-1")
        loaded = db.load(str(tmp_path / "workspace"))

    assert saved == loaded
    assert loaded["activeConversationId"] == "conv-1"
    assert loaded["conversations"][0]["generationSettings"] == {"temperature": 0.2}
    assert loaded["conversations"][0]["messages"][1]["usage"] == {"totalTokens": 12}


def test_workspaces_are_isolated(tmp_path):
    with ChatHistoryDb(tmp_path / "chat.db") as db:
        db.save(str(tmp_path / "a"), [_conversation("a")], "a")
        db.save(str(tmp_path / "b"), [_conversation("b")], "b")

        assert db.load(str(tmp_path / "a"))["conversations"][0]["id"] == "a"
        assert db.load(str(tmp_path / "b"))["conversations"][0]["id"] == "b"


def test_snapshot_replaces_deleted_conversations_and_can_clear(tmp_path):
    workspace = str(tmp_path / "workspace")
    with ChatHistoryDb(tmp_path / "chat.db") as db:
        db.save(workspace, [_conversation("a"), _conversation("b")], "b")
        result = db.save(workspace, [_conversation("a")], "missing")
        assert [entry["id"] for entry in result["conversations"]] == ["a"]
        assert result["activeConversationId"] == "a"

        assert db.save(workspace, [], "") == {
            "conversations": [],
            "activeConversationId": "",
        }


def test_limits_history_and_message_growth(tmp_path):
    conversations = [
        _conversation(f"conv-{index}", message_count=MAX_MESSAGES + 5, updated_at=index)
        for index in range(MAX_CONVERSATIONS + 5)
    ]
    with ChatHistoryDb(tmp_path / "chat.db") as db:
        result = db.save(str(tmp_path / "workspace"), conversations, "conv-0")

    assert len(result["conversations"]) == MAX_CONVERSATIONS
    assert all(
        len(entry["messages"]) == MAX_MESSAGES for entry in result["conversations"]
    )


def test_schema_is_normalized_sqlite_without_json_history_blob(tmp_path):
    db_path = tmp_path / "chat.db"
    with ChatHistoryDb(db_path) as db:
        db.save(str(tmp_path / "workspace"), [_conversation()], "conv-1")
    with sqlite3.connect(db_path) as conn:
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        assert {"chat_workspaces", "chat_conversations", "chat_messages"} <= tables
        assert conn.execute("SELECT COUNT(*) FROM chat_messages").fetchone()[0] == 2


def test_cli_reads_save_payload_from_stdin(tmp_path, monkeypatch, capsys):
    payload = {
        "conversations": [_conversation()],
        "activeConversationId": "conv-1",
    }
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps(payload)))
    db_path = tmp_path / "chat.db"
    workspace = str(tmp_path / "workspace")

    assert main(["save", "--workspace", workspace, "--db", str(db_path)]) == 0
    result = json.loads(capsys.readouterr().out)

    assert result["activeConversationId"] == "conv-1"
