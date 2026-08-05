# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite persistence for AI chat conversations, isolated by workspace."""

from __future__ import annotations

import argparse
import hashlib
import json
import sqlite3
import sys
from pathlib import Path
from typing import Any

MAX_CONVERSATIONS = 24
MAX_MESSAGES = 40
MAX_CONTENT_CHARS = 200_000


def default_db_path() -> Path:
    return Path.home() / ".pile-ou-face" / "chat-history.db"


def workspace_key(workspace_path: str) -> str:
    resolved = str(Path(workspace_path).expanduser().resolve())
    return hashlib.sha256(resolved.encode("utf-8")).hexdigest()


class ChatHistoryDb:
    def __init__(self, db_path: str | Path | None = None):
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()

    def _init_schema(self) -> None:
        self._conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS chat_workspaces (
                workspace_key TEXT PRIMARY KEY,
                workspace_path TEXT NOT NULL,
                active_conversation_id TEXT NOT NULL DEFAULT '',
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chat_conversations (
                workspace_key TEXT NOT NULL REFERENCES chat_workspaces(workspace_key) ON DELETE CASCADE,
                conversation_id TEXT NOT NULL,
                title TEXT NOT NULL,
                custom_title INTEGER NOT NULL DEFAULT 0,
                model TEXT NOT NULL DEFAULT '',
                binary_path TEXT NOT NULL DEFAULT '',
                generation_settings TEXT,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (workspace_key, conversation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_chat_conversations_updated
                ON chat_conversations(workspace_key, updated_at DESC);
            CREATE TABLE IF NOT EXISTS chat_messages (
                workspace_key TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                model TEXT NOT NULL DEFAULT '',
                usage_json TEXT,
                PRIMARY KEY (workspace_key, conversation_id, ordinal),
                FOREIGN KEY (workspace_key, conversation_id)
                    REFERENCES chat_conversations(workspace_key, conversation_id) ON DELETE CASCADE
            );
            """
        )
        self._conn.commit()

    @staticmethod
    def _normalize_conversations(raw: Any) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        result: list[dict[str, Any]] = []
        seen: set[str] = set()
        for entry in raw[:MAX_CONVERSATIONS]:
            if not isinstance(entry, dict):
                continue
            conversation_id = str(entry.get("id") or "").strip()[:128]
            if not conversation_id or conversation_id in seen:
                continue
            seen.add(conversation_id)
            messages = []
            for message in (entry.get("messages") or [])[-MAX_MESSAGES:]:
                if not isinstance(message, dict):
                    continue
                role = str(message.get("role") or "").strip().lower()
                content = str(message.get("content") or "").strip()[:MAX_CONTENT_CHARS]
                if role not in {"user", "assistant", "system"} or not content:
                    continue
                usage = message.get("usage")
                messages.append(
                    {
                        "role": role,
                        "content": content,
                        "ts": int(message.get("ts") or 0),
                        "model": str(message.get("model") or "")[:256],
                        "usage": usage if isinstance(usage, dict) else None,
                    }
                )
            generation_settings = entry.get("generationSettings")
            result.append(
                {
                    "id": conversation_id,
                    "title": str(entry.get("title") or "Nouvelle discussion")[:80],
                    "customTitle": entry.get("customTitle") is True,
                    "model": str(entry.get("model") or "")[:256],
                    "binaryPath": str(entry.get("binaryPath") or "")[:4096],
                    "generationSettings": (
                        generation_settings
                        if isinstance(generation_settings, dict)
                        else None
                    ),
                    "updatedAt": int(entry.get("updatedAt") or 0),
                    "messages": messages,
                }
            )
        return result

    def load(self, workspace_path: str) -> dict[str, Any]:
        key = workspace_key(workspace_path)
        workspace = self._conn.execute(
            "SELECT active_conversation_id FROM chat_workspaces WHERE workspace_key = ?",
            (key,),
        ).fetchone()
        conversations = []
        rows = self._conn.execute(
            """
            SELECT conversation_id, title, custom_title, model, binary_path,
                   generation_settings, updated_at
            FROM chat_conversations
            WHERE workspace_key = ?
            ORDER BY updated_at DESC
            LIMIT ?
            """,
            (key, MAX_CONVERSATIONS),
        ).fetchall()
        for row in rows:
            messages = []
            for message in self._conn.execute(
                """
                SELECT role, content, created_at, model, usage_json
                FROM chat_messages
                WHERE workspace_key = ? AND conversation_id = ?
                ORDER BY ordinal
                """,
                (key, row["conversation_id"]),
            ):
                item = {
                    "role": message["role"],
                    "content": message["content"],
                    "ts": message["created_at"],
                }
                if message["model"]:
                    item["model"] = message["model"]
                if message["usage_json"]:
                    item["usage"] = json.loads(message["usage_json"])
                messages.append(item)
            conversations.append(
                {
                    "id": row["conversation_id"],
                    "title": row["title"],
                    "customTitle": bool(row["custom_title"]),
                    "model": row["model"],
                    "binaryPath": row["binary_path"],
                    "generationSettings": (
                        json.loads(row["generation_settings"])
                        if row["generation_settings"]
                        else None
                    ),
                    "updatedAt": row["updated_at"],
                    "messages": messages,
                }
            )
        return {
            "conversations": conversations,
            "activeConversationId": (
                workspace["active_conversation_id"] if workspace else ""
            ),
        }

    def save(
        self,
        workspace_path: str,
        conversations: Any,
        active_conversation_id: str = "",
    ) -> dict[str, Any]:
        normalized = self._normalize_conversations(conversations)
        key = workspace_key(workspace_path)
        resolved_path = str(Path(workspace_path).expanduser().resolve())
        active_id = str(active_conversation_id or "")[:128]
        valid_ids = {entry["id"] for entry in normalized}
        if active_id not in valid_ids:
            active_id = normalized[0]["id"] if normalized else ""
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO chat_workspaces
                    (workspace_key, workspace_path, active_conversation_id, updated_at)
                VALUES (?, ?, ?, strftime('%s', 'now'))
                ON CONFLICT(workspace_key) DO UPDATE SET
                    workspace_path = excluded.workspace_path,
                    active_conversation_id = excluded.active_conversation_id,
                    updated_at = excluded.updated_at
                """,
                (key, resolved_path, active_id),
            )
            self._conn.execute(
                "DELETE FROM chat_conversations WHERE workspace_key = ?", (key,)
            )
            for entry in normalized:
                self._conn.execute(
                    """
                    INSERT INTO chat_conversations (
                        workspace_key, conversation_id, title, custom_title, model,
                        binary_path, generation_settings, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        key,
                        entry["id"],
                        entry["title"],
                        int(entry["customTitle"]),
                        entry["model"],
                        entry["binaryPath"],
                        json.dumps(entry["generationSettings"], separators=(",", ":"))
                        if entry["generationSettings"] is not None
                        else None,
                        entry["updatedAt"],
                    ),
                )
                for ordinal, message in enumerate(entry["messages"]):
                    self._conn.execute(
                        """
                        INSERT INTO chat_messages (
                            workspace_key, conversation_id, ordinal, role, content,
                            created_at, model, usage_json
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            key,
                            entry["id"],
                            ordinal,
                            message["role"],
                            message["content"],
                            message["ts"],
                            message["model"],
                            json.dumps(message["usage"], separators=(",", ":"))
                            if message["usage"] is not None
                            else None,
                        ),
                    )
        return self.load(workspace_path)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> ChatHistoryDb:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Persist AI chat history in SQLite")
    parser.add_argument("command", choices=("load", "save"))
    parser.add_argument("--workspace", required=True)
    parser.add_argument("--db")
    args = parser.parse_args(argv)
    with ChatHistoryDb(args.db) as db:
        if args.command == "load":
            result = db.load(args.workspace)
        else:
            payload = json.load(sys.stdin)
            result = db.save(
                args.workspace,
                payload.get("conversations"),
                payload.get("activeConversationId", ""),
            )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
