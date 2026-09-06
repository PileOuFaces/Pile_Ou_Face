#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Exercise the MCP server through its real stdio transport."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any


EXTENSION_ROOT = Path(__file__).resolve().parents[2]
SERVER_PATH = EXTENSION_ROOT / "backends" / "mcp" / "server.py"
TIMEOUT_SECONDS = 20.0


def _frame(message: dict[str, Any]) -> bytes:
    body = json.dumps(message, separators=(",", ":")).encode("utf-8")
    return f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body


def _parse_messages(stream: bytes) -> list[dict[str, Any]]:
    messages = []
    cursor = 0
    while cursor < len(stream):
        header_end = stream.find(b"\r\n\r\n", cursor)
        if header_end < 0:
            raise AssertionError(f"incomplete MCP headers at byte {cursor}")
        headers = stream[cursor:header_end].decode("ascii").split("\r\n")
        lengths = [
            value
            for key, value in (line.split(":", 1) for line in headers)
            if key.lower() == "content-length"
        ]
        if len(lengths) != 1:
            raise AssertionError(f"invalid MCP Content-Length headers: {headers!r}")
        length = int(lengths[0].strip())
        body_start = header_end + 4
        body_end = body_start + length
        if body_end > len(stream):
            raise AssertionError("incomplete MCP response payload")
        messages.append(json.loads(stream[body_start:body_end].decode("utf-8")))
        cursor = body_end
    return messages


def main() -> int:
    requests = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "pof-mcp-e2e", "version": "1.0.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "find_files", "arguments": {"query": "server.py", "limit": 20}},
        },
    ]
    completed = subprocess.run(
        [sys.executable, str(SERVER_PATH), "--transport", "stdio"],
        cwd=EXTENSION_ROOT,
        input=b"".join(_frame(message) for message in requests),
        capture_output=True,
        timeout=TIMEOUT_SECONDS,
        check=False,
    )
    stderr = completed.stderr.decode("utf-8", errors="replace").strip()
    assert completed.returncode == 0, f"MCP server exited with {completed.returncode}: {stderr}"
    responses = _parse_messages(completed.stdout)
    assert [response.get("id") for response in responses] == [1, 2, 3]
    assert all("error" not in response for response in responses), responses

    initialized, listed, called = (response["result"] for response in responses)
    assert initialized["serverInfo"]["name"] == "pile-ou-face-mcp"
    assert "tools" in initialized["capabilities"]

    tool_names = {tool["name"] for tool in listed["tools"]}
    expected = {"get_binary_info", "disassemble", "find_files", "plugins_list", "plugin_invoke"}
    missing = expected - tool_names
    assert not missing, f"missing MCP tools: {sorted(missing)}"

    assert called["isError"] is False
    payload = called["structuredContent"]
    assert payload["ok"] is True
    relative_paths = {item["relative_path"] for item in payload["results"]}
    assert "backends/mcp/server.py" in relative_paths

    print("MCP stdio E2E smoke passed: initialize -> tools/list -> tools/call")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
