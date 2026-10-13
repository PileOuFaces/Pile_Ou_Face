# SPDX-License-Identifier: AGPL-3.0-only
"""Real-subprocess tests for the MCP stdio wire protocol (NDJSON)."""

from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
SERVER_PATH = ROOT / "backends" / "mcp" / "server.py"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp.ollama_bridge import McpStdioClient


class TestServerWireProtocol(unittest.TestCase):
    def test_server_responds_with_ndjson_not_content_length(self):
        proc = subprocess.Popen(
            [sys.executable, str(SERVER_PATH), "--transport", "stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=str(ROOT),
        )
        try:
            request = {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {"protocolVersion": "2024-11-05"},
            }
            line = json.dumps(request) + "\n"
            assert proc.stdin is not None
            proc.stdin.write(line.encode("utf-8"))
            proc.stdin.flush()

            assert proc.stdout is not None
            response_line = proc.stdout.readline()
            self.assertNotIn(b"Content-Length", response_line)

            response = json.loads(response_line.decode("utf-8"))
            self.assertEqual(response.get("id"), 1)
            self.assertIn("result", response)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


class TestMcpStdioClientWireProtocol(unittest.TestCase):
    def test_round_trip_against_real_server(self):
        client = McpStdioClient(
            [sys.executable, str(SERVER_PATH), "--transport", "stdio"],
            cwd=str(ROOT),
        )
        client.start()
        try:
            result = client.request("initialize", {"protocolVersion": "2024-11-05"})
            self.assertIn("serverInfo", result)
        finally:
            client.close()


if __name__ == "__main__":
    unittest.main()
