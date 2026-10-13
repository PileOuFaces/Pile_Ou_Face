# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for backends.mcp.setup_cli (Claude Code / Codex MCP installer)."""

from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp import setup_cli


class TestInstallClaudeCode(unittest.TestCase):
    def test_creates_project_mcp_json_from_scratch(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = setup_cli.install_claude_code(tmp_dir, "project")
            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
        self.assertEqual(path, os.path.join(tmp_dir, ".mcp.json"))
        entry = config["mcpServers"][setup_cli.SERVER_ID]
        self.assertEqual(entry["command"], "python3")
        self.assertEqual(entry["args"][0], setup_cli.SERVER_PY)
        self.assertEqual(entry["env"]["POF_MCP_WORKSPACE_ROOT"], tmp_dir)

    def test_preserves_existing_unrelated_servers_and_keys(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, ".mcp.json")
            existing = {
                "mcpServers": {
                    "other-tool": {"command": "npx", "args": ["other"], "env": {}}
                },
                "someOtherTopLevelKey": True,
            }
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(existing, fh)

            setup_cli.install_claude_code(tmp_dir, "project")

            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
        self.assertIn("other-tool", config["mcpServers"])
        self.assertIn(setup_cli.SERVER_ID, config["mcpServers"])
        self.assertTrue(config["someOtherTopLevelKey"])

    def test_backs_up_existing_file_before_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, ".mcp.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"mcpServers": {}}, fh)

            setup_cli.install_claude_code(tmp_dir, "project")

            self.assertTrue(os.path.isfile(path + ".bak"))

    def test_dry_run_does_not_write(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = setup_cli.install_claude_code(tmp_dir, "project", dry_run=True)
            self.assertFalse(os.path.isfile(path))

    def test_rerun_is_idempotent(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_cli.install_claude_code(tmp_dir, "project")
            path = setup_cli.install_claude_code(tmp_dir, "project")
            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
        self.assertEqual(len(config["mcpServers"]), 1)


class TestInstallCodex(unittest.TestCase):
    def _codex_home(self, tmp_dir: str) -> str:
        return os.path.join(tmp_dir, "config.toml")

    def test_appends_table_to_fresh_file(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            codex_path = self._codex_home(tmp_dir)
            with unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    codex_path if p == "~/.codex/config.toml" else os.path.expanduser(p)
                ),
            ):
                path = setup_cli.install_codex(tmp_dir)
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn(f"[mcp_servers.{setup_cli.SERVER_ID}]", text)
        self.assertIn('command = "python3"', text)
        self.assertIn(tmp_dir, text)

    def test_preserves_other_toml_tables(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            codex_path = self._codex_home(tmp_dir)
            with open(codex_path, "w", encoding="utf-8") as fh:
                fh.write('[projects."/some/path"]\ntrusted = true\n')

            with unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    codex_path if p == "~/.codex/config.toml" else os.path.expanduser(p)
                ),
            ):
                setup_cli.install_codex(tmp_dir)

            with open(codex_path, encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn('[projects."/some/path"]', text)
        self.assertIn("trusted = true", text)
        self.assertIn(f"[mcp_servers.{setup_cli.SERVER_ID}]", text)

    def test_rerun_replaces_block_instead_of_duplicating(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            codex_path = self._codex_home(tmp_dir)
            with unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    codex_path if p == "~/.codex/config.toml" else os.path.expanduser(p)
                ),
            ):
                setup_cli.install_codex(tmp_dir)
                setup_cli.install_codex(tmp_dir)
            with open(codex_path, encoding="utf-8") as fh:
                text = fh.read()
        self.assertEqual(text.count("[mcp_servers."), 1)


if __name__ == "__main__":
    unittest.main()
