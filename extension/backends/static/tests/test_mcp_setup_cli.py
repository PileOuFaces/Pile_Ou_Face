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


def _patch_resolved_interpreter(command: str = "/usr/bin/python3.11"):
    return unittest.mock.patch.object(
        setup_cli,
        "resolve_python_interpreter",
        return_value=(command, (3, 11), False),
    )


class TestInstallClaudeCode(unittest.TestCase):
    def test_creates_project_mcp_json_from_scratch(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter("/usr/bin/python3.11"),
        ):
            path = setup_cli.install_claude_code(tmp_dir, "project")
            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
        self.assertEqual(path, os.path.join(tmp_dir, ".mcp.json"))
        entry = config["mcpServers"][setup_cli.SERVER_ID]
        self.assertEqual(entry["command"], "/usr/bin/python3.11")
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
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter("/usr/bin/python3.11"),
        ):
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
        self.assertIn('command = "/usr/bin/python3.11"', text)
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


class TestResolvePythonInterpreter(unittest.TestCase):
    def test_prefers_sys_executable_when_modern_enough(self):
        with (
            unittest.mock.patch.object(
                setup_cli.sys, "version_info", (3, 12, 0, "final", 0)
            ),
            unittest.mock.patch.object(
                setup_cli.sys, "executable", "/opt/homebrew/bin/python3.12"
            ),
        ):
            command, version, is_fallback = setup_cli.resolve_python_interpreter()
        self.assertEqual(command, "/opt/homebrew/bin/python3.12")
        self.assertEqual(version, (3, 12))
        self.assertFalse(is_fallback)

    def test_probes_named_interpreters_when_running_under_old_python(self):
        def fake_which(name: str) -> str | None:
            return f"/usr/local/bin/{name}" if name == "python3.11" else None

        with (
            unittest.mock.patch.object(
                setup_cli.sys, "version_info", (3, 9, 6, "final", 0)
            ),
            unittest.mock.patch.object(
                setup_cli.shutil, "which", side_effect=fake_which
            ),
            unittest.mock.patch.object(
                setup_cli, "_interpreter_version", return_value=(3, 11)
            ),
        ):
            command, version, is_fallback = setup_cli.resolve_python_interpreter()
        self.assertEqual(command, "/usr/local/bin/python3.11")
        self.assertEqual(version, (3, 11))
        self.assertFalse(is_fallback)

    def test_falls_back_to_bare_python3_with_warning_when_nothing_found(self):
        with (
            unittest.mock.patch.object(
                setup_cli.sys, "version_info", (3, 9, 6, "final", 0)
            ),
            unittest.mock.patch.object(setup_cli.shutil, "which", return_value=None),
        ):
            command, version, is_fallback = setup_cli.resolve_python_interpreter()
        self.assertEqual(command, "python3")
        self.assertIsNone(version)
        self.assertTrue(is_fallback)


class TestRollback(unittest.TestCase):
    def test_rollback_restores_backup(self):
        with tempfile.TemporaryDirectory() as tmp_dir, _patch_resolved_interpreter():
            setup_cli.install_claude_code(tmp_dir, "project")
            path = setup_cli._claude_config_path("project", tmp_dir)
            with open(path, encoding="utf-8") as fh:
                original = fh.read()

            # Simulate a second install mutating the file, so .bak differs.
            setup_cli.install_claude_code(tmp_dir, "project")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write('{"mcpServers": {}, "mutated": true}')

            restored_path = setup_cli.rollback("claude", tmp_dir, "project")
            with open(restored_path, encoding="utf-8") as fh:
                restored = fh.read()

        self.assertEqual(restored_path, path)
        self.assertEqual(restored, original)

    def test_rollback_raises_when_no_backup_exists(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            with self.assertRaises(FileNotFoundError):
                setup_cli.rollback("claude", tmp_dir, "project")


class TestRunDoctor(unittest.TestCase):
    def test_handshake_ok_against_real_server(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter(sys.executable),
        ):
            diagnosis = setup_cli.run_doctor(tmp_dir)
        self.assertTrue(diagnosis["handshake_ok"])
        self.assertIsNone(diagnosis["error"])
        self.assertEqual(diagnosis["interpreter"], sys.executable)

    def test_reports_error_when_interpreter_does_not_exist(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter("/nonexistent/python3-doctor-test"),
        ):
            diagnosis = setup_cli.run_doctor(tmp_dir)
        self.assertFalse(diagnosis["handshake_ok"])
        self.assertIsNotNone(diagnosis["error"])


if __name__ == "__main__":
    unittest.main()
