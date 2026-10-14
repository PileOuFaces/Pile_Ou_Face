# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for backends.mcp.setup_cli (Claude Code / Codex MCP installer)."""

from __future__ import annotations

import io
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

    def test_preserves_manually_added_env_key_on_rerun(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            setup_cli.install_claude_code(tmp_dir, "project")
            path = setup_cli._claude_config_path("project", tmp_dir)
            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
            config["mcpServers"][setup_cli.SERVER_ID]["env"]["MY_CUSTOM_KEY"] = "kept"
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(config, fh)

            setup_cli.install_claude_code(tmp_dir, "project")
            with open(path, encoding="utf-8") as fh:
                config = json.load(fh)
        entry_env = config["mcpServers"][setup_cli.SERVER_ID]["env"]
        self.assertEqual(entry_env["MY_CUSTOM_KEY"], "kept")
        self.assertEqual(entry_env["POF_MCP_WORKSPACE_ROOT"], tmp_dir)

    def test_rejects_malformed_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, ".mcp.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not valid json")

            with self.assertRaises(setup_cli.MalformedConfigError):
                setup_cli.install_claude_code(tmp_dir, "project")

            # The malformed file must be left untouched: no write, no backup.
            with open(path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "{not valid json")
            self.assertFalse(os.path.isfile(path + ".bak"))

    def test_backup_keeps_pristine_snapshot_and_stores_drift_as_recovery(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            path = os.path.join(tmp_dir, ".mcp.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"mcpServers": {}, "marker": "first"}, fh)

            setup_cli.install_claude_code(tmp_dir, "project")
            with open(path + ".bak", encoding="utf-8") as fh:
                first_bak = json.load(fh)
            self.assertEqual(first_bak["marker"], "first")

            # Simulate a manual edit between runs, then rerun: the pristine
            # .bak must stay as-is, and the drifted bytes must be preserved
            # separately rather than discarded.
            with open(path, "w", encoding="utf-8") as fh:
                json.dump({"mcpServers": {}, "marker": "manually-edited"}, fh)

            setup_cli.install_claude_code(tmp_dir, "project")

            with open(path + ".bak", encoding="utf-8") as fh:
                bak_after = json.load(fh)
            self.assertEqual(bak_after["marker"], "first")

            recovery_files = [
                name
                for name in os.listdir(tmp_dir)
                if name.startswith(".mcp.json.recovery.")
            ]
            self.assertEqual(len(recovery_files), 1)
            with open(os.path.join(tmp_dir, recovery_files[0]), encoding="utf-8") as fh:
                recovery_content = json.load(fh)
            self.assertEqual(recovery_content["marker"], "manually-edited")


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

    def test_preserves_manually_added_env_key_on_rerun(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            codex_path = self._codex_home(tmp_dir)
            with unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    codex_path if p == "~/.codex/config.toml" else os.path.expanduser(p)
                ),
            ):
                setup_cli.install_codex(tmp_dir)
                with open(codex_path, encoding="utf-8") as fh:
                    text = fh.read()
                text = text.replace("}\n", ', MY_CUSTOM_KEY = "kept" }\n', 1)
                with open(codex_path, "w", encoding="utf-8") as fh:
                    fh.write(text)

                setup_cli.install_codex(tmp_dir)
            with open(codex_path, encoding="utf-8") as fh:
                text = fh.read()
        self.assertIn('MY_CUSTOM_KEY = "kept"', text)

    def test_rejects_malformed_existing_config(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            codex_path = self._codex_home(tmp_dir)
            with open(codex_path, "w", encoding="utf-8") as fh:
                fh.write("[not valid toml")

            with unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    codex_path if p == "~/.codex/config.toml" else os.path.expanduser(p)
                ),
            ):
                with self.assertRaises(setup_cli.MalformedConfigError):
                    setup_cli.install_codex(tmp_dir)

            with open(codex_path, encoding="utf-8") as fh:
                self.assertEqual(fh.read(), "[not valid toml")
            self.assertFalse(os.path.isfile(codex_path + ".bak"))


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

    def test_rejects_json_without_json_rpc_initialize_result(self):
        process = unittest.mock.Mock(
            stdin=unittest.mock.Mock(),
            stdout=io.BytesIO(b"{}\n"),
            stderr=io.BytesIO(),
        )
        process.poll.return_value = 0
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter(sys.executable),
            unittest.mock.patch.object(
                setup_cli.subprocess, "Popen", return_value=process
            ),
        ):
            diagnosis = setup_cli.run_doctor(tmp_dir)

        self.assertFalse(diagnosis["handshake_ok"])
        self.assertEqual(diagnosis["error"], "invalid JSON-RPC response")

    def test_reports_error_when_interpreter_does_not_exist(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter("/nonexistent/python3-doctor-test"),
        ):
            diagnosis = setup_cli.run_doctor(tmp_dir)
        self.assertFalse(diagnosis["handshake_ok"])
        self.assertIsNotNone(diagnosis["error"])

    def test_reports_malformed_claude_config_without_blocking_handshake(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter(sys.executable),
        ):
            path = os.path.join(tmp_dir, ".mcp.json")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write("{not valid json")

            diagnosis = setup_cli.run_doctor(tmp_dir, scope="project")
        self.assertTrue(diagnosis["handshake_ok"])
        self.assertIsNotNone(diagnosis["claude_config_error"])
        self.assertIn(path, diagnosis["claude_config_error"])

    def test_reports_no_config_errors_when_configs_are_absent(self):
        with (
            tempfile.TemporaryDirectory() as tmp_dir,
            _patch_resolved_interpreter(sys.executable),
            unittest.mock.patch(
                "os.path.expanduser",
                side_effect=lambda p: (
                    os.path.join(tmp_dir, "codex-config.toml")
                    if p == "~/.codex/config.toml"
                    else os.path.expanduser(p)
                ),
            ),
        ):
            diagnosis = setup_cli.run_doctor(tmp_dir, scope="project")
        self.assertIsNone(diagnosis["claude_config_error"])
        self.assertIsNone(diagnosis["codex_config_error"])


if __name__ == "__main__":
    unittest.main()
