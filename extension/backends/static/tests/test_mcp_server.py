# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for backends.mcp_server."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends import mcp_server
from backends.mcp import server as mcp_impl


class TestMcpServer(unittest.TestCase):
    def test_initialize(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertEqual(response["id"], 1)
        self.assertIn("result", response)
        self.assertIn("capabilities", response["result"])
        self.assertIn("serverInfo", response["result"])

    @patch("backends.mcp.server._load_mcp_memory_context")
    def test_initialize_includes_instructions_when_memory_is_available(
        self, mock_memory
    ):
        mock_memory.return_value = "MCP memory context"
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertIn("instructions", result)
        self.assertIn("MCP memory context", result["instructions"])

    def test_tools_list_contains_expected_names(self):
        request = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        tools = response["result"]["tools"]
        names = {tool["name"] for tool in tools}
        self.assertIn("get_binary_info", names)
        self.assertIn("disassemble", names)
        self.assertIn("get_symbols", names)
        self.assertIn("extract_strings", names)
        self.assertIn("get_xrefs", names)
        self.assertIn("find_files", names)
        self.assertIn("plugins_list", names)
        self.assertIn("plugin_invoke", names)
        self.assertNotIn("find_vulnerabilities", names)
        self.assertNotIn("taint_analysis", names)

    @patch("backends.mcp.server._dynamic_plugin_tools")
    def test_tools_list_includes_dynamic_plugin_commands(
        self, mock_dynamic_plugin_tools
    ):
        mock_dynamic_plugin_tools.return_value = [
            {
                "name": "plugin.audit.vulns.run",
                "description": "Plugin command exposed by pof.vulnerability-audit-pro: audit.vulns.run",
                "inputSchema": {
                    "type": "object",
                    "properties": {"payload": {"type": "object"}},
                    "additionalProperties": False,
                },
            }
        ]
        request = {"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}}
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        names = {tool["name"] for tool in response["result"]["tools"]}
        self.assertIn("plugin.audit.vulns.run", names)

    @patch("backends.mcp.server._plugin_runtime_records")
    def test_tools_call_plugins_list(self, mock_plugin_runtime_records):
        mock_plugin_runtime_records.return_value = {
            "host_version": "0.1.0",
            "api_version": 1,
            "search_paths": ["/repo/.pile-ou-face/plugins"],
            "summary": {"active": 1},
            "plugins": [
                {
                    "id": "pof.vulnerability-audit-pro",
                    "state": "active",
                    "manifest": {"name": "Vulnerability Audit Pro"},
                }
            ],
            "attached": {"commands": ["audit.vulns.run"]},
        }
        request = {
            "jsonrpc": "2.0",
            "id": 21,
            "method": "tools/call",
            "params": {"name": "plugins_list", "arguments": {}},
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["summary"], {"active": 1})

    @patch("backends.plugins.runtime.invoke_plugin_command")
    @patch("backends.plugins.runtime.build_plugin_registry")
    @patch("backends.plugins.runtime.default_plugin_search_paths")
    def test_tools_call_plugin_invoke(
        self, mock_search_paths, mock_build_registry, mock_invoke
    ):
        mock_search_paths.return_value = [Path("/repo/.pile-ou-face/plugins")]
        mock_build_registry.return_value = []
        mock_invoke.return_value = (
            {"ok": True, "command": "audit.vulns.run", "result": {"findings": 1}},
            type(
                "Ctx", (), {"snapshot": lambda self: {"commands": ["audit.vulns.run"]}}
            )(),
            [],
        )
        request = {
            "jsonrpc": "2.0",
            "id": 22,
            "method": "tools/call",
            "params": {
                "name": "plugin_invoke",
                "arguments": {
                    "command_id": "audit.vulns.run",
                    "payload": {"binaryPath": "/repo/demo.bin"},
                },
            },
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["result"], {"findings": 1})

    @patch("backends.mcp.server._dynamic_plugin_tools")
    @patch("backends.plugins.runtime.invoke_plugin_command")
    @patch("backends.plugins.runtime.build_plugin_registry")
    @patch("backends.plugins.runtime.default_plugin_search_paths")
    def test_tools_call_dynamic_plugin_tool_name(
        self,
        mock_search_paths,
        mock_build_registry,
        mock_invoke,
        mock_dynamic_plugin_tools,
    ):
        mock_dynamic_plugin_tools.return_value = [
            {
                "name": "plugin.audit.vulns.run",
                "description": "Plugin command",
                "inputSchema": {
                    "type": "object",
                    "properties": {"payload": {"type": "object"}},
                    "additionalProperties": False,
                },
            }
        ]
        mock_search_paths.return_value = [Path("/repo/.pile-ou-face/plugins")]
        mock_build_registry.return_value = []
        mock_invoke.return_value = (
            {"ok": True, "command": "audit.vulns.run", "result": {"findings": 2}},
            type(
                "Ctx", (), {"snapshot": lambda self: {"commands": ["audit.vulns.run"]}}
            )(),
            [],
        )
        request = {
            "jsonrpc": "2.0",
            "id": 23,
            "method": "tools/call",
            "params": {
                "name": "plugin.audit.vulns.run",
                "arguments": {
                    "payload": {"binaryPath": "/repo/demo.bin"},
                },
            },
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["result"], {"findings": 2})

    @patch("backends.mcp.server._extract_symbols")
    def test_tools_call_get_symbols(self, mock_extract):
        mock_extract.return_value = [{"name": "main", "addr": "0x401000", "type": "T"}]
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "get_symbols",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_extract.assert_called_once_with(binary_path, defined_only=True)

    @patch("backends.mcp.server._find_files")
    def test_tools_call_find_files(self, mock_find_files):
        mock_find_files.return_value = {"ok": True, "count": 1, "results": []}
        request = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "find_files",
                "arguments": {"query": "demo_analysis.elf"},
            },
        }
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        result = response["result"]
        self.assertFalse(result["isError"])
        self.assertEqual(result["structuredContent"]["ok"], True)
        mock_find_files.assert_called_once_with("demo_analysis.elf", limit=20)

    @patch("backends.static.decompile.decompile.decompile_function")
    def test_tools_call_decompile_function_ignores_legacy_quality(
        self, mock_decompile_function
    ):
        mock_decompile_function.return_value = {
            "addr": "0x401000",
            "code": "int main() { return 0; }",
            "decompiler": "ghidra",
            "error": None,
        }
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 31,
                "method": "tools/call",
                "params": {
                    "name": "decompile_function",
                    "arguments": {
                        "binary_path": binary_path,
                        "addr": "0x401000",
                        "func_name": "main",
                        "decompiler": "ghidra",
                        "quality": "precision",
                    },
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_decompile_function.assert_called_once_with(
                binary_path,
                "0x401000",
                func_name="main",
                decompiler="ghidra",
            )

    @patch("backends.static.decompile.decompile.decompile_binary")
    def test_tools_call_decompile_binary_ignores_legacy_quality(
        self, mock_decompile_binary
    ):
        mock_decompile_binary.return_value = {
            "functions": [
                {"addr": "0x401000", "code": "int main() { return 0; }", "error": None}
            ],
            "decompiler": "retdec",
            "error": None,
        }
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 32,
                "method": "tools/call",
                "params": {
                    "name": "decompile_binary",
                    "arguments": {
                        "binary_path": binary_path,
                        "decompiler": "retdec",
                        "quality": "precision",
                    },
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_decompile_binary.assert_called_once_with(
                binary_path,
                decompiler="retdec",
            )

    @patch("backends.mcp.server._call_tool")
    def test_tools_call_alias_strings_resolves_to_extract_strings(self, mock_call_tool):
        mock_call_tool.return_value = {"ok": True, "strings": ["hello"]}
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 33,
                "method": "tools/call",
                "params": {
                    "name": "strings",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_call_tool.assert_called_once_with(
                "extract_strings", {"binary_path": binary_path}
            )

    def test_tools_call_invalid_params_returns_tool_error_payload(self):
        with tempfile.NamedTemporaryFile() as tmp:
            request = {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "get_xrefs",
                    "arguments": {"binary_path": str(Path(tmp.name).resolve())},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], False)
            self.assertIn("addr", result["structuredContent"]["error"])

    @patch("backends.mcp.server._disassemble_for_mcp")
    def test_tools_call_disassemble_without_output_param(self, mock_disassemble):
        mock_disassemble.return_value = {
            "ok": True,
            "count": 2,
            "lines": [{"addr": "0x1"}],
        }
        with tempfile.NamedTemporaryFile() as tmp:
            binary_path = str(Path(tmp.name).resolve())
            request = {
                "jsonrpc": "2.0",
                "id": 41,
                "method": "tools/call",
                "params": {
                    "name": "disassemble",
                    "arguments": {"binary_path": binary_path},
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertFalse(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], True)
            mock_disassemble.assert_called_once_with(
                binary_path, addr=None, max_lines=400
            )

    def test_tools_call_disassemble_invalid_max_lines(self):
        with tempfile.NamedTemporaryFile() as tmp:
            request = {
                "jsonrpc": "2.0",
                "id": 42,
                "method": "tools/call",
                "params": {
                    "name": "disassemble",
                    "arguments": {
                        "binary_path": str(Path(tmp.name).resolve()),
                        "max_lines": "bad",
                    },
                },
            }
            response = mcp_server.handle_request(request)
            self.assertIsNotNone(response)
            assert response is not None
            result = response["result"]
            self.assertTrue(result["isError"])
            self.assertEqual(result["structuredContent"]["ok"], False)
            self.assertIn("max_lines", result["structuredContent"]["error"])

    def test_unknown_method_returns_jsonrpc_error(self):
        request = {"jsonrpc": "2.0", "id": 5, "method": "does/not/exist"}
        response = mcp_server.handle_request(request)
        self.assertIsNotNone(response)
        assert response is not None
        self.assertIn("error", response)
        self.assertEqual(response["error"]["code"], mcp_server.JSONRPC_METHOD_NOT_FOUND)

    @patch("backends.mcp.server._iter_workspace_files")
    @patch("backends.mcp.server.os.path.isfile")
    def test_resolve_binary_path_with_basename_search(
        self, mock_isfile, mock_iter_files
    ):
        mock_isfile.return_value = False
        mock_iter_files.return_value = [
            "/repo/examples/demo_analysis.elf",
            "/repo/other/file.txt",
        ]
        resolved = mcp_impl._resolve_binary_path("demo_analysis.elf")
        self.assertEqual(resolved, "/repo/examples/demo_analysis.elf")

    @patch("backends.mcp.server._iter_workspace_files")
    @patch("backends.mcp.server.os.path.isfile")
    def test_resolve_binary_path_with_fuzzy_basename(
        self, mock_isfile, mock_iter_files
    ):
        mock_isfile.return_value = False
        mock_iter_files.return_value = [
            "/repo/examples/vuln_demo.elf",
            "/repo/examples/demo_analysis.elf",
        ]
        resolved = mcp_impl._resolve_binary_path("vul_demo.elf")
        self.assertEqual(resolved, "/repo/examples/vuln_demo.elf")


if __name__ == "__main__":
    unittest.main()
