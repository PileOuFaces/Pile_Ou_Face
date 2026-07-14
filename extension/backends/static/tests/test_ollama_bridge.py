# SPDX-License-Identifier: AGPL-3.0-only
"""Unit tests for backends.mcp.ollama_bridge helpers."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from unittest.mock import patch

from backends.mcp.ollama_bridge import (
    OllamaToolsUnsupportedError,
    _auto_tool_fallback,
    _build_system_prompt,
    _coerce_tool_arguments,
    _default_server_cmd,
    _detect_tool_intent,
    _extract_binary_candidate,
    _extract_user_request,
    _looks_like_noop_response,
    _normalize_tool_call_arguments,
    _prompt_likely_needs_tools,
    _resolve_binary_from_prompt,
    _resolve_requested_tool_name,
    _select_mcp_tools_for_prompt,
    _strip_passive_binary_context,
    mcp_tool_to_ollama_tool,
    ollama_chat,
    parse_args,
    run_agent_once,
)


class _StreamingResponse:
    def __init__(self, chunks):
        self._lines = [
            (json.dumps(chunk, ensure_ascii=False) + "\n").encode("utf-8")
            for chunk in chunks
        ]

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False

    def __iter__(self):
        return iter(self._lines)


class TestOllamaBridgeHelpers(unittest.TestCase):
    class _FakeClient:
        def __init__(self, payload):
            self.payload = payload
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            return {"structuredContent": self.payload}

    class _FakeClientByTool:
        def __init__(self, payload_by_tool):
            self.payload_by_tool = payload_by_tool
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            name = params.get("name")
            return {"structuredContent": self.payload_by_tool.get(name, {"ok": False})}

    class _FakeFindClient:
        def __init__(self, results):
            self.results = results
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            if params.get("name") == "find_files":
                return {
                    "structuredContent": {
                        "ok": True,
                        "results": self.results,
                    }
                }
            return {"structuredContent": {"ok": False}}

    def test_mcp_tool_to_ollama_tool(self):
        tool = {
            "name": "get_symbols",
            "description": "Extract symbols",
            "inputSchema": {
                "type": "object",
                "properties": {"binary_path": {"type": "string"}},
                "required": ["binary_path"],
            },
        }
        converted = mcp_tool_to_ollama_tool(tool)
        self.assertEqual(converted["type"], "function")
        self.assertEqual(converted["function"]["name"], "get_symbols")
        self.assertIn("parameters", converted["function"])

    def test_coerce_tool_arguments_from_dict(self):
        args = {"binary_path": "/tmp/a.elf"}
        self.assertEqual(_coerce_tool_arguments(args), args)

    def test_coerce_tool_arguments_from_json_string(self):
        parsed = _coerce_tool_arguments(
            '{"binary_path": "/tmp/a.elf", "addr": "0x401000"}'
        )
        self.assertEqual(parsed["binary_path"], "/tmp/a.elf")
        self.assertEqual(parsed["addr"], "0x401000")

    def test_coerce_tool_arguments_empty_string(self):
        self.assertEqual(_coerce_tool_arguments(""), {})

    def test_coerce_tool_arguments_invalid_json_raises(self):
        with self.assertRaises(ValueError):
            _coerce_tool_arguments("{invalid json")

    def test_default_server_cmd_points_to_mcp_server(self):
        cmd = _default_server_cmd()
        self.assertIn("backends/mcp/server.py", cmd)

    def test_looks_like_noop_response(self):
        self.assertTrue(_looks_like_noop_response("Please provide a request."))
        self.assertTrue(
            _looks_like_noop_response("Please provide a file or a request.")
        )
        self.assertTrue(
            _looks_like_noop_response(
                "I still need a file or a specific request to use the available tools."
            )
        )
        self.assertFalse(
            _looks_like_noop_response("Voici les 5 premieres instructions...")
        )

    def test_prompt_likely_needs_tools(self):
        self.assertTrue(_prompt_likely_needs_tools("Analyse demo_analysis.elf"))
        self.assertTrue(_prompt_likely_needs_tools("disassemble ce binaire"))
        self.assertTrue(
            _prompt_likely_needs_tools("donne le code asm de sample_demo.elf")
        )
        self.assertFalse(_prompt_likely_needs_tools("dis moi bonjour"))

    def test_extract_user_request_ignores_passive_binary_context(self):
        prompt = (
            "Contexte binaire passif :\n"
            "Binaire actuellement ouvert dans l'application : examples/demo.elf\n\n"
            "Demande utilisateur : fait moi un message long avec 200 mots"
        )
        self.assertEqual(
            _extract_user_request(prompt),
            "fait moi un message long avec 200 mots",
        )

    def test_strip_passive_binary_context_keeps_general_request(self):
        prompt = (
            "Contexte binaire passif :\n"
            "Binaire actuellement ouvert dans l'application : examples/demo.elf\n\n"
            "Demande utilisateur : raconte une histoire"
        )
        self.assertEqual(
            _strip_passive_binary_context(prompt),
            "raconte une histoire",
        )

    def test_detect_tool_intent(self):
        self.assertEqual(_detect_tool_intent("Donne le code ASM"), "disassemble")
        self.assertEqual(_detect_tool_intent("Trouve les symboles"), "symbols")
        self.assertEqual(_detect_tool_intent("Liste les strings"), "strings")
        self.assertIsNone(_detect_tool_intent("dis moi bonjour"))

    def test_extract_binary_candidate(self):
        self.assertEqual(
            _extract_binary_candidate("Analyse examples/demo_analysis.elf"),
            "examples/demo_analysis.elf",
        )
        self.assertIsNone(_extract_binary_candidate("Analyse ce fichier"))

    def test_auto_tool_fallback_disassemble(self):
        payload = {
            "ok": True,
            "count": 3,
            "lines": [
                {"addr": "0x1", "text": "55 push rbp"},
                {"addr": "0x2", "text": "48 89 e5 mov rbp, rsp"},
            ],
        }
        client = self._FakeClient(payload)
        out = _auto_tool_fallback(client, "disassemble demo_analysis.elf")
        assert out is not None
        self.assertIn("Désassemblage", out)
        self.assertIn("demo_analysis.elf", out)
        self.assertEqual(client.calls[0][1]["name"], "disassemble")

    def test_auto_tool_fallback_disassemble_from_asm_prompt(self):
        payload = {
            "ok": True,
            "count": 1,
            "lines": [{"addr": "0x1000", "text": "ret"}],
        }
        client = self._FakeClient(payload)
        out = _auto_tool_fallback(client, "Donne le code ASM de sample_demo.elf")
        assert out is not None
        self.assertIn("Désassemblage", out)
        self.assertEqual(client.calls[0][1]["name"], "disassemble")

    def test_auto_tool_fallback_binary_info_when_intent_missing(self):
        client = self._FakeClientByTool(
            {
                "get_binary_info": {
                    "ok": True,
                    "format": "ELF",
                    "arch": "x86_64",
                    "bits": 64,
                }
            }
        )
        out = _auto_tool_fallback(client, "le fichier c'est sample_demo.elf")
        assert out is not None
        self.assertIn("Fichier pris en compte", out)
        self.assertEqual(client.calls[0][1]["name"], "get_binary_info")

    def test_resolve_binary_from_prompt_via_find_files_hint(self):
        client = self._FakeFindClient(
            [
                {
                    "path": "/repo/examples/sample_demo.elf",
                    "relative_path": "examples/sample_demo.elf",
                }
            ]
        )
        out = _resolve_binary_from_prompt(client, "le fichier c'est sample_demo")
        self.assertEqual(out, "/repo/examples/sample_demo.elf")
        self.assertEqual(client.calls[0][1]["name"], "find_files")

    def test_normalize_tool_call_arguments_adds_binary_and_default_max_lines(self):
        client = self._FakeFindClient(
            [
                {
                    "path": "/repo/examples/sample_demo.elf",
                    "relative_path": "examples/sample_demo.elf",
                }
            ]
        )
        normalized = _normalize_tool_call_arguments(
            client,
            "disassemble",
            {"max_lines": "oops"},
            "analyse sample_demo",
        )
        self.assertEqual(normalized["binary_path"], "/repo/examples/sample_demo.elf")
        self.assertEqual(normalized["max_lines"], 120)

    def test_select_mcp_tools_for_prompt_disassemble_intent(self):
        tools = [
            {"name": "disassemble"},
            {"name": "find_files"},
            {"name": "get_symbols"},
            {"name": "get_binary_info"},
            {"name": "demo_plugin_tool"},
        ]
        selected = _select_mcp_tools_for_prompt(
            tools, "donne le code asm de sample_demo.elf"
        )
        names = {tool["name"] for tool in selected}
        self.assertIn("disassemble", names)
        self.assertIn("find_files", names)
        self.assertNotIn("demo_plugin_tool", names)

    def test_select_mcp_tools_for_prompt_general_chat_returns_no_tools(self):
        tools = [{"name": "get_binary_info"}, {"name": "disassemble"}]
        self.assertEqual(
            _select_mcp_tools_for_prompt(
                tools, "fait moi un message long avec 200 mots"
            ),
            [],
        )

    def test_resolve_requested_tool_name_alias(self):
        available = {"extract_strings", "get_symbols", "disassemble"}
        self.assertEqual(
            _resolve_requested_tool_name("strings", available),
            "extract_strings",
        )
        self.assertEqual(
            _resolve_requested_tool_name("DISASM", available),
            "disassemble",
        )
        self.assertEqual(
            _resolve_requested_tool_name("unknown_tool", available),
            "unknown_tool",
        )

    def test_resolve_requested_tool_name_supports_dynamic_plugin_tool_short_name(
        self,
    ):
        available = {"plugin.demo_feature", "plugin.demo_extra"}
        self.assertEqual(
            _resolve_requested_tool_name("demo_feature", available),
            "plugin.demo_feature",
        )
        self.assertEqual(
            _resolve_requested_tool_name("missing_feature", available),
            "missing_feature",
        )

    def test_build_system_prompt_appends_memory_context(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            memory_path = Path(tmpdir) / "memory.md"
            memory_path.write_text("MCP memory context", encoding="utf-8")
            prompt = _build_system_prompt("Base system prompt", str(memory_path))
        assert prompt is not None
        self.assertIn("Base system prompt", prompt)
        self.assertIn("MCP memory context", prompt)
        self.assertIn("Additional project context", prompt)

    def test_ollama_chat_stream_preserves_exact_chunks(self):
        chunks = [
            {"message": {"content": "ligne 1\n"}, "done": False},
            {"message": {"content": "  ligne 2"}, "done": False},
            {"message": {"content": ""}, "done": True},
        ]
        tokens = []
        with patch(
            "backends.mcp.ollama_bridge.request.urlopen",
            return_value=_StreamingResponse(chunks),
        ):
            result = ollama_chat(
                "http://localhost:11434",
                "qwen3:8b",
                [{"role": "user", "content": "test"}],
                [],
                10,
                on_token=tokens.append,
            )
        self.assertEqual(tokens, ["ligne 1\n", "  ligne 2"])
        self.assertEqual(result["message"]["content"], "ligne 1\n  ligne 2")

    def test_ollama_chat_done_full_content_only_emits_missing_suffix(self):
        chunks = [
            {"message": {"content": "Bonjour"}, "done": False},
            {"message": {"content": "Bonjour le monde"}, "done": True},
        ]
        tokens = []
        with patch(
            "backends.mcp.ollama_bridge.request.urlopen",
            return_value=_StreamingResponse(chunks),
        ):
            result = ollama_chat(
                "http://localhost:11434",
                "gemma4",
                [{"role": "user", "content": "test"}],
                [],
                10,
                on_token=tokens.append,
            )
        self.assertEqual(tokens, ["Bonjour", " le monde"])
        self.assertEqual(result["message"]["content"], "Bonjour le monde")

    def test_ollama_chat_preserves_final_token_usage(self):
        chunks = [
            {"message": {"content": "Bonjour"}, "done": False},
            {
                "message": {"content": ""},
                "done": True,
                "prompt_eval_count": 17,
                "eval_count": 3,
            },
        ]
        with patch(
            "backends.mcp.ollama_bridge.request.urlopen",
            return_value=_StreamingResponse(chunks),
        ):
            result = ollama_chat(
                "http://localhost:11434",
                "gemma4",
                [{"role": "user", "content": "test"}],
                [],
                10,
                on_token=lambda _chunk: None,
            )
        self.assertEqual(
            result["usage"],
            {"prompt_eval_count": 17, "eval_count": 3},
        )

    def test_ollama_chat_forwards_generation_options(self):
        captured = {}

        def fake_urlopen(req, timeout=None):
            captured["payload"] = json.loads(req.data)
            return _StreamingResponse(
                [
                    {"message": {"content": "ok"}, "done": False},
                    {"message": {"content": ""}, "done": True},
                ]
            )

        with patch(
            "backends.mcp.ollama_bridge.request.urlopen",
            side_effect=fake_urlopen,
        ):
            ollama_chat(
                "http://localhost:11434",
                "gemma4",
                [{"role": "user", "content": "test"}],
                [],
                10,
                on_token=lambda _chunk: None,
                generation_options={
                    "temperature": 0.4,
                    "top_p": 0.8,
                    "num_predict": 2048,
                },
            )

        self.assertEqual(
            captured["payload"]["options"],
            {
                "temperature": 0.4,
                "top_p": 0.8,
                "num_predict": 2048,
            },
        )


class TestRunAgentOnce(unittest.TestCase):
    """Tests for run_agent_once return format and tool call tracking."""

    class _AgentFakeClient:
        def __init__(self, tools, tool_results):
            self.tools = tools
            self.tool_results = tool_results
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            if method == "tools/list":
                return {"tools": self.tools}
            if method == "tools/call":
                name = params.get("name", "")
                return self.tool_results.get(name, {"content": [{"text": "ok"}]})
            return {}

    _DISASM_TOOL = {
        "name": "disassemble",
        "description": "Disassemble binary",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
        },
    }

    def test_run_agent_once_returns_dict_with_response_and_tool_calls(self):
        client = self._AgentFakeClient(tools=[], tool_results={})
        fake_response = {
            "message": {
                "role": "assistant",
                "content": "Voici l'analyse.",
                "tool_calls": None,
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", return_value=fake_response
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Analyse demo.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertIsInstance(result, dict)
        self.assertIn("response", result)
        self.assertIn("tool_calls", result)
        self.assertIsInstance(result["tool_calls"], list)
        self.assertIn("Voici l'analyse", result["response"])

    def test_run_agent_once_exposes_final_and_whole_request_usage(self):
        client = self._AgentFakeClient(
            tools=[self._DISASM_TOOL],
            tool_results={"disassemble": {"content": [{"text": "ret"}]}},
        )
        responses = [
            {
                "message": {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {"function": {"name": "disassemble", "arguments": {}}},
                    ],
                },
                "usage": {"prompt_eval_count": 10, "eval_count": 2},
            },
            {
                "message": {
                    "role": "assistant",
                    "content": "Terminé.",
                    "tool_calls": [],
                },
                "usage": {"prompt_eval_count": 20, "eval_count": 4},
            },
        ]
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=responses,
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Désassemble demo.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertEqual(
            result["usage"],
            {
                "prompt_tokens": 20,
                "completion_tokens": 4,
                "total_tokens": 24,
                "request_prompt_tokens": 30,
                "request_completion_tokens": 6,
                "request_total_tokens": 36,
            },
        )

    def test_run_agent_once_general_chat_does_not_offer_mcp_tools(self):
        client = self._AgentFakeClient(tools=[self._DISASM_TOOL], tool_results={})
        captured_tools = []
        captured_messages = []

        def fake_ollama_chat(
            base_url, model, messages, tools, timeout_s, on_token=None
        ):
            captured_tools.extend(tools)
            captured_messages.extend(messages)
            return {
                "message": {
                    "role": "assistant",
                    "content": "Voici un long message.",
                    "tool_calls": [],
                }
            }

        prompt = (
            "Contexte binaire passif :\n"
            "Binaire actuellement ouvert dans l'application : examples/demo.elf\n\n"
            "Demande utilisateur : fait moi un message long avec 200 mots"
        )
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=fake_ollama_chat,
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="gemma4:e4b",
                prompt=prompt,
                max_steps=4,
                timeout_s=10,
            )
        self.assertEqual(captured_tools, [])
        self.assertNotIn("examples/demo.elf", captured_messages[-1]["content"])
        self.assertIn("fait moi un message long", captured_messages[-1]["content"])
        self.assertEqual(result["response"], "Voici un long message.")

    def test_run_agent_once_tracks_successful_tool_call(self):
        tool_results = {
            "disassemble": {
                "content": [{"text": "push rbp\nmov rbp, rsp"}],
                "isError": False,
            }
        }
        client = self._AgentFakeClient(
            tools=[self._DISASM_TOOL], tool_results=tool_results
        )
        step1 = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "disassemble",
                            "arguments": {"binary_path": "demo.elf"},
                        }
                    }
                ],
            }
        }
        step2 = {
            "message": {
                "role": "assistant",
                "content": "Le fichier contient 10 instructions.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", side_effect=[step1, step2]
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Désassemble demo.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertEqual(len(result["tool_calls"]), 1)
        self.assertEqual(result["tool_calls"][0]["name"], "disassemble")
        self.assertTrue(result["tool_calls"][0]["ok"])
        self.assertIn("10 instructions", result["response"])

    def test_noop_tool_fallback_is_synthesized_with_streaming(self):
        class _FallbackClient(self._AgentFakeClient):
            def request(self, method, params):
                if method == "tools/list":
                    return {"tools": [TestRunAgentOnce._DISASM_TOOL]}
                if method == "tools/call":
                    return {
                        "structuredContent": {
                            "ok": True,
                            "count": 2,
                            "lines": [
                                {"addr": "0x1000", "text": "push rbp"},
                                {"addr": "0x1001", "text": "mov rbp, rsp"},
                            ],
                        }
                    }
                return {}

        client = _FallbackClient(tools=[self._DISASM_TOOL], tool_results={})
        events = []
        call_count = 0

        def fake_ollama_chat(
            base_url, model, messages, tools, timeout_s, on_token=None
        ):
            nonlocal call_count
            call_count += 1
            if call_count <= 2:
                if on_token:
                    on_token("Please provide a file.")
                return {
                    "message": {
                        "role": "assistant",
                        "content": "Please provide a file.",
                        "tool_calls": [],
                    }
                }
            self.assertEqual(tools, [])
            self.assertIn("Résultat extrait automatiquement", messages[-1]["content"])
            if on_token:
                on_token("Le prologue ")
                on_token("prépare la pile.")
            return {
                "message": {
                    "role": "assistant",
                    "content": "Le prologue prépare la pile.",
                    "tool_calls": [],
                }
            }

        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=fake_ollama_chat,
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="gemma4:e4b",
                prompt="Désassemble demo.elf et explique le code.",
                max_steps=4,
                timeout_s=10,
                on_event=events.append,
            )

        self.assertEqual(result["response"], "Le prologue prépare la pile.")
        self.assertEqual(
            [event["type"] for event in events],
            [
                "token",
                "token_rollback",
                "token",
                "token_rollback",
                "token",
                "token",
            ],
        )

    def test_run_agent_once_tracks_failed_tool_call(self):
        tool_results = {
            "disassemble": {
                "content": [],
                "isError": True,
                "structuredContent": {"ok": False, "error": "file not found"},
            }
        }
        client = self._AgentFakeClient(
            tools=[self._DISASM_TOOL], tool_results=tool_results
        )
        step1 = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "disassemble",
                            "arguments": {"binary_path": "missing.elf"},
                        }
                    }
                ],
            }
        }
        step2 = {
            "message": {
                "role": "assistant",
                "content": "Fichier introuvable.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", side_effect=[step1, step2]
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Désassemble missing.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertEqual(len(result["tool_calls"]), 1)
        self.assertFalse(result["tool_calls"][0]["ok"])

    def test_run_agent_once_on_event_called_for_each_tool(self):
        """on_event callback receives tool_call and tool_result events in order."""
        tool_results = {
            "disassemble": {"content": [{"text": "push rbp"}], "isError": False}
        }
        client = self._AgentFakeClient(
            tools=[self._DISASM_TOOL], tool_results=tool_results
        )
        events = []
        step1 = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "disassemble",
                            "arguments": {"binary_path": "demo.elf"},
                        }
                    }
                ],
            }
        }
        step2 = {
            "message": {
                "role": "assistant",
                "content": "Analyse complète.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", side_effect=[step1, step2]
        ):
            run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Désassemble demo.elf",
                max_steps=4,
                timeout_s=10,
                on_event=events.append,
            )
        types = [e["type"] for e in events]
        self.assertEqual(types, ["tool_call", "tool_result"])
        self.assertEqual(events[0]["name"], "disassemble")
        self.assertTrue(events[1]["ok"])

    def test_run_agent_once_multiple_tool_calls_logged(self):
        tools = [
            self._DISASM_TOOL,
            {
                "name": "get_symbols",
                "description": "Get symbols",
                "inputSchema": {
                    "type": "object",
                    "properties": {"binary_path": {"type": "string"}},
                    "required": [],
                },
            },
        ]
        tool_results = {
            "disassemble": {"content": [{"text": "push rbp"}], "isError": False},
            "get_symbols": {"content": [{"text": "main, _start"}], "isError": False},
        }
        client = self._AgentFakeClient(tools=tools, tool_results=tool_results)
        step1 = {
            "message": {
                "role": "assistant",
                "content": "",
                "tool_calls": [
                    {
                        "function": {
                            "name": "disassemble",
                            "arguments": {"binary_path": "a.elf"},
                        }
                    },
                    {
                        "function": {
                            "name": "get_symbols",
                            "arguments": {"binary_path": "a.elf"},
                        }
                    },
                ],
            }
        }
        step2 = {
            "message": {
                "role": "assistant",
                "content": "Analyse complète.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", side_effect=[step1, step2]
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="qwen3:8b",
                prompt="Analyse a.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertEqual(len(result["tool_calls"]), 2)
        names = [tc["name"] for tc in result["tool_calls"]]
        self.assertIn("disassemble", names)
        self.assertIn("get_symbols", names)


class TestOllamaToolsUnsupportedPath(unittest.TestCase):
    """Tests for the OllamaToolsUnsupportedError auto-fallback path (Task #27)."""

    class _NoToolClient:
        def __init__(self, binary_info):
            self.binary_info = binary_info
            self.calls = []

        def request(self, method, params):
            self.calls.append((method, params))
            if method == "tools/list":
                return {
                    "tools": [
                        {
                            "name": "get_binary_info",
                            "description": "Get binary info",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"binary_path": {"type": "string"}},
                                "required": [],
                            },
                        }
                    ]
                }
            if method == "tools/call" and params.get("name") == "get_binary_info":
                return {"structuredContent": self.binary_info}
            return {}

    def test_unsupported_tools_returns_dict_with_empty_tool_calls(self):
        client = self._NoToolClient(
            binary_info={"ok": True, "format": "ELF", "arch": "x86_64"}
        )
        final_resp = {
            "message": {
                "role": "assistant",
                "content": "C'est un ELF x86_64.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=[OllamaToolsUnsupportedError("no tools"), final_resp],
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="codegemma:7b",
                prompt="fait moi un rapport sur demo.elf",
                max_steps=4,
                timeout_s=10,
            )
        self.assertIsInstance(result, dict)
        self.assertIn("response", result)
        self.assertIn("tool_calls", result)
        self.assertEqual(result["tool_calls"], [])

    def test_unsupported_tools_warning_prepended_when_no_fallback_data(self):
        """When _auto_tool_fallback returns nothing, warning is prepended to response."""

        class _EmptyClient:
            def request(self, method, params):
                if method == "tools/list":
                    return {"tools": []}
                return {}

        final_resp = {
            "message": {
                "role": "assistant",
                "content": "Je ne sais pas.",
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=[OllamaToolsUnsupportedError("no tools"), final_resp],
        ):
            result = run_agent_once(
                client=_EmptyClient(),
                base_url="http://localhost:11434",
                model="codegemma:7b",
                prompt="Analyse",
                max_steps=4,
                timeout_s=10,
            )
        self.assertIn("ne supporte pas", result["response"])

    def test_unsupported_tools_injects_prefetch_into_user_message(self):
        """Binary data pre-fetched by _auto_tool_fallback is injected into the prompt."""
        client = self._NoToolClient(
            binary_info={"ok": True, "format": "PE", "arch": "x86"}
        )
        call_log = []

        def fake_ollama_chat(
            base_url, model, messages, tools, timeout_s, on_token=None
        ):
            call_log.append(messages[:])
            if len(call_log) == 1:
                raise OllamaToolsUnsupportedError("no tools")
            return {
                "message": {
                    "role": "assistant",
                    "content": "C'est un PE x86.",
                    "tool_calls": [],
                }
            }

        with patch(
            "backends.mcp.ollama_bridge._ollama_chat", side_effect=fake_ollama_chat
        ):
            run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="codegemma:7b",
                prompt="rapport sur demo.exe",
                max_steps=4,
                timeout_s=10,
            )
        # On the second call (retry), the user message should contain prefetch data
        second_call_messages = call_log[1]
        user_msg = next(m for m in second_call_messages if m["role"] == "user")
        self.assertIn("Données du fichier", user_msg["content"])
        self.assertIn("rapport sur demo.exe", user_msg["content"])

    def test_non_streaming_retry_emits_exact_response_once(self):
        client = self._NoToolClient(
            binary_info={"ok": True, "format": "PE", "arch": "x86"}
        )
        full_response = "Ligne 1\n\n  Ligne 2"
        events = []
        final_resp = {
            "message": {
                "role": "assistant",
                "content": full_response,
                "tool_calls": [],
            }
        }
        with patch(
            "backends.mcp.ollama_bridge._ollama_chat",
            side_effect=[
                OllamaToolsUnsupportedError("no tools"),
                RuntimeError("stream rejected"),
                final_resp,
            ],
        ):
            result = run_agent_once(
                client=client,
                base_url="http://localhost:11434",
                model="codegemma:7b",
                prompt="rapport sur demo.exe",
                max_steps=4,
                timeout_s=10,
                on_event=events.append,
            )
        token_events = [event for event in events if event["type"] == "token"]
        self.assertEqual(token_events, [{"type": "token", "content": full_response}])
        self.assertTrue(result["response"].endswith(full_response))


class TestParseArgsJsonOutput(unittest.TestCase):
    def test_json_output_flag_default_false(self):
        args = parse_args(["--prompt", "test"])
        self.assertFalse(args.json_output)

    def test_json_output_flag_enabled(self):
        args = parse_args(["--prompt", "test", "--json-output"])
        self.assertTrue(args.json_output)

    def test_stream_output_flag_default_false(self):
        args = parse_args(["--prompt", "test"])
        self.assertFalse(args.stream_output)

    def test_stream_output_flag_enabled(self):
        args = parse_args(["--prompt", "test", "--stream-output"])
        self.assertTrue(args.stream_output)

    def test_generation_flags(self):
        args = parse_args(
            [
                "--prompt",
                "test",
                "--temperature",
                "0.4",
                "--top-p",
                "0.8",
                "--max-tokens",
                "2048",
            ]
        )
        self.assertEqual(args.temperature, 0.4)
        self.assertEqual(args.top_p, 0.8)
        self.assertEqual(args.max_tokens, 2048)


if __name__ == "__main__":
    unittest.main()
