#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""MCP server for Pile ou Face.

Transport: stdio (JSON-RPC 2.0 with Content-Length framing).
"""

from __future__ import annotations

import argparse
import difflib
import fnmatch
import importlib.util
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from backends.mcp.ai_provider import (
    call_provider,
    list_providers,
    set_provider_configuration,
)
from backends.mcp.env_loader import load_pof_env
from backends.mcp.tool_scanner import scan_backend_tools
from backends.static.binary.symbols import extract_symbols as _extract_symbols

LOGGER = logging.getLogger("pile_ou_face.mcp")
SERVER_NAME = "pile-ou-face-mcp"
SERVER_VERSION = "0.1.0"
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
MCP_MEMORY_PATH = os.path.join(ROOT, "docs", "mcp", "memory.md")
MCP_MEMORY_LEGACY_DOCS_PATH = os.path.join(ROOT, "docs", "mcp", "docs", "memory.md")
MCP_MEMORY_LEGACY_ROOT_PATH = os.path.join(ROOT, "memory.md")

JSONRPC_PARSE_ERROR = -32700
JSONRPC_INVALID_REQUEST = -32600
JSONRPC_METHOD_NOT_FOUND = -32601
JSONRPC_INVALID_PARAMS = -32602
JSONRPC_INTERNAL_ERROR = -32603

SEARCH_SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    ".venv",
    "venv",
    "node_modules",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
}

TOOLS: list[dict[str, Any]] = [
    {
        "name": "annotations_list",
        "description": "List annotations.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "annotations_save",
        "description": "Save annotation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
                "comment": {"type": "string"},
                "name": {"type": "string"},
            },
            "required": ["binary_path", "addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "annotations_delete",
        "description": "Delete annotation.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
                "kind": {"type": "string"},
            },
            "required": ["binary_path", "addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "simulate_asm",
        "description": "Simulate asm code.",
        "inputSchema": {
            "type": "object",
            "properties": {"asm_code": {"type": "string"}},
            "required": ["asm_code"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_exports",
        "description": "Extract exports.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cache_invalidate",
        "description": "Invalidate cache entry.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "cache_db": {"type": "string"},
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "cache_stats",
        "description": "Get cache stats.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "cache_db": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cache_list",
        "description": "List cache entries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "cache_db": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "cache_purge",
        "description": "Purge cache entries.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "cache_db": {"type": "string"},
                "target_binary": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "build_call_graph",
        "description": "Build call graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "mapping_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "build_cfg",
        "description": "Build full CFG.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "mapping_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "build_cfg_for_function",
        "description": "Build function CFG.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "mapping_path": {"type": "string"},
                "addr": {"type": "string"},
            },
            "required": ["addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "decompile_function",
        "description": "Decompile function.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
                "func_name": {"type": "string"},
                "decompiler": {"type": "string"},
                "quality": {
                    "type": "string",
                    "description": "Legacy hint accepted for compatibility and ignored by the backend.",
                },
            },
            "required": ["binary_path", "addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "decompile_binary",
        "description": "Decompile binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "decompiler": {"type": "string"},
                "quality": {
                    "type": "string",
                    "description": "Legacy hint accepted for compatibility and ignored by the backend.",
                },
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "disassemble",
        "description": "Disassemble binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
                "max_lines": {"type": "integer", "minimum": 1, "maximum": 5000},
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "discover_functions",
        "description": "Discover functions.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "mapping_path": {"type": "string"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "extract_dwarf",
        "description": "Extract dwarf info.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_entropy",
        "description": "Analyze entropy.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "threshold": {"type": "number"},
                "window": {"type": "integer"},
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "export_results",
        "description": "Export results to file.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "kind": {"type": "string"},
                "output_path": {"type": "string"},
                "data": {},
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
                "graph_name": {"type": "string"},
            },
            "required": ["kind", "output_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_binary_info",
        "description": "Get binary info.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "hex_dump",
        "description": "Hex dump.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "offset": {"type": "integer"},
                "length": {"type": "integer"},
            },
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "find_import_callsites",
        "description": "Find import callsites.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "function": {"type": "string"},
            },
            "required": ["binary_path", "function"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_imports",
        "description": "Analyze imports.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "offset_to_vaddr",
        "description": "Offset to virtual address.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "offset": {"type": "string"},
            },
            "required": ["binary_path", "offset"],
            "additionalProperties": False,
        },
    },
    {
        "name": "execute_script",
        "description": "Execute a Python analysis script.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "code": {"type": "string"},
                "binary_path": {"type": "string"},
                "timeout": {"type": "integer"},
            },
            "required": ["code"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rules_list",
        "description": "List rules.",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "rules_toggle",
        "description": "Toggle rule.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "rule_id": {"type": "string"},
                "enabled": {"type": "boolean"},
            },
            "required": ["rule_id", "enabled"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rules_add",
        "description": "Add rule.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "type": {"type": "string"},
                "content": {"type": "string"},
            },
            "required": ["name", "type", "content"],
            "additionalProperties": False,
        },
    },
    {
        "name": "rules_delete",
        "description": "Delete rule.",
        "inputSchema": {
            "type": "object",
            "properties": {"rule_id": {"type": "string"}},
            "required": ["rule_id"],
            "additionalProperties": False,
        },
    },
    {
        "name": "search_binary",
        "description": "Search in binary.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "pattern": {"type": "string"},
                "mode": {"type": "string"},
                "section": {"type": "string"},
            },
            "required": ["binary_path", "pattern"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_sections",
        "description": "Get sections.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "analyze_stack_frame",
        "description": "Analyze stack frame.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "addr": {"type": "string"},
            },
            "required": ["binary_path", "addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "extract_strings",
        "description": "Extract strings.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_symbols",
        "description": "Get symbols.",
        "inputSchema": {
            "type": "object",
            "properties": {"binary_path": {"type": "string"}},
            "required": ["binary_path"],
            "additionalProperties": False,
        },
    },
    {
        "name": "get_xrefs",
        "description": "Get cross-references.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "binary_path": {"type": "string"},
                "mapping_path": {"type": "string"},
                "addr": {"type": "string"},
                "mode": {"type": "string"},
            },
            "required": ["addr"],
            "additionalProperties": False,
        },
    },
    {
        "name": "plugins_list",
        "description": "List installed plugins, states, commands and capabilities exposed by the host runtime.",
        "inputSchema": {
            "type": "object",
            "properties": {"attach": {"type": "boolean"}},
            "additionalProperties": False,
        },
    },
    {
        "name": "plugin_invoke",
        "description": "Invoke a command or feature exposed by an active plugin.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "command_id": {"type": "string"},
                "feature_id": {"type": "string"},
                "payload": {"type": "object"},
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "find_files",
        "description": "Find files in workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200},
            },
            "required": ["query"],
            "additionalProperties": False,
        },
    },
]

TOOL_NAME_SET = {
    str(tool.get("name", "")).strip()
    for tool in TOOLS
    if isinstance(tool, dict) and str(tool.get("name", "")).strip()
}

PLUGIN_TOOL_NAME_PREFIX = "plugin."

# MCP v2: startup — load env, scan backend tools, define AI tools
load_pof_env()

_STATIC_TOOL_NAMES: set[str] = {t["name"] for t in TOOLS}
_STATIC_ROOT = Path(__file__).resolve().parents[2] / "backends" / "static"
DYNAMIC_TOOLS: list[dict] = scan_backend_tools(
    _STATIC_ROOT, exclude_names=_STATIC_TOOL_NAMES
)

AI_TOOLS: list[dict] = [
    {
        "name": "ai_providers_list",
        "description": "List AI providers and their configuration status (keys are never returned).",
        "inputSchema": {
            "type": "object",
            "properties": {},
            "required": [],
            "additionalProperties": False,
        },
    },
    {
        "name": "ai_providers_set",
        "description": "Write or update an AI provider API key in ~/.pile-ou-face/.env.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "provider": {"type": "string"},
                "api_key": {"type": "string"},
                "model": {"type": "string"},
            },
            "required": ["provider", "api_key"],
            "additionalProperties": False,
        },
    },
    {
        "name": "ai_analyze",
        "description": "Analyze binary context with an AI provider.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "prompt": {"type": "string"},
                "context": {"type": "string"},
                "provider": {"type": "string"},
                "model": {"type": "string"},
                "binary_path": {"type": "string"},
            },
            "required": ["prompt", "context"],
            "additionalProperties": False,
        },
    },
]

TOOL_NAME_ALIASES: dict[str, str] = {
    "strings": "extract_strings",
    "string": "extract_strings",
    "symbols": "get_symbols",
    "symboles": "get_symbols",
    "symbol": "get_symbols",
    "disasm": "disassemble",
    "asm": "disassemble",
    "xref": "get_xrefs",
    "xrefs": "get_xrefs",
    "sections": "get_sections",
    "imports": "analyze_imports",
    "callgraph": "build_call_graph",
    "call_graph": "build_call_graph",
    "cfg_function": "build_cfg_for_function",
    "binary_info": "get_binary_info",
}


def _jsonrpc_success(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _jsonrpc_error(
    request_id: Any, code: int, message: str, data: Any | None = None
) -> dict[str, Any]:
    payload = {"code": code, "message": message}
    if data is not None:
        payload["data"] = data
    return {"jsonrpc": "2.0", "id": request_id, "error": payload}


def _tool_result(payload: Any, is_error: bool = False) -> dict[str, Any]:
    """Format a MCP tool result with structured content + text fallback."""
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, ensure_ascii=True),
            }
        ],
        "structuredContent": payload,
        "isError": is_error,
    }


def _load_mcp_memory_context(max_chars: int = 6000) -> str:
    for path in (
        MCP_MEMORY_PATH,
        MCP_MEMORY_LEGACY_DOCS_PATH,
        MCP_MEMORY_LEGACY_ROOT_PATH,
    ):
        if not os.path.isfile(path):
            continue
        try:
            with open(path, encoding="utf-8") as f:
                content = f.read().strip()
        except OSError:
            continue
        if not content:
            continue
        if len(content) <= max_chars:
            return content
        return content[:max_chars].rstrip() + "\n...[truncated]"
    return ""


def _normalize_params(params: Any) -> dict[str, Any]:
    return params if isinstance(params, dict) else {}


def _resolve_tool_name(name: str) -> str:
    raw = name.strip()
    if not raw:
        return raw
    if raw in TOOL_NAME_SET:
        return raw
    candidate = raw.lower().replace("-", "_")
    if candidate in TOOL_NAME_SET:
        return candidate
    alias = TOOL_NAME_ALIASES.get(candidate)
    if isinstance(alias, str) and alias in TOOL_NAME_SET:
        return alias
    return raw


def _required_string(params: dict[str, Any], key: str) -> str:
    value = params.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid required parameter: {key}")
    return value.strip()


def _parse_int_addr(value: str | None) -> int | None:
    if not value:
        return None
    text = value.strip()
    if not text:
        return None
    try:
        if text.lower().startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


def _python_exe() -> str:
    venv_python = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
    return venv_python if os.path.isfile(venv_python) else sys.executable


def _plugin_runtime_records() -> dict[str, Any]:
    from backends.plugins.runtime import (
        HOST_API_VERSION as plugin_api_version,
    )
    from backends.plugins.runtime import (
        collect_runtime_state,
        default_plugin_search_paths,
    )

    payload = collect_runtime_state(
        host_version=SERVER_VERSION,
        api_version=plugin_api_version,
        search_paths=default_plugin_search_paths(
            cwd=ROOT, allow_workspace_discovery=False
        ),
        attach=True,
    )
    return payload


def _dynamic_plugin_tools() -> list[dict[str, Any]]:
    routes = _dynamic_plugin_tool_routes()
    tools: list[dict[str, Any]] = []
    for tool_name, route in sorted(routes.items()):
        command_name = str(route.get("command_id") or "")
        feature_name = str(route.get("feature_id") or "")
        owner = str(route.get("plugin_id") or "").strip()
        target = feature_name or command_name
        tools.append(
            {
                "name": tool_name,
                "description": (
                    f"Plugin feature exposed by {owner or 'plugin runtime'}: {target}"
                ),
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "binary_path": {
                            "type": "string",
                            "description": "Absolute path to the binary",
                        },
                        "payload": {
                            "type": "object",
                            "description": "Additional parameters",
                        },
                    },
                    "additionalProperties": False,
                },
            }
        )
    return tools


def _dynamic_plugin_tool_routes() -> dict[str, dict[str, str]]:
    payload = _plugin_runtime_records()
    attached = payload.get("attached") if isinstance(payload, dict) else {}
    if not isinstance(attached, dict):
        return {}
    command_sources = attached.get("command_sources")
    if not isinstance(command_sources, dict):
        return {}
    routes: dict[str, dict[str, str]] = {}
    for command_id, plugin_id in sorted(command_sources.items()):
        command_name = str(command_id or "").strip()
        owner = str(plugin_id or "").strip()
        if not command_name:
            continue
        routes[f"{PLUGIN_TOOL_NAME_PREFIX}{command_name}"] = {
            "command_id": command_name,
            "plugin_id": owner,
        }

    plugins = payload.get("plugins") if isinstance(payload, dict) else []
    if not isinstance(plugins, list):
        return routes
    for record in plugins:
        if not isinstance(record, dict) or record.get("state") != "active":
            continue
        plugin_id = str(record.get("id") or "").strip()
        manifest = record.get("manifest")
        if not isinstance(manifest, dict):
            continue
        for item in manifest.get("commands") or []:
            if not isinstance(item, dict):
                continue
            command_id = str(item.get("id") or item.get("command") or "").strip()
            feature_id = str(
                item.get("feature") or item.get("feature_id") or ""
            ).strip()
            if not command_id or command_id not in command_sources or not feature_id:
                continue
            routes[f"{PLUGIN_TOOL_NAME_PREFIX}{feature_id}"] = {
                "feature_id": feature_id,
                "command_id": command_id,
                "plugin_id": plugin_id,
            }
    return routes


def _run_static_script_json(
    script_name: str, args: list[str], timeout: int = 120
) -> dict[str, Any]:
    script_path = os.path.join(ROOT, "backends", "static", script_name)
    env = {**os.environ, "PYTHONPATH": ROOT}
    proc = subprocess.run(
        [_python_exe(), script_path, *args],
        capture_output=True,
        text=True,
        cwd=ROOT,
        env=env,
        timeout=timeout,
    )
    stdout = (proc.stdout or "").strip()
    stderr = (proc.stderr or "").strip()
    try:
        parsed = json.loads(stdout) if stdout else {}
        if isinstance(parsed, list):
            return {"ok": proc.returncode == 0, "data": parsed}
        if isinstance(parsed, dict):
            parsed.setdefault("ok", proc.returncode == 0)
            return parsed
    except json.JSONDecodeError:
        pass
    return {"ok": False, "error": stderr or stdout or f"{script_name} failed"}


def _ensure_ok(payload: Any) -> dict[str, Any]:
    if isinstance(payload, list):
        return {"ok": True, "data": payload}
    if isinstance(payload, dict):
        payload = dict(payload)
        payload.setdefault("ok", not bool(payload.get("error")))
        return payload
    return {"ok": True, "data": payload}


def _cache_db_from_args(args: dict[str, Any]) -> str:
    from backends.static.cache.cache import default_cache_path

    cache_db = args.get("cache_db")
    if isinstance(cache_db, str) and cache_db.strip():
        return os.path.abspath(cache_db.strip())
    raw_binary = args.get("binary_path", args.get("binary"))
    if not isinstance(raw_binary, str) or not raw_binary.strip():
        raise ValueError("Missing parameter: provide binary_path or cache_db")
    binary_path = _binary_path_from(args)
    return default_cache_path(binary_path)


def _iter_workspace_files() -> list[str]:
    paths: list[str] = []
    for dirpath, dirnames, filenames in os.walk(ROOT):
        dirnames[:] = [d for d in dirnames if d not in SEARCH_SKIP_DIRS]
        for filename in filenames:
            paths.append(os.path.join(dirpath, filename))
    return paths


def _find_files(query: str, limit: int = 20) -> dict[str, Any]:
    q = query.strip()
    if not q:
        raise ValueError("Missing or invalid required parameter: query")

    wildcard = any(ch in q for ch in "*?[]")
    ql = q.lower()

    matches: list[tuple[str, str, str]] = []
    for abs_path in _iter_workspace_files():
        rel_path = os.path.relpath(abs_path, ROOT).replace(os.sep, "/")
        name = os.path.basename(abs_path)
        if wildcard:
            ok = fnmatch.fnmatch(rel_path, q) or fnmatch.fnmatch(name, q)
        else:
            low_name = name.lower()
            low_rel = rel_path.lower()
            ok = low_name == ql or ql in low_name or ql in low_rel
        if ok:
            matches.append((abs_path, rel_path, name))

    def _rank(entry: tuple[str, str, str]) -> tuple[int, int, str]:
        _, rel_path, name = entry
        low_name = name.lower()
        if wildcard:
            score = 2
        elif low_name == ql:
            score = 0
        elif ql in low_name:
            score = 1
        else:
            score = 2
        return (score, len(rel_path), rel_path)

    matches.sort(key=_rank)
    total = len(matches)
    limited = matches[: max(1, min(limit, 200))]
    return {
        "ok": True,
        "query": q,
        "count": total,
        "truncated": total > len(limited),
        "root": ROOT,
        "results": [
            {"path": abs_path, "relative_path": rel_path}
            for abs_path, rel_path, _ in limited
        ],
    }


def _disassemble_for_mcp(
    binary_path: str,
    *,
    addr: str | None = None,
    max_lines: int = 400,
) -> dict[str, Any]:
    os.makedirs(os.path.join(ROOT, ".pile-ou-face", "mcp"), exist_ok=True)
    stamp = int(time.time() * 1000)
    safe_name = os.path.basename(binary_path).replace(" ", "_")
    out_asm = os.path.join(
        ROOT, ".pile-ou-face", "mcp", f"{safe_name}.{stamp}.disasm.asm"
    )
    out_map = os.path.join(
        ROOT, ".pile-ou-face", "mcp", f"{safe_name}.{stamp}.mapping.json"
    )

    python_exe = _python_exe()
    disasm_script = os.path.join(ROOT, "backends", "static", "disasm", "disasm.py")
    env = {**os.environ, "PYTHONPATH": ROOT}
    cmd = [
        python_exe,
        disasm_script,
        "--binary",
        binary_path,
        "--output",
        out_asm,
        "--output-mapping",
        out_map,
        "--syntax",
        "intel",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=env,
            timeout=180,
        )
    except Exception as exc:
        return {"ok": False, "error": f"Disassembly failed: {exc}"}

    if proc.returncode != 0:
        err = proc.stderr.strip() or proc.stdout.strip() or "Unknown disassembly error"
        return {"ok": False, "error": err}

    if not os.path.isfile(out_map):
        return {
            "ok": False,
            "error": "Disassembly failed: mapping file was not produced",
        }

    try:
        with open(out_map, encoding="utf-8") as f:
            mapping = json.load(f)
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Disassembly failed: cannot read mapping ({exc})",
        }

    lines = mapping.get("lines", [])
    if not isinstance(lines, list):
        lines = []

    normalized_max = max(1, min(int(max_lines), 5000))
    selected = lines
    addr_value = _parse_int_addr(addr)
    if addr_value is not None and lines:
        idx = None
        for i, line in enumerate(lines):
            line_addr = _parse_int_addr(str(line.get("addr", "")))
            if line_addr is None:
                continue
            if line_addr >= addr_value:
                idx = i
                break
        if idx is None:
            idx = max(0, len(lines) - 1)
        half = max(1, normalized_max // 2)
        start = max(0, idx - half)
        end = min(len(lines), start + normalized_max)
        selected = lines[start:end]
    elif len(lines) > normalized_max:
        selected = lines[:normalized_max]

    return {
        "ok": True,
        "binary_path": binary_path,
        "asm_path": out_asm,
        "mapping_path": out_map,
        "count": len(lines),
        "truncated": len(selected) < len(lines),
        "addr_filter": addr if isinstance(addr, str) and addr.strip() else None,
        "lines": selected,
    }


def _resolve_binary_path(raw_value: str) -> str:
    value = raw_value.strip()
    if not value:
        raise ValueError("Missing or invalid required parameter: binary_path")

    direct_candidates: list[str] = []
    if os.path.isabs(value):
        direct_candidates.append(value)
    else:
        direct_candidates.append(os.path.abspath(value))
        direct_candidates.append(os.path.abspath(os.path.join(ROOT, value)))

    for candidate in direct_candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)

    basename = os.path.basename(value)
    if not basename:
        raise ValueError(f"Binary not found: {value}")

    workspace_files = _iter_workspace_files()
    matches: list[str] = []
    for abs_path in workspace_files:
        if os.path.basename(abs_path) == basename:
            matches.append(abs_path)

    if not matches:
        requested_ext = os.path.splitext(basename)[1].lower()
        requested_name = basename.lower()
        requested_norm = (
            "".join(ch for ch in requested_name if ch.isalnum()) or requested_name
        )
        scored: list[tuple[float, str]] = []
        for abs_path in workspace_files:
            candidate_name = os.path.basename(abs_path)
            if (
                requested_ext
                and os.path.splitext(candidate_name)[1].lower() != requested_ext
            ):
                continue
            candidate_low = candidate_name.lower()
            candidate_norm = (
                "".join(ch for ch in candidate_low if ch.isalnum()) or candidate_low
            )
            score = difflib.SequenceMatcher(
                None, requested_norm, candidate_norm
            ).ratio()
            if score >= 0.72:
                scored.append((score, abs_path))
        if scored:
            scored.sort(
                key=lambda item: (
                    -item[0],
                    0 if "/examples/" in item[1].replace(os.sep, "/") else 1,
                    len(item[1]),
                    item[1],
                )
            )
            best_score, best_path = scored[0]
            LOGGER.info(
                "Resolved binary '%s' to '%s' via fuzzy match (score=%.3f)",
                value,
                best_path,
                best_score,
            )
            return best_path

    if not matches:
        raise ValueError(
            f"Binary not found: {value}. Use find_files to locate available paths."
        )

    matches.sort(
        key=lambda p: (
            0 if "/examples/" in p.replace(os.sep, "/") else 1,
            len(p),
            p,
        )
    )
    if len(matches) > 1:
        LOGGER.info(
            "Resolved binary '%s' to '%s' (%d candidates)",
            value,
            matches[0],
            len(matches),
        )
    return matches[0]


def _binary_path_from(params: dict[str, Any]) -> str:
    # Accept both keys for compatibility with existing ecosystem patterns.
    value = params.get("binary_path", params.get("binary"))
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing or invalid required parameter: binary_path")
    return _resolve_binary_path(value)


def _mapping_path_from(params: dict[str, Any]) -> str:
    mapping = params.get("mapping_path", params.get("mapping"))
    if isinstance(mapping, str) and mapping.strip():
        path = mapping.strip()
        if not os.path.isabs(path):
            path = os.path.abspath(os.path.join(ROOT, path))
        if os.path.isfile(path):
            return path
        raise ValueError(f"Mapping file not found: {path}")
    binary_path = _binary_path_from(params)
    generated = _disassemble_for_mcp(binary_path, max_lines=1)
    if not generated.get("ok"):
        raise ValueError(str(generated.get("error", "Cannot generate mapping")))
    mapping_path = generated.get("mapping_path")
    if not isinstance(mapping_path, str) or not os.path.isfile(mapping_path):
        raise ValueError("Cannot resolve mapping_path")
    return mapping_path


def _parse_offset(value: Any) -> int:
    if isinstance(value, int):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("Missing or invalid required parameter: offset")
    text = value.strip()
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


def _parse_int_arg(
    args: dict[str, Any],
    key: str,
    default: int | None = None,
    *,
    minimum: int | None = None,
) -> int:
    raw = args.get(key, default)
    if raw is None:
        raise ValueError(f"Missing or invalid required parameter: {key}")
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid parameter: {key} must be an integer") from exc
    if minimum is not None and value < minimum:
        raise ValueError(f"Invalid parameter: {key} must be >= {minimum}")
    return value


def _parse_float_arg(
    args: dict[str, Any],
    key: str,
    default: float | None = None,
) -> float:
    raw = args.get(key, default)
    if raw is None:
        raise ValueError(f"Missing or invalid required parameter: {key}")
    try:
        return float(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid parameter: {key} must be a number") from exc


def _load_mapping_lines(mapping_path: str) -> tuple[list[dict[str, Any]], str | None]:
    try:
        with open(mapping_path, encoding="utf-8") as f:
            payload = json.load(f)
    except Exception as exc:
        raise ValueError(f"Cannot read mapping file: {exc}") from exc

    lines = payload.get("lines", [])
    if not isinstance(lines, list):
        lines = []
    binary = payload.get("binary")
    binary_path = binary if isinstance(binary, str) and binary.strip() else None
    return lines, binary_path


def _dispatch_dynamic_tool(tool_name: str, args: dict) -> dict:
    """Dispatch a dynamic backend tool discovered by scan_backend_tools."""
    module_slug, fn_name = tool_name.split(".", 1)
    for path in _STATIC_ROOT.rglob(f"{module_slug}.py"):
        spec = importlib.util.spec_from_file_location(module_slug, path)
        if not spec or not spec.loader:
            continue
        module = importlib.util.module_from_spec(spec)
        try:
            spec.loader.exec_module(module)  # type: ignore[union-attr]
        except (Exception, SystemExit):
            return {"ok": False, "error": f"Module load error for {module_slug}"}
        fn = getattr(module, fn_name, None)
        if fn is None:
            return {"ok": False, "error": f"Function not found: {fn_name}"}
        try:
            result = fn(**args)
        except Exception as exc:
            return {"ok": False, "error": str(exc)}
        if isinstance(result, dict):
            return {"ok": True, **result}
        return {"ok": True, "result": result}
    return {"ok": False, "error": f"Module not found: {module_slug}"}


def _call_tool(name: str, args: dict[str, Any]) -> dict[str, Any]:
    if name == "annotations_list":
        from backends.static.annotations.annotations import AnnotationStore

        binary_path = _binary_path_from(args)
        addr = args.get("addr")
        addr_value = (
            str(addr).strip() if isinstance(addr, str) and addr.strip() else None
        )
        with AnnotationStore(binary_path) as store:
            return {"ok": True, "annotations": store.list(addr=addr_value)}

    if name == "annotations_save":
        from backends.static.annotations.annotations import AnnotationStore

        binary_path = _binary_path_from(args)
        addr = _required_string(args, "addr")
        comment = args.get("comment")
        rename = args.get("name")
        did_write = False
        with AnnotationStore(binary_path) as store:
            if isinstance(comment, str) and comment.strip():
                store.comment(addr, comment)
                did_write = True
            if isinstance(rename, str) and rename.strip():
                store.rename(addr, rename)
                did_write = True
            if not did_write:
                raise ValueError("Provide at least one of: comment, name")
            return {"ok": True, "annotations": store.get(addr)}

    if name == "annotations_delete":
        from backends.static.annotations.annotations import AnnotationStore

        binary_path = _binary_path_from(args)
        addr = _required_string(args, "addr")
        kind = args.get("kind")
        kind_value = (
            str(kind).strip() if isinstance(kind, str) and kind.strip() else None
        )
        with AnnotationStore(binary_path) as store:
            deleted = store.delete(addr, kind=kind_value)
        return {"ok": True, "deleted": deleted, "addr": addr, "kind": kind_value}

    if name == "simulate_asm":
        from backends.static.disasm.asm_sim import parse_program, simulate

        asm_code = _required_string(args, "asm_code")
        lines = [(idx + 1, line) for idx, line in enumerate(asm_code.splitlines())]
        program, labels = parse_program(lines)
        snapshots = simulate(program, labels)
        return {
            "ok": True,
            "snapshots": snapshots,
            "meta": {"view_mode": "x86_64", "word_size": 8},
            "risks": [],
        }

    if name == "get_exports":
        from backends.static.binary.binary_exports import extract_exports

        return _ensure_ok(extract_exports(_binary_path_from(args)))

    if name == "plugins_list":
        attach = bool(args.get("attach", True))
        payload = _plugin_runtime_records()
        if not attach:
            payload = dict(payload)
            payload.pop("attached", None)
        return _ensure_ok(payload)

    if name == "plugin_invoke":
        from backends.plugins.runtime import (
            HOST_API_VERSION as plugin_api_version,
        )
        from backends.plugins.runtime import (
            build_plugin_registry,
            default_plugin_search_paths,
            invoke_plugin_command,
            invoke_plugin_feature,
        )

        command_id = str(args.get("command_id") or "").strip()
        feature_id = str(args.get("feature_id") or "").strip()
        if bool(command_id) == bool(feature_id):
            raise ValueError("Provide exactly one of command_id or feature_id")
        payload = args.get("payload")
        if payload is None:
            payload_dict: dict[str, Any] = {}
        elif isinstance(payload, dict):
            payload_dict = payload
        else:
            raise ValueError("payload doit être un objet")
        records = build_plugin_registry(
            default_plugin_search_paths(cwd=ROOT, allow_workspace_discovery=False),
            host_version=SERVER_VERSION,
            api_version=plugin_api_version,
        )
        if feature_id:
            response, context, attached_records = invoke_plugin_feature(
                records,
                feature_id,
                payload_dict,
                host_version=SERVER_VERSION,
                api_version=plugin_api_version,
            )
        else:
            response, context, attached_records = invoke_plugin_command(
                records,
                command_id,
                payload_dict,
                host_version=SERVER_VERSION,
                api_version=plugin_api_version,
            )
        response["plugins"] = [record.to_dict() for record in attached_records]
        response["attached"] = context.snapshot()
        return _ensure_ok(response)

    if name == "cache_invalidate":
        from backends.static.cache.cache import DisasmCache

        binary_path = _binary_path_from(args)
        cache_db = _cache_db_from_args(args)
        with DisasmCache(cache_db) as cache:
            cache.invalidate(binary_path)
        return {"ok": True, "cache_db": cache_db, "invalidated": binary_path}

    if name == "cache_stats":
        from backends.static.cache.cache_admin import db_stats

        cache_db = _cache_db_from_args(args)
        payload = db_stats(cache_db)
        payload["ok"] = not bool(payload.get("error"))
        return payload

    if name == "cache_list":
        from backends.static.cache.cache_admin import list_binaries

        cache_db = _cache_db_from_args(args)
        return {"ok": True, "cache_db": cache_db, "binaries": list_binaries(cache_db)}

    if name == "cache_purge":
        from backends.static.cache.cache_admin import purge_binary

        cache_db = _cache_db_from_args(args)
        target_binary = args.get("target_binary")
        target = (
            _resolve_binary_path(target_binary)
            if isinstance(target_binary, str) and target_binary.strip()
            else None
        )
        deleted = purge_binary(cache_db, binary_path=target)
        return {"ok": True, "cache_db": cache_db, "deleted": deleted, "target": target}

    if name == "build_call_graph":
        from backends.static.binary.symbols import extract_symbols
        from backends.static.disasm.call_graph import build_call_graph
        from backends.static.disasm.cfg import build_cfg

        mapping_path = _mapping_path_from(args)
        lines, mapping_binary = _load_mapping_lines(mapping_path)
        binary_path = (
            _binary_path_from(args) if "binary_path" in args else mapping_binary
        )
        cfg_payload = build_cfg(lines, binary_path=binary_path)
        symbols_payload = (
            extract_symbols(binary_path, defined_only=False) if binary_path else []
        )
        graph = build_call_graph(
            cfg_payload,
            symbols_payload,
            lines=lines,
            binary_path=binary_path,
        )
        graph["ok"] = True
        graph["mapping_path"] = mapping_path
        if binary_path:
            graph["binary_path"] = binary_path
        return graph

    if name == "build_cfg":
        from backends.static.disasm.cfg import build_cfg

        mapping_path = _mapping_path_from(args)
        lines, mapping_binary = _load_mapping_lines(mapping_path)
        binary_path = (
            _binary_path_from(args) if "binary_path" in args else mapping_binary
        )
        payload = build_cfg(lines, binary_path=binary_path)
        payload["ok"] = True
        payload["mapping_path"] = mapping_path
        if binary_path:
            payload["binary_path"] = binary_path
        return payload

    if name == "build_cfg_for_function":
        from backends.static.disasm.cfg import build_cfg_for_function

        mapping_path = _mapping_path_from(args)
        lines, mapping_binary = _load_mapping_lines(mapping_path)
        binary_path = (
            _binary_path_from(args) if "binary_path" in args else mapping_binary
        )
        addr = _required_string(args, "addr")
        payload = build_cfg_for_function(lines, addr, binary_path=binary_path)
        payload["ok"] = True
        payload["mapping_path"] = mapping_path
        if binary_path:
            payload["binary_path"] = binary_path
        return payload

    if name == "decompile_function":
        from backends.static.decompile.decompile import decompile_function

        binary_path = _binary_path_from(args)
        addr = _required_string(args, "addr")
        func_name = str(args.get("func_name", "") or "")
        decompiler = str(args.get("decompiler", "") or "")
        return _ensure_ok(
            decompile_function(
                binary_path,
                addr,
                func_name=func_name,
                decompiler=decompiler,
            )
        )

    if name == "decompile_binary":
        from backends.static.decompile.decompile import decompile_binary

        binary_path = _binary_path_from(args)
        decompiler = str(args.get("decompiler", "") or "")
        return _ensure_ok(decompile_binary(binary_path, decompiler=decompiler))

    if name == "disassemble":
        binary_path = _binary_path_from(args)
        addr = args.get("addr")
        addr_value = (
            str(addr).strip() if isinstance(addr, str) and addr.strip() else None
        )
        max_lines = _parse_int_arg(args, "max_lines", 400, minimum=1)
        return _disassemble_for_mcp(binary_path, addr=addr_value, max_lines=max_lines)

    if name == "discover_functions":
        from backends.static.binary.symbols import extract_symbols
        from backends.static.disasm.discover_functions import discover_functions

        mapping_path = _mapping_path_from(args)
        lines, mapping_binary = _load_mapping_lines(mapping_path)
        binary_path = (
            _binary_path_from(args) if "binary_path" in args else mapping_binary
        )
        known_addrs: set[str] = set()
        if binary_path:
            symbols = extract_symbols(binary_path, defined_only=False)
            known_addrs = {
                str(s.get("addr", "")).strip()
                for s in symbols
                if isinstance(s, dict) and str(s.get("addr", "")).strip()
            }
        functions = discover_functions(
            lines,
            known_addrs=known_addrs,
            binary_path=binary_path,
        )
        return {
            "ok": True,
            "mapping_path": mapping_path,
            "binary_path": binary_path,
            "functions": functions,
        }

    if name == "extract_dwarf":
        from backends.static.binary.dwarf import extract_dwarf_info

        return _ensure_ok(extract_dwarf_info(_binary_path_from(args)))

    if name == "analyze_entropy":
        from backends.static.binary.entropy import entropy_of_file, high_entropy_regions

        binary_path = _binary_path_from(args)
        threshold = _parse_float_arg(args, "threshold", 7.0)
        window = _parse_int_arg(args, "window", 256, minimum=1)
        payload = entropy_of_file(binary_path)
        payload["high_entropy_regions"] = high_entropy_regions(
            binary_path,
            threshold=threshold,
            window=window,
        )
        return _ensure_ok(payload)

    if name == "export_results":
        from backends.static import export as export_mod
        from backends.static.binary.symbols import extract_symbols
        from backends.static.disasm.cfg import build_cfg, build_cfg_for_function
        from backends.static.disasm.xrefs import build_xref_map
        from backends.static.search.strings import extract_strings

        kind = _required_string(args, "kind").lower()
        output_path = _required_string(args, "output_path")
        data = args.get("data")

        if kind in {"symbols_csv", "symbols"}:
            if data is None:
                payload = extract_symbols(_binary_path_from(args), defined_only=False)
            elif isinstance(data, dict):
                payload = data.get("symbols", [])
            else:
                payload = data
            count = export_mod.export_symbols_csv(payload or [], output_path)
            return {
                "ok": True,
                "kind": "symbols_csv",
                "output_path": output_path,
                "written": count,
            }

        if kind in {"strings_csv", "strings"}:
            if data is None:
                payload = extract_strings(_binary_path_from(args))
            elif isinstance(data, dict):
                payload = data.get("strings", [])
            else:
                payload = data
            count = export_mod.export_strings_csv(payload or [], output_path)
            return {
                "ok": True,
                "kind": "strings_csv",
                "output_path": output_path,
                "written": count,
            }

        if kind in {"xrefs_json", "xrefs"}:
            if data is None:
                mapping_path = _mapping_path_from(args)
                lines, mapping_binary = _load_mapping_lines(mapping_path)
                binary_path = (
                    _binary_path_from(args) if "binary_path" in args else mapping_binary
                )
                payload = build_xref_map(lines, binary_path=binary_path)
            else:
                payload = data
            count = export_mod.export_xrefs_json(payload or {}, output_path)
            return {
                "ok": True,
                "kind": "xrefs_json",
                "output_path": output_path,
                "written": count,
            }

        if kind in {"cfg_dot", "cfg"}:
            if data is None:
                mapping_path = _mapping_path_from(args)
                lines, mapping_binary = _load_mapping_lines(mapping_path)
                binary_path = (
                    _binary_path_from(args) if "binary_path" in args else mapping_binary
                )
                addr = args.get("addr")
                if isinstance(addr, str) and addr.strip():
                    payload = build_cfg_for_function(
                        lines, addr.strip(), binary_path=binary_path
                    )
                else:
                    payload = build_cfg(lines, binary_path=binary_path)
            else:
                payload = data
            graph_name = str(args.get("graph_name", "CFG") or "CFG")
            count = export_mod.export_cfg_dot(
                payload or {}, output_path, graph_name=graph_name
            )
            return {
                "ok": True,
                "kind": "cfg_dot",
                "output_path": output_path,
                "written": count,
            }

        raise ValueError(
            "Invalid kind. Expected one of: symbols_csv, strings_csv, xrefs_json, cfg_dot"
        )

    if name == "get_binary_info":
        from backends.static.binary.headers import extract_binary_info

        return _ensure_ok(extract_binary_info(_binary_path_from(args)))

    if name == "hex_dump":
        from backends.static.search.hex_view import hex_dump

        binary_path = _binary_path_from(args)
        offset = _parse_offset(args.get("offset", 0))
        length = _parse_int_arg(args, "length", 512, minimum=1)
        return _ensure_ok(hex_dump(binary_path, offset=offset, length=length))

    if name == "find_import_callsites":
        from backends.static.disasm.import_xrefs import find_callsites

        binary_path = _binary_path_from(args)
        function = _required_string(args, "function")
        return _ensure_ok(find_callsites(binary_path, function))

    if name == "analyze_imports":
        from backends.static.binary.imports_analysis import analyze_imports

        return _ensure_ok(analyze_imports(_binary_path_from(args)))

    if name == "offset_to_vaddr":
        from backends.static.binary.offset_to_vaddr import offset_to_vaddr

        binary_path = _binary_path_from(args)
        file_offset = _parse_offset(args.get("offset"))
        vaddr = offset_to_vaddr(binary_path, file_offset)
        return {
            "ok": True,
            "file_offset": file_offset,
            "vaddr": f"0x{vaddr:x}" if isinstance(vaddr, int) else None,
        }

    if name == "execute_script":
        from backends.static.repl.repl import execute_script

        code = _required_string(args, "code")
        binary = args.get("binary_path", args.get("binary"))
        binary_path = (
            _binary_path_from(args)
            if isinstance(binary, str) and binary.strip()
            else str(binary or "")
        )
        timeout = _parse_int_arg(args, "timeout", 30, minimum=1)
        return _ensure_ok(execute_script(code, binary_path, timeout=timeout))

    if name == "rules_list":
        from backends.static.rules.rules_manager import RulesManager

        mgr = RulesManager(ROOT)
        return {"ok": True, "rules": mgr.list_rules()}

    if name == "rules_toggle":
        from backends.static.rules.rules_manager import RulesManager

        rule_id = _required_string(args, "rule_id")
        enabled = args.get("enabled")
        if not isinstance(enabled, bool):
            raise ValueError("Invalid parameter: enabled must be a boolean")
        mgr = RulesManager(ROOT)
        mgr.toggle_rule(rule_id, enabled)
        return {"ok": True, "rule_id": rule_id, "enabled": enabled}

    if name == "rules_add":
        from backends.static.rules.rules_manager import RulesManager

        mgr = RulesManager(ROOT)
        rule_id = mgr.add_user_rule(
            _required_string(args, "name"),
            _required_string(args, "content"),
            _required_string(args, "type"),
        )
        return {"ok": True, "rule_id": rule_id}

    if name == "rules_delete":
        from backends.static.rules.rules_manager import RulesManager

        rule_id = _required_string(args, "rule_id")
        mgr = RulesManager(ROOT)
        mgr.delete_user_rule(rule_id)
        return {"ok": True, "rule_id": rule_id}

    if name == "search_binary":
        from backends.static.search.search import search_in_binary

        binary_path = _binary_path_from(args)
        pattern = _required_string(args, "pattern")
        mode = str(args.get("mode", "text") or "text")
        section = str(args.get("section", "") or "").strip() or None
        results = search_in_binary(
            binary_path,
            pattern,
            mode=mode,
            section=section,
        )
        return {"ok": True, "count": len(results), "results": results}

    if name == "get_sections":
        from backends.static.binary.sections import extract_sections

        return {"ok": True, "sections": extract_sections(_binary_path_from(args))}

    if name == "analyze_stack_frame":
        from backends.static.disasm.stack_frame import analyse_stack_frame

        binary_path = _binary_path_from(args)
        addr = _required_string(args, "addr")
        func_addr = _parse_offset(addr)
        return _ensure_ok(analyse_stack_frame(binary_path, func_addr))

    if name == "extract_strings":
        from backends.static.search.strings import extract_strings

        binary_path = _binary_path_from(args)
        min_len = _parse_int_arg(args, "min_len", 4, minimum=1)
        encoding = str(args.get("encoding", "auto") or "auto")
        section = str(args.get("section", "") or "").strip() or None
        values = extract_strings(
            binary_path,
            min_len=min_len,
            encoding=encoding,
            section=section,
        )
        return {"ok": True, "strings": values}

    if name == "get_symbols":
        binary_path = _binary_path_from(args)
        include_all = bool(args.get("all", False))
        syms = _extract_symbols(binary_path, defined_only=not include_all)
        payload = {"ok": True, "symbols": syms}
        return _ensure_ok(payload)

    if name == "get_xrefs":
        from backends.static.disasm.xrefs import (
            build_xref_map,
            extract_xrefs,
            extract_xrefs_from_addr,
        )

        mode = str(args.get("mode", "to") or "to").strip().lower()
        addr = _required_string(args, "addr")
        mapping_path = _mapping_path_from(args)
        lines, mapping_binary = _load_mapping_lines(mapping_path)
        binary_path = (
            _binary_path_from(args) if "binary_path" in args else mapping_binary
        )
        if mode == "map":
            return {
                "ok": True,
                "addr": addr,
                "mode": "map",
                "xref_map": build_xref_map(lines, binary_path=binary_path),
            }
        if mode == "from":
            return {
                "ok": True,
                "addr": addr,
                "mode": "from",
                "targets": extract_xrefs_from_addr(lines, addr),
            }
        refs = extract_xrefs(lines, addr, binary_path=binary_path)
        return {"ok": True, "addr": addr, "mode": "to", "refs": refs}

    if name == "find_files":
        query = _required_string(args, "query")
        limit = _parse_int_arg(args, "limit", 20, minimum=1)
        return _find_files(query, limit=limit)

    if name == "ai_providers_list":
        return {"ok": True, **list_providers()}

    if name == "ai_providers_set":
        provider = args.get("provider", "")
        api_key = args.get("api_key", "")
        model = args.get("model")
        return set_provider_configuration(provider, api_key, model)

    if name == "ai_analyze":
        provider = args.get("provider") or os.environ.get(
            "POF_DEFAULT_AI_PROVIDER", "ollama"
        )
        model = args.get("model")
        try:
            response = call_provider(
                provider, args.get("prompt", ""), args.get("context", ""), model
            )
            return {
                "ok": True,
                "provider": provider,
                "model": model,
                "response": response,
            }
        except Exception as exc:
            return {"ok": False, "error": str(exc)}

    # Dynamic backend tool dispatch
    if (
        "." in name
        and name not in _STATIC_TOOL_NAMES
        and not name.startswith("plugin.")
    ):
        return _dispatch_dynamic_tool(name, args)

    raise KeyError(f"Unknown tool: {name}")


def handle_request(request: dict[str, Any]) -> dict[str, Any] | None:
    """Handle one JSON-RPC request.

    Returns:
      - response dict for standard requests
      - None for notifications
    """
    if not isinstance(request, dict):
        return _jsonrpc_error(None, JSONRPC_INVALID_REQUEST, "Invalid Request")

    request_id = request.get("id")
    method = request.get("method")
    params = _normalize_params(request.get("params"))

    if not isinstance(method, str) or not method:
        return _jsonrpc_error(request_id, JSONRPC_INVALID_REQUEST, "Invalid Request")

    # Notifications do not require a response.
    is_notification = "id" not in request

    if method == "notifications/initialized":
        return None

    if method == "initialize":
        protocol = params.get("protocolVersion")
        protocol_version = (
            protocol
            if isinstance(protocol, str) and protocol
            else DEFAULT_PROTOCOL_VERSION
        )
        result = {
            "protocolVersion": protocol_version,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }
        memory_context = _load_mcp_memory_context()
        if memory_context:
            result["instructions"] = (
                f"Project MCP context from docs/mcp/memory.md:\n\n{memory_context}"
            )
        if is_notification:
            return None
        return _jsonrpc_success(request_id, result)

    if method == "tools/list":
        if is_notification:
            return None
        plugin_tools = _dynamic_plugin_tools()
        return _jsonrpc_success(
            request_id, {"tools": TOOLS + AI_TOOLS + DYNAMIC_TOOLS + plugin_tools}
        )

    if method == "tools/call":
        name = params.get("name")
        arguments = _normalize_params(params.get("arguments"))
        if not isinstance(name, str) or not name.strip():
            if is_notification:
                return None
            return _jsonrpc_error(
                request_id,
                JSONRPC_INVALID_PARAMS,
                "Invalid params",
                {"reason": "Missing tool name"},
            )
        try:
            resolved_name = _resolve_tool_name(name.strip())
            plugin_routes = _dynamic_plugin_tool_routes()
            if name.strip() in plugin_routes:
                route = plugin_routes[name.strip()]
                payload = _call_tool(
                    "plugin_invoke",
                    {
                        **(
                            {"feature_id": route["feature_id"]}
                            if route.get("feature_id")
                            else {"command_id": route["command_id"]}
                        ),
                        "payload": arguments.get("payload", {}),
                    },
                )
            elif resolved_name in plugin_routes:
                route = plugin_routes[resolved_name]
                payload = _call_tool(
                    "plugin_invoke",
                    {
                        **(
                            {"feature_id": route["feature_id"]}
                            if route.get("feature_id")
                            else {"command_id": route["command_id"]}
                        ),
                        "payload": arguments.get("payload", {}),
                    },
                )
            else:
                payload = _call_tool(resolved_name, arguments)
            is_error = bool(isinstance(payload, dict) and payload.get("ok") is False)
            result = _tool_result(payload, is_error=is_error)
        except (ValueError, KeyError) as exc:
            result = _tool_result({"ok": False, "error": str(exc)}, is_error=True)
        except Exception as exc:  # pragma: no cover - defensive hardening
            LOGGER.exception("Unhandled tools/call error")
            result = _tool_result(
                {"ok": False, "error": f"Internal tool error: {exc}"},
                is_error=True,
            )
        if is_notification:
            return None
        return _jsonrpc_success(request_id, result)

    if is_notification:
        return None
    return _jsonrpc_error(
        request_id,
        JSONRPC_METHOD_NOT_FOUND,
        f"Method not found: {method}",
    )


def _read_message(stdin: Any) -> dict[str, Any] | None:
    """Read one framed JSON-RPC message from stdin.

    MCP stdio framing uses HTTP-like headers:
        Content-Length: N

        {json payload}
    """
    header_line = stdin.readline()
    if header_line == b"":
        return None

    # Skip accidental blank lines.
    while header_line in (b"\r\n", b"\n"):
        header_line = stdin.readline()
        if header_line == b"":
            return None

    # Fallback for line-delimited JSON (useful in local smoke tests).
    if header_line.lstrip().startswith(b"{"):
        try:
            return json.loads(header_line.decode("utf-8"))
        except json.JSONDecodeError as err:
            raise ValueError("Invalid JSON payload") from err

    headers: dict[str, str] = {}
    line = header_line
    while line not in (b"\r\n", b"\n", b""):
        try:
            key, value = line.decode("utf-8").split(":", 1)
        except ValueError as exc:
            raise ValueError(f"Invalid header line: {line!r}") from exc
        headers[key.strip().lower()] = value.strip()
        line = stdin.readline()

    raw_len = headers.get("content-length")
    if raw_len is None:
        raise ValueError("Missing Content-Length header")
    try:
        content_length = int(raw_len)
    except ValueError as exc:
        raise ValueError("Invalid Content-Length header") from exc
    if content_length <= 0:
        raise ValueError("Invalid Content-Length value")

    payload = stdin.read(content_length)
    if len(payload) != content_length:
        raise ValueError("Unexpected EOF while reading payload")
    try:
        decoded = payload.decode("utf-8")
        return json.loads(decoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("Invalid JSON payload") from exc


def _write_message(stdout: Any, message: dict[str, Any]) -> None:
    body = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    headers = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii")
    stdout.write(headers)
    stdout.write(body)
    stdout.flush()


def run_stdio_server() -> int:
    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    while True:
        try:
            message = _read_message(stdin)
        except ValueError as exc:
            error = _jsonrpc_error(None, JSONRPC_PARSE_ERROR, "Parse error", str(exc))
            _write_message(stdout, error)
            continue

        if message is None:
            return 0

        response = handle_request(message)
        if response is not None:
            _write_message(stdout, response)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pile ou Face MCP server")
    parser.add_argument(
        "--transport",
        choices=["stdio"],
        default="stdio",
        help="MCP transport mode (current: stdio only).",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logs on stderr.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    )
    if args.transport == "stdio":
        return run_stdio_server()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
