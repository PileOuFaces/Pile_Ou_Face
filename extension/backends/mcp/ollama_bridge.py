#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Bridge between Ollama tool-calling and the local MCP server.

This script allows a local Ollama model to call MCP tools exposed by:
    backends/mcp/server.py
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import subprocess
import sys
from collections.abc import Callable
from typing import Any
from urllib import error, request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_PROTOCOL_VERSION = "2024-11-05"
DEFAULT_MEMORY_PATH = os.path.join(ROOT, "docs", "mcp", "memory.md")
LEGACY_DOCS_MEMORY_PATH = os.path.join(ROOT, "docs", "mcp", "docs", "memory.md")
LEGACY_ROOT_MEMORY_PATH = os.path.join(ROOT, "memory.md")

DEFAULT_DISASM_MAX_LINES = 120
DEFAULT_MEMORY_MAX_CHARS = 6000
KNOWN_BINARY_EXTENSIONS = (
    ".elf",
    ".exe",
    ".bin",
    ".dll",
    ".so",
    ".dylib",
    ".macho",
)

TOOL_NAME_ALIASES: dict[str, tuple[str, ...]] = {
    "strings": ("extract_strings",),
    "string": ("extract_strings",),
    "symbols": ("get_symbols",),
    "symboles": ("get_symbols",),
    "symbol": ("get_symbols",),
    "disasm": ("disassemble",),
    "asm": ("disassemble",),
    "xref": ("get_xrefs",),
    "xrefs": ("get_xrefs",),
    "sections": ("get_sections",),
    "imports": ("analyze_imports",),
    "vulns": ("find_vulnerabilities", "plugin.audit.vulns.run"),
    "vulns_scan": ("find_vulnerabilities", "plugin.audit.vulns.run"),
    "rop": ("find_rop_gadgets", "plugin.offensive.rop.run"),
    "behavior": ("analyze_behavior", "plugin.malware.behavior.run"),
    "anti_analysis": ("detect_anti_analysis", "plugin.malware.anti_analysis.run"),
    "capa": ("capa_scan", "plugin.malware.capa.run"),
    "yara": ("yara_scan", "plugin.malware.yara.run"),
    "callgraph": ("build_call_graph",),
    "call_graph": ("build_call_graph",),
    "cfg_function": ("build_cfg_for_function",),
    "binary_info": ("get_binary_info",),
    "typed_data": ("typed_data.get_typed_data",),
    "pe_resources": ("pe_resources.get_pe_resources",),
    "calling_convention": ("calling_convention.analyze_calling_conventions",),
    "function_radar": ("function_radar.build_function_radar",),
    "analysis_index": ("analysis_index.build_analysis_index",),
    "structs": ("structs.list_struct_store",),
    "struct_list": ("structs.list_struct_store",),
    "struct_save": ("structs.save_struct_source",),
    "struct_load": ("structs.load_struct_store",),
    "patch": ("binary_patch.patch_bytes",),
}


class OllamaToolsUnsupportedError(RuntimeError):
    """Raised when the Ollama model does not support tool calling."""


class McpStdioClient:
    """Minimal JSON-RPC client over MCP stdio framing."""

    def __init__(self, cmd: list[str], cwd: str, timeout_s: int = 60) -> None:
        self.cmd = cmd
        self.cwd = cwd
        self.timeout_s = timeout_s
        self.proc: subprocess.Popen[bytes] | None = None
        self._next_id = 1

    def start(self) -> None:
        if self.proc is not None:
            return
        self.proc = subprocess.Popen(
            self.cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=self.cwd,
        )

    def close(self) -> None:
        if self.proc is None:
            return
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        self.proc = None

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        payload: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)

    def request(
        self, method: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        payload: dict[str, Any] = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            payload["params"] = params
        self._write_message(payload)
        response = self._read_message()
        if response.get("id") != req_id:
            raise RuntimeError(
                f"Unexpected response id: {response.get('id')} != {req_id}"
            )
        if "error" in response:
            err = response["error"]
            raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")
        return response.get("result", {})

    def _pipes(self) -> tuple[Any, Any]:
        if self.proc is None or self.proc.stdin is None or self.proc.stdout is None:
            raise RuntimeError("MCP process is not running")
        return self.proc.stdin, self.proc.stdout

    def _write_message(self, message: dict[str, Any]) -> None:
        stdin, _ = self._pipes()
        body = json.dumps(message, ensure_ascii=True, separators=(",", ":")).encode(
            "utf-8"
        )
        frame = f"Content-Length: {len(body)}\r\n\r\n".encode("ascii") + body
        stdin.write(frame)
        stdin.flush()

    def _read_message(self) -> dict[str, Any]:
        _, stdout = self._pipes()
        header = b""
        while b"\r\n\r\n" not in header:
            chunk = stdout.read(1)
            if not chunk:
                raise RuntimeError("EOF while reading MCP headers")
            header += chunk

        head, _ = header.split(b"\r\n\r\n", 1)
        content_length = None
        for line in head.split(b"\r\n"):
            if line.lower().startswith(b"content-length:"):
                content_length = int(line.split(b":", 1)[1].strip())
                break
        if content_length is None:
            raise RuntimeError("MCP response missing Content-Length")

        payload = stdout.read(content_length)
        if len(payload) != content_length:
            raise RuntimeError("Unexpected EOF while reading MCP payload")
        try:
            return json.loads(payload.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise RuntimeError("Invalid JSON in MCP response") from exc


def mcp_tool_to_ollama_tool(mcp_tool: dict[str, Any]) -> dict[str, Any]:
    """Convert MCP tool schema to Ollama function-tool schema."""
    name = str(mcp_tool.get("name", ""))
    desc = str(mcp_tool.get("description", ""))
    params = mcp_tool.get("inputSchema")
    if not isinstance(params, dict):
        params = {"type": "object", "properties": {}, "additionalProperties": True}
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": desc,
            "parameters": params,
        },
    }


def _coerce_tool_arguments(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        value = raw.strip()
        if not value:
            return {}
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Tool arguments are not valid JSON: {value}") from exc
        if not isinstance(parsed, dict):
            raise ValueError("Tool arguments JSON must decode to an object")
        return parsed
    return {}


def _looks_like_noop_response(text: str) -> bool:
    t = text.strip().lower()
    if not t:
        return True
    direct_hints = [
        "please provide a request",
        "please provide a file",
        "please provide the file",
        "ready to assist",
        "provide a task",
        "i still need a file",
        "need a file or",
    ]
    if any(h in t for h in direct_hints):
        return True

    generic_patterns = [
        r"\bplease provide\b.*\b(file|request|task)\b",
        r"\b(i\s+)?need\b.*\b(file|path|request)\b",
    ]
    return any(re.search(pat, t) is not None for pat in generic_patterns)


def _prompt_likely_needs_tools(prompt: str) -> bool:
    p = prompt.lower()
    if _detect_tool_intent(p):
        return True
    return any(
        token in p
        for token in [
            ".elf",
            ".exe",
            ".bin",
            ".dll",
            ".so",
            ".dylib",
            "xrefs",
            "analyse",
            "analyze",
            "asm",
            "mcp",
            "rapport",
            "report",
            "imports",
            "sections",
            "entropie",
            "entropy",
            "header",
            "vuln",
            "packer",
        ]
    )


def _extract_user_request(prompt: str) -> str:
    """Return the actual user request, excluding host-injected passive context."""
    marker = "Demande utilisateur :"
    if marker in prompt:
        return prompt.rsplit(marker, 1)[1].strip()
    conversation_marker = "Utilisateur:"
    if conversation_marker in prompt:
        tail = prompt.rsplit(conversation_marker, 1)[1]
        return tail.split("\nAssistant:", 1)[0].strip()
    return prompt.strip()


def _strip_passive_binary_context(prompt: str) -> str:
    """Keep conversation context while removing unrelated binary metadata."""
    passive_marker = "Contexte binaire passif"
    if passive_marker not in prompt:
        return prompt
    conversation_marker = "Contexte de conversation à respecter :"
    if conversation_marker in prompt:
        return prompt[prompt.index(conversation_marker) :].strip()
    return _extract_user_request(prompt)


def _detect_tool_intent(prompt: str) -> str | None:
    p = prompt.lower()
    disasm_tokens = (
        "disassemble",
        "disasm",
        "desassemble",
        "dessasemble",
        "désassemble",
        "desassemblage",
        "désassemblage",
        "assembleur",
        "assembly",
        "code asm",
    )
    if any(token in p for token in disasm_tokens) or re.search(r"\basm\b", p):
        return "disassemble"

    symbol_tokens = (
        "symbol",
        "symbole",
    )
    if any(token in p for token in symbol_tokens):
        return "symbols"

    strings_tokens = (
        "strings",
        "chaine",
        "chaîne",
    )
    if any(token in p for token in strings_tokens):
        return "strings"

    imports_tokens = (
        "import",
        "section",
        "header",
        "entete",
        "entête",
        "entropie",
        "entropy",
        "info",
        "rapport",
        "report",
        "vuln",
        "packer",
    )
    if any(token in p for token in imports_tokens):
        return "binary_info"

    return None


def _extract_binary_candidate(prompt: str) -> str | None:
    pattern = re.compile(
        r"([A-Za-z0-9_./\\-]+\.(?:elf|exe|bin|dll|so|dylib|macho|mach-o))",
        re.IGNORECASE,
    )
    match = pattern.search(prompt)
    if not match:
        return None
    return match.group(1)


def _extract_filename_hints(prompt: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_./\\-]{3,}", prompt)
    stopwords = {
        "analyse",
        "analysis",
        "disassemble",
        "desassemble",
        "dessasemble",
        "disasm",
        "symbols",
        "symboles",
        "strings",
        "mcp",
        "outil",
        "tools",
        "code",
    }
    hints: list[str] = []
    for token in tokens:
        t = token.strip().strip(".,;:!?\"'()[]{}")
        if not t:
            continue
        if t.lower() in stopwords:
            continue
        hints.append(t)
    seen = set()
    unique: list[str] = []
    for hint in hints:
        if hint in seen:
            continue
        seen.add(hint)
        unique.append(hint)
    return unique


def _select_best_file_from_find_results(
    query: str, results: list[dict[str, Any]]
) -> str | None:
    if not results:
        return None
    query_low = query.lower()
    has_ext = "." in os.path.basename(query_low)

    scored: list[tuple[int, str]] = []
    for item in results:
        path = str(item.get("path", "")).strip()
        if not path:
            continue
        rel = str(item.get("relative_path", "")).strip()
        basename = os.path.basename(path).lower()
        rel_low = rel.lower()
        ext = os.path.splitext(basename)[1]
        is_binary_like = ext in KNOWN_BINARY_EXTENSIONS
        score = 100
        if has_ext and basename == os.path.basename(query_low):
            score = 0
        elif is_binary_like and query_low in basename:
            score = 5
        elif is_binary_like and query_low in rel_low:
            score = 10
        elif is_binary_like:
            score = 20
        elif query_low in basename:
            score = 30
        if "/examples/" in path.replace("\\", "/"):
            score -= 1
        scored.append((score, path))

    if not scored:
        return None
    scored.sort(key=lambda item: (item[0], len(item[1]), item[1]))
    return scored[0][1]


def _resolve_binary_from_prompt(client: McpStdioClient, prompt: str) -> str | None:
    direct = _extract_binary_candidate(prompt)
    if direct:
        return direct
    hints = _extract_filename_hints(prompt)
    if not hints:
        return None
    for hint in hints[:6]:
        try:
            find_result = client.request(
                "tools/call",
                {"name": "find_files", "arguments": {"query": hint, "limit": 12}},
            )
        except Exception:
            continue
        payload = find_result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            continue
        results = payload.get("results", [])
        if not isinstance(results, list):
            continue
        selected = _select_best_file_from_find_results(hint, results)
        if selected:
            return selected
    return None


def _normalize_tool_call_arguments(
    client: McpStdioClient, name: str, args: dict[str, Any], prompt: str
) -> dict[str, Any]:
    normalized = dict(args)
    needs_binary = name in {
        "disassemble",
        "get_symbols",
        "extract_strings",
        "get_binary_info",
        "get_sections",
        "get_xrefs",
        "discover_functions",
        "analyze_imports",
        "analyze_entropy",
        "hex_dump",
        "extract_dwarf",
        "search_binary",
        "analyze_stack_frame",
        "get_exports",
        "offset_to_vaddr",
        "build_call_graph",
        "build_cfg",
        "build_cfg_for_function",
        "decompile_function",
        "decompile_binary",
        "typed_data.get_typed_data",
        "pe_resources.get_pe_resources",
        "calling_convention.analyze_calling_conventions",
        "function_radar.build_function_radar",
        "analysis_index.build_analysis_index",
        "analyze_behavior",
        "find_vulnerabilities",
        "find_rop_gadgets",
        "deobfuscate_strings",
        "plugin.audit.vulns.run",
        "plugin.audit.taint.run",
        "plugin.malware.behavior.run",
        "plugin.malware.anti_analysis.run",
        "plugin.malware.capa.run",
        "plugin.malware.yara.run",
        "plugin.malware.deobfuscate.run",
        "plugin.offensive.rop.run",
    }
    if needs_binary:
        raw_binary = normalized.get("binary_path", normalized.get("binary"))
        if not isinstance(raw_binary, str) or not raw_binary.strip():
            inferred = _resolve_binary_from_prompt(client, prompt)
            if inferred:
                normalized["binary_path"] = inferred
    if name == "disassemble":
        raw_max = normalized.get("max_lines")
        try:
            max_lines = (
                int(raw_max) if raw_max is not None else DEFAULT_DISASM_MAX_LINES
            )
        except (TypeError, ValueError):
            max_lines = DEFAULT_DISASM_MAX_LINES
        if max_lines <= 0:
            max_lines = DEFAULT_DISASM_MAX_LINES
        normalized["max_lines"] = max_lines
    return normalized


def _resolve_requested_tool_name(name: str, available_tool_names: set[str]) -> str:
    raw = name.strip()
    if not raw:
        return raw
    if raw in available_tool_names:
        return raw
    candidate = raw.lower().replace("-", "_")
    if candidate in available_tool_names:
        return candidate
    aliases = TOOL_NAME_ALIASES.get(candidate, ())
    for alias in aliases:
        if alias in available_tool_names:
            return alias
    return raw


def _select_mcp_tools_for_prompt(
    mcp_tools: list[dict[str, Any]], prompt: str
) -> list[dict[str, Any]]:
    if not _prompt_likely_needs_tools(prompt):
        return []
    intent = _detect_tool_intent(prompt)
    if not intent:
        return mcp_tools
    names_by_intent: dict[str, set[str]] = {
        "disassemble": {"disassemble", "find_files", "get_binary_info", "get_symbols"},
        "symbols": {"get_symbols", "find_files", "get_binary_info", "disassemble"},
        "strings": {"extract_strings", "find_files", "get_binary_info", "disassemble"},
    }
    allowed = names_by_intent.get(intent, set())
    if not allowed:
        return mcp_tools
    selected = [
        tool
        for tool in mcp_tools
        if isinstance(tool, dict) and str(tool.get("name", "")) in allowed
    ]
    return selected or mcp_tools


def _auto_tool_fallback(client: McpStdioClient, prompt: str) -> str | None:
    intent = _detect_tool_intent(prompt)
    binary = _resolve_binary_from_prompt(client, prompt)
    if not binary:
        return None

    if intent == "disassemble":
        result = client.request(
            "tools/call",
            {
                "name": "disassemble",
                "arguments": {"binary_path": binary, "max_lines": 60},
            },
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        lines = payload.get("lines", [])
        if not isinstance(lines, list):
            lines = []
        head = lines[:8]
        out = [
            (
                f"Désassemblage de {binary}: {payload.get('count', len(lines))} instructions "
                f"(aperçu {len(head)})."
            )
        ]
        for idx, line in enumerate(head, start=1):
            if not isinstance(line, dict):
                continue
            addr = str(line.get("addr", "")).strip()
            text = str(line.get("text", "")).strip()
            out.append(f"{idx}. {addr} {text}".strip())
        return "\n".join(out)

    if intent == "symbols":
        result = client.request(
            "tools/call",
            {"name": "get_symbols", "arguments": {"binary_path": binary}},
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        symbols = payload.get("symbols", [])
        if not isinstance(symbols, list):
            symbols = []
        head = symbols[:12]
        out = [f"Symboles pour {binary}: {len(symbols)} entrées (aperçu {len(head)})."]
        for idx, item in enumerate(head, start=1):
            if not isinstance(item, dict):
                continue
            name = item.get("name", "")
            addr = item.get("addr", "")
            out.append(f"{idx}. {name} {addr}".strip())
        return "\n".join(out)

    if intent == "strings":
        result = client.request(
            "tools/call",
            {"name": "extract_strings", "arguments": {"binary_path": binary}},
        )
        payload = result.get("structuredContent", {})
        if not isinstance(payload, dict) or not payload.get("ok"):
            return None
        strings = payload.get("strings", [])
        if not isinstance(strings, list):
            strings = []
        head = strings[:12]
        out = [f"Strings pour {binary}: {len(strings)} entrées (aperçu {len(head)})."]
        for idx, item in enumerate(head, start=1):
            out.append(f"{idx}. {str(item)}")
        return "\n".join(out)

    result = client.request(
        "tools/call",
        {"name": "get_binary_info", "arguments": {"binary_path": binary}},
    )
    payload = result.get("structuredContent", {})
    if not isinstance(payload, dict) or not payload.get("ok"):
        return None
    fmt = payload.get("format") or payload.get("type") or "unknown"
    arch = payload.get("arch") or payload.get("architecture") or "unknown"
    bits = payload.get("bits")
    bits_text = f"{bits}-bit" if bits is not None else "bits inconnus"
    return (
        f"Fichier pris en compte: {binary}. "
        f"Format: {fmt}. Architecture: {arch} ({bits_text}). "
        "Tu peux demander explicitement: disassemble, get_symbols ou extract_strings."
    )


def _load_memory_context(
    memory_path: str | None, max_chars: int = DEFAULT_MEMORY_MAX_CHARS
) -> str:
    candidates: list[str] = []
    if isinstance(memory_path, str) and memory_path.strip():
        candidates.append(memory_path.strip())
    for fallback in (
        DEFAULT_MEMORY_PATH,
        LEGACY_DOCS_MEMORY_PATH,
        LEGACY_ROOT_MEMORY_PATH,
    ):
        if fallback not in candidates:
            candidates.append(fallback)

    for path in candidates:
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


_DEFAULT_SYSTEM_PROMPT = """\
You are an expert binary reverse engineering assistant. You have access to a full static analysis toolchain. \
Always call tools to gather real data before answering — never guess or hallucinate values.

## Workflow
1. Read what the user wants.
2. Pick the most specific tool for the job (see rules below).
3. Chain tools when needed to build a complete picture.
4. Synthesize the results into a clear, structured answer.

## Tool selection rules

### Binary overview
- Format, arch, entry point, stripped? → `get_binary_info`
- Sections list (.text, .data, .rodata, …) → `get_sections`
- Imports / dynamic dependencies → `analyze_imports`
- Exports → `get_exports`
- Symbols / function names + addresses → `get_symbols`

### Code analysis
- Disassemble instructions → `disassemble` (add `addr` to target a function)
- Discover all function boundaries → `discover_functions`
- Calling conventions per function (System V, stdcall…) → `calling_convention.analyze_calling_conventions`
- Control flow graph → `build_cfg` or `build_cfg_for_function`
- Call graph → `build_call_graph`
- Cross-references → `get_xrefs`
- Import callsites → `find_import_callsites`
- Stack frame layout → `analyze_stack_frame`
- Function complexity / hotspots / risk scores → `function_radar.build_function_radar`
- DWARF debug info → `extract_dwarf`

### Data analysis
- Typed view of .data/.rodata (pointers, ints, floats, strings) → `typed_data.get_typed_data` with `section_name`
  → DO NOT use extract_strings or disassemble for section data inspection
- Raw strings in the whole binary → `extract_strings`
- Hex dump at offset → `hex_dump`
- Entropy / packed regions → `analyze_entropy`
- Pattern / byte search → `search_binary`
- PE resources (icons, manifests, version info, dialogs) → `pe_resources.get_pe_resources`

### Structs & type system
- List saved structs → `structs.list_struct_store`
- Load full struct definitions → `structs.load_struct_store`
- Save new or updated structs (C syntax: typedef struct/union/enum) → `structs.save_struct_source`
- Parse C struct source without saving → `structs.parse_struct_definitions`
- Compute struct field offsets and sizes → `structs.compute_struct_layout`
- Apply a struct to a binary section → `typed_data.get_typed_data` with `struct_name`

### Decompilation
- Decompile one function → `decompile_function` (requires `binary_path` + `addr`)
- Decompile full binary → `decompile_binary`

### Patching
- Patch bytes in place → `binary_patch.patch_bytes`
- Patch with undo support → `patch_manager.apply_patch`
- List patches → `patch_manager.list_patches`
- Revert patch → `patch_manager.revert_patch`

### Plugins & AI
- List installed plugins and their commands → `plugins_list`
- Invoke a plugin command → `plugin_invoke`
- Run AI analysis with a different provider → `ai_analyze`

### Workspace
- Find files → `find_files`
- Execute custom Python analysis → `execute_script`

## Response format
- Use markdown tables for addresses, symbols, and structured data.
- Group findings by category (code, data, imports, risks).
- For malware / suspicious binaries: highlight IOCs (URLs, keys, shell commands, C2 indicators) in a dedicated section.
- Always state which tool produced each piece of data.
- If a tool returns an error, explain what failed and suggest an alternative approach.
"""


def _build_system_prompt(
    base_prompt: str | None, memory_path: str | None
) -> str | None:
    base = (base_prompt or _DEFAULT_SYSTEM_PROMPT).strip()
    memory = _load_memory_context(memory_path)
    if not memory:
        return base or None
    memory_block = f"Additional project context from docs/mcp/memory.md:\n{memory}"
    return f"{base}\n\n{memory_block}"


def _read_http_error_body(exc: error.HTTPError) -> str:
    """Extract a readable message from an Ollama HTTPError body."""
    try:
        body = json.loads(exc.read())
        return str(body.get("error") or body)
    except Exception:
        return str(exc.reason)


def _ollama_chat(
    base_url: str,
    model: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    timeout_s: int,
    on_token: Callable[[str], None] | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    use_stream = on_token is not None
    payload: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "stream": use_stream,
    }
    if tools:
        payload["tools"] = tools
    if generation_options:
        payload["options"] = generation_options
    url = base_url.rstrip("/") + "/api/chat"
    req = request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=timeout_s) as resp:
            if not use_stream:
                raw = resp.read().decode("utf-8")
                try:
                    parsed = json.loads(raw)
                except json.JSONDecodeError as exc:
                    raise RuntimeError("Invalid JSON from Ollama /api/chat") from exc
                if not isinstance(parsed, dict):
                    raise RuntimeError("Unexpected Ollama response shape")
                if "error" in parsed:
                    raise RuntimeError(f"Ollama error: {parsed['error']}")
                return parsed
            # Streaming: parse NDJSON line by line
            full_content = ""
            final_tool_calls: list[dict[str, Any]] = []
            usage: dict[str, int] = {}
            try:
                for raw_line in resp:
                    line = raw_line.strip()
                    if not line:
                        continue
                    try:
                        chunk = json.loads(line.decode("utf-8"))
                    except json.JSONDecodeError:
                        continue
                    delta = chunk.get("message", {})
                    content = delta.get("content", "")
                    if content:
                        # Most Ollama models send deltas. A few send the complete
                        # response again in the final chunk, so only emit its
                        # missing suffix instead of duplicating prior content.
                        if chunk.get("done") and full_content:
                            if content.startswith(full_content):
                                content = content[len(full_content) :]
                            elif full_content.endswith(content):
                                content = ""
                        if content:
                            on_token(content)
                            full_content += content
                    if chunk.get("done"):
                        final_tool_calls = delta.get("tool_calls") or []
                        for key in ("prompt_eval_count", "eval_count"):
                            value = chunk.get(key)
                            if isinstance(value, int) and value >= 0:
                                usage[key] = value
                        break
            except OSError as exc:
                raise RuntimeError(f"Stream interrupted from Ollama: {exc}") from exc
            return {
                "message": {"content": full_content, "tool_calls": final_tool_calls},
                "usage": usage,
            }
    except error.HTTPError as exc:
        msg = _read_http_error_body(exc)
        if exc.code == 400 and "does not support tools" in msg:
            raise OllamaToolsUnsupportedError(msg) from None
        raise RuntimeError(
            f"Ollama rejected request (HTTP {exc.code}): {msg}"
        ) from None
    except error.URLError as exc:
        raise RuntimeError(f"Cannot reach Ollama at {url}: {exc.reason}") from None


# Public alias kept for backward compatibility and external callers.
ollama_chat = _ollama_chat


def run_agent_once(
    client: McpStdioClient,
    base_url: str,
    model: str,
    prompt: str,
    max_steps: int,
    timeout_s: int,
    system_prompt: str | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    user_request = _extract_user_request(prompt)
    needs_tools = _prompt_likely_needs_tools(user_request)
    model_prompt = prompt if needs_tools else _strip_passive_binary_context(prompt)
    tools_result = client.request("tools/list", {})
    mcp_tools = tools_result.get("tools", [])
    if not isinstance(mcp_tools, list):
        raise RuntimeError("MCP tools/list returned unexpected payload")
    selected_tools = _select_mcp_tools_for_prompt(
        [t for t in mcp_tools if isinstance(t, dict)],
        user_request,
    )
    ollama_tools = [mcp_tool_to_ollama_tool(t) for t in selected_tools]
    available_tool_names = {
        str(tool.get("name", "")).strip()
        for tool in selected_tools
        if isinstance(tool, dict) and str(tool.get("name", "")).strip()
    }

    messages: list[dict[str, Any]] = []
    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})
    messages.append({"role": "user", "content": model_prompt})

    tools_warning = ""
    last_content = ""
    retried_after_noop = False
    tool_calls_log: list[dict[str, Any]] = []
    _streamed_content: list[str] = []
    usage = {"prompt_tokens": 0, "completion_tokens": 0}
    request_usage = {"prompt_tokens": 0, "completion_tokens": 0}

    def _collect_usage(response_payload: dict[str, Any]) -> None:
        source = response_payload.get("usage", response_payload)
        if not isinstance(source, dict):
            return
        prompt_tokens = source.get("prompt_eval_count", source.get("prompt_tokens", 0))
        completion_tokens = source.get("eval_count", source.get("completion_tokens", 0))
        if isinstance(prompt_tokens, int) and prompt_tokens >= 0:
            usage["prompt_tokens"] = prompt_tokens
            request_usage["prompt_tokens"] += prompt_tokens
        if isinstance(completion_tokens, int) and completion_tokens >= 0:
            usage["completion_tokens"] = completion_tokens
            request_usage["completion_tokens"] += completion_tokens

    def _result(response_text: str) -> dict[str, Any]:
        return {
            "response": response_text,
            "tool_calls": tool_calls_log,
            "usage": {
                **usage,
                "total_tokens": usage["prompt_tokens"] + usage["completion_tokens"],
                "request_prompt_tokens": request_usage["prompt_tokens"],
                "request_completion_tokens": request_usage["completion_tokens"],
                "request_total_tokens": (
                    request_usage["prompt_tokens"] + request_usage["completion_tokens"]
                ),
            },
        }

    for _ in range(max_steps):

        def _on_token(chunk: str) -> None:
            _streamed_content.append(chunk)
            if on_event:
                on_event({"type": "token", "content": chunk})

        try:
            response = _ollama_chat(
                base_url,
                model,
                messages,
                ollama_tools,
                timeout_s,
                on_token=_on_token if on_event else None,
                **(
                    {"generation_options": generation_options}
                    if generation_options
                    else {}
                ),
            )
            _collect_usage(response)
            msg = response.get("message", {})
            tool_calls = msg.get("tool_calls") or []
            last_content = msg.get("content", "")

            # If response had tool_calls, streamed tokens were NOT the final answer.
            # Emit token_rollback so the frontend clears the streaming bubble.
            if tool_calls and _streamed_content and on_event:
                on_event({"type": "token_rollback"})
            _streamed_content.clear()
        except OllamaToolsUnsupportedError:
            # Model doesn't support tool calling — pre-fetch binary data via MCP
            # and inject it as context so the model can still answer about the file.
            _streamed_content.clear()
            ollama_tools = []
            prefetch = _auto_tool_fallback(client, prompt)
            if prefetch and messages and messages[-1].get("role") == "user":
                original = messages[-1]["content"]
                messages[-1] = {
                    "role": "user",
                    "content": (
                        f"[Données du fichier extraites via les outils MCP]\n{prefetch}\n\n"
                        f"{original}"
                    ),
                }
                tools_warning = (
                    f"[{model} ne supporte pas les outils MCP — "
                    "données pré-extraites automatiquement.]\n\n"
                )
            else:
                tools_warning = (
                    f"[Avertissement: {model} ne supporte pas les outils MCP. "
                    "Réponse sans données de fichier.]\n\n"
                )
            _streamed_content.clear()
            try:
                response = _ollama_chat(
                    base_url=base_url,
                    model=model,
                    messages=messages,
                    tools=[],
                    timeout_s=timeout_s,
                    on_token=_on_token if on_event else None,
                    **(
                        {"generation_options": generation_options}
                        if generation_options
                        else {}
                    ),
                )
                _collect_usage(response)
            except RuntimeError:
                # Streaming rejected (HTTP 500) — retry without streaming.
                # Emit the exact full response once; inventing word-by-word
                # chunks corrupts whitespace and adds artificial latency.
                _streamed_content.clear()
                response = _ollama_chat(
                    base_url=base_url,
                    model=model,
                    messages=messages,
                    tools=[],
                    timeout_s=timeout_s,
                    **(
                        {"generation_options": generation_options}
                        if generation_options
                        else {}
                    ),
                )
                _collect_usage(response)
                if on_event:
                    full_response = response.get("message", {}).get("content", "")
                    if full_response:
                        _on_token(full_response)
            msg = response.get("message", {})
            tool_calls = msg.get("tool_calls") or []
            last_content = msg.get("content", "")
        message = response.get("message", {})
        if not isinstance(message, dict):
            raise RuntimeError("Ollama response missing 'message' object")

        assistant_entry: dict[str, Any] = {
            "role": "assistant",
            "content": str(message.get("content", "")),
        }
        # Use tool_calls already extracted above (set in both try and except branches)
        if isinstance(tool_calls, list) and tool_calls:
            assistant_entry["tool_calls"] = tool_calls
        messages.append(assistant_entry)
        last_content = assistant_entry.get("content", "")

        if not isinstance(tool_calls, list) or not tool_calls:
            if (
                not retried_after_noop
                and needs_tools
                and _looks_like_noop_response(last_content)
            ):
                retried_after_noop = True
                if on_event:
                    on_event({"type": "token_rollback"})
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "You already have enough context. Use tools now. "
                            "If filename is uncertain, call find_files first. "
                            "Do not ask the user for CLI commands or extra arguments."
                        ),
                    }
                )
                continue
            if needs_tools and _looks_like_noop_response(last_content):
                fallback = _auto_tool_fallback(client, prompt)
                if fallback:
                    if on_event:
                        on_event({"type": "token_rollback"})
                    messages.append(
                        {
                            "role": "user",
                            "content": (
                                "[Résultat extrait automatiquement par les outils MCP]\n"
                                f"{fallback}\n\n"
                                "Réponds maintenant à la demande utilisateur originale. "
                                "Explique et interprète ces données clairement au lieu de "
                                "simplement les recopier."
                            ),
                        }
                    )
                    try:
                        synthesis = _ollama_chat(
                            base_url=base_url,
                            model=model,
                            messages=messages,
                            tools=[],
                            timeout_s=timeout_s,
                            on_token=_on_token if on_event else None,
                            **(
                                {"generation_options": generation_options}
                                if generation_options
                                else {}
                            ),
                        )
                        _collect_usage(synthesis)
                        synthesis_message = synthesis.get("message", {})
                        if isinstance(synthesis_message, dict):
                            synthesis_content = str(
                                synthesis_message.get("content", "")
                            ).strip()
                            if synthesis_content:
                                return _result(tools_warning + synthesis_content)
                    except RuntimeError:
                        pass
                    return _result(tools_warning + fallback)
            return _result(tools_warning + last_content)

        for tc in tool_calls:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function", {})
            if not isinstance(fn, dict):
                continue
            name = fn.get("name")
            if not isinstance(name, str) or not name.strip():
                continue
            requested_name = name.strip()
            name = _resolve_requested_tool_name(requested_name, available_tool_names)
            args = _coerce_tool_arguments(fn.get("arguments"))
            args = _normalize_tool_call_arguments(client, name, args, prompt)
            if on_event:
                on_event({"type": "tool_call", "name": name, "args": args})
            try:
                tool_result = client.request(
                    "tools/call",
                    {"name": name, "arguments": args},
                )
            except Exception as exc:
                tool_result = {
                    "structuredContent": {
                        "ok": False,
                        "error": str(exc),
                        "requested_tool": requested_name,
                        "tool": name,
                        "arguments": args,
                    },
                    "content": [],
                    "isError": True,
                }
            content_list = tool_result.get("content")
            tool_content = ""
            if isinstance(content_list, list) and content_list:
                first = content_list[0]
                if isinstance(first, dict) and isinstance(first.get("text"), str):
                    tool_content = first["text"]
            if not tool_content:
                tool_content = json.dumps(
                    tool_result.get("structuredContent", tool_result), ensure_ascii=True
                )
            call_ok = not tool_result.get("isError", False)
            if on_event:
                on_event({"type": "tool_result", "name": name, "ok": call_ok})
            tool_calls_log.append(
                {
                    "name": name,
                    "args": args,
                    "ok": call_ok,
                }
            )
            # Truncate large tool results to avoid saturating the model context.
            # 6000 chars ≈ 1500 tokens — leaves room for the final response.
            _MAX_TOOL_CONTENT = 6000
            if len(tool_content) > _MAX_TOOL_CONTENT:
                tool_content = (
                    tool_content[:_MAX_TOOL_CONTENT]
                    + f"\n... [truncated {len(tool_content) - _MAX_TOOL_CONTENT} chars]"
                )
            messages.append(
                {
                    "role": "tool",
                    "tool_name": name,
                    "content": tool_content,
                }
            )

    return _result(tools_warning + last_content)


def _default_server_cmd() -> str:
    server_path = os.path.join(ROOT, "backends", "mcp", "server.py")
    venv_python = os.path.join(ROOT, "backends", ".venv", "bin", "python3")
    python_exe = venv_python if os.path.isfile(venv_python) else sys.executable
    return f"{shlex.quote(python_exe)} {shlex.quote(server_path)} --transport stdio"


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Ollama <-> MCP bridge runner")
    parser.add_argument("--model", default="qwen3:8b", help="Ollama model name")
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:11434",
        help="Base URL of the Ollama API",
    )
    parser.add_argument("--prompt", default="", help="User prompt (one-shot mode)")
    parser.add_argument(
        "--system",
        default=(
            "You can use tools when useful. Prefer tools over guessing. "
            "If a binary path is missing or ambiguous, call find_files first. "
            "Understand natural requests like 'analyse', 'code asm', 'desassemblage', "
            "'symboles', 'strings'. "
            "Do not ask the user to run CLI commands for tools (like --output); "
            "call the tools directly with JSON arguments. "
            "If the user gives a filename (like demo_analysis.elf), use it directly."
        ),
        help="System prompt for the agent loop",
    )
    parser.add_argument(
        "--max-steps",
        type=int,
        default=8,
        help="Max tool-calling iterations per prompt",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="HTTP timeout (seconds) for Ollama calls",
    )
    parser.add_argument(
        "--server-cmd",
        default=_default_server_cmd(),
        help="Shell-like command used to start the MCP server",
    )
    parser.add_argument(
        "--list-tools",
        action="store_true",
        help="Print exposed MCP tools then exit",
    )
    parser.add_argument(
        "--memory-path",
        default=DEFAULT_MEMORY_PATH,
        help=(
            "Path to a Markdown memory file appended to the system prompt "
            "(default: docs/mcp/memory.md)."
        ),
    )
    parser.add_argument(
        "--json-output",
        action="store_true",
        help="Output a JSON object {ok, response, tool_calls, model} instead of plain text",
    )
    parser.add_argument(
        "--stream-output",
        action="store_true",
        help="Emit NDJSON events (tool_call, tool_result, done) on stdout as they happen",
    )
    parser.add_argument("--temperature", type=float, default=None)
    parser.add_argument("--top-p", type=float, default=None)
    parser.add_argument("--max-tokens", type=int, default=None)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    cmd = shlex.split(args.server_cmd)
    client = McpStdioClient(cmd=cmd, cwd=ROOT, timeout_s=args.timeout)
    client.start()
    system_prompt = _build_system_prompt(args.system, args.memory_path)

    try:
        _ = client.request(
            "initialize",
            {
                "protocolVersion": DEFAULT_PROTOCOL_VERSION,
                "clientInfo": {"name": "ollama-mcp-bridge", "version": "0.1.0"},
            },
        )
        client.notify("notifications/initialized", {})

        if args.list_tools:
            tools_result = client.request("tools/list", {})
            tools = tools_result.get("tools", [])
            for tool in tools:
                if isinstance(tool, dict):
                    print(tool.get("name", ""))
            return 0

        if args.prompt.strip():
            emitted_token: list[bool] = [False]

            def _emit(event: dict[str, Any]) -> None:
                if event.get("type") == "token":
                    emitted_token[0] = True
                elif event.get("type") == "token_rollback":
                    emitted_token[0] = False
                sys.stdout.write(json.dumps(event, ensure_ascii=True) + "\n")
                sys.stdout.flush()

            on_event: Callable[[dict[str, Any]], None] | None = (
                _emit if args.stream_output else None
            )

            result = run_agent_once(
                client=client,
                base_url=args.base_url,
                model=args.model,
                prompt=args.prompt.strip(),
                max_steps=max(1, args.max_steps),
                timeout_s=max(5, args.timeout),
                system_prompt=system_prompt,
                on_event=on_event,
                generation_options={
                    key: value
                    for key, value in {
                        "temperature": args.temperature,
                        "top_p": args.top_p,
                        "num_predict": args.max_tokens,
                    }.items()
                    if value is not None
                },
            )
            if args.stream_output:
                if not emitted_token[0] and result.get("response"):
                    # A non-streaming fallback still uses the same event contract,
                    # but preserves the response byte-for-byte in one chunk.
                    _emit({"type": "token", "content": result["response"]})
                sys.stdout.write(
                    json.dumps(
                        {
                            "type": "done",
                            "ok": True,
                            "response": result["response"],
                            "tool_calls": result["tool_calls"],
                            "model": args.model,
                            "usage": result.get("usage", {}),
                        },
                        ensure_ascii=True,
                    )
                    + "\n"
                )
                sys.stdout.flush()
            elif args.json_output:
                print(
                    json.dumps(
                        {
                            "ok": True,
                            "response": result["response"],
                            "tool_calls": result["tool_calls"],
                            "model": args.model,
                            "usage": result.get("usage", {}),
                        }
                    )
                )
            else:
                print(result["response"])
            return 0

        print("Interactive mode (type 'exit' to quit)")
        while True:
            user_prompt = input("> ").strip()
            if not user_prompt:
                continue
            if user_prompt.lower() in {"exit", "quit"}:
                break
            result = run_agent_once(
                client=client,
                base_url=args.base_url,
                model=args.model,
                prompt=user_prompt,
                max_steps=max(1, args.max_steps),
                timeout_s=max(5, args.timeout),
                system_prompt=system_prompt,
            )
            print(result["response"])
        return 0
    except Exception as exc:
        # Print only the clean message — no traceback — so the caller
        # (Node.js) receives a single readable line on stderr.
        if args.stream_output:
            sys.stdout.write(
                json.dumps(
                    {
                        "type": "error",
                        "ok": False,
                        "error": str(exc),
                        "model": args.model,
                    },
                    ensure_ascii=True,
                )
                + "\n"
            )
            sys.stdout.flush()
        elif args.json_output:
            print(json.dumps({"ok": False, "error": str(exc), "model": args.model}))
        else:
            print(str(exc), file=sys.stderr)
        return 1
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
