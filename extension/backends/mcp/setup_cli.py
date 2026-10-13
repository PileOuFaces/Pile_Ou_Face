#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Standalone setup CLI: registers the Pile ou Face MCP server into Claude Code
and/or Codex, the same way `npx rea-agents setup` does for REA.

Usage:
    python3 backends/mcp/setup_cli.py [--agent claude|codex|all]
                                       [--project-dir PATH] [--scope project|user]
                                       [--dry-run] [--json]
                                       [--doctor] [--rollback]

Each target config is backed up (``<file>.bak``) before being modified, and
only the ``pile-ou-face`` entry is ever touched — every other key in the file
is preserved as-is.
"""

from __future__ import annotations

import argparse
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading

SERVER_ID = "pile-ou-face"
SERVER_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "server.py"))

MIN_PYTHON_VERSION = (3, 10)
CANDIDATE_INTERPRETERS = (
    "python3.13",
    "python3.12",
    "python3.11",
    "python3.10",
    "python3",
    "python",
)


def _backup(path: str) -> None:
    if os.path.isfile(path):
        shutil.copy2(path, path + ".bak")


def _interpreter_version(path: str) -> tuple[int, int] | None:
    try:
        result = subprocess.run(
            [path, "-c", "import sys; print(sys.version_info[0], sys.version_info[1])"],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if result.returncode != 0:
        return None
    try:
        major, minor = result.stdout.strip().split()
        return (int(major), int(minor))
    except ValueError:
        return None


def resolve_python_interpreter() -> tuple[str, tuple[int, int] | None, bool]:
    """Resolve a Python {MIN_PYTHON_VERSION}+ interpreter to run server.py with.

    server.py uses PEP 604 syntax (``str | None``) and requires Python 3.10+.
    A bare "python3" command can resolve to an older stub interpreter when
    spawned by a non-interactive process (e.g. a GUI app), so this prefers
    the interpreter currently running this script, then probes named
    interpreters on PATH, and only falls back to a bare "python3" literal
    (which may crash) as a last resort.

    Returns (command, version, is_fallback).
    """
    current_version = sys.version_info[:2]
    if current_version >= MIN_PYTHON_VERSION:
        return sys.executable, current_version, False

    for name in CANDIDATE_INTERPRETERS:
        path = shutil.which(name)
        if not path:
            continue
        version = _interpreter_version(path)
        if version is not None and version >= MIN_PYTHON_VERSION:
            return path, version, False

    print(
        "warning: could not confirm a Python 3.10+ interpreter; falling back "
        "to bare 'python3' (may fail to start if it resolves to an older "
        "interpreter)",
        file=sys.stderr,
    )
    return "python3", None, True


def _server_entry(project_dir: str, interpreter: str | None = None) -> dict:
    command = (
        interpreter if interpreter is not None else resolve_python_interpreter()[0]
    )
    return {
        "type": "stdio",
        "command": command,
        "args": [SERVER_PY, "--transport", "stdio"],
        "env": {
            "PYTHONUNBUFFERED": "1",
            "POF_MCP_WORKSPACE_ROOT": project_dir,
        },
    }


def _claude_config_path(scope: str, project_dir: str) -> str:
    if scope == "user":
        return os.path.expanduser("~/.claude.json")
    return os.path.join(project_dir, ".mcp.json")


def install_claude_code(project_dir: str, scope: str, *, dry_run: bool = False) -> str:
    path = _claude_config_path(scope, project_dir)
    config: dict = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            config = json.load(fh)

    servers = config.setdefault("mcpServers", {})
    servers[SERVER_ID] = _server_entry(project_dir)

    if dry_run:
        return path

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    _backup(path)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(config, fh, indent=2, ensure_ascii=False)
        fh.write("\n")
    return path


_TOML_TABLE_RE = re.compile(
    r"^\[mcp_servers\." + re.escape(SERVER_ID) + r"\]\s*$", re.MULTILINE
)


def _toml_env_literal(value: str) -> str:
    return json.dumps(value)


def _render_toml_block(project_dir: str) -> str:
    entry = _server_entry(project_dir)
    command_literal = json.dumps(entry["command"])
    args_literal = json.dumps(entry["args"])
    env_pairs = ", ".join(
        f"{key} = {_toml_env_literal(val)}" for key, val in entry["env"].items()
    )
    return (
        f"[mcp_servers.{SERVER_ID}]\n"
        f"command = {command_literal}\n"
        f"args = {args_literal}\n"
        f"env = {{ {env_pairs} }}\n"
    )


def _replace_or_append_toml_block(text: str, block: str) -> str:
    match = _TOML_TABLE_RE.search(text)
    if not match:
        sep = "" if text.endswith("\n") or not text else "\n"
        return text + sep + "\n" + block

    start = match.start()
    # Find the next top-level table header after our own, or end of file.
    next_header = re.search(r"^\[", text[match.end() :], re.MULTILINE)
    end = match.end() + next_header.start() if next_header else len(text)
    return text[:start] + block + text[end:]


def install_codex(project_dir: str, *, dry_run: bool = False) -> str:
    path = os.path.expanduser("~/.codex/config.toml")
    text = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

    block = _render_toml_block(project_dir)
    new_text = _replace_or_append_toml_block(text, block)

    if dry_run:
        return path

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    _backup(path)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    return path


def run_doctor(project_dir: str, *, timeout_s: float = 5.0) -> dict:
    """Spawn server.py and perform a real NDJSON MCP handshake.

    Uses a background reader thread + queue (rather than selectors) so this
    works identically on Windows pipes and POSIX pipes.
    """
    command, version, is_fallback = resolve_python_interpreter()
    result: dict = {
        "interpreter": command,
        "interpreter_version": f"{version[0]}.{version[1]}" if version else None,
        "interpreter_is_fallback": is_fallback,
        "handshake_ok": False,
        "protocol_version": None,
        "error": None,
    }

    env = dict(os.environ)
    env["PYTHONUNBUFFERED"] = "1"
    env["POF_MCP_WORKSPACE_ROOT"] = project_dir

    try:
        proc = subprocess.Popen(
            [command, SERVER_PY, "--transport", "stdio"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=project_dir,
            env=env,
        )
    except OSError as exc:
        result["error"] = f"failed to start server: {exc}"
        return result

    response_queue: queue.Queue = queue.Queue()

    def _read_line() -> None:
        assert proc.stdout is not None
        response_queue.put(proc.stdout.readline())

    threading.Thread(target=_read_line, daemon=True).start()

    try:
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
        assert proc.stdin is not None
        proc.stdin.write((json.dumps(request) + "\n").encode("utf-8"))
        proc.stdin.flush()

        try:
            line = response_queue.get(timeout=timeout_s)
        except queue.Empty:
            result["error"] = "timed out waiting for MCP handshake response"
            return result

        if not line:
            stderr_output = (
                proc.stderr.read().decode("utf-8", errors="replace")
                if proc.stderr
                else ""
            )
            result["error"] = (
                f"server exited without responding: {stderr_output.strip()[-500:]}"
            )
            return result

        try:
            response = json.loads(line.decode("utf-8"))
        except json.JSONDecodeError as exc:
            result["error"] = f"invalid JSON response: {exc}"
            return result

        if (
            not isinstance(response, dict)
            or response.get("jsonrpc") != "2.0"
            or response.get("id") != request["id"]
        ):
            result["error"] = "invalid JSON-RPC response"
            return result

        if "error" in response:
            err = response["error"]
            if isinstance(err, dict):
                result["error"] = f"MCP error {err.get('code')}: {err.get('message')}"
            else:
                result["error"] = f"invalid MCP error response: {err!r}"
            return result

        initialize_result = response.get("result")
        if (
            not isinstance(initialize_result, dict)
            or not isinstance(initialize_result.get("protocolVersion"), str)
            or not initialize_result["protocolVersion"]
        ):
            result["error"] = "invalid MCP initialize result"
            return result

        result["protocol_version"] = initialize_result["protocolVersion"]
        result["handshake_ok"] = True
        return result
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()


def rollback(agent: str, project_dir: str, scope: str) -> str:
    """Restore ``<path>.bak`` over ``<path>`` for the given agent's config."""
    if agent == "claude":
        path = _claude_config_path(scope, project_dir)
    elif agent == "codex":
        path = os.path.expanduser("~/.codex/config.toml")
    else:
        raise ValueError(f"Unknown agent: {agent}")

    backup_path = path + ".bak"
    if not os.path.isfile(backup_path):
        raise FileNotFoundError(f"No backup found for {agent}: {backup_path}")

    shutil.copy2(backup_path, path)
    return path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--agent",
        choices=["claude", "codex", "all"],
        default="all",
        help="Which agent config to update (default: all).",
    )
    parser.add_argument(
        "--project-dir",
        default=os.getcwd(),
        help="Project directory the MCP server should scan (default: cwd).",
    )
    parser.add_argument(
        "--scope",
        choices=["project", "user"],
        default="project",
        help="Claude Code config scope: project .mcp.json or user ~/.claude.json "
        "(default: project).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would change without writing any file.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit a structured JSON result instead of human-readable text.",
    )
    parser.add_argument(
        "--doctor",
        action="store_true",
        help="Perform a real MCP handshake against server.py and report the "
        "diagnosis instead of installing anything.",
    )
    parser.add_argument(
        "--rollback",
        action="store_true",
        help="Restore the agent config(s) from their .bak backup instead of "
        "installing anything.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    project_dir = os.path.abspath(args.project_dir)

    if args.doctor:
        diagnosis = run_doctor(project_dir)
        if args.json:
            print(json.dumps(diagnosis))
        else:
            for key, value in diagnosis.items():
                print(f"{key}: {value}")
        return 0 if diagnosis["handshake_ok"] else 1

    if args.rollback:
        agents = ["claude", "codex"] if args.agent == "all" else [args.agent]
        restored: list[dict] = []
        errors: list[dict] = []
        for agent in agents:
            try:
                path = rollback(agent, project_dir, args.scope)
                restored.append({"agent": agent, "path": path})
            except FileNotFoundError as exc:
                errors.append({"agent": agent, "error": str(exc)})
        if args.json:
            print(json.dumps({"restored": restored, "errors": errors}))
        else:
            for item in restored:
                print(
                    f"Restored {item['agent']} MCP config from backup: {item['path']}"
                )
            for item in errors:
                print(
                    f"No backup to restore for {item['agent']}: {item['error']}",
                    file=sys.stderr,
                )
        return 0 if restored or not errors else 1

    actions: list[tuple[str, str]] = []
    if args.agent in ("claude", "all"):
        path = install_claude_code(project_dir, args.scope, dry_run=args.dry_run)
        actions.append(("Claude Code", path))
    if args.agent in ("codex", "all"):
        path = install_codex(project_dir, dry_run=args.dry_run)
        actions.append(("Codex", path))

    if args.json:
        print(
            json.dumps(
                {
                    "dry_run": args.dry_run,
                    "project_dir": project_dir,
                    "actions": [
                        {"agent": name, "path": path} for name, path in actions
                    ],
                }
            )
        )
        return 0

    verb = "Would update" if args.dry_run else "Updated"
    for agent_name, path in actions:
        print(f"{verb} {agent_name} MCP config: {path}")
    if not args.dry_run:
        print(
            f"Restart {', '.join(name for name, _ in actions)} to pick up the "
            f"'{SERVER_ID}' MCP server (workspace: {project_dir})."
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
