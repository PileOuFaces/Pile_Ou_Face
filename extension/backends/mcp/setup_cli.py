#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Standalone setup CLI: registers the Pile ou Face MCP server into Claude Code
and/or Codex, the same way `npx rea-agents setup` does for REA.

Usage:
    python3 backends/mcp/setup_cli.py [--agent claude|codex|all]
                                       [--project-dir PATH] [--scope project|user]
                                       [--dry-run]

Each target config is backed up (``<file>.bak``) before being modified, and
only the ``pile-ou-face`` entry is ever touched — every other key in the file
is preserved as-is.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import sys

SERVER_ID = "pile-ou-face"
SERVER_PY = os.path.abspath(os.path.join(os.path.dirname(__file__), "server.py"))


def _backup(path: str) -> None:
    if os.path.isfile(path):
        shutil.copy2(path, path + ".bak")


def _server_entry(project_dir: str) -> dict:
    return {
        "type": "stdio",
        "command": "python3",
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
    args_literal = json.dumps(entry["args"])
    env_pairs = ", ".join(
        f"{key} = {_toml_env_literal(val)}" for key, val in entry["env"].items()
    )
    return (
        f"[mcp_servers.{SERVER_ID}]\n"
        f'command = "python3"\n'
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
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    project_dir = os.path.abspath(args.project_dir)

    actions: list[tuple[str, str]] = []
    if args.agent in ("claude", "all"):
        path = install_claude_code(project_dir, args.scope, dry_run=args.dry_run)
        actions.append(("Claude Code", path))
    if args.agent in ("codex", "all"):
        path = install_codex(project_dir, dry_run=args.dry_run)
        actions.append(("Codex", path))

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
