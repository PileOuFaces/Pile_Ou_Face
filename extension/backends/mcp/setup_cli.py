#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
"""Standalone setup CLI: registers the Pile ou Face MCP server into Claude Code
and/or Codex, the same way `npx rea-agents setup` does for REA.

Usage:
    python3 backends/mcp/setup_cli.py [--agent claude|codex|all]
                                       [--project-dir PATH] [--scope project|user]
                                       [--dry-run] [--json]
                                       [--doctor] [--rollback]

Each target config is backed up before being modified, and only the
``pile-ou-face`` entry is ever touched — every other key in the file is
preserved as-is. The first backup snapshot (``<file>.bak``) is kept pristine
across reruns; if the file has drifted since then (e.g. a manual edit), the
drifted bytes are preserved separately as ``<file>.recovery.<sha256>``
instead of being silently discarded. Writes are atomic (temp file +
``os.replace``) and verified by re-reading the result. ``--doctor`` also
validates the existing Claude Code / Codex config files for well-formedness,
and install will refuse to touch a malformed config rather than guessing.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import tempfile
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

MANAGED_ENV_KEYS = ("PYTHONUNBUFFERED", "POF_MCP_WORKSPACE_ROOT")


class MalformedConfigError(RuntimeError):
    """Raised when an agent's existing config file is not well-formed and
    must not be touched."""


def _backup(path: str) -> str | None:
    """Snapshot ``path`` before it gets modified.

    The first snapshot (``<path>.bak``) is kept pristine forever: reruns
    never overwrite it. If the file on disk has drifted from that pristine
    snapshot (e.g. a manual edit between runs), the drifted bytes are
    preserved as a separate ``<path>.recovery.<sha256>`` copy instead of
    being discarded, so a rollback never loses user edits silently.
    """
    if not os.path.isfile(path):
        return None
    with open(path, "rb") as fh:
        current_bytes = fh.read()

    bak_path = path + ".bak"
    if not os.path.isfile(bak_path):
        with open(bak_path, "wb") as fh:
            fh.write(current_bytes)
        return bak_path

    with open(bak_path, "rb") as fh:
        bak_bytes = fh.read()
    if bak_bytes == current_bytes:
        return bak_path

    digest = hashlib.sha256(current_bytes).hexdigest()[:12]
    recovery_path = f"{path}.recovery.{digest}"
    if not os.path.isfile(recovery_path):
        with open(recovery_path, "wb") as fh:
            fh.write(current_bytes)
    return recovery_path


def _atomic_write(path: str, data: str) -> None:
    """Write ``data`` to ``path`` via a temp file + atomic rename, then
    re-read it back to verify the write actually landed as intended."""
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(
        dir=directory, prefix=".pof-mcp-setup-", suffix=".tmp"
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise

    with open(path, encoding="utf-8") as fh:
        written = fh.read()
    if written != data:
        raise RuntimeError(
            f"post-write verification failed for {path}: on-disk content "
            "does not match what was written"
        )


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


def _server_entry(
    project_dir: str,
    interpreter: str | None = None,
    *,
    existing_env: dict | None = None,
) -> dict:
    """Build the ``pile-ou-face`` server entry.

    Only the keys in ``MANAGED_ENV_KEYS`` are ever set/overwritten in
    ``env``; any other env key already present on an existing entry
    (``existing_env``) is preserved as-is instead of being dropped.
    """
    command = (
        interpreter if interpreter is not None else resolve_python_interpreter()[0]
    )
    env = dict(existing_env) if isinstance(existing_env, dict) else {}
    env["PYTHONUNBUFFERED"] = "1"
    env["POF_MCP_WORKSPACE_ROOT"] = project_dir
    return {
        "type": "stdio",
        "command": command,
        "args": [SERVER_PY, "--transport", "stdio"],
        "env": env,
    }


def _claude_config_path(scope: str, project_dir: str) -> str:
    if scope == "user":
        return os.path.expanduser("~/.claude.json")
    return os.path.join(project_dir, ".mcp.json")


def _validate_claude_config(path: str) -> str | None:
    """Return an error message if the Claude Code config at ``path`` is
    malformed, or None if it is absent or well-formed."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            config = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        return f"malformed Claude Code config at {path}: {exc}"
    if not isinstance(config, dict):
        return f"malformed Claude Code config at {path}: expected a JSON object"
    servers = config.get("mcpServers")
    if servers is not None and not isinstance(servers, dict):
        return f"malformed Claude Code config at {path}: 'mcpServers' is not an object"
    return None


def install_claude_code(project_dir: str, scope: str, *, dry_run: bool = False) -> str:
    path = _claude_config_path(scope, project_dir)
    error = _validate_claude_config(path)
    if error:
        raise MalformedConfigError(error)

    config: dict = {}
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            config = json.load(fh)

    servers = config.setdefault("mcpServers", {})
    existing_entry = servers.get(SERVER_ID)
    existing_env = (
        existing_entry.get("env") if isinstance(existing_entry, dict) else None
    )
    servers[SERVER_ID] = _server_entry(project_dir, existing_env=existing_env)

    if dry_run:
        return path

    payload = json.dumps(config, indent=2, ensure_ascii=False) + "\n"
    _backup(path)
    _atomic_write(path, payload)
    return path


_TOML_TABLE_RE = re.compile(
    r"^\[mcp_servers\." + re.escape(SERVER_ID) + r"\]\s*$", re.MULTILINE
)


def _toml_env_literal(value: str) -> str:
    return json.dumps(value)


def _render_toml_block(project_dir: str, *, existing_env: dict | None = None) -> str:
    entry = _server_entry(project_dir, existing_env=existing_env)
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


_ENV_PAIR_RE = re.compile(r'(\w+)\s*=\s*"((?:[^"\\]|\\.)*)"')


def _extract_existing_toml_env(text: str) -> dict | None:
    """Pull the ``env`` table out of our existing ``[mcp_servers.pile-ou-face]``
    block (if any), so a rerun can merge managed keys into it instead of
    discarding any env key a user added by hand."""
    match = _TOML_TABLE_RE.search(text)
    if not match:
        return None
    next_header = re.search(r"^\[", text[match.end() :], re.MULTILINE)
    end = match.end() + next_header.start() if next_header else len(text)
    block_text = text[match.start() : end]

    env_match = re.search(r"^env\s*=\s*\{(.*)\}\s*$", block_text, re.MULTILINE)
    if not env_match:
        return None

    try:
        import tomllib

        parsed = tomllib.loads(f"env = {{{env_match.group(1)}}}")
        env = parsed.get("env")
        return env if isinstance(env, dict) else None
    except ModuleNotFoundError:
        pass
    except Exception:
        return None

    pairs = dict(_ENV_PAIR_RE.findall(env_match.group(1)))
    return pairs or None


def _validate_codex_config(path: str) -> str | None:
    """Return an error message if the Codex config at ``path`` is malformed,
    or None if it is absent, well-formed, or cannot be validated (no
    ``tomllib`` available, i.e. running under Python <3.11)."""
    if not os.path.isfile(path):
        return None
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except OSError as exc:
        return f"cannot read Codex config at {path}: {exc}"
    try:
        import tomllib
    except ModuleNotFoundError:
        return None
    try:
        tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        return f"malformed Codex config at {path}: {exc}"
    return None


def install_codex(project_dir: str, *, dry_run: bool = False) -> str:
    path = os.path.expanduser("~/.codex/config.toml")
    error = _validate_codex_config(path)
    if error:
        raise MalformedConfigError(error)

    text = ""
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as fh:
            text = fh.read()

    existing_env = _extract_existing_toml_env(text)
    block = _render_toml_block(project_dir, existing_env=existing_env)
    new_text = _replace_or_append_toml_block(text, block)

    if dry_run:
        return path

    _backup(path)
    _atomic_write(path, new_text)
    return path


def run_doctor(
    project_dir: str, *, scope: str = "project", timeout_s: float = 5.0
) -> dict:
    """Spawn server.py and perform a real NDJSON MCP handshake.

    Uses a background reader thread + queue (rather than selectors) so this
    works identically on Windows pipes and POSIX pipes. Also validates the
    existing Claude Code / Codex config files for well-formedness, since a
    successful handshake with ``server.py`` says nothing about whether
    ``install_*`` would actually be able to write those files.
    """
    command, version, is_fallback = resolve_python_interpreter()
    result: dict = {
        "interpreter": command,
        "interpreter_version": f"{version[0]}.{version[1]}" if version else None,
        "interpreter_is_fallback": is_fallback,
        "claude_config_error": _validate_claude_config(
            _claude_config_path(scope, project_dir)
        ),
        "codex_config_error": _validate_codex_config(
            os.path.expanduser("~/.codex/config.toml")
        ),
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
        directory = os.path.dirname(path) or "."
        base = os.path.basename(path)
        recovery_snapshots = sorted(
            name
            for name in (os.listdir(directory) if os.path.isdir(directory) else [])
            if name.startswith(base + ".recovery.")
        )
        hint = (
            f" (recovery snapshots found instead: "
            f"{', '.join(os.path.join(directory, n) for n in recovery_snapshots)})"
            if recovery_snapshots
            else ""
        )
        raise FileNotFoundError(f"No backup found for {agent}: {backup_path}{hint}")

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
        diagnosis = run_doctor(project_dir, scope=args.scope)
        if args.json:
            print(json.dumps(diagnosis))
        else:
            for key, value in diagnosis.items():
                print(f"{key}: {value}")
        ok = (
            diagnosis["handshake_ok"]
            and not diagnosis["claude_config_error"]
            and not diagnosis["codex_config_error"]
        )
        return 0 if ok else 1

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
    errors: list[dict] = []
    if args.agent in ("claude", "all"):
        try:
            path = install_claude_code(project_dir, args.scope, dry_run=args.dry_run)
            actions.append(("Claude Code", path))
        except MalformedConfigError as exc:
            errors.append({"agent": "Claude Code", "error": str(exc)})
    if args.agent in ("codex", "all"):
        try:
            path = install_codex(project_dir, dry_run=args.dry_run)
            actions.append(("Codex", path))
        except MalformedConfigError as exc:
            errors.append({"agent": "Codex", "error": str(exc)})

    if args.json:
        print(
            json.dumps(
                {
                    "dry_run": args.dry_run,
                    "project_dir": project_dir,
                    "actions": [
                        {"agent": name, "path": path} for name, path in actions
                    ],
                    "errors": errors,
                }
            )
        )
        return 0 if not errors else 1

    verb = "Would update" if args.dry_run else "Updated"
    for agent_name, path in actions:
        print(f"{verb} {agent_name} MCP config: {path}")
    for item in errors:
        print(f"Skipped {item['agent']}: {item['error']}", file=sys.stderr)
    if not args.dry_run and actions:
        print(
            f"Restart {', '.join(name for name, _ in actions)} to pick up the "
            f"'{SERVER_ID}' MCP server (workspace: {project_dir})."
        )
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
