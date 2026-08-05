# SPDX-License-Identifier: AGPL-3.0-only
"""Tests for the AI-provider consent gate used by auto-triage (#124).

Mirrors backends/plugins/tests/test_consent.py's coverage shape, but for a
different question: not "do you trust this plugin's code" but "do you agree
to send this binary's code to this AI provider" — checked once per provider,
including local ones, before backends/mcp/auto_triage.py ever spawns a
provider call.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.mcp.ai_consent import (
    default_ai_consent_path,
    grant_ai_consent,
    is_provider_consented,
    load_ai_consent,
    revoke_ai_consent,
    save_ai_consent,
)


def test_default_ai_consent_path_prefers_workspace_root_when_present(tmp_path):
    project = tmp_path / "project"
    (project / ".pile-ou-face").mkdir(parents=True)
    path = default_ai_consent_path(cwd=project, home=tmp_path / "home", env={})
    assert path == project / ".pile-ou-face" / "ai_consent.json"


def test_default_ai_consent_path_falls_back_to_home_without_workspace_root(tmp_path):
    path = default_ai_consent_path(
        cwd=tmp_path / "project", home=tmp_path / "home", env={}
    )
    assert path == tmp_path / "home" / ".pile-ou-face" / "ai_consent.json"


def test_default_ai_consent_path_workspace_discovery_can_be_disabled(tmp_path):
    project = tmp_path / "project"
    (project / ".pile-ou-face").mkdir(parents=True)
    path = default_ai_consent_path(
        cwd=project, home=tmp_path / "home", env={}, allow_workspace_discovery=False
    )
    assert path == tmp_path / "home" / ".pile-ou-face" / "ai_consent.json"


def test_default_ai_consent_path_env_override(tmp_path):
    override = tmp_path / "custom" / "ai_consent.json"
    path = default_ai_consent_path(env={"BINHOST_AI_CONSENT_PATH": str(override)})
    assert path == override


def test_is_provider_consented_false_when_absent():
    assert is_provider_consented("ollama", {}) is False


def test_grant_then_is_consented(tmp_path):
    path = tmp_path / "ai_consent.json"
    grant_ai_consent("ollama", path)
    store = load_ai_consent(path)
    assert is_provider_consented("ollama", store) is True


def test_local_provider_still_requires_consent(tmp_path):
    # V1 deliberately does not exempt local providers: the binary's code
    # still leaves the process boundary to reach even a local model.
    path = tmp_path / "ai_consent.json"
    assert is_provider_consented("ollama", load_ai_consent(path)) is False


def test_consent_is_scoped_per_provider(tmp_path):
    path = tmp_path / "ai_consent.json"
    grant_ai_consent("ollama", path)
    store = load_ai_consent(path)
    assert is_provider_consented("openai", store) is False


def test_revoke_ai_consent(tmp_path):
    path = tmp_path / "ai_consent.json"
    grant_ai_consent("ollama", path)
    revoke_ai_consent("ollama", path)
    store = load_ai_consent(path)
    assert is_provider_consented("ollama", store) is False


def test_load_ai_consent_returns_empty_dict_for_missing_file(tmp_path):
    assert load_ai_consent(tmp_path / "does-not-exist.json") == {}


def test_load_ai_consent_returns_empty_dict_for_corrupt_file(tmp_path):
    path = tmp_path / "ai_consent.json"
    path.write_text("not json{{{", encoding="utf-8")
    assert load_ai_consent(path) == {}


def test_save_ai_consent_creates_parent_directories(tmp_path):
    path = tmp_path / "a" / "b" / "ai_consent.json"
    save_ai_consent(path, {"ollama": {"approved": True}})
    assert path.exists()


def _run_cli(*args: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(ROOT / "backends" / "mcp" / "ai_consent.py"), *args],
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_cli_check_exits_nonzero_when_not_consented(tmp_path):
    env = {**os.environ, "BINHOST_AI_CONSENT_PATH": str(tmp_path / "ai_consent.json")}
    result = _run_cli("--provider", "ollama", "--check", env=env)
    assert result.returncode == 1
    assert json.loads(result.stdout) == {"consented": False}


def test_cli_grant_then_check_exits_zero(tmp_path):
    env = {**os.environ, "BINHOST_AI_CONSENT_PATH": str(tmp_path / "ai_consent.json")}
    granted = _run_cli("--provider", "ollama", "--grant", env=env)
    assert granted.returncode == 0
    checked = _run_cli("--provider", "ollama", "--check", env=env)
    assert checked.returncode == 0
    assert json.loads(checked.stdout) == {"consented": True}
