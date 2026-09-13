"""Regression guards for the repository security controls."""

from pathlib import Path


ROOT = Path(__file__).parents[2]


def test_security_workflows_and_configs_are_present() -> None:
    required = (
        ".github/workflows/codeql.yml",
        ".github/workflows/sast.yml",
        ".github/workflows/gitleaks.yml",
        ".github/workflows/trivy.yml",
        ".github/workflows/publish.yml",
        ".gitleaks.toml",
        ".bandit.yml",
        "security/semgrep/host-security.yml",
    )
    missing = [path for path in required if not (ROOT / path).is_file()]
    assert not missing, f"Missing security control files: {missing}"


def test_security_workflows_use_immutable_action_refs() -> None:
    workflows = list((ROOT / ".github/workflows").glob("*.yml"))
    mutable = []
    for workflow in workflows:
        for line_number, line in enumerate(workflow.read_text().splitlines(), 1):
            if "uses:" in line and "@v" in line:
                mutable.append(f"{workflow}:{line_number}")
    assert not mutable, f"Mutable GitHub Action refs found: {mutable}"


def test_semgrep_has_repository_owned_rule_fixtures() -> None:
    fixtures = list((ROOT / "security/semgrep").glob("host-security.*"))
    assert len(fixtures) >= 3
