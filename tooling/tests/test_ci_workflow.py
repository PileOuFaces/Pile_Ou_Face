"""Structure and gate logic of .github/workflows/ci.yml (required check « CI Success »).

The « Check results » script of the ci-success job is executed for real with bash on
every scenario: documentation-only, code-only, mixed and workflow changes, failures,
skipped suites and a failed or ambiguous classification.
"""

import re
import subprocess
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # PyYAML is not a project dependency: skip rather than fail
    yaml = None

ROOT = Path(__file__).parents[2]
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
UNGATED = {"changes", "security-baseline", "ci-success", "large-real-corpus"}
NOT_REQUIRED = {"deployment-profile-artifacts"}  # was already outside « CI Success »
DOCS_GATE = "needs.changes.outputs.docs_only != 'true'"


@unittest.skipIf(yaml is None, "PyYAML not installed")
class CiWorkflowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
        cls.jobs = cls.workflow["jobs"]
        cls.triggers = cls.workflow[True]  # YAML 1.1 reads the `on:` key as True

    def test_every_pull_request_to_main_or_develops_runs_the_workflow(self) -> None:
        self.assertEqual(self.triggers["pull_request"], {"branches": ["main", "develops"]})

    def test_heavy_jobs_are_gated_by_the_classification(self) -> None:
        for name, job in self.jobs.items():
            if name in UNGATED:
                continue
            with self.subTest(job=name):
                self.assertIn("changes", [job["needs"]] if isinstance(job["needs"], str) else job["needs"])
                self.assertEqual(job["if"], DOCS_GATE)
        self.assertEqual(self.jobs["large-real-corpus"]["needs"], "large-real-corpus-changes")

    def test_ci_success_needs_every_required_job(self) -> None:
        job = self.jobs["ci-success"]
        self.assertEqual(job["name"], "CI Success")
        self.assertEqual(job["if"], "always()")
        self.assertEqual(set(job["needs"]), set(self.jobs) - {"ci-success"} - NOT_REQUIRED)

    def test_classification_step_is_strict(self) -> None:
        steps = self.jobs["changes"]["steps"]
        self.assertEqual(steps[0]["with"], {"fetch-depth": 0})
        script = next(s for s in steps if s.get("id") == "classify")["run"]
        self.assertIn("set -euo pipefail", script)
        self.assertIn('git diff --name-status -z --no-renames "$BASE_SHA...$HEAD_SHA"', script)
        self.assertIn("python3 -m tooling.ci_change_scope", script)


SUITES = ("lint", "security-baseline", "full-test", "dynamic-unicorn", "real-corpus-arm64", "e2e-runtime-audit",
          "backend-loadtest", "security-scan", "auth-licensing-e2e", "auth-licensing-windows",
          "large-real-corpus-changes", "large-real-corpus")


@unittest.skipIf(yaml is None, "PyYAML not installed")
class CiSuccessGateTest(unittest.TestCase):
    """Runs the real « Check results » script with substituted job results."""

    @classmethod
    def setUpClass(cls) -> None:
        job = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["ci-success"]
        cls.step = job["steps"][0]

    def gate(self, results: dict[str, str], changes: str = "success", docs_only: str = "false") -> int:
        script = re.sub(r"\$\{\{ needs\.([a-z0-9-]+)\.result \}\}", lambda m: results[m.group(1)], self.step["run"])
        self.assertNotIn("${{", script)
        env = {"PATH": "/usr/bin:/bin", "CHANGES": changes, "DOCS_ONLY": docs_only}
        return subprocess.run(["bash", "-c", script], env=env, capture_output=True, check=False).returncode

    @staticmethod
    def code_pr(**overrides: str) -> dict[str, str]:
        results = {name: "success" for name in SUITES}
        results["large-real-corpus"] = "skipped"  # only on develops when the corpus changes
        return {**results, **overrides}

    @staticmethod
    def docs_pr(**overrides: str) -> dict[str, str]:
        results = {name: "skipped" for name in SUITES}
        results["security-baseline"] = "success"
        return {**results, **overrides}

    def test_docs_only_pr_passes_when_every_heavy_suite_is_skipped(self) -> None:
        self.assertEqual(self.gate(self.docs_pr(), docs_only="true"), 0)

    def test_docs_only_pr_never_passes_with_a_failed_or_cancelled_job(self) -> None:
        for job, result in (("lint", "failure"), ("full-test", "cancelled"), ("security-baseline", "failure"),
                            ("security-baseline", "skipped"), ("large-real-corpus", "failure")):
            with self.subTest(job=job, result=result):
                self.assertEqual(self.gate(self.docs_pr(**{job: result}), docs_only="true"), 1)

    def test_code_pr_keeps_every_required_validation(self) -> None:
        self.assertEqual(self.gate(self.code_pr()), 0)
        for job in ("lint", "full-test", "dynamic-unicorn", "real-corpus-arm64", "e2e-runtime-audit",
                    "backend-loadtest", "auth-licensing-e2e", "auth-licensing-windows", "large-real-corpus-changes",
                    "security-baseline"):
            for result in ("failure", "cancelled", "skipped"):
                with self.subTest(job=job, result=result):
                    self.assertEqual(self.gate(self.code_pr(**{job: result})), 1)
        self.assertEqual(self.gate(self.code_pr(**{"large-real-corpus": "failure"})), 1)

    def test_skipped_suites_cannot_pass_as_a_code_pr(self) -> None:
        # Mixed or workflow changes are classified docs_only=false: skipped suites must fail the gate.
        self.assertEqual(self.gate(self.docs_pr(), docs_only="false"), 1)

    def test_failed_or_ambiguous_classification_fails_the_gate(self) -> None:
        for changes, docs_only in (("failure", ""), ("cancelled", ""), ("skipped", ""), ("success", ""),
                                   ("success", "maybe"), ("failure", "true")):
            with self.subTest(changes=changes, docs_only=docs_only):
                self.assertEqual(self.gate(self.docs_pr(), changes=changes, docs_only=docs_only), 1)
                self.assertEqual(self.gate(self.code_pr(), changes=changes, docs_only=docs_only), 1)


if __name__ == "__main__":
    unittest.main()
