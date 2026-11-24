"""Regression tests for the CI change classifier (docs-only fast path, fail-closed)."""

import subprocess
import sys
import unittest
from pathlib import Path

from tooling.ci_change_scope import docs_only, is_documentation

ROOT = Path(__file__).parents[2]


def listing(*changes: tuple[str, str]) -> str:
    return "".join(f"{status}\0{path}\0" for status, path in changes)


class DocsOnlyTest(unittest.TestCase):
    def test_documentation_only_changes(self) -> None:
        for changes in (
            [("A", "docs/ci/WORKFLOWS.md")],
            [("M", "README.md"), ("M", "docs/static/GUIDE_UTILISATION.md")],
            [("D", "docs/old.md"), ("A", "docs/new.md")],
            [("M", "docs/ci/binary-scan-action.yml")],
        ):
            with self.subTest(changes=changes):
                self.assertTrue(docs_only(listing(*changes)))

    def test_code_only_changes_run_every_suite(self) -> None:
        for path in ("extension/src/extension.ts", "extension/backends/static/cache/cache.py",
                     "tooling/security_baseline.py", "docker/decompilers/Dockerfile", "LICENSE",
                     "extension/README.md", "security/control-inventory.json"):
            with self.subTest(path=path):
                self.assertFalse(docs_only(listing(("M", path))))

    def test_mixed_changes_run_every_suite(self) -> None:
        self.assertFalse(docs_only(listing(("M", "docs/a.md"), ("M", "extension/package.json"))))

    def test_workflow_changes_run_every_suite(self) -> None:
        for path in (".github/workflows/ci.yml", ".github/dependabot.yml", ".pre-commit-config.yaml"):
            with self.subTest(path=path):
                self.assertFalse(docs_only(listing(("M", path), ("A", "docs/x.md"))))

    def test_ambiguous_input_fails_closed(self) -> None:
        for raw in ("", "\0", "M\0", "R100\0docs/a.md\0", "T\0docs/a.md\0", "M\0docs/a.md\0extra",
                    listing(("M", "docs/../extension/x.py")), listing(("M", "/docs/a.md")),
                    listing(("M", "docs/a\nb.md"))):
            with self.subTest(raw=raw):
                self.assertFalse(docs_only(raw))

    def test_nested_markdown_outside_docs_is_code(self) -> None:
        self.assertFalse(is_documentation("extension/backends/dynamic/README.md"))
        self.assertTrue(is_documentation("CONTRIBUTING.md"))

    def test_cli_output_for_github_output(self) -> None:
        for changes, expected in (([("A", "docs/x.md")], "docs_only=true"),
                                  ([("A", "extension/x.ts")], "docs_only=false")):
            proc = subprocess.run([sys.executable, "-m", "tooling.ci_change_scope"], cwd=ROOT,
                                  input=listing(*changes).encode(), capture_output=True, check=True)
            self.assertEqual(proc.stdout.decode().strip(), expected)

    def test_cli_rejects_invalid_utf8(self) -> None:
        proc = subprocess.run([sys.executable, "-m", "tooling.ci_change_scope"], cwd=ROOT,
                              input=b"M\0docs/\xff.md\0", capture_output=True, check=False)
        self.assertNotEqual(proc.returncode, 0)
        self.assertNotIn(b"docs_only=true", proc.stdout)


if __name__ == "__main__":
    unittest.main()
