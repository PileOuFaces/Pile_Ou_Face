# Security controls and baseline

`control-inventory.json` is the source of truth for automated security controls in this repository.
Update it in the same pull request whenever a scanner, scope, trigger or blocking policy changes.

`suppressions.json` contains accepted scanner findings. An exception must identify the scanner,
rule, narrow path, concrete reason, accountable GitHub owner or team, and expiry date. Exceptions
cannot last more than 90 days and wildcard repository-wide paths are rejected. Renewals require a
new review in a pull request.

Run the guard locally:

```bash
python3 -m tooling.security_baseline
```

The guard validates structure, unique identifiers, referenced workflow paths, ownership and expiry.
It never prints finding contents or secrets. Existing vulnerabilities belong in private scanner/SARIF
results and tracking issues, not in this baseline file.

## CodeQL

`.github/workflows/codeql.yml` analyzes JavaScript/TypeScript and Python with the
`security-extended` query suite. It runs on pull requests and pushes targeting maintained branches,
on a weekly schedule, and on manual dispatch. GitHub uploads the SARIF results directly to the
repository's **Security > Code scanning** view.

`.github/codeql/codeql-config.yml` excludes only the deliberately vulnerable positive fixtures used
to test repository-owned Semgrep rules. Production, tooling and ordinary test code remain analyzed.

The workflow itself is validated locally, but a complete CodeQL database and SARIF upload require a
GitHub Actions run. CodeQL is currently informational: findings are triaged in the private scanner
view before code-scanning merge protection is enabled, avoiding an undocumented blanket suppression.

## Semgrep and Bandit

`security/semgrep/host-security.yml` contains repository-owned rules for webview HTML, process
execution, plaintext HTTP, weak hashes and archive extraction. Rule fixtures live beside the rules
and must pass `semgrep --test security/semgrep`. Pull requests use Semgrep's baseline mode so only
findings introduced relative to the PR base are reported; scheduled and branch runs scan the full
scope.

Bandit complements those rules for Python without duplicating Ruff. It scans production backend and
tooling code, excludes tests and reports only findings with medium-or-higher severity and confidence.
Pull requests scan only changed Python files; branch and scheduled runs cover the complete scope.
Both scanners upload SARIF to **Security > Code scanning** and retain the same report as a 14-day CI
artifact. During baseline triage they are informational; accepted findings still require a narrow,
owned and expiring entry in `suppressions.json`. Bandit's native report is retained unchanged in the
artifact; only the GitHub presentation level is temporarily capped at `warning`, while native
severity and confidence remain present in SARIF properties for triage.
