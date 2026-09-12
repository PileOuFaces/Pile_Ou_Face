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
