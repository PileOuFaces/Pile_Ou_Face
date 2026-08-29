# SPDX-License-Identifier: AGPL-3.0-only
"""Headless binary scanner for CI pipelines.

The host owns orchestration and report formats; analysis remains provided by
installed plugins through the public runtime contract.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from backends.plugins.runtime import (
    DEFAULT_HOST_VERSION,
    HOST_API_VERSION,
    apply_plugin_licensing,
    build_plugin_registry,
    default_plugin_search_paths,
    invoke_plugin_feature,
)

REPORT_SCHEMA = "https://pileouface.dev/schemas/ci-scan/v1"
DEFAULT_FEATURES = ("yara_scan", "capa_scan", "vulns")
SEVERITY_RANK = {"none": 0, "note": 1, "low": 1, "medium": 2, "high": 3, "critical": 4}
FINDING_KEYS = (
    "matches",
    "findings",
    "vulnerabilities",
    "capabilities",
    "indicators",
    "techniques",
    "packers",
    "flows",
    "taint_flows",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _severity(item: dict[str, Any]) -> str:
    value = str(item.get("severity") or item.get("level") or "medium").lower()
    return value if value in SEVERITY_RANK else "medium"


def _message(feature: str, item: dict[str, Any]) -> str:
    for key in (
        "message",
        "description",
        "evidence",
        "name",
        "rule",
        "capability",
        "sink",
        "value",
    ):
        value = item.get(key)
        if value not in (None, ""):
            return str(value)
    return f"{feature} reported a finding"


def _rule_id(feature: str, item: dict[str, Any]) -> str:
    value = (
        item.get("rule_id")
        or item.get("rule")
        or item.get("cwe")
        or item.get("name")
        or "finding"
    )
    safe = "".join(
        char if char.isalnum() or char in ".-_" else "-" for char in str(value)
    )
    return f"pof.{feature}.{safe.strip('-') or 'finding'}"


def normalize_findings(feature: str, result: Any) -> list[dict[str, Any]]:
    if not isinstance(result, dict):
        return []
    findings: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for key in FINDING_KEYS:
        values = result.get(key)
        if isinstance(values, dict):
            values = list(values.values())
        if not isinstance(values, list):
            continue
        for value in values:
            item = value if isinstance(value, dict) else {"value": value}
            finding = {
                "feature": feature,
                "rule_id": _rule_id(feature, item),
                "severity": _severity(item),
                "message": _message(feature, item),
            }
            for source, target in (
                ("address", "address"),
                ("addr", "address"),
                ("offset", "offset"),
                ("cwe", "cwe"),
            ):
                if source in item and target not in finding:
                    finding[target] = item[source]
            identity = (finding["rule_id"], finding["severity"], finding["message"])
            if identity not in seen:
                seen.add(identity)
                findings.append(finding)
    return findings


def scan_binary(
    binary: Path,
    *,
    features: Iterable[str],
    plugin_paths: list[Path] | None = None,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    paths = plugin_paths or default_plugin_search_paths(cwd=Path.cwd())
    records = apply_plugin_licensing(build_plugin_registry(paths))
    scans: list[dict[str, Any]] = []
    all_findings: list[dict[str, Any]] = []
    base_payload = {
        "binaryPath": str(binary.resolve()),
        "workspaceRoot": str(Path.cwd()),
    }
    base_payload.update(payload or {})

    for feature in features:
        response, _context, records = invoke_plugin_feature(
            records,
            feature,
            base_payload,
            host_version=DEFAULT_HOST_VERSION,
            api_version=HOST_API_VERSION,
            require_consent=False,
        )
        result = response.get("result") if response.get("ok") else None
        result_error = result.get("error") if isinstance(result, dict) else None
        scan_ok = bool(response.get("ok")) and not result_error
        findings = normalize_findings(feature, result)
        all_findings.extend(findings)
        scans.append(
            {
                "feature": feature,
                "command": response.get("command"),
                "plugin_id": response.get("plugin_id"),
                "ok": scan_ok,
                "error": response.get("error") or result_error,
                "findings": findings,
            }
        )

    return {
        "$schema": REPORT_SCHEMA,
        "binary": {"path": str(binary.resolve()), "sha256": _sha256(binary)},
        "summary": {
            "features": len(scans),
            "failed_features": sum(not scan["ok"] for scan in scans),
            "findings": len(all_findings),
        },
        "scans": scans,
        "findings": all_findings,
    }


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    findings = report.get("findings") or []
    rules: dict[str, dict[str, Any]] = {}
    results = []
    level_map = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "note": "note",
    }
    uri = Path(report["binary"]["path"]).as_uri()
    for finding in findings:
        rule_id = finding["rule_id"]
        rules.setdefault(
            rule_id, {"id": rule_id, "shortDescription": {"text": finding["message"]}}
        )
        results.append(
            {
                "ruleId": rule_id,
                "level": level_map.get(finding["severity"], "warning"),
                "message": {"text": finding["message"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": uri}}}],
                "properties": {
                    "feature": finding["feature"],
                    "severity": finding["severity"],
                },
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Pile ou Face CI scan",
                        "informationUri": "https://pileouface.dev",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "invocations": [
                    {"executionSuccessful": report["summary"]["failed_features"] == 0}
                ],
            }
        ],
    }


def exit_code(report: dict[str, Any], fail_on: str) -> int:
    if report["summary"]["failed_features"]:
        return 2
    threshold = SEVERITY_RANK[fail_on]
    if threshold and any(
        SEVERITY_RANK.get(item["severity"], 2) >= threshold
        for item in report["findings"]
    ):
        return 1
    return 0


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Scan a binary with installed Pile ou Face plugins"
    )
    parser.add_argument("binary", type=Path)
    parser.add_argument(
        "--feature",
        action="append",
        dest="features",
        help="Plugin feature to run (repeatable)",
    )
    parser.add_argument("--plugin-path", action="append", type=Path, default=[])
    parser.add_argument("--format", choices=("json", "sarif"), default="json")
    parser.add_argument(
        "--output", type=Path, help="Write the report to a file instead of stdout"
    )
    parser.add_argument("--fail-on", choices=tuple(SEVERITY_RANK), default="high")
    parser.add_argument(
        "--payload-json",
        default="{}",
        help="Extra object merged into every plugin payload",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_arg_parser().parse_args(argv)
    if not args.binary.is_file():
        print(
            json.dumps({"ok": False, "error": f"Binary not found: {args.binary}"}),
            file=sys.stderr,
        )
        return 2
    try:
        payload = json.loads(args.payload_json)
        if not isinstance(payload, dict):
            raise ValueError("--payload-json must contain an object")
        report = scan_binary(
            args.binary,
            features=args.features or DEFAULT_FEATURES,
            plugin_paths=args.plugin_path or None,
            payload=payload,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 2
    rendered = to_sarif(report) if args.format == "sarif" else report
    output = json.dumps(rendered, indent=2, ensure_ascii=False) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(output, encoding="utf-8")
    else:
        sys.stdout.write(output)
    return exit_code(report, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
