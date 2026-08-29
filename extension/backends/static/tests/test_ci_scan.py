# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json
from pathlib import Path

from backends import ci_scan


def test_normalize_findings_and_sarif(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    report = {
        "binary": {"path": str(binary)},
        "summary": {"failed_features": 0},
        "findings": ci_scan.normalize_findings(
            "vulns",
            {
                "findings": [
                    {
                        "cwe": "CWE-120",
                        "severity": "HIGH",
                        "evidence": "unsafe copy",
                        "addr": "0x401000",
                    }
                ]
            },
        ),
    }
    assert report["findings"][0]["address"] == "0x401000"
    sarif = ci_scan.to_sarif(report)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "pof.vulns.CWE-120"
    assert result["level"] == "error"


def test_scan_binary_uses_plugin_features(monkeypatch, tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    monkeypatch.setattr(ci_scan, "build_plugin_registry", lambda paths: [])
    monkeypatch.setattr(ci_scan, "apply_plugin_licensing", lambda records: records)

    def fake_invoke(records, feature, payload, **kwargs):
        assert payload["binaryPath"] == str(binary.resolve())
        return (
            {
                "ok": True,
                "command": f"test.{feature}",
                "plugin_id": "pof.test",
                "result": {"matches": [{"rule": "demo", "severity": "critical"}]},
            },
            object(),
            records,
        )

    monkeypatch.setattr(ci_scan, "invoke_plugin_feature", fake_invoke)
    report = ci_scan.scan_binary(
        binary, features=["yara_scan"], plugin_paths=[tmp_path]
    )
    assert report["summary"] == {"features": 1, "failed_features": 0, "findings": 1}
    assert report["binary"]["sha256"]
    assert ci_scan.exit_code(report, "high") == 1
    assert ci_scan.exit_code(report, "none") == 0


def test_main_writes_json_and_uses_ci_exit_codes(monkeypatch, tmp_path):
    binary = tmp_path / "sample.bin"
    output = tmp_path / "report.json"
    binary.write_bytes(b"sample")
    report = {
        "$schema": ci_scan.REPORT_SCHEMA,
        "binary": {"path": str(binary), "sha256": "abc"},
        "summary": {"features": 1, "failed_features": 0, "findings": 1},
        "scans": [],
        "findings": [
            {
                "feature": "vulns",
                "rule_id": "pof.vulns.demo",
                "severity": "high",
                "message": "demo",
            }
        ],
    }
    monkeypatch.setattr(ci_scan, "scan_binary", lambda *args, **kwargs: report)
    assert (
        ci_scan.main([str(binary), "--output", str(output), "--fail-on", "high"]) == 1
    )
    assert json.loads(output.read_text())["summary"]["findings"] == 1


def test_main_returns_two_for_missing_binary(tmp_path, capsys):
    assert ci_scan.main([str(tmp_path / "missing.bin")]) == 2
    assert "Binary not found" in capsys.readouterr().err


def test_plugin_result_error_is_operational_failure(monkeypatch, tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"sample")
    monkeypatch.setattr(ci_scan, "build_plugin_registry", lambda paths: [])
    monkeypatch.setattr(ci_scan, "apply_plugin_licensing", lambda records: records)
    monkeypatch.setattr(
        ci_scan,
        "invoke_plugin_feature",
        lambda records, feature, payload, **kwargs: (
            {"ok": True, "result": {"matches": [], "error": "yara unavailable"}},
            object(),
            records,
        ),
    )
    report = ci_scan.scan_binary(
        binary, features=["yara_scan"], plugin_paths=[tmp_path]
    )
    assert report["scans"][0]["error"] == "yara unavailable"
    assert report["summary"]["failed_features"] == 1
    assert ci_scan.exit_code(report, "high") == 2
