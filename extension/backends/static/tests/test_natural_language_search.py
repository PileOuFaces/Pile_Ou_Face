# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import json

import pytest

from backends.mcp import natural_language_search as search


def _radar():
    return {
        "functions": [
            {
                "addr": "0x401000",
                "name": "sub_401000",
                "focus_summary": "Network configuration hotspot",
                "signal_tags": ["Reseau"],
                "string_signals": [{"preview": "/etc/app.conf"}],
                "import_signals": [{"function": "fopen"}],
                "annotation_preview": [],
            },
            {
                "addr": "0x402000",
                "name": "decrypt_payload",
                "focus_summary": "Crypto routine",
                "signal_tags": ["Crypto"],
                "string_signals": [],
                "import_signals": [],
                "annotation_preview": [{"value": "AES key schedule"}],
            },
        ]
    }


def test_search_returns_only_grounded_ranked_functions(monkeypatch):
    response = {
        "results": [
            {"addr": "0x402000", "score": 71, "reason": "crypto evidence"},
            {"addr": "0x401000", "score": 94, "reason": "config string"},
            {"addr": "0x999999", "score": 100, "reason": "invented"},
        ]
    }
    monkeypatch.setattr(search, "call_provider", lambda *args: json.dumps(response))

    result = search.search_functions(
        "/tmp/sample.bin", "où lit-il la configuration ?", "ollama", radar=_radar()
    )

    assert [item["addr"] for item in result["results"]] == [
        "0x401000",
        "0x402000",
    ]
    assert result["results"][0]["name"] == "sub_401000"
    assert result["results"][0]["evidence"]["strings"] == ["/etc/app.conf"]
    assert result["candidate_count"] == 2


def test_search_rejects_malformed_provider_response(monkeypatch):
    monkeypatch.setattr(search, "call_provider", lambda *args: "not json")
    with pytest.raises(search.NaturalLanguageSearchError, match="JSON"):
        search.search_functions("/tmp/sample.bin", "crypto", "ollama", radar=_radar())


def test_search_rejects_empty_or_oversized_query():
    with pytest.raises(search.NaturalLanguageSearchError, match="manquante"):
        search.search_functions("/tmp/sample.bin", " ", "ollama", radar=_radar())
    with pytest.raises(search.NaturalLanguageSearchError, match="trop longue"):
        search.search_functions("/tmp/sample.bin", "x" * 501, "ollama", radar=_radar())


def test_search_returns_empty_result_without_provider_call(monkeypatch):
    monkeypatch.setattr(
        search,
        "call_provider",
        lambda *args: pytest.fail("provider should not be called"),
    )
    result = search.search_functions(
        "/tmp/sample.bin", "network", "ollama", radar={"functions": []}
    )
    assert result["results"] == []
