import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from backends.mcp.ai_provider import (
    _fetch_models,
    call_provider,
    call_provider_result,
    list_providers,
    set_default_provider,
    set_provider_configuration,
)


class StreamingResponse:
    def __init__(self, lines):
        self.lines = [line.encode() for line in lines]

    def __iter__(self):
        return iter(self.lines)

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


@patch("backends.mcp.ai_provider._fetch_models", return_value=[])
def test_list_providers_returns_all_supported_providers(_fetch_models):
    names = [p["name"] for p in list_providers()["providers"]]
    assert set(names) == {
        "anthropic",
        "openai",
        "mistral",
        "gemini",
        "openrouter",
        "groq",
        "deepseek",
        "ollama",
    }


@patch("backends.mcp.ai_provider._fetch_models", return_value=[])
def test_configured_true_when_key_set(_fetch_models):
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
        ant = next(p for p in list_providers()["providers"] if p["name"] == "anthropic")
        assert ant["configured"] is True


@patch("backends.mcp.ai_provider._fetch_models", return_value=[])
def test_configured_false_when_key_missing(_fetch_models):
    env = {k: v for k, v in os.environ.items() if k != "OPENAI_API_KEY"}
    with patch.dict(os.environ, env, clear=True):
        oai = next(p for p in list_providers()["providers"] if p["name"] == "openai")
        assert oai["configured"] is False


@patch("backends.mcp.ai_provider._fetch_models", return_value=[])
def test_default_provider_from_env(_fetch_models):
    with patch.dict(os.environ, {"POF_DEFAULT_AI_PROVIDER": "mistral"}, clear=False):
        assert list_providers()["default_provider"] == "mistral"


@patch("backends.mcp.ai_provider._fetch_models", return_value=[])
def test_keys_never_returned(_fetch_models):
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-secret"}, clear=False):
        assert "sk-secret" not in json.dumps(list_providers())


def test_unknown_provider_raises():
    with pytest.raises(ValueError, match="Provider inconnu"):
        call_provider("unknown_provider", "prompt", "context", None)


def test_anthropic_call_uses_http(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "content": [{"text": "test response"}],
            "usage": {"input_tokens": 12, "output_tokens": 4},
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: mock_response
    )
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
        result = call_provider("anthropic", "What is this?", "some context", None)
        assert result == "test response"


def test_anthropic_usage_is_normalized(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "content": [{"text": "done"}],
            "usage": {"input_tokens": 20, "output_tokens": 5},
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: mock_response
    )
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
        result = call_provider_result("anthropic", "Prompt", "Context", None)
    assert result["usage"] == {
        "prompt_tokens": 20,
        "completion_tokens": 5,
        "total_tokens": 25,
        "request_prompt_tokens": 20,
        "request_completion_tokens": 5,
        "request_total_tokens": 25,
    }


def test_openai_compatible_usage_is_normalized(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "choices": [{"message": {"content": "done"}}],
            "usage": {
                "prompt_tokens": 30,
                "completion_tokens": 7,
                "total_tokens": 37,
            },
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: mock_response
    )
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
        result = call_provider_result("openai", "Prompt", "Context", "gpt-4o")
    assert result["text"] == "done"
    assert result["usage"]["total_tokens"] == 37


def test_gemini_usage_is_normalized(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "candidates": [{"content": {"parts": [{"text": "done"}]}}],
            "usageMetadata": {
                "promptTokenCount": 11,
                "candidatesTokenCount": 6,
                "totalTokenCount": 17,
            },
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: mock_response
    )
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}, clear=False):
        result = call_provider_result("gemini", "Prompt", "Context", "gemini-2.5-flash")
    assert result["text"] == "done"
    assert result["usage"]["total_tokens"] == 17


def test_openai_compatible_streams_text_and_usage(monkeypatch):
    import urllib.request

    response = StreamingResponse(
        [
            'data: {"choices":[{"delta":{"content":"Bonjour"}}]}\n',
            "\n",
            'data: {"choices":[{"delta":{"content":" monde"}}]}\n',
            "\n",
            (
                'data: {"choices":[],"usage":{"prompt_tokens":10,'
                '"completion_tokens":2,"total_tokens":12}}\n'
            ),
            "\n",
            "data: [DONE]\n",
            "\n",
        ]
    )
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    chunks = []
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
        result = call_provider_result(
            "openai",
            "Prompt",
            "Context",
            "gpt-4o",
            chunks.append,
        )

    payload = json.loads(captured_request["request"].data)
    assert payload["stream"] is True
    assert payload["stream_options"] == {"include_usage": True}
    assert chunks == ["Bonjour", " monde"]
    assert result["text"] == "Bonjour monde"
    assert result["usage"]["total_tokens"] == 12


def test_openai_compatible_forwards_generation_options(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"choices": [{"message": {"content": "done"}}], "usage": {}}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with patch.dict(os.environ, {"OPENAI_API_KEY": "sk-test"}, clear=False):
        call_provider_result(
            "openai",
            "Prompt",
            "Context",
            "gpt-4o",
            generation_options={
                "temperature": 0.3,
                "top_p": 0.8,
                "max_tokens": 1234,
            },
        )

    payload = json.loads(captured_request["request"].data)
    assert payload["temperature"] == 0.3
    assert payload["top_p"] == 0.8
    assert payload["max_tokens"] == 1234


def test_gemini_forwards_generation_options(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": "done"}]}}]}
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}, clear=False):
        call_provider_result(
            "gemini",
            "Prompt",
            "Context",
            "gemini-2.5-flash",
            generation_options={
                "temperature": 0.5,
                "top_p": 0.7,
                "max_tokens": 2048,
            },
        )

    payload = json.loads(captured_request["request"].data)
    assert payload["generationConfig"] == {
        "temperature": 0.5,
        "topP": 0.7,
        "maxOutputTokens": 2048,
    }


@pytest.mark.parametrize(
    "provider",
    ["openai", "mistral", "openrouter", "groq", "deepseek"],
)
def test_openai_compatible_streams_request_usage_for_every_provider(
    monkeypatch,
    provider,
):
    import urllib.request

    response = StreamingResponse(
        [
            "data: [DONE]\n",
            "\n",
        ]
    )
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    call_provider_result(provider, "Prompt", "Context", "model", lambda _chunk: None)

    payload = json.loads(captured_request["request"].data)
    assert payload["stream_options"] == {"include_usage": True}


def test_anthropic_streams_text_and_usage(monkeypatch):
    import urllib.request

    response = StreamingResponse(
        [
            ("event: message_start\n"),
            (
                'data: {"type":"message_start","message":{"usage":{"input_tokens":14}}}\n'
            ),
            "\n",
            "event: content_block_delta\n",
            (
                'data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"Salut"}}\n'
            ),
            "\n",
            "event: message_delta\n",
            ('data: {"type":"message_delta","usage":{"output_tokens":3}}\n'),
            "\n",
        ]
    )
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: response)
    chunks = []
    with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}, clear=False):
        result = call_provider_result(
            "anthropic",
            "Prompt",
            "Context",
            "claude-test",
            chunks.append,
        )

    assert chunks == ["Salut"]
    assert result["text"] == "Salut"
    assert result["usage"]["prompt_tokens"] == 14
    assert result["usage"]["completion_tokens"] == 3


def test_gemini_streams_text_and_usage(monkeypatch):
    import urllib.request

    response = StreamingResponse(
        [
            'data: {"candidates":[{"content":{"parts":[{"text":"Bon"}]}}]}\n',
            "\n",
            (
                'data: {"candidates":[{"content":{"parts":[{"text":"jour"}]}}],'
                '"usageMetadata":{"promptTokenCount":8,'
                '"candidatesTokenCount":2,"totalTokenCount":10}}\n'
            ),
            "\n",
        ]
    )
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    chunks = []
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test"}, clear=False):
        result = call_provider_result(
            "gemini",
            "Prompt",
            "Context",
            "gemini-test",
            chunks.append,
        )

    request = captured_request["request"]
    assert request.full_url.endswith(":streamGenerateContent?alt=sse")
    assert "key=" not in request.full_url
    assert request.get_header("X-goog-api-key") == "test"
    assert chunks == ["Bon", "jour"]
    assert result["text"] == "Bonjour"
    assert result["usage"]["total_tokens"] == 10


def test_set_default_provider_persists_env(monkeypatch):
    write_env = MagicMock()
    monkeypatch.setattr("backends.mcp.env_loader._write_env_key", write_env)
    result = set_default_provider("groq")
    assert result == {"ok": True, "default_provider": "groq"}
    write_env.assert_called_once_with("POF_DEFAULT_AI_PROVIDER", "groq")


SECRET_KEY = "sk-test-secret-value"


def _redirect_env_file(monkeypatch, env_file):
    from backends.mcp import env_loader

    original = env_loader._write_env_key
    monkeypatch.setattr(
        env_loader,
        "_write_env_key",
        lambda key, value: original(key, value, env_file),
    )


def test_set_provider_configuration_persists_reloadable_key(monkeypatch, tmp_path):
    from backends.mcp.env_loader import _load_env_file

    env_file = tmp_path / "pof" / ".env"
    _redirect_env_file(monkeypatch, env_file)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    result = set_provider_configuration("anthropic", SECRET_KEY, None)
    assert result["ok"] is True
    assert SECRET_KEY not in json.dumps(result)
    monkeypatch.delenv("ANTHROPIC_API_KEY")
    _load_env_file(env_file)
    assert os.environ["ANTHROPIC_API_KEY"] == SECRET_KEY


def test_set_provider_configuration_error_hides_key(monkeypatch, tmp_path, caplog):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("")
    _redirect_env_file(monkeypatch, blocker / ".env")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    with caplog.at_level(logging.DEBUG):
        result = set_provider_configuration("openai", SECRET_KEY, None)
    assert result["ok"] is False
    assert "OPENAI_API_KEY" in result["error"]
    assert SECRET_KEY not in result["error"]
    assert SECRET_KEY not in caplog.text
    assert "OPENAI_API_KEY" not in os.environ


def test_openai_model_list_excludes_non_chat_models(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "data": [
                {"id": "gpt-5"},
                {"id": "gpt-4o-mini-transcribe"},
                {"id": "gpt-image-1"},
                {"id": "text-embedding-3-small"},
            ]
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    monkeypatch.setattr(
        urllib.request, "urlopen", lambda req, timeout=None: mock_response
    )
    assert _fetch_models("openai", "sk-test") == ["gpt-5"]


def test_gemini_model_list_uses_api_key_header(monkeypatch):
    import urllib.request

    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps(
        {
            "models": [
                {
                    "name": "models/gemini-test",
                    "supportedGenerationMethods": ["generateContent"],
                },
                {
                    "name": "models/gemini-embed",
                    "supportedGenerationMethods": ["embedContent"],
                },
            ]
        }
    ).encode()
    mock_response.__enter__ = lambda s: s
    mock_response.__exit__ = MagicMock(return_value=False)
    captured_request = {}

    def fake_urlopen(req, timeout=None):
        captured_request["request"] = req
        return mock_response

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)

    assert _fetch_models("gemini", "test") == ["gemini-test"]
    request = captured_request["request"]
    assert request.full_url == "https://generativelanguage.googleapis.com/v1beta/models"
    assert "key=" not in request.full_url
    assert request.get_header("X-goog-api-key") == "test"


def test_cli_set_failure_reports_the_reason_on_stderr_without_the_key(tmp_path):
    """The extension host only shows stderr when the CLI fails (sharedHandlers)."""
    home = tmp_path / "home"
    home.mkdir()
    (home / ".pile-ou-face").write_text("")  # a file where the config dir should be
    env = {**os.environ, "HOME": str(home), "USERPROFILE": str(home)}
    env.pop("OPENAI_API_KEY", None)
    extension_root = Path(__file__).resolve().parents[3]
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "backends.mcp.ai_provider",
            "set",
            "--provider",
            "openai",
            "--api-key-stdin",
        ],
        input=f"{SECRET_KEY}\n",
        capture_output=True,
        text=True,
        cwd=extension_root,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 1
    assert "Cannot save OPENAI_API_KEY" in proc.stderr
    assert SECRET_KEY not in proc.stderr
    assert SECRET_KEY not in proc.stdout
    assert json.loads(proc.stdout)["ok"] is False
