import json
from concurrent.futures import Future, ThreadPoolExecutor
from functools import partial
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Callable, Iterator

TokenCallback = Callable[[str], None]

# Load ~/.pile-ou-face/.env so saved API keys are visible to os.environ
_POF_ENV = Path.home() / ".pile-ou-face" / ".env"
if _POF_ENV.is_file():
    for _line in _POF_ENV.read_text(encoding="utf-8").splitlines():
        _line = _line.strip()
        if not _line or _line.startswith("#") or "=" not in _line:
            continue
        _k, _, _v = _line.partition("=")
        _k = _k.strip()
        _v = _v.strip().strip('"').strip("'")
        if _k and _k not in os.environ:
            os.environ[_k] = _v

_PROVIDER_ENV_KEYS: dict[str, str] = {
    "anthropic": "ANTHROPIC_API_KEY",
    "openai": "OPENAI_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "gemini": "GEMINI_API_KEY",
    "openrouter": "OPENROUTER_API_KEY",
    "groq": "GROQ_API_KEY",
    "deepseek": "DEEPSEEK_API_KEY",
}

_OPENAI_COMPATIBLE: dict[str, dict[str, str]] = {
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "default_model": "gpt-4o",
    },
    "mistral": {
        "base_url": "https://api.mistral.ai/v1",
        "default_model": "mistral-large-latest",
    },
    "openrouter": {
        "base_url": "https://openrouter.ai/api/v1",
        "default_model": "openai/gpt-4o-mini",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "default_model": "llama-3.3-70b-versatile",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com",
        "default_model": "deepseek-chat",
    },
}


def _provider_model_env(provider: str) -> str:
    return "OLLAMA_MODEL" if provider == "ollama" else f"POF_{provider.upper()}_MODEL"


def _bearer_request(url: str, api_key: str) -> urllib.request.Request:
    return urllib.request.Request(
        url,
        headers={"Authorization": f"Bearer {api_key}"},
    )


def _fetch_models(name: str, api_key: str = "", base_url: str = "") -> list[str]:
    """Fetch available models from the provider API. Returns [] on any error."""
    if name == "anthropic":
        req = urllib.request.Request(
            "https://api.anthropic.com/v1/models",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01"},
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            return [m["id"] for m in json.loads(resp.read()).get("data", [])]

    if name in _OPENAI_COMPATIBLE:
        req = _bearer_request(
            f"{_OPENAI_COMPATIBLE[name]['base_url']}/models",
            api_key,
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            ids = [m["id"] for m in json.loads(resp.read()).get("data", [])]
        if name == "openai":
            keep = ("gpt-", "o1", "o3", "o4", "chatgpt-")
            exclude = (
                "audio",
                "image",
                "realtime",
                "search",
                "transcribe",
                "tts",
            )
            ids = [
                m
                for m in ids
                if any(m.startswith(p) for p in keep) and not any(marker in m for marker in exclude)
            ]
        elif name == "mistral":
            ids = [
                m
                for m in ids
                if not any(marker in m.lower() for marker in ("embed", "moderation", "ocr"))
            ]
        return sorted(ids)

    if name == "gemini":
        req = urllib.request.Request(
            f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}",
        )
        with urllib.request.urlopen(req, timeout=8) as resp:
            models = json.loads(resp.read()).get("models", [])
        return sorted(
            str(m.get("name", "")).removeprefix("models/")
            for m in models
            if "generateContent" in m.get("supportedGenerationMethods", [])
        )

    if name == "ollama":
        req = urllib.request.Request(f"{base_url}/api/tags")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return [m["name"] for m in json.loads(resp.read()).get("models", [])]

    return []


def list_providers() -> dict[str, Any]:
    """Return configured status and available models for all AI providers."""
    ollama_base = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")

    # Collect per-provider config
    entries: list[tuple[str, str, bool, str | None]] = []
    for name, env_key in _PROVIDER_ENV_KEYS.items():
        api_key = os.environ.get(env_key, "")
        configured = bool(api_key)
        model_env = _provider_model_env(name)
        model = os.environ.get(model_env) if configured else None
        entries.append((name, api_key, configured, model))

    # Fetch models in parallel (only for configured cloud providers + always ollama)
    futures: dict[str, Future[list[str]]] = {}
    with ThreadPoolExecutor(max_workers=len(entries) + 1) as ex:
        for name, api_key, configured, _ in entries:
            if configured:
                futures[name] = ex.submit(_fetch_models, name, api_key)
        futures["ollama"] = ex.submit(_fetch_models, "ollama", base_url=ollama_base)

    def _get(name: str) -> list[str] | None:
        fut = futures.get(name)
        if fut is None:
            return None
        try:
            return fut.result(timeout=10) or None
        except Exception:
            return None

    providers: list[dict[str, Any]] = []
    for name, _, configured, model in entries:
        models = _get(name)
        valid = bool(models)  # True only if API call succeeded with a real key
        resolved_model = model or (models[0] if models else None)
        providers.append(
            {
                "name": name,
                "kind": "cloud",
                "configured": configured,
                "valid": valid,
                "model": resolved_model,
                "models": models,
            }
        )

    ollama_models = _get("ollama")
    providers.append(
        {
            "name": "ollama",
            "kind": "local",
            "configured": True,
            "valid": bool(ollama_models),
            "base_url": ollama_base,
            "model": os.environ.get("OLLAMA_MODEL")
            or (ollama_models[0] if ollama_models else "qwen3:8b"),
            "models": ollama_models,
        }
    )
    return {
        "providers": providers,
        "default_provider": os.environ.get("POF_DEFAULT_AI_PROVIDER", "ollama"),
    }


def _normalize_usage(
    prompt_tokens: Any = 0,
    completion_tokens: Any = 0,
    total_tokens: Any = 0,
) -> dict[str, int]:
    prompt_count = max(0, int(prompt_tokens or 0))
    completion_count = max(0, int(completion_tokens or 0))
    total_count = max(0, int(total_tokens or 0)) or prompt_count + completion_count
    return {
        "prompt_tokens": prompt_count,
        "completion_tokens": completion_count,
        "total_tokens": total_count,
        "request_prompt_tokens": prompt_count,
        "request_completion_tokens": completion_count,
        "request_total_tokens": total_count,
    }


def _iter_sse_data(response: Any) -> Iterator[str]:
    """Yield complete ``data:`` payloads from an SSE HTTP response."""
    data_lines: list[str] = []
    for raw_line in response:
        line = raw_line.decode("utf-8").rstrip("\r\n")
        if not line:
            if data_lines:
                yield "\n".join(data_lines)
                data_lines = []
            continue
        if line.startswith("data:"):
            data_lines.append(line[5:].lstrip())
    if data_lines:
        yield "\n".join(data_lines)


def _emit_token(on_token: TokenCallback | None, chunks: list[str], text: Any) -> None:
    if not isinstance(text, str) or not text:
        return
    chunks.append(text)
    if on_token is not None:
        on_token(text)


def _openai_delta_text(delta: dict[str, Any]) -> str:
    content = delta.get("content")
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "".join(
            str(chunk.get("text", ""))
            for chunk in content
            if isinstance(chunk, dict) and chunk.get("type") == "text"
        )
    return ""


def _anthropic_complete(
    prompt: str,
    context: str,
    model: str | None,
    on_token: TokenCallback | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    model = model or os.environ.get("POF_ANTHROPIC_MODEL", "claude-opus-4-6")
    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    options = generation_options or {}
    payload = {
        "model": model,
        "max_tokens": int(options.get("max_tokens", 4096)),
        "system": f"You are a binary analysis assistant. Context:\n{context}",
        "messages": [{"role": "user", "content": prompt}],
        "stream": on_token is not None,
    }
    if "temperature" in options:
        payload["temperature"] = float(options["temperature"])
    if "top_p" in options:
        payload["top_p"] = float(options["top_p"])
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(payload).encode(),
        headers={
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        if on_token is None:
            data = json.loads(resp.read())
        else:
            chunks: list[str] = []
            input_tokens = 0
            output_tokens = 0
            for payload_data in _iter_sse_data(resp):
                event = json.loads(payload_data)
                event_type = event.get("type")
                if event_type == "message_start":
                    input_tokens = (
                        event.get("message", {})
                        .get("usage", {})
                        .get(
                            "input_tokens",
                            input_tokens,
                        )
                    )
                elif event_type == "content_block_delta":
                    delta = event.get("delta", {})
                    if delta.get("type") == "text_delta":
                        _emit_token(on_token, chunks, delta.get("text"))
                elif event_type == "message_delta":
                    output_tokens = event.get("usage", {}).get(
                        "output_tokens",
                        output_tokens,
                    )
                elif event_type == "error":
                    error = event.get("error", {})
                    raise RuntimeError(error.get("message") or "Erreur de streaming Anthropic")
            return {
                "text": "".join(chunks),
                "usage": _normalize_usage(input_tokens, output_tokens),
            }
    usage = data.get("usage", {})
    return {
        "text": data["content"][0]["text"],
        "usage": _normalize_usage(
            usage.get("input_tokens"),
            usage.get("output_tokens"),
        ),
    }


def _openai_compatible_complete(
    provider: str,
    prompt: str,
    context: str,
    model: str | None,
    on_token: TokenCallback | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    spec = _OPENAI_COMPATIBLE[provider]
    model = model or os.environ.get(
        f"POF_{provider.upper()}_MODEL",
        spec["default_model"],
    )
    api_key = os.environ.get(_PROVIDER_ENV_KEYS[provider], "")
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": f"Binary analysis assistant. Context:\n{context}"},
            {"role": "user", "content": prompt},
        ],
        "stream": on_token is not None,
    }
    options = generation_options or {}
    if "temperature" in options:
        payload["temperature"] = float(options["temperature"])
    if "top_p" in options:
        payload["top_p"] = float(options["top_p"])
    if "max_tokens" in options:
        payload["max_tokens"] = int(options["max_tokens"])
    if on_token is not None:
        payload["stream_options"] = {"include_usage": True}
    req = urllib.request.Request(
        f"{spec['base_url']}/chat/completions",
        data=json.dumps(payload).encode(),
        headers={"Authorization": f"Bearer {api_key}", "content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        if on_token is None:
            data = json.loads(resp.read())
        else:
            chunks: list[str] = []
            usage: dict[str, Any] = {}
            for payload_data in _iter_sse_data(resp):
                if payload_data == "[DONE]":
                    break
                event = json.loads(payload_data)
                if event.get("error"):
                    error = event["error"]
                    message = error.get("message") if isinstance(error, dict) else str(error)
                    raise RuntimeError(message or f"Erreur de streaming {provider}")
                choices = event.get("choices") or []
                if choices:
                    _emit_token(
                        on_token,
                        chunks,
                        _openai_delta_text(choices[0].get("delta", {})),
                    )
                if event.get("usage"):
                    usage = event["usage"]
            return {
                "text": "".join(chunks),
                "usage": _normalize_usage(
                    usage.get("prompt_tokens"),
                    usage.get("completion_tokens"),
                    usage.get("total_tokens"),
                ),
            }
    usage = data.get("usage", {})
    return {
        "text": data["choices"][0]["message"]["content"],
        "usage": _normalize_usage(
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
            usage.get("total_tokens"),
        ),
    }


def _gemini_complete(
    prompt: str,
    context: str,
    model: str | None,
    on_token: TokenCallback | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    model = model or os.environ.get("POF_GEMINI_MODEL", "gemini-2.5-flash")
    api_key = os.environ.get("GEMINI_API_KEY", "")
    payload = {
        "systemInstruction": {
            "parts": [{"text": f"Binary analysis assistant. Context:\n{context}"}],
        },
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
    }
    options = generation_options or {}
    generation_config: dict[str, Any] = {}
    if "temperature" in options:
        generation_config["temperature"] = float(options["temperature"])
    if "top_p" in options:
        generation_config["topP"] = float(options["top_p"])
    if "max_tokens" in options:
        generation_config["maxOutputTokens"] = int(options["max_tokens"])
    if generation_config:
        payload["generationConfig"] = generation_config
    req = urllib.request.Request(
        (
            "https://generativelanguage.googleapis.com/v1beta/models/"
            f"{model}:{'streamGenerateContent?alt=sse&' if on_token else 'generateContent?'}"
            f"key={api_key}"
        ),
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        if on_token is None:
            data = json.loads(resp.read())
        else:
            chunks: list[str] = []
            usage: dict[str, Any] = {}
            for payload_data in _iter_sse_data(resp):
                event = json.loads(payload_data)
                if event.get("error"):
                    error = event["error"]
                    message = error.get("message") if isinstance(error, dict) else str(error)
                    raise RuntimeError(message or "Erreur de streaming Gemini")
                candidates = event.get("candidates") or []
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    for part in parts:
                        _emit_token(on_token, chunks, part.get("text"))
                if event.get("usageMetadata"):
                    usage = event["usageMetadata"]
            return {
                "text": "".join(chunks),
                "usage": _normalize_usage(
                    usage.get("promptTokenCount"),
                    usage.get("candidatesTokenCount"),
                    usage.get("totalTokenCount"),
                ),
            }
    parts = data.get("candidates", [{}])[0].get("content", {}).get("parts", [])
    text = "".join(str(part.get("text", "")) for part in parts)
    usage = data.get("usageMetadata", {})
    return {
        "text": text,
        "usage": _normalize_usage(
            usage.get("promptTokenCount"),
            usage.get("candidatesTokenCount"),
            usage.get("totalTokenCount"),
        ),
    }


def _ollama_complete(
    prompt: str,
    context: str,
    model: str | None,
    on_token: TokenCallback | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base_url = os.environ.get("OLLAMA_BASE_URL", "http://127.0.0.1:11434")
    model = model or os.environ.get("OLLAMA_MODEL", "qwen3:8b")
    payload = {
        "model": model,
        "prompt": f"Context:\n{context}\n\n{prompt}",
        "stream": on_token is not None,
    }
    options = generation_options or {}
    ollama_options: dict[str, Any] = {}
    if "temperature" in options:
        ollama_options["temperature"] = float(options["temperature"])
    if "top_p" in options:
        ollama_options["top_p"] = float(options["top_p"])
    if "max_tokens" in options:
        ollama_options["num_predict"] = int(options["max_tokens"])
    if ollama_options:
        payload["options"] = ollama_options
    req = urllib.request.Request(
        f"{base_url}/api/generate",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        if on_token is None:
            data = json.loads(resp.read())
        else:
            chunks: list[str] = []
            final: dict[str, Any] = {}
            for raw_line in resp:
                if not raw_line.strip():
                    continue
                event = json.loads(raw_line)
                _emit_token(on_token, chunks, event.get("response"))
                if event.get("done"):
                    final = event
            return {
                "text": "".join(chunks),
                "usage": _normalize_usage(
                    final.get("prompt_eval_count"),
                    final.get("eval_count"),
                ),
            }
    return {
        "text": data.get("response", ""),
        "usage": _normalize_usage(
            data.get("prompt_eval_count"),
            data.get("eval_count"),
        ),
    }


_PROVIDERS: dict[str, Any] = {
    "anthropic": _anthropic_complete,
    **{name: partial(_openai_compatible_complete, name) for name in _OPENAI_COMPATIBLE},
    "gemini": _gemini_complete,
    "ollama": _ollama_complete,
}


def _http_error_message(exc: urllib.error.HTTPError) -> str:
    """Extract a human-readable message from an HTTPError response body."""
    try:
        body = json.loads(exc.read())
        err = body.get("error")
        if isinstance(err, dict):
            return err.get("message") or err.get("type") or str(exc)
        if isinstance(err, str):
            return err
        # Anthropic wraps errors differently sometimes
        return body.get("message") or str(exc)
    except Exception:
        return str(exc)


def call_provider_result(
    provider: str,
    prompt: str,
    context: str,
    model: str | None,
    on_token: TokenCallback | None = None,
    generation_options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Call the specified AI provider and return the text response.

    Raises ValueError for unknown provider names.
    Raises RuntimeError with a readable message on HTTP errors.
    """
    fn = _PROVIDERS.get(provider)
    if fn is None:
        raise ValueError(f"Provider inconnu: {provider}")
    try:
        result = fn(prompt, context, model, on_token, generation_options)
        if not isinstance(result, dict):
            return {"text": str(result), "usage": _normalize_usage()}
        return {
            "text": str(result.get("text", "")),
            "usage": result.get("usage", _normalize_usage()),
        }
    except urllib.error.HTTPError as exc:
        raise RuntimeError(f"HTTP {exc.code}: {_http_error_message(exc)}") from exc


def call_provider(provider: str, prompt: str, context: str, model: str | None) -> str:
    """Backward-compatible text-only provider call."""
    return call_provider_result(provider, prompt, context, model)["text"]


def set_provider_configuration(
    provider: str,
    api_key: str,
    model: str | None,
) -> dict[str, Any]:
    """Persist api_key and optional model for a provider to ~/.pile-ou-face/.env."""
    import sys

    ROOT = __import__("os").path.abspath(
        __import__("os").path.join(__import__("os").path.dirname(__file__), "..", "..")
    )
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    from backends.mcp.env_loader import _write_env_key  # type: ignore[import]

    known = set(_PROVIDER_ENV_KEYS) | {"ollama"}
    if provider not in known:
        return {"ok": False, "error": f"Unknown provider: {provider}"}
    if provider in _PROVIDER_ENV_KEYS and api_key:
        env_key = _PROVIDER_ENV_KEYS[provider]
        _write_env_key(env_key, api_key)
        os.environ[env_key] = api_key
    if model:
        model_env = _provider_model_env(provider)
        _write_env_key(model_env, model)
        os.environ[model_env] = model
    return {"ok": True, "provider": provider, "written_to": "~/.pile-ou-face/.env"}


def set_default_provider(provider: str) -> dict[str, Any]:
    if provider not in _PROVIDERS:
        return {"ok": False, "error": f"Unknown provider: {provider}"}
    from backends.mcp.env_loader import _write_env_key

    _write_env_key("POF_DEFAULT_AI_PROVIDER", provider)
    os.environ["POF_DEFAULT_AI_PROVIDER"] = provider
    return {"ok": True, "default_provider": provider}


if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(description="AI provider CLI helper for Pile ou Face")
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("list", help="List configured providers (JSON on stdout)")

    p_set = sub.add_parser("set", help="Save API key and model for a provider")
    p_set.add_argument("--provider", required=True)
    p_set.add_argument("--api-key", default="")
    p_set.add_argument("--api-key-stdin", action="store_true", help="Read API key from stdin")
    p_set.add_argument("--model", default=None)

    p_call = sub.add_parser("call", help="Call a provider with a prompt read from stdin")
    p_call.add_argument("--provider", required=True)
    p_call.add_argument("--model", default=None)
    p_call.add_argument("--context", default="", help="System context / instructions")
    p_call.add_argument("--temperature", type=float, default=None)
    p_call.add_argument("--top-p", type=float, default=None)
    p_call.add_argument("--max-tokens", type=int, default=None)
    p_call.add_argument(
        "--stream-output",
        action="store_true",
        help="Write token and completion events as NDJSON",
    )

    p_default = sub.add_parser("set-default", help="Save the default AI provider")
    p_default.add_argument("--provider", required=True)

    args = parser.parse_args()
    if args.cmd == "list":
        print(json.dumps({"ok": True, **list_providers()}))
    elif args.cmd == "set":
        api_key = sys.stdin.readline().rstrip("\n") if args.api_key_stdin else args.api_key
        result = set_provider_configuration(args.provider, api_key, args.model)
        print(json.dumps(result))
        if not result.get("ok"):
            sys.exit(1)
    elif args.cmd == "call":
        prompt = sys.stdin.read().strip()
        if not prompt:
            event = {"ok": False, "error": "Prompt vide"}
            if args.stream_output:
                event["type"] = "error"
            print(json.dumps(event))
            sys.exit(1)

        def emit_event(event: dict[str, Any]) -> None:
            print(json.dumps(event), flush=True)

        try:
            on_token = lambda content: (
                emit_event({"type": "token", "content": content}) if args.stream_output else None
            )
            generation_options = {
                key: value
                for key, value in {
                    "temperature": args.temperature,
                    "top_p": args.top_p,
                    "max_tokens": args.max_tokens,
                }.items()
                if value is not None
            }
            result = call_provider_result(
                args.provider,
                prompt,
                args.context,
                args.model or None,
                on_token,
                generation_options,
            )
            if args.stream_output:
                emit_event({"type": "done", "ok": True, **result})
            else:
                print(json.dumps({"ok": True, **result}))
        except Exception as exc:
            if args.stream_output:
                emit_event({"type": "error", "ok": False, "error": str(exc)})
            else:
                print(json.dumps({"ok": False, "error": str(exc)}))
            sys.exit(1)
    elif args.cmd == "set-default":
        result = set_default_provider(args.provider)
        print(json.dumps(result))
        if not result.get("ok"):
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
