# SPDX-License-Identifier: AGPL-3.0-only
"""CodeQL py/clear-text-logging-sensitive-data #1/#2: the HTTP decompiler error printed by
decompile/__main__.py names the missing environment variable, never a credential value."""

import json
import urllib.error
from unittest import mock

import pytest

from backends.static.decompile.decompile import _run_http_decompiler

PASSWORD = "s3cret-password-value"
USER = "alice-user-value"
TOKEN = "t0ken-value"
CONFIG = {
    "endpoint": "http://127.0.0.1:9/decompile",
    "method": "POST",
    "body_template": '{"addr": "{addr}"}',
    "output_format": "json",
    "timeout": 1,
}


def _call(auth, monkeypatch, env):
    for name in ("POF_TEST_USER", "POF_TEST_PASSWORD", "POF_TEST_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    return _run_http_decompiler(
        "remote", "/tmp/sample.elf", {**CONFIG, "auth": auth}, addr="0x1000"
    )


BASIC = {
    "type": "basic",
    "user_env": "POF_TEST_USER",
    "password_env": "POF_TEST_PASSWORD",
}


@pytest.mark.parametrize(
    ("auth", "env", "missing"),
    [
        (BASIC, {"POF_TEST_USER": USER}, "POF_TEST_PASSWORD"),
        (BASIC, {"POF_TEST_PASSWORD": PASSWORD}, "POF_TEST_USER"),
        ({"type": "bearer", "token_env": "POF_TEST_TOKEN"}, {}, "POF_TEST_TOKEN"),
    ],
)
def test_missing_credential_error_names_the_variable_only(
    auth, env, missing, monkeypatch
):
    result = _call(auth, monkeypatch, env)
    serialized = json.dumps(result)
    assert missing in result["error"]
    for secret in (PASSWORD, USER, TOKEN):
        assert secret not in serialized


def test_transport_error_never_echoes_credentials(monkeypatch):
    def refuse(request, *args, **kwargs):
        # The credentials are present in the request headers; the error must not carry them.
        assert request.get_header("Authorization", "").startswith("Basic ")
        raise urllib.error.URLError("connection refused")

    monkeypatch.setattr("urllib.request.urlopen", refuse)
    result = _call(
        BASIC, monkeypatch, {"POF_TEST_USER": USER, "POF_TEST_PASSWORD": PASSWORD}
    )
    serialized = json.dumps(result)
    assert result["error"]
    assert PASSWORD not in serialized and USER not in serialized


def test_http_error_body_is_not_a_channel_for_the_authorization_header(monkeypatch):
    def reject(request, *args, **kwargs):
        raise urllib.error.HTTPError(
            request.full_url, 401, "Unauthorized", hdrs=None, fp=None
        )

    monkeypatch.setattr("urllib.request.urlopen", reject)
    with mock.patch.dict("os.environ", {}, clear=False):
        result = _call(
            BASIC, monkeypatch, {"POF_TEST_USER": USER, "POF_TEST_PASSWORD": PASSWORD}
        )
    assert PASSWORD not in json.dumps(result)
