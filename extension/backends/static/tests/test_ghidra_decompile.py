# SPDX-License-Identifier: AGPL-3.0-only
"""Tests du système de détection de décompilateurs via decompilers.json.

Remplace l'ancien test pyghidra (supprimé) — vérifie que _load_decompilers,
_is_decompiler_available_local et list_available_decompilers fonctionnent
correctement avec différentes configurations JSON.
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import (
    _load_decompilers,
    _normalize_decompiler_id,
    list_available_decompilers,
)


class TestLoadDecompilers(unittest.TestCase):
    def _write_config(self, tmp: str, data: dict) -> Path:
        p = Path(tmp) / "decompilers.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        return p

    def test_load_basic_entry(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp,
                {
                    "decompilers": {
                        "mytool": {
                            "label": "My Tool",
                            "detect": "mytool",
                            "command": [
                                "mytool",
                                "--binary",
                                "{binary}",
                                "--addr",
                                "{addr}",
                            ],
                            "output_format": "c",
                        }
                    }
                },
            )
            result = _load_decompilers(cfg)
            self.assertIn("mytool", result)
            self.assertEqual(result["mytool"]["label"], "My Tool")
            self.assertEqual(result["mytool"]["detect"], "mytool")
            self.assertEqual(result["mytool"]["output_format"], "c")

    def test_root_dir_substituted_in_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp,
                {
                    "decompilers": {
                        "ghidra": {
                            "label": "Ghidra",
                            "command": [
                                "python3",
                                "{root_dir}/backends/bridge.py",
                                "--binary",
                                "{binary}",
                            ],
                            "output_format": "json",
                        }
                    }
                },
            )
            result = _load_decompilers(cfg)
            cmd = result["ghidra"]["command"]
            self.assertNotIn("{root_dir}", " ".join(cmd))
            self.assertTrue(any("backends/bridge.py" in part for part in cmd))

    def test_entry_without_command_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp, {"decompilers": {"nodeco": {"label": "No Command"}}}
            )
            result = _load_decompilers(cfg)
            self.assertNotIn("nodeco", result)

    def test_comment_keys_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp,
                {
                    "_comment": "ceci est un commentaire",
                    "decompilers": {
                        "tool_a": {
                            "label": "Tool A",
                            "command": ["tool_a_bin", "--addr", "{addr}", "{binary}"],
                            "output_format": "c",
                        }
                    },
                },
            )
            result = _load_decompilers(cfg)
            self.assertNotIn("_comment", result)
            self.assertIn("tool_a", result)

    def test_missing_config_returns_empty(self):
        result = _load_decompilers(Path("/nonexistent/path/decompilers.json"))
        self.assertEqual(result, {})

    def test_bias_fields_not_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp,
                {
                    "decompilers": {
                        "tool_a": {
                            "label": "Tool A",
                            "command": ["tool_a", "{binary}", "{addr}"],
                            "output_format": "c",
                            "quality_bias": 15,
                            "precision_bias": 20,
                        }
                    }
                },
            )
            result = _load_decompilers(cfg)
            self.assertNotIn("quality_bias", result["tool_a"])
            self.assertNotIn("precision_bias", result["tool_a"])

    def test_support_fields_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = self._write_config(
                tmp,
                {
                    "decompilers": {
                        "tool_a": {
                            "label": "Tool A",
                            "command": ["tool_a", "{binary}", "{addr}"],
                            "supports": {
                                "formats": ["ELF", "MachO"],
                                "architectures": ["x86_64", "ARM64"],
                                "bitness": [64],
                            },
                            "exclude_targets": [
                                {
                                    "format": "macho",
                                    "arch": "arm64",
                                    "reason": "fragile",
                                },
                            ],
                        }
                    }
                },
            )
            result = _load_decompilers(cfg)
        self.assertEqual(result["tool_a"]["supports"]["formats"], ["elf", "macho"])
        self.assertEqual(
            result["tool_a"]["supports"]["architectures"], ["x86_64", "arm64"]
        )
        self.assertEqual(result["tool_a"]["supports"]["bitness"], ["64"])
        self.assertEqual(result["tool_a"]["exclude_targets"][0]["format"], "macho")
        self.assertEqual(result["tool_a"]["exclude_targets"][0]["arch"], "arm64")
        self.assertEqual(result["tool_a"]["exclude_targets"][0]["reason"], "fragile")


class TestIsDecompilerAvailableLocal(unittest.TestCase):
    def test_detect_found_in_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = Path(tmp) / "decompilers.json"
            cfg.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "tool_a": {
                                "label": "Tool A",
                                "detect": "tool_a_bin",
                                "command": [
                                    "tool_a_bin",
                                    "--addr",
                                    "{addr}",
                                    "{binary}",
                                ],
                                "output_format": "c",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            # Simule tool_a présent dans PATH
            with (
                mock.patch(
                    "backends.static.decompile.decompile._load_decompilers",
                    return_value={
                        "tool_a": {
                            "command": ["tool_a_bin", "..."],
                            "detect": "tool_a_bin",
                        }
                    },
                ),
                mock.patch("shutil.which", return_value="/usr/bin/tool_a_bin"),
            ):
                from backends.static.decompile.decompile import (
                    _is_decompiler_available_local,
                )

                self.assertTrue(_is_decompiler_available_local("tool_a"))

    def test_detect_not_found_in_path(self):
        with (
            mock.patch(
                "backends.static.decompile.decompile._load_decompilers",
                return_value={
                    "ghidra": {
                        "command": ["analyzeHeadless", "..."],
                        "detect": "analyzeHeadless",
                    }
                },
            ),
            mock.patch("shutil.which", return_value=None),
        ):
            from backends.static.decompile.decompile import (
                _is_decompiler_available_local,
            )

            self.assertFalse(_is_decompiler_available_local("ghidra"))

    def test_no_detect_field_always_available(self):
        with mock.patch(
            "backends.static.decompile.decompile._load_decompilers",
            return_value={
                "mytool": {
                    "command": ["mytool", "--binary", "{binary}"],
                    # pas de champ "detect"
                }
            },
        ):
            from backends.static.decompile.decompile import (
                _is_decompiler_available_local,
            )

            self.assertTrue(_is_decompiler_available_local("mytool"))


class TestNormalizeDecompilerId(unittest.TestCase):
    def test_lowercase(self):
        self.assertEqual(_normalize_decompiler_id("Ghidra"), "ghidra")

    def test_special_chars_replaced(self):
        self.assertEqual(_normalize_decompiler_id("my tool!"), "my-tool")

    def test_none_returns_empty(self):
        self.assertEqual(_normalize_decompiler_id(None), "")


class TestListAvailableDecompilersReasons(unittest.TestCase):
    def test_unavailable_decompiler_has_reason(self):
        from unittest import mock

        with mock.patch(
            "backends.static.decompile.decompile._load_decompilers",
            return_value={
                "tool_a": {
                    "id": "tool_a",
                    "label": "Tool A",
                    "docker_command": ["run", "{binary}"],
                    "docker_image": "example/tool_a:latest",
                }
            },
        ):
            with mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available_local",
                return_value=False,
            ):
                with mock.patch(
                    "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                    return_value=False,
                ):
                    result = list_available_decompilers("auto")
        meta = result.get("_meta", {})
        self.assertIn("reasons", meta)
        self.assertIn("tool_a", meta["reasons"])
        self.assertIsInstance(meta["reasons"]["tool_a"], str)
        self.assertGreater(len(meta["reasons"]["tool_a"]), 0)

    def test_available_decompiler_has_no_reason(self):
        from unittest import mock

        with mock.patch(
            "backends.static.decompile.decompile._load_decompilers",
            return_value={
                "tool_b": {
                    "id": "tool_b",
                    "label": "Tool B",
                    "docker_command": ["run", "{binary}"],
                    "docker_image": "example/tool_b:latest",
                }
            },
        ):
            with mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available_local",
                return_value=False,
            ):
                with mock.patch(
                    "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                    return_value=True,
                ):
                    result = list_available_decompilers("docker")
        meta = result.get("_meta", {})
        reasons = meta.get("reasons", {})
        self.assertNotIn("tool_b", reasons)

    def test_binary_target_can_mark_backend_unavailable_with_reason(self):
        with mock.patch(
            "backends.static.decompile.decompile._load_decompilers",
            return_value={
                "tool_c": {
                    "id": "tool_c",
                    "label": "Tool C",
                    "docker_command": ["run", "{binary}"],
                    "docker_image": "example/tool_c:latest",
                    "exclude_targets": [
                        {"format": "macho", "arch": "arm64", "reason": "fragile"}
                    ],
                }
            },
        ):
            with mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available_local",
                return_value=False,
            ):
                with mock.patch(
                    "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                    return_value=True,
                ):
                    with mock.patch(
                        "backends.static.decompile.decompile._binary_info",
                        return_value={
                            "format": "macho",
                            "arch": "arm64",
                            "bitness": "64",
                        },
                    ):
                        result = list_available_decompilers(
                            "docker", binary_path="/tmp/demo", full=False
                        )
        self.assertFalse(result["tool_c"])
        self.assertIn("tool_c", result["_meta"]["reasons"])
        self.assertIn("fragile", result["_meta"]["reasons"]["tool_c"])


class TestBinaryInfoAndTokens(unittest.TestCase):
    def test_binary_info_returns_dict(self):
        from backends.static.decompile.decompile import _binary_info

        # Sans lief disponible ou fichier inexistant → retourne des valeurs par défaut
        info = _binary_info("/nonexistent/binary")
        self.assertIn("arch", info)
        self.assertIn("bitness", info)
        self.assertIn("format", info)
        self.assertEqual(info["bitness"], "64")  # valeur par défaut
        self.assertEqual(info["format"], "raw")  # valeur par défaut

    def test_format_command_with_arch_token(self):
        from backends.static.decompile.decompile import _format_custom_command

        with mock.patch(
            "backends.static.decompile.decompile._binary_info",
            return_value={"arch": "x86_64", "bitness": "64", "format": "elf"},
        ):
            result = _format_custom_command(
                [
                    "mytool",
                    "--arch",
                    "{arch}",
                    "--bits",
                    "{bitness}",
                    "--fmt",
                    "{format}",
                    "{binary}",
                ],
                binary_path="/tmp/test.elf",
                addr="0x1000",
            )
        self.assertEqual(result[2], "x86_64")
        self.assertEqual(result[4], "64")
        self.assertEqual(result[6], "elf")
        self.assertEqual(result[7], "/tmp/test.elf")

    def test_format_command_without_arch_token_unchanged(self):
        from backends.static.decompile.decompile import _format_custom_command

        with mock.patch("backends.static.decompile.decompile._binary_info") as mock_bi:
            result = _format_custom_command(
                ["mytool", "{binary}", "--addr", "{addr}"],
                binary_path="/tmp/test",
                addr="0x400",
            )
            mock_bi.assert_not_called()
        self.assertEqual(result, ["mytool", "/tmp/test", "--addr", "0x400"])


class TestOutputFilter(unittest.TestCase):
    def test_output_filter_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "decompilers.json"
            p.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "noisy_tool": {
                                "label": "Noisy Tool",
                                "command": ["noisy_tool", "{binary}"],
                                "output_format": "c",
                                "output_filter": ["^\\[\\*\\]", "^DEBUG:"],
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = _load_decompilers(p)
        self.assertIn("output_filter", result["noisy_tool"])
        self.assertEqual(
            result["noisy_tool"]["output_filter"], ["^\\[\\*\\]", "^DEBUG:"]
        )

    def test_output_filter_strips_matching_lines(self):
        from backends.static.decompile.decompile import (
            _parse_external_decompiler_output,
        )

        raw = "[*] Starting analysis\nDEBUG: loading...\nvoid foo() {\n  return;\n}"
        with mock.patch(
            "backends.static.decompile.decompile._load_decompilers",
            return_value={"noisy": {"output_filter": ["^\\[\\*\\]", "^DEBUG:"]}},
        ):
            result = _parse_external_decompiler_output(
                raw, decompiler="noisy", addr="0x1000", output_format="c"
            )
        self.assertNotIn("[*]", result.get("code", ""))
        self.assertNotIn("DEBUG:", result.get("code", ""))
        self.assertIn("void foo()", result.get("code", ""))

    def test_output_filter_absent_when_not_declared(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "decompilers.json"
            p.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "clean_tool": {
                                "label": "Clean",
                                "command": ["clean", "{binary}"],
                                "output_format": "json",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = _load_decompilers(p)
        self.assertNotIn("output_filter", result["clean_tool"])


class TestHttpEndpoint(unittest.TestCase):
    def test_http_endpoint_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "decompilers.json"
            p.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "ida_server": {
                                "label": "IDA Server",
                                "endpoint": "http://localhost:9090/decompile",
                                "method": "POST",
                                "body_template": '{"addr": "{addr}", "binary_b64": "{binary_b64}"}',
                                "output_format": "json",
                                "timeout": 30,
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = _load_decompilers(p)
        self.assertIn("ida_server", result)
        self.assertEqual(
            result["ida_server"]["endpoint"], "http://localhost:9090/decompile"
        )
        self.assertEqual(result["ida_server"]["method"], "POST")

    def test_run_http_decompiler_sends_request(self):
        from backends.static.decompile.decompile import _run_http_decompiler

        fake_response = json.dumps(
            {"addr": "0x1000", "code": "int foo() { return 0; }", "error": None}
        )
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = fake_response.encode()
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        config = {
            "endpoint": "http://localhost:9090/decompile",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "body_template": '{"addr": "{addr}"}',
            "output_format": "json",
            "timeout": 10,
        }
        with mock.patch("urllib.request.urlopen", return_value=mock_resp) as mock_open:
            result = _run_http_decompiler(
                "ida_server", "/tmp/test.elf", config, addr="0x1000"
            )
        self.assertTrue(mock_open.called)
        self.assertEqual(result.get("code"), "int foo() { return 0; }")
        self.assertIsNone(result.get("error"))
        self.assertEqual(result.get("provider"), "http")

    def test_run_http_decompiler_handles_connection_error(self):
        import urllib.error

        from backends.static.decompile.decompile import _run_http_decompiler

        config = {
            "endpoint": "http://localhost:9090/decompile",
            "method": "POST",
            "body_template": "{}",
            "output_format": "json",
            "timeout": 5,
        }
        with mock.patch(
            "urllib.request.urlopen",
            side_effect=urllib.error.URLError("Connection refused"),
        ):
            result = _run_http_decompiler(
                "ida_server", "/tmp/test.elf", config, addr="0x1000"
            )
        self.assertIsNotNone(result.get("error"))
        self.assertIn("Connection refused", result["error"])
        self.assertEqual(result.get("provider"), "http")

    def test_run_custom_decompiler_routes_to_http(self):
        """Vérifie que _run_custom_decompiler délègue à HTTP si endpoint présent."""
        with (
            mock.patch(
                "backends.static.decompile.decompile._load_custom_decompilers",
                return_value={
                    "ida": {
                        "endpoint": "http://localhost:9090/decompile",
                        "method": "POST",
                        "body_template": "{}",
                        "output_format": "json",
                        "timeout": 10,
                    }
                },
            ),
            mock.patch(
                "backends.static.decompile.decompile._run_http_decompiler",
                return_value={"code": "int f() {}", "error": None, "provider": "http"},
            ) as mock_http,
        ):
            from backends.static.decompile.decompile import _run_custom_decompiler

            result = _run_custom_decompiler("ida", "/tmp/test.elf", addr="0x1000")
        self.assertTrue(mock_http.called)
        self.assertEqual(result.get("provider"), "http")


class TestHttpAuth(unittest.TestCase):
    def test_auth_config_loaded(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "decompilers.json"
            p.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "secured": {
                                "label": "Secured",
                                "endpoint": "http://localhost:9090/decompile",
                                "body_template": "{}",
                                "auth": {
                                    "type": "bearer",
                                    "token_env": "MY_SECRET_TOKEN",
                                },
                                "output_format": "json",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            result = _load_decompilers(p)
        self.assertIn("auth", result["secured"])
        self.assertEqual(result["secured"]["auth"]["type"], "bearer")
        self.assertEqual(result["secured"]["auth"]["token_env"], "MY_SECRET_TOKEN")

    def test_bearer_token_added_to_request(self):
        from backends.static.decompile.decompile import _run_http_decompiler

        fake_response = json.dumps(
            {"addr": "0x1000", "code": "int foo() {}", "error": None}
        )
        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = fake_response.encode()
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        config = {
            "endpoint": "http://localhost:9090/decompile",
            "method": "POST",
            "body_template": "{}",
            "output_format": "json",
            "timeout": 10,
            "auth": {"type": "bearer", "token_env": "TEST_TOKEN"},
        }
        captured_req = {}

        def mock_urlopen(req, timeout=None):
            captured_req["headers"] = dict(req.headers)
            return mock_resp

        with mock.patch.dict("os.environ", {"TEST_TOKEN": "supersecret"}):
            with mock.patch("urllib.request.urlopen", side_effect=mock_urlopen):
                _run_http_decompiler("secured", "/tmp/test.elf", config, addr="0x1000")
        auth_header = captured_req["headers"].get("Authorization", "")
        self.assertIn("Bearer", auth_header)
        self.assertIn("supersecret", auth_header)

    def test_api_key_added_to_custom_header(self):
        from backends.static.decompile.decompile import _run_http_decompiler

        mock_resp = mock.MagicMock()
        mock_resp.read.return_value = b'{"addr":"0x0","code":"","error":null}'
        mock_resp.__enter__ = mock.MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = mock.MagicMock(return_value=False)
        config = {
            "endpoint": "http://api.example.com/decompile",
            "method": "POST",
            "body_template": "{}",
            "output_format": "json",
            "timeout": 10,
            "auth": {
                "type": "api_key",
                "token_env": "API_KEY_VAR",
                "header": "X-API-Key",
            },
        }
        captured_req = {}

        def mock_urlopen(req, timeout=None):
            captured_req["headers"] = dict(req.headers)
            return mock_resp

        with mock.patch.dict("os.environ", {"API_KEY_VAR": "myapikey123"}):
            with mock.patch("urllib.request.urlopen", side_effect=mock_urlopen):
                _run_http_decompiler("api_tool", "/tmp/test.elf", config, addr="0x1000")
        # urllib normalise les noms de headers en title-case
        found = any("myapikey123" in v for v in captured_req["headers"].values())
        self.assertTrue(
            found, f"API key not found in headers: {captured_req['headers']}"
        )

    def test_missing_token_env_returns_error(self):
        import os

        from backends.static.decompile.decompile import _run_http_decompiler

        config = {
            "endpoint": "http://localhost:9090/decompile",
            "method": "POST",
            "body_template": "{}",
            "output_format": "json",
            "timeout": 10,
            "auth": {"type": "bearer", "token_env": "NONEXISTENT_TOKEN_PILE_OU_FACE"},
        }
        os.environ.pop("NONEXISTENT_TOKEN_PILE_OU_FACE", None)
        result = _run_http_decompiler("secured", "/tmp/test.elf", config, addr="0x1000")
        self.assertIsNotNone(result.get("error"))
        self.assertIn("NONEXISTENT_TOKEN_PILE_OU_FACE", result["error"])


if __name__ == "__main__":
    unittest.main()
