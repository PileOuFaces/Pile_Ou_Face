# SPDX-License-Identifier: AGPL-3.0-only
# backends/static/tests/test_decompile.py
import io
import json
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.decompile.decompile import (
    _decompiler_target_support,
    _docker_missing_image_error,
    _get_decompiler_docker_image,
    _load_custom_decompilers,
    _parse_c_like_function_blocks,
    _preferred_docker_platform_for_decompiler,
    _resolve_function_target,
    _run_custom_decompiler,
    _run_custom_decompiler_in_docker,
    _score_decompile_code,
    decompile_binary,
    decompile_function,
    list_available_decompilers,
)


class TestDecompile(unittest.TestCase):
    def test_nonexistent_file_returns_error(self):
        r = decompile_function("/nonexistent/binary", "0x401000")
        self.assertIn("error", r)
        self.assertIsNotNone(r["error"])

    def test_result_has_required_fields(self):
        r = decompile_function("/nonexistent/binary", "0x401000")
        for field in ("addr", "code", "error"):
            self.assertIn(field, r)

    def test_binary_result_has_required_fields(self):
        r = decompile_binary("/nonexistent/binary")
        for field in ("functions", "error"):
            self.assertIn(field, r)

    def test_builtin_docker_image_defaults_to_per_backend_image(self):
        self.assertEqual(
            _get_decompiler_docker_image("retdec"),
            "pile-ou-face/decompiler-retdec:latest",
        )

    def test_missing_builtin_docker_image_error_suggests_make(self):
        error = _docker_missing_image_error(
            "retdec", "pile-ou-face/decompiler-retdec:latest"
        )
        self.assertIn("make decompiler-docker-build DECOMPILER=retdec", error)
        self.assertIn("POF_DECOMPILER_IMAGE_RETDEC", error)

    def test_builtin_docker_run_reports_missing_image_helpfully(self):
        missing_stderr = (
            "Unable to find image 'pile-ou-face/decompiler-retdec:latest' locally\n"
            "docker: Error response from daemon: pull access denied for pile-ou-face/decompiler-retdec, "
            "repository does not exist or may require 'docker login': denied: requested access to the resource is denied"
        )
        completed = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=125,
            stdout="",
            stderr=missing_stderr,
        )
        with (
            mock.patch(
                "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                return_value=True,
            ),
            mock.patch(
                "backends.static.decompile.decompile.subprocess.run",
                return_value=completed,
            ),
        ):
            result = _run_custom_decompiler_in_docker(
                "retdec", "/bin/ls", addr="0x401000"
            )
        self.assertIn(
            "make decompiler-docker-build DECOMPILER=retdec", result.get("error", "")
        )
        self.assertEqual(
            result.get("docker_image"), "pile-ou-face/decompiler-retdec:latest"
        )

    def test_builtin_docker_run_uses_real_container_result_even_if_probe_is_unreliable(
        self,
    ):
        completed = subprocess.CompletedProcess(
            args=["docker", "run"],
            returncode=0,
            stdout=json.dumps(
                {
                    "addr": "0x401000",
                    "code": "int add(){ return 5; }",
                    "error": None,
                }
            ),
            stderr="",
        )
        with (
            mock.patch(
                "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                side_effect=AssertionError(
                    "preflight inspect should not gate docker run"
                ),
            ),
            mock.patch(
                "backends.static.decompile.decompile.subprocess.run",
                return_value=completed,
            ),
        ):
            result = _run_custom_decompiler_in_docker(
                "retdec", "/bin/ls", addr="0x401000"
            )
        self.assertIsNone(result.get("error"))
        self.assertEqual(result.get("provider"), "docker")
        self.assertEqual(
            result.get("docker_image"), "pile-ou-face/decompiler-retdec:latest"
        )
        self.assertIn("return 5", result.get("code", ""))

    def test_target_support_rejects_declared_excluded_combo(self):
        supported, reason = _decompiler_target_support(
            {
                "exclude_targets": [
                    {"format": "macho", "arch": "arm64", "reason": "support fragile"},
                ]
            },
            {"format": "macho", "arch": "arm64", "bitness": "64"},
        )
        self.assertFalse(supported)
        self.assertIn("fragile", reason)

    def test_docker_image_availability_rechecks_stale_negative_cache(self):
        image = "pile-ou-face/decompiler-retdec:latest"
        from backends.static.decompile import decompile as decompile_mod

        original_cache = dict(decompile_mod._DOCKER_AVAILABLE_CACHE)
        decompile_mod._DOCKER_AVAILABLE_CACHE.clear()
        decompile_mod._DOCKER_AVAILABLE_CACHE[image] = False
        try:
            completed = subprocess.CompletedProcess(
                args=["docker", "image", "inspect", image],
                returncode=0,
                stdout="[]",
                stderr="",
            )
            with (
                mock.patch(
                    "backends.static.decompile.decompile._find_docker_executable",
                    return_value="/usr/bin/docker",
                ),
                mock.patch(
                    "backends.static.decompile.decompile.subprocess.run",
                    return_value=completed,
                ) as run_mock,
            ):
                self.assertTrue(
                    decompile_mod._is_docker_decompiler_image_available(image)
                )
            run_mock.assert_called_once()
            self.assertTrue(decompile_mod._DOCKER_AVAILABLE_CACHE[image])
        finally:
            decompile_mod._DOCKER_AVAILABLE_CACHE.clear()
            decompile_mod._DOCKER_AVAILABLE_CACHE.update(original_cache)

    def test_preferred_docker_platform_is_only_forced_by_env(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            self.assertEqual(_preferred_docker_platform_for_decompiler("retdec"), "")
        with mock.patch.dict(
            os.environ, {"DOCKER_PLATFORM": "linux/amd64"}, clear=False
        ):
            self.assertEqual(
                _preferred_docker_platform_for_decompiler("retdec"), "linux/amd64"
            )

    def test_list_available_decompilers_returns_configured_decompilers(self):
        fake_decompilers = {
            "ghidra": {
                "id": "ghidra",
                "label": "Ghidra",
                "command": ["ghidra"],
                "supports_full": True,
                "output_format": "json",
                "network": "none",
                "env": {},
                "docker_extra_args": [],
            },
            "retdec": {
                "id": "retdec",
                "label": "RetDec",
                "command": ["retdec"],
                "supports_full": True,
                "output_format": "json",
                "network": "none",
                "env": {},
                "docker_extra_args": [],
            },
            "angr": {
                "id": "angr",
                "label": "angr",
                "command": ["angr"],
                "supports_full": True,
                "output_format": "json",
                "network": "none",
                "env": {},
                "docker_extra_args": [],
            },
        }
        with (
            mock.patch(
                "backends.static.decompile.decompile._load_decompilers",
                return_value=fake_decompilers,
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available_local",
                return_value=False,
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_docker_decompiler_image_available",
                return_value=False,
            ),
        ):
            result = list_available_decompilers(provider="auto")

        self.assertIn("ghidra", result)
        self.assertIn("retdec", result)
        self.assertIn("angr", result)
        self.assertNotIn("r2ghidra", result)
        self.assertNotIn("boomerang", result)

    def test_cli_list_passes_binary_target_metadata(self):
        argv = [
            "python -m backends.static.decompile",
            "--list",
            "--provider",
            "auto",
            "--binary",
            "/bin/foo",
            "--full",
        ]
        with (
            mock.patch.object(sys, "argv", argv),
            mock.patch(
                "backends.static.decompile.decompile.list_available_decompilers",
                return_value={"ghidra": True},
            ) as list_mock,
            mock.patch("sys.stdout", new_callable=io.StringIO),
        ):
            with self.assertRaises(SystemExit) as exit_ctx:
                runpy.run_module("backends.static.decompile", run_name="__main__")
        self.assertEqual(exit_ctx.exception.code, 0)
        list_mock.assert_called_once_with(
            provider="auto", binary_path="/bin/foo", full=True
        )

    def test_custom_docker_image_is_loaded_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            config_path = Path(d) / "decompilers.json"
            config_path.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "my-ghidra": {
                                "label": "My Ghidra",
                                "command": [
                                    "wrapper",
                                    "--binary",
                                    "{binary}",
                                    "--addr",
                                    "{addr}",
                                ],
                                "docker_image": "registry.example/my-ghidra:latest",
                            }
                        }
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.dict(
                os.environ, {"DECOMPILERS_CONFIG": str(config_path)}, clear=False
            ):
                self.assertEqual(
                    _get_decompiler_docker_image("my-ghidra"),
                    "registry.example/my-ghidra:latest",
                )

    def test_decompile_function_rewrites_typed_struct_addresses(self):
        empty_stack = {
            "arch": "unknown",
            "abi": "unknown",
            "frame_size": 0,
            "vars": [],
            "args": [],
        }

        def fake_run_custom(
            decompiler, _binary, addr="", func_name="", full=False, **kw
        ):
            return {
                "addr": "0x401000",
                "code": "int f() { return *(int *)0x402000; }",
                "error": None,
                "decompiler": decompiler,
            }

        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch(
                "backends.static.decompile.decompile._run_custom_decompiler",
                fake_run_custom,
            ),
            mock.patch(
                "backends.static.disasm.stack_frame.analyse_stack_frame",
                return_value=empty_stack,
            ),
            mock.patch(
                "backends.static.decompile.decompile.build_typed_struct_index",
                return_value={
                    "exact_by_addr": {
                        "0x402000": {
                            "kind": "field",
                            "label": "Demo.magic",
                            "comment": "struct Demo • champ magic • uint32_t",
                            "addr": "0x402000",
                            "struct_name": "Demo",
                            "field_name": "magic",
                            "field_type": "uint32_t",
                        }
                    }
                },
            ),
            mock.patch(
                "backends.static.decompile.decompile.typed_struct_signature",
                return_value="structsig",
            ),
        ):
            result = decompile_function(
                "/bin/ls",
                "0x401000",
                decompiler="ghidra",
                provider="local",
                cache_dir=Path(d),
            )

        self.assertIn("Demo.magic", result["code"])
        self.assertEqual(result["typed_structs"][0]["name"], "Demo.magic")

    def test_score_decompile_code_rewards_expected_calls(self):
        plain = _score_decompile_code("int main(){ return 0; }", {"win"})
        with_call = _score_decompile_code("int main(){ win(); return 0; }", {"win"})
        self.assertGreater(with_call["score"], plain["score"])
        self.assertEqual(with_call["metrics"]["matched_calls"], 1)

    def test_score_prefers_faithful_output(self):
        pretty_but_wrong = _score_decompile_code(
            'int main(){ printf("Try again, you got 0x%08x\\n", 0); return 0; }',
            {"win"},
        )
        uglier_but_faithful = _score_decompile_code(
            "int main(){ if (v) goto loc_0x1; win(); loc_0x1: return 0; }",
            {"win"},
        )
        self.assertGreater(uglier_but_faithful["score"], pretty_but_wrong["score"])
        self.assertEqual(uglier_but_faithful["metrics"]["matched_calls"], 1)
        self.assertEqual(pretty_but_wrong["metrics"]["missed_calls"], 1)

    def test_parse_c_like_function_blocks_skips_import_stubs(self):
        sample = (
            "void __stdcall sym.imp.printf(char *format)\n"
            "{\n"
            "    return;\n"
            "}\n\n"
            "int main(int argc, char **argv)\n"
            "{\n"
            "    return 0;\n"
            "}\n\n"
            "int64_t sym._helper(void)\n"
            "{\n"
            "    return 1;\n"
            "}\n"
        )
        parsed = _parse_c_like_function_blocks(sample)
        self.assertEqual([entry["name"] for entry in parsed], ["main", "sym._helper"])
        self.assertEqual(len(parsed), 2)

    def test_parse_c_like_function_blocks_handles_same_line_brace(self):
        sample = "int main (int argc, char **argv) {\n    return 0;\n}\n"
        parsed = _parse_c_like_function_blocks(sample)
        self.assertEqual(len(parsed), 1)
        self.assertIn("return 0;", parsed[0]["code"])

    def test_decompile_binary_nonexistent_returns_error(self):
        r = decompile_binary("/nonexistent/binary")
        self.assertIn("error", r)
        self.assertIsNotNone(r["error"])

    def test_load_custom_decompilers_from_config(self):
        with tempfile.TemporaryDirectory() as d:
            config = Path(d) / "decompilers.json"
            config.write_text(
                json.dumps(
                    {
                        "decompilers": {
                            "my ghidra": {
                                "label": "My Ghidra",
                                "command": ["echo", '{"code":"int f(){return 1;}"}'],
                            },
                            "retdec": {
                                "command": ["retdec-decompiler"],
                            },
                        }
                    }
                ),
                encoding="utf-8",
            )
            loaded = _load_custom_decompilers(config)
        self.assertIn("my-ghidra", loaded)
        self.assertEqual(loaded["my-ghidra"]["label"], "My Ghidra")
        # In the new config-driven architecture, any decompiler with a valid command is loaded
        self.assertIn("retdec", loaded)

    def test_run_custom_decompiler_parses_json_stdout(self):
        with tempfile.NamedTemporaryFile("w", delete=False) as tmp:
            tmp.write("bin")
            binary_path = tmp.name
        try:
            with tempfile.TemporaryDirectory() as d:
                config = Path(d) / "decompilers.json"
                config.write_text(
                    json.dumps(
                        {
                            "decompilers": {
                                "toy": {
                                    "command": [
                                        sys.executable,
                                        "-c",
                                        "import json; print(json.dumps({'code':'int toy(){return 7;}'}))",
                                    ]
                                }
                            }
                        }
                    ),
                    encoding="utf-8",
                )
                with mock.patch.dict(os.environ, {"DECOMPILERS_CONFIG": str(config)}):
                    result = _run_custom_decompiler("toy", binary_path, addr="0x401000")
            self.assertIsNone(result.get("error"))
            self.assertEqual(result.get("decompiler"), "toy")
            self.assertIn("return 7", result.get("code", ""))
        finally:
            Path(binary_path).unlink(missing_ok=True)

    def test_resolve_function_target_matches_symbol_aliases(self):
        fake_symbols = [
            {"addr": "0x100000490", "name": "_main"},
            {"addr": "0x100000470", "name": "_win"},
        ]
        with mock.patch(
            "backends.static.binary.symbols.extract_symbols", return_value=fake_symbols
        ):
            addr, func_name = _resolve_function_target(
                "/tmp/demo.bin", "0x4011a6", "_main"
            )
        self.assertEqual(addr, "0x100000490")

    def test_decompile_function_auto_skips_backend_excluded_for_target(self):
        fake_decompilers = {
            "ghidra": {"id": "ghidra", "label": "Ghidra", "command": ["ghidra"]},
            "retdec": {
                "id": "retdec",
                "label": "RetDec",
                "command": ["retdec"],
                "exclude_targets": [
                    {"format": "macho", "arch": "arm64", "reason": "fragile"}
                ],
            },
        }
        called = []

        def fake_run(candidate, binary_path, *, addr="", func_name="", full=False):
            called.append(candidate)
            return {
                "addr": addr,
                "code": f"int {candidate}() {{ return 0; }}",
                "error": None,
                "decompiler": candidate,
            }

        with tempfile.NamedTemporaryFile("wb", delete=False) as handle:
            binary_path = handle.name
        try:
            with (
                mock.patch(
                    "backends.static.decompile.decompile._load_decompilers",
                    return_value=fake_decompilers,
                ),
                mock.patch(
                    "backends.static.decompile.decompile._is_decompiler_available",
                    return_value=True,
                ),
                mock.patch(
                    "backends.static.decompile.decompile._binary_info",
                    return_value={"format": "macho", "arch": "arm64", "bitness": "64"},
                ),
                mock.patch(
                    "backends.static.decompile.decompile._resolve_function_target",
                    return_value=("0x1000", ""),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._extract_reachable_call_names",
                    return_value=set(),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._run_custom_decompiler",
                    side_effect=fake_run,
                ),
                mock.patch(
                    "backends.static.decompile.decompile._read_cache", return_value=None
                ),
                mock.patch("backends.static.decompile.decompile._write_cache"),
                mock.patch(
                    "backends.static.decompile.decompile._load_typed_struct_annotation_payload",
                    return_value=({}, {}, []),
                ),
                mock.patch(
                    "backends.static.decompile.decompile._build_cache_meta",
                    return_value=None,
                ),
            ):
                result = decompile_function(binary_path, "0x1000", provider="local")
        finally:
            Path(binary_path).unlink(missing_ok=True)

        self.assertIsNone(result.get("error"))
        self.assertEqual(called, ["ghidra"])

    def test_decompile_function_prefers_resolved_func_name_address(self):
        empty_stack = {
            "arch": "unknown",
            "abi": "unknown",
            "frame_size": 0,
            "vars": [],
            "args": [],
        }

        def fake_run_custom(
            decompiler, _binary, addr="", func_name="", full=False, **kw
        ):
            return {
                "addr": addr,
                "code": f"int {func_name or 'main'}() {{ return 0; }}",
                "error": None,
                "decompiler": decompiler,
            }

        fake_symbols = [{"addr": "0x100000490", "name": "_main"}]
        with (
            tempfile.TemporaryDirectory() as d,
            mock.patch(
                "backends.static.decompile.decompile._run_custom_decompiler",
                fake_run_custom,
            ),
            mock.patch(
                "backends.static.disasm.stack_frame.analyse_stack_frame",
                return_value=empty_stack,
            ),
            mock.patch(
                "backends.static.binary.symbols.extract_symbols",
                return_value=fake_symbols,
            ),
            mock.patch(
                "backends.static.decompile.decompile.typed_struct_signature",
                return_value="structsig",
            ),
        ):
            result = decompile_function(
                "/bin/ls",
                "0x4011a6",
                func_name="_main",
                decompiler="ghidra",
                provider="local",
                cache_dir=Path(d),
            )

        self.assertIsNone(result["error"])
        self.assertEqual(result["addr"], "0x100000490")
        self.assertIn("_main", result["code"])


class TestBuiltinTargetPolicies(unittest.TestCase):
    """Vérifie que _BUILTIN_TARGET_POLICIES accepte les combos format/arch attendus
    pour chaque backend, et que _decompiler_target_support les respecte correctement."""

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _support(self, backend_id, fmt, arch, bitness="64"):
        return _decompiler_target_support(
            {"id": backend_id},
            {"format": fmt, "arch": arch, "bitness": bitness},
        )

    def assertAccepted(self, backend_id, fmt, arch, bitness="64"):
        ok, reason = self._support(backend_id, fmt, arch, bitness)
        self.assertTrue(
            ok, f"{backend_id} should accept {fmt}/{arch}/{bitness}bit — got: {reason}"
        )

    def assertRejected(self, backend_id, fmt, arch, bitness="64"):
        ok, reason = self._support(backend_id, fmt, arch, bitness)
        self.assertFalse(
            ok,
            f"{backend_id} should reject {fmt}/{arch}/{bitness}bit — reason was empty",
        )
        return reason

    # ------------------------------------------------------------------
    # Mach-O ARM64 — les 3 backends doivent accepter
    # ------------------------------------------------------------------

    def test_ghidra_accepts_macho_arm64(self):
        self.assertAccepted("ghidra", "macho", "arm64")

    def test_angr_accepts_macho_arm64(self):
        self.assertAccepted("angr", "macho", "arm64")

    def test_retdec_accepts_macho_arm64(self):
        self.assertAccepted("retdec", "macho", "arm64")

    # ------------------------------------------------------------------
    # Mach-O x86_64
    # ------------------------------------------------------------------

    def test_ghidra_accepts_macho_x86_64(self):
        self.assertAccepted("ghidra", "macho", "x86_64")

    def test_angr_accepts_macho_x86_64(self):
        self.assertAccepted("angr", "macho", "x86_64")

    def test_retdec_accepts_macho_x86_64(self):
        self.assertAccepted("retdec", "macho", "x86_64")

    # ------------------------------------------------------------------
    # ELF ARM64
    # ------------------------------------------------------------------

    def test_ghidra_accepts_elf_arm64(self):
        self.assertAccepted("ghidra", "elf", "arm64")

    def test_angr_accepts_elf_arm64(self):
        self.assertAccepted("angr", "elf", "arm64")

    def test_retdec_accepts_elf_arm64(self):
        self.assertAccepted("retdec", "elf", "arm64")

    # ------------------------------------------------------------------
    # ELF x86_64
    # ------------------------------------------------------------------

    def test_ghidra_accepts_elf_x86_64(self):
        self.assertAccepted("ghidra", "elf", "x86_64")

    def test_angr_accepts_elf_x86_64(self):
        self.assertAccepted("angr", "elf", "x86_64")

    def test_retdec_accepts_elf_x86_64(self):
        self.assertAccepted("retdec", "elf", "x86_64")

    # ------------------------------------------------------------------
    # ELF x86 32-bit
    # ------------------------------------------------------------------

    def test_ghidra_accepts_elf_x86_32(self):
        self.assertAccepted("ghidra", "elf", "x86", "32")

    def test_angr_accepts_elf_x86_32(self):
        self.assertAccepted("angr", "elf", "x86", "32")

    def test_retdec_accepts_elf_x86_32(self):
        self.assertAccepted("retdec", "elf", "x86", "32")

    # ------------------------------------------------------------------
    # PE ARM64
    # ------------------------------------------------------------------

    def test_ghidra_accepts_pe_arm64(self):
        self.assertAccepted("ghidra", "pe", "arm64")

    def test_angr_accepts_pe_arm64(self):
        self.assertAccepted("angr", "pe", "arm64")

    def test_retdec_accepts_pe_arm64(self):
        self.assertAccepted("retdec", "pe", "arm64")

    # ------------------------------------------------------------------
    # Architectures spécifiques à Ghidra (PPC)
    # ------------------------------------------------------------------

    def test_ghidra_accepts_elf_ppc64(self):
        self.assertAccepted("ghidra", "elf", "ppc64")

    def test_angr_rejects_elf_ppc64(self):
        self.assertRejected("angr", "elf", "ppc64")

    def test_retdec_rejects_elf_ppc64(self):
        self.assertRejected("retdec", "elf", "ppc64")

    # ------------------------------------------------------------------
    # Architecture inconnue — doit être acceptée (pas de filtre sur "unknown")
    # ------------------------------------------------------------------

    def test_all_backends_accept_unknown_arch(self):
        for backend in ("ghidra", "angr", "retdec"):
            self.assertAccepted(backend, "elf", "unknown")

    def test_all_backends_accept_unknown_arch_macho(self):
        for backend in ("ghidra", "angr", "retdec"):
            self.assertAccepted(backend, "macho", "unknown")

    # ------------------------------------------------------------------
    # Format non déclaré — doit être refusé
    # ------------------------------------------------------------------

    def test_all_backends_reject_raw_format(self):
        for backend in ("ghidra", "angr", "retdec"):
            self.assertRejected(backend, "raw", "x86_64")

    # ------------------------------------------------------------------
    # Architecture non déclarée — doit être refusée
    # ------------------------------------------------------------------

    def test_all_backends_reject_riscv_arch(self):
        for backend in ("ghidra", "angr", "retdec"):
            self.assertRejected(backend, "elf", "riscv64")

    # ------------------------------------------------------------------
    # exclude_targets : correspondances partielles et complètes
    # ------------------------------------------------------------------

    def test_exclude_format_only_blocks_all_arches(self):
        entry = {"exclude_targets": [{"format": "macho"}]}
        ok, _ = _decompiler_target_support(
            entry, {"format": "macho", "arch": "arm64", "bitness": "64"}
        )
        self.assertFalse(ok)
        ok2, _ = _decompiler_target_support(
            entry, {"format": "macho", "arch": "x86_64", "bitness": "64"}
        )
        self.assertFalse(ok2)

    def test_exclude_format_only_does_not_block_other_format(self):
        entry = {"exclude_targets": [{"format": "macho"}]}
        ok, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "arm64", "bitness": "64"}
        )
        self.assertTrue(ok)

    def test_exclude_arch_only_blocks_all_formats(self):
        entry = {"exclude_targets": [{"arch": "arm64"}]}
        for fmt in ("elf", "pe", "macho"):
            ok, _ = _decompiler_target_support(
                entry, {"format": fmt, "arch": "arm64", "bitness": "64"}
            )
            self.assertFalse(ok, f"should block {fmt}/arm64")

    def test_exclude_format_arch_combo_does_not_block_other_arch(self):
        entry = {"exclude_targets": [{"format": "pe", "arch": "arm64"}]}
        ok, _ = _decompiler_target_support(
            entry, {"format": "pe", "arch": "x86_64", "bitness": "64"}
        )
        self.assertTrue(ok)

    def test_exclude_format_arch_combo_does_not_block_other_format(self):
        entry = {"exclude_targets": [{"format": "pe", "arch": "arm64"}]}
        ok, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "arm64", "bitness": "64"}
        )
        self.assertTrue(ok)

    def test_exclude_with_bitness_blocks_only_matching_bitness(self):
        entry = {
            "exclude_targets": [{"format": "elf", "arch": "arm64", "bitness": "32"}]
        }
        ok64, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "arm64", "bitness": "64"}
        )
        self.assertTrue(ok64, "should not block 64-bit")
        ok32, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "arm64", "bitness": "32"}
        )
        self.assertFalse(ok32, "should block 32-bit")

    def test_exclude_full_flag_blocks_only_full_mode(self):
        entry = {"exclude_targets": [{"format": "elf", "full": True}]}
        ok_full, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "x86_64", "bitness": "64"}, full=True
        )
        self.assertFalse(ok_full, "should block full mode")
        ok_func, _ = _decompiler_target_support(
            entry, {"format": "elf", "arch": "x86_64", "bitness": "64"}, full=False
        )
        self.assertTrue(ok_func, "should allow function mode")

    def test_exclude_reason_is_returned(self):
        entry = {
            "exclude_targets": [
                {"format": "macho", "arch": "arm64", "reason": "test raison précise"}
            ]
        }
        ok, reason = _decompiler_target_support(
            entry, {"format": "macho", "arch": "arm64", "bitness": "64"}
        )
        self.assertFalse(ok)
        self.assertEqual(reason, "test raison précise")

    def test_exclude_without_reason_returns_default_message(self):
        entry = {"exclude_targets": [{"format": "macho", "arch": "arm64"}]}
        ok, reason = _decompiler_target_support(
            entry, {"format": "macho", "arch": "arm64", "bitness": "64"}
        )
        self.assertFalse(ok)
        self.assertTrue(len(reason) > 0)

    # ------------------------------------------------------------------
    # supports déclaré dans l'entrée (override builtin)
    # ------------------------------------------------------------------

    def test_entry_supports_overrides_builtin(self):
        # Entrée qui ne supporte que elf — doit rejeter macho même si le builtin l'autorise
        entry = {
            "id": "ghidra",
            "supports": {"formats": ["elf"], "architectures": ["x86_64"]},
        }
        ok, reason = _decompiler_target_support(
            entry, {"format": "macho", "arch": "x86_64", "bitness": "64"}
        )
        self.assertFalse(ok)
        self.assertIn("macho", reason)

    def test_empty_entry_accepts_everything(self):
        # Entrée sans supports ni exclude_targets — tout est accepté
        ok, reason = _decompiler_target_support(
            {}, {"format": "macho", "arch": "arm64", "bitness": "64"}
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    def test_none_entry_accepts_everything(self):
        ok, reason = _decompiler_target_support(
            None, {"format": "macho", "arch": "arm64", "bitness": "64"}
        )
        self.assertTrue(ok)
        self.assertEqual(reason, "")

    # ------------------------------------------------------------------
    # Sélection auto — les 3 backends candidats sur Mach-O ARM64
    # ------------------------------------------------------------------

    def test_auto_mode_includes_all_three_for_macho_arm64(self):
        fake_decompilers = {
            "ghidra": {"id": "ghidra", "label": "Ghidra"},
            "angr": {"id": "angr", "label": "Angr"},
            "retdec": {"id": "retdec", "label": "RetDec"},
        }
        with (
            mock.patch(
                "backends.static.decompile.decompile._load_decompilers",
                return_value=fake_decompilers,
            ),
            mock.patch(
                "backends.static.decompile.decompile._is_decompiler_available",
                return_value=True,
            ),
            mock.patch(
                "backends.static.decompile.decompile._binary_info",
                return_value={"format": "macho", "arch": "arm64", "bitness": "64"},
            ),
            mock.patch(
                "backends.static.decompile.decompile._resolve_function_target",
                return_value=("0x1000", ""),
            ),
            mock.patch(
                "backends.static.decompile.decompile._extract_reachable_call_names",
                return_value=set(),
            ),
            mock.patch(
                "backends.static.decompile.decompile._run_custom_decompiler",
                side_effect=lambda c, _b, **kw: {
                    "addr": kw.get("addr", ""),
                    "code": f"int {c}();",
                    "error": None,
                    "decompiler": c,
                },
            ),
            mock.patch(
                "backends.static.decompile.decompile._read_cache", return_value=None
            ),
            mock.patch("backends.static.decompile.decompile._write_cache"),
            mock.patch(
                "backends.static.decompile.decompile._load_typed_struct_annotation_payload",
                return_value=({}, {}, []),
            ),
            mock.patch(
                "backends.static.decompile.decompile._build_cache_meta",
                return_value=None,
            ),
        ):
            import tempfile

            with tempfile.NamedTemporaryFile("wb", delete=False) as fh:
                binary_path = fh.name
            try:
                decompile_function(binary_path, "0x1000", provider="local")
            finally:
                Path(binary_path).unlink(missing_ok=True)
        # Vérifié indirectement via _decompiler_target_support pour chaque backend
        for backend in ("ghidra", "angr", "retdec"):
            entry = fake_decompilers[backend]
            ok, reason = _decompiler_target_support(
                entry, {"format": "macho", "arch": "arm64", "bitness": "64"}
            )
            self.assertTrue(
                ok, f"{backend} should be a candidate for macho/arm64 — got: {reason}"
            )


class TestErrorType(unittest.TestCase):
    def test_tool_error_sets_error_type(self):
        with mock.patch(
            "backends.static.decompile.decompile._load_custom_decompilers",
            return_value={
                "tool_a": {
                    "command": ["false"],
                    "output_format": "json",
                    "timeout": 10,
                }
            },
        ):
            result = _run_custom_decompiler("tool_a", "/bin/ls", addr="0x0")
        self.assertIn("error_type", result)
        self.assertEqual(result["error_type"], "tool_error")

    def test_timeout_sets_error_type(self):
        with (
            mock.patch(
                "subprocess.run",
                side_effect=subprocess.TimeoutExpired(cmd="x", timeout=1),
            ),
            mock.patch(
                "backends.static.decompile.decompile._load_custom_decompilers",
                return_value={
                    "tool_a": {
                        "command": ["sleep", "999"],
                        "output_format": "json",
                        "timeout": 1,
                    }
                },
            ),
        ):
            result = _run_custom_decompiler("tool_a", "/bin/ls", addr="0x0")
        self.assertEqual(result.get("error_type"), "timeout")


if __name__ == "__main__":
    unittest.main()
