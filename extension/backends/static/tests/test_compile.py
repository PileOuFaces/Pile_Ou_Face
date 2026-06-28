# SPDX-License-Identifier: AGPL-3.0-only
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from backends.static.compile.compile import (
    _build_target_flags_native,
    _load_compilers,
    _select_toolchain,
    compile_source,
    list_available_compilers,
)

FAKE_CONFIG = {
    "compilers": {
        "tool_a": {
            "label": "Tool A",
            "docker_image": "pile-ou-face/compiler-tool_a:latest",
            "docker_command": [
                "python3",
                "/opt/pof/compile.py",
                "--src",
                "{src}",
                "--lang",
                "{lang}",
                "--target",
                "{target}",
                "--output",
                "{output}",
            ],
            "native_cmd": "tool_a_bin",
            "langs": ["c", "cpp"],
            "targets": ["elf-x64", "elf-arm64", "pe-x64"],
        },
        "tool_b": {
            "label": "Tool B",
            "docker_image": "pile-ou-face/compiler-tool_b:latest",
            "docker_command": [
                "python3",
                "/opt/pof/compile.py",
                "--src",
                "{src}",
                "--lang",
                "{lang}",
                "--target",
                "{target}",
                "--output",
                "{output}",
            ],
            "native_cmd": "tool_b_bin",
            "langs": ["rust"],
            "targets": ["elf-x64", "elf-arm64"],
        },
    }
}

# Toolchain avec native_platforms restreint à linux (simule gcc-multiarch sur macOS)
FAKE_CONFIG_PLATFORM_RESTRICTED = {
    "compilers": {
        "linux_only_tool": {
            "label": "Linux Only",
            "docker_image": "pile-ou-face/compiler-linux_only:latest",
            "docker_command": [
                "python3",
                "/opt/pof/compile.py",
                "--src",
                "{src}",
                "--lang",
                "{lang}",
                "--target",
                "{target}",
                "--output",
                "{output}",
            ],
            "native_cmd": "linux_gcc_bin",
            "native_platforms": ["linux"],
            "langs": ["c"],
            "targets": ["elf-x64", "elf-x86"],
        },
    }
}


class TestLoadCompilers(unittest.TestCase):
    def test_loads_from_dict(self):
        with tempfile.NamedTemporaryFile(suffix=".json", mode="w", delete=False) as f:
            json.dump(FAKE_CONFIG, f)
            cfg_path = Path(f.name)
        result = _load_compilers(config_path=cfg_path)
        self.assertIn("tool_a", result)
        self.assertIn("tool_b", result)
        cfg_path.unlink()

    def test_returns_empty_on_missing_file(self):
        result = _load_compilers(config_path=Path("/nonexistent/compilers.json"))
        self.assertEqual(result, {})


class TestSelectToolchain(unittest.TestCase):
    def test_selects_matching_toolchain(self):
        compilers = FAKE_CONFIG["compilers"]
        result = _select_toolchain(compilers, lang="c", target="elf-x64")
        self.assertEqual(result, "tool_a")

    def test_returns_none_when_no_match(self):
        compilers = FAKE_CONFIG["compilers"]
        result = _select_toolchain(compilers, lang="go", target="elf-x64")
        self.assertIsNone(result)

    def test_selects_by_lang_rust(self):
        compilers = FAKE_CONFIG["compilers"]
        result = _select_toolchain(compilers, lang="rust", target="elf-arm64")
        self.assertEqual(result, "tool_b")


class TestListAvailableCompilers(unittest.TestCase):
    def test_lists_all_when_docker_available(self):
        compilers = FAKE_CONFIG["compilers"]
        with (
            mock.patch(
                "backends.static.compile.compile._is_docker_image_available",
                return_value=True,
            ),
            mock.patch("shutil.which", return_value=None),
        ):
            result = list_available_compilers(compilers=compilers)
        self.assertEqual(len(result), 2)
        self.assertIn("tool_a", [c["id"] for c in result])


class TestCompileSource(unittest.TestCase):
    def test_error_when_no_toolchain(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        result = compile_source(
            src, lang="cobol", target="elf-x64", compilers=FAKE_CONFIG["compilers"]
        )
        self.assertIn("error", result)
        self.assertIn("cobol", result["error"])

    def test_error_when_src_missing(self):
        result = compile_source(
            "/nonexistent/file.c",
            lang="c",
            target="elf-x64",
            compilers=FAKE_CONFIG["compilers"],
        )
        self.assertIn("error", result)

    def test_uses_native_when_available(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        with mock.patch("shutil.which", return_value="/usr/bin/tool_a_bin"):
            with mock.patch(
                "backends.static.compile.compile._run_native_compiler"
            ) as mock_native:
                mock_native.return_value = {
                    "output_path": "/tmp/out.elf",
                    "compiler_used": "tool_a",
                    "target": "elf-x64",
                    "exit_code": 0,
                    "stderr": "",
                }
                result = compile_source(
                    src, lang="c", target="elf-x64", compilers=FAKE_CONFIG["compilers"]
                )
        mock_native.assert_called_once()
        self.assertIn("output_path", result)

    def test_falls_back_to_docker(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        with (
            mock.patch("shutil.which", return_value=None),
            mock.patch(
                "backends.static.compile.compile._is_docker_image_available",
                return_value=True,
            ),
            mock.patch(
                "backends.static.compile.compile._run_docker_compiler"
            ) as mock_docker,
        ):
            mock_docker.return_value = {
                "output_path": "/tmp/out.elf",
                "compiler_used": "tool_a",
                "target": "elf-x64",
                "exit_code": 0,
                "stderr": "",
            }
            result = compile_source(
                src,
                lang="c",
                target="elf-x64",
                compilers=FAKE_CONFIG["compilers"],
            )
        mock_docker.assert_called_once()
        self.assertIn("output_path", result)

    def test_error_when_both_native_and_docker_unavailable(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        with (
            mock.patch("shutil.which", return_value=None),
            mock.patch(
                "backends.static.compile.compile._is_docker_image_available",
                return_value=False,
            ),
        ):
            result = compile_source(
                src,
                lang="c",
                target="elf-x64",
                compilers=FAKE_CONFIG["compilers"],
            )
        self.assertIn("error", result)
        self.assertIn("tool_a", result["error"])


class TestBuildTargetFlagsNative(unittest.TestCase):
    def test_gcc_multiarch_x64(self):
        self.assertEqual(
            _build_target_flags_native("gcc-multiarch", "elf-x64"), ["-m64"]
        )

    def test_gcc_multiarch_x86(self):
        self.assertEqual(
            _build_target_flags_native("gcc-multiarch", "elf-x86"), ["-m32"]
        )

    def test_gcc_multiarch_unknown_target(self):
        self.assertEqual(_build_target_flags_native("gcc-multiarch", "elf-mips"), [])

    def test_clang_macho_x64(self):
        flags = _build_target_flags_native("clang", "macho-x64")
        self.assertIn("-target", flags)
        self.assertIn("x86_64-apple-macosx10.15", flags)

    def test_clang_macho_arm64(self):
        flags = _build_target_flags_native("clang", "macho-arm64")
        self.assertIn("-target", flags)
        self.assertIn("arm64-apple-macosx12.0", flags)

    def test_unknown_toolchain_returns_empty(self):
        self.assertEqual(_build_target_flags_native("unknown", "elf-x64"), [])


class TestNativePlatforms(unittest.TestCase):
    """native_platforms bloque l'invocation native sur les plateformes non autorisées."""

    def _src(self):
        f = tempfile.NamedTemporaryFile(suffix=".c", delete=False)
        f.write(b"int main(){return 0;}")
        f.flush()
        return f.name

    def test_native_blocked_on_wrong_platform(self):
        """Sur darwin, un toolchain native_platforms=['linux'] doit passer par Docker."""
        src = self._src()
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/bin/linux_gcc_bin"):
                with mock.patch(
                    "backends.static.compile.compile._is_docker_image_available",
                    return_value=True,
                ):
                    with mock.patch(
                        "backends.static.compile.compile._run_docker_compiler"
                    ) as mock_docker:
                        mock_docker.return_value = {
                            "output_path": "/tmp/out.elf",
                            "compiler_used": "linux_only_tool",
                            "target": "elf-x64",
                            "exit_code": 0,
                            "stderr": "",
                        }
                        compile_source(
                            src, lang="c", target="elf-x64", compilers=compilers
                        )
        mock_docker.assert_called_once()

    def test_native_allowed_on_correct_platform(self):
        """Sur linux, native_platforms=['linux'] autorise l'invocation native."""
        src = self._src()
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Linux"):
            with mock.patch("shutil.which", return_value="/usr/bin/linux_gcc_bin"):
                with mock.patch(
                    "backends.static.compile.compile._run_native_compiler"
                ) as mock_native:
                    mock_native.return_value = {
                        "output_path": "/tmp/out.elf",
                        "compiler_used": "linux_only_tool",
                        "target": "elf-x64",
                        "exit_code": 0,
                        "stderr": "",
                    }
                    compile_source(src, lang="c", target="elf-x64", compilers=compilers)
        mock_native.assert_called_once()

    def test_error_message_mentions_platform_on_darwin(self):
        """L'erreur quand Docker manque aussi doit mentionner la plateforme."""
        src = self._src()
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/bin/linux_gcc_bin"):
                with mock.patch(
                    "backends.static.compile.compile._is_docker_image_available",
                    return_value=False,
                ):
                    result = compile_source(
                        src, lang="c", target="elf-x64", compilers=compilers
                    )
        self.assertIn("error", result)
        self.assertIn("darwin", result["error"])


class TestListAvailableCompilersExtended(unittest.TestCase):
    def test_native_platform_restricted_field_present(self):
        """list_available_compilers expose native_platform_restricted et native_platforms."""
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/bin/linux_gcc_bin"):
                with mock.patch(
                    "backends.static.compile.compile._is_docker_image_available",
                    return_value=False,
                ):
                    result = list_available_compilers(compilers=compilers)
        entry = result[0]
        self.assertIn("native_platform_restricted", entry)
        self.assertIn("native_platforms", entry)
        self.assertTrue(entry["native_platform_restricted"])
        self.assertEqual(entry["native_platforms"], ["linux"])

    def test_available_false_when_platform_restricted_and_no_docker(self):
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value="/usr/bin/linux_gcc_bin"):
                with mock.patch(
                    "backends.static.compile.compile._is_docker_image_available",
                    return_value=False,
                ):
                    result = list_available_compilers(compilers=compilers)
        self.assertFalse(result[0]["available"])

    def test_available_true_when_docker_present_even_if_native_restricted(self):
        compilers = FAKE_CONFIG_PLATFORM_RESTRICTED["compilers"]
        with mock.patch("platform.system", return_value="Darwin"):
            with mock.patch("shutil.which", return_value=None):
                with mock.patch(
                    "backends.static.compile.compile._is_docker_image_available",
                    return_value=True,
                ):
                    result = list_available_compilers(compilers=compilers)
        self.assertTrue(result[0]["available"])
        self.assertTrue(result[0]["available_docker"])
        self.assertFalse(result[0]["available_native"])


class TestCompileSourceFlags(unittest.TestCase):
    def test_custom_flags_passed_to_native_compiler(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        custom_flags = ["-O2", "-fno-pie"]
        with mock.patch("shutil.which", return_value="/usr/bin/tool_a_bin"):
            with mock.patch(
                "backends.static.compile.compile._run_native_compiler"
            ) as mock_native:
                mock_native.return_value = {
                    "output_path": "/tmp/out.elf",
                    "compiler_used": "tool_a",
                    "target": "elf-x64",
                    "exit_code": 0,
                    "stderr": "",
                }
                compile_source(
                    src,
                    lang="c",
                    target="elf-x64",
                    compilers=FAKE_CONFIG["compilers"],
                    flags=custom_flags,
                )
        call_args = mock_native.call_args[0]
        self.assertEqual(call_args[-1], custom_flags)

    def test_custom_flags_passed_to_docker_compiler(self):
        with tempfile.NamedTemporaryFile(suffix=".c", delete=False) as f:
            f.write(b"int main(){return 0;}")
            src = f.name
        custom_flags = ["-O2", "-g"]
        with (
            mock.patch("shutil.which", return_value=None),
            mock.patch(
                "backends.static.compile.compile._is_docker_image_available",
                return_value=True,
            ),
            mock.patch(
                "backends.static.compile.compile._run_docker_compiler"
            ) as mock_docker,
        ):
            mock_docker.return_value = {
                "output_path": "/tmp/out.elf",
                "compiler_used": "tool_a",
                "target": "elf-x64",
                "exit_code": 0,
                "stderr": "",
            }
            compile_source(
                src,
                lang="c",
                target="elf-x64",
                compilers=FAKE_CONFIG["compilers"],
                flags=custom_flags,
            )
        call_args = mock_docker.call_args[0]
        self.assertEqual(call_args[-1], custom_flags)


if __name__ == "__main__":
    unittest.main()
