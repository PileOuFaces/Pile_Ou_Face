# SPDX-License-Identifier: AGPL-3.0-only
from __future__ import annotations

import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from types import ModuleType, SimpleNamespace
from unittest.mock import patch

from tooling.loadtest.real_corpus import (
    _sha256_file,
    _toolchain,
    _write_deterministic_blob,
    build_large_real_corpus,
    main,
)


class TestRealCorpusBuilder(unittest.TestCase):
    def test_blob_has_exact_size_and_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            first = Path(tmp) / "first.bin"
            second = Path(tmp) / "second.bin"
            _write_deterministic_blob(first, 1024 * 1024 + 17)
            _write_deterministic_blob(second, 1024 * 1024 + 17)
            self.assertEqual(first.stat().st_size, 1024 * 1024 + 17)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertNotEqual(first.read_bytes()[:4096], bytes(4096))

    @patch("tooling.loadtest.real_corpus.shutil.which")
    def test_arm64_uses_cross_toolchain(self, which):
        which.side_effect = lambda name: f"/tools/{name}"
        self.assertEqual(
            _toolchain("arm64"),
            ("/tools/aarch64-linux-gnu-gcc", "/tools/aarch64-linux-gnu-objcopy"),
        )

    @patch("tooling.loadtest.real_corpus.shutil.which", return_value=None)
    def test_missing_toolchain_fails_explicitly(self, _which):
        with self.assertRaisesRegex(RuntimeError, "gcc"):
            _toolchain("x86_64")

    def test_sha256_file_streams_the_complete_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "payload.bin"
            path.write_bytes(b"abc")
            self.assertEqual(
                _sha256_file(path),
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            )

    def test_builds_compiled_corpus_and_returns_traceable_metadata(self):
        fixture_module = ModuleType("backends.static.tests.fixtures.real_binary_corpus")
        fixture_module.CorpusSpec = SimpleNamespace

        def build_binary(root, spec):
            root.mkdir(parents=True)
            binary = root / "sample.elf"
            binary.write_bytes(b"ELF-compiled")
            self.assertEqual(spec.arch, "x86_64")
            return SimpleNamespace(built=True, binary_path=binary, skipped_reason=None)

        fixture_module.build_corpus_binary = build_binary

        def run_objcopy(command, **_kwargs):
            source = Path(command[-2])
            output = Path(command[-1])
            output.write_bytes(source.read_bytes() + b"-padded")
            return SimpleNamespace(returncode=0, stderr="", stdout="")

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "large.elf"
            with (
                patch(
                    "tooling.loadtest.real_corpus._toolchain",
                    return_value=("/tools/gcc", "/tools/objcopy"),
                ),
                patch.dict(
                    "sys.modules",
                    {
                        "backends.static.tests.fixtures.real_binary_corpus": fixture_module
                    },
                ),
                patch(
                    "tooling.loadtest.real_corpus._write_deterministic_blob"
                ) as write_blob,
                patch(
                    "tooling.loadtest.real_corpus.subprocess.run",
                    side_effect=run_objcopy,
                ),
            ):
                metadata = build_large_real_corpus(output, "x86_64", 1)

            write_blob.assert_called_once()
            self.assertEqual(metadata["architecture"], "x86_64")
            self.assertEqual(metadata["compiler"], "gcc")
            self.assertEqual(metadata["size_bytes"], output.stat().st_size)
            self.assertEqual(len(metadata["sha256"]), 64)

    def test_rejects_invalid_size_before_toolchain_lookup(self):
        with patch("tooling.loadtest.real_corpus._toolchain") as toolchain:
            with self.assertRaisesRegex(ValueError, "strictement positif"):
                build_large_real_corpus(Path("unused"), "x86_64", 0)
            toolchain.assert_not_called()

    def test_cli_prints_metadata(self):
        metadata = {"schema": "test", "architecture": "arm64"}
        stdout = StringIO()
        with (
            patch(
                "tooling.loadtest.real_corpus.build_large_real_corpus",
                return_value=metadata,
            ),
            redirect_stdout(stdout),
        ):
            self.assertEqual(
                main(["--arch", "arm64", "--output", "/tmp/corpus.elf"]), 0
            )
        self.assertEqual(
            stdout.getvalue().strip(), '{"architecture": "arm64", "schema": "test"}'
        )

    def test_cli_surfaces_builder_error(self):
        with (
            patch(
                "tooling.loadtest.real_corpus.build_large_real_corpus",
                side_effect=RuntimeError("toolchain absent"),
            ),
            redirect_stderr(StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            main(["--arch", "x86_64", "--output", "/tmp/corpus.elf"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
