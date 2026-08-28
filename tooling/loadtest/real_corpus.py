# SPDX-License-Identifier: AGPL-3.0-only
"""Construit un gros ELF compilé pour les campagnes loadtest planifiées.

Le programme et ses symboles proviennent du corpus réel partagé avec les tests
statiques. Une section ELF déterministe de grande taille est ensuite ajoutée
pour exercer les chemins utilisateur qui dépendent de la taille du fichier,
sans versionner un artefact binaire opaque de 100 à 200 Mio.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXTENSION_ROOT = REPO_ROOT / "extension"
MIB = 1024 * 1024


def _toolchain(arch: str) -> tuple[str, str]:
    names = {
        "x86_64": ("gcc", "objcopy"),
        "arm64": ("aarch64-linux-gnu-gcc", "aarch64-linux-gnu-objcopy"),
        "mips32": ("mips-linux-gnu-gcc", "mips-linux-gnu-objcopy"),
        "ppc32": ("powerpc-linux-gnu-gcc", "powerpc-linux-gnu-objcopy"),
        "riscv64": ("riscv64-linux-gnu-gcc", "riscv64-linux-gnu-objcopy"),
    }
    compiler_name, objcopy_name = names[arch]
    compiler = shutil.which(compiler_name)
    objcopy = shutil.which(objcopy_name)
    if compiler is None or objcopy is None:
        missing = compiler_name if compiler is None else objcopy_name
        raise RuntimeError(f"outil de corpus introuvable : {missing}")
    return compiler, objcopy


def _write_deterministic_blob(path: Path, size_bytes: int) -> None:
    seed = b"pile-ou-face-real-corpus-v1"
    block = bytearray()
    counter = 0
    while len(block) < MIB:
        block.extend(hashlib.sha256(seed + counter.to_bytes(8, "little")).digest())
        counter += 1
    chunk = bytes(block[:MIB])

    remaining = size_bytes
    with path.open("wb") as stream:
        while remaining:
            part = chunk[: min(remaining, len(chunk))]
            stream.write(part)
            remaining -= len(part)


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(MIB), b""):
            digest.update(chunk)
    return digest.hexdigest()


def build_large_real_corpus(output: Path, arch: str, size_mib: int) -> dict:
    if size_mib <= 0:
        raise ValueError("size_mib doit être strictement positif")

    compiler, objcopy = _toolchain(arch)
    sys.path.insert(0, str(EXTENSION_ROOT))
    from backends.static.tests.fixtures.real_binary_corpus import (  # noqa: PLC0415
        CorpusSpec,
        build_corpus_binary,
    )

    output = output.resolve()
    output.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="pof-real-corpus-") as tmp:
        root = Path(tmp)
        spec = CorpusSpec(
            compiler=compiler,
            opt="-O2",
            pie=False,
            stripped=False,
            arch=arch,
        )
        built = build_corpus_binary(root / "compiled", spec)
        if not built.built:
            raise RuntimeError(
                f"échec de compilation du corpus : {built.skipped_reason}"
            )

        target_bytes = size_mib * MIB
        padding_bytes = max(target_bytes - built.binary_path.stat().st_size, 1)
        blob = root / "corpus-data.bin"
        _write_deterministic_blob(blob, padding_bytes)
        result = subprocess.run(
            [
                objcopy,
                "--add-section",
                f".pof_corpus={blob}",
                "--set-section-flags",
                ".pof_corpus=alloc,load,readonly,data,contents",
                str(built.binary_path),
                str(output),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 or not output.exists():
            message = (result.stderr or result.stdout or "objcopy failed").strip()
            raise RuntimeError(f"échec de création du gros corpus : {message}")

    return {
        "schema": "pile-ou-face.loadtest-real-corpus.v1",
        "architecture": arch,
        "compiler": Path(compiler).name,
        "size_bytes": output.stat().st_size,
        "sha256": _sha256_file(output),
        "path": str(output),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Construit un corpus ELF loadtest")
    parser.add_argument(
        "--arch",
        choices=("x86_64", "arm64", "mips32", "ppc32", "riscv64"),
        required=True,
    )
    parser.add_argument("--size-mib", type=int, default=100)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        metadata = build_large_real_corpus(args.output, args.arch, args.size_mib)
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
