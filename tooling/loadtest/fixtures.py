# SPDX-License-Identifier: AGPL-3.0-only
"""Génère des binaires synthétiques de taille/complexité contrôlées.

Le padding (taille du fichier) est fourni comme blob binaire brut inclus via
une directive assembleur `.incbin`, pas comme tableau littéral en C — un
fichier source C contenant un tableau de plusieurs centaines de Mo serait
extrêmement lent à compiler. Le nombre de fonctions contrôle la complexité
(désassemblage, CFG, call graph) indépendamment de la taille du fichier.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class FixtureSpec:
    name: str
    num_functions: int
    padding_bytes: int


def _generate_c_source(spec: FixtureSpec) -> str:
    lines = ["extern const unsigned char pof_padding[];", "extern const long pof_padding_len;", ""]
    for i in range(spec.num_functions):
        lines.append(f"int pof_fn_{i}(int x) {{ return x * {i + 1} + (x ^ {i}); }}")
    lines.append("")
    lines.append("int main(void) {")
    lines.append("    int acc = 0;")
    for i in range(spec.num_functions):
        lines.append(f"    acc += pof_fn_{i}(acc + {i});")
    lines.append("    acc += (int)pof_padding[0] + (int)pof_padding_len;")
    lines.append("    return acc % 256;")
    lines.append("}")
    return "\n".join(lines) + "\n"


def _generate_asm_source(padding_bytes: int, blob_path: Path) -> str:
    if sys.platform == "darwin":
        return (
            ".section __DATA,__data\n"
            ".globl _pof_padding\n"
            "_pof_padding:\n"
            f'.incbin "{blob_path}"\n'
            ".globl _pof_padding_len\n"
            "_pof_padding_len:\n"
            f".quad {padding_bytes}\n"
        )
    return (
        ".section .data\n"
        ".globl pof_padding\n"
        "pof_padding:\n"
        f'.incbin "{blob_path}"\n'
        ".globl pof_padding_len\n"
        "pof_padding_len:\n"
        f".quad {padding_bytes}\n"
    )


def _cache_key(spec: FixtureSpec) -> str:
    return f"{spec.name}-{spec.num_functions}fn-{spec.padding_bytes}b"


def build_fixture(spec: FixtureSpec, cache_dir: Path) -> Path:
    """Construit (ou réutilise depuis le cache) un binaire pour ce spec."""
    cache_dir.mkdir(parents=True, exist_ok=True)
    binary_path = cache_dir / f"{_cache_key(spec)}.bin"
    if binary_path.exists():
        return binary_path

    cc = shutil.which("cc") or shutil.which("gcc") or shutil.which("clang")
    if not cc:
        raise RuntimeError("Aucun compilateur C (cc/gcc/clang) trouvé sur ce système.")

    work_dir = cache_dir / f"_build_{_cache_key(spec)}"
    work_dir.mkdir(parents=True, exist_ok=True)
    try:
        blob_path = work_dir / "padding.bin"
        with open(blob_path, "wb") as f:
            f.write(os.urandom(min(spec.padding_bytes, 1024 * 1024)))
            remaining = spec.padding_bytes - min(spec.padding_bytes, 1024 * 1024)
            if remaining > 0:
                f.write(b"\x00" * remaining)

        asm_path = work_dir / "padding.s"
        asm_path.write_text(_generate_asm_source(spec.padding_bytes, blob_path), encoding="utf-8")

        c_path = work_dir / "main.c"
        c_path.write_text(_generate_c_source(spec), encoding="utf-8")

        result = subprocess.run(
            [cc, "-O0", str(c_path), str(asm_path), "-o", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0 or not binary_path.exists():
            raise RuntimeError(f"Échec de compilation de la fixture {spec.name}: {result.stderr}")
        return binary_path
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)
