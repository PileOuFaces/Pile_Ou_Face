# SPDX-License-Identifier: AGPL-3.0-only
"""Fixtures de corpus réel pour l'analyse statique.

Le corpus est généré à la volée pour éviter de versionner des binaires opaques.
Chaque fixture garde les adresses attendues avant stripping afin que les tests
puissent mesurer les analyseurs même quand la table de symboles est retirée.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import warnings
from dataclasses import dataclass
from pathlib import Path

from backends.static.binary.symbols import extract_symbols

SOURCE = r"""
#include <stdint.h>

volatile int pof_sink;

#if defined(__GNUC__) || defined(__clang__)
#define POF_NOINLINE __attribute__((noinline, used))
#else
#define POF_NOINLINE
#endif

POF_NOINLINE int pof_leaf(int x) {
    return (x * 3) + 1;
}

POF_NOINLINE int pof_branchy(int x) {
    if (x & 1) {
        return pof_leaf(x) + 7;
    }
    return x - 7;
}

POF_NOINLINE int pof_stacky(const char *s) {
    char local[32];
    int acc = 0;
    for (int i = 0; i < 32; ++i) {
        char c = s[i & 3];
        local[i] = (char)(c + i);
        acc += local[i];
    }
    return acc;
}

POF_NOINLINE int pof_switchy(int x) {
    switch (x & 3) {
    case 0:
        return pof_leaf(x);
    case 1:
        return pof_branchy(x);
    case 2:
        return pof_stacky("POF!");
    default:
        return x ^ 0x55;
    }
}

int main(int argc, char **argv) {
    int seed = argc;
    if (argv && argv[0]) {
        seed += argv[0][0];
    }
    int result = pof_switchy(seed) + pof_branchy(seed + 1);
    pof_sink = result;
    return result & 0xff;
}
"""


EXPECTED_FUNCTION_NAMES = {
    "main",
    "pof_leaf",
    "pof_branchy",
    "pof_stacky",
    "pof_switchy",
}

EXPECTED_CFG_CALL_EDGES = {
    ("main", "pof_switchy"),
    ("main", "pof_branchy"),
    ("pof_branchy", "pof_leaf"),
}

EXPECTED_CFG_CALL_EDGES_O0 = {
    ("pof_switchy", "pof_leaf"),
    ("pof_switchy", "pof_branchy"),
    ("pof_switchy", "pof_stacky"),
}


@dataclass(frozen=True)
class CorpusSpec:
    compiler: str
    opt: str
    pie: bool
    stripped: bool
    arch: str = "native"

    @property
    def case_id(self) -> str:
        pie = "pie" if self.pie else "nopie"
        stripped = "stripped" if self.stripped else "symbols"
        compiler = Path(self.compiler).name.replace("-", "_")
        return f"{compiler}_{self.opt.lstrip('-').lower()}_{pie}_{stripped}_{self.arch}"


@dataclass(frozen=True)
class CorpusBinary:
    spec: CorpusSpec
    source_path: Path
    binary_path: Path
    expected_functions: dict[str, str]
    skipped_reason: str = ""

    @property
    def built(self) -> bool:
        return self.binary_path.exists() and not self.skipped_reason


def expected_cfg_call_edges(spec: CorpusSpec) -> set[tuple[str, str]]:
    """Arêtes call nommées attendues pour la fixture source déterministe."""
    edges = set(EXPECTED_CFG_CALL_EDGES)
    if spec.opt == "-O0":
        edges.update(EXPECTED_CFG_CALL_EDGES_O0)
    return edges


def default_corpus_specs() -> list[CorpusSpec]:
    """Matrice courte et CI-friendly couvrant compilateurs/optimisations clés.

    Set POF_CORPUS_SKIP_COMPILERS=clang (comma-separated) to exclude compilers
    whose analysis is known to be incomplete (e.g. clang PIE on linux/x86_64).
    """
    skip = {c.strip() for c in os.environ.get("POF_CORPUS_SKIP_COMPILERS", "").split(",") if c.strip()}
    specs: list[CorpusSpec] = []
    if shutil.which("gcc") and "gcc" not in skip:
        specs.extend(
            [
                CorpusSpec("gcc", "-O0", pie=False, stripped=False),
                CorpusSpec("gcc", "-O2", pie=True, stripped=False),
            ]
        )
        if shutil.which("strip"):
            specs.append(CorpusSpec("gcc", "-Os", pie=False, stripped=True))
    if shutil.which("clang") and "clang" not in skip:
        specs.extend(
            [
                CorpusSpec("clang", "-O0", pie=False, stripped=False),
                CorpusSpec("clang", "-O2", pie=True, stripped=False),
            ]
        )
        if shutil.which("strip"):
            specs.append(CorpusSpec("clang", "-Os", pie=False, stripped=True))
    if shutil.which("aarch64-linux-gnu-gcc") and "aarch64-linux-gnu-gcc" not in skip:
        specs.append(
            CorpusSpec(
                "aarch64-linux-gnu-gcc", "-O2", pie=True, stripped=False, arch="arm64"
            )
        )
    return specs


def _compile_command(spec: CorpusSpec, source: Path, output: Path) -> list[str]:
    cmd = [
        spec.compiler,
        spec.opt,
        "-g",
        "-fno-builtin",
        "-Wall",
        "-Wextra",
        str(source),
        "-o",
        str(output),
    ]
    if spec.pie:
        cmd[2:2] = ["-fPIE", "-pie"]
    else:
        cmd[2:2] = ["-fno-pie", "-no-pie"]
    return cmd


def _expected_functions(binary_path: Path) -> dict[str, str]:
    with warnings.catch_warnings():
        warnings.filterwarnings(
            "ignore",
            message=r".*is not a valid TYPE.*",
            category=RuntimeWarning,
        )
        symbols = extract_symbols(str(binary_path))
    expected: dict[str, str] = {}
    for symbol in symbols:
        name = str(symbol.get("name") or "").lstrip("_")
        addr = str(symbol.get("addr") or "")
        if name in EXPECTED_FUNCTION_NAMES and addr and addr != "0x0":
            expected[name] = addr
    return expected


def build_corpus_binary(root: Path, spec: CorpusSpec) -> CorpusBinary:
    """Compile une fixture et retourne les adresses attendues si disponible."""
    root.mkdir(parents=True, exist_ok=True)
    source = root / f"{spec.case_id}.c"
    binary = root / f"{spec.case_id}.bin"
    source.write_text(SOURCE, encoding="utf-8")

    try:
        result = subprocess.run(
            _compile_command(spec, source, binary),
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CorpusBinary(spec, source, binary, {}, skipped_reason=str(exc))

    if result.returncode != 0 or not binary.exists():
        reason = (result.stderr or result.stdout or "compiler failed").strip()
        return CorpusBinary(spec, source, binary, {}, skipped_reason=reason)

    expected = _expected_functions(binary)
    missing = EXPECTED_FUNCTION_NAMES - set(expected)
    if missing:
        return CorpusBinary(
            spec,
            source,
            binary,
            expected,
            skipped_reason=f"missing expected symbols before strip: {sorted(missing)}",
        )

    if spec.stripped:
        strip = shutil.which("strip")
        if not strip:
            return CorpusBinary(
                spec, source, binary, expected, skipped_reason="strip unavailable"
            )
        stripped = subprocess.run(
            [strip, str(binary)],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if stripped.returncode != 0:
            reason = (stripped.stderr or stripped.stdout or "strip failed").strip()
            return CorpusBinary(spec, source, binary, expected, skipped_reason=reason)

    return CorpusBinary(spec, source, binary, expected)
