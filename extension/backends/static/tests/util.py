# SPDX-License-Identifier: AGPL-3.0-only
"""Utilitaires pour les tests static (compilation d'un binaire minimal)."""

import subprocess
import sys
from pathlib import Path


def compile_minimal_elf(tmpdir: Path) -> Path | None:
    """Compile un C minimal en ELF. Retourne le chemin du binaire ou None si indisponible.

    Sur macOS/Windows, gcc natif produit du Mach-O ou PE — pas de l'ELF.
    On retourne None pour que les tests appelants fassent skipTest.
    """
    if sys.platform != "linux":
        return None
    src = tmpdir / "minimal.c"
    src.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    out = tmpdir / "minimal.elf"
    try:
        r = subprocess.run(
            ["gcc", "-O0", "-o", str(out), str(src)],
            capture_output=True,
            timeout=15,
        )
        return out if r.returncode == 0 and out.exists() else None
    except (OSError, subprocess.TimeoutExpired):
        return None
