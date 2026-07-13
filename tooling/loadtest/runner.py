# SPDX-License-Identifier: AGPL-3.0-only
"""Exécute une commande enveloppée par /usr/bin/time pour mesurer le pic
réel de RSS (résident set size) et le temps écoulé — une mesure noyau,
pas une estimation applicative.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys


def parse_time_output_macos(output: str) -> dict:
    elapsed_match = re.search(r"^\s*([\d.]+)\s+real", output, re.MULTILINE)
    footprint_match = re.search(r"^\s*(\d+)\s+peak memory footprint", output, re.MULTILINE)
    max_rss_match = re.search(r"^\s*(\d+)\s+maximum resident set size", output, re.MULTILINE)
    peak_rss = int(footprint_match.group(1)) if footprint_match else (
        int(max_rss_match.group(1)) if max_rss_match else 0
    )
    return {
        "elapsed_s": float(elapsed_match.group(1)) if elapsed_match else 0.0,
        "peak_rss_bytes": peak_rss,
    }


def parse_time_output_linux(output: str) -> dict:
    elapsed_match = re.search(r"Elapsed \(wall clock\) time.*?:\s*([\d:.]+)", output)
    rss_match = re.search(r"Maximum resident set size \(kbytes\):\s*(\d+)", output)
    elapsed_s = 0.0
    if elapsed_match:
        parts = elapsed_match.group(1).split(":")
        parts = [float(p) for p in parts]
        while len(parts) < 3:
            parts.insert(0, 0.0)
        h, m, s = parts[-3:]
        elapsed_s = h * 3600 + m * 60 + s
    return {
        "elapsed_s": elapsed_s,
        "peak_rss_bytes": int(rss_match.group(1)) * 1024 if rss_match else 0,
    }


def run_measured(command: list[str], timeout_s: int, env: dict | None = None) -> dict:
    """Exécute `command` enveloppée par /usr/bin/time, retourne les mesures.

    Décision : si /usr/bin/time (ou la commande enveloppée) est introuvable,
    ce n'est pas un échec normal de la commande analysée mais un
    environnement cassé (outil système absent) — on laisse `FileNotFoundError`
    se propager plutôt que de la masquer dans le dict de retour. Un appelant
    qui lance une campagne de mesures doit savoir immédiatement que
    l'environnement est mal configuré, pas voir un `returncode` ambigu.

    `env`: variables d'environnement pour le processus enfant. `None`
    (défaut) hérite de `os.environ`, comme avant l'ajout de ce paramètre.

    Returns:
        dict avec: returncode, peak_rss_bytes, elapsed_s, timed_out, stderr_tail
    """
    if sys.platform == "darwin":
        wrapped = ["/usr/bin/time", "-l"] + command
        parser = parse_time_output_macos
    else:
        wrapped = ["/usr/bin/time", "-v"] + command
        parser = parse_time_output_linux

    # stdout discarded: not needed for measurement (only /usr/bin/time's
    # stderr is parsed), and capturing it would undermine this tool's own
    # memory-safety purpose for scenarios with large output (e.g. disasm.py
    # on big binaries can emit megabytes of stdout).
    proc = subprocess.Popen(
        wrapped,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
        env=env,
    )
    try:
        _, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        # subprocess.run's default timeout handling only kills the direct
        # child (/usr/bin/time), leaving the actual analyzed command (its
        # grandchild) running in the background. Killing the whole process
        # group ensures the wrapped command dies too.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.communicate()
        return {
            "returncode": None,
            "peak_rss_bytes": 0,
            "elapsed_s": float(timeout_s),
            "timed_out": True,
            "stderr_tail": "",
        }

    measured = parser(stderr)
    return {
        "returncode": proc.returncode,
        "peak_rss_bytes": measured["peak_rss_bytes"],
        "elapsed_s": measured["elapsed_s"],
        "timed_out": False,
        "stderr_tail": stderr[-2000:],
    }
