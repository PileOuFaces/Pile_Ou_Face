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
import tempfile
import time


def parse_time_output_macos(output: str) -> dict:
    elapsed_match = re.search(r"^\s*([\d.]+)\s+real", output, re.MULTILINE)
    footprint_match = re.search(
        r"^\s*(\d+)\s+peak memory footprint", output, re.MULTILINE
    )
    max_rss_match = re.search(
        r"^\s*(\d+)\s+maximum resident set size", output, re.MULTILINE
    )
    peak_rss = (
        int(footprint_match.group(1))
        if footprint_match
        else (int(max_rss_match.group(1)) if max_rss_match else 0)
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


def parse_process_tree_rss(output: str, root_pid: int) -> int:
    """Retourne le RSS cumule de ``root_pid`` et de tous ses descendants.

    ``ps`` exprime le RSS en KiB sur Linux comme sur macOS. Une lecture
    invalide ou un processus disparu pendant l'echantillonnage est ignore.
    """
    rss_by_pid: dict[int, int] = {}
    children_by_pid: dict[int, list[int]] = {}
    for line in output.splitlines():
        try:
            pid_text, ppid_text, rss_text = line.split()
            pid, ppid, rss_kib = int(pid_text), int(ppid_text), int(rss_text)
        except (TypeError, ValueError):
            continue
        rss_by_pid[pid] = rss_kib * 1024
        children_by_pid.setdefault(ppid, []).append(pid)

    total = 0
    pending = [root_pid]
    seen: set[int] = set()
    while pending:
        pid = pending.pop()
        if pid in seen:
            continue
        seen.add(pid)
        total += rss_by_pid.get(pid, 0)
        pending.extend(children_by_pid.get(pid, ()))
    return total


def process_tree_rss_bytes(root_pid: int) -> int:
    snapshot = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,rss="],
        capture_output=True,
        text=True,
        check=False,
    )
    if snapshot.returncode != 0:
        raise RuntimeError(f"impossible de mesurer le RSS: {snapshot.stderr.strip()}")
    return parse_process_tree_rss(snapshot.stdout, root_pid)


def kill_process_group(proc: subprocess.Popen) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except ProcessLookupError:
        pass


def run_measured(
    command: list[str],
    timeout_s: int,
    env: dict | None = None,
    memory_limit_bytes: int | None = None,
) -> dict:
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
    started_at = time.monotonic()
    peak_observed_rss = 0
    timed_out = False
    memory_limited = False
    with tempfile.TemporaryFile(mode="w+") as stderr_file:
        proc = subprocess.Popen(
            wrapped,
            stdout=subprocess.DEVNULL,
            stderr=stderr_file,
            text=True,
            start_new_session=True,
            env=env,
        )
        while proc.poll() is None:
            elapsed = time.monotonic() - started_at
            if elapsed >= timeout_s:
                timed_out = True
                kill_process_group(proc)
                break
            if memory_limit_bytes is not None:
                try:
                    current_rss = process_tree_rss_bytes(proc.pid)
                except Exception:
                    # Fail closed: never leave an unbounded workload running
                    # when its memory guard cannot be sampled.
                    kill_process_group(proc)
                    proc.wait()
                    raise
                peak_observed_rss = max(peak_observed_rss, current_rss)
                if current_rss >= memory_limit_bytes:
                    memory_limited = True
                    kill_process_group(proc)
                    break
            time.sleep(0.05)

        proc.wait()
        stderr_file.seek(0)
        stderr = stderr_file.read()

    measured = parser(stderr)
    elapsed = time.monotonic() - started_at
    return {
        "returncode": None if timed_out or memory_limited else proc.returncode,
        "peak_rss_bytes": max(measured["peak_rss_bytes"], peak_observed_rss),
        "elapsed_s": max(measured["elapsed_s"], elapsed),
        "timed_out": timed_out,
        "memory_limited": memory_limited,
        "stderr_tail": stderr[-2000:],
    }
