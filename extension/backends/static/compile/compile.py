# SPDX-License-Identifier: AGPL-3.0-only
"""Moteur de compilation générique — aucun toolchain n'est câblé en dur.

Tous les outils sont déclarés dans .pile-ou-face/compilers.json (ou via
la variable d'environnement COMPILERS_CONFIG). Le moteur détecte ce qui
est disponible localement (champ "native_cmd") ou via Docker (champ "docker_image"),
et route automatiquement vers le bon compilateur.

Ajouter un nouveau compilateur = ajouter une entrée JSON + créer docker/compilers/<name>/.
Zéro code Python à modifier dans ce fichier.

CLI (via __main__.py) :
  python -m backends.static.compile --src file.c --lang c --target elf-x64 --output out.elf
  python -m backends.static.compile --list

Output JSON :
  {
    "output_path": "/path/to/out.elf",
    "compiler_used": "gcc-multiarch",
    "target": "elf-x64",
    "exit_code": 0,
    "stderr": ""
  }
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import subprocess
from pathlib import Path
from typing import Any

_COMPILERS_CONFIG = (
    Path.cwd() / ".pile-ou-face" / "compilers.json"
)
_POF_DIR = Path.cwd()  # racine du projet (workspace root passé en cwd par l'extension)
_DOCKER_AVAILABLE_CACHE: dict[str, bool] = {}


def _load_compilers(config_path: Path | None = None) -> dict[str, dict[str, Any]]:
    """Charge les toolchains depuis .pile-ou-face/compilers.json."""
    env_path = os.environ.get("COMPILERS_CONFIG", "").strip()
    cfg_path = config_path or (Path(env_path) if env_path else _COMPILERS_CONFIG)
    try:
        raw = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    entries = raw.get("compilers", raw) if isinstance(raw, dict) else {}
    if not isinstance(entries, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for key, value in entries.items():
        if str(key).startswith("_"):
            continue
        if not isinstance(value, dict):
            continue
        result[str(key)] = value
    return result


def _select_toolchain(
    compilers: dict[str, dict[str, Any]],
    lang: str,
    target: str,
) -> str | None:
    """Retourne l'id du premier toolchain supportant lang+target, ou None."""
    for toolchain_id, cfg in compilers.items():
        langs = cfg.get("langs", [])
        targets = cfg.get("targets", [])
        if lang in langs and target in targets:
            return toolchain_id
    return None


def _is_docker_image_available(image: str) -> bool:
    """Vérifie si une image Docker est disponible localement (avec cache)."""
    if image in _DOCKER_AVAILABLE_CACHE:
        return _DOCKER_AVAILABLE_CACHE[image]
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=5,
        )
        available = r.returncode == 0
    except Exception:
        available = False
    _DOCKER_AVAILABLE_CACHE[image] = available
    return available


def _build_target_flags_native(toolchain_id: str, target: str) -> list[str]:
    """Retourne les flags de cross-compilation pour invocation native gcc/clang."""
    if toolchain_id == "gcc-multiarch":
        return {"elf-x64": ["-m64"], "elf-x86": ["-m32"]}.get(target, [])
    if toolchain_id == "clang":
        return {
            "macho-x64": ["-target", "x86_64-apple-macosx10.15"],
            "macho-arm64": ["-target", "arm64-apple-macosx12.0"],
        }.get(target, [])
    return []


def _run_native_compiler(
    toolchain_id: str,
    cfg: dict[str, Any],
    src: str,
    lang: str,
    target: str,
    output: str,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Invoque le compilateur natif directement."""
    native_cmd_cpp = cfg.get("native_cmd_cpp", "")
    native_cmd = native_cmd_cpp if lang == "cpp" and native_cmd_cpp else cfg.get("native_cmd", "")
    arch_flags = _build_target_flags_native(toolchain_id, target)
    extra = flags if flags else ["-O0", "-g"]
    cmd: list[str] = [native_cmd, *arch_flags, *extra, "-o", output, src]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return {
            "output_path": output if r.returncode == 0 else None,
            "compiler_used": toolchain_id,
            "target": target,
            "exit_code": r.returncode,
            "stderr": r.stderr,
        }
    except Exception as exc:
        return {
            "output_path": None,
            "compiler_used": toolchain_id,
            "target": target,
            "exit_code": -1,
            "stderr": str(exc),
        }


def _run_docker_compiler(
    toolchain_id: str,
    cfg: dict[str, Any],
    src: str,
    lang: str,
    target: str,
    output: str,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Invoque le compilateur via Docker."""
    image = cfg.get("docker_image", "")
    docker_cmd_template = cfg.get("docker_command", [])

    src_path = Path(src).resolve()
    out_path = Path(output).resolve()
    out_dir = out_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    src_container = f"/src/{src_path.name}"
    out_container = f"/out/{out_path.name}"

    docker_cmd = [
        str(c)
        .replace("{src}", src_container)
        .replace("{lang}", lang)
        .replace("{target}", target)
        .replace("{output}", out_container)
        for c in docker_cmd_template
    ]

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{src_path.parent}:/src:ro",
        "-v",
        f"{out_dir}:/out",
        image,
        *docker_cmd,
        *(["--flags", json.dumps(flags)] if flags else []),
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
        return {
            "output_path": str(out_path) if r.returncode == 0 and out_path.exists() else None,
            "compiler_used": toolchain_id,
            "target": target,
            "exit_code": r.returncode,
            "stderr": r.stderr,
        }
    except Exception as exc:
        return {
            "output_path": None,
            "compiler_used": toolchain_id,
            "target": target,
            "exit_code": -1,
            "stderr": str(exc),
        }


def compile_source(
    src: str,
    lang: str,
    target: str,
    output: str | None = None,
    compilers: dict[str, dict[str, Any]] | None = None,
    config_path: Path | None = None,
    flags: list[str] | None = None,
) -> dict[str, Any]:
    """Point d'entrée principal du moteur.

    Args:
        src:        Chemin absolu vers le fichier source.
        lang:       Langage source ("c", "cpp", "rust", "go").
        target:     Target ID ("elf-x64", "pe-x64", "macho-arm64", ...).
        output:     Chemin de sortie du binaire (auto si None).
        compilers:  Optionnel — dict de config (pour les tests).
        config_path: Optionnel — chemin vers compilers.json (pour les tests).
        flags:      Flags extra passés au compilateur (ex: ["-O2", "-fno-pie"]).

    Returns:
        dict avec "output_path", "compiler_used", "target", "exit_code", "stderr".
        En cas d'erreur fatale : {"error": "<message>"}.
    """
    if not Path(src).exists():
        return {"error": f"Source introuvable : {src}"}

    cfg = compilers if compilers is not None else _load_compilers(config_path)

    toolchain_id = _select_toolchain(cfg, lang, target)
    if toolchain_id is None:
        return {
            "error": (
                f"Aucun toolchain disponible pour lang={lang!r} target={target!r}. "
                "Lance: make compiler-docker-build COMPILER=gcc-multiarch"
            )
        }

    toolchain_cfg = cfg[toolchain_id]

    if output is None:
        ext = {"pe-x64": ".exe", "pe-x86": ".exe"}.get(target, ".elf")
        output = str(_POF_DIR / "examples" / f"compiled_{target}{ext}")

    native_cmd = toolchain_cfg.get("native_cmd", "")
    native_platforms = toolchain_cfg.get("native_platforms", [])
    current_platform = platform.system().lower()
    native_allowed = not native_platforms or current_platform in native_platforms
    if native_allowed and native_cmd and shutil.which(native_cmd):
        return _run_native_compiler(toolchain_id, toolchain_cfg, src, lang, target, output, flags)

    docker_image = toolchain_cfg.get("docker_image", "")
    if docker_image and _is_docker_image_available(docker_image):
        return _run_docker_compiler(toolchain_id, toolchain_cfg, src, lang, target, output, flags)

    platform_note = ""
    if native_platforms and current_platform not in native_platforms:
        platform_note = (
            f" (sur {current_platform}, gcc\u202f=\u202fApple Clang — ne produit pas d'ELF/PE)"
        )
    return {
        "error": (
            f"Docker requis pour {toolchain_id!r}{platform_note}. "
            f"Lance\u00a0: make compiler-docker-build COMPILER={toolchain_id}"
        )
    }


def list_available_compilers(
    compilers: dict[str, dict[str, Any]] | None = None,
    config_path: Path | None = None,
) -> list[dict[str, Any]]:
    """Retourne la liste des toolchains avec leur statut de disponibilité."""
    cfg = compilers if compilers is not None else _load_compilers(config_path)
    result = []
    for tid, tcfg in cfg.items():
        native_cmd = tcfg.get("native_cmd", "")
        docker_image = tcfg.get("docker_image", "")
        native_platforms = tcfg.get("native_platforms", [])
        current_platform = platform.system().lower()
        native_allowed = not native_platforms or current_platform in native_platforms
        native_ok = bool(native_allowed and native_cmd and shutil.which(native_cmd))
        docker_ok = bool(docker_image and _is_docker_image_available(docker_image))
        native_platform_restricted = bool(
            native_platforms and current_platform not in native_platforms
        )
        result.append(
            {
                "id": tid,
                "label": tcfg.get("label", tid),
                "langs": tcfg.get("langs", []),
                "targets": tcfg.get("targets", []),
                "available_native": native_ok,
                "available_docker": docker_ok,
                "available": native_ok or docker_ok,
                "native_platform_restricted": native_platform_restricted,
                "native_platforms": native_platforms,
            }
        )
    return result


if __name__ == "__main__":
    import argparse as _ap
    import sys as _sys

    _parser = _ap.ArgumentParser(description="Moteur de compilation multi-toolchain")
    _parser.add_argument("--src")
    _parser.add_argument("--lang")
    _parser.add_argument("--target")
    _parser.add_argument("--output")
    _parser.add_argument("--flags", default="[]")
    _parser.add_argument("--list", action="store_true")
    _args = _parser.parse_args()

    if _args.list:
        print(json.dumps(list_available_compilers(), indent=2))
        _sys.exit(0)

    if not _args.src or not _args.lang or not _args.target:
        _parser.error("--src, --lang et --target sont requis")

    try:
        _flags = json.loads(_args.flags) if _args.flags and _args.flags != "[]" else None
    except json.JSONDecodeError:
        _flags = None

    _result = compile_source(_args.src, _args.lang, _args.target, _args.output, flags=_flags)
    print(json.dumps(_result))
    _sys.exit(0)  # exit_code in JSON carries the compilation result; caller parses stdout
