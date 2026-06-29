# SPDX-License-Identifier: AGPL-3.0-only
"""Moteur de décompilation générique — aucun décompilateur n'est câblé en dur.

Tous les outils sont déclarés dans .pile-ou-face/decompilers.json (ou via
la variable d'environnement DECOMPILERS_CONFIG). Le moteur détecte ce qui
est disponible localement (champ "detect") ou via Docker (champ "docker_image"),
et route automatiquement vers le meilleur résultat.

Ajouter un nouveau décompilateur = ajouter une entrée JSON + éventuellement
un adapter dans son container. Zéro code Python à modifier dans ce fichier.

CLI (via __main__.py) :
  python -m backends.static.decompile --binary <path> [--addr 0x401000] [--full]
  python -m backends.static.decompile --list --provider local

Output JSON :
  {
    "addr": "0x401000",
    "code": "int f() { ... }",
    "error": null
  }
"""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from backends.shared.log import get_logger
from backends.static.annotations.typed_struct_refs import (
    build_typed_struct_index,
    typed_struct_signature,
)

_log = get_logger(__name__)
_FILE_SIGNATURE_CACHE: dict[tuple[str, int, int], str] = {}
_DECOMPILE_CACHE_VERSION = "8"
_PLACEHOLDER_SYMBOL_RE = re.compile(
    r"\b(?:local_[0-9a-f]+|var_[0-9a-f]+(?:h)?|param_\d+|arg_[a-z0-9_]+|auStack_[0-9a-f]+|puStack_[0-9a-f]+|"
    r"DAT_[0-9a-f]+|LAB_[0-9a-f]+|PTR_[0-9a-f]+|code_[0-9a-f]+)\b",
    flags=re.IGNORECASE,
)
_CALL_NAME_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
_TYPE_HINT_RE = re.compile(
    r"\b(?:char|short|int|long|float|double|bool|size_t|ssize_t|"
    r"uint(?:8|16|32|64)_t|int(?:8|16|32|64)_t|struct)\b"
)
# Patterns génériques indiquant un pseudo-C encore trop proche de l'assembleur.
# Intentionnellement indépendants du décompilateur et de l'architecture :
#   - labels de saut bruts (loc_0x..., LAB_..., case_...)
#   - préfixes de symboles non résolus issus de formats ELF/PE/Mach-O
#     (sym., imp., sub_, FUN_, nullsub_)
#   - commentaires de référence croisée asm (XREF, WARN, orphan)
#   - tailles mémoire exprimées comme qualificateurs de type bas niveau
#     (BYTE, WORD, DWORD, QWORD, LOBYTE, HIBYTE — communs à IDA, Ghidra, BinaryNinja, etc.)
_LOW_LEVEL_PSEUDOC_RE = re.compile(
    r"\b(?:loc_0x[0-9a-f]+|LAB_[0-9a-f]+|case_[0-9a-f]+"
    r"|sym\.[A-Za-z_][A-Za-z0-9_.]*|imp\.[A-Za-z_][A-Za-z0-9_]*"
    r"|sub_[0-9a-f]+|FUN_[0-9a-f]+|nullsub_[0-9a-f]+"
    r"|CODE\s+XREF|DATA\s+XREF|orphan"
    r"|LOBYTE|HIBYTE|BYTE\s*\[|WORD\s*\[|DWORD\s*\[|QWORD\s*\[)\b",
    flags=re.IGNORECASE,
)
_cfg_env = os.environ.get("DECOMPILERS_CONFIG", "").strip()
_DECOMPILERS_CONFIG = (
    Path(_cfg_env)
    if _cfg_env
    else Path.home() / ".config" / "pile-ou-face" / "decompilers.json"
)
_pof_storage_env = os.environ.get("POF_STORAGE_DIR", "").strip()
_POF_DIR = (
    Path(_pof_storage_env).resolve()
    if _pof_storage_env
    else Path.home() / ".config" / "pile-ou-face"
)
_DOCKER_AVAILABLE_CACHE: dict[str, bool] = {}
_BUILTIN_TARGET_POLICIES: dict[str, dict[str, Any]] = {
    "ghidra": {
        "supports": {
            "formats": ["elf", "pe", "macho"],
            "architectures": [
                "x86",
                "x86_64",
                "arm",
                "arm64",
                "mips",
                "mips64",
                "ppc",
                "ppc64",
            ],
        },
        "quality_bias": 20,
    },
    "angr": {
        "supports": {
            "formats": ["elf", "pe", "macho"],
            "architectures": ["x86", "x86_64", "arm", "arm64", "mips", "mips64"],
        },
        "quality_bias": 5,
    },
    "retdec": {
        "supports": {
            "formats": ["elf", "pe", "macho"],
            "architectures": ["x86", "x86_64", "arm", "arm64", "mips", "mips64"],
        },
    },
}


def _binary_info(binary_path: str) -> dict[str, str]:
    """Retourne les métadonnées du binaire pour les tokens {arch}, {bitness}, {format}.

    Utilise lief si disponible, sinon détecte via magic bytes.
    Retourne toujours un dict complet — jamais d'exception.
    """
    _ARCH_MAP_LIEF = {
        "X86_64": ("x86_64", "64"),
        "X86": ("x86", "32"),
        "I386": ("x86", "32"),
        "AMD64": ("x86_64", "64"),
        "ARM": ("arm", "32"),
        "ARM64": ("arm64", "64"),
        "AARCH64": ("arm64", "64"),
        "MIPS": ("mips", "32"),
        "MIPS64": ("mips64", "64"),
        "PPC": ("ppc", "32"),
        "PPC64": ("ppc64", "64"),
        "POWERPC": ("ppc", "32"),
        "POWERPC64": ("ppc64", "64"),
    }
    try:
        if not Path(binary_path).exists():
            raise FileNotFoundError(binary_path)
        import lief  # type: ignore[import]

        binary = lief.parse(binary_path)
        if binary is None:
            raise ValueError("lief.parse returned None")
        # Déterminer le format
        if isinstance(binary, lief.ELF.Binary):
            fmt = "elf"
        elif isinstance(binary, lief.PE.Binary):
            fmt = "pe"
        elif isinstance(binary, lief.MachO.Binary):
            fmt = "macho"
        else:
            fmt = "raw"
        # Déterminer l'architecture
        arch_name = ""
        if hasattr(binary, "header"):
            hdr = binary.header
            for attr in ("machine_type", "machine", "cpu_type"):
                val = getattr(hdr, attr, None)
                if val is not None:
                    arch_name = str(val).split(".")[-1].upper()
                    break
        arch, bitness = _ARCH_MAP_LIEF.get(arch_name, ("unknown", "64"))
        return {"arch": arch, "bitness": bitness, "format": fmt}
    except Exception:
        pass
    # Fallback : magic bytes
    try:
        with open(binary_path, "rb") as fh:
            magic = fh.read(5)
    except OSError:
        return {"arch": "unknown", "bitness": "64", "format": "raw"}
    if magic[:4] == b"\x7fELF":
        bitness = "64" if len(magic) >= 5 and magic[4] == 2 else "32"
        return {"arch": "unknown", "bitness": bitness, "format": "elf"}
    if magic[:2] in (b"MZ", b"ZM"):
        return {"arch": "unknown", "bitness": "32", "format": "pe"}
    if magic[:4] in (b"\xca\xfe\xba\xbe", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return {"arch": "unknown", "bitness": "64", "format": "macho"}
    return {"arch": "unknown", "bitness": "64", "format": "raw"}


# ---------------------------------------------------------------------------
# Cache disque
# ---------------------------------------------------------------------------


def _file_signature(path: str | None) -> str:
    """Retourne une signature sha256 stable du contenu du fichier."""
    if not path:
        return ""
    try:
        file_path = Path(path)
        stat = file_path.stat()
    except OSError:
        return ""
    cache_key = (str(file_path.resolve()), int(stat.st_mtime_ns), int(stat.st_size))
    cached = _FILE_SIGNATURE_CACHE.get(cache_key)
    if cached:
        return cached
    digest = hashlib.sha256()
    try:
        with file_path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return ""
    signature = digest.hexdigest()
    _FILE_SIGNATURE_CACHE.clear()
    _FILE_SIGNATURE_CACHE[cache_key] = signature
    return signature


def _normalize_decompiler_id(value: str | None) -> str:
    """Normalize an external/backend identifier for registry lookups."""
    normalized = re.sub(r"[^a-z0-9_.-]+", "-", str(value or "").strip().lower())
    return normalized.strip("-")


def _load_decompilers(
    config_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    """Charge tous les décompilateurs depuis .pile-ou-face/decompilers.json.

    Chaque entrée peut déclarer :
      - "command" / "full_command"       : invocation locale
      - "docker_image" + "docker_command": invocation Docker
      - "detect"                         : executable à chercher dans PATH pour
                                           confirmer que l'outil est installé
                                           (ex: "analyzeHeadless" pour Ghidra)
      - "detect_cmd"                     : commande à lancer pour vérifier la dispo
                                           (ex: "ghidra-server check" pour Ghidra Server)
                                           — disponible si returncode == 0
      - "output_format"                  : "json" | "c" | "text" (défaut: "json")
      - "supports_full"                  : bool (défaut: true)
      - "timeout"                        : secondes (défaut: 120)
      - "env"                            : dict de variables d'environnement
      - "network"                        : réseau Docker "none"|"bridge"|"host"
      - "docker_extra_args"              : args supplémentaires pour docker run

    Le placeholder {root_dir} dans les commandes est remplacé par le chemin
    absolu de la racine du projet (utile pour pointer vers des scripts internes).
    """
    env_path = os.environ.get("DECOMPILERS_CONFIG", "").strip()
    cfg_path = config_path or (Path(env_path) if env_path else _DECOMPILERS_CONFIG)
    try:
        raw = json.loads(Path(cfg_path).read_text(encoding="utf-8"))
    except Exception:
        return {}
    entries = raw.get("decompilers", raw) if isinstance(raw, dict) else {}
    if not isinstance(entries, dict):
        return {}
    result: dict[str, dict[str, Any]] = {}
    for key, value in entries.items():
        if str(key).startswith("_"):  # clés de commentaire (_comment, etc.)
            continue
        decompiler_id = _normalize_decompiler_id(str(key))
        if not decompiler_id:
            continue
        if not isinstance(value, dict):
            continue

        command = value.get("command")
        docker_command = value.get("docker_command")
        endpoint_url = str(value.get("endpoint") or "").strip()
        has_http = endpoint_url.startswith(("http://", "https://"))
        has_local = isinstance(command, list) and len(command) > 0
        has_docker = isinstance(docker_command, list) and len(docker_command) > 0
        if not has_local and not has_docker and not has_http:
            _log.debug(
                "Décompilateur '%s' ignoré : aucune command, docker_command ni endpoint",
                decompiler_id,
            )
            continue

        normalized: dict[str, Any] = {}
        normalized["id"] = decompiler_id
        normalized["label"] = str(value.get("label") or decompiler_id)

        # Champ detect : executable dont la présence confirme l'install locale
        detect = str(value.get("detect") or "").strip()
        if detect:
            normalized["detect"] = detect

        # Commandes locales (remplacement de {root_dir})
        root_dir = str(_POF_DIR)
        if has_local:
            normalized["command"] = [
                str(p).replace("{root_dir}", root_dir) for p in command
            ]  # type: ignore[union-attr]
        full_command = value.get("full_command")
        if isinstance(full_command, list) and full_command:
            normalized["full_command"] = [
                str(p).replace("{root_dir}", root_dir) for p in full_command
            ]

        # Commandes Docker
        if has_docker:
            normalized["docker_command"] = [str(p) for p in docker_command]  # type: ignore[union-attr]
        docker_full = value.get("docker_full_command")
        if isinstance(docker_full, list) and docker_full:
            normalized["docker_full_command"] = [str(p) for p in docker_full]
        docker_image = str(value.get("docker_image") or "").strip()
        if docker_image:
            normalized["docker_image"] = docker_image

        normalized["supports_full"] = bool(value.get("supports_full", True))
        raw_timeout = value.get("timeout")
        if raw_timeout is not None:
            with contextlib.suppress(TypeError, ValueError):
                normalized["timeout"] = max(5, int(raw_timeout))

        output_format = str(value.get("output_format") or "json").strip().lower()
        if output_format not in ("json", "c", "text"):
            output_format = "json"
        normalized["output_format"] = output_format

        supports_cfg = value.get("supports") or {}
        if isinstance(supports_cfg, dict):
            normalized_supports: dict[str, list[str]] = {}
            for cfg_key, normalized_key in (
                ("formats", "formats"),
                ("architectures", "architectures"),
                ("archs", "architectures"),
                ("bitness", "bitness"),
            ):
                raw_values = supports_cfg.get(cfg_key)
                if not isinstance(raw_values, list):
                    continue
                cleaned = [
                    str(item).strip().lower()
                    for item in raw_values
                    if str(item).strip()
                ]
                if cleaned:
                    normalized_supports[normalized_key] = cleaned
            if normalized_supports:
                normalized["supports"] = normalized_supports

        exclude_targets = value.get("exclude_targets") or []
        if isinstance(exclude_targets, list):
            normalized_excludes: list[dict[str, Any]] = []
            for entry_cfg in exclude_targets:
                if not isinstance(entry_cfg, dict):
                    continue
                normalized_entry: dict[str, Any] = {}
                for source_key, target_key in (
                    ("format", "format"),
                    ("arch", "arch"),
                    ("architecture", "arch"),
                    ("bitness", "bitness"),
                    ("reason", "reason"),
                ):
                    raw_val = entry_cfg.get(source_key)
                    if raw_val is None or str(raw_val).strip() == "":
                        continue
                    normalized_entry[target_key] = (
                        str(raw_val).strip().lower()
                        if target_key != "reason"
                        else str(raw_val).strip()
                    )
                if "full" in entry_cfg:
                    normalized_entry["full"] = bool(entry_cfg.get("full"))
                if normalized_entry:
                    normalized_excludes.append(normalized_entry)
            if normalized_excludes:
                normalized["exclude_targets"] = normalized_excludes

        network = str(value.get("network") or "none").strip()
        if network not in ("none", "bridge", "host", ""):
            network = "none"
        normalized["network"] = network or "none"

        env_vars = value.get("env") or {}
        if isinstance(env_vars, dict):
            normalized["env"] = {str(k): str(v) for k, v in env_vars.items()}

        extra_args = value.get("docker_extra_args") or []
        if isinstance(extra_args, list):
            normalized["docker_extra_args"] = [str(a) for a in extra_args]

        output_filter = value.get("output_filter")
        if isinstance(output_filter, list) and output_filter:
            valid_filters = [str(f) for f in output_filter if f and str(f).strip()]
            if valid_filters:
                normalized["output_filter"] = valid_filters

        if has_http:
            normalized["endpoint"] = endpoint_url
            normalized["method"] = str(value.get("method") or "POST").strip().upper()
            body_tmpl = value.get("body_template")
            if isinstance(body_tmpl, str):
                normalized["body_template"] = body_tmpl
            raw_headers = value.get("headers")
            if isinstance(raw_headers, dict):
                normalized["headers"] = {str(k): str(v) for k, v in raw_headers.items()}
            auth_cfg = value.get("auth")
            if isinstance(auth_cfg, dict):
                auth_type = str(auth_cfg.get("type") or "").lower()
                if auth_type in ("bearer", "api_key", "basic"):
                    normalized_auth: dict[str, str] = {"type": auth_type}
                    for auth_key in ("token_env", "user_env", "password_env", "header"):
                        val = auth_cfg.get(auth_key)
                        if val:
                            normalized_auth[auth_key] = str(val)
                    normalized["auth"] = normalized_auth

        result[decompiler_id] = normalized
    return result


# Alias pour compatibilité interne
def _load_custom_decompilers(
    config_path: Path | None = None,
) -> dict[str, dict[str, Any]]:
    return _load_decompilers(config_path)


def _custom_decompiler_labels() -> dict[str, str]:
    return {
        key: str(value.get("label") or key)
        for key, value in _load_decompilers().items()
    }


def _docker_env_var_name_for_decompiler(decompiler: str) -> str:
    suffix = re.sub(
        r"[^A-Z0-9]+", "_", _normalize_decompiler_id(decompiler).upper()
    ).strip("_")
    return f"POF_DECOMPILER_IMAGE_{suffix}"


def _get_decompiler_docker_image(decompiler: str) -> str:
    normalized = _normalize_decompiler_id(decompiler)
    # Variable d'env prioritaire (permet de surcharger l'image sans toucher au JSON)
    specific = os.environ.get(
        _docker_env_var_name_for_decompiler(normalized), ""
    ).strip()
    if specific:
        return specific
    entry = _load_decompilers().get(normalized)
    if entry:
        img = str(entry.get("docker_image") or "").strip()
        if img:
            return img
    # Fallback OCI : ghcr.io/pileoufaces/pile-ou-face/decompiler-{name}:latest
    # Permet d'utiliser un décompilateur builtin même sans entrée dans decompilers.json
    if normalized:
        return f"ghcr.io/pileoufaces/pile-ou-face/decompiler-{normalized}:latest"
    return ""


def _docker_pull_image(image_name: str) -> bool:
    """Lance docker pull sur l'image et retourne True si succès.

    Uniquement pour les images avec un registre distant (ghcr.io, etc.).
    Ne tente pas de puller des images locales de dev.
    """
    if _is_local_dev_docker_image(image_name):
        return False
    docker_exe = _find_docker_executable() or "docker"
    _log.info("Pulling Docker image %s …", image_name)
    try:
        proc = subprocess.run(
            [docker_exe, "pull", image_name],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if proc.returncode == 0:
            _log.info("Pull réussi : %s", image_name)
            _DOCKER_AVAILABLE_CACHE[image_name] = True
            return True
        _log.warning("docker pull %s a échoué (code %d): %s", image_name, proc.returncode, proc.stderr.strip()[-400:])
        return False
    except (subprocess.TimeoutExpired, OSError) as exc:
        _log.warning("docker pull %s exception: %s", image_name, exc)
        return False


def _get_all_docker_images() -> dict[str, str]:
    images = {}
    for name in _load_decompilers():
        image = _get_decompiler_docker_image(name)
        if image:
            images[name] = image
    return images


def _format_custom_command(
    command: list[str],
    *,
    binary_path: str,
    addr: str = "",
    func_name: str = "",
    mode: str = "function",
    out_file: Path | None = None,
) -> list[str]:
    # Détecter si la commande utilise des tokens binaires avant d'appeler lief
    needs_binary_info = any(
        "{arch}" in str(p) or "{bitness}" in str(p) or "{format}" in str(p)
        for p in command
    )
    binary_meta = _binary_info(binary_path) if needs_binary_info else {}
    replacements = {
        "binary": binary_path,
        "addr": addr,
        "func_name": func_name,
        "mode": mode,
        "out": str(out_file or ""),
        "arch": binary_meta.get("arch", "unknown"),
        "bitness": binary_meta.get("bitness", "64"),
        "format": binary_meta.get("format", "raw"),
    }
    formatted: list[str] = []
    for part in command:
        text = str(part)
        for key, replacement in replacements.items():
            text = text.replace("{" + key + "}", replacement)
        formatted.append(text)
    return formatted


def _parse_c_like_function_blocks(source: str) -> list[dict[str, Any]]:
    """Découpe du pseudo-C brut produit par n'importe quel décompilateur en blocs de fonctions.

    Chaque bloc est un dict {"addr": str, "name": str, "code": str}.
    - Les stubs d'import (sym.imp.*) sont ignorés — convention ELF standard pour les PLT stubs.
    - Les mots-clés C (if/while/for/switch/return/else) ne sont pas confondus avec des noms de fonctions.
    - Les commentaires "// address: 0x..." sont détectés et associés au bloc suivant
      (format produit par divers outils : Ghidra, Binary Ninja, etc.).
    """
    # Mots-clés C qui ne sont jamais des noms de fonctions
    _C_KEYWORDS = frozenset(
        {
            "if",
            "else",
            "while",
            "for",
            "do",
            "switch",
            "case",
            "return",
            "break",
            "continue",
            "goto",
            "sizeof",
            "typedef",
            "struct",
            "enum",
            "union",
            "static",
            "extern",
            "inline",
            "const",
            "volatile",
        }
    )
    _IMPORT_STUB_RE = re.compile(r"\bsym\.imp\.", re.IGNORECASE)
    # Commentaire d'adresse avant chaque fonction : "// address: 0x..."
    _ADDR_COMMENT_RE = re.compile(r"//\s*address:\s*(0x[0-9a-fA-F]+)", re.IGNORECASE)
    # Signature de fonction : type retour + nom + args + accolade optionnelle
    # On exige qu'il y ait au moins un espace dans le type (pour éviter "if(...")
    _SIG_RE = re.compile(
        r"^([\w\s\*]+?\s+)"  # type retour avec au moins un espace
        r"(\w[\w\.\:]*)"  # nom de la fonction
        r"\s*\([^)]*\)"  # paramètres
        r"\s*\{?"  # accolade ouvrante optionnelle
        r"\s*$",
    )
    lines = source.splitlines()
    blocks: list[dict[str, Any]] = []
    i = 0
    pending_addr = ""
    while i < len(lines):
        line = lines[i]
        # Récupérer l'adresse depuis un commentaire "// address: 0x..."
        addr_m = _ADDR_COMMENT_RE.search(line)
        if addr_m:
            pending_addr = addr_m.group(1)
            i += 1
            continue
        m = _SIG_RE.match(line)
        if not m:
            i += 1
            continue
        func_name = m.group(2)
        # Exclure les mots-clés C
        if func_name in _C_KEYWORDS:
            i += 1
            continue
        # Exclure les stubs d'import
        if _IMPORT_STUB_RE.search(func_name):
            pending_addr = ""
            i += 1
            continue
        func_addr = pending_addr
        pending_addr = ""
        # Collecter le corps — suivre la profondeur des accolades
        body_lines = [line]
        depth = line.count("{") - line.count("}")
        j = i + 1
        # Si pas d'accolade ouvrante sur la ligne de signature, chercher sur la suivante
        if depth == 0 and j < len(lines):
            body_lines.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        while j < len(lines) and depth > 0:
            body_lines.append(lines[j])
            depth += lines[j].count("{") - lines[j].count("}")
            j += 1
        block_code = "\n".join(body_lines).strip()
        blocks.append({"addr": func_addr, "name": func_name, "code": block_code})
        i = j
    return blocks


def _parse_external_decompiler_output(
    stdout: str,
    *,
    decompiler: str,
    addr: str = "",
    out_file: Path | None = None,
    full: bool = False,
    output_format: str = "json",
) -> dict[str, Any]:
    """Parse la sortie d'un décompilateur custom.

    output_format:
      "json"  — JSON dict ou liste (défaut)
      "c"     — code C brut, parsé en blocs de fonctions
      "text"  — texte brut, retourné tel quel dans code
    """
    text = ""
    if out_file and out_file.exists():
        try:
            text = out_file.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
    if not text:
        text = stdout or ""
    # Filtrage custom par outil (output_filter déclaré dans decompilers.json)
    _tool_filters = (_load_decompilers().get(decompiler or "", {}) or {}).get(
        "output_filter"
    ) or []
    if _tool_filters and text:
        _compiled_filters = [re.compile(f) for f in _tool_filters if f]
        filtered_lines = [
            ln
            for ln in text.splitlines()
            if not any(pat.search(ln) for pat in _compiled_filters)
        ]
        text = "\n".join(filtered_lines)
    # Filtrer les lignes de diagnostic CLI qui polluent stdout.
    # Ces patterns sont génériques : codes ANSI, niveaux de log (ERROR/WARNING/INFO),
    # séparateurs unicode box-drawing — produits par n'importe quel outil en mode verbose.
    raw_text = text
    if output_format in ("c", "text"):
        _CLI_NOISE_RE = re.compile(
            r"^(?:\x1b\[[0-9;]*[A-Za-z]"  # codes ANSI / séquences d'échappement terminal
            r"|ERROR:"
            r"|WARNING:"
            r"|VERBOSE:"
            r"|Usage:"
            r"|INFO:"
            r"|rz_"  # préfixe interne  (rz_config_set, rz_analysis_*, etc.)
            r"|│"  # box-drawing unicode (tableaux CLI)
            r"|─"
            r"|\[x\]"  # indicateurs d'état CLI
            r"|\[!\]"
            r"|\[-\]"
            r")",
        )
        filtered_lines = [
            ln for ln in text.splitlines() if ln.strip() and not _CLI_NOISE_RE.match(ln)
        ]
        text = "\n".join(filtered_lines)
    stripped = text.strip()
    if not stripped:
        # Inclure un extrait du raw pour faciliter le diagnostic
        raw_preview = raw_text.strip()[:300].replace("\n", " | ")
        hint = f" (sortie brute: {raw_preview})" if raw_preview else ""
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"aucune sortie{hint}",
            "decompiler": decompiler,
        }

    # ── Format C/text : pas de parsing JSON ──────────────────────────────────
    if output_format in ("c", "text"):
        if full:
            blocks = (
                _parse_c_like_function_blocks(stripped) if output_format == "c" else []
            )
            return {
                "functions": blocks,
                "code": stripped,
                "error": None,
                "decompiler": decompiler,
            }
        return {"addr": addr, "code": stripped, "error": None, "decompiler": decompiler}

    # ── Format JSON (défaut) ──────────────────────────────────────────────────
    # Tentative de décodage JSON, avec fallback vers C/text brut
    try:
        data = json.loads(stripped)
        if isinstance(data, dict):
            out = dict(data)
            out.setdefault("decompiler", decompiler)
            if full:
                out.setdefault("functions", [])
            else:
                out.setdefault("addr", addr)
                out.setdefault("code", "")
            out.setdefault("error", None)
            return out
        if isinstance(data, list):
            # Liste d'un seul élément avec une erreur → propager l'erreur
            if (
                len(data) == 1
                and isinstance(data[0], dict)
                and data[0].get("error")
                and not data[0].get("code")
            ):
                return {
                    "addr": addr,
                    "code": "",
                    "functions": [],
                    "error": data[0]["error"],
                    "decompiler": decompiler,
                }
            functions = [
                {
                    "addr": str(item.get("addr") or ""),
                    "name": str(item.get("name") or ""),
                    "code": str(item.get("code") or ""),
                    "error": item.get("error"),
                }
                for item in data
                if isinstance(item, dict)
            ]
            if full:
                good = [item for item in functions if item.get("code")]
                if not good:
                    # Toutes les fonctions sont vides → erreur explicite
                    first_err = next(
                        (item.get("error") for item in functions if item.get("error")),
                        None,
                    )
                    return {
                        "functions": [],
                        "code": "",
                        "error": first_err or "aucune fonction décompilée",
                        "decompiler": decompiler,
                    }
                return {
                    "functions": good,
                    "code": "\n\n".join(item["code"] for item in good),
                    "error": None,
                    "decompiler": decompiler,
                }
            chosen = next((item for item in functions if item.get("code")), None)
            if chosen:
                return {
                    **chosen,
                    "decompiler": decompiler,
                    "error": chosen.get("error"),
                }
    except Exception:
        pass
    # Fallback : traiter comme C/texte brut
    if full:
        return {
            "functions": _parse_c_like_function_blocks(stripped),
            "code": stripped,
            "error": None,
            "decompiler": decompiler,
        }
    return {"addr": addr, "code": stripped, "error": None, "decompiler": decompiler}


def _run_http_decompiler(
    decompiler: str,
    binary_path: str,
    config: dict[str, Any],
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
) -> dict[str, Any]:
    """Appelle un service HTTP/REST pour décompiler.

    Le service doit retourner du JSON compatible avec _parse_external_decompiler_output.
    Credentials via le champ 'auth' — jamais dans la config JSON.
    """
    endpoint = config.get("endpoint", "")
    method = str(config.get("method") or "POST").upper()
    headers = dict(config.get("headers") or {})

    # Authentification — credentials depuis variables d'environnement uniquement
    auth_cfg = config.get("auth") or {}
    if auth_cfg:
        auth_type = str(auth_cfg.get("type") or "").lower()
        if auth_type == "bearer":
            token_env = str(auth_cfg.get("token_env") or "")
            token_val = os.environ.get(token_env, "")
            if not token_val:
                return {
                    "addr": addr,
                    "code": "",
                    "functions": [],
                    "error": f"Variable d'environnement '{token_env}' non définie (auth bearer)",
                    "decompiler": decompiler,
                    "provider": "http",
                }
            headers["Authorization"] = f"Bearer {token_val}"
        elif auth_type == "api_key":
            token_env = str(auth_cfg.get("token_env") or "")
            token_val = os.environ.get(token_env, "")
            if not token_val:
                return {
                    "addr": addr,
                    "code": "",
                    "functions": [],
                    "error": f"Variable d'environnement '{token_env}' non définie (auth api_key)",
                    "decompiler": decompiler,
                    "provider": "http",
                }
            header_name = str(auth_cfg.get("header") or "X-API-Key")
            headers[header_name] = token_val
        elif auth_type == "basic":
            user_env = str(auth_cfg.get("user_env") or "")
            password_env = str(auth_cfg.get("password_env") or "")
            user_val = os.environ.get(user_env, "")
            password_val = os.environ.get(password_env, "")
            if not user_val or not password_val:
                missing = user_env if not user_val else password_env
                return {
                    "addr": addr,
                    "code": "",
                    "functions": [],
                    "error": f"Variable d'environnement '{missing}' non définie (auth basic)",
                    "decompiler": decompiler,
                    "provider": "http",
                }
            credentials = base64.b64encode(
                f"{user_val}:{password_val}".encode()
            ).decode()
            headers["Authorization"] = f"Basic {credentials}"

    body_template = str(config.get("body_template") or "")
    timeout = int(config.get("timeout") or 60)
    output_format = str(config.get("output_format") or "json")

    # Encoder le binaire en base64 (lazy : seulement si {binary_b64} présent dans template)
    binary_b64 = ""
    if "{binary_b64}" in body_template:
        try:
            with open(binary_path, "rb") as fh:
                binary_b64 = base64.b64encode(fh.read()).decode("ascii")
        except OSError as exc:
            return {
                "addr": addr,
                "code": "",
                "functions": [],
                "error": str(exc),
                "decompiler": decompiler,
                "provider": "http",
            }

    body_str = (
        body_template.replace("{binary}", binary_path)
        .replace("{binary_b64}", binary_b64)
        .replace("{addr}", addr)
        .replace("{func_name}", func_name)
        .replace("{mode}", "full" if full else "function")
    )

    try:
        data = body_str.encode("utf-8") if body_str else None
        req = urllib.request.Request(
            endpoint, data=data, headers=headers, method=method
        )
        if "Content-Type" not in headers and data:
            req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        result = _parse_external_decompiler_output(
            raw,
            decompiler=decompiler,
            addr=addr,
            full=full,
            output_format=output_format,
        )
        result["provider"] = "http"
        result["endpoint"] = endpoint
        return result
    except urllib.error.HTTPError as exc:
        body_err = ""
        with contextlib.suppress(Exception):
            body_err = exc.read().decode("utf-8", errors="replace")[:500]
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"HTTP {exc.code}: {body_err or exc.reason}",
            "decompiler": decompiler,
            "provider": "http",
        }
    except urllib.error.URLError as exc:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": str(exc.reason),
            "decompiler": decompiler,
            "provider": "http",
        }
    except Exception as exc:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": str(exc),
            "decompiler": decompiler,
            "provider": "http",
        }


def _run_custom_decompiler(
    decompiler: str,
    binary_path: str,
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
) -> dict[str, Any]:
    config = _load_custom_decompilers().get(_normalize_decompiler_id(decompiler))
    if not config:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Décompilateur custom inconnu : {decompiler}",
            "decompiler": decompiler,
        }
    # Si endpoint HTTP configuré → déléguer à _run_http_decompiler
    if config.get("endpoint"):
        return _run_http_decompiler(
            decompiler, binary_path, config, addr=addr, func_name=func_name, full=full
        )
    command = (
        config.get("full_command")
        if full and config.get("full_command")
        else config.get("command")
    )
    if (
        full
        and not config.get("supports_full", True)
        and not config.get("full_command")
    ):
        return {
            "functions": [],
            "error": f"{decompiler} ne déclare pas supports_full",
            "decompiler": decompiler,
        }
    if not isinstance(command, list) or not command:
        # Mode docker-only : pas de commande locale disponible
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"{decompiler} n'a pas de commande locale (utiliser provider=docker)",
            "decompiler": decompiler,
        }
    timeout = int(config.get("timeout") or (300 if full else 120))
    # Variables d'environnement : fusionner env courant + vars custom
    proc_env = {**os.environ}
    custom_env = config.get("env") or {}
    if isinstance(custom_env, dict):
        proc_env.update({str(k): str(v) for k, v in custom_env.items()})
    output_format = config.get("output_format", "json")
    try:
        with tempfile.TemporaryDirectory(prefix="pof_custom_decompiler_") as tmp:
            out_ext = (
                ".json"
                if output_format == "json"
                else ".c"
                if output_format == "c"
                else ".txt"
            )
            out_file = Path(tmp) / f"out{out_ext}"
            argv = _format_custom_command(
                command,
                binary_path=binary_path,
                addr=addr,
                func_name=func_name,
                mode="full" if full else "function",
                out_file=out_file,
            )

            def _run_argv(argv_: list[str], out_file_: Path) -> dict[str, Any]:
                proc_ = subprocess.run(
                    argv_,
                    capture_output=True,
                    timeout=timeout,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    env=proc_env,
                )
                # Certains outils écrivent sur stderr plutôt que stdout (comportement non-TTY)
                stdout_text_ = proc_.stdout or ""
                if not stdout_text_.strip() and proc_.stderr:
                    stdout_text_ = proc_.stderr or ""
                result_ = _parse_external_decompiler_output(
                    stdout_text_,
                    decompiler=decompiler,
                    addr=addr,
                    out_file=out_file_,
                    full=full,
                    output_format=output_format,
                )
                if (
                    proc_.returncode != 0
                    and not result_.get("code")
                    and not result_.get("functions")
                ):
                    stderr_tail_ = (proc_.stderr or "").strip()[-800:]
                    result_["error"] = (
                        stderr_tail_
                        or f"{decompiler} exited with code {proc_.returncode}"
                    )
                    result_["error_type"] = "tool_error"
                return result_

            parsed = _run_argv(argv, out_file)

            # Si la commande principale ne produit rien, tenter fallback_command
            if (
                parsed.get("error")
                and not parsed.get("code")
                and not parsed.get("functions")
            ):
                fallback_command = config.get("fallback_command")
                if not full and fallback_command and isinstance(fallback_command, list):
                    fb_argv = _format_custom_command(
                        fallback_command,
                        binary_path=binary_path,
                        addr=addr,
                        func_name=func_name,
                        mode="function",
                        out_file=out_file,
                    )
                    fb_parsed = _run_argv(fb_argv, out_file)
                    if fb_parsed.get("code") or fb_parsed.get("functions"):
                        fb_parsed["fallback"] = True
                        parsed = fb_parsed

            parsed.setdefault("provider", "local")
            return parsed
    except subprocess.TimeoutExpired:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Timeout {decompiler} ({timeout}s)",
            "decompiler": decompiler,
            "error_type": "timeout",
        }
    except Exception as exc:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": str(exc),
            "decompiler": decompiler,
            "error_type": "tool_error",
        }


def _run_custom_decompiler_in_docker(
    decompiler: str,
    binary_path: str,
    *,
    addr: str = "",
    func_name: str = "",
    full: bool = False,
) -> dict[str, Any]:
    normalized_id = _normalize_decompiler_id(decompiler)
    config = _load_custom_decompilers().get(normalized_id)
    image_name = _get_decompiler_docker_image(decompiler)
    if not image_name:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Aucune image Docker configurée pour {decompiler}",
            "decompiler": decompiler,
            "provider": "docker",
        }
    # Si pas de config explicite, construire un config minimal pour les builtins
    # (l'image est conventionnelle : pile-ou-face/decompiler-{name}:latest)
    if not config:
        config = {
            "id": normalized_id,
            "label": normalized_id,
            "docker_command": ["{binary}", "--addr", "{addr}", "--output", "{output}"],
            "output_format": "json",
            "supports_full": True,
            "timeout": 120,
        }
    # Priorité : docker_full_command > docker_command > full_command > command
    command = (
        config.get("docker_full_command")
        if full and config.get("docker_full_command")
        else config.get("docker_command")
    )
    if not command:
        command = (
            config.get("full_command")
            if full and config.get("full_command")
            else config.get("command")
        )
    if (
        full
        and not config.get("supports_full", True)
        and not config.get("docker_full_command")
        and not config.get("full_command")
    ):
        return {
            "functions": [],
            "error": f"{decompiler} ne déclare pas supports_full",
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
        }
    if not isinstance(command, list) or not command:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Commande Docker custom invalide pour {decompiler}",
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
        }
    timeout = int(config.get("timeout") or (300 if full else 120))
    network = config.get("network", "none")
    output_format = config.get("output_format", "json")
    custom_env = config.get("env") or {}
    extra_docker_args = config.get("docker_extra_args") or []
    try:
        with tempfile.TemporaryDirectory(prefix="pof_custom_docker_") as tmp:
            binary_mount_dir, container_binary = _docker_mount_for_binary(binary_path)
            output_mount_dir, container_out = _docker_mount_for_output(tmp)
            out_ext = (
                ".json"
                if output_format == "json"
                else ".c"
                if output_format == "c"
                else ".txt"
            )
            # Adapter le chemin de sortie container selon l'extension
            container_out_path = f"/output/out{out_ext}"
            argv = _format_custom_command(
                [str(part) for part in command],
                binary_path=container_binary,
                addr=addr,
                func_name=func_name,
                mode="full" if full else "function",
                out_file=Path(container_out_path),
            )
            # Construire la commande docker run
            docker_exe = _find_docker_executable() or "docker"
            docker_cmd: list[str] = [
                docker_exe,
                "run",
                "--rm",
                "--network",
                network,
                "--hostname",
                "localhost",
            ]
            # --platform : utilise DOCKER_PLATFORM si défini (utile sur ARM / multi-arch)
            pof_platform = _preferred_docker_platform_for_decompiler(decompiler)
            if pof_platform:
                docker_cmd += ["--platform", pof_platform]
            # Variables d'environnement
            for k, v in custom_env.items() if isinstance(custom_env, dict) else []:
                docker_cmd += ["-e", f"{k}={v}"]
            # Volumes
            docker_cmd += ["-v", f"{binary_mount_dir}:/input:ro"]
            docker_cmd += ["-v", f"{output_mount_dir}:/output"]
            # Arguments supplémentaires
            docker_cmd += [str(a) for a in extra_docker_args]
            # Image + commande
            docker_cmd += [image_name, *argv]
            proc = subprocess.run(
                docker_cmd,
                capture_output=True,
                timeout=timeout,
                text=True,
            )
            parsed = _parse_external_decompiler_output(
                proc.stdout,
                decompiler=decompiler,
                addr=addr,
                out_file=output_mount_dir / f"out{out_ext}",
                full=full,
                output_format=output_format,
            )
            parsed["provider"] = "docker"
            parsed["docker_image"] = image_name
            if proc.returncode != 0:
                stderr_tail = (proc.stderr or "").strip()[-800:]
                if _docker_run_failed_because_image_missing(stderr_tail):
                    _DOCKER_AVAILABLE_CACHE[image_name] = False
                    # Tenter un pull automatique puis relancer
                    if _docker_pull_image(image_name):
                        proc2 = subprocess.run(
                            docker_cmd,
                            capture_output=True,
                            timeout=timeout,
                            text=True,
                        )
                        parsed = _parse_external_decompiler_output(
                            proc2.stdout,
                            decompiler=decompiler,
                            addr=addr,
                            out_file=output_mount_dir / f"out{out_ext}",
                            full=full,
                            output_format=output_format,
                        )
                        parsed["provider"] = "docker"
                        parsed["docker_image"] = image_name
                        if proc2.returncode != 0:
                            parsed["error"] = (proc2.stderr or "").strip()[-800:] or f"{decompiler} Docker exited with code {proc2.returncode}"
                            parsed["error_type"] = "tool_error"
                        return parsed
                    parsed["error"] = _docker_missing_image_error(
                        decompiler, image_name
                    )
                    parsed["error_type"] = "image_not_found"
                else:
                    parsed["error"] = (
                        stderr_tail
                        or f"{decompiler} Docker exited with code {proc.returncode}"
                    )
                    parsed["error_type"] = "tool_error"
            return parsed
    except subprocess.TimeoutExpired:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": f"Timeout Docker {decompiler} ({timeout}s)",
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
            "error_type": "timeout",
        }
    except Exception as exc:
        return {
            "addr": addr,
            "code": "",
            "functions": [],
            "error": str(exc),
            "decompiler": decompiler,
            "provider": "docker",
            "docker_image": image_name,
            "error_type": "tool_error",
        }


def _cache_key(
    binary_path: str,
    addr: str,
    func_name: str = "",
    decompiler: str = "",
    annotations_json: str | None = None,
    stack_signature: str = "",
    typed_structs_signature: str = "",
) -> str:
    """Clé de cache 16 hex chars."""
    binary_signature = _file_signature(binary_path) or binary_path
    ann_signature = _file_signature(annotations_json) or (annotations_json or "")
    raw = "|".join(
        [
            _DECOMPILE_CACHE_VERSION,
            binary_signature,
            addr.lower(),
            _normalize_symbol_lookup_name(func_name),
            decompiler,
            ann_signature,
            stack_signature,
            typed_structs_signature,
        ]
    )
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


def _read_cache(key: str, cache_dir: Path) -> dict | None:
    p = cache_dir / f"{key}.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return None
    return None


def _build_cache_meta(binary_path: str) -> dict[str, Any] | None:
    try:
        stat = Path(binary_path).stat()
    except Exception:
        return None
    return {
        "binary_path": str(Path(binary_path).resolve()),
        "binary_mtime_ms": stat.st_mtime_ns / 1_000_000
        if getattr(stat, "st_mtime_ns", None)
        else stat.st_mtime * 1000.0,
        "binary_size": stat.st_size,
    }


def _write_cache(
    key: str, cache_dir: Path, data: dict, *, meta: dict[str, Any] | None = None
) -> None:
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
        payload = dict(data)
        if meta:
            payload["_cache_meta"] = dict(meta)
        (cache_dir / f"{key}.json").write_text(
            json.dumps(payload, ensure_ascii=False), encoding="utf-8"
        )
    except Exception:
        pass  # cache write failure is non-fatal


_DEFAULT_CACHE_DIR = (
    Path(_pof_storage_env) / "decompile_cache"
    if _pof_storage_env
    else Path.home() / ".config" / "pile-ou-face" / "decompile_cache"
)


# ---------------------------------------------------------------------------
# Détection locale des décompilateurs via le champ "detect" du JSON
# L'user installe ce qu'il veut ; POF détecte via shutil.which(detect).
# ---------------------------------------------------------------------------


def _is_decompiler_available_local(decompiler: str) -> bool:
    """Vérifie si un décompilateur est disponible localement.

    1. Si "detect_cmd" est défini : lance la commande, disponible si returncode == 0.
    2. Sinon si "detect" est défini : vérifie la présence dans PATH (shutil.which).
    3. Sinon : disponible dès qu'une "command" est déclarée.
    """
    entry = _load_decompilers().get(_normalize_decompiler_id(decompiler))
    if not entry:
        return False
    if not entry.get("command"):
        return False  # pas de commande locale
    detect_cmd = entry.get("detect_cmd")
    if detect_cmd and isinstance(detect_cmd, list):
        try:
            r = subprocess.run(detect_cmd, capture_output=True, timeout=10)
            return r.returncode == 0
        except Exception:
            return False
    detect = entry.get("detect", "").strip()
    if not detect:
        return True  # pas de contrainte de détection → considéré présent
    return shutil.which(detect) is not None


def _find_docker_executable() -> str | None:
    env_candidate = os.environ.get("DOCKER_BIN", "").strip()
    candidates = [
        env_candidate,
        shutil.which("docker"),
        "/usr/local/bin/docker",
        "/opt/homebrew/bin/docker",
        str(Path.home() / ".orbstack" / "bin" / "docker"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        try:
            if Path(candidate).exists():
                return candidate
        except Exception:
            continue
    return None


def _is_docker_decompiler_image_available(image: str) -> bool:
    """Return true when Docker can see a specific decompiler image locally."""
    image_name = str(image or "").strip()
    if not image_name:
        return False
    cached = _DOCKER_AVAILABLE_CACHE.get(image_name)
    # Cache only positive hits durably. A previously-missing local image may
    # appear later after `docker build`, while the backend process keeps
    # running, so negative cache entries must be revalidated.
    if cached is True:
        return cached
    docker_exe = _find_docker_executable()
    if not docker_exe:
        _DOCKER_AVAILABLE_CACHE[image_name] = False
        return False
    try:
        result = subprocess.run(
            [docker_exe, "image", "inspect", image_name],
            capture_output=True,
            timeout=4,
            text=True,
        )
        ok = result.returncode == 0
    except Exception:
        ok = False
    if ok:
        _DOCKER_AVAILABLE_CACHE[image_name] = True
    else:
        _DOCKER_AVAILABLE_CACHE.pop(image_name, None)
    return ok


def _is_docker_image_available_for_decompiler(decompiler: str) -> bool:
    return _is_docker_decompiler_image_available(
        _get_decompiler_docker_image(decompiler)
    )


def _is_local_dev_docker_image(image_name: str) -> bool:
    """Retourne True si l'image est une image de dev local (sans registre distant).

    Les images OCI publiées ont un hostname avec un '.' dans le premier segment
    (ex: ghcr.io/..., docker.io/...). Les images locales n'en ont pas.
    """
    first_segment = str(image_name or "").strip().split("/")[0]
    return "." not in first_segment and ":" not in first_segment


def _docker_missing_image_error(decompiler: str, image_name: str) -> str:
    normalized = _normalize_decompiler_id(decompiler)
    lines = [f"Image Docker introuvable pour {decompiler} : {image_name}"]
    if _is_local_dev_docker_image(image_name):
        lines.append(
            f"Construis-la d'abord : make decompiler-docker-build DECOMPILER={normalized}"
        )
        lines.append(
            f"Ou surcharge l'image avec {_docker_env_var_name_for_decompiler(normalized)}=registry/image:tag"
        )
    else:
        lines.append(f"Pull automatique échoué pour {image_name}.")
        lines.append(f"Vérifie ta connexion ou tente manuellement : docker pull {image_name}")
        lines.append(
            f"Surcharge possible avec {_docker_env_var_name_for_decompiler(normalized)}=registry/image:tag"
        )
    return "\n".join(lines)


def _docker_run_failed_because_image_missing(stderr: str) -> bool:
    normalized = str(stderr or "").lower()
    markers = (
        "unable to find image",
        "pull access denied",
        "repository does not exist",
        "requested access to the resource is denied",
        "manifest unknown",
        "not found",
    )
    return any(marker in normalized for marker in markers)


def _docker_mount_for_binary(binary_path: str) -> tuple[Path, str]:
    binary = Path(binary_path).resolve()
    mount_dir = binary.parent
    return mount_dir, f"/input/{binary.name}"


def _docker_mount_for_output(temp_dir: str) -> tuple[Path, str]:
    mount_dir = Path(temp_dir).resolve()
    return mount_dir, "/output/out.json"


def _preferred_docker_platform_for_decompiler(decompiler: str) -> str:
    forced = os.environ.get("DOCKER_PLATFORM", "").strip()
    if forced:
        return forced
    return ""


def _load_annotations_payload(
    annotations_json: str | None,
) -> tuple[dict[str, str], dict[str, str]]:
    """Charge ({addr_norm: name}, {addr_norm: comment}) depuis un fichier d'annotations."""
    if not annotations_json:
        return {}, {}
    try:
        data = json.loads(Path(annotations_json).read_text(encoding="utf-8"))
        names: dict[str, str] = {}
        comments: dict[str, str] = {}
        for addr_str, entry in data.items():
            if not isinstance(entry, dict):
                continue
            norm = addr_str.lower().lstrip("0x").lstrip("0") or "0"
            name = (entry.get("name") or "").strip()
            comment = (entry.get("comment") or "").strip()
            if name:
                names[norm] = name
            if comment:
                comments[norm] = comment
        return names, comments
    except Exception:
        return {}, {}


def _load_typed_struct_annotation_payload(
    binary_path: str,
) -> tuple[dict[str, str], dict[str, str], list[dict[str, Any]]]:
    try:
        index = build_typed_struct_index(binary_path)
    except Exception:
        return {}, {}, []
    names: dict[str, str] = {}
    comments: dict[str, str] = {}
    notes: list[dict[str, Any]] = []
    seen_notes: set[str] = set()
    for addr, entry in (index.get("exact_by_addr") or {}).items():
        norm = addr.lower().lstrip("0x").lstrip("0") or "0"
        label = str(entry.get("label") or "").strip()
        comment = str(entry.get("comment") or "").strip()
        if label:
            names[norm] = label
        if comment:
            comments[norm] = comment
        if entry.get("kind") != "field":
            continue
        key = f"{entry.get('struct_name')}:{entry.get('field_name')}:{addr}"
        if key in seen_notes:
            continue
        seen_notes.add(key)
        notes.append(
            {
                "addr": addr,
                "name": label or addr,
                "comment": comment,
                "struct_name": str(entry.get("struct_name") or "").strip(),
                "field_name": str(entry.get("field_name") or "").strip(),
                "field_type": str(entry.get("field_type") or "").strip(),
            }
        )
    return names, comments, notes


def _annotation_patterns(addr_norm: str) -> list[str]:
    hex_no0x = addr_norm.lower().lstrip("0") or "0"
    hex_with0x = f"0x{hex_no0x}"
    padded8 = hex_no0x.zfill(8)
    padded16 = hex_no0x.zfill(16)
    return [
        hex_with0x,
        f"fcn_{padded8}",
        f"fcn_{padded16}",
        f"sub_{padded8}",
        f"sub_{padded16}",
        f"FUN_{padded8}",
        f"FUN_{padded16}",
        f"fun_{padded8}",
        f"fun_{padded16}",
        f"DAT_{padded8}",
        f"DAT_{padded16}",
        f"LAB_{padded8}",
        f"LAB_{padded16}",
        f"PTR_{padded8}",
        f"PTR_{padded16}",
        f"code_{padded8}",
        f"code_{padded16}",
    ]


def _extract_call_names(code: str) -> set[str]:
    names: set[str] = set()
    for match in _CALL_NAME_RE.finditer(code or ""):
        name = (match.group(1) or "").strip()
        if not name or name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        names.add(name)
    return names


def _extract_reachable_call_names(
    binary_path: str,
    addr: str,
    *,
    instruction_map: dict[str, dict[str, Any]] | None = None,
    symbol_map: dict[str, str] | None = None,
    max_nodes: int = 256,
) -> set[str]:
    start_addr = _normalize_hex_addr(addr)
    if not start_addr:
        return set()
    if instruction_map is None or symbol_map is None:
        loaded_instruction_map, loaded_symbol_map = _load_disasm_context(binary_path)
        if instruction_map is None:
            instruction_map = loaded_instruction_map
        if symbol_map is None:
            symbol_map = loaded_symbol_map
    if not instruction_map:
        return set()

    def _parse_target(operands: str) -> str:
        ops = str(operands or "").strip()
        if not ops:
            return ""
        match = re.search(r"0x[0-9a-f]+", ops, flags=re.IGNORECASE)
        return _normalize_hex_addr(match.group(0)) if match else ""

    def _is_return(ins: dict[str, Any]) -> bool:
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        operands = str(ins.get("operands") or "").strip().lower()
        if mnemonic in {"ret", "retq", "retn"}:
            return True
        if mnemonic == "bx" and operands == "lr":
            return True
        return bool(mnemonic == "pop" and "pc" in operands)

    def _successors(ins: dict[str, Any]) -> list[str]:
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        operands = str(ins.get("operands") or "").strip()
        next_addr = _normalize_hex_addr(ins.get("next_addr"))
        target = _parse_target(operands)
        if _is_return(ins):
            return []
        if mnemonic in {"call", "callq", "bl", "blx"}:
            return [next_addr] if next_addr else []
        if mnemonic == "jmp" or mnemonic == "b":
            return [target] if target else []
        if mnemonic.startswith("j") and mnemonic != "jmp":
            return [item for item in (target, next_addr) if item]
        if mnemonic.startswith("b.") or mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}:
            return [item for item in (target, next_addr) if item]
        if re.fullmatch(r"b[a-z]{1,2}", mnemonic) and mnemonic not in {
            "bl",
            "blx",
            "bx",
        }:
            return [item for item in (target, next_addr) if item]
        return [next_addr] if next_addr else []

    queue = [start_addr]
    visited: set[str] = set()
    calls: set[str] = set()
    while queue and len(visited) < max_nodes:
        current = queue.pop(0)
        if current in visited:
            continue
        visited.add(current)
        ins = instruction_map.get(current)
        if not ins:
            continue
        mnemonic = str(ins.get("mnemonic") or "").strip().lower()
        if mnemonic in {"call", "callq", "bl", "blx"}:
            target = _parse_target(ins.get("operands"))
            if target:
                calls.add(_pretty_symbol_name(symbol_map.get(target, target)).lower())
        for succ in _successors(ins):
            if succ and succ not in visited:
                queue.append(succ)
    return {
        name
        for name in calls
        if name and not re.fullmatch(r"0x[0-9a-f]+", name, flags=re.IGNORECASE)
    }


def _score_decompile_code(
    code: str,
    expected_calls=None,
) -> dict[str, Any]:
    text = code or ""
    stripped_lines = [line.strip() for line in text.splitlines() if line.strip()]
    line_count = len(stripped_lines)
    call_names = {
        _pretty_symbol_name(name).lower() for name in _extract_call_names(text)
    }
    call_count = len(call_names)
    placeholder_count = len(_PLACEHOLDER_SYMBOL_RE.findall(text))
    control_count = sum(
        len(re.findall(rf"\b{kw}\b", text))
        for kw in ("if", "switch", "while", "for", "case", "return")
    )
    goto_count = len(re.findall(r"\bgoto\b", text))
    cast_count = len(re.findall(r"\([A-Za-z_][A-Za-z0-9_\s\*]*\)", text))
    type_hint_count = len(_TYPE_HINT_RE.findall(text))
    low_level_count = len(_LOW_LEVEL_PSEUDOC_RE.findall(text))
    warning_count = len(re.findall(r"//\s*WARNING:", text, flags=re.IGNORECASE))
    score = 0
    score += min(line_count, 40)
    score += min(call_count * 4, 24)
    score += min(control_count * 5, 30)
    score += min(type_hint_count * 2, 16)
    score += min(cast_count * 2, 8)
    score -= placeholder_count * 3
    score -= goto_count * 4
    score -= low_level_count * 3
    score -= warning_count * 10
    matched_call_count = 0
    missing_call_count = 0
    if expected_calls:
        normalized_expected = {
            _pretty_symbol_name(name).lower()
            for name in expected_calls
            if str(name or "").strip()
        }
        matched_call_count = len(call_names & normalized_expected)
        missing_call_count = len(normalized_expected - call_names)
        score += matched_call_count * 15
        score -= missing_call_count * 10
    return {
        "score": score,
        "metrics": {
            "lines": line_count,
            "calls": call_count,
            "control": control_count,
            "type_hints": type_hint_count,
            "casts": cast_count,
            "placeholders": placeholder_count,
            "gotos": goto_count,
            "low_level": low_level_count,
            "warnings": warning_count,
            "matched_calls": matched_call_count,
            "missed_calls": missing_call_count,
        },
    }


def _score_binary_decompile(
    result: dict[str, Any], decompiler: str = ""
) -> dict[str, Any]:
    functions = result.get("functions") or []
    fn_count = len(functions)
    total_code_len = sum(
        len(f.get("code") or "") for f in functions if isinstance(f, dict)
    )
    error_count = sum(1 for f in functions if isinstance(f, dict) and f.get("error"))
    score = fn_count * 14
    score += min(total_code_len // 150, 28)
    score -= error_count * 5
    return {
        "score": score,
        "metrics": {
            "functions": fn_count,
            "code_len": total_code_len,
            "errors": error_count,
        },
    }


def _select_best_function_candidate(
    attempts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    successes = [
        attempt
        for attempt in attempts
        if not attempt.get("error") and attempt.get("code")
    ]
    if not successes:
        return None
    scored = []
    for index, attempt in enumerate(successes):
        quality_score = attempt.get("_quality_score")
        if not isinstance(quality_score, int):
            quality = _score_decompile_code(attempt.get("code", ""))
            quality_score = quality["score"]
        did = _normalize_decompiler_id(str(attempt.get("decompiler") or ""))
        _bias_entry = _load_decompilers().get(did) or {}
        _bias_raw = (
            _bias_entry.get("quality_bias")
            if _bias_entry.get("quality_bias") is not None
            else _BUILTIN_TARGET_POLICIES.get(did, {}).get("quality_bias")
        )
        bias = int(_bias_raw) if _bias_raw is not None else 0
        scored.append((quality_score + bias, -index, attempt))
    scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return scored[0][2]


def _select_best_binary_candidate(
    attempts: list[dict[str, Any]],
) -> dict[str, Any] | None:
    successes = [
        attempt
        for attempt in attempts
        if not attempt.get("error") and attempt.get("functions")
    ]
    if not successes:
        return None
    scored = []
    for index, attempt in enumerate(successes):
        quality_score = attempt.get("_quality_score")
        if not isinstance(quality_score, int):
            quality = _score_binary_decompile(attempt, attempt.get("decompiler", ""))
            quality_score = quality["score"]
        scored.append((quality_score, -index, attempt))
    scored.sort(reverse=True, key=lambda item: (item[0], item[1]))
    return scored[0][2]


def _build_function_quality_details(
    attempts: list[dict[str, Any]],
    selected: dict[str, Any] | None,
    expected_calls=None,
) -> dict[str, Any]:
    backends: list[dict[str, Any]] = []
    selected_backend = (
        str(selected.get("decompiler") or "") if isinstance(selected, dict) else ""
    )
    selected_score = 0
    for attempt in attempts:
        decompiler = str(attempt.get("decompiler") or "")
        error = attempt.get("error")
        if error:
            backends.append(
                {
                    "decompiler": decompiler,
                    "ok": False,
                    "error": error,
                    "selected": False,
                }
            )
            continue
        scored = _score_decompile_code(attempt.get("code", ""), expected_calls)
        score = scored["score"]
        attempt["_quality_score"] = score
        if decompiler == selected_backend:
            selected_score = score
        backends.append(
            {
                "decompiler": decompiler,
                "ok": True,
                "error": None,
                "selected": decompiler == selected_backend,
                "score": score,
                "metrics": scored["metrics"],
            }
        )
    return {
        "strategy": "auto_first",
        "selected_backend": selected_backend,
        "selected_score": selected_score,
        "backends": backends,
    }


def _build_binary_quality_details(
    attempts: list[dict[str, Any]],
    selected: dict[str, Any] | None,
) -> dict[str, Any]:
    backends: list[dict[str, Any]] = []
    selected_backend = (
        str(selected.get("decompiler") or "") if isinstance(selected, dict) else ""
    )
    selected_score = 0
    for attempt in attempts:
        decompiler = str(attempt.get("decompiler") or "")
        error = attempt.get("error")
        if error:
            backends.append(
                {
                    "decompiler": decompiler,
                    "ok": False,
                    "error": error,
                    "selected": False,
                }
            )
            continue
        scored = _score_binary_decompile(attempt, decompiler)
        score = scored["score"]
        attempt["_quality_score"] = score
        if decompiler == selected_backend:
            selected_score = score
        backends.append(
            {
                "decompiler": decompiler,
                "ok": True,
                "error": None,
                "selected": decompiler == selected_backend,
                "score": score,
                "metrics": scored["metrics"],
            }
        )
    return {
        "strategy": "auto_first",
        "selected_backend": selected_backend,
        "selected_score": selected_score,
        "backends": backends,
    }


def _parse_numeric_token(value: str | int | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    if not text:
        return None
    try:
        return (
            int(text, 16)
            if text.startswith("0x") or text.startswith("-0x")
            else int(text, 10)
        )
    except ValueError:
        return None


def _normalize_hex_addr(value: str | int | None) -> str:
    parsed = _parse_numeric_token(value)
    return f"0x{parsed:x}" if parsed is not None else ""


def _pretty_symbol_name(name: str) -> str:
    """Normalise un nom de symbole brut vers un identifiant C lisible.

    Deux transformations génériques indépendantes du décompilateur :
    - Strip du préfixe "sym.imp." : convention ELF standard pour les stubs
      d'importation (PLT), produit par objdump, nm, readelf, lief et tout outil
      qui expose les symboles ELF — pas spécifique à un décompilateur.
    - Strip du underscore leading : convention d'ABI C sur macOS/Windows
      (_printf → printf) — standard indépendant de l'outil.
    """
    symbol = str(name or "").strip()
    if symbol.startswith("sym.imp."):
        symbol = symbol.split("sym.imp.", 1)[1]
    if symbol.startswith("_") and re.fullmatch(r"_[A-Za-z][A-Za-z0-9_]*", symbol):
        return symbol[1:]
    return symbol


def _load_disasm_context(
    binary_path: str,
) -> tuple[dict[str, dict[str, Any]], dict[str, str]]:
    instruction_map: dict[str, dict[str, Any]] = {}
    symbol_map: dict[str, str] = {}
    try:
        from backends.static.disasm.disasm import disassemble_with_capstone

        lines = disassemble_with_capstone(binary_path) or []
        normalized_lines: list[dict[str, Any]] = []
        for line in lines:
            normalized = _normalize_hex_addr(line.get("addr"))
            if not normalized:
                continue
            copied = dict(line)
            copied["addr"] = normalized
            normalized_lines.append(copied)
        for index, line in enumerate(normalized_lines):
            next_addr = (
                normalized_lines[index + 1]["addr"]
                if index + 1 < len(normalized_lines)
                else ""
            )
            line["next_addr"] = next_addr
            instruction_map[line["addr"]] = line
    except Exception:
        instruction_map = {}
    try:
        from backends.static.binary.symbols import extract_symbols

        for sym in extract_symbols(binary_path):
            addr = _normalize_hex_addr(sym.get("addr"))
            name = str(sym.get("name") or "").strip()
            if addr and name:
                symbol_map.setdefault(addr, name)
    except Exception:
        symbol_map = {}
    return instruction_map, symbol_map


_X86_REGISTER_ALIASES: dict[str, tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "rbp": ("rbp", "ebp", "bp", "bpl"),
    "rsp": ("rsp", "esp", "sp", "spl"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
}


def _canonicalize_stack_base(base: str) -> str:
    normalized = str(base or "").strip().lower()
    if normalized == "fp":
        return "r11"
    return normalized


def _canonicalize_stack_location(location: str) -> str:
    match = re.fullmatch(
        r"\[(?P<base>rbp|ebp|rsp|esp|sp|x29|r11|fp)(?:(?P<sign>[+\-])(?P<off>0x[0-9a-f]+|\d+))?\]",
        str(location or "").strip().lower(),
        flags=re.IGNORECASE,
    )
    if not match:
        return str(location or "").strip().lower()
    base = _canonicalize_stack_base(match.group("base"))
    sign = match.group("sign")
    off = _parse_numeric_token(match.group("off") or "0") or 0
    if sign == "-":
        off = -off
    if off == 0:
        return f"[{base}]"
    sign = "+" if off > 0 else "-"
    return f"[{base}{sign}0x{abs(off):x}]"


def _register_aliases(location: str) -> tuple[str, ...]:
    normalized = str(location or "").strip().lower()
    if not normalized:
        return ()
    if normalized in _X86_REGISTER_ALIASES:
        return _X86_REGISTER_ALIASES[normalized]
    if re.fullmatch(r"x\d+", normalized):
        suffix = normalized[1:]
        return (normalized, f"w{suffix}")
    if re.fullmatch(r"w\d+", normalized):
        suffix = normalized[1:]
        return (f"x{suffix}", normalized)
    if re.fullmatch(r"r\d+", normalized):
        return (normalized,)
    return (normalized,)


def _canonicalize_stack_entries(entries: list[dict] | None) -> list[dict]:
    normalized: list[dict] = []
    for entry in entries or []:
        if not isinstance(entry, dict):
            continue
        normalized.append(
            {
                "name": str(entry.get("name") or ""),
                "offset": entry.get("offset"),
                "size": entry.get("size"),
                "source": str(entry.get("source") or ""),
                "location": str(entry.get("location") or ""),
            }
        )
    return sorted(
        normalized,
        key=lambda item: (
            item["name"],
            item["location"],
            item["offset"] if isinstance(item["offset"], int) else 0,
            item["size"] if isinstance(item["size"], int) else 0,
            item["source"],
        ),
    )


def _stack_token_aliases(stack_vars: list[dict] | None) -> dict[str, str]:
    """Construit des alias pour substituer les noms de variables générés par le décompilateur.

    Conventions courantes selon les outils (non exhaustif) :
    - Ghidra : local_10, auStack_18, puStack_20
    - IDA Pro : var_8, arg_0
    - rizin/r2 : var_8h, arg_10h
    - générique : param_1, param_2, local_1
    """
    aliases: dict[str, str] = {}
    ordered_args: list[str] = []

    def _remember(alias: str, name: str) -> None:
        alias = str(alias or "").strip()
        name = str(name or "").strip()
        if not alias or not name or alias == name:
            return
        aliases.setdefault(alias, name)

    for entry in stack_vars or []:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        if not name:
            continue
        offset = entry.get("offset")
        size = _parse_numeric_token(entry.get("size"))
        source = str(entry.get("source") or "").strip().lower()
        is_arg = source == "abi"
        if not is_arg and isinstance(offset, int):
            is_arg = offset >= 0
        if is_arg:
            ordered_args.append(name)

        if not isinstance(offset, int):
            continue

        abs_hex = f"{abs(offset):x}"
        abs_dec = str(abs(offset))
        if offset < 0:
            for prefix in ("local_", "uStack_", "iStack_", "puStack_", "auStack_"):
                _remember(f"{prefix}{abs_hex}", name)
                _remember(f"{prefix}{abs_dec}", name)
            _remember(f"var_{abs_hex}h", name)
            _remember(f"var_{abs_hex}", name)
            _remember(f"stack0x{((1 << 32) + offset):x}", name)
            _remember(f"stack0x{((1 << 64) + offset):x}", name)
            if size:
                _remember(f"local_res{size}", name)
        elif offset > 0:
            _remember(f"arg_{abs_hex}h", name)
            _remember(f"arg_{abs_hex}", name)
            _remember(f"arg_{abs_dec}", name)
            _remember(f"stack0x{offset:x}", name)

    for index, name in enumerate(ordered_args, start=1):
        _remember(f"param_{index}", name)

    return aliases


def _stack_frame_payload(
    stack_frame: dict[str, Any] | None, stack_vars: list[dict] | None
) -> dict[str, Any] | None:
    if stack_frame:
        return {
            "arch": stack_frame.get("arch") or "unknown",
            "abi": stack_frame.get("abi") or "unknown",
            "frame_size": int(stack_frame.get("frame_size") or 0),
            "vars": _canonicalize_stack_entries(stack_frame.get("vars")),
            "args": _canonicalize_stack_entries(stack_frame.get("args")),
        }
    if not stack_vars:
        return None

    args: list[dict] = []
    vars_: list[dict] = []
    for entry in _canonicalize_stack_entries(stack_vars):
        is_arg = entry.get("source") == "abi"
        if not is_arg and isinstance(entry.get("offset"), int):
            is_arg = entry["offset"] >= 0
        (args if is_arg else vars_).append(entry)
    return {
        "arch": "unknown",
        "abi": "unknown",
        "frame_size": 0,
        "vars": vars_,
        "args": args,
    }


def _stack_signature(
    stack_frame: dict[str, Any] | None, stack_vars: list[dict] | None
) -> str:
    payload = _stack_frame_payload(stack_frame, stack_vars)
    if not payload:
        return ""
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def _postprocess_code(
    code: str,
    annotations_map: dict[str, str],
    stack_vars: list[dict] | None = None,
    *,
    binary_path: str = "",
    addr: str = "",
    decompiler: str = "",
) -> str:
    """Post-traitement du pseudo-C : injecte les noms d'annotations et variables de stack.

    Args:
        code: Pseudo-C brut du décompilateur
        annotations_map: {addr_hex_norm: name} (adresses sans préfixe 0x, lowercase)
        stack_vars: Optionnel, liste de {name, offset} depuis stack_frame.py

    Returns:
        Pseudo-C enrichi avec les noms symboliques.
    """
    if not code:
        return code

    # 1. Inject annotation names: replace 0xADDR, fcn_ADDR, sub_ADDR, FUN_ADDR
    for addr_norm, name in annotations_map.items():
        for pattern in _annotation_patterns(addr_norm):
            code = re.sub(re.escape(pattern), name, code, flags=re.IGNORECASE)

    # 2. Stack variable substitution: *(uintN_t *)(rbp - 0xN) → var_name
    if stack_vars:
        offset_to_name: dict[int, str] = {}
        raw_expr_to_name: dict[tuple[str, str, int], str] = {}
        register_name_map: dict[str, str] = {}
        stack_token_aliases = _stack_token_aliases(stack_vars)
        for v in stack_vars:
            off = v.get("offset")
            vname = v.get("name", "")
            if off is not None and vname:
                offset_to_name[int(off)] = vname
            location = _canonicalize_stack_location(v.get("location") or "")
            match = re.fullmatch(
                r"\[(?P<base>rbp|ebp|rsp|esp|sp|x29|r11)(?:(?P<sign>[+\-])(?P<off>0x[0-9a-f]+|\d+))?\]",
                location,
                flags=re.IGNORECASE,
            )
            if match and vname:
                off_value = _parse_numeric_token(match.group("off") or "0") or 0
                raw_expr_to_name[
                    (match.group("base").lower(), match.group("sign") or "+", off_value)
                ] = vname
            if vname and location and not location.startswith("["):
                for alias in _register_aliases(location):
                    register_name_map[alias] = vname

        def _replace_stack_ref(m: re.Match) -> str:
            base = _canonicalize_stack_base(m.group("base"))
            sign = m.group("sign")
            off_int = _parse_numeric_token(m.group("off")) or 0
            direct = raw_expr_to_name.get((base, sign, off_int))
            if direct:
                return direct
            actual = -off_int if sign == "-" else off_int
            return offset_to_name.get(actual, m.group(0))

        # Pattern: (rbp|rsp|sp|x29) ± N inside a cast or array index
        stack_re = re.compile(
            r"\((?P<base>rbp|ebp|rsp|esp|sp|x29|r11|fp)\s*(?P<sign>[+\-])\s*(?P<off>0x[0-9a-fA-F]+|\d+)\)",
            flags=re.IGNORECASE,
        )
        code = stack_re.sub(_replace_stack_ref, code)
        for alias, stack_name in sorted(
            stack_token_aliases.items(),
            key=lambda item: (-len(item[0]), item[0]),
        ):
            code = re.sub(
                rf"\b{re.escape(alias)}\b",
                stack_name,
                code,
                flags=re.IGNORECASE,
            )
        for reg_name, arg_name in sorted(
            register_name_map.items(), key=lambda item: (-len(item[0]), item[0])
        ):
            code = re.sub(
                rf"\b{re.escape(reg_name)}\b",
                arg_name,
                code,
                flags=re.IGNORECASE,
            )

    return code


def _collect_annotation_notes(
    raw_code: str,
    annotations_map: dict[str, str],
    annotation_comments: dict[str, str],
) -> list[dict[str, str]]:
    """Retourne les annotations référencées par le pseudo-C avec leurs commentaires."""
    notes: list[dict[str, str]] = []
    seen: set[str] = set()
    for addr_norm, name in annotations_map.items():
        matched = any(
            re.search(re.escape(pattern), raw_code, flags=re.IGNORECASE)
            for pattern in _annotation_patterns(addr_norm)
        )
        if not matched:
            continue
        key = f"{addr_norm}:{name}"
        if key in seen:
            continue
        seen.add(key)
        notes.append(
            {
                "addr": f"0x{addr_norm}",
                "name": name,
                "comment": annotation_comments.get(addr_norm, ""),
            }
        )
    return notes


def _collect_typed_struct_notes(
    raw_code: str,
    struct_notes: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    notes: list[dict[str, Any]] = []
    seen: set[str] = set()
    for entry in struct_notes or []:
        addr_norm = str(entry.get("addr") or "").lower().lstrip("0x").lstrip("0") or "0"
        matched = any(
            re.search(re.escape(pattern), raw_code, flags=re.IGNORECASE)
            for pattern in _annotation_patterns(addr_norm)
        )
        if not matched:
            continue
        key = f"{entry.get('struct_name')}:{entry.get('field_name')}:{addr_norm}"
        if key in seen:
            continue
        seen.add(key)
        notes.append(dict(entry))
    return notes


def _normalize_provider(provider: str | None) -> str:
    normalized = str(provider or "auto").strip().lower()
    if normalized in {"local", "docker", "auto"}:
        return normalized
    return "auto"


def _target_metadata(binary_path: str) -> dict[str, str]:
    meta = _binary_info(binary_path)
    return {
        "arch": str(meta.get("arch") or "unknown").strip().lower(),
        "bitness": str(meta.get("bitness") or "64").strip().lower(),
        "format": str(meta.get("format") or "raw").strip().lower(),
    }


def _decompiler_target_support(
    entry: dict[str, Any] | None,
    binary_meta: dict[str, str],
    *,
    full: bool = False,
) -> tuple[bool, str]:
    if not isinstance(entry, dict):
        return True, ""
    decompiler_id = _normalize_decompiler_id(str(entry.get("id") or ""))
    builtin_policy = _BUILTIN_TARGET_POLICIES.get(decompiler_id, {})
    fmt = str(binary_meta.get("format") or "raw").strip().lower()
    arch = str(binary_meta.get("arch") or "unknown").strip().lower()
    bitness = str(binary_meta.get("bitness") or "64").strip().lower()

    supports = entry.get("supports") or builtin_policy.get("supports") or {}
    if isinstance(supports, dict):
        formats = [
            str(item).strip().lower()
            for item in supports.get("formats", [])
            if str(item).strip()
        ]
        if formats and fmt not in formats:
            return False, f"format {fmt} non déclaré pour ce backend"
        architectures = [
            str(item).strip().lower()
            for item in supports.get("architectures", [])
            if str(item).strip()
        ]
        if architectures and arch != "unknown" and arch not in architectures:
            return False, f"architecture {arch} non déclarée pour ce backend"
        bitnesses = [
            str(item).strip().lower()
            for item in supports.get("bitness", [])
            if str(item).strip()
        ]
        if bitnesses and bitness not in bitnesses:
            return False, f"mode {bitness}-bit non déclaré pour ce backend"

    excludes = entry.get("exclude_targets")
    if not excludes:
        excludes = builtin_policy.get("exclude_targets") or []
    for excluded in excludes or []:
        if not isinstance(excluded, dict):
            continue
        if (
            excluded.get("format")
            and str(excluded.get("format")).strip().lower() != fmt
        ):
            continue
        if excluded.get("arch") and str(excluded.get("arch")).strip().lower() != arch:
            continue
        if (
            excluded.get("bitness")
            and str(excluded.get("bitness")).strip().lower() != bitness
        ):
            continue
        if "full" in excluded and bool(excluded.get("full")) != bool(full):
            continue
        return False, str(
            excluded.get("reason") or "cible explicitement exclue pour ce backend"
        )
    return True, ""


def _is_decompiler_available(decompiler: str, provider: str = "auto") -> bool:
    """Vérifie si un décompilateur est disponible selon le provider demandé."""
    provider = _normalize_provider(provider)
    decompiler = _normalize_decompiler_id(decompiler)
    entry = _load_decompilers().get(decompiler)
    if not entry:
        return False
    if provider == "local":
        return _is_decompiler_available_local(decompiler)
    if provider == "docker":
        return _is_docker_image_available_for_decompiler(decompiler)
    # auto : local OU docker
    return _is_decompiler_available_local(
        decompiler
    ) or _is_docker_image_available_for_decompiler(decompiler)


def list_available_decompilers(
    provider: str = "auto",
    *,
    binary_path: str | None = None,
    full: bool = False,
) -> dict[str, Any]:
    """Retourne tous les décompilateurs déclarés dans decompilers.json.

    Pour chaque entrée, indique si elle est disponible (local ou Docker)
    selon le provider demandé.

    _meta.local_available         : dict id → bool (outil détecté localement)
    _meta.docker_images_available : dict id → bool (image Docker présente)
    _meta.labels                  : dict id → label lisible
    """
    provider = _normalize_provider(provider)
    all_decompilers = _load_decompilers()
    docker_images = _get_all_docker_images()

    local_available: dict[str, bool] = {
        did: _is_decompiler_available_local(did) for did in all_decompilers
    }
    docker_avail: dict[str, bool] = {
        key: _is_docker_decompiler_image_available(image)
        for key, image in docker_images.items()
    }
    available: dict[str, Any] = {
        did: _is_decompiler_available(did, provider) for did in all_decompilers
    }
    reasons: dict[str, str] = {}
    target_reasons: dict[str, str] = {}
    binary_meta = _target_metadata(binary_path) if binary_path else None
    for did in all_decompilers:
        entry = all_decompilers.get(did)
        if binary_meta:
            supported, support_reason = _decompiler_target_support(
                entry, binary_meta, full=full
            )
            if not supported:
                target_reasons[did] = support_reason
                available[did] = False
        if available.get(did):
            continue
        has_docker_image = bool(docker_images.get(did))
        local_ok = local_available.get(did, False)
        docker_ok = docker_avail.get(did, False)
        if did in target_reasons:
            reasons[did] = target_reasons[did]
            continue
        if not has_docker_image and not local_ok:
            reasons[did] = "outil local absent et aucune image Docker configurée"
        elif has_docker_image and not docker_ok and not local_ok:
            reasons[did] = (
                f"image Docker absente — make decompiler-docker-build DECOMPILER={did}"
            )
        elif not local_ok:
            reasons[did] = "outil non détecté localement (detect introuvable dans PATH)"
        elif not docker_ok:
            reasons[did] = "image Docker absente"
        else:
            reasons[did] = "indisponible"
    available["_meta"] = {
        "provider": provider,
        "target": binary_meta,
        "full": bool(full),
        "docker_images": docker_images,
        "docker_images_available": docker_avail,
        "local_available": local_available,
        "labels": _custom_decompiler_labels(),
        "reasons": reasons,
        "timeouts": {
            did: int(all_decompilers[did].get("timeout") or 120)
            for did in all_decompilers
        },
    }
    return available


def _auto_decompiler_order() -> list[str]:
    """Ordre de préférence auto : ordre de déclaration dans decompilers.json."""
    return list(_load_decompilers().keys())


# ---------------------------------------------------------------------------
# Résolution de cibles de fonction (symboles → adresse)
# ---------------------------------------------------------------------------


def _normalize_symbol_lookup_name(name: str) -> str:
    symbol = _pretty_symbol_name(str(name or "").strip())
    if symbol.startswith("sym."):
        symbol = symbol.split("sym.", 1)[1]
    return symbol.strip().lower()


def _symbol_name_aliases(name: str) -> set[str]:
    raw_name = str(name or "").strip()
    aliases = {
        raw_name,
        _pretty_symbol_name(raw_name),
        _normalize_symbol_lookup_name(raw_name),
    }
    if raw_name.startswith("_") and len(raw_name) > 1:
        aliases.add(raw_name[1:])
        aliases.add(_normalize_symbol_lookup_name(raw_name[1:]))
    if raw_name.startswith("sym.") and len(raw_name) > 4:
        trimmed = raw_name.split("sym.", 1)[1]
        aliases.add(trimmed)
        aliases.add(_pretty_symbol_name(trimmed))
        aliases.add(_normalize_symbol_lookup_name(trimmed))
    return {alias.strip() for alias in aliases if str(alias or "").strip()}


def _build_function_target_index(
    binary_path: str,
) -> tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]:
    name_index: dict[str, dict[str, str]] = {}
    addr_index: dict[str, dict[str, str]] = {}

    def _add(addr: str, name: str) -> None:
        normalized_addr = _normalize_hex_addr(addr)
        raw_name = str(name or "").strip()
        if not normalized_addr or not raw_name:
            return
        entry = addr_index.setdefault(
            normalized_addr,
            {
                "addr": normalized_addr,
                "name": _pretty_symbol_name(raw_name) or raw_name,
                "raw_name": raw_name,
            },
        )
        for alias in _symbol_name_aliases(raw_name):
            name_index.setdefault(alias, entry)

    try:
        from backends.static.binary.symbols import extract_symbols

        for sym in extract_symbols(binary_path):
            _add(str(sym.get("addr") or ""), str(sym.get("name") or ""))
    except Exception:
        pass

    return name_index, addr_index


def _resolve_function_target(
    binary_path: str, addr: str, func_name: str = ""
) -> tuple[str, str]:
    """Résout une cible de fonction (nom → adresse ou adresse → nom) via l'index des symboles."""
    normalized_addr = _normalize_hex_addr(addr)
    wanted_name = str(func_name or "").strip()
    if not normalized_addr and not wanted_name:
        return normalized_addr, wanted_name

    name_index, addr_index = _build_function_target_index(binary_path)
    if wanted_name:
        resolved = name_index.get(_normalize_symbol_lookup_name(wanted_name))
        if resolved:
            normalized_addr = resolved["addr"]
            wanted_name = (
                resolved.get("raw_name") or resolved.get("name") or wanted_name
            )

    if normalized_addr:
        resolved = addr_index.get(normalized_addr)
        if resolved and not wanted_name:
            wanted_name = (
                resolved.get("raw_name") or resolved.get("name") or wanted_name
            )

    return normalized_addr or _normalize_hex_addr(addr), wanted_name


def decompile_function(
    binary_path: str,
    addr: str,
    func_name: str = "",
    decompiler: str = "",
    annotations_json: str | None = None,
    stack_vars: list[dict] | None = None,
    cache_dir: Path | None = None,
    provider: str = "auto",
) -> dict[str, Any]:
    """Décompile une fonction. decompiler='' → sélection automatique parmi les outils disponibles."""
    provider = _normalize_provider(provider)
    binary_meta = _target_metadata(binary_path)
    resolved_addr, resolved_func_name = _resolve_function_target(
        binary_path, addr, func_name
    )
    addr = resolved_addr or addr
    func_name = resolved_func_name or func_name
    base: dict[str, Any] = {"addr": addr, "code": "", "error": None}
    if not Path(binary_path).exists():
        base["error"] = f"Fichier introuvable : {binary_path}"
        return base
    ann_map, annotation_comments = _load_annotations_payload(annotations_json)
    typed_struct_map, typed_struct_comments, typed_struct_note_catalog = (
        _load_typed_struct_annotation_payload(binary_path)
    )
    for addr_norm, label in typed_struct_map.items():
        ann_map.setdefault(addr_norm, label)
    for addr_norm, comment in typed_struct_comments.items():
        annotation_comments.setdefault(addr_norm, comment)

    # Stack vars depuis stack_frame (graceful degradation si capstone/lief absent)
    stack_frame_data: dict[str, Any] | None = None
    if stack_vars is None:
        try:
            from backends.static.disasm.stack_frame import analyse_stack_frame

            func_addr = int(addr, 16) if addr.startswith("0x") else int(addr, 10)
            sf = analyse_stack_frame(binary_path, func_addr)
            stack_frame_data = _stack_frame_payload(sf, None)
            stack_vars = sf.get("vars", []) + sf.get("args", [])
        except Exception as e:
            _log.debug("stack_frame unavailable for %s at %s: %s", binary_path, addr, e)
            stack_vars = []
    else:
        stack_frame_data = _stack_frame_payload(None, stack_vars)

    _cdir = cache_dir if cache_dir is not None else _DEFAULT_CACHE_DIR
    _key = _cache_key(
        binary_path,
        addr,
        func_name=func_name,
        decompiler=decompiler,
        annotations_json=annotations_json,
        stack_signature=_stack_signature(stack_frame_data, stack_vars),
        typed_structs_signature=typed_struct_signature(binary_path),
    )
    cached = _read_cache(_key, _cdir)
    if cached is not None:
        if not cached.get("error") and not isinstance(
            cached.get("score"), (int, float)
        ):
            cached["score"] = _score_decompile_code(cached.get("code", ""))["score"]
        return cached

    expected_calls = _extract_reachable_call_names(binary_path, addr)

    def _postprocess(result: dict) -> dict:
        raw_code = result.get("code", "") or ""
        if result.get("code"):
            result["code"] = _postprocess_code(
                raw_code,
                ann_map,
                stack_vars,
                binary_path=binary_path,
                addr=addr,
                decompiler=str(result.get("decompiler") or decompiler or ""),
            )
        notes = _collect_annotation_notes(raw_code, ann_map, annotation_comments)
        if notes:
            result["annotations"] = notes
        typed_struct_notes = _collect_typed_struct_notes(
            raw_code, typed_struct_note_catalog
        )
        if typed_struct_notes:
            result["typed_structs"] = typed_struct_notes
        if stack_frame_data:
            result["stack_frame"] = stack_frame_data
        return result

    def _postprocess_and_cache(result: dict) -> dict:
        out = _postprocess(result)
        if not out.get("error"):
            if not isinstance(out.get("score"), (int, float)):
                raw_score = _score_decompile_code(out.get("code", ""))["score"]
                did = _normalize_decompiler_id(
                    str(out.get("decompiler") or decompiler or "")
                )
                _entry = _load_decompilers().get(did) or {}
                _bias_raw = (
                    _entry.get("quality_bias")
                    if _entry.get("quality_bias") is not None
                    else _BUILTIN_TARGET_POLICIES.get(did, {}).get("quality_bias")
                )
                _bias = int(_bias_raw) if _bias_raw is not None else 0
                out["score"] = raw_score + _bias
            _write_cache(_key, _cdir, out, meta=_build_cache_meta(binary_path))
        return out

    decompiler = _normalize_decompiler_id(decompiler)

    def _run_function_candidate(candidate: str) -> dict[str, Any]:
        entry = _load_decompilers().get(_normalize_decompiler_id(candidate))
        supported, reason = _decompiler_target_support(entry, binary_meta, full=False)
        if not supported:
            return {
                "addr": addr,
                "code": "",
                "functions": [],
                "error": f"{candidate} non retenu pour {binary_meta.get('format')}/{binary_meta.get('arch')}: {reason}",
                "decompiler": candidate,
                "error_type": "unsupported_target",
            }
        if provider == "docker":
            return _run_custom_decompiler_in_docker(
                candidate,
                binary_path,
                addr=addr,
                func_name=func_name,
                full=False,
            )
        if provider == "local":
            return _run_custom_decompiler(
                candidate,
                binary_path,
                addr=addr,
                func_name=func_name,
                full=False,
            )
        # provider == "auto" : local d'abord, Docker en fallback si pas de commande locale
        local_result = _run_custom_decompiler(
            candidate,
            binary_path,
            addr=addr,
            func_name=func_name,
            full=False,
        )
        if local_result.get("error") and "commande locale" in str(
            local_result.get("error", "")
        ):
            return _run_custom_decompiler_in_docker(
                candidate,
                binary_path,
                addr=addr,
                func_name=func_name,
                full=False,
            )
        return local_result

    # Dispatch explicite si décompilateur spécifié
    if decompiler:
        return _postprocess_and_cache(_run_function_candidate(decompiler))

    # '' → chaîne auto : lance tous les décompilateurs disponibles en parallèle
    candidates = []
    for candidate in _auto_decompiler_order():
        if not _is_decompiler_available(candidate, provider):
            continue
        entry = _load_decompilers().get(candidate)
        supported, _reason = _decompiler_target_support(entry, binary_meta, full=False)
        if supported:
            candidates.append(candidate)

    def _run_candidate_safe(candidate: str) -> dict[str, Any]:
        try:
            attempt = _run_function_candidate(candidate)
            attempt.setdefault("decompiler", candidate)
            return attempt
        except Exception as exc:
            return {
                "addr": addr,
                "code": "",
                "error": str(exc),
                "decompiler": candidate,
            }

    # Lance tous les décompilateurs en parallèle puis retient le meilleur score.
    attempts: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(candidates) or 1
    ) as pool:
        futures = {pool.submit(_run_candidate_safe, c): c for c in candidates}
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            attempts.append(r)
            if r.get("error"):
                _log.warning(
                    "%s failed (%s), fallback", futures[future], r.get("error")
                )
    best = _select_best_function_candidate(attempts)
    if best is None:
        if not candidates:
            base["error"] = (
                f"Aucun décompilateur compatible disponible pour {binary_meta.get('format')}/{binary_meta.get('arch')}"
            )
        return _postprocess(base)
    best["quality_details"] = _build_function_quality_details(
        attempts, best, expected_calls
    )
    return _postprocess_and_cache(best)


def decompile_binary(
    binary_path: str,
    decompiler: str = "",
    provider: str = "auto",
) -> dict[str, Any]:
    """Décompile le binaire entier. decompiler='' → sélection automatique parmi les outils disponibles."""
    provider = _normalize_provider(provider)
    binary_meta = _target_metadata(binary_path)
    decompiler = _normalize_decompiler_id(decompiler)
    result: dict[str, Any] = {"functions": [], "error": None}
    if not Path(binary_path).exists():
        result["error"] = f"Fichier introuvable : {binary_path}"
        return result

    def _run_binary_candidate(candidate: str) -> dict[str, Any]:
        entry = _load_decompilers().get(_normalize_decompiler_id(candidate))
        supported, reason = _decompiler_target_support(entry, binary_meta, full=True)
        if not supported:
            return {
                "functions": [],
                "error": f"{candidate} non retenu pour {binary_meta.get('format')}/{binary_meta.get('arch')}: {reason}",
                "decompiler": candidate,
                "error_type": "unsupported_target",
            }
        if provider == "docker":
            return _run_custom_decompiler_in_docker(candidate, binary_path, full=True)
        if provider == "local":
            return _run_custom_decompiler(candidate, binary_path, full=True)
        # provider == "auto" : local d'abord, Docker en fallback si pas de commande locale
        local_result = _run_custom_decompiler(candidate, binary_path, full=True)
        if local_result.get("error") and "commande locale" in str(
            local_result.get("error", "")
        ):
            return _run_custom_decompiler_in_docker(candidate, binary_path, full=True)
        return local_result

    # Dispatch explicite si décompilateur spécifié
    if decompiler:
        result = _run_binary_candidate(decompiler)
        if not result.get("error") and "score" not in result:
            result["score"] = _score_binary_decompile(result, decompiler)["score"]
        return result

    # '' → chaîne auto : lance tous les décompilateurs disponibles en parallèle
    bin_candidates = []
    for candidate in _auto_decompiler_order():
        if not _is_decompiler_available(candidate, provider):
            continue
        entry = _load_decompilers().get(candidate)
        supported, _reason = _decompiler_target_support(entry, binary_meta, full=True)
        if supported:
            bin_candidates.append(candidate)

    def _run_binary_candidate_safe(candidate: str) -> dict[str, Any]:
        try:
            attempt = _run_binary_candidate(candidate)
            attempt.setdefault("decompiler", candidate)
            return attempt
        except Exception as exc:
            return {"functions": [], "error": str(exc), "decompiler": candidate}

    # Lance tous les décompilateurs en parallèle puis retient le meilleur score.
    attempts: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=len(bin_candidates) or 1
    ) as pool:
        futures = {
            pool.submit(_run_binary_candidate_safe, c): c for c in bin_candidates
        }
        for future in concurrent.futures.as_completed(futures):
            r = future.result()
            attempts.append(r)
            if r.get("error"):
                _log.warning(
                    "%s binary failed (%s), fallback", futures[future], r.get("error")
                )
    best = _select_best_binary_candidate(attempts)
    if best is None:
        if not bin_candidates:
            result["error"] = (
                f"Aucun décompilateur compatible disponible pour {binary_meta.get('format')}/{binary_meta.get('arch')}"
            )
        else:
            result["error"] = "Aucun décompilateur disponible"
        return result
    best["quality_details"] = _build_binary_quality_details(attempts, best)
    return best


if __name__ == "__main__":
    # Délègue au __main__.py du package pour éviter la duplication.
    import runpy

    runpy.run_module("backends.static.decompile", run_name="__main__", alter_sys=True)
