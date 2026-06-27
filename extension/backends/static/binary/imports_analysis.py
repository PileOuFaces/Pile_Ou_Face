# SPDX-License-Identifier: AGPL-3.0-only
"""Analyse des imports d'un binaire : regroupement par DLL et détection de patterns suspects.

CLI:
  python imports_analysis.py --binary <path> [--threshold 30]

Output JSON:
  {
    "imports": [{"dll": str, "functions": [str], "count": int}],
    "suspicious": [{"function": str, "dll": str, "category": str, "description": str}],
    "score": int,   // 0-100, suspicion globale
    "error": null
  }
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any

# Patterns de fonctions suspectes classées par catégorie
# Format : {nom_fonction_lower: (categorie, description)}
_SUSPICIOUS_PATTERNS: dict[str, tuple[str, str]] = {
    # Injection de code / shellcode
    "virtualalloc": ("INJECTION", "Alloue mémoire exécutable (souvent shellcode)"),
    "virtualallocex": ("INJECTION", "Alloue mémoire dans un processus distant"),
    "writeprocessmemory": ("INJECTION", "Écrit dans la mémoire d'un autre processus"),
    "createremotethread": ("INJECTION", "Crée un thread dans un autre processus"),
    "createremotethreadex": (
        "INJECTION",
        "Crée un thread dans un autre processus (ex)",
    ),
    "ntcreatethread": ("INJECTION", "Crée un thread (NT API)"),
    "rtlcreatethread": ("INJECTION", "Crée un thread (RTL)"),
    "queueuserapc": ("INJECTION", "APC injection"),
    "setwindowshookex": ("INJECTION", "Hook d'API Windows (keylogger, injection)"),
    "ntmapviewofsection": ("INJECTION", "Mappe une section dans un processus distant"),
    "zwmapviewofsection": (
        "INJECTION",
        "Mappe une section dans un processus distant (Zw)",
    ),
    "virtualprotect": ("SHELLCODE", "Change les permissions mémoire (writable → exec)"),
    "virtualprotectex": (
        "SHELLCODE",
        "Change les permissions mémoire d'un processus distant",
    ),
    # Exécution de commandes
    "createprocess": ("EXECUTION", "Lance un processus"),
    "createprocessa": ("EXECUTION", "Lance un processus (ANSI)"),
    "createprocessw": ("EXECUTION", "Lance un processus (Unicode)"),
    "winexec": ("EXECUTION", "Exécute une commande shell"),
    "shellexecute": ("EXECUTION", "Exécute un fichier/URL via le shell"),
    "shellexecuteex": ("EXECUTION", "Exécute un fichier/URL via le shell (ex)"),
    "system": ("EXECUTION", "Exécute une commande shell (libc)"),
    "popen": ("EXECUTION", "Lance un processus avec pipe"),
    "execve": ("EXECUTION", "Exécute un binaire (Linux)"),
    "execvp": ("EXECUTION", "Exécute un binaire (Linux)"),
    # Anti-debug / anti-analyse
    "isdebuggerpresent": ("ANTI_DEBUG", "Détecte un débogueur"),
    "checkremotedebuggerpresent": ("ANTI_DEBUG", "Détecte un débogueur distant"),
    "ntqueryinformationprocess": (
        "ANTI_DEBUG",
        "Détecte un débogueur via ProcessDebugPort",
    ),
    "outputdebugstring": ("ANTI_DEBUG", "Trick anti-debug via OutputDebugString"),
    "zwqueryinformationprocess": ("ANTI_DEBUG", "Détecte un débogueur (Zw)"),
    "findwindow": ("ANTI_DEBUG", "Peut détecter des fenêtres de débogueurs"),
    "ptrace": ("ANTI_DEBUG", "Détecte ou empêche le débogage (Linux)"),
    "prctl": ("ANTI_DEBUG", "Peut désactiver le ptrace (Linux)"),
    # Réseau
    "wsastartup": ("NETWORK", "Initialise Winsock (réseau Windows)"),
    "socket": ("NETWORK", "Crée un socket réseau"),
    "connect": ("NETWORK", "Connexion TCP/UDP à un serveur distant"),
    "send": ("NETWORK", "Envoie des données sur le réseau"),
    "recv": ("NETWORK", "Reçoit des données du réseau"),
    "internetopen": ("NETWORK", "Ouvre une session WinINet (HTTP)"),
    "internetconnect": ("NETWORK", "Connexion HTTP/FTP"),
    "httpopenrequest": ("NETWORK", "Crée une requête HTTP"),
    "httpsendrequesta": ("NETWORK", "Envoie une requête HTTP"),
    "urldownloadtofile": ("NETWORK", "Télécharge un fichier depuis une URL"),
    "winHttpopen": ("NETWORK", "Ouvre une session WinHTTP"),
    # Crypto / chiffrement
    "cryptencrypt": ("CRYPTO", "Chiffrement via CryptoAPI"),
    "cryptdecrypt": ("CRYPTO", "Déchiffrement via CryptoAPI"),
    "cryptcreatehash": ("CRYPTO", "Hachage via CryptoAPI"),
    "bcryptencrypt": ("CRYPTO", "Chiffrement via BCrypt"),
    "bcryptdecrypt": ("CRYPTO", "Déchiffrement via BCrypt"),
    # Persistance (registre, services)
    "regsetvalue": ("PERSISTENCE", "Écrit dans le registre (persistance)"),
    "regsetvaluea": ("PERSISTENCE", "Écrit dans le registre (ANSI)"),
    "regsetvaluew": ("PERSISTENCE", "Écrit dans le registre (Unicode)"),
    "regsetvalueex": ("PERSISTENCE", "Écrit dans le registre (Extended)"),
    "regsetvalueexa": ("PERSISTENCE", "Écrit dans le registre (Ex ANSI)"),
    "regsetvalueexw": ("PERSISTENCE", "Écrit dans le registre (Ex Unicode)"),
    "createservice": ("PERSISTENCE", "Crée un service Windows"),
    "openscmanager": ("PERSISTENCE", "Ouvre le gestionnaire de services"),
    # Accès fichiers système
    "ntcreatedirectoryobject": ("PRIVILEGE", "Crée un objet répertoire NT"),
    "adjusttokenprivileges": (
        "PRIVILEGE",
        "Ajuste les privilèges du token (élévation)",
    ),
    "openprocesstoken": ("PRIVILEGE", "Ouvre le token d'un processus"),
    "duplicatetoken": ("PRIVILEGE", "Duplique un token (impersonation)"),
    # Linux spécifique
    "mprotect": ("SHELLCODE", "Change les permissions mémoire (Linux)"),
    "mmap": ("SHELLCODE", "Mappe de la mémoire (peut créer une zone exec)"),
    "dlopen": ("INJECTION", "Charge une bibliothèque dynamiquement (Linux)"),
    "dlsym": ("INJECTION", "Résout un symbole dynamiquement (Linux)"),
}

# Score par catégorie (contribue au score de suspicion global)
_CATEGORY_SCORES: dict[str, int] = {
    "INJECTION": 25,
    "SHELLCODE": 15,
    "EXECUTION": 10,
    "ANTI_DEBUG": 20,
    "NETWORK": 5,
    "CRYPTO": 5,
    "PERSISTENCE": 15,
    "PRIVILEGE": 10,
}


def analyze_imports(binary_path: str) -> dict[str, Any]:
    """Analyse les imports d'un binaire et détecte les patterns suspects.

    Returns:
        {
            "imports": [{"dll": str, "functions": [str], "count": int}],
            "suspicious": [{"function": str, "dll": str, "category": str, "description": str}],
            "score": int,
            "error": null
        }
    """
    path = Path(binary_path)
    if not path.exists():
        return {
            "error": f"Fichier introuvable : {binary_path}",
            "imports": [],
            "suspicious": [],
            "score": 0,
        }

    try:
        import lief
    except ImportError:
        return _fallback_scan_import_strings(path)

    try:
        binary = lief.parse(str(path))
    except Exception as e:
        return _fallback_scan_import_strings(path)

    if binary is None:
        return _fallback_scan_import_strings(path)

    raw_imports = _extract_raw_imports(binary)
    imports_by_dll = _group_by_dll(raw_imports)
    suspicious = _find_suspicious(raw_imports)
    score = _compute_score(suspicious)

    return {
        "imports": imports_by_dll,
        "suspicious": suspicious,
        "score": score,
        "error": None,
    }


def _fallback_scan_import_strings(path: Path) -> dict[str, Any]:
    try:
        data = path.read_bytes()
    except Exception as e:
        return {
            "error": str(e),
            "imports": [],
            "suspicious": [],
            "score": 0,
        }
    raw_imports = _extract_string_import_candidates(data)
    imports_by_dll = _group_by_dll(raw_imports)
    suspicious = _find_suspicious(raw_imports)
    return {
        "imports": imports_by_dll,
        "suspicious": suspicious,
        "score": _compute_score(suspicious),
        "error": None,
        "source": "string-reference",
    }


def _extract_string_import_candidates(data: bytes) -> list[tuple[str, str]]:
    candidates: list[tuple[str, str]] = []
    seen: set[str] = set()
    pattern = rb"[A-Za-z_][A-Za-z0-9_@.$]{1,96}"
    suspicious_names = set(_SUSPICIOUS_PATTERNS)
    for match in re.finditer(pattern, data):
        raw_name = match.group().decode("ascii", errors="ignore")
        normalized = raw_name.lower().lstrip("_")
        normalized = re.sub(r"@@?[^@]+$", "", normalized)
        if normalized in suspicious_names and normalized not in seen:
            seen.add(normalized)
            candidates.append(("<strings>", raw_name))
    return candidates


def _extract_raw_imports(binary: Any) -> list[tuple[str, str]]:
    """Extrait la liste (dll, function) depuis un binaire lief."""
    result: list[tuple[str, str]] = []
    try:
        import lief

        # PE : table d'import explicite avec noms de DLL
        if isinstance(binary, lief.PE.Binary):
            for imp in binary.imports:
                dll = getattr(imp, "name", "") or ""
                for entry in imp.entries:
                    func = getattr(entry, "name", "") or ""
                    if not func and hasattr(entry, "ordinal"):
                        func = f"Ordinal_{entry.ordinal}"
                    if func:
                        result.append((dll, func))

        # Mach-O : binary.symbols contient library_ordinal (1-based → binary.libraries)
        elif isinstance(binary, lief.MachO.Binary):
            libs: list[str] = [
                getattr(lib_cmd, "name", "").split("/")[-1]
                for lib_cmd in getattr(binary, "libraries", [])
            ]
            fn_names = {f.name for f in getattr(binary, "imported_functions", [])}
            for sym in getattr(binary, "symbols", []):
                sym_name = getattr(sym, "name", "") or ""
                if not sym_name or sym_name not in fn_names:
                    continue
                ordinal = getattr(sym, "library_ordinal", 0) or 0
                lib = libs[ordinal - 1] if 1 <= ordinal <= len(libs) else ""
                # Retirer le préfixe _ du C mangling Mach-O (_printf → printf)
                # Un seul _ seulement (__ = symbole système, conserver tel quel)
                display_name = (
                    sym_name[1:]
                    if sym_name.startswith("_") and not sym_name.startswith("__")
                    else sym_name
                )
                result.append((lib, display_name))

        # ELF : pas de notion de bibliothèque source, grouper par ""
        elif hasattr(binary, "imported_functions"):
            for sym in binary.imported_functions:
                name = getattr(sym, "name", "") or ""
                if name:
                    result.append(("", name))
        else:
            for sym in getattr(binary, "symbols", []):
                name = getattr(sym, "name", "") or ""
                binding = getattr(sym, "binding", None)
                if name and binding is not None:
                    binding_name = getattr(binding, "name", str(binding))
                    if "GLOBAL" in str(binding_name) or "WEAK" in str(binding_name):
                        result.append(("", name))
    except Exception:
        pass
    return result


def _group_by_dll(raw: list[tuple[str, str]]) -> list[dict]:
    """Regroupe les imports par DLL."""
    dll_map: dict[str, list[str]] = {}
    for dll, func in raw:
        dll_map.setdefault(dll or "<unknown>", []).append(func)
    return [
        {"dll": dll, "functions": sorted(funcs), "count": len(funcs)}
        for dll, funcs in sorted(dll_map.items())
    ]


def _find_suspicious(raw: list[tuple[str, str]]) -> list[dict]:
    """Cherche les fonctions correspondant aux patterns suspects."""
    seen: set[str] = set()
    result: list[dict] = []
    for dll, func in raw:
        func_lower = func.lower().lstrip("_")
        if func_lower in _SUSPICIOUS_PATTERNS and func_lower not in seen:
            seen.add(func_lower)
            category, description = _SUSPICIOUS_PATTERNS[func_lower]
            result.append(
                {
                    "function": func,
                    "dll": dll,
                    "category": category,
                    "description": description,
                }
            )
    return sorted(
        result,
        key=lambda x: (_CATEGORY_SCORES.get(x["category"], 0), x["function"]),
        reverse=True,
    )


def _compute_score(suspicious: list[dict]) -> int:
    """Calcule un score de suspicion 0-100."""
    total = 0
    seen_categories: set[str] = set()
    for entry in suspicious:
        cat = entry["category"]
        if cat not in seen_categories:
            total += _CATEGORY_SCORES.get(cat, 5)
            seen_categories.add(cat)
        else:
            total += max(1, _CATEGORY_SCORES.get(cat, 5) // 3)
    return min(100, total)


def main() -> int:
    """CLI : analyse les imports d'un binaire."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Analyze imports for suspicious patterns")
    parser.add_argument("--binary", required=True, help="Binary path")
    parser.add_argument(
        "--threshold",
        type=int,
        default=0,
        help="Afficher uniquement si score >= threshold (default: 0 = toujours)",
    )
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    result = analyze_imports(args.binary)

    if args.threshold and result.get("score", 0) < args.threshold:
        result["note"] = f"Score {result['score']} < threshold {args.threshold}"

    out = json.dumps(result, indent=2, ensure_ascii=False)
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        n = len(result.get("suspicious", []))
        print(
            f"Imports analysis written to {args.output} ({n} suspicious function(s), score={result.get('score', 0)})"
        )
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
