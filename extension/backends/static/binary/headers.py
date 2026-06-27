# SPDX-License-Identifier: AGPL-3.0-only
"""Extraction des infos binaires (ELF/Mach-O/PE).

Utilise lief pour extraire les métadonnées du binaire (robuste, multi-format).
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

try:
    import lief
except ImportError:
    lief = None

from backends.shared.log import configure_logging, get_logger, make_meta
from backends.static.binary.arch import detect_binary_arch
from backends.static.binary.entropy import entropy_of_file, high_entropy_regions
from backends.static.binary.imports_analysis import analyze_imports
from backends.static.binary.pe_resources import get_pe_resources
from backends.static.binary.sections import extract_sections

logger = get_logger(__name__)

_PACKER_SECTION_NAME_HINTS = {
    "upx",
    ".upx",
    "upx0",
    "upx1",
    "upx2",
    "aspack",
    ".aspack",
    "mpress1",
    "mpress2",
    ".packed",
    "packed",
    "petite",
    ".petite",
    "pec",
    "pec1",
    "pec2",
}

_PACKER_FAMILY_BY_SECTION = {
    "upx": "UPX",
    ".upx": "UPX",
    "upx0": "UPX",
    "upx1": "UPX",
    "upx2": "UPX",
    "aspack": "ASPack",
    ".aspack": "ASPack",
    "mpress1": "MPRESS",
    "mpress2": "MPRESS",
    "petite": "Petite",
    ".petite": "Petite",
    "pec": "PECompact",
    "pec1": "PECompact",
    "pec2": "PECompact",
}

_DYNAMIC_PACKER_IMPORT_HINTS = {
    "getprocaddress",
    "loadlibrarya",
    "loadlibraryw",
    "virtualalloc",
    "virtualallocex",
    "virtualprotect",
    "virtualprotectex",
}


def _normalize_section_name(name: str) -> str:
    return str(name or "").strip().strip("\x00").lower()


def _looks_like_packer_section(name: str) -> bool:
    normalized = _normalize_section_name(name)
    if not normalized:
        return False
    if normalized in _PACKER_SECTION_NAME_HINTS:
        return True
    return any(normalized.startswith(f"{hint}.") for hint in _PACKER_SECTION_NAME_HINTS)


def _family_from_section_name(name: str) -> str | None:
    normalized = _normalize_section_name(name)
    if not normalized:
        return None
    exact = _PACKER_FAMILY_BY_SECTION.get(normalized)
    if exact:
        return exact
    for hint, family in _PACKER_FAMILY_BY_SECTION.items():
        if normalized.startswith(f"{hint}."):
            return family
    return None


def _packer_verdict(score: int) -> tuple[str, str]:
    if score >= 55:
        return ("high", "Suspicion forte de packer")
    if score >= 30:
        return ("medium", "Indices de packer à confirmer")
    if score >= 10:
        return ("low", "Quelques indices de packing")
    return ("none", "Pas d'indice fort de packer")


def _family_confidence_label(score: int) -> str:
    if score >= 55:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _build_packer_analysis(binary_path: str, format_name: str) -> dict[str, Any]:
    sections = extract_sections(binary_path)
    entropy = entropy_of_file(binary_path)
    section_entropy = {
        str(entry.get("name") or ""): entry
        for entry in entropy.get("sections", [])
        if isinstance(entry, dict)
    }
    high_regions = []
    if not entropy.get("error"):
        high_regions = high_entropy_regions(binary_path, threshold=7.2, window=512)[:3]

    imports_data = analyze_imports(binary_path)
    imports_list = imports_data.get("imports", []) if isinstance(imports_data, dict) else []
    import_names = {
        str(function).strip().lower()
        for dll in imports_list
        if isinstance(dll, dict)
        for function in dll.get("functions", [])
        if str(function).strip()
    }

    resources_data = None
    if str(format_name or "").startswith("PE"):
        resource_result = get_pe_resources(binary_path)
        if isinstance(resource_result, dict) and resource_result.get("applicable"):
            resources_data = resource_result

    score = 0
    signals: list[dict[str, Any]] = []
    suspicious_sections: list[dict[str, Any]] = []
    family_scores: dict[str, int] = {}
    family_reasons: dict[str, list[str]] = {}

    global_entropy = entropy.get("global")
    if isinstance(global_entropy, (int, float)):
        if global_entropy >= 7.2:
            score += 24
            signals.append(
                {
                    "kind": "global_entropy",
                    "severity": "high",
                    "label": "Entropie globale élevée",
                    "detail": f"{global_entropy:.2f} bits/octet sur l'ensemble du binaire.",
                }
            )
        elif global_entropy >= 6.8:
            score += 12
            signals.append(
                {
                    "kind": "global_entropy",
                    "severity": "medium",
                    "label": "Entropie globale soutenue",
                    "detail": f"{global_entropy:.2f} bits/octet, à recouper avec les sections.",
                }
            )

    for section in sections:
        if not isinstance(section, dict):
            continue
        section_name = str(section.get("name") or "")
        entropy_entry = section_entropy.get(section_name, {})
        section_ent = entropy_entry.get("entropy")
        reasons: list[str] = []
        section_score = 0

        if _looks_like_packer_section(section_name):
            reasons.append("nom de section typique d'un packer")
            section_score += 20
            family = _family_from_section_name(section_name)
            if family:
                family_scores[family] = family_scores.get(family, 0) + 24
                family_reasons.setdefault(family, []).append(f"section {section_name}")

        if (
            isinstance(section_ent, (int, float))
            and section_ent >= 7.25
            and int(section.get("size") or 0) >= 1024
        ):
            reasons.append("entropie section élevée (compression/chiffrement plausible)")
            section_score += 14

        if (
            section.get("type") == "TEXT"
            and isinstance(section_ent, (int, float))
            and section_ent >= 7.0
            and int(section.get("size") or 0) >= 1024
        ):
            reasons.append("section exécutable inhabituellement dense")
            section_score += 10

        if not reasons:
            continue

        score += min(section_score, 28)
        suspicious_sections.append(
            {
                "name": section_name or "<unnamed>",
                "type": section.get("type") or "UNKNOWN",
                "size": int(section.get("size") or 0),
                "size_hex": section.get("size_hex") or f"0x{int(section.get('size') or 0):x}",
                "offset_hex": entropy_entry.get("offset_hex")
                or f"0x{int(section.get('offset') or 0):x}",
                "entropy": round(float(section_ent), 4)
                if isinstance(section_ent, (int, float))
                else None,
                "reasons": reasons,
            }
        )

    if high_regions:
        score += min(12, 4 * len(high_regions))
        signals.append(
            {
                "kind": "high_entropy_regions",
                "severity": "medium",
                "label": "Fenêtres locales à haute entropie",
                "detail": f"{len(high_regions)} zone(s) >= 7.2 bits/octet détectée(s).",
            }
        )

    if import_names and len(import_names) <= 8 and (suspicious_sections or score >= 12):
        score += 12
        signals.append(
            {
                "kind": "few_imports",
                "severity": "medium",
                "label": "Peu d'imports statiques",
                "detail": f"{len(import_names)} import(s) nommés seulement, ce qui est fréquent après packing.",
            }
        )

    dynamic_hints = sorted(import_names & _DYNAMIC_PACKER_IMPORT_HINTS)
    if dynamic_hints and (
        suspicious_sections or (isinstance(global_entropy, (int, float)) and global_entropy >= 6.8)
    ):
        score += 10
        signals.append(
            {
                "kind": "dynamic_resolution",
                "severity": "medium",
                "label": "Imports compatibles avec un stub de dépack",
                "detail": ", ".join(dynamic_hints[:4]),
            }
        )
        for family, bonus in (("UPX", 6), ("ASPack", 4), ("MPRESS", 4)):
            if family in family_scores:
                family_scores[family] += bonus
                family_reasons.setdefault(family, []).append("stub d'imports dynamique")

    if resources_data:
        large_rcdata = [
            resource
            for resource in resources_data.get("resources", [])
            if str(resource.get("type") or "") == "RT_RCDATA"
            and int(resource.get("size") or 0) >= 65536
        ]
        if large_rcdata:
            score += 8
            signals.append(
                {
                    "kind": "embedded_payload",
                    "severity": "low",
                    "label": "RCDATA volumineux embarqué",
                    "detail": f"{len(large_rcdata)} ressource(s) RT_RCDATA >= 64 KiB.",
                }
            )

    import_count = len(import_names)
    packer_named_sections = sum(
        1 for section in suspicious_sections if _family_from_section_name(section.get("name") or "")
    )
    versionish_resources = 0
    if resources_data:
        versionish_resources = sum(
            1
            for resource in resources_data.get("resources", [])
            if str(resource.get("type") or "")
            in {"RT_VERSION", "RT_MANIFEST", "RT_GROUP_ICON", "RT_ICON"}
        )

    if (
        score >= 18
        and import_count >= 18
        and not dynamic_hints
        and packer_named_sections == 0
        and versionish_resources
    ):
        score = max(0, score - 12)
        signals.append(
            {
                "kind": "benign_layout_bias",
                "severity": "low",
                "label": "Contexte applicatif plutôt classique",
                "detail": "Imports nombreux et ressources standard, ce qui réduit la probabilité d'un stub de packing minimal.",
            }
        )
    elif score >= 18 and import_count >= 28 and not dynamic_hints and packer_named_sections == 0:
        score = max(0, score - 8)
        signals.append(
            {
                "kind": "rich_import_surface",
                "severity": "low",
                "label": "Surface d'imports déjà riche",
                "detail": "Le binaire expose déjà de nombreux imports nommés, atypique pour un packing agressif.",
            }
        )

    # Signatures YARA formelles (optionnel — fallback gracieux si yara absent)
    yara_matches = _scan_with_yara(binary_path)
    yara_by_family: dict[str, list[str]] = {}
    for match in yara_matches:
        yara_by_family.setdefault(match["family"], []).append(match["rule"])
    for yara_family, rules in yara_by_family.items():
        family_scores[yara_family] = family_scores.get(yara_family, 0) + 40
        family_reasons.setdefault(yara_family, []).append(f"signature(s) YARA ({', '.join(rules)})")
        score += 30
        signals.append(
            {
                "kind": "yara_signature",
                "severity": "high",
                "label": f"Signature YARA : {', '.join(rules)}",
                "detail": f"Pattern formel {yara_family} identifié.",
            }
        )

    score = min(100, score)
    verdict, summary = _packer_verdict(score)
    families: list[dict[str, Any]] = []
    for family, family_score in sorted(family_scores.items(), key=lambda item: (-item[1], item[0])):
        families.append(
            {
                "name": family,
                "confidence": _family_confidence_label(family_score),
                "score": min(100, family_score),
                "reasons": family_reasons.get(family, []),
            }
        )
    suspected_family = families[0]["name"] if families else None
    if suspected_family and verdict != "none":
        summary = f"{summary} ({suspected_family} probable)"
    return {
        "verdict": verdict,
        "score": score,
        "summary": summary,
        "global_entropy": global_entropy,
        "signals": signals,
        "suspicious_sections": suspicious_sections,
        "high_entropy_regions": high_regions,
        "import_count": import_count,
        "resource_count": resources_data.get("count") if isinstance(resources_data, dict) else None,
        "suspected_family": suspected_family,
        "families": families,
        "yara_matches": yara_matches,
    }


def _scan_with_yara(binary_path: str) -> list[dict[str, str]]:
    """Scanne le binaire contre les signatures YARA packer.

    Returns:
        Liste de {"rule": str, "family": str} pour chaque règle matchée.
        Liste vide si yara-python n'est pas installé ou si une erreur survient.
    """
    try:
        import yara
    except ImportError:
        return []
    sigs_path = Path(__file__).parent / "packer_signatures.yar"
    if not sigs_path.exists():
        return []
    try:
        rules = yara.compile(str(sigs_path))
        matches = rules.match(binary_path)
        return [
            {
                "rule": m.rule,
                "family": m.meta.get("family", m.rule),
            }
            for m in matches
        ]
    except Exception as exc:
        logger.warning("YARA scan failed for %s: %s", binary_path, exc)
        return []


def extract_binary_info(binary_path: str) -> dict:
    """Extrait les infos de base (type, machine, entry, etc.).

    Args:
        binary_path: Chemin vers le binaire

    Returns:
        Dict avec path, format, machine, entry, type, bits, arch, stripped, packers
    """
    if not lief:
        return {"error": "lief not installed"}

    path = Path(binary_path)
    if not path.exists():
        return {"error": "Fichier introuvable"}

    try:
        binary = lief.parse(str(path))
        if binary is None:
            return {"error": "Format de binaire non supporté"}
    except Exception as e:
        return {"error": f"Erreur parsing: {str(e)}"}

    # Hash du binaire
    raw = path.read_bytes()
    md5 = hashlib.md5(raw).hexdigest()
    sha256 = hashlib.sha256(raw).hexdigest()

    info = {
        "path": str(path),
        "format": "",
        "machine": "",
        "entry": "",
        "type": "",
        "bits": "",
        "arch": "",
        "endianness": "",
        "stripped": "—",
        "interp": "",
        "packers": "—",
        "packer_analysis": {
            "verdict": "none",
            "score": 0,
            "summary": "Pas d'indice fort de packer",
            "global_entropy": None,
            "signals": [],
            "suspicious_sections": [],
            "high_entropy_regions": [],
            "import_count": 0,
            "resource_count": None,
        },
        "md5": md5,
        "sha256": sha256,
        "imphash": "",
    }
    arch_info = detect_binary_arch(binary)

    # ELF
    if isinstance(binary, lief.ELF.Binary):
        info["format"] = f"ELF {binary.header.file_type.name}"
        info["machine"] = binary.header.machine_type.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = binary.header.file_type.name  # EXEC, DYN, REL, CORE

        info["bits"] = (
            str(arch_info.bits)
            if arch_info is not None
            else ("64" if binary.header.identity_class == lief.ELF.Header.CLASS.ELF64 else "32")
        )
        info["arch"] = (
            arch_info.raw_name if arch_info is not None else binary.header.machine_type.name.lower()
        )
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        # Stripped: vérifier s'il y a des symboles
        sym_count = len(
            [s for s in binary.symtab_symbols if s.name and s.type == lief.ELF.Symbol.TYPE.FUNC]
        )
        info["stripped"] = "oui" if sym_count <= 1 else "non"

        # Interpreter (ld.so)
        if binary.interpreter:
            info["interp"] = binary.interpreter

    # Mach-O
    elif isinstance(binary, lief.MachO.Binary):
        info["format"] = f"Mach-O {binary.header.file_type.name}"
        info["machine"] = binary.header.cpu_type.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = binary.header.file_type.name  # EXECUTE, DYLIB, etc.

        info["bits"] = (
            str(arch_info.bits)
            if arch_info is not None
            else ("64" if binary.header.is_64bit else "32")
        )
        info["arch"] = (
            arch_info.raw_name if arch_info is not None else binary.header.cpu_type.name.lower()
        )
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        # Stripped: vérifier symboles
        sym_count = len([s for s in binary.symbols if s.name and not s.name.startswith("_mh_")])
        info["stripped"] = "oui" if sym_count <= 1 else "non"

    # PE
    elif isinstance(binary, lief.PE.Binary):
        info["format"] = f"PE {binary.header.machine.name}"
        info["machine"] = binary.header.machine.name
        info["entry"] = f"0x{binary.entrypoint:x}"
        info["type"] = "EXECUTABLE"

        machine = binary.header.machine
        info["bits"] = str(arch_info.bits) if arch_info is not None else "?"
        info["arch"] = arch_info.raw_name if arch_info is not None else machine.name.lower()
        info["endianness"] = arch_info.endian if arch_info is not None else "little"

        # Stripped: vérifier exports
        export_count = 0
        if hasattr(binary, "exported_functions"):
            export_count = len([f for f in binary.exported_functions if f.name])
        info["stripped"] = "oui" if export_count == 0 else "non"

        # imphash : hash MD5 des imports (DLL::fonction normalisés), compatible IDA/VirusTotal
        info["imphash"] = _compute_imphash(binary)

    info["packer_analysis"] = _build_packer_analysis(str(path), info["format"])
    info["packers"] = info["packer_analysis"].get("summary") or "—"
    return info


def _compute_imphash(binary: Any) -> str:
    """Calcule l'imphash d'un PE : MD5(dll.func,dll.func,...) normalisé.
    Compatible avec la convention VirusTotal / pefile.
    """
    try:
        entries = []
        for imp in binary.imports:
            dll = imp.name.lower().removesuffix(".dll")
            for entry in imp.entries:
                func = entry.name.lower() if entry.name else f"ord{entry.ordinal}"
                entries.append(f"{dll}.{func}")
        if not entries:
            return ""
        return hashlib.md5(",".join(entries).encode()).hexdigest()
    except Exception:
        return ""


def main() -> int:
    """Point d'entrée CLI : extrait les infos binaires (type, machine, entry, etc.)."""
    import argparse
    import json

    parser = argparse.ArgumentParser(description="Extract binary header info (LIEF)")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument("--output", help="Output JSON path (default: stdout)")
    args = parser.parse_args()

    configure_logging()

    if not lief:
        logger.error("lief not installed. Install with: pip install lief")
        return 1

    info = extract_binary_info(args.binary)
    info["meta"] = make_meta("headers")
    out = json.dumps(info, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(out)
        print(f"Info written to {args.output}")
    else:
        print(out)
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
