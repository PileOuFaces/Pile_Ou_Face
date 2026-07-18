# SPDX-License-Identifier: AGPL-3.0-only
"""Désassemblage et mapping adresse ↔ ligne.

Utilise capstone pour le désassemblage et lief pour parser le binaire.
Alternative robuste à objdump (pas de regex fragiles, pas de subprocess).
"""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path

from backends.shared.exceptions import (
    BinaryNotFoundError,
    BinaryParseError,
    DisassemblyError,
)
from backends.shared.log import configure_logging, get_logger, make_meta
from backends.shared.utils import normalize_addr as _normalize_addr
from backends.shared.utils import parse_addr as _addr_to_int
from backends.static.annotations.typed_struct_refs import (
    build_typed_struct_index,
    collect_typed_struct_hints,
)
from backends.static.binary.arch import (
    FEATURES,
    detect_binary_arch,
    get_feature_support_matrix,
    get_raw_arch_info,
    iter_supported_adapters,
)
from backends.static.binary.symbols import extract_symbols
from backends.static.disasm import mapping_db

logger = get_logger(__name__)

PROGRESS_PREFIX = "POF_PROGRESS "
_MACHO_HEADER_SYMBOLS = {
    "__mh_execute_header",
    "__mh_dylib_header",
    "__mh_bundle_header",
}


def _emit_progress(
    progress_callback: Callable[[dict], None] | None,
    phase: str,
    message: str,
    *,
    current: int | None = None,
    total: int | None = None,
    percent: int | None = None,
) -> None:
    """Émet un événement de progression structuré."""
    if progress_callback is None:
        return
    payload: dict = {"phase": phase, "message": message}
    if current is not None:
        payload["current"] = current
    if total is not None:
        payload["total"] = total
    if percent is None and current is not None and total:
        percent = int(round((current / max(total, 1)) * 100))
    if percent is not None:
        payload["percent"] = max(0, min(100, int(percent)))
    with contextlib.suppress(Exception):
        progress_callback(payload)


def _is_generic_macho_header_symbol(name: str | None) -> bool:
    return str(name or "").strip() in _MACHO_HEADER_SYMBOLS


try:
    import capstone
except ImportError:
    capstone = None

try:
    import lief
except ImportError:
    lief = None


def _get_arch_mode(binary: lief.Binary) -> tuple[int, int] | None:
    """Retourne (capstone_arch, capstone_mode) pour le binaire."""
    info = detect_binary_arch(binary)
    return info.capstone_tuple if info else None


def _get_raw_arch_mode(
    raw_arch: str, raw_endian: str | None = None
) -> tuple[int, int] | None:
    """Retourne (capstone_arch, capstone_mode) pour un blob brut."""
    info = get_raw_arch_info(raw_arch, raw_endian)
    return info.capstone_tuple if info else None


def _resolve_arch_payload(
    binary_path: str,
    *,
    raw_arch: str | None = None,
    raw_endian: str | None = None,
) -> dict | None:
    """Construit les métadonnées architecture/support exposées dans le mapping."""
    try:
        info = get_raw_arch_info(raw_arch, raw_endian) if raw_arch else None
        if info is None and lief and Path(binary_path).exists():
            binary = lief.parse(binary_path)
            if binary is not None:
                info = detect_binary_arch(binary)
    except Exception:
        info = None
    if info is None:
        return None
    support_matrix = get_feature_support_matrix()
    support = support_matrix.get(info.adapter.key)
    if support is None:
        support = {
            feature: info.adapter.support_for(feature).as_dict() for feature in FEATURES
        }
    return {
        "key": info.key,
        "family": info.family,
        "display_name": info.display_name,
        "bits": info.bits,
        "ptr_size": info.ptr_size,
        "abi": info.abi,
        "endian": info.endian,
        "support": support,
    }


def _apply_capstone_syntax(md, cs_arch: int, syntax: str) -> None:
    """Applique la syntaxe quand Capstone la supporte pour cette ISA."""
    if not capstone or cs_arch != getattr(capstone, "CS_ARCH_X86", None):
        return
    if syntax == "intel":
        md.syntax = capstone.CS_OPT_SYNTAX_INTEL
    elif syntax == "att":
        md.syntax = capstone.CS_OPT_SYNTAX_ATT


_RISCV_PC_RELATIVE_MNEMONICS = {
    "b",
    "beq",
    "beqz",
    "bge",
    "bgez",
    "bgeu",
    "bgt",
    "bgtu",
    "bgtz",
    "ble",
    "bleu",
    "blez",
    "blt",
    "bltu",
    "bltz",
    "bne",
    "bnez",
    "j",
    "jal",
    "tail",
}


def _parse_capstone_immediate(value: str) -> int | None:
    text = str(value or "").strip().lower()
    if not text:
        return None
    try:
        return int(text, 16) if text.startswith("0x") else int(text)
    except ValueError:
        return None


# Capstone (binding Python) matérialise en mémoire C *tout* le buffer passé
# à un seul appel md.disasm(), avant même que l'itérateur Python ne cède le
# premier résultat — la RAM du process scale donc avec la taille du buffer
# soumis, pas avec ce que le code Python en fait ensuite. Sur un binaire de
# plusieurs Go, un unique appel sur code_bytes entier est hors de portée
# (mesuré : #180). On fenêtre les appels pour borner ce pic indépendamment
# de la taille totale du binaire.
_DISASM_WINDOW_BYTES = 4 * 1024 * 1024
# Marge de chevauchement en fin de fenêtre pour ne jamais couper une
# instruction : largement supérieure au max réel (15 octets en x86, les
# autres ISA supportées ici sont à taille fixe ≤ 8 octets).
_DISASM_WINDOW_OVERLAP_BYTES = 32


def _iter_windowed_instructions(
    md,
    code_bytes: bytes,
    base_addr: int,
    *,
    window_bytes: int = _DISASM_WINDOW_BYTES,
    overlap_bytes: int = _DISASM_WINDOW_OVERLAP_BYTES,
):
    """Désassemble par fenêtres bornées au lieu d'un appel sur tout le buffer.

    Chaque fenêtre est décodée avec un chevauchement de lookahead pour que
    les instructions proches de la frontière restent décodables. Une
    instruction dont l'adresse dépasse la frontière « utile » de la fenêtre
    est reportée : elle sera décodée correctement au début de la fenêtre
    suivante, qui reprend exactement à son adresse (pas à un offset fixe),
    ce qui garantit l'alignement même pour un ISA à taille d'instruction
    variable (x86).
    """
    total = len(code_bytes)
    offset = 0
    while offset < total:
        read_end = min(offset + window_bytes + overlap_bytes, total)
        chunk = code_bytes[offset:read_end]
        soft_limit_addr = base_addr + offset + window_bytes
        reached_soft_limit = False
        for instr in md.disasm(chunk, base_addr + offset):
            if read_end < total and instr.address >= soft_limit_addr:
                offset = instr.address - base_addr
                reached_soft_limit = True
                break
            yield instr
        if reached_soft_limit:
            continue
        if read_end >= total:
            # Fin réelle du buffer atteinte proprement : terminé.
            offset = total
        else:
            # Capstone a arrêté de décoder avant la frontière logicielle
            # (octets non décodables) — même comportement d'arrêt silencieux
            # que l'ancien appel unique sur tout le buffer : ne pas boucler.
            offset = total


def _normalize_capstone_operands(cs_arch: int, instr) -> str:
    """Normalise certains opérandes Capstone vers les adresses attendues.

    Capstone RISC-V expose les cibles PC-relatives comme offsets (`jal 0x1c`)
    alors que CFG/Call Graph attendent des adresses virtuelles (`jal 0xc020`).
    Capstone BPF expose `call imm` avec l'immédiat eBPF relatif en instructions
    de 8 octets ; le CFG attend aussi une adresse virtuelle.
    """
    op_str = str(getattr(instr, "op_str", "") or "")
    if not capstone:
        return op_str
    mnemonic = str(getattr(instr, "mnemonic", "") or "").lower()
    operands = [part.strip() for part in op_str.split(",") if part.strip()]
    if not operands:
        return op_str

    if cs_arch == getattr(capstone, "CS_ARCH_RISCV", None):
        if mnemonic not in _RISCV_PC_RELATIVE_MNEMONICS:
            return op_str
        offset = _parse_capstone_immediate(operands[-1])
        if offset is None:
            return op_str
        operands[-1] = f"0x{int(instr.address) + offset:x}"
        return ", ".join(operands)

    if cs_arch == getattr(capstone, "CS_ARCH_BPF", None) and mnemonic == "call":
        offset = _parse_capstone_immediate(operands[-1])
        if offset is None:
            return op_str
        operands[-1] = f"0x{int(instr.address) + (offset + 1) * 8:x}"
        return ", ".join(operands)

    return op_str


def _parse_base_addr(value: str | int | None) -> int:
    """Parse une adresse de base hexadécimale ou décimale."""
    if value is None or value == "":
        return 0
    if isinstance(value, int):
        return value
    text = str(value).strip()
    if not text:
        return 0
    return int(text, 16) if text.lower().startswith("0x") else int(text, 10)


def _find_code_section(
    binary: lief.Binary, section_name: str | None = None
) -> tuple[bytes, int] | None:
    """Trouve et retourne (code_bytes, base_addr) de la section de code.

    Args:
        binary: Binaire lief
        section_name: Nom de section spécifique (ex: ".text", "__TEXT,__text") ou None pour auto

    Returns:
        (bytes, addr) ou None si non trouvé
    """
    # ELF
    if isinstance(binary, lief.ELF.Binary):
        sections = binary.sections
        if section_name:
            # Chercher section par nom exact
            for sec in sections:
                if sec.name == section_name:
                    return (bytes(sec.content), sec.virtual_address)
        # Auto: .text ou première section exécutable
        for sec in sections:
            if sec.name == ".text":
                return (bytes(sec.content), sec.virtual_address)
        for sec in sections:
            if sec.has(lief.ELF.Section.FLAGS.EXECINSTR):
                return (bytes(sec.content), sec.virtual_address)

    # Mach-O
    elif isinstance(binary, lief.MachO.Binary):
        sections = binary.sections
        if section_name:
            # Format "__TEXT,__text" ou juste "__text"
            target = section_name.split(",")[-1]  # Prendre la partie après la virgule
            for sec in sections:
                if sec.name == target or sec.fullname == section_name:
                    return (bytes(sec.content), sec.virtual_address)
        # Auto: __text ou première section exécutable
        for sec in sections:
            if sec.name == "__text":
                return (bytes(sec.content), sec.virtual_address)
        for seg in binary.segments:
            if seg.name == "__TEXT":
                for sec in seg.sections:
                    if sec.name == "__text":
                        return (bytes(sec.content), sec.virtual_address)

    # PE
    elif isinstance(binary, lief.PE.Binary):
        sections = binary.sections
        if section_name:
            for sec in sections:
                if sec.name == section_name:
                    return (bytes(sec.content), sec.virtual_address)
        # Auto: .text ou première section exécutable
        for sec in sections:
            if sec.name == ".text":
                return (bytes(sec.content), sec.virtual_address)
        for sec in sections:
            if sec.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                return (bytes(sec.content), sec.virtual_address)

    return None


def _resolve_disasm_source(
    binary_path: str,
    *,
    section: str | None = None,
    raw_arch: str | None = None,
    raw_base_addr: str | int | None = None,
    raw_endian: str | None = None,
) -> tuple[bytes, int, int, int] | None:
    """Résout (code_bytes, base_addr, cs_arch, cs_mode) une seule fois.

    Extrait de disassemble_with_capstone/disassemble_raw_blob pour pouvoir
    désassembler la même source plusieurs fois (deux passages fenêtrés) sans
    reparser le binaire à chaque fois.
    """
    if raw_arch:
        if not capstone:
            return None
        if not Path(binary_path).exists():
            raise BinaryNotFoundError(f"Binary not found: {binary_path}")
        arch_mode = _get_raw_arch_mode(raw_arch, raw_endian)
        if not arch_mode:
            raise DisassemblyError(f"Unsupported raw architecture: {raw_arch}")
        try:
            code_bytes = Path(binary_path).read_bytes()
        except OSError as exc:
            raise BinaryParseError(f"Failed to read raw blob: {binary_path}") from exc
        try:
            base_addr = _parse_base_addr(raw_base_addr)
        except ValueError as exc:
            raise DisassemblyError(
                f"Invalid raw base address: {raw_base_addr}"
            ) from exc
        cs_arch, cs_mode = arch_mode
        return code_bytes, base_addr, cs_arch, cs_mode

    if not lief or not capstone:
        return None
    if not Path(binary_path).exists():
        raise BinaryNotFoundError(f"Binary not found: {binary_path}")
    try:
        binary = lief.parse(binary_path)
        if binary is None:
            raise BinaryParseError(f"lief could not parse binary: {binary_path}")
    except (BinaryNotFoundError, BinaryParseError):
        raise
    except Exception as exc:
        raise BinaryParseError(f"Failed to parse binary: {binary_path}") from exc
    arch_mode = _get_arch_mode(binary)
    if not arch_mode:
        raise DisassemblyError(f"Unsupported architecture for: {binary_path}")
    cs_arch, cs_mode = arch_mode
    code_data = _find_code_section(binary, section)
    if not code_data:
        return None
    code_bytes, base_addr = code_data
    return code_bytes, base_addr, cs_arch, cs_mode


def _iter_raw_instruction_dicts(
    md,
    cs_arch: int,
    code_bytes: bytes,
    base_addr: int,
    *,
    progress_callback: Callable[[dict], None] | None = None,
    total_code_bytes: int | None = None,
    progress_message: str = "Désassemblage en cours",
):
    """Désassemble par fenêtres et yield {addr,text,bytes,mnemonic,operands}.

    Partagé par le chemin section-de-code et le chemin blob brut — seule la
    résolution de la source (_resolve_disasm_source) diffère entre les deux.
    """
    total = max(total_code_bytes or len(code_bytes), 1)
    next_report_percent = 15
    for instr in _iter_windowed_instructions(md, code_bytes, base_addr):
        bytes_hex = " ".join(f"{b:02x}" for b in instr.bytes)
        op_str = _normalize_capstone_operands(cs_arch, instr)
        text = f"{bytes_hex:<20} {instr.mnemonic:<8} {op_str}".strip()
        yield {
            "addr": f"0x{instr.address:x}",
            "text": text,
            "bytes": bytes_hex,
            "mnemonic": instr.mnemonic,
            "operands": op_str,
        }
        processed = min(total, max(0, (instr.address - base_addr) + len(instr.bytes)))
        percent = 10 + int((processed / total) * 75)
        if percent >= next_report_percent:
            _emit_progress(
                progress_callback,
                "disasm",
                progress_message,
                current=processed,
                total=total,
                percent=percent,
            )
            next_report_percent = percent + 5


def disassemble_with_capstone(
    binary_path: str,
    syntax: str = "intel",
    section: str | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    raw_arch: str | None = None,
    raw_base_addr: str | int | None = None,
    raw_endian: str | None = None,
) -> list[dict] | None:
    """Désassemble un binaire avec capstone + lief.

    Args:
        binary_path: Chemin vers le binaire
        syntax: "intel" ou "att" (capstone supporte uniquement intel par défaut)
        section: Nom de section optionnel (ex: ".text", "__TEXT,__text")

    Returns:
        Liste de {addr, text, bytes} ou None si échec
    """
    if raw_arch:
        return disassemble_raw_blob(
            binary_path,
            raw_arch=raw_arch,
            raw_base_addr=raw_base_addr,
            raw_endian=raw_endian,
            syntax=syntax,
            progress_callback=progress_callback,
        )

    _emit_progress(progress_callback, "parse", "Lecture du binaire", percent=5)
    resolved = _resolve_disasm_source(binary_path, section=section)
    if resolved is None:
        return None
    code_bytes, base_addr, cs_arch, cs_mode = resolved
    total_code_bytes = max(len(code_bytes), 1)
    _emit_progress(
        progress_callback,
        "prepare",
        "Section de code chargée",
        current=0,
        total=total_code_bytes,
        percent=10,
    )

    try:
        md = capstone.Cs(cs_arch, cs_mode)
        _apply_capstone_syntax(md, cs_arch, syntax)
    except Exception:
        return None

    try:
        lines = list(
            _iter_raw_instruction_dicts(
                md,
                cs_arch,
                code_bytes,
                base_addr,
                progress_callback=progress_callback,
                total_code_bytes=total_code_bytes,
                progress_message="Désassemblage en cours",
            )
        )
    except Exception:
        return None

    _emit_progress(
        progress_callback,
        "disasm",
        f"Désassemblage terminé ({len(lines)} instructions)",
        current=total_code_bytes,
        total=total_code_bytes,
        percent=85,
    )
    return lines


def disassemble_raw_blob(
    binary_path: str,
    *,
    raw_arch: str,
    raw_base_addr: str | int | None = None,
    raw_endian: str | None = None,
    syntax: str = "intel",
    progress_callback: Callable[[dict], None] | None = None,
) -> list[dict] | None:
    """Désassemble un blob brut en utilisant uniquement Capstone."""
    _emit_progress(progress_callback, "parse", "Lecture du blob brut", percent=5)
    resolved = _resolve_disasm_source(
        binary_path,
        raw_arch=raw_arch,
        raw_base_addr=raw_base_addr,
        raw_endian=raw_endian,
    )
    if resolved is None:
        return None
    code_bytes, base_addr, cs_arch, cs_mode = resolved
    total_code_bytes = max(len(code_bytes), 1)
    _emit_progress(
        progress_callback,
        "prepare",
        "Blob brut chargé",
        current=0,
        total=total_code_bytes,
        percent=10,
    )

    try:
        md = capstone.Cs(cs_arch, cs_mode)
        _apply_capstone_syntax(md, cs_arch, syntax)
        md.skipdata = True
    except Exception as exc:
        raise DisassemblyError(
            f"Failed to initialize raw disassembler: {raw_arch}"
        ) from exc

    try:
        lines = list(
            _iter_raw_instruction_dicts(
                md,
                cs_arch,
                code_bytes,
                base_addr,
                progress_callback=progress_callback,
                total_code_bytes=total_code_bytes,
                progress_message="Désassemblage du blob en cours",
            )
        )
    except Exception as exc:
        raise DisassemblyError(f"Raw disassembly failed: {binary_path}") from exc

    _emit_progress(
        progress_callback,
        "disasm",
        f"Désassemblage brut terminé ({len(lines)} instructions)",
        current=total_code_bytes,
        total=total_code_bytes,
        percent=85,
    )
    return lines


def _load_annotation_maps(
    annotations_json_path: str | None,
) -> tuple[dict[int, str], dict[int, str]]:
    """Load {int_addr: name/comment} from annotations JSON. Returns ({}, {}) if absent/invalid."""
    if not annotations_json_path:
        return {}, {}
    try:
        data = json.loads(Path(annotations_json_path).read_text(encoding="utf-8"))
        labels = {}
        comments = {}
        for addr_str, entry in data.items():
            try:
                addr = int(addr_str, 16) if addr_str.startswith("0x") else int(addr_str)
                if isinstance(entry, dict):
                    name = (entry.get("name") or "").strip()
                    comment = (entry.get("comment") or "").strip()
                    if name:
                        labels[addr] = name
                    if comment:
                        comments[addr] = comment
            except (ValueError, AttributeError):
                pass
        return labels, comments
    except Exception:
        return {}, {}


def _merge_annotation_rows(
    rows: list[dict],
    label_map: dict[int, str],
    comment_map: dict[int, str],
    *,
    override: bool = True,
) -> None:
    for entry in rows:
        addr = _addr_to_int(entry.get("addr"))
        if addr is None:
            continue
        value = str(entry.get("value") or "").strip()
        if not value:
            continue
        if entry.get("kind") == "rename":
            if override:
                label_map[addr] = value
            else:
                label_map.setdefault(addr, value)
        elif entry.get("kind") == "comment":
            if override:
                comment_map[addr] = value
            else:
                comment_map.setdefault(addr, value)


def _load_sqlite_annotation_maps(
    binary_path: str,
    annotations_db_path: str | None = "auto",
) -> tuple[dict[int, str], dict[int, str]]:
    if annotations_db_path is None:
        return {}, {}
    try:
        from backends.static.annotations.annotation_db import AnnotationDb

        db_path = None if annotations_db_path in ("", "auto") else annotations_db_path
        with AnnotationDb(db_path) as db:
            rows = db.get_annotations(binary_path)
        labels: dict[int, str] = {}
        comments: dict[int, str] = {}
        _merge_annotation_rows(rows, labels, comments, override=True)
        return labels, comments
    except Exception:
        return {}, {}


def _normalize_for_match(text: str) -> str:
    return re.sub(r"\s+", "", text.lower())


_ARM_MEMORY_BASE_ALIASES: dict[str, str] = {
    "fp": "r11",
}

_REGISTER_LOCATION_ALIASES: dict[str, tuple[str, ...]] = {
    "rax": ("rax", "eax", "ax", "al", "ah"),
    "rbx": ("rbx", "ebx", "bx", "bl", "bh"),
    "rcx": ("rcx", "ecx", "cx", "cl", "ch"),
    "rdx": ("rdx", "edx", "dx", "dl", "dh"),
    "rsi": ("rsi", "esi", "si", "sil"),
    "rdi": ("rdi", "edi", "di", "dil"),
    "r8": ("r8", "r8d", "r8w", "r8b"),
    "r9": ("r9", "r9d", "r9w", "r9b"),
}


def _canonicalize_memory_location(text: str) -> str:
    match = re.search(r"\[([^\]]+)\]", str(text or ""))
    if not match:
        return ""
    inner = re.sub(r"\s+", "", match.group(1).strip().lower())
    if not inner:
        return ""

    arm_match = re.fullmatch(r"([a-z0-9]+)(?:,#?([-+]?(?:0x[0-9a-f]+|\d+)))?", inner)
    if arm_match:
        base = _ARM_MEMORY_BASE_ALIASES.get(arm_match.group(1), arm_match.group(1))
        offset_text = arm_match.group(2)
        if not offset_text:
            return f"[{base}]"
        try:
            offset = (
                int(offset_text, 16) if "0x" in offset_text else int(offset_text, 10)
            )
        except ValueError:
            return ""
        if offset == 0:
            return f"[{base}]"
        sign = "+" if offset > 0 else "-"
        return f"[{base}{sign}0x{abs(offset):x}]"

    x86_match = re.fullmatch(r"([a-z0-9]+)(?:([+-])(0x[0-9a-f]+|\d+))?", inner)
    if x86_match:
        base = x86_match.group(1)
        sign = x86_match.group(2)
        offset_text = x86_match.group(3)
        if not sign or not offset_text:
            return f"[{base}]"
        try:
            offset = (
                int(offset_text, 16)
                if offset_text.startswith("0x")
                else int(offset_text, 10)
            )
        except ValueError:
            return ""
        if sign == "-":
            offset = -offset
        if offset == 0:
            return f"[{base}]"
        sign = "+" if offset > 0 else "-"
        return f"[{base}{sign}0x{abs(offset):x}]"
    return ""


def _extract_canonical_memory_locations(text: str) -> set[str]:
    canonical: set[str] = set()
    for match in re.finditer(r"\[[^\]]+\]", str(text or "")):
        value = _canonicalize_memory_location(match.group(0))
        if value:
            canonical.add(value)
    return canonical


def _location_aliases(location: str) -> tuple[str, ...]:
    normalized = str(location or "").strip().lower()
    if not normalized:
        return ()
    if normalized.startswith("["):
        return (normalized,)
    if normalized in _REGISTER_LOCATION_ALIASES:
        return _REGISTER_LOCATION_ALIASES[normalized]
    if re.fullmatch(r"x\d+", normalized):
        return (normalized, f"w{normalized[1:]}")
    if re.fullmatch(r"w\d+", normalized):
        return (f"x{normalized[1:]}", normalized)
    return (normalized,)


def _location_matches_text(location: str, text: str) -> bool:
    if not location or not text:
        return False
    if location.startswith("["):
        canonical_location = _canonicalize_memory_location(location)
        if canonical_location:
            return canonical_location in _extract_canonical_memory_locations(text)
        return _normalize_for_match(location) in _normalize_for_match(text)
    aliases = _location_aliases(location)
    if not aliases:
        return False
    pattern = re.compile(
        r"\b(?:" + "|".join(re.escape(alias) for alias in aliases) + r")\b",
        re.IGNORECASE,
    )
    return bool(pattern.search(text))


def _build_cfg_attribution(
    lines,
    function_ranges: list[tuple[int, int | None, dict]],
) -> dict[int, str]:
    """Attribue chaque instruction à une fonction par BFS dans le graphe de flot.

    Contrairement à l'attribution linéaire par plage d'adresses, cette méthode
    suit le flux de contrôle réel (sauts, branches) depuis chaque point d'entrée.
    Les instructions non-atteignables tombent en fallback linéaire dans l'appelant.

    `lines` n'est parcouru qu'une seule fois (compatible générateur à usage
    unique, utilisé par le désassemblage streaming) : seul (addr, is_branch,
    is_call, target, is_unconditional) est conservé par instruction, pas le
    dict complet. Suppose `lines` en ordre d'adresse croissant (garanti par
    le désassembleur, fenêtré ou non) — "l'instruction suivante" est donc
    simplement la suivante dans l'itération, sans recherche par bisection.

    Returns: {addr_int -> normalized_func_addr_str}
    """
    from collections import deque

    try:
        from backends.static.disasm.cfg import _get_mnemonic, _is_branch
    except ImportError:
        return {}

    if not function_ranges:
        return {}

    # Un seul passage : ne retient que l'essentiel par instruction (pas le
    # texte/bytes/opérandes formatés déjà présents dans le dict complet).
    addr_sorted: list[int] = []
    raw: list[tuple[int, bool, bool, int | None, bool]] = []
    for line in lines:
        a = _addr_to_int(line.get("addr"))
        if a is None:
            continue
        text = line.get("text", "")
        is_br, is_call, target_str = _is_branch(text)
        target_int = _addr_to_int(target_str) if target_str else None
        is_unconditional = _get_mnemonic(text) in {"jmp", "jmpq", "b", "br"}
        addr_sorted.append(a)
        raw.append((a, is_br, is_call, target_int, is_unconditional))

    addr_set = set(addr_sorted)

    # Successor map: addr_int -> [next reachable addr_int] (calls not followed)
    successors: dict[int, list[int]] = {}
    for idx, (a, is_br, is_call, target_int, is_unconditional) in enumerate(raw):
        next_a = raw[idx + 1][0] if idx + 1 < len(raw) else None
        succs: list[int] = []
        if not is_br or is_call:
            if next_a is not None:
                succs.append(next_a)
        else:
            if target_int is not None and target_int in addr_set:
                succs.append(target_int)
            if not is_unconditional and target_int is not None and next_a is not None:
                succs.append(next_a)
        successors[a] = succs

    # Entry map: addr_int -> normalized_addr_str
    entry_map: dict[int, str] = {}
    for _, _, fn in function_ranges:
        e = _addr_to_int(fn.get("addr"))
        if e is not None and e in addr_set:
            entry_map[e] = _normalize_addr(fn.get("addr", ""))

    if not entry_map:
        return {}

    # Pre-mark all entry points so cross-function jumps (tail calls) stop BFS
    attribution: dict[int, str] = {e: s for e, s in entry_map.items()}

    # BFS in ascending address order so earlier functions are claimed first
    for entry_int, entry_str in sorted(entry_map.items()):
        queue: deque[int] = deque([entry_int])
        seen: set[int] = {entry_int}
        while queue:
            curr = queue.popleft()
            owner = attribution.get(curr)
            if owner is not None and owner != entry_str:
                continue
            attribution[curr] = entry_str
            for succ in successors.get(curr, []):
                if succ in seen:
                    continue
                if succ in entry_map and entry_map[succ] != entry_str:
                    continue  # tail call → stop
                succ_owner = attribution.get(succ)
                if succ_owner is not None and succ_owner != entry_str:
                    continue  # already claimed by another function
                seen.add(succ)
                queue.append(succ)

    return attribution


def _build_function_ranges(functions: list[dict]) -> list[tuple[int, int | None, dict]]:
    starts = []
    for fn in functions:
        start = _addr_to_int(fn.get("addr"))
        if start is None:
            continue
        starts.append((start, fn))
    starts.sort(key=lambda item: item[0])

    ranges: list[tuple[int, int | None, dict]] = []
    for idx, (start, fn) in enumerate(starts):
        next_start = starts[idx + 1][0] if idx + 1 < len(starts) else None
        size = _addr_to_int(fn.get("size"))
        end = start + size if size and size > 0 else None
        if next_start is not None:
            end = min(end, next_start) if end is not None else next_start
        ranges.append((start, end, fn))
    return ranges


def _find_function_context(
    function_ranges: list[tuple[int, int | None, dict]], addr_int: int | None
) -> dict | None:
    if addr_int is None:
        return None
    for start, end, fn in function_ranges:
        if addr_int < start:
            break
        if end is None or addr_int < end:
            return fn
    return None


def _extract_stack_hints_from_frame(op_str: str, frame: dict | None) -> list[dict]:
    if not frame:
        return []
    hints = []
    seen: set[tuple[str, str, str]] = set()
    for kind_name, kind_label in (("args", "arg"), ("vars", "var")):
        for entry in frame.get(kind_name, []) or []:
            location = str(entry.get("location") or "").strip()
            name = str(entry.get("name") or "").strip()
            if not location or not name:
                continue
            if not _location_matches_text(location, op_str):
                continue
            key = (kind_label, location, name)
            if key in seen:
                continue
            seen.add(key)
            hints.append(
                {
                    "kind": kind_label,
                    "name": name,
                    "location": location,
                }
            )
    return hints


def _extract_typed_struct_hints(
    text: str, typed_struct_index: dict[str, object] | None
) -> list[dict]:
    addresses = [
        _normalize_addr(match.group(0))
        for match in re.finditer(r"0x[0-9a-fA-F]+", str(text or ""))
    ]
    return collect_typed_struct_hints(typed_struct_index, addresses)


def _comment_suffix(parts: list[str]) -> str:
    clean = [part.strip() for part in parts if part and str(part).strip()]
    return f"  ; {' | '.join(clean)}" if clean else ""


def _load_disasm_context(
    binary_path: str,
    annotations_json_path: str | None = None,
    cache_db_path: str | None = None,
    annotations_db_path: str | None = "auto",
    *,
    raw_mode: bool = False,
) -> dict:
    label_map, comment_map = _load_annotation_maps(annotations_json_path)
    functions: list[dict] = []
    stack_frames: dict[str, dict] = {}
    typed_struct_index = build_typed_struct_index(binary_path)

    resolved_cache = cache_db_path
    if resolved_cache == "auto":
        from backends.static.cache.cache import default_cache_path

        resolved_cache = default_cache_path(binary_path)
    if not resolved_cache:
        from backends.static.cache.cache import default_cache_path

        candidate = default_cache_path(binary_path)
        resolved_cache = candidate if os.path.exists(candidate) else None

    if resolved_cache and os.path.exists(resolved_cache):
        try:
            from backends.static.cache.cache import DisasmCache

            with DisasmCache(resolved_cache) as cache:
                cached_functions = cache.get_functions(binary_path) or []
                cached_symbols = cache.get_symbols(binary_path) or []
                cached_annotations = cache.get_annotations(binary_path) or []
                functions = [
                    fn
                    for fn in cached_functions
                    if not _is_generic_macho_header_symbol(fn.get("name"))
                ]
                for symbol in cached_symbols:
                    if symbol.get("type") not in {"T", "t"}:
                        continue
                    addr = _addr_to_int(symbol.get("addr"))
                    name = str(symbol.get("name") or "").strip()
                    if _is_generic_macho_header_symbol(name):
                        continue
                    if addr is None or not name:
                        continue
                    label_map.setdefault(addr, name)
                _merge_annotation_rows(
                    cached_annotations,
                    label_map,
                    comment_map,
                    override=False,
                )
                for fn in functions:
                    func_addr = str(fn.get("addr") or "")
                    if not func_addr:
                        continue
                    frame = cache.get_stack_frame(binary_path, func_addr)
                    if frame:
                        stack_frames[_normalize_addr(func_addr)] = frame
        except Exception:
            functions = []
            stack_frames = {}

    sqlite_labels, sqlite_comments = _load_sqlite_annotation_maps(
        binary_path,
        annotations_db_path,
    )
    label_map.update(sqlite_labels)
    comment_map.update(sqlite_comments)

    if not raw_mode and not functions:
        for symbol in extract_symbols(binary_path):
            if symbol.get("type") not in {"T", "t"}:
                continue
            addr = _addr_to_int(symbol.get("addr"))
            name = str(symbol.get("name") or "").strip()
            if _is_generic_macho_header_symbol(name):
                continue
            if addr is None or not name:
                continue
            label_map.setdefault(addr, name)
            functions.append(
                {
                    "addr": symbol.get("addr"),
                    "name": name,
                    "size": symbol.get("size"),
                    "reason": "symbol",
                }
            )

    function_ranges = _build_function_ranges(functions)
    return {
        "label_map": label_map,
        "comment_map": comment_map,
        "function_ranges": function_ranges,
        "stack_frames": stack_frames,
        "typed_struct_index": typed_struct_index,
    }


def _augment_context_with_discovered_functions(
    context: dict,
    lines: list[dict],
    binary_path: str,
    *,
    raw_mode: bool = False,
) -> dict:
    if raw_mode or context.get("function_ranges") or not lines:
        return context
    try:
        from backends.static.disasm.discover_functions import discover_functions

        known_addrs: set[str] = set()
        for symbol in extract_symbols(binary_path):
            if symbol.get("type") not in {"T", "t"}:
                continue
            name = str(symbol.get("name") or "").strip()
            if _is_generic_macho_header_symbol(name):
                continue
            addr = str(symbol.get("addr") or "").strip()
            if addr:
                known_addrs.add(addr if addr.startswith("0x") else f"0x{addr}")
        discovered = discover_functions(
            lines,
            known_addrs,
            binary_path=binary_path,
        )
    except Exception:
        return context
    if not discovered:
        return context
    context = dict(context)
    label_map = dict(context.get("label_map") or {})
    for fn in discovered:
        addr = _addr_to_int(fn.get("addr"))
        name = str(fn.get("name") or "").strip()
        if addr is not None and name and not _is_generic_macho_header_symbol(name):
            label_map.setdefault(addr, name)
    context["label_map"] = label_map
    context["function_ranges"] = _build_function_ranges(discovered)
    return context


_X86_BRANCH_MNEMONICS = {
    "call",
    "jmp",
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "jo",
    "jno",
    "js",
    "jns",
    "jp",
    "jnp",
    "jcxz",
    "jecxz",
    "jrcxz",
    "loop",
    "loope",
    "loopz",
    "loopne",
    "loopnz",
    "jpe",
    "jpo",
}


def _label_target_mnemonics() -> set[str]:
    mnemonics = set(_X86_BRANCH_MNEMONICS)
    for adapter in iter_supported_adapters():
        mnemonics.update(adapter.call_mnemonics)
        mnemonics.update(adapter.unconditional_jump_mnemonics)
        mnemonics.update(adapter.conditional_branch_mnemonics)
        mnemonics.update(adapter.return_mnemonics)
    return mnemonics


_BRANCH_MNEMONICS = _label_target_mnemonics()


def _apply_labels(
    lines: list[dict],
    label_map: dict[int, str],
    line_map: dict | None = None,
    *,
    comment_map: dict[int, str] | None = None,
    function_ranges: list[tuple[int, int | None, dict]] | None = None,
    stack_frames: dict[str, dict] | None = None,
    typed_struct_index: dict[str, object] | None = None,
) -> list[str]:
    """Return formatted ASM lines with function context, labels, comments and optional DWARF info."""
    output = []
    prev_src: tuple[str, int] | None = (
        None  # (file, line) of the last emitted source comment
    )
    comment_map = comment_map or {}
    function_ranges = function_ranges or []
    stack_frames = stack_frames or {}
    emitted_function_banners: set[int] = set()
    for line in lines:
        try:
            addr_int = int(line["addr"], 16)
        except (ValueError, KeyError):
            addr_int = None

        current_function = _find_function_context(function_ranges, addr_int)
        if (
            current_function is not None
            and addr_int is not None
            and _addr_to_int(current_function.get("addr")) == addr_int
            and addr_int not in emitted_function_banners
        ):
            emitted_function_banners.add(addr_int)
            function_name = str(
                current_function.get("name") or label_map.get(addr_int) or line["addr"]
            )
            output.append("")
            output.append(f"; ===== Function {function_name} @ {line['addr']} =====")

        is_function_start = (
            current_function is not None
            and addr_int is not None
            and _addr_to_int(current_function.get("addr")) == addr_int
        )

        # Insert label header before this address if it has a name.
        # Function-start renames and instruction annotations are intentionally
        # marked differently so the text disassembly stays easy to scan.
        if addr_int is not None and addr_int in label_map:
            label_kind = "function rename" if is_function_start else "annotation label"
            output.append(f"; -- {label_kind} @ {line['addr']} --")
            output.append(f"{label_map[addr_int]}:")

        text = line["text"]
        mnemonic = line.get("mnemonic", "").lower()
        op_str = line.get("operands", "")

        # Replace numeric operand with label name for branch/call instructions
        if mnemonic in _BRANCH_MNEMONICS and op_str and label_map:
            token = op_str.strip()
            try:
                target = int(token, 16)
                if target in label_map:
                    text = text.replace(token, label_map[target])
            except ValueError:
                pass  # Not a plain address (e.g. [rax], register)

        comment_parts: list[str] = []
        if addr_int is not None and addr_int in comment_map:
            comment_parts.append(comment_map[addr_int])

        if current_function is not None:
            func_addr = _normalize_addr(current_function.get("addr", ""))
            stack_hints = _extract_stack_hints_from_frame(
                op_str, stack_frames.get(func_addr)
            )
            if stack_hints:
                hint_str = ", ".join(
                    f"{hint['kind']} {hint['name']} @ {hint['location']}"
                    for hint in stack_hints
                )
                comment_parts.append(hint_str)
        typed_struct_hints = _extract_typed_struct_hints(text, typed_struct_index)
        if typed_struct_hints:
            typed_hint_str = ", ".join(
                str(hint.get("label") or hint.get("addr") or "").strip()
                for hint in typed_struct_hints[:2]
                if str(hint.get("label") or hint.get("addr") or "").strip()
            )
            if typed_hint_str:
                if len(typed_struct_hints) > 2:
                    typed_hint_str += f", +{len(typed_struct_hints) - 2}"
                comment_parts.append(f"struct {typed_hint_str}")

        # Append DWARF source comment when file:line changes
        if line_map is not None and addr_int is not None and addr_int in line_map:
            src = line_map[addr_int]
            cur = (src["file"], src["line"])
            if cur != prev_src:
                comment_parts.insert(0, f"{src['file']}:{src['line']}")
                prev_src = cur

        output.append(f"  {line['addr']}:  {text}{_comment_suffix(comment_parts)}")
    return output


def _write_disasm_outputs(
    lines: list[dict],
    binary_path: str,
    output_asm: str,
    output_mapping: str | None,
    *,
    label_map: dict[int, str] | None = None,
    comment_map: dict[int, str] | None = None,
    function_ranges: list[tuple[int, int | None, dict]] | None = None,
    stack_frames: dict[str, dict] | None = None,
    typed_struct_index: dict[str, object] | None = None,
    line_map: dict | None = None,
    progress_callback: Callable[[dict], None] | None = None,
    raw_profile: dict | None = None,
) -> dict:
    """Écrit le .asm et le mapping JSON à partir de lignes déjà désassemblées."""
    label_map = label_map or {}
    comment_map = comment_map or {}
    function_ranges = function_ranges or []
    stack_frames = stack_frames or {}

    _emit_progress(
        progress_callback, "format", "Formatage du désassemblage", percent=90
    )
    if (
        label_map
        or comment_map
        or function_ranges
        or stack_frames
        or line_map
        or typed_struct_index
    ):
        asm_output = _apply_labels(
            lines,
            label_map,
            line_map,
            comment_map=comment_map,
            function_ranges=function_ranges,
            stack_frames=stack_frames,
            typed_struct_index=typed_struct_index,
        )
    else:
        asm_output = [f"  {line['addr']}:  {line['text']}" for line in lines]

    _emit_progress(progress_callback, "write", "Écriture du fichier ASM", percent=95)
    with open(output_asm, "w", encoding="utf-8") as f:
        f.write("\n".join(asm_output))

    # CFG-based function attribution (more accurate than linear address ranges)
    cfg_attribution = _build_cfg_attribution(lines, function_ranges)
    entry_addr_to_fn: dict[str, dict] = {
        _normalize_addr(fn.get("addr", "")): fn for _, _, fn in function_ranges
    }

    def _resolve_function(addr_int: int | None) -> dict | None:
        if addr_int is None:
            return None
        cfg_addr = cfg_attribution.get(addr_int)
        if cfg_addr:
            fn = entry_addr_to_fn.get(cfg_addr)
            if fn is not None:
                return fn
        return _find_function_context(function_ranges, addr_int)

    lines_with_line_num = []
    # Toujours résoudre les numéros de ligne physiques depuis la sortie ASM :
    # les bannières de fonctions et labels insèrent des lignes même quand
    # label_map est vide, et le patch in-place des annotations (host) dépend
    # de l'exactitude de mapping.line.
    addr_to_line: dict[str, int] = {}
    for physical_lineno, out_line in enumerate(asm_output, start=1):
        stripped = out_line.strip()
        if stripped.startswith("0x") and ":" in stripped:
            addr = stripped.split(":")[0].strip()
            if addr not in addr_to_line:
                addr_to_line[addr] = physical_lineno
    for line in lines:
        addr_int = _addr_to_int(line.get("addr"))
        current_function = _resolve_function(addr_int)
        function_addr = (
            _normalize_addr(current_function.get("addr", ""))
            if current_function
            else ""
        )
        function_name = ""
        if current_function:
            function_name = str(
                current_function.get("name") or label_map.get(addr_int or -1) or ""
            ).strip()
        stack_hints = _extract_stack_hints_from_frame(
            line.get("operands", ""),
            stack_frames.get(function_addr) if function_addr else None,
        )
        typed_struct_hints = _extract_typed_struct_hints(
            line.get("text", ""), typed_struct_index
        )
        lines_with_line_num.append(
            {
                "addr": line["addr"],
                "text": line["text"],
                "line": addr_to_line.get(line["addr"], 0),
                "bytes": line.get("bytes", ""),
                "mnemonic": line.get("mnemonic", ""),
                "operands": line.get("operands", ""),
                "label": label_map.get(addr_int) if addr_int is not None else None,
                "comment": comment_map.get(addr_int) if addr_int is not None else None,
                "function_addr": function_addr or None,
                "function_name": function_name or None,
                "stack_hints": stack_hints,
                "typed_struct_hints": typed_struct_hints,
            }
        )

    mapping = {
        "meta": make_meta("disasm"),
        "path": output_asm,
        "binary": binary_path,
        "lines": lines_with_line_num,
        "functions": [
            {
                "addr": fn.get("addr"),
                "name": fn.get("name"),
                "size": fn.get("size"),
                "reason": fn.get("reason"),
            }
            for _, _, fn in function_ranges
        ],
    }
    arch_payload = _resolve_arch_payload(
        binary_path,
        raw_arch=raw_profile.get("arch") if raw_profile else None,
        raw_endian=raw_profile.get("endian") if raw_profile else None,
    )
    if arch_payload:
        mapping["arch"] = arch_payload
    if raw_profile:
        mapping["raw"] = raw_profile
    if output_mapping:
        _emit_progress(progress_callback, "write", "Écriture du mapping", percent=98)
        # Les lignes (une par instruction) vont dans un SQLite requêtable par
        # adresse ; le JSON ne garde qu'un en-tête borné par le nombre de
        # fonctions — jamais de JSON à un enregistrement par instruction.
        db_path = mapping_db.mapping_db_path_for(output_mapping)
        mapping_db.write_mapping_db(db_path, mapping)
        function_addr_keys = {
            mapping_db.normalize_addr_key(fn.get("addr")) for fn in mapping["functions"]
        }
        function_addr_keys.discard("")
        for entry in lines_with_line_num:
            addr_key = mapping_db.normalize_addr_key(entry.get("addr"))
            fn_key = mapping_db.normalize_addr_key(entry.get("function_addr"))
            if addr_key and fn_key and addr_key == fn_key:
                function_addr_keys.add(addr_key)
        slim = {key: value for key, value in mapping.items() if key != "lines"}
        slim["function_addrs"] = sorted(function_addr_keys, key=lambda a: int(a, 16))
        slim["line_count"] = len(lines_with_line_num)
        slim["lines_db"] = os.path.basename(db_path)
        with open(output_mapping, "w", encoding="utf-8") as f:
            json.dump(slim, f, indent=2)

    _emit_progress(progress_callback, "done", "Désassemblage prêt", percent=100)
    return mapping


def disassemble(
    binary_path: str,
    output_asm: str,
    output_mapping: str | None = None,
    syntax: str = "intel",
    section: str | None = None,
    arch: str | None = None,  # Gardé pour compatibilité, ignoré (lief auto-détecte)
    raw_arch: str | None = None,
    raw_base_addr: str | None = None,
    raw_endian: str | None = None,
    annotations_json: str | None = None,
    annotations_db: str | None = "auto",
    dwarf_lines: bool = False,
    cache_db_path: str | None = None,
    progress_callback: Callable[[dict], None] | None = None,
) -> dict | None:
    """Désassemble un binaire, écrit le .asm et optionnellement un JSON de mapping.

    Args:
        binary_path: Chemin vers le binaire (ELF, Mach-O, PE)
        output_asm: Chemin de sortie pour le fichier .asm
        output_mapping: Chemin de sortie JSON optionnel pour le mapping addr->line
        syntax: "intel" ou "att" (capstone supporte intel)
        section: Nom de section optionnel (ex: ".text")
        arch: Ignoré (lief auto-détecte), gardé pour compatibilité API

    Returns:
        {"path": str, "lines": list[dict]} ou None si échec
    """
    # Désassembler avec capstone + lief
    try:
        lines = disassemble_with_capstone(
            binary_path,
            syntax=syntax,
            section=section,
            progress_callback=progress_callback,
            raw_arch=raw_arch,
            raw_base_addr=raw_base_addr,
            raw_endian=raw_endian,
        )
    except (BinaryNotFoundError, BinaryParseError, DisassemblyError):
        raise
    except Exception as exc:
        raise DisassemblyError(f"Unexpected disassembly error: {binary_path}") from exc

    if lines is None:
        return None

    # Charger le mapping DWARF ligne → source si demandé
    line_map: dict | None = None
    if dwarf_lines and not raw_arch:
        from backends.static.binary.dwarf import extract_line_mapping

        _emit_progress(
            progress_callback, "dwarf", "Chargement des lignes DWARF", percent=88
        )
        line_map = extract_line_mapping(binary_path) or None

    context = _load_disasm_context(
        binary_path,
        annotations_json_path=annotations_json,
        cache_db_path=cache_db_path,
        annotations_db_path=annotations_db,
        raw_mode=bool(raw_arch),
    )
    context = _augment_context_with_discovered_functions(
        context,
        lines,
        binary_path,
        raw_mode=bool(raw_arch),
    )
    raw_info = get_raw_arch_info(raw_arch, raw_endian) if raw_arch else None
    return _write_disasm_outputs(
        lines,
        binary_path,
        output_asm,
        output_mapping,
        label_map=context["label_map"],
        comment_map=context["comment_map"],
        function_ranges=context["function_ranges"],
        stack_frames=context["stack_frames"],
        typed_struct_index=context["typed_struct_index"],
        line_map=line_map,
        progress_callback=progress_callback,
        raw_profile={
            "arch": raw_info.raw_name if raw_info else raw_arch,
            "base_addr": raw_base_addr or "0x0",
            "endian": raw_info.endian if raw_info else (raw_endian or "little"),
        }
        if raw_arch
        else None,
    )


def main() -> int:
    """Point d'entrée CLI : désassemble un binaire et écrit le .asm + mapping JSON."""
    parser = argparse.ArgumentParser(description="Static disassembly (Capstone + LIEF)")
    parser.add_argument("--binary", required=True, help="Binary path (ELF, Mach-O, PE)")
    parser.add_argument("--output", required=True, help="Output .asm path")
    parser.add_argument(
        "--output-mapping", help="Output JSON mapping addr->line (for navigation)"
    )
    parser.add_argument(
        "--syntax",
        default="intel",
        choices=["intel", "att"],
        help="Syntax: intel (att not supported by capstone)",
    )
    parser.add_argument(
        "--section", help="Section to disassemble (e.g. .text, __TEXT,__text)"
    )
    parser.add_argument("--arch", help="Architecture (ignored, auto-detected by lief)")
    parser.add_argument(
        "--raw-arch",
        help="Disassemble input as raw blob using a Capstone architecture profile (e.g. i386, i386:x86-64, arm, thumb, aarch64, mips32, ppc64, riscv64, wasm)",
    )
    parser.add_argument(
        "--raw-base-addr",
        help="Base virtual address for raw blobs (default: 0x0)",
    )
    parser.add_argument(
        "--raw-endian",
        choices=["little", "big"],
        default="little",
        help="Endianness for raw blobs (default: little)",
    )
    parser.add_argument(
        "--annotations-json",
        help="Path to annotations JSON {addr: {name, comment}} for label injection",
    )
    parser.add_argument(
        "--annotations-db",
        default="auto",
        help="SQLite annotations DB path. Use 'auto' for the default AnnotationStore DB.",
    )
    parser.add_argument(
        "--dwarf-lines",
        action="store_true",
        help="Inject DWARF source line comments (requires ELF with -g debug info)",
    )
    parser.add_argument(
        "--cache-db", help="SQLite cache path (.pfdb). Use 'auto' for default location."
    )
    parser.add_argument(
        "--no-cache", action="store_true", help="Disable cache (always recompute)"
    )
    parser.add_argument(
        "--cache-write-only",
        action="store_true",
        help="Recompute even when cache exists, then save the fresh result to cache.",
    )
    parser.add_argument(
        "--progress",
        action="store_true",
        help="Emit machine-readable progress events on stderr.",
    )
    args = parser.parse_args()

    configure_logging()

    if not args.raw_arch and not lief:
        logger.error("lief not installed. Install with: pip install lief")
        return 1

    if not capstone:
        logger.error("capstone not installed. Install with: pip install capstone")
        return 1

    # --- Cache SQLite (optionnel) ---
    cache_db = getattr(args, "cache_db", None)
    use_cache = (
        not getattr(args, "no_cache", False)
        and cache_db is not None
        and not getattr(args, "raw_arch", None)
    )

    progress_callback = None
    if args.progress:

        def _cli_progress(payload: dict) -> None:
            sys.stderr.write(
                PROGRESS_PREFIX + json.dumps(payload, ensure_ascii=False) + "\n"
            )
            sys.stderr.flush()

        progress_callback = _cli_progress

    if use_cache and cache_db:
        from backends.static.cache.cache import DisasmCache, default_cache_path

        if cache_db == "auto":
            cache_db = default_cache_path(args.binary)
        with DisasmCache(cache_db) as cache:
            hit = (
                None
                if getattr(args, "cache_write_only", False)
                else cache.get_disasm(args.binary)
            )
            if hit is not None:
                _, cached_lines = hit
                logger.debug("Cache hit — skipping disassembly")
                _emit_progress(
                    progress_callback, "cache", "Cache SQLite trouvé", percent=20
                )
                ann_json = getattr(args, "annotations_json", None)
                cached_line_map = None
                if getattr(args, "dwarf_lines", False):
                    from backends.static.binary.dwarf import extract_line_mapping

                    _emit_progress(
                        progress_callback,
                        "dwarf",
                        "Chargement des lignes DWARF",
                        percent=70,
                    )
                    cached_line_map = extract_line_mapping(args.binary) or None
                context = _load_disasm_context(
                    args.binary,
                    annotations_json_path=ann_json,
                    cache_db_path=cache_db,
                    annotations_db_path=getattr(args, "annotations_db", "auto"),
                )
                _write_disasm_outputs(
                    cached_lines,
                    args.binary,
                    args.output,
                    getattr(args, "output_mapping", None),
                    label_map=context["label_map"],
                    comment_map=context["comment_map"],
                    function_ranges=context["function_ranges"],
                    stack_frames=context["stack_frames"],
                    typed_struct_index=context["typed_struct_index"],
                    line_map=cached_line_map,
                    progress_callback=progress_callback,
                )
                print(
                    f"Disassembly written to {args.output} ({len(cached_lines)} instructions) [cached]"
                )
                return 0
            # Cache miss → désassembler et sauvegarder
            result = disassemble(
                args.binary,
                args.output,
                getattr(args, "output_mapping", None),
                syntax=args.syntax,
                section=args.section or None,
                raw_arch=getattr(args, "raw_arch", None),
                raw_base_addr=getattr(args, "raw_base_addr", None),
                raw_endian=getattr(args, "raw_endian", None),
                annotations_json=getattr(args, "annotations_json", None),
                annotations_db=getattr(args, "annotations_db", "auto"),
                dwarf_lines=getattr(args, "dwarf_lines", False),
                cache_db_path=cache_db,
                progress_callback=progress_callback,
            )
            if result is None:
                logger.error("Disassembly failed.")
                return 1
            cache.save_disasm(args.binary, result["lines"])
            _emit_progress(
                progress_callback,
                "cache",
                "Résultat enregistré dans le cache SQLite",
                percent=100,
            )
            print(
                f"Disassembly written to {args.output} ({len(result['lines'])} instructions) [cached]"
            )
            return 0

    try:
        result = disassemble(
            args.binary,
            args.output,
            getattr(args, "output_mapping", None),
            syntax=args.syntax,
            section=args.section or None,
            raw_arch=getattr(args, "raw_arch", None),
            raw_base_addr=getattr(args, "raw_base_addr", None),
            raw_endian=getattr(args, "raw_endian", None),
            annotations_json=getattr(args, "annotations_json", None),
            annotations_db=getattr(args, "annotations_db", "auto"),
            dwarf_lines=getattr(args, "dwarf_lines", False),
            cache_db_path=cache_db,
            progress_callback=progress_callback,
        )
    except (BinaryNotFoundError, BinaryParseError, DisassemblyError) as exc:
        logger.error("%s", exc)
        return 1

    if result is None:
        logger.error(
            "Disassembly failed. Check binary format and architecture support."
        )
        return 1

    print(f"Disassembly written to {args.output} ({len(result['lines'])} instructions)")
    if getattr(args, "output_mapping", None):
        print(f"Mapping written to {args.output_mapping}")
    return 0


if __name__ == "__main__":
    import sys

    sys.exit(main())
