# SPDX-License-Identifier: AGPL-3.0-only
"""Patch en place de l'overlay d'annotations dans le .asm généré.

Un changement de commentaire ne modifie qu'un suffixe de fin de ligne : ce
module localise la ligne via le mapping SQLite (`*.disasm.mapping.db`),
reconstruit le suffixe `; [src dwarf | ]commentaire[ | hints pile][ | hints
struct]` et réécrit le fichier .asm en streaming (ligne à ligne, temp +
os.replace) sans jamais le charger entièrement en mémoire.

Les renames exigent toujours un rebuild complet (insertion de lignes de
label, réécriture des opérandes de branchement).

Les règles de formatage du suffixe sont un miroir de disasm.py
(_comment_suffix / _apply_labels) — dupliquées ici pour ne pas payer
l'import de capstone/lief dans le spawn annotations. Toute divergence est
détectée par la vérification de la ligne existante et retombe sur
'rebuild-required'.
"""

from __future__ import annotations

import os
import tempfile

from backends.static.disasm import mapping_db

VERDICT_UNCHANGED = "unchanged"
VERDICT_PATCHED = "patched"
VERDICT_REBUILD = "rebuild-required"


def asm_path_for(mapping_json_path: str) -> str:
    if mapping_json_path.endswith(".disasm.mapping.json"):
        return mapping_json_path[: -len(".disasm.mapping.json")] + ".disasm.asm"
    if mapping_json_path.endswith(".mapping.json"):
        return mapping_json_path[: -len(".mapping.json")] + ".asm"
    return ""


def _stack_hints_part(stack_hints: list | None) -> str:
    hints = stack_hints or []
    if not hints:
        return ""
    return ", ".join(
        f"{hint.get('kind')} {hint.get('name')} @ {hint.get('location')}"
        for hint in hints
    )


def _typed_struct_part(typed_hints: list | None) -> str:
    hints = typed_hints or []
    labels = [
        str(hint.get("label") or hint.get("addr") or "").strip() for hint in hints[:2]
    ]
    labels = [label for label in labels if label]
    if not labels:
        return ""
    text = ", ".join(labels)
    if len(hints) > 2:
        text += f", +{len(hints) - 2}"
    return f"struct {text}"


def _comment_suffix(parts: list[str]) -> str:
    clean = [str(part or "").strip() for part in parts]
    clean = [part for part in clean if part]
    return f"  ; {' | '.join(clean)}" if clean else ""


def _split_asm_line(
    line: str, old_comment: str, stack_part: str, struct_part: str
) -> tuple[str, str] | None:
    """Sépare (instruction, src dwarf capturé) en validant le suffixe attendu."""
    tail_parts = [p for p in (old_comment, stack_part, struct_part) if p]
    tail_joined = " | ".join(tail_parts)
    if tail_joined:
        no_src_suffix = f"  ; {tail_joined}"
        if line.endswith(no_src_suffix):
            return line[: -len(no_src_suffix)], ""
        with_src_tail = f" | {tail_joined}"
        if line.endswith(with_src_tail):
            rest = line[: -len(with_src_tail)]
            marker = rest.rfind("  ; ")
            if marker > 0:
                src = rest[marker + 4 :]
                if src and " | " not in src:
                    return rest[:marker], src
        return None
    marker = line.find("  ; ")
    if marker == -1:
        return line, ""
    src = line[marker + 4 :]
    if src and " | " not in src:
        return line[:marker], src
    return None


def _rewrite_asm_lines(asm_path: str, replacements: dict[int, str]) -> None:
    """Réécrit les lignes (1-indexées) du .asm en streaming, atomiquement."""
    dir_name = os.path.dirname(asm_path) or "."
    fd, tmp_path = tempfile.mkstemp(prefix=".overlay-patch-", dir=dir_name)
    try:
        with (
            os.fdopen(fd, "w", encoding="utf-8", newline="") as out,
            open(asm_path, encoding="utf-8", newline="") as src,
        ):
            for lineno, raw in enumerate(src, start=1):
                if lineno in replacements:
                    newline = "\n" if raw.endswith("\n") else ""
                    out.write(replacements[lineno] + newline)
                else:
                    out.write(raw)
        os.replace(tmp_path, asm_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def apply_overlay_mutation(
    mapping_json_path: str,
    addr: str,
    *,
    name: str | None = None,
    comment: str | None = None,
    deleted: bool = False,
) -> str:
    """Classifie une mutation et patche le .asm si seul un commentaire change.

    `name`/`comment` à None signifient « champ non modifié » ; une chaîne
    vide signifie « effacé » (disasm.py ignore les valeurs vides au bake).
    """
    db_path = mapping_db.mapping_db_path_for(mapping_json_path)
    asm_path = asm_path_for(mapping_json_path)
    if not asm_path or not os.path.exists(db_path) or not os.path.exists(asm_path):
        # Pas d'artefacts : rien de périmé, le prochain build bakera l'état frais.
        return VERDICT_UNCHANGED

    try:
        entries = mapping_db.query_lines_by_addr(db_path, addr)
    except Exception:
        return VERDICT_REBUILD
    if not entries:
        # Adresse hors du désassemblage courant (autre section, données…).
        return VERDICT_UNCHANGED

    baked_label = str(entries[0].get("label") or "").strip()
    baked_comment = str(entries[0].get("comment") or "").strip()

    if deleted:
        target_name = ""
        target_comment = ""
    else:
        target_name = baked_label if name is None else str(name).strip()
        target_comment = baked_comment if comment is None else str(comment).strip()

    try:
        original_fn_name = mapping_db.query_function_name(db_path, addr)
    except Exception:
        return VERDICT_REBUILD

    # Après rebuild, le label serait le rename utilisateur s'il existe, sinon
    # le nom de fonction d'origine (seedé dans label_map par disasm.py).
    label_after = target_name or original_fn_name
    if label_after != baked_label:
        return VERDICT_REBUILD
    if target_comment == baked_comment:
        return VERDICT_UNCHANGED

    replacements: dict[int, str] = {}
    try:
        with open(asm_path, encoding="utf-8") as src:
            asm_line_cache: dict[int, str] = {}
            wanted = {
                int(entry.get("line") or 0)
                for entry in entries
                if int(entry.get("line") or 0) > 0
            }
            if not wanted or len(wanted) != len(entries):
                return VERDICT_REBUILD
            for lineno, raw in enumerate(src, start=1):
                if lineno in wanted:
                    asm_line_cache[lineno] = raw.rstrip("\n")
        if len(asm_line_cache) != len(wanted):
            return VERDICT_REBUILD
    except OSError:
        return VERDICT_REBUILD

    for entry in entries:
        lineno = int(entry.get("line") or 0)
        line = asm_line_cache[lineno]
        if not line.startswith(f"  {entry.get('addr')}:  "):
            return VERDICT_REBUILD
        stack_part = _stack_hints_part(entry.get("stack_hints"))
        struct_part = _typed_struct_part(entry.get("typed_struct_hints"))
        split = _split_asm_line(line, baked_comment, stack_part, struct_part)
        if split is None:
            return VERDICT_REBUILD
        instr, src_part = split
        replacements[lineno] = instr + _comment_suffix(
            [src_part, target_comment, stack_part, struct_part]
        )

    try:
        _rewrite_asm_lines(asm_path, replacements)
        mapping_db.update_line_comments(db_path, addr, target_comment or None)
    except Exception:
        return VERDICT_REBUILD
    return VERDICT_PATCHED
