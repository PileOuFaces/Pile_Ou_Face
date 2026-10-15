# SPDX-License-Identifier: AGPL-3.0-only
"""Mapping désassemblage en SQLite.

Le mapping adresse ↔ ligne contient un enregistrement par instruction : en
JSON il atteint des centaines de Mo sur un vrai binaire et chaque parse
complet côté extension host est un risque d'OOM. Ce module stocke les lignes
dans un fichier SQLite (`*.disasm.mapping.db`) requêtable par adresse, le
JSON `*.disasm.mapping.json` ne conservant qu'un en-tête borné (méta, arch,
fonctions, function_addrs).

Écriture atomique : fichier temporaire puis os.replace.
"""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterable

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE functions (addr TEXT, name TEXT, size INTEGER, reason TEXT);
CREATE TABLE lines (
    seq INTEGER PRIMARY KEY,
    addr TEXT,
    addr_int INTEGER,
    line INTEGER,
    text TEXT,
    bytes TEXT,
    mnemonic TEXT,
    operands TEXT,
    label TEXT,
    comment TEXT,
    function_addr TEXT,
    function_name TEXT,
    stack_hints TEXT,
    typed_struct_hints TEXT
);
CREATE INDEX idx_lines_addr ON lines (addr);
CREATE INDEX idx_lines_addr_int ON lines (addr_int);
"""

_INSERT_LINE = "INSERT INTO lines VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"

_BATCH_SIZE = 5000


def mapping_db_path_for(mapping_json_path: str) -> str:
    """`X.disasm.mapping.json` → `X.disasm.mapping.db` (idem pour .mapping.json)."""
    if mapping_json_path.endswith(".json"):
        return mapping_json_path[: -len(".json")] + ".db"
    return mapping_json_path + ".db"


def normalize_addr_key(value: str | None) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    raw = text[2:] if text.startswith("0x") else text
    try:
        return f"0x{int(raw, 16):x}"
    except ValueError:
        return text


def _addr_int_or_none(key: str) -> int | None:
    try:
        return int(key, 16)
    except (TypeError, ValueError):
        return None


def _line_row(seq: int, entry: dict) -> tuple:
    addr_key = normalize_addr_key(entry.get("addr"))
    return (
        seq,
        addr_key,
        _addr_int_or_none(addr_key),
        int(entry.get("line") or 0),
        entry.get("text") or "",
        entry.get("bytes") or "",
        entry.get("mnemonic") or "",
        entry.get("operands") or "",
        entry.get("label"),
        entry.get("comment"),
        normalize_addr_key(entry.get("function_addr")) or None,
        entry.get("function_name"),
        json.dumps(entry.get("stack_hints") or []),
        json.dumps(entry.get("typed_struct_hints") or []),
    )


def write_mapping_db(db_path: str, mapping: dict) -> None:
    """Écrit le mapping complet (meta + functions + lines) atomiquement."""
    tmp_path = f"{db_path}.tmp-{os.getpid()}"
    if os.path.exists(tmp_path):
        os.remove(tmp_path)
    conn = sqlite3.connect(tmp_path)
    try:
        conn.executescript(_SCHEMA)
        meta_rows = [("schema_version", str(SCHEMA_VERSION))]
        for key in ("path", "binary"):
            if mapping.get(key):
                meta_rows.append((key, str(mapping[key])))
        for key in ("meta", "arch", "raw"):
            if mapping.get(key) is not None:
                meta_rows.append((key, json.dumps(mapping[key])))
        conn.executemany("INSERT INTO meta VALUES (?, ?)", meta_rows)
        conn.executemany(
            "INSERT INTO functions VALUES (?, ?, ?, ?)",
            [
                (
                    normalize_addr_key(fn.get("addr")),
                    fn.get("name"),
                    fn.get("size"),
                    fn.get("reason"),
                )
                for fn in mapping.get("functions") or []
            ],
        )
        lines: Iterable[dict] = mapping.get("lines") or []
        batch: list[tuple] = []
        for seq, entry in enumerate(lines, start=1):
            batch.append(_line_row(seq, entry))
            if len(batch) >= _BATCH_SIZE:
                conn.executemany(_INSERT_LINE, batch)
                batch = []
        if batch:
            conn.executemany(_INSERT_LINE, batch)
        conn.commit()
    finally:
        conn.close()
    os.replace(tmp_path, db_path)


def _row_to_entry(row: sqlite3.Row) -> dict:
    entry = {
        "addr": row["addr"],
        "line": row["line"],
        "text": row["text"],
        "bytes": row["bytes"],
        "mnemonic": row["mnemonic"],
        "operands": row["operands"],
        "label": row["label"],
        "comment": row["comment"],
        "function_addr": row["function_addr"],
        "function_name": row["function_name"],
    }
    for key in ("stack_hints", "typed_struct_hints"):
        try:
            entry[key] = json.loads(row[key] or "[]")
        except (TypeError, ValueError):
            entry[key] = []
    return entry


def _connect_ro(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def read_meta(db_path: str) -> dict:
    conn = _connect_ro(db_path)
    try:
        rows = conn.execute("SELECT key, value FROM meta").fetchall()
    finally:
        conn.close()
    meta: dict = {}
    for row in rows:
        key, value = row["key"], row["value"]
        if key in ("meta", "arch", "raw"):
            try:
                meta[key] = json.loads(value)
            except (TypeError, ValueError):
                continue
        else:
            meta[key] = value
    return meta


def query_lines_by_addr(db_path: str, addr: str) -> list[dict]:
    """Toutes les entrées pour une adresse exacte (normalisée)."""
    key = normalize_addr_key(addr)
    if not key:
        return []
    conn = _connect_ro(db_path)
    try:
        rows = conn.execute(
            "SELECT * FROM lines WHERE addr = ? ORDER BY seq", (key,)
        ).fetchall()
    finally:
        conn.close()
    return [_row_to_entry(row) for row in rows]


def query_entry_at_or_after(db_path: str, addr: str) -> dict | None:
    """Première entrée dont l'adresse est >= addr (navigation)."""
    target = _addr_int_or_none(normalize_addr_key(addr))
    if target is None:
        return None
    conn = _connect_ro(db_path)
    try:
        row = conn.execute(
            "SELECT * FROM lines WHERE addr_int >= ? ORDER BY addr_int, seq LIMIT 1",
            (target,),
        ).fetchone()
    finally:
        conn.close()
    return _row_to_entry(row) if row is not None else None


def query_window(db_path: str, addr: str | None, limit: int) -> tuple[list[dict], int]:
    """Fenêtre d'entrées centrée sur addr (ou depuis le début), + total."""
    limit = max(1, int(limit))
    conn = _connect_ro(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) AS n FROM lines").fetchone()["n"]
        center_seq = None
        target = _addr_int_or_none(normalize_addr_key(addr)) if addr else None
        if target is not None:
            center = conn.execute(
                "SELECT seq FROM lines WHERE addr_int >= ? "
                "ORDER BY addr_int, seq LIMIT 1",
                (target,),
            ).fetchone()
            if center is not None:
                center_seq = center["seq"]
            else:
                last = conn.execute(
                    "SELECT seq FROM lines ORDER BY seq DESC LIMIT 1"
                ).fetchone()
                center_seq = last["seq"] if last is not None else None
        if center_seq is not None:
            start = max(1, center_seq - limit // 2)
            rows = conn.execute(
                "SELECT * FROM lines WHERE seq >= ? ORDER BY seq LIMIT ?",
                (start, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM lines ORDER BY seq LIMIT ?", (limit,)
            ).fetchall()
    finally:
        conn.close()
    return [_row_to_entry(row) for row in rows], int(total)


def query_function_addrs(db_path: str) -> list[str]:
    """Adresses de fonctions : table functions + lignes addr == function_addr."""
    conn = _connect_ro(db_path)
    try:
        rows = conn.execute(
            "SELECT DISTINCT addr FROM functions WHERE addr != '' "
            "UNION SELECT DISTINCT addr FROM lines "
            "WHERE function_addr IS NOT NULL AND addr = function_addr"
        ).fetchall()
    finally:
        conn.close()
    addrs = [row["addr"] for row in rows if row["addr"]]
    return sorted(addrs, key=lambda a: _addr_int_or_none(a) or 0)


def read_all_lines(db_path: str) -> list[dict]:
    """Toutes les lignes dans l'ordre du fichier (pour les outils qui
    traitent le désassemblage entier : CFG, call graph, xrefs…)."""
    conn = _connect_ro(db_path)
    try:
        rows = conn.execute("SELECT * FROM lines ORDER BY seq").fetchall()
    finally:
        conn.close()
    return [_row_to_entry(row) for row in rows]


def load_mapping_with_lines(mapping_json_path: str) -> dict:
    """Charge le mapping au format historique (avec `lines`).

    JSON allégé → recompose depuis le SQLite associé ; artefact legacy
    (avant migration) → renvoyé tel quel.
    """
    with open(mapping_json_path, encoding="utf-8") as f:
        mapping = json.load(f)
    if isinstance(mapping.get("lines"), list) and mapping["lines"]:
        return mapping
    db_path = mapping_db_path_for(mapping_json_path)
    mapping["lines"] = read_all_lines(db_path) if os.path.exists(db_path) else []
    return mapping


def query_function_name(db_path: str, addr: str) -> str:
    """Nom de fonction d'origine pour une adresse (table functions), ou ''."""
    key = normalize_addr_key(addr)
    if not key:
        return ""
    conn = _connect_ro(db_path)
    try:
        row = conn.execute(
            "SELECT name FROM functions WHERE addr = ? LIMIT 1", (key,)
        ).fetchone()
    finally:
        conn.close()
    return str(row["name"] or "").strip() if row is not None else ""


def update_line_comments(db_path: str, addr: str, comment: str | None) -> int:
    """Met à jour le commentaire des entrées d'une adresse. Retourne le nombre modifié."""
    key = normalize_addr_key(addr)
    if not key:
        return 0
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(
            "UPDATE lines SET comment = ? WHERE addr = ?", (comment, key)
        )
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()
