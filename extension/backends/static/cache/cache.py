# SPDX-License-Identifier: AGPL-3.0-only
"""Cache SQLite pour les résultats d'analyse statique.

Format : fichier `.pfdb` (SQLite) stocké sous `.pile-ou-face/pfdb/` ou chemin explicite.
Schéma : voir docs/static/BDD_FICHIERS_IDA_CUTTER.md

Usage:
    cache = DisasmCache("output.pfdb")
    # Lecture
    result = cache.get_disasm("/path/to/binary")
    if result:
        binary_id, lines = result
    else:
        lines = disassemble("/path/to/binary")
        binary_id = cache.save_disasm("/path/to/binary", lines)
    cache.close()

    # Ou avec context manager
    with DisasmCache("output.pfdb") as cache:
        ...
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path
from typing import Any

from backends.shared.exceptions import CacheCorruptedError, CacheError
from backends.shared.log import get_logger

logger = get_logger(__name__)

# Version du schéma SQLite — incrémentée si changement incompatible
SCHEMA_VERSION = 2

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS schema_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS binary (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    path       TEXT    NOT NULL,
    hash       TEXT    NOT NULL,
    created_at DATETIME DEFAULT (datetime('now'))
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_binary_path ON binary(path);

CREATE TABLE IF NOT EXISTS disasm_lines (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    addr      TEXT    NOT NULL,
    line      INTEGER,
    text      TEXT    NOT NULL,
    bytes     TEXT,
    mnemonic  TEXT,
    operands  TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_disasm_binary ON disasm_lines(binary_id);

CREATE TABLE IF NOT EXISTS symbols (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    name      TEXT    NOT NULL,
    addr      TEXT    NOT NULL,
    type      TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_symbols_binary_addr ON symbols(binary_id, addr);

CREATE TABLE IF NOT EXISTS strings_data (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    addr      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    length    INTEGER,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_strings_binary_addr ON strings_data(binary_id, addr);

CREATE TABLE IF NOT EXISTS annotations (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id INTEGER NOT NULL,
    addr      TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    value     TEXT    NOT NULL,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_annotations_binary_addr ON annotations(binary_id, addr);

CREATE TABLE IF NOT EXISTS functions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL,
    addr       TEXT    NOT NULL,
    name       TEXT,
    confidence TEXT,
    reason     TEXT,
    size       INTEGER,
    payload    TEXT    NOT NULL,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_functions_binary_addr ON functions(binary_id, addr);

CREATE TABLE IF NOT EXISTS basic_blocks (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id         INTEGER NOT NULL,
    function_addr     TEXT,
    addr              TEXT    NOT NULL,
    lines_json        TEXT    NOT NULL,
    successors_json   TEXT    NOT NULL,
    is_call           INTEGER NOT NULL DEFAULT 0,
    is_switch         INTEGER NOT NULL DEFAULT 0,
    switch_cases_json TEXT    NOT NULL DEFAULT '[]',
    payload           TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_basic_blocks_binary_addr ON basic_blocks(binary_id, function_addr, addr);

CREATE TABLE IF NOT EXISTS cfg_edges (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id     INTEGER NOT NULL,
    function_addr TEXT,
    from_addr     TEXT    NOT NULL,
    to_addr       TEXT    NOT NULL,
    type          TEXT    NOT NULL,
    case_label    TEXT,
    payload       TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_cfg_edges_binary_from ON cfg_edges(binary_id, function_addr, from_addr);

CREATE TABLE IF NOT EXISTS xrefs (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL,
    target_addr TEXT   NOT NULL,
    from_addr  TEXT    NOT NULL,
    from_line  INTEGER,
    text       TEXT,
    type       TEXT,
    type_info  TEXT,
    payload    TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_xrefs_binary_target ON xrefs(binary_id, target_addr);

CREATE TABLE IF NOT EXISTS imports (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id     INTEGER NOT NULL,
    dll           TEXT    NOT NULL,
    function_name TEXT    NOT NULL,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_imports_binary_dll ON imports(binary_id, dll);

CREATE TABLE IF NOT EXISTS import_findings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id     INTEGER NOT NULL,
    function_name TEXT    NOT NULL,
    dll           TEXT,
    category      TEXT,
    description   TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_import_findings_binary_fn ON import_findings(binary_id, function_name);

CREATE TABLE IF NOT EXISTS import_analysis_meta (
    binary_id INTEGER PRIMARY KEY,
    score     INTEGER,
    error     TEXT,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS stack_frames (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    binary_id  INTEGER NOT NULL,
    func_addr  TEXT    NOT NULL,
    frame_size INTEGER NOT NULL DEFAULT 0,
    vars_json  TEXT    NOT NULL DEFAULT '[]',
    args_json  TEXT    NOT NULL DEFAULT '[]',
    payload    TEXT    NOT NULL,
    FOREIGN KEY (binary_id) REFERENCES binary(id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_stack_frames_binary_func ON stack_frames(binary_id, func_addr);
"""

_DROP_SCHEMA_SQL = """
DROP TABLE IF EXISTS stack_frames;
DROP TABLE IF EXISTS import_analysis_meta;
DROP TABLE IF EXISTS import_findings;
DROP TABLE IF EXISTS imports;
DROP TABLE IF EXISTS xrefs;
DROP TABLE IF EXISTS cfg_edges;
DROP TABLE IF EXISTS basic_blocks;
DROP TABLE IF EXISTS functions;
DROP TABLE IF EXISTS annotations;
DROP TABLE IF EXISTS strings_data;
DROP TABLE IF EXISTS symbols;
DROP TABLE IF EXISTS disasm_lines;
DROP TABLE IF EXISTS binary;
DROP TABLE IF EXISTS schema_meta;
"""


def compute_sha256(path: str) -> str:
    """Calcule le SHA256 d'un fichier binaire.

    Args:
        path: Chemin vers le fichier

    Returns:
        Hash SHA256 en hexadécimal (64 caractères)
    """
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _find_pof_dir(start_dir: Path) -> Path | None:
    current = start_dir.resolve()
    while True:
        candidate = current / ".pile-ou-face"
        if candidate.is_dir():
            return candidate
        if current.parent == current:
            return None
        current = current.parent


def _sanitize_cache_filename(name: str) -> str:
    safe = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
    return safe or "binary"


def _addr_sort_key(addr: str | None) -> tuple[int, str]:
    if not addr:
        return (1 << 62, "")
    try:
        return (int(addr, 16), addr)
    except ValueError:
        return (1 << 62, addr)


def _json_dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def _json_loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return default


class DisasmCache:
    """Cache SQLite pour les résultats de désassemblage.

    Stocke le désassemblage indexé par hash SHA256 du binaire.
    Si le binaire change (hash différent), le cache est automatiquement invalidé.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        try:
            self._conn = sqlite3.connect(db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
        except sqlite3.OperationalError as exc:
            raise CacheError(f"Cannot open cache database: {db_path}") from exc
        except sqlite3.DatabaseError as exc:
            raise CacheCorruptedError(
                f"Cache database is corrupted: {db_path}"
            ) from exc
        self._init_schema()

    def _init_schema(self) -> None:
        try:
            self._conn.executescript(_SCHEMA_SQL)
        except sqlite3.DatabaseError as exc:
            raise CacheCorruptedError(
                f"Cache database is corrupted: {self._db_path}"
            ) from exc

        try:
            cur = self._conn.execute(
                "SELECT value FROM schema_meta WHERE key='version'"
            )
            row = cur.fetchone()
        except sqlite3.DatabaseError as exc:
            raise CacheCorruptedError(
                f"Cache database is corrupted: {self._db_path}"
            ) from exc

        if row is None:
            self._conn.execute(
                "INSERT INTO schema_meta(key, value) VALUES('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()
            return

        try:
            stored = int(row["value"])
        except (TypeError, ValueError):
            stored = -1

        if stored != SCHEMA_VERSION:
            logger.warning(
                "Cache schema version mismatch: stored=%d expected=%d — cache rebuilt",
                stored,
                SCHEMA_VERSION,
            )
            self._rebuild_schema()

    def _rebuild_schema(self) -> None:
        """Reconstruit entièrement le schéma après changement incompatible."""
        try:
            self._conn.executescript(_DROP_SCHEMA_SQL)
            self._conn.executescript(_SCHEMA_SQL)
            self._conn.execute(
                "INSERT OR REPLACE INTO schema_meta(key, value) VALUES('version', ?)",
                (str(SCHEMA_VERSION),),
            )
            self._conn.commit()
        except sqlite3.DatabaseError as exc:
            raise CacheCorruptedError(
                f"Cache database is corrupted: {self._db_path}"
            ) from exc

    # ------------------------------------------------------------------
    # API publique — désassemblage
    # ------------------------------------------------------------------

    def get_disasm(self, binary_path: str) -> tuple[int, list[dict]] | None:
        """Charge le désassemblage depuis le cache si valide.

        Returns:
            (binary_id, lines) si le cache est valide, None sinon.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        lines = self._load_disasm_lines(binary_id)
        if not lines:
            return None
        logger.debug("Cache hit: %s (%d lines)", binary_path, len(lines))
        return binary_id, lines

    def save_disasm(self, binary_path: str, lines: list[dict]) -> int:
        """Sauvegarde le désassemblage dans le cache.

        Args:
            binary_path: Chemin absolu vers le binaire
            lines: Lignes de désassemblage

        Returns:
            binary_id de l'entrée créée ou mise à jour.
        """
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM disasm_lines WHERE binary_id=?", (binary_id,))
        self._conn.executemany(
            """
            INSERT INTO disasm_lines(binary_id, addr, line, text, bytes, mnemonic, operands)
            VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    binary_id,
                    ln.get("addr", ""),
                    ln.get("line", idx),
                    ln.get("text", ""),
                    ln.get("bytes", ""),
                    ln.get("mnemonic", ""),
                    ln.get("operands", ""),
                )
                for idx, ln in enumerate(lines, start=1)
            ],
        )
        self._conn.commit()
        logger.debug("Cache saved: %s (%d lines)", binary_path, len(lines))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — symboles
    # ------------------------------------------------------------------

    def get_symbols(self, binary_path: str) -> list[dict] | None:
        """Charge les symboles depuis le cache si valide.

        Returns:
            Liste de {name, addr, type} ou None si absent/invalidé.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        cur = self._conn.execute(
            "SELECT name, addr, type FROM symbols WHERE binary_id=?",
            (binary_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return None
        symbols = [
            {"name": r["name"], "addr": r["addr"], "type": r["type"]} for r in rows
        ]
        return sorted(symbols, key=lambda s: _addr_sort_key(s.get("addr")))

    def save_symbols(self, binary_path: str, symbols: list[dict]) -> int:
        """Sauvegarde les symboles dans le cache.

        Args:
            binary_path: Chemin absolu vers le binaire
            symbols: [{name, addr, type}, ...]

        Returns:
            binary_id de l'entrée.
        """
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM symbols WHERE binary_id=?", (binary_id,))
        self._conn.executemany(
            "INSERT INTO symbols(binary_id, name, addr, type) VALUES(?,?,?,?)",
            [
                (binary_id, s.get("name", ""), s.get("addr", ""), s.get("type", ""))
                for s in symbols
            ],
        )
        self._conn.commit()
        logger.debug("Symbols cached: %s (%d symbols)", binary_path, len(symbols))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — strings
    # ------------------------------------------------------------------

    def get_strings(self, binary_path: str) -> list[dict] | None:
        """Charge les strings depuis le cache si valide.

        Returns:
            Liste de {addr, value, length} ou None si absent/invalidé.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        cur = self._conn.execute(
            "SELECT addr, value, length FROM strings_data WHERE binary_id=?",
            (binary_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return None
        strings = [
            {"addr": r["addr"], "value": r["value"], "length": r["length"]}
            for r in rows
        ]
        return sorted(strings, key=lambda s: _addr_sort_key(s.get("addr")))

    def get_strings_for_addresses(
        self, binary_path: str, addresses: list[str] | set[str] | tuple[str, ...]
    ) -> list[dict] | None:
        """Charge uniquement les strings cachees aux adresses demandees.

        Retourne None si le cache strings est absent/invalidé pour ce binaire.
        Retourne [] si le cache existe mais qu'aucune adresse demandée ne matche.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]

        cur = self._conn.execute(
            "SELECT 1 FROM strings_data WHERE binary_id=? LIMIT 1",
            (binary_id,),
        )
        if cur.fetchone() is None:
            return None

        normalized = sorted({str(addr or "").strip().lower() for addr in addresses})
        normalized = [addr for addr in normalized if addr]
        if not normalized:
            return []

        rows = []
        # SQLite limite souvent les placeholders a 999 variables.
        for idx in range(0, len(normalized), 900):
            chunk = normalized[idx : idx + 900]
            placeholders = ",".join("?" for _ in chunk)
            cur = self._conn.execute(
                f"""
                SELECT addr, value, length
                FROM strings_data
                WHERE binary_id=? AND lower(addr) IN ({placeholders})
                """,
                (binary_id, *chunk),
            )
            rows.extend(cur.fetchall())

        strings = [
            {"addr": r["addr"], "value": r["value"], "length": r["length"]}
            for r in rows
        ]
        return sorted(strings, key=lambda s: _addr_sort_key(s.get("addr")))

    def save_strings(self, binary_path: str, strings: list[dict]) -> int:
        """Sauvegarde les strings dans le cache.

        Args:
            binary_path: Chemin absolu vers le binaire
            strings: [{addr, value, length}, ...]

        Returns:
            binary_id de l'entrée.
        """
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM strings_data WHERE binary_id=?", (binary_id,))
        self._conn.executemany(
            "INSERT INTO strings_data(binary_id, addr, value, length) VALUES(?,?,?,?)",
            [
                (binary_id, s.get("addr", ""), s.get("value", ""), s.get("length"))
                for s in strings
            ],
        )
        self._conn.commit()
        logger.debug("Strings cached: %s (%d strings)", binary_path, len(strings))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — annotations
    # ------------------------------------------------------------------

    def get_annotations(self, binary_path: str, addr: str | None = None) -> list[dict]:
        """Charge les annotations depuis le cache.

        Args:
            binary_path: Chemin absolu vers le binaire
            addr: Filtrer par adresse (None = toutes)

        Returns:
            Liste de {addr, kind, value}.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return []
        binary_id: int = row["id"]
        if addr is not None:
            cur = self._conn.execute(
                "SELECT addr, kind, value FROM annotations WHERE binary_id=? AND addr=? ORDER BY id",
                (binary_id, addr),
            )
        else:
            cur = self._conn.execute(
                "SELECT addr, kind, value FROM annotations WHERE binary_id=? ORDER BY addr, id",
                (binary_id,),
            )
        return [
            {"addr": r["addr"], "kind": r["kind"], "value": r["value"]} for r in cur
        ]

    def save_annotation(
        self, binary_path: str, addr: str, kind: str, value: str
    ) -> None:
        """Ajoute ou remplace une annotation pour une adresse.

        Si une annotation du même (addr, kind) existe, elle est remplacée.

        Args:
            binary_path: Chemin absolu vers le binaire
            addr: Adresse (ex: "0x401000")
            kind: Type d'annotation ("comment", "rename", ...)
            value: Valeur de l'annotation
        """
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute(
            "DELETE FROM annotations WHERE binary_id=? AND addr=? AND kind=?",
            (binary_id, addr, kind),
        )
        self._conn.execute(
            "INSERT INTO annotations(binary_id, addr, kind, value) VALUES(?,?,?,?)",
            (binary_id, addr, kind, value),
        )
        self._conn.commit()

    def delete_annotation(
        self, binary_path: str, addr: str, kind: str | None = None
    ) -> int:
        """Supprime les annotations pour une adresse.

        Args:
            binary_path: Chemin absolu vers le binaire
            addr: Adresse cible
            kind: Type à supprimer (None = tous les types pour cette adresse)

        Returns:
            Nombre d'annotations supprimées.
        """
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return 0
        binary_id: int = row["id"]
        if kind is not None:
            cur = self._conn.execute(
                "DELETE FROM annotations WHERE binary_id=? AND addr=? AND kind=?",
                (binary_id, addr, kind),
            )
        else:
            cur = self._conn.execute(
                "DELETE FROM annotations WHERE binary_id=? AND addr=?",
                (binary_id, addr),
            )
        self._conn.commit()
        return cur.rowcount

    # ------------------------------------------------------------------
    # API publique — fonctions découvertes
    # ------------------------------------------------------------------

    def get_functions(self, binary_path: str) -> list[dict] | None:
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        cur = self._conn.execute(
            "SELECT addr, name, confidence, reason, size, payload FROM functions WHERE binary_id=?",
            (binary_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return None

        functions = []
        for r in rows:
            payload = _json_loads(r["payload"], {})
            if not isinstance(payload, dict):
                payload = {}
            payload.setdefault("addr", r["addr"])
            payload.setdefault("name", r["name"])
            if r["confidence"] is not None:
                payload.setdefault("confidence", r["confidence"])
            if r["reason"] is not None:
                payload.setdefault("reason", r["reason"])
            if r["size"] is not None:
                payload.setdefault("size", r["size"])
            functions.append(payload)
        return sorted(functions, key=lambda fn: _addr_sort_key(fn.get("addr")))

    def save_functions(self, binary_path: str, functions: list[dict]) -> int:
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM functions WHERE binary_id=?", (binary_id,))
        self._conn.executemany(
            """
            INSERT INTO functions(binary_id, addr, name, confidence, reason, size, payload)
            VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    binary_id,
                    fn.get("addr", ""),
                    fn.get("name"),
                    fn.get("confidence"),
                    fn.get("reason"),
                    fn.get("size"),
                    _json_dumps(fn),
                )
                for fn in functions
            ],
        )
        self._conn.commit()
        logger.debug("Functions cached: %s (%d functions)", binary_path, len(functions))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — CFG
    # ------------------------------------------------------------------

    def get_cfg(self, binary_path: str, func_addr: str | None = None) -> dict | None:
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]

        if func_addr is None:
            block_cur = self._conn.execute(
                """
                SELECT addr, lines_json, successors_json, is_call, is_switch, switch_cases_json, payload
                FROM basic_blocks
                WHERE binary_id=? AND function_addr IS NULL
                """,
                (binary_id,),
            )
            edge_cur = self._conn.execute(
                """
                SELECT from_addr, to_addr, type, case_label, payload
                FROM cfg_edges
                WHERE binary_id=? AND function_addr IS NULL
                """,
                (binary_id,),
            )
        else:
            block_cur = self._conn.execute(
                """
                SELECT addr, lines_json, successors_json, is_call, is_switch, switch_cases_json, payload
                FROM basic_blocks
                WHERE binary_id=? AND function_addr=?
                """,
                (binary_id, func_addr),
            )
            edge_cur = self._conn.execute(
                """
                SELECT from_addr, to_addr, type, case_label, payload
                FROM cfg_edges
                WHERE binary_id=? AND function_addr=?
                """,
                (binary_id, func_addr),
            )

        block_rows = block_cur.fetchall()
        edge_rows = edge_cur.fetchall()
        if not block_rows and not edge_rows:
            return None

        blocks = []
        for r in block_rows:
            payload = _json_loads(r["payload"], {})
            if not isinstance(payload, dict):
                payload = {}
            payload.setdefault("addr", r["addr"])
            payload.setdefault("lines", _json_loads(r["lines_json"], []))
            payload.setdefault("successors", _json_loads(r["successors_json"], []))
            payload.setdefault("is_call", bool(r["is_call"]))
            payload.setdefault("is_switch", bool(r["is_switch"]))
            payload.setdefault("switch_cases", _json_loads(r["switch_cases_json"], []))
            blocks.append(payload)

        edges = []
        for r in edge_rows:
            payload = _json_loads(r["payload"], {})
            if not isinstance(payload, dict):
                payload = {}
            payload.setdefault("from", r["from_addr"])
            payload.setdefault("to", r["to_addr"])
            payload.setdefault("type", r["type"])
            if r["case_label"] is not None:
                payload.setdefault("case_label", r["case_label"])
            edges.append(payload)

        result = {
            "blocks": sorted(blocks, key=lambda b: _addr_sort_key(b.get("addr"))),
            "edges": sorted(
                edges,
                key=lambda e: (
                    _addr_sort_key(e.get("from")),
                    _addr_sort_key(e.get("to")),
                    str(e.get("type", "")),
                ),
            ),
        }
        if func_addr is not None:
            result["func_addr"] = func_addr
        return result

    def save_cfg(self, binary_path: str, cfg: dict) -> int:
        binary_id = self._ensure_binary(binary_path)
        func_addr = cfg.get("func_addr")

        if func_addr is None:
            self._conn.execute(
                "DELETE FROM basic_blocks WHERE binary_id=? AND function_addr IS NULL",
                (binary_id,),
            )
            self._conn.execute(
                "DELETE FROM cfg_edges WHERE binary_id=? AND function_addr IS NULL",
                (binary_id,),
            )
        else:
            self._conn.execute(
                "DELETE FROM basic_blocks WHERE binary_id=? AND function_addr=?",
                (binary_id, func_addr),
            )
            self._conn.execute(
                "DELETE FROM cfg_edges WHERE binary_id=? AND function_addr=?",
                (binary_id, func_addr),
            )

        blocks = cfg.get("blocks", []) or []
        edges = cfg.get("edges", []) or []
        self._conn.executemany(
            """
            INSERT INTO basic_blocks(
                binary_id, function_addr, addr, lines_json, successors_json,
                is_call, is_switch, switch_cases_json, payload
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            [
                (
                    binary_id,
                    func_addr,
                    block.get("addr", ""),
                    _json_dumps(block.get("lines", [])),
                    _json_dumps(block.get("successors", [])),
                    int(bool(block.get("is_call"))),
                    int(bool(block.get("is_switch"))),
                    _json_dumps(block.get("switch_cases", [])),
                    _json_dumps(block),
                )
                for block in blocks
            ],
        )
        self._conn.executemany(
            """
            INSERT INTO cfg_edges(binary_id, function_addr, from_addr, to_addr, type, case_label, payload)
            VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    binary_id,
                    func_addr,
                    edge.get("from", ""),
                    edge.get("to", ""),
                    edge.get("type", ""),
                    edge.get("case_label"),
                    _json_dumps(edge),
                )
                for edge in edges
            ],
        )
        self._conn.commit()
        logger.debug(
            "CFG cached: %s (%d blocks, %d edges)",
            binary_path,
            len(blocks),
            len(edges),
        )
        return binary_id

    # ------------------------------------------------------------------
    # API publique — xrefs
    # ------------------------------------------------------------------

    def get_xref_map(self, binary_path: str) -> dict | None:
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        cur = self._conn.execute(
            """
            SELECT target_addr, from_addr, from_line, text, type, type_info, payload
            FROM xrefs
            WHERE binary_id=?
            ORDER BY target_addr, from_line, from_addr
            """,
            (binary_id,),
        )
        rows = cur.fetchall()
        if not rows:
            return None

        xref_map: dict[str, list[dict]] = {}
        for r in rows:
            payload = _json_loads(r["payload"], {})
            if not isinstance(payload, dict):
                payload = {}
            payload.setdefault("from_addr", r["from_addr"])
            payload.setdefault("from_line", r["from_line"])
            payload.setdefault("text", r["text"])
            payload.setdefault("type", r["type"])
            payload.setdefault("type_info", _json_loads(r["type_info"], r["type_info"]))
            xref_map.setdefault(r["target_addr"], []).append(payload)
        return dict(sorted(xref_map.items(), key=lambda item: _addr_sort_key(item[0])))

    def save_xref_map(self, binary_path: str, xref_map: dict) -> int:
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM xrefs WHERE binary_id=?", (binary_id,))

        rows = []
        for target_addr, refs in xref_map.items():
            for ref in refs:
                type_info = ref.get("type_info")
                rows.append(
                    (
                        binary_id,
                        target_addr,
                        ref.get("from_addr", ""),
                        ref.get("from_line"),
                        ref.get("text"),
                        ref.get("type"),
                        _json_dumps(type_info)
                        if isinstance(type_info, (dict, list))
                        else type_info,
                        _json_dumps(ref),
                    )
                )

        self._conn.executemany(
            """
            INSERT INTO xrefs(binary_id, target_addr, from_addr, from_line, text, type, type_info, payload)
            VALUES(?,?,?,?,?,?,?,?)
            """,
            rows,
        )
        self._conn.commit()
        logger.debug("Xrefs cached: %s (%d targets)", binary_path, len(xref_map))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — imports
    # ------------------------------------------------------------------

    def get_imports_analysis(self, binary_path: str) -> dict | None:
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]

        imports_cur = self._conn.execute(
            "SELECT dll, function_name FROM imports WHERE binary_id=? ORDER BY dll, function_name",
            (binary_id,),
        )
        findings_cur = self._conn.execute(
            """
            SELECT function_name, dll, category, description
            FROM import_findings
            WHERE binary_id=?
            ORDER BY function_name
            """,
            (binary_id,),
        )
        meta = self._conn.execute(
            "SELECT score, error FROM import_analysis_meta WHERE binary_id=?",
            (binary_id,),
        ).fetchone()

        import_rows = imports_cur.fetchall()
        finding_rows = findings_cur.fetchall()
        if not import_rows and not finding_rows and meta is None:
            return None

        dll_map: dict[str, list[str]] = {}
        for r in import_rows:
            dll_map.setdefault(r["dll"], []).append(r["function_name"])

        imports = [
            {"dll": dll, "functions": funcs, "count": len(funcs)}
            for dll, funcs in sorted(dll_map.items())
        ]
        suspicious = [
            {
                "function": r["function_name"],
                "dll": r["dll"],
                "category": r["category"],
                "description": r["description"],
            }
            for r in finding_rows
        ]
        return {
            "imports": imports,
            "suspicious": suspicious,
            "score": (
                meta["score"] if meta is not None and meta["score"] is not None else 0
            ),
            "error": (meta["error"] if meta is not None else None),
        }

    def save_imports_analysis(self, binary_path: str, analysis: dict) -> int:
        binary_id = self._ensure_binary(binary_path)
        self._conn.execute("DELETE FROM imports WHERE binary_id=?", (binary_id,))
        self._conn.execute(
            "DELETE FROM import_findings WHERE binary_id=?", (binary_id,)
        )
        self._conn.execute(
            "DELETE FROM import_analysis_meta WHERE binary_id=?",
            (binary_id,),
        )

        import_rows = []
        for group in analysis.get("imports", []) or []:
            dll = group.get("dll", "")
            for fn_name in group.get("functions", []) or []:
                import_rows.append((binary_id, dll, fn_name))

        finding_rows = [
            (
                binary_id,
                finding.get("function", ""),
                finding.get("dll"),
                finding.get("category"),
                finding.get("description"),
            )
            for finding in analysis.get("suspicious", []) or []
        ]

        if import_rows:
            self._conn.executemany(
                "INSERT INTO imports(binary_id, dll, function_name) VALUES(?,?,?)",
                import_rows,
            )
        if finding_rows:
            self._conn.executemany(
                """
                INSERT INTO import_findings(binary_id, function_name, dll, category, description)
                VALUES(?,?,?,?,?)
                """,
                finding_rows,
            )
        self._conn.execute(
            "INSERT INTO import_analysis_meta(binary_id, score, error) VALUES(?,?,?)",
            (
                binary_id,
                analysis.get("score", 0),
                analysis.get("error"),
            ),
        )
        self._conn.commit()
        logger.debug("Imports cached: %s (%d rows)", binary_path, len(import_rows))
        return binary_id

    # ------------------------------------------------------------------
    # API publique — stack frames
    # ------------------------------------------------------------------

    def get_stack_frame(self, binary_path: str, func_addr: str) -> dict | None:
        row = self._get_valid_binary_row(binary_path)
        if row is None:
            return None
        binary_id: int = row["id"]
        frame_row = self._conn.execute(
            """
            SELECT func_addr, frame_size, vars_json, args_json, payload
            FROM stack_frames
            WHERE binary_id=? AND func_addr=?
            ORDER BY id DESC
            LIMIT 1
            """,
            (binary_id, func_addr),
        ).fetchone()
        if frame_row is None:
            return None

        payload = _json_loads(frame_row["payload"], {})
        if not isinstance(payload, dict):
            payload = {}
        payload.setdefault("func_addr", frame_row["func_addr"])
        payload.setdefault("frame_size", frame_row["frame_size"])
        payload.setdefault("vars", _json_loads(frame_row["vars_json"], []))
        payload.setdefault("args", _json_loads(frame_row["args_json"], []))
        return payload

    def save_stack_frame(self, binary_path: str, frame: dict) -> int:
        binary_id = self._ensure_binary(binary_path)
        func_addr = frame.get("func_addr", "")
        self._conn.execute(
            "DELETE FROM stack_frames WHERE binary_id=? AND func_addr=?",
            (binary_id, func_addr),
        )
        self._conn.execute(
            """
            INSERT INTO stack_frames(binary_id, func_addr, frame_size, vars_json, args_json, payload)
            VALUES(?,?,?,?,?,?)
            """,
            (
                binary_id,
                func_addr,
                frame.get("frame_size", 0),
                _json_dumps(frame.get("vars", [])),
                _json_dumps(frame.get("args", [])),
                _json_dumps(frame),
            ),
        )
        self._conn.commit()
        logger.debug("Stack frame cached: %s (%s)", binary_path, func_addr)
        return binary_id

    # ------------------------------------------------------------------
    # Helpers internes
    # ------------------------------------------------------------------

    def _get_valid_binary_row(self, binary_path: str) -> sqlite3.Row | None:
        """Retourne la row binary si le hash est valide, None sinon."""
        binary_path = os.path.abspath(binary_path)
        try:
            current_hash = compute_sha256(binary_path)
        except OSError:
            return None
        cur = self._conn.execute(
            "SELECT id, hash FROM binary WHERE path=?", (binary_path,)
        )
        row = cur.fetchone()
        if row is None:
            return None
        if row["hash"] != current_hash:
            self._invalidate_binary(row["id"])
            return None
        return row  # type: ignore[no-any-return]

    def _ensure_binary(self, binary_path: str) -> int:
        """Retourne binary_id existant ou crée une nouvelle entrée binary."""
        binary_path = os.path.abspath(binary_path)
        binary_hash = compute_sha256(binary_path)
        cur = self._conn.execute(
            "SELECT id, hash FROM binary WHERE path=?", (binary_path,)
        )
        row = cur.fetchone()
        if row is not None and row["hash"] == binary_hash:
            return int(row["id"])
        # Hash différent ou absent : créer/remplacer
        self._conn.execute("DELETE FROM binary WHERE path=?", (str(binary_path),))
        cur = self._conn.execute(
            "INSERT INTO binary(path, hash) VALUES(?, ?)",
            (str(binary_path), binary_hash),
        )
        binary_id = cur.lastrowid
        assert binary_id is not None
        self._conn.commit()
        return binary_id

    def invalidate(self, binary_path: str) -> None:
        """Supprime l'entrée cache pour un binaire."""
        self._conn.execute(
            "DELETE FROM binary WHERE path=?", (os.path.abspath(binary_path),)
        )
        self._conn.commit()

    def _invalidate_binary(self, binary_id: int) -> None:
        self._conn.execute("DELETE FROM binary WHERE id=?", (binary_id,))
        self._conn.commit()

    def _load_disasm_lines(self, binary_id: int) -> list[dict]:
        cur = self._conn.execute(
            """
            SELECT addr, line, text, bytes, mnemonic, operands
            FROM disasm_lines
            WHERE binary_id=?
            ORDER BY COALESCE(line, id), id
            """,
            (binary_id,),
        )
        return [
            {
                "addr": r["addr"],
                "line": r["line"],
                "text": r["text"],
                "bytes": r["bytes"] or "",
                "mnemonic": r["mnemonic"] or "",
                "operands": r["operands"] or "",
            }
            for r in cur
        ]

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> DisasmCache:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def default_cache_path(binary_path: str) -> str:
    """Retourne le chemin par défaut du fichier cache pour un binaire.

    Place le cache dans `.pile-ou-face/pfdb/` pour éviter de polluer le
    répertoire du binaire avec des fichiers générés.

    Exemple :
        `/workspace/examples/prog` →
        `/workspace/.pile-ou-face/pfdb/prog.<hash>.pfdb`
    """
    p = Path(binary_path).resolve()
    pof_dir = _find_pof_dir(p.parent)
    cache_dir = (pof_dir / "pfdb") if pof_dir else (p.parent / ".pile-ou-face" / "pfdb")
    cache_dir.mkdir(parents=True, exist_ok=True)

    cache_key = hashlib.sha256(str(p).encode("utf-8")).hexdigest()[:16]
    cache_name = _sanitize_cache_filename(p.name)
    return str(cache_dir / f"{cache_name}.{cache_key}.pfdb")
