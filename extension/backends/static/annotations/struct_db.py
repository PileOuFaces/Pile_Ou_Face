# SPDX-License-Identifier: AGPL-3.0-only
"""SQLite persistence for user-defined C types and their applied references."""

from __future__ import annotations

import json
import os
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

STRUCTS_DB_NAME = "types.db"
MAX_SOURCE_BYTES = 1_048_576
MAX_DEFINITIONS = 2_048
MAX_FIELDS_PER_DEFINITION = 4_096
MAX_TYPED_REFS = 4_096
MAX_FIELDS_PER_REF = 4_096
MAX_TYPED_VAR_BINDINGS = 4_096
MAX_TYPED_VAR_BINDINGS_PER_FUNCTION = 64


def get_struct_db_path(workspace_root: str | None = None) -> str:
    root = (
        workspace_root or os.environ.get("POF_STORAGE_DIR", "").strip() or os.getcwd()
    )
    return os.path.join(os.path.abspath(root), STRUCTS_DB_NAME)


class StructDb:
    """Own the normalized SQLite store for a single workspace."""

    def __init__(self, workspace_root: str | None = None) -> None:
        self.path = get_struct_db_path(workspace_root)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA journal_mode = WAL")
        self._create_schema(connection)
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _create_schema(connection: sqlite3.Connection) -> None:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS metadata (
                binary TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (binary, key)
            );
            CREATE TABLE IF NOT EXISTS definitions (
                binary TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL CHECK(kind IN ('struct', 'union', 'enum', 'typedef', 'function')),
                PRIMARY KEY (binary, name)
            );
            CREATE TABLE IF NOT EXISTS definition_fields (
                binary TEXT NOT NULL,
                definition_name TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                type_kind TEXT NOT NULL,
                pointer_level INTEGER NOT NULL,
                array_len INTEGER,
                array_dims TEXT,
                display_type TEXT NOT NULL,
                PRIMARY KEY (binary, definition_name, ordinal),
                FOREIGN KEY (binary, definition_name)
                    REFERENCES definitions(binary, name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS enum_values (
                binary TEXT NOT NULL,
                definition_name TEXT NOT NULL,
                ordinal INTEGER NOT NULL,
                name TEXT NOT NULL,
                value INTEGER NOT NULL,
                PRIMARY KEY (binary, definition_name, ordinal),
                FOREIGN KEY (binary, definition_name)
                    REFERENCES definitions(binary, name) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS typed_refs (
                id INTEGER PRIMARY KEY,
                binary TEXT NOT NULL,
                name TEXT NOT NULL,
                kind TEXT NOT NULL,
                addr TEXT NOT NULL,
                section TEXT NOT NULL,
                offset INTEGER NOT NULL,
                size INTEGER NOT NULL,
                align INTEGER NOT NULL,
                UNIQUE(binary, addr, name)
            );
            CREATE TABLE IF NOT EXISTS typed_ref_fields (
                ref_id INTEGER NOT NULL REFERENCES typed_refs(id) ON DELETE CASCADE,
                ordinal INTEGER NOT NULL,
                field_name TEXT NOT NULL,
                field_type TEXT NOT NULL,
                offset INTEGER NOT NULL,
                absolute_offset INTEGER NOT NULL,
                addr TEXT NOT NULL,
                tag TEXT NOT NULL,
                size INTEGER NOT NULL,
                PRIMARY KEY (ref_id, ordinal)
            );
            CREATE TABLE IF NOT EXISTS typed_var_bindings (
                id INTEGER PRIMARY KEY,
                binary TEXT NOT NULL,
                func_addr TEXT NOT NULL,
                var_kind TEXT NOT NULL CHECK(var_kind IN ('param', 'local')),
                var_key TEXT NOT NULL,
                type_name TEXT NOT NULL,
                type_kind TEXT NOT NULL CHECK(type_kind IN ('struct', 'union', 'enum')),
                pointer_level INTEGER NOT NULL DEFAULT 0,
                UNIQUE(binary, func_addr, var_kind, var_key),
                FOREIGN KEY (binary, type_name) REFERENCES definitions(binary, name) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_typed_refs_binary ON typed_refs(binary);
            CREATE INDEX IF NOT EXISTS idx_definitions_binary ON definitions(binary);
            CREATE INDEX IF NOT EXISTS idx_typed_var_bindings_func ON typed_var_bindings(binary, func_addr);
            """
        )

    def load_definitions(self, binary: str) -> dict[str, Any]:
        if not binary:
            raise ValueError("Chemin binaire manquant.")
        if not os.path.isfile(self.path):
            return {"source": "", "definitions": {}}
        with self._connect() as connection:
            source_row = connection.execute(
                "SELECT value FROM metadata WHERE binary = ? AND key = 'source'",
                (binary,),
            ).fetchone()
            definitions: dict[str, dict[str, Any]] = {}
            for row in connection.execute(
                "SELECT name, kind FROM definitions WHERE binary = ? ORDER BY name",
                (binary,),
            ):
                definition: dict[str, Any] = {"name": row["name"], "kind": row["kind"]}
                if row["kind"] == "enum":
                    values = [
                        {"name": item["name"], "value": item["value"]}
                        for item in connection.execute(
                            "SELECT name, value FROM enum_values WHERE binary = ? AND definition_name = ? ORDER BY ordinal",
                            (binary, row["name"]),
                        )
                    ]
                    definition["values"] = values
                    definition["value_map"] = {
                        item["name"]: item["value"] for item in values
                    }
                else:
                    definition["fields"] = [
                        {
                            "name": item["name"],
                            "type": item["type"],
                            "type_kind": item["type_kind"],
                            "pointer_level": item["pointer_level"],
                            "array_len": item["array_len"],
                            "array_dims": json.loads(item["array_dims"])
                            if item["array_dims"]
                            else None,
                            "display_type": item["display_type"],
                        }
                        for item in connection.execute(
                            "SELECT * FROM definition_fields WHERE binary = ? AND definition_name = ? ORDER BY ordinal",
                            (binary, row["name"]),
                        )
                    ]
                definitions[row["name"]] = definition
            return {
                "source": source_row["value"] if source_row else "",
                "definitions": definitions,
            }

    def replace_definitions(
        self, binary: str, source: str, definitions: dict[str, dict[str, Any]]
    ) -> None:
        if not binary:
            raise ValueError("Chemin binaire manquant.")
        if len(source.encode("utf-8")) > MAX_SOURCE_BYTES:
            raise ValueError("Les définitions dépassent la limite de 1 Mio.")
        if len(definitions) > MAX_DEFINITIONS:
            raise ValueError(f"Trop de types: limite de {MAX_DEFINITIONS}.")
        with self._connect() as connection:
            connection.execute("DELETE FROM definitions WHERE binary = ?", (binary,))
            connection.execute(
                "INSERT INTO metadata(binary, key, value) VALUES(?, 'source', ?) ON CONFLICT(binary, key) DO UPDATE SET value=excluded.value",
                (binary, source),
            )
            for name, definition in definitions.items():
                _insert_definition(connection, binary, name, definition)

    def merge_definitions(
        self, binary: str, definitions: dict[str, dict[str, Any]], source_label: str
    ) -> None:
        """Upsert only the given type names, leaving the rest of the binary's catalog untouched."""
        if not binary:
            raise ValueError("Chemin binaire manquant.")
        if not definitions:
            return
        with self._connect() as connection:
            placeholders = ",".join("?" * len(definitions))
            existing_total = connection.execute(
                "SELECT COUNT(*) FROM definitions WHERE binary = ?", (binary,)
            ).fetchone()[0]
            existing_matched = connection.execute(
                f"SELECT COUNT(*) FROM definitions WHERE binary = ? AND name IN ({placeholders})",
                (binary, *definitions.keys()),
            ).fetchone()[0]
            projected_total = existing_total - existing_matched + len(definitions)
            if projected_total > MAX_DEFINITIONS:
                raise ValueError(f"Trop de types: limite de {MAX_DEFINITIONS}.")
            for name, definition in definitions.items():
                connection.execute(
                    "DELETE FROM definitions WHERE binary = ? AND name = ?",
                    (binary, name),
                )
                _insert_definition(connection, binary, name, definition)
                connection.execute(
                    "INSERT INTO metadata(binary, key, value) VALUES(?, ?, ?) "
                    "ON CONFLICT(binary, key) DO UPDATE SET value=excluded.value",
                    (binary, f"import_source:{name}", source_label),
                )

    def list_typed_refs(self, binary: str | None = None) -> list[dict[str, Any]]:
        if not os.path.isfile(self.path):
            return []
        with self._connect() as connection:
            query = "SELECT * FROM typed_refs"
            parameters: tuple[Any, ...] = ()
            if binary:
                query += " WHERE binary = ?"
                parameters = (binary,)
            query += " ORDER BY binary, addr, name"
            entries: list[dict[str, Any]] = []
            for row in connection.execute(query, parameters):
                fields = [
                    dict(item)
                    for item in connection.execute(
                        """SELECT field_name, field_type, offset, absolute_offset, addr, tag, size
                    FROM typed_ref_fields WHERE ref_id = ? ORDER BY ordinal""",
                        (row["id"],),
                    )
                ]
                entries.append(
                    {
                        "binary": row["binary"],
                        "name": row["name"],
                        "kind": row["kind"],
                        "addr": row["addr"],
                        "section": row["section"],
                        "offset": row["offset"],
                        "size": row["size"],
                        "align": row["align"],
                        "fields": fields,
                    }
                )
            entries.sort(
                key=lambda item: (
                    item["binary"],
                    _address_sort_value(item["addr"]),
                    item["name"],
                )
            )
            return entries

    def save_typed_ref(self, entry: dict[str, Any]) -> None:
        fields = entry.get("fields") or []
        if len(fields) > MAX_FIELDS_PER_REF:
            raise ValueError(
                f"Trop de champs appliqués: limite de {MAX_FIELDS_PER_REF}."
            )
        with self._connect() as connection:
            existing = connection.execute("SELECT COUNT(*) FROM typed_refs").fetchone()[
                0
            ]
            matched = connection.execute(
                "SELECT id FROM typed_refs WHERE binary = ? AND addr = ? AND name = ?",
                (entry["binary"], entry["addr"], entry["name"]),
            ).fetchone()
            if not matched and existing >= MAX_TYPED_REFS:
                raise ValueError(
                    f"Trop de références typées: limite de {MAX_TYPED_REFS}."
                )
            connection.execute(
                """INSERT INTO typed_refs(binary, name, kind, addr, section, offset, size, align)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(binary, addr, name) DO UPDATE SET
                kind=excluded.kind, section=excluded.section, offset=excluded.offset,
                size=excluded.size, align=excluded.align""",
                tuple(
                    entry[key]
                    for key in (
                        "binary",
                        "name",
                        "kind",
                        "addr",
                        "section",
                        "offset",
                        "size",
                        "align",
                    )
                ),
            )
            ref_id = connection.execute(
                "SELECT id FROM typed_refs WHERE binary = ? AND addr = ? AND name = ?",
                (entry["binary"], entry["addr"], entry["name"]),
            ).fetchone()["id"]
            connection.execute(
                "DELETE FROM typed_ref_fields WHERE ref_id = ?", (ref_id,)
            )
            connection.executemany(
                """INSERT INTO typed_ref_fields
                (ref_id, ordinal, field_name, field_type, offset, absolute_offset, addr, tag, size)
                VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                [
                    (
                        ref_id,
                        index,
                        field["field_name"],
                        field["field_type"],
                        field["offset"],
                        field["absolute_offset"],
                        field["addr"],
                        field["tag"],
                        field["size"],
                    )
                    for index, field in enumerate(fields)
                ],
            )

    def list_typed_var_bindings(
        self, binary: str | None = None, func_addr: str | None = None
    ) -> list[dict[str, Any]]:
        if not os.path.isfile(self.path):
            return []
        with self._connect() as connection:
            query = "SELECT * FROM typed_var_bindings"
            clauses: list[str] = []
            parameters: list[Any] = []
            if binary:
                clauses.append("binary = ?")
                parameters.append(binary)
            if func_addr:
                clauses.append("func_addr = ?")
                parameters.append(func_addr)
            if clauses:
                query += " WHERE " + " AND ".join(clauses)
            query += " ORDER BY binary, func_addr, var_kind, var_key"
            return [
                {
                    "binary": row["binary"],
                    "func_addr": row["func_addr"],
                    "var_kind": row["var_kind"],
                    "var_key": row["var_key"],
                    "type_name": row["type_name"],
                    "type_kind": row["type_kind"],
                    "pointer_level": row["pointer_level"],
                }
                for row in connection.execute(query, tuple(parameters))
            ]

    def save_typed_var_binding(self, entry: dict[str, Any]) -> None:
        with self._connect() as connection:
            existing = connection.execute(
                "SELECT COUNT(*) FROM typed_var_bindings"
            ).fetchone()[0]
            matched = connection.execute(
                """SELECT id FROM typed_var_bindings
                WHERE binary = ? AND func_addr = ? AND var_kind = ? AND var_key = ?""",
                (
                    entry["binary"],
                    entry["func_addr"],
                    entry["var_kind"],
                    entry["var_key"],
                ),
            ).fetchone()
            if not matched and existing >= MAX_TYPED_VAR_BINDINGS:
                raise ValueError(
                    f"Trop de bindings de variables typées: limite de {MAX_TYPED_VAR_BINDINGS}."
                )
            if not matched:
                per_function = connection.execute(
                    "SELECT COUNT(*) FROM typed_var_bindings WHERE binary = ? AND func_addr = ?",
                    (entry["binary"], entry["func_addr"]),
                ).fetchone()[0]
                if per_function >= MAX_TYPED_VAR_BINDINGS_PER_FUNCTION:
                    raise ValueError(
                        "Trop de bindings de variables typées pour cette fonction: "
                        f"limite de {MAX_TYPED_VAR_BINDINGS_PER_FUNCTION}."
                    )
            connection.execute(
                """INSERT INTO typed_var_bindings
                (binary, func_addr, var_kind, var_key, type_name, type_kind, pointer_level)
                VALUES(?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(binary, func_addr, var_kind, var_key) DO UPDATE SET
                type_name=excluded.type_name, type_kind=excluded.type_kind,
                pointer_level=excluded.pointer_level""",
                (
                    entry["binary"],
                    entry["func_addr"],
                    entry["var_kind"],
                    entry["var_key"],
                    entry["type_name"],
                    entry["type_kind"],
                    entry.get("pointer_level", 0),
                ),
            )


def _insert_definition(
    connection: sqlite3.Connection, binary: str, name: str, definition: dict[str, Any]
) -> None:
    kind = str(definition.get("kind") or "struct")
    connection.execute(
        "INSERT INTO definitions(binary, name, kind) VALUES(?, ?, ?)",
        (binary, name, kind),
    )
    if kind == "enum":
        values = definition.get("values") or []
        if len(values) > MAX_FIELDS_PER_DEFINITION:
            raise ValueError(f"Trop de valeurs dans {name}.")
        connection.executemany(
            "INSERT INTO enum_values(binary, definition_name, ordinal, name, value) VALUES(?, ?, ?, ?, ?)",
            [
                (binary, name, index, item["name"], int(item["value"]))
                for index, item in enumerate(values)
            ],
        )
        return
    fields = definition.get("fields") or []
    if len(fields) > MAX_FIELDS_PER_DEFINITION:
        raise ValueError(f"Trop de champs dans {name}.")
    connection.executemany(
        """INSERT INTO definition_fields
        (binary, definition_name, ordinal, name, type, type_kind, pointer_level, array_len, array_dims, display_type)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        [
            (
                binary,
                name,
                index,
                field["name"],
                field["type"],
                field["type_kind"],
                int(field.get("pointer_level") or 0),
                field.get("array_len"),
                json.dumps(field["array_dims"])
                if field.get("array_dims") is not None
                else None,
                field.get("display_type") or field["type"],
            )
            for index, field in enumerate(fields)
        ],
    )


def _address_sort_value(value: Any) -> int:
    try:
        return int(str(value), 0)
    except (TypeError, ValueError):
        return 0
