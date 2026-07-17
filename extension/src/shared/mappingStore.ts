// SPDX-License-Identifier: AGPL-3.0-only
/**
 * Accès au mapping de désassemblage sans jamais charger un JSON à un
 * enregistrement par instruction dans l'extension host.
 *
 * Depuis la migration SQLite, `*.disasm.mapping.json` est un en-tête borné
 * (méta, arch, fonctions, function_addrs) et les lignes vivent dans
 * `*.disasm.mapping.db`, requêtable par adresse. Les requêtes utilisent
 * node:sqlite (extension host Node >= 22) avec repli sur un one-shot Python
 * (`mapping_query.py`) quand le module natif est absent — et repli legacy
 * sur l'ancien JSON complet si un artefact d'avant migration traîne encore.
 */

const fs = require('fs');
const path = require('path');

let _sqlite = null;
let _sqliteChecked = false;
function getNodeSqlite() {
  if (!_sqliteChecked) {
    _sqliteChecked = true;
    try {
      _sqlite = require('node:sqlite');
    } catch (_) {
      _sqlite = null;
    }
  }
  return _sqlite;
}

const MAPPING_QUERY_SCRIPT = 'backends/static/disasm/mapping_query.py';

function mappingDbPathFor(mappingJsonPath) {
  const text = String(mappingJsonPath || '');
  return text.endsWith('.json') ? `${text.slice(0, -'.json'.length)}.db` : `${text}.db`;
}

function normalizeAddrKey(value) {
  const text = String(value || '').trim().toLowerCase();
  if (!text) return '';
  const raw = text.startsWith('0x') ? text.slice(2) : text;
  if (!/^[0-9a-f]+$/.test(raw)) return text;
  return `0x${raw.replace(/^0+/, '') || '0'}`;
}

function readSlimMapping(mappingPath) {
  if (!mappingPath || !fs.existsSync(mappingPath)) return null;
  try {
    return JSON.parse(fs.readFileSync(mappingPath, 'utf8'));
  } catch (_) {
    return null;
  }
}

function isLegacyFatMapping(mapping) {
  return Array.isArray(mapping?.lines) && mapping.lines.length > 0;
}

function entryFromDbRow(row) {
  const entry = {
    addr: row.addr,
    line: Number(row.line || 0),
    text: row.text,
    bytes: row.bytes,
    mnemonic: row.mnemonic,
    operands: row.operands,
    label: row.label,
    comment: row.comment,
    function_addr: row.function_addr,
    function_name: row.function_name,
  };
  for (const key of ['stack_hints', 'typed_struct_hints']) {
    try {
      entry[key] = JSON.parse(row[key] || '[]');
    } catch (_) {
      entry[key] = [];
    }
  }
  return entry;
}

function withDb(mappingPath, fn) {
  const sqlite = getNodeSqlite();
  if (!sqlite) return undefined;
  const dbPath = mappingDbPathFor(mappingPath);
  if (!fs.existsSync(dbPath)) return undefined;
  let db = null;
  try {
    db = new sqlite.DatabaseSync(dbPath, { readOnly: true });
    return fn(db);
  } catch (_) {
    return undefined;
  } finally {
    try { db?.close(); } catch (_) { /* déjà fermée */ }
  }
}

/**
 * Nombre d'instructions par fonction, sous forme de lookup `.get(addr)`
 * tolérant aux formats d'adresse (clés normalisées en interne).
 */
function getFunctionInstrCounts(mappingPath, mapping = null) {
  const source = mapping || readSlimMapping(mappingPath);
  const counts = new Map();
  const lookup = { get: (addr) => counts.get(normalizeAddrKey(addr)) };
  if (isLegacyFatMapping(source)) {
    for (const line of source.lines) {
      const key = normalizeAddrKey(line?.function_addr);
      if (key) counts.set(key, (counts.get(key) || 0) + 1);
    }
    return lookup;
  }
  const fromDb = withDb(mappingPath, (db) => {
    const rows = db
      .prepare('SELECT function_addr, COUNT(*) AS n FROM lines '
        + 'WHERE function_addr IS NOT NULL GROUP BY function_addr')
      .all();
    for (const row of rows) counts.set(normalizeAddrKey(row.function_addr), Number(row.n));
    return true;
  });
  void fromDb;
  return lookup;
}

function makeMappingStore({ runPythonJson = null } = {}) {
  const pythonQuery = async (mappingPath, payload) => {
    if (!runPythonJson) return null;
    const args = [MAPPING_QUERY_SCRIPT, '--db', mappingDbPathFor(mappingPath)];
    for (const [key, value] of Object.entries(payload)) {
      if (value !== null && value !== undefined && value !== '') {
        args.push(`--${key}`, String(value));
      }
    }
    try {
      return await runPythonJson(args[0], args.slice(1));
    } catch (_) {
      return null;
    }
  };

  const getFunctionAddrs = (mappingPath) => {
    const slim = readSlimMapping(mappingPath);
    if (!slim) return [];
    if (Array.isArray(slim.function_addrs)) {
      return slim.function_addrs.map(normalizeAddrKey).filter(Boolean);
    }
    // Artefact d'avant migration : dériver depuis le JSON complet.
    const addrs = new Set<string>();
    for (const fn of Array.isArray(slim.functions) ? slim.functions : []) {
      const addr = normalizeAddrKey(fn?.addr);
      if (addr) addrs.add(addr);
    }
    for (const line of Array.isArray(slim.lines) ? slim.lines : []) {
      const addr = normalizeAddrKey(line?.addr);
      const functionAddr = normalizeAddrKey(line?.function_addr);
      if (addr && functionAddr && addr === functionAddr) addrs.add(addr);
    }
    return Array.from(addrs).sort((a, b) => parseInt(a, 16) - parseInt(b, 16));
  };

  const findEntryByAddr = async (mappingPath, addr) => {
    const key = normalizeAddrKey(addr);
    if (!key) return null;
    const fromDb = withDb(mappingPath, (db) => {
      const row = db
        .prepare('SELECT * FROM lines WHERE addr = ? ORDER BY seq LIMIT 1')
        .get(key);
      return row ? entryFromDbRow(row) : null;
    });
    if (fromDb !== undefined) return fromDb;
    const slim = readSlimMapping(mappingPath);
    if (isLegacyFatMapping(slim)) {
      return slim.lines.find((line) => normalizeAddrKey(line?.addr) === key) || null;
    }
    const result = await pythonQuery(mappingPath, { mode: 'entry', addr: key });
    return result?.entry || null;
  };

  const queryWindow = async (mappingPath, addr, limit) => {
    const bounded = Math.max(1, Number(limit) || 1);
    const fromDb = withDb(mappingPath, (db) => {
      let centerSeq = null;
      const key = normalizeAddrKey(addr);
      if (key) {
        const exact = db
          .prepare('SELECT seq FROM lines WHERE addr = ? ORDER BY seq LIMIT 1')
          .get(key);
        if (exact) centerSeq = Number(exact.seq);
      }
      let rows;
      if (centerSeq !== null) {
        const start = Math.max(1, centerSeq - Math.floor(bounded / 2));
        rows = db
          .prepare('SELECT * FROM lines WHERE seq >= ? ORDER BY seq LIMIT ?')
          .all(start, bounded);
      } else {
        rows = db.prepare('SELECT * FROM lines ORDER BY seq LIMIT ?').all(bounded);
      }
      return rows.map(entryFromDbRow);
    });
    if (fromDb !== undefined) return fromDb;
    const slim = readSlimMapping(mappingPath);
    if (isLegacyFatMapping(slim)) {
      const key = normalizeAddrKey(addr);
      const idx = key
        ? slim.lines.findIndex((line) => normalizeAddrKey(line?.addr) === key)
        : -1;
      const start = idx >= 0 ? Math.max(0, idx - Math.floor(bounded / 2)) : 0;
      return slim.lines.slice(start, start + bounded);
    }
    const result = await pythonQuery(mappingPath, {
      mode: 'window',
      addr: normalizeAddrKey(addr) || null,
      limit: bounded,
    });
    return Array.isArray(result?.lines) ? result.lines : [];
  };

  return {
    readSlimMapping,
    getFunctionAddrs,
    findEntryByAddr,
    queryWindow,
    mappingDbPathFor,
  };
}

module.exports = {
  makeMappingStore,
  readSlimMapping,
  mappingDbPathFor,
  normalizeAddrKey,
  getFunctionInstrCounts,
};
