// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { makeMappingStore, mappingDbPathFor } = require('../shared/mappingStore');

let sqlite = null;
try {
  sqlite = require('node:sqlite');
} catch (_) {
  sqlite = null;
}

const SCHEMA = `
CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE functions (addr TEXT, name TEXT, size INTEGER, reason TEXT);
CREATE TABLE lines (
  seq INTEGER PRIMARY KEY, addr TEXT, addr_int INTEGER, line INTEGER,
  text TEXT, bytes TEXT, mnemonic TEXT, operands TEXT, label TEXT,
  comment TEXT, function_addr TEXT, function_name TEXT,
  stack_hints TEXT, typed_struct_hints TEXT
);
CREATE INDEX idx_lines_addr ON lines (addr);
CREATE INDEX idx_lines_addr_int ON lines (addr_int);
`;

function writeFixture(dir) {
  const mappingPath = path.join(dir, 'sample.disasm.mapping.json');
  fs.writeFileSync(mappingPath, JSON.stringify({
    binary: '/bin/fake',
    path: path.join(dir, 'sample.disasm.asm'),
    functions: [{ addr: '0x401000', name: 'entry0' }],
    function_addrs: ['0x401000'],
    line_count: 3,
    lines_db: 'sample.disasm.mapping.db',
  }), 'utf8');
  const db = new sqlite.DatabaseSync(mappingDbPathFor(mappingPath));
  // Accès indexé : DatabaseSync.exec est du SQL node:sqlite, pas child_process.
  db['exec'](SCHEMA);
  const insert = db.prepare('INSERT INTO lines VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
  insert.run(1, '0x401000', 0x401000, 3, 'push rbp', '55', 'push', 'rbp', 'entry0', null, '0x401000', 'entry0', '[]', '[]');
  insert.run(2, '0x401001', 0x401001, 4, 'mov eax, 1', 'b8 01', 'mov', 'eax, 1', null, 'note', '0x401000', 'entry0', '[{"kind":"var","name":"x","location":"rbp-0x8"}]', '[]');
  insert.run(3, '0x401006', 0x401006, 5, 'ret', 'c3', 'ret', '', null, null, '0x401000', 'entry0', '[]', '[]');
  db.close();
  return mappingPath;
}

describe('mappingStore', () => {
  let dir;
  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-mapping-store-'));
  });
  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('reads precomputed function addrs from the slim header', () => {
    const mappingPath = path.join(dir, 'slim.disasm.mapping.json');
    fs.writeFileSync(mappingPath, JSON.stringify({
      functions: [{ addr: '0x2000', name: 'f' }],
      function_addrs: ['0x1000', '0x2000'],
      line_count: 10,
    }), 'utf8');
    const store = makeMappingStore();
    expect(store.getFunctionAddrs(mappingPath)).to.deep.equal(['0x1000', '0x2000']);
  });

  it('falls back to scanning a legacy fat mapping for function addrs', () => {
    const mappingPath = path.join(dir, 'legacy.disasm.mapping.json');
    fs.writeFileSync(mappingPath, JSON.stringify({
      functions: [{ addr: '0x2000', name: 'f' }],
      lines: [
        { addr: '0x1000', function_addr: '0x1000' },
        { addr: '0x1004', function_addr: '0x1000' },
      ],
    }), 'utf8');
    const store = makeMappingStore();
    expect(store.getFunctionAddrs(mappingPath)).to.deep.equal(['0x1000', '0x2000']);
  });

  (sqlite ? describe : describe.skip)('avec node:sqlite', () => {
    it('finds an exact entry by address', async () => {
      const mappingPath = writeFixture(dir);
      const store = makeMappingStore();
      const entry = await store.findEntryByAddr(mappingPath, '0x401001');
      expect(entry.line).to.equal(4);
      expect(entry.comment).to.equal('note');
      expect(entry.stack_hints[0].name).to.equal('x');
      expect(await store.findEntryByAddr(mappingPath, '0xdead')).to.equal(null);
    });

    it('returns a window of lines centered on the address', async () => {
      const mappingPath = writeFixture(dir);
      const store = makeMappingStore();
      const lines = await store.queryWindow(mappingPath, '0x401001', 2);
      expect(lines.map((l) => l.addr)).to.deep.equal(['0x401000', '0x401001']);
      const all = await store.queryWindow(mappingPath, null, 10);
      expect(all).to.have.length(3);
    });
  });

  it('finds entries in a legacy fat mapping without any db', async () => {
    const mappingPath = path.join(dir, 'legacy.disasm.mapping.json');
    fs.writeFileSync(mappingPath, JSON.stringify({
      lines: [{ addr: '0x1000', line: 1 }, { addr: '0x1004', line: 2 }],
    }), 'utf8');
    const store = makeMappingStore();
    const entry = await store.findEntryByAddr(mappingPath, '0x1004');
    expect(entry.line).to.equal(2);
  });
});
