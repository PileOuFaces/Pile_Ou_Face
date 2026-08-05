// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const proxyquire = require('proxyquire');

const makeRoot = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pof-files-'));
const cacheStub = (overrides = {}) => ({
  listCacheEntries: () => [],
  pruneCacheEntries: () => 0,
  clearCacheEntries: () => 0,
  deleteCacheEntriesForBinary: () => 0,
  ...overrides,
});
const manager = (stub) => proxyquire('../shared/fileManager', { './staticCache': cacheStub(stub) });

describe('fileManager SQLite cache integration', () => {
  it('hides persistent configuration from artifacts', () => {
    const root = makeRoot();
    fs.writeFileSync(path.join(root, 'decompilers.json'), '{}');
    fs.writeFileSync(path.join(root, 'sample.disasm.asm'), 'asm');
    expect(manager().listArtifacts(root).map((item) => item.name)).to.deep.equal(['sample.disasm.asm']);
  });

  it('surfaces and sorts SQLite cache entries', () => {
    const root = makeRoot();
    const entries = [
      { key: 'old', status: 'stale', mtime: 1 },
      { key: 'new', status: 'ok', mtime: 2 },
    ];
    const summary = manager({ listCacheEntries: () => entries }).listAll(root);
    expect(summary.cache.map((item) => item.key)).to.deep.equal(['new', 'old']);
    expect(summary.staleCache.map((item) => item.key)).to.deep.equal(['old']);
  });

  it('purges stale SQLite rows and orphaned pfdb files', () => {
    const root = makeRoot();
    const workspace = path.join(root, 'workspace');
    const storage = path.join(root, 'storage');
    fs.mkdirSync(workspace);
    fs.mkdirSync(path.join(storage, 'pfdb'), { recursive: true });
    fs.writeFileSync(path.join(storage, 'pfdb', 'orphan.pfdb'), 'db');
    const result = manager({ pruneCacheEntries: () => 2 }).purgeStaleCache(storage, workspace);
    expect(result.removed).to.equal(3);
    expect(fs.existsSync(path.join(storage, 'pfdb', 'orphan.pfdb'))).to.equal(false);
  });

  it('cleans one binary through SQL and removes its artifacts', () => {
    const root = makeRoot();
    const binaryPath = path.join(root, 'demo.bin');
    fs.writeFileSync(path.join(root, 'demo.bin.disasm.asm'), 'asm');
    const result = manager({ deleteCacheEntriesForBinary: (storage, value) => {
      expect(value).to.equal(path.resolve(binaryPath));
      return 3;
    }}).cleanupForBinary(root, binaryPath, { purgeStale: false });
    expect(result.removedArtifacts).to.equal(1);
    expect(result.removedCache).to.equal(3);
  });

  it('clears SQL cache but preserves protected settings and the database directory', () => {
    const root = makeRoot();
    fs.mkdirSync(path.join(root, 'static_cache'));
    fs.writeFileSync(path.join(root, 'decompilers.json'), '{}');
    const result = manager({ clearCacheEntries: () => 4 }).cleanupAll(root, { cacheOnly: true });
    expect(result.removedCache).to.equal(4);
    expect(fs.existsSync(path.join(root, 'static_cache'))).to.equal(true);
    expect(fs.existsSync(path.join(root, 'decompilers.json'))).to.equal(true);
  });

  it('preserves every protected entry during full cleanup', () => {
    const root = makeRoot();
    for (const name of ['decompilers.json', 'compilers.json', 'licenses', 'plugins', 'pfdb']) {
      const target = path.join(root, name);
      if (name.includes('.')) fs.writeFileSync(target, '{}');
      else fs.mkdirSync(target);
    }
    fs.writeFileSync(path.join(root, 'temporary.artifact'), 'x');
    manager().cleanupAll(root, { artifactsOnly: true });
    expect(fs.existsSync(path.join(root, 'temporary.artifact'))).to.equal(false);
    for (const name of ['decompilers.json', 'compilers.json', 'licenses', 'plugins', 'pfdb']) {
      expect(fs.existsSync(path.join(root, name))).to.equal(true);
    }
  });
});
