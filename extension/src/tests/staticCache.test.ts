// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cache = require('../shared/staticCache');
const { setExtensionPath } = require('../shared/utils');

setExtensionPath(path.resolve(__dirname, '../..'));
const temp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cache-'));
const binary = (dir, content = 'binary') => {
  const result = path.join(dir, 'sample.bin');
  fs.writeFileSync(result, content);
  return result;
};

describe('SQLite static cache', () => {
  it('derives stable paths and keys', () => {
    const dir = temp();
    const bin = binary(dir);
    expect(cache.getCacheKey(bin)).to.match(/^[a-f0-9]{16}$/);
    expect(cache.getCacheKey('/missing')).to.equal(null);
    expect(cache.getCacheDir(dir)).to.equal(path.join(dir, 'static_cache'));
    expect(cache.getStaticCacheDbPath(dir)).to.equal(path.join(dir, 'static_cache', 'static-cache.sqlite3'));
  });

  it('round-trips data without JSON cache files', () => {
    const dir = temp();
    const bin = binary(dir);
    expect(cache.writeCache(dir, bin, 'info', { arch: 'arm64' })).to.equal(true);
    expect(cache.readCache(dir, bin, 'info')).to.deep.equal({ arch: 'arm64' });
    expect(fs.existsSync(cache.getStaticCacheDbPath(dir))).to.equal(true);
    expect(fs.readdirSync(cache.getCacheDir(dir)).filter((name) => name.endsWith('.json'))).to.deep.equal([]);
  });

  it('isolates strings option variants', () => {
    const dir = temp();
    const bin = binary(dir);
    cache.writeCache(dir, bin, 'strings', ['utf8'], { minLen: 4, encoding: 'utf-8' });
    cache.writeCache(dir, bin, 'strings', ['wide'], { minLen: 8, encoding: 'utf-16-le' });
    expect(cache.readCache(dir, bin, 'strings', { minLen: 4, encoding: 'utf-8' })).to.deep.equal(['utf8']);
    expect(cache.readCache(dir, bin, 'strings', { minLen: 8, encoding: 'utf-16-le' })).to.deep.equal(['wide']);
  });

  it('misses after binary changes and prunes the stale row', () => {
    const dir = temp();
    const bin = binary(dir);
    cache.writeCache(dir, bin, 'symbols', [{ name: 'main' }]);
    fs.writeFileSync(bin, 'changed-longer');
    expect(cache.readCache(dir, bin, 'symbols')).to.equal(null);
    expect(cache.pruneCacheEntries(dir)).to.equal(1);
  });

  it('lists, deletes per binary, and clears entries', () => {
    const dir = temp();
    const bin = binary(dir);
    cache.writeCache(dir, bin, 'info', { ok: true });
    expect(cache.listCacheEntries(dir)[0]).to.include({ status: 'ok', binaryPath: fs.realpathSync(bin) });
    expect(cache.deleteCacheEntriesForBinary(dir, bin)).to.equal(1);
    cache.writeCache(dir, bin, 'info', { ok: true });
    expect(cache.clearCacheEntries(dir)).to.equal(1);
    expect(cache.listCacheEntries(dir)).to.deep.equal([]);
  });
});
