// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
const { expect } = require('chai');
const fs = require('fs');
const os = require('os');
const path = require('path');

const {
  readCache,
  writeCache,
  getCacheKey,
  getCacheDir,
  getCacheIndexDbPath,
  readMeta,
  listIndexedCacheEntries,
} = require('../shared/staticCache');
const { setExtensionPath } = require('../shared/utils');

setExtensionPath(path.resolve(__dirname, '../..'));

function makeTmpDir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cache-test-'));
}

function makeBinary(dir, content = 'BINARY_CONTENT') {
  const p = path.join(dir, 'test.bin');
  fs.writeFileSync(p, content);
  return p;
}

describe('staticCache — getCacheKey', () => {
  it('returns a 16-char hex string for an existing file', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const key = getCacheKey(bin);
    expect(key).to.be.a('string');
    expect(key).to.have.length(16);
    expect(key).to.match(/^[0-9a-f]+$/);
  });

  it('returns null for a nonexistent file', () => {
    const key = getCacheKey('/nonexistent/path/to/binary.exe');
    expect(key).to.equal(null);
  });

  it('returns a different key when the file content changes', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir, 'CONTENT_V1');
    const key1 = getCacheKey(bin);
    // Overwrite to change mtime and size
    fs.writeFileSync(bin, 'CONTENT_V2_LONGER');
    const key2 = getCacheKey(bin);
    expect(key1).to.not.equal(key2);
  });
});

describe('staticCache — getCacheDir', () => {
  it('appends static_cache to storageDir', () => {
    expect(getCacheDir('/my/storage')).to.equal(path.join('/my/storage', 'static_cache'));
  });
});

describe('staticCache — getCacheIndexDbPath', () => {
  it('returns path inside static_cache', () => {
    const p = getCacheIndexDbPath('/storage');
    expect(p).to.include('static_cache');
    expect(p).to.include('cache-index.sqlite3');
  });
});

describe('staticCache — readMeta', () => {
  it('returns null when meta.json does not exist', () => {
    const dir = makeTmpDir();
    const result = readMeta(dir, 'nonexistentkey');
    expect(result).to.equal(null);
  });

  it('returns parsed meta when meta.json exists', () => {
    const dir = makeTmpDir();
    const key = 'abc1234567890123';
    const keyDir = path.join(dir, key);
    fs.mkdirSync(keyDir);
    const meta = { path: '/bin/test', mtimeMs: 12345, size: 100 };
    fs.writeFileSync(path.join(keyDir, 'meta.json'), JSON.stringify(meta));
    const result = readMeta(dir, key);
    expect(result).to.deep.equal(meta);
  });

  it('returns null when meta.json is malformed JSON', () => {
    const dir = makeTmpDir();
    const key = 'abc123defabc123d';
    const keyDir = path.join(dir, key);
    fs.mkdirSync(keyDir);
    fs.writeFileSync(path.join(keyDir, 'meta.json'), 'not_valid_json{{{');
    const result = readMeta(dir, key);
    expect(result).to.equal(null);
  });
});

describe('staticCache — writeCache / readCache round-trip', () => {
  it('stores and retrieves generic data', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const data = { ok: true, symbols: [{ name: 'main', addr: '0x400000' }] };
    writeCache(dir, bin, 'symbols', data);
    const result = readCache(dir, bin, 'symbols');
    expect(result).to.deep.equal(data);
  });

  it('returns null for a cache miss (file not written yet)', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const result = readCache(dir, bin, 'symbols');
    expect(result).to.equal(null);
  });

  it('returns null after the binary mtime changes', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir, 'original');
    writeCache(dir, bin, 'info', { arch: 'x86_64' });
    // Invalidate by changing file content (changes mtime+size)
    fs.writeFileSync(bin, 'modified_content_different_size');
    const result = readCache(dir, bin, 'info');
    expect(result).to.equal(null);
  });

  it('returns null for a nonexistent binary', () => {
    const dir = makeTmpDir();
    const result = readCache(dir, '/does/not/exist.bin', 'symbols');
    expect(result).to.equal(null);
  });

  it('records cache writes in the SQLite index', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    writeCache(dir, bin, 'info', { arch: 'x86_64' });

    const entries = listIndexedCacheEntries(dir);
    expect(entries).to.be.an('array').with.length(1);
    expect(entries[0].binaryPath).to.equal(path.resolve(bin));
    expect(entries[0].cacheTypes).to.deep.equal(['info']);
    expect(entries[0].status).to.equal('ok');
  });
});

describe('staticCache — strings cache filename (_v2)', () => {
  it('stores strings with _v2 suffix in filename', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const strings = [{ addr: '0x1000', value: 'hello', length: 5, encoding: 'utf-8' }];
    writeCache(dir, bin, 'strings', strings, { minLen: 4, encoding: 'utf-8', section: null });

    const key = getCacheKey(bin);
    const cacheDir = getCacheDir(dir);
    const cacheFile = path.join(cacheDir, key, 'strings_4_utf-8_all_v2.json');
    expect(fs.existsSync(cacheFile)).to.equal(true);
  });

  it('reads back strings using _v2 suffix', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const strings = [{ addr: '0x1000', value: 'hello', length: 5, encoding: 'utf-8' }];
    writeCache(dir, bin, 'strings', strings, { minLen: 4, encoding: 'utf-8' });
    const result = readCache(dir, bin, 'strings', { minLen: 4, encoding: 'utf-8' });
    expect(result).to.deep.equal(strings);
  });

  it('does NOT read an old cache file without _v2', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);

    // Manually write an old-style cache file (no _v2 suffix)
    const key = getCacheKey(bin);
    const cacheDir = getCacheDir(dir);
    const keyDir = path.join(cacheDir, key);
    fs.mkdirSync(keyDir, { recursive: true });
    const stat = fs.statSync(bin);
    fs.writeFileSync(path.join(keyDir, 'meta.json'), JSON.stringify({ path: bin, mtimeMs: stat.mtimeMs, size: stat.size }));
    const oldStrings = [{ addr: '0x0', value: 'stale', length: 5, encoding: 'utf-8' }];
    fs.writeFileSync(path.join(keyDir, 'strings_4_utf-8_all.json'), JSON.stringify(oldStrings));

    // readCache looks for strings_4_utf-8_all_v2.json → miss
    const result = readCache(dir, bin, 'strings', { minLen: 4, encoding: 'utf-8' });
    expect(result).to.equal(null);
  });

  it('builds correct filename with custom section', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const strings = [{ addr: '0x2000', value: 'world', length: 5, encoding: 'utf-8' }];
    writeCache(dir, bin, 'strings', strings, { minLen: 4, encoding: 'utf-8', section: '.rodata' });

    const key = getCacheKey(bin);
    const cacheDir = getCacheDir(dir);
    const cacheFile = path.join(cacheDir, key, 'strings_4_utf-8_.rodata_v2.json');
    expect(fs.existsSync(cacheFile)).to.equal(true);
  });

  it('builds correct filename with utf-16-le encoding', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    writeCache(dir, bin, 'strings', [], { minLen: 8, encoding: 'utf-16-le' });

    const key = getCacheKey(bin);
    const cacheDir = getCacheDir(dir);
    const cacheFile = path.join(cacheDir, key, 'strings_8_utf-16-le_all_v2.json');
    expect(fs.existsSync(cacheFile)).to.equal(true);
  });

  it('reads back strings with custom options', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir);
    const strings = [{ addr: '0x3000', value: 'wide', length: 4, encoding: 'utf-16-le' }];
    writeCache(dir, bin, 'strings', strings, { minLen: 4, encoding: 'utf-16-le', section: '.data' });
    const result = readCache(dir, bin, 'strings', { minLen: 4, encoding: 'utf-16-le', section: '.data' });
    expect(result).to.deep.equal(strings);
  });
});

describe('staticCache — isCacheValid / cache invalidation', () => {
  it('returns null if meta.json path does not match the requested binary', () => {
    const dir = makeTmpDir();
    const bin = makeBinary(dir, 'hello');

    // Write cache for bin
    writeCache(dir, bin, 'info', { arch: 'arm' });

    // Try to read with a different absolute path
    const otherBin = path.join(dir, 'other.bin');
    fs.writeFileSync(otherBin, 'hello'); // same content
    // otherBin has different path → different key → miss
    const result = readCache(dir, otherBin, 'info');
    expect(result).to.equal(null);
  });
});
