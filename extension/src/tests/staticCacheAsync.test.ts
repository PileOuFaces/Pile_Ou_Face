// SPDX-License-Identifier: AGPL-3.0-only
// POF-P1-010 : API asynchrone du cache statique (ordre, event loop, contention SQLite).
const { expect } = require('chai');
const cp = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');
const cache = require('../shared/staticCache');
const utils = require('../shared/utils');

const EXTENSION_ROOT = path.resolve(__dirname, '../..');
const CACHE_SCRIPT = path.join(EXTENSION_ROOT, 'backends', 'static', 'cache', 'cache_index.py');
// Each case spawns several Python processes; the lock case waits for LOCK_HOLD_MS.
const CASE_TIMEOUT_MS = 30000;
// Shorter than the backend busy_timeout (5 s), so blocked writers must wait, then succeed.
const LOCK_HOLD_MS = 1500;
const CONCURRENT_WRITES = 8;
const EXTERNAL_WRITERS = 4;
const TICK_INTERVAL_MS = 1;

// Holds an exclusive SQLite write lock, prints "locked", then releases it after a delay.
const HOLD_LOCK_SCRIPT = [
  'import sqlite3, sys, time',
  'db = sqlite3.connect(sys.argv[1], isolation_level=None)',
  'db.execute("BEGIN IMMEDIATE")',
  'print("locked", flush=True)',
  'time.sleep(float(sys.argv[2]) / 1000)',
  'db.execute("COMMIT")',
].join('\n');

const python = () => utils.resolvePythonExecutable(EXTENSION_ROOT);

const runExternalPut = (dbPath, cacheKey, payload) => new Promise((resolve, reject) => {
  const child = cp.execFile(python(), [
    CACHE_SCRIPT, '--db', dbPath, 'put', '--namespace', 'external', '--cache-key', cacheKey,
  ], { env: { ...process.env, PYTHONPATH: EXTENSION_ROOT } }, (error, stdout) => {
    if (error) reject(error);
    else resolve(JSON.parse(String(stdout).trim()));
  });
  child.stdin.end(JSON.stringify(payload));
});

const holdWriteLock = (dbPath) => new Promise((resolve, reject) => {
  const child = cp.spawn(python(), ['-c', HOLD_LOCK_SCRIPT, dbPath, String(LOCK_HOLD_MS)]);
  const released = new Promise((done, fail) => {
    child.on('exit', (code) => (code === 0 ? done(code) : fail(new Error(`lock holder exit ${code}`))));
  });
  child.on('error', reject);
  child.stdout.once('data', () => resolve({ released }));
});

describe('static cache async API (POF-P1-010)', function () {
  this.timeout(CASE_TIMEOUT_MS);
  let previousExtensionPath;
  let dir;
  let bin;

  beforeEach(() => {
    previousExtensionPath = utils.getExtensionPath();
    utils.setExtensionPath(EXTENSION_ROOT);
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pof-cache-async-'));
    bin = path.join(dir, 'sample.bin');
    fs.writeFileSync(bin, 'binary');
  });

  afterEach(() => {
    utils.setExtensionPath(previousExtensionPath);
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('round-trips with the same storage as the sync API', async () => {
    expect(await cache.writeCacheAsync(dir, bin, 'info', { arch: 'x86_64' })).to.equal(true);
    expect(await cache.readCacheAsync(dir, bin, 'info')).to.deep.equal({ arch: 'x86_64' });
    expect(cache.readCache(dir, bin, 'info')).to.deep.equal({ arch: 'x86_64' });
  });

  it('misses without throwing for a missing binary', async () => {
    const missing = path.join(dir, 'missing.bin');
    expect(await cache.readCacheAsync(dir, missing, 'info')).to.equal(null);
    expect(await cache.writeCacheAsync(dir, missing, 'info', {})).to.equal(false);
  });

  it('resolves false instead of rejecting when the payload cannot be serialised', async () => {
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(await cache.writeCacheAsync(dir, bin, 'info', cyclic)).to.equal(false);
  });

  it('preserves submission order for interleaved reads and writes', async () => {
    // Nothing is awaited between submissions: only the queue orders them.
    const results = await Promise.all([
      cache.readCacheAsync(dir, bin, 'info'),
      cache.writeCacheAsync(dir, bin, 'info', { v: 1 }),
      cache.readCacheAsync(dir, bin, 'info'),
      cache.writeCacheAsync(dir, bin, 'info', { v: 2 }),
      cache.readCacheAsync(dir, bin, 'info'),
    ]);
    expect(results).to.deep.equal([null, true, { v: 1 }, true, { v: 2 }]);
  });

  it('keeps the event loop running while cache operations are pending', async () => {
    let ticks = 0;
    const timer = setInterval(() => { ticks += 1; }, TICK_INTERVAL_MS);
    try {
      const pending = cache.writeCacheAsync(dir, bin, 'info', { ok: true })
        .then(() => cache.readCacheAsync(dir, bin, 'info'));
      expect(ticks).to.equal(0);
      expect(await pending).to.deep.equal({ ok: true });
    } finally {
      clearInterval(timer);
    }
    expect(ticks).to.be.greaterThan(0);
  });

  it('waits for an external SQLite write lock, then stores every entry', async () => {
    expect(await cache.writeCacheAsync(dir, bin, 'info', { init: true })).to.equal(true);
    const lock = await holdWriteLock(cache.getStaticCacheDbPath(dir));
    const writes = Array.from({ length: CONCURRENT_WRITES }, (_, i) => (
      cache.writeCacheAsync(dir, bin, `ns${i}`, { i })
    ));
    expect(await Promise.all(writes)).to.deep.equal(Array(CONCURRENT_WRITES).fill(true));
    await lock.released;
    for (let i = 0; i < CONCURRENT_WRITES; i += 1) {
      expect(await cache.readCacheAsync(dir, bin, `ns${i}`)).to.deep.equal({ i });
    }
  });

  it('stays consistent with concurrent writers from other processes', async () => {
    expect(await cache.writeCacheAsync(dir, bin, 'info', { init: true })).to.equal(true);
    const dbPath = cache.getStaticCacheDbPath(dir);
    const external = Array.from({ length: EXTERNAL_WRITERS }, (_, i) => (
      runExternalPut(dbPath, `external-${i}`, { writer: i })
    ));
    const internal = Array.from({ length: CONCURRENT_WRITES }, (_, i) => (
      cache.writeCacheAsync(dir, bin, 'info', { v: i })
    ));
    const lastRead = cache.readCacheAsync(dir, bin, 'info');
    const [externalResults, internalResults, finalValue] = await Promise.all([
      Promise.all(external), Promise.all(internal), lastRead,
    ]);
    expect(externalResults.every((result) => result.stored === true)).to.equal(true);
    expect(internalResults).to.deep.equal(Array(CONCURRENT_WRITES).fill(true));
    expect(finalValue).to.deep.equal({ v: CONCURRENT_WRITES - 1 });
  });
});
