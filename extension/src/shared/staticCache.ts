// SPDX-License-Identifier: AGPL-3.0-only
/**
 * SQLite-only, bounded cache for static-analysis results.
 *
 * Sync functions block the Extension Host while Python runs; they remain for the
 * maintenance paths (list, prune, clear, delete). Hot paths use readCacheAsync and
 * writeCacheAsync: one bounded FIFO queue per database keeps reads and writes in
 * submission order without blocking the event loop. clear and delete-binary bypass the queue but
 * invalidate writes submitted before them (see staticCacheInvalidation.ts).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { getExtensionPath, resolvePythonExecutable, logDebug, logWarning } = require('./utils');
const { createBoundedSerialQueue, QUEUE_FULL_CODE } = require('./boundedSerialQueue');
const {
  currentInvalidationSeq, markInvalidated, isInvalidatedSince, binaryIdentitySync,
} = require('./staticCacheInvalidation');

const CACHE_DIR_NAME = 'static_cache';
const CACHE_DB_NAME = 'static-cache.sqlite3';
const CACHE_STORE_TIMEOUT_MS = 10000;
// Same bound as the spawnSync default, so async and sync paths accept the same payloads.
const CACHE_STORE_MAX_OUTPUT_BYTES = 1024 * 1024;
// Queued + running operations per database; beyond it reads miss and writes are skipped.
const CACHE_QUEUE_LIMIT = 32;

type CacheStoreOptions = {
  input?: string;
};

type CacheVariantOptions = {
  encoding?: string;
  section?: string;
  minLen?: number;
};

function hashCacheKey(absPath, stat) {
  return crypto.createHash('sha256')
    .update(`${path.resolve(absPath)}:${stat.mtimeMs}:${stat.size}`)
    .digest('hex').slice(0, 16);
}

function getCacheKey(absPath) {
  try {
    return hashCacheKey(absPath, fs.statSync(absPath));
  } catch {
    return null;
  }
}

function getCacheDir(storageDir) {
  return path.join(storageDir, CACHE_DIR_NAME);
}

function getStaticCacheDbPath(storageDir) {
  return path.join(getCacheDir(storageDir), CACHE_DB_NAME);
}

function getCacheScriptPath(root) {
  const base = getExtensionPath() || root;
  return path.join(base, 'backends', 'static', 'cache', 'cache_index.py');
}

function buildCacheStoreCall(storageDir, args) {
  const extensionPath = getExtensionPath();
  const scriptPath = getCacheScriptPath(extensionPath);
  return {
    scriptPath,
    command: resolvePythonExecutable(extensionPath),
    argv: [scriptPath, '--db', getStaticCacheDbPath(storageDir), ...args],
    options: {
      cwd: storageDir,
      env: { ...process.env, PYTHONPATH: extensionPath || storageDir },
      encoding: 'utf8',
      timeout: CACHE_STORE_TIMEOUT_MS,
      maxBuffer: CACHE_STORE_MAX_OUTPUT_BYTES,
    },
  };
}

function parseCacheStoreOutput(stdout) {
  const text = String(stdout || '').trim();
  return text ? JSON.parse(text) : null;
}

function runCacheStore(storageDir, args, { input }: CacheStoreOptions = {}) {
  try {
    const call = buildCacheStoreCall(storageDir, args);
    if (!fs.existsSync(call.scriptPath)) return null;
    fs.mkdirSync(getCacheDir(storageDir), { recursive: true });
    const result = cp.spawnSync(call.command, call.argv, { ...call.options, input });
    if (result.error || result.status !== 0) return null;
    return parseCacheStoreOutput(result.stdout);
  } catch {
    return null;
  }
}

function execCacheStore(call, input): Promise<string> {
  return new Promise((resolve, reject) => {
    const child = cp.execFile(call.command, call.argv, call.options, (error, stdout) => {
      if (error) reject(error);
      else resolve(stdout);
    });
    // The child may exit before reading stdin (EPIPE); its exit status is what gets reported.
    child.stdin?.on('error', (err) => logDebug(`[static-cache] stdin : ${err?.message || err}`));
    child.stdin?.end(input ?? '');
  });
}

async function runCacheStoreAsync(storageDir, args, { input }: CacheStoreOptions = {}) {
  const call = buildCacheStoreCall(storageDir, args);
  try {
    await fs.promises.access(call.scriptPath);
    await fs.promises.mkdir(getCacheDir(storageDir), { recursive: true });
    return parseCacheStoreOutput(await execCacheStore(call, input));
  } catch (err) {
    logDebug(`[static-cache] ${args[0]} en échec : ${err?.message || err}`);
    return null;
  }
}

const cacheQueues = new Map();

function enqueueCacheTask(storageDir, task) {
  const dbPath = getStaticCacheDbPath(storageDir);
  let queue = cacheQueues.get(dbPath);
  if (!queue) {
    queue = createBoundedSerialQueue(CACHE_QUEUE_LIMIT);
    cacheQueues.set(dbPath, queue);
  }
  return queue.push(task).catch((err) => {
    if (err?.code !== QUEUE_FULL_CODE) throw err;
    logWarning(`[static-cache] ${err.message} : opération ignorée`);
    return null;
  });
}

function cacheVariant(type, options: CacheVariantOptions = {}) {
  if (type !== 'strings') return '';
  const enc = String(options.encoding || 'utf-8').replace(/[^a-z0-9-]/gi, '_');
  const section = String(options.section || '').replace(/[^a-z0-9._-]/gi, '_') || 'all';
  return `${options.minLen || 4}_${enc}_${section}_v2`;
}

function getArgs(key, type, options) {
  return ['get', '--namespace', type, '--cache-key', key, '--variant', cacheVariant(type, options)];
}

function putArgs(absPath, key, stat, type, options) {
  return [
    'put', '--namespace', type, '--cache-key', key,
    '--variant', cacheVariant(type, options),
    '--binary-path', path.resolve(absPath),
    '--binary-mtime-ms', String(stat.mtimeMs),
    '--binary-size', String(stat.size),
  ];
}

function readCache(storageDir, absPath, type, options: CacheVariantOptions = {}) {
  const key = getCacheKey(absPath);
  if (!key) return null;
  const result = runCacheStore(storageDir, getArgs(key, type, options));
  return result?.found === true ? result.payload : null;
}

function writeCache(storageDir, absPath, type, data, options: CacheVariantOptions = {}) {
  const key = getCacheKey(absPath);
  if (!key) return false;
  try {
    const stat = fs.statSync(absPath);
    const result = runCacheStore(storageDir, putArgs(absPath, key, stat, type, options), {
      input: JSON.stringify(data),
    });
    return result?.stored === true;
  } catch {
    return false;
  }
}

async function statCacheTarget(absPath) {
  try {
    const stat = await fs.promises.stat(absPath);
    return { stat, key: hashCacheKey(absPath, stat) };
  } catch {
    return null;
  }
}

// Captured synchronously at submission (two cheap syscalls, no Python): an async stat could
// resolve after the binary is replaced and file the caller's data under the new binary's key.
function captureWriteTarget(absPath) {
  try {
    const stat = fs.statSync(absPath);
    return { stat, key: hashCacheKey(absPath, stat), identity: binaryIdentitySync(absPath) };
  } catch {
    return null;
  }
}

async function storeQueuedWrite(storageDir, absPath, submission, putOptions) {
  const { target } = submission;
  if (!target) return false;
  const current = await statCacheTarget(absPath);
  if (current?.key !== target.key) {
    logDebug(`[static-cache] put ignoré : binaire modifié pendant l'attente (${absPath})`);
    return false;
  }
  const dbPath = getStaticCacheDbPath(storageDir);
  if (isInvalidatedSince(dbPath, target.identity, submission.seq)) return false;
  const args = putArgs(absPath, target.key, target.stat, putOptions.type, putOptions.options);
  const result = await runCacheStoreAsync(storageDir, args, { input: JSON.stringify(putOptions.data) });
  if (isInvalidatedSince(dbPath, target.identity, submission.seq)) {
    // A clear/delete ran while this put was in flight and may have committed before it.
    await runCacheStoreAsync(storageDir, deleteBinaryArgs(target.identity));
    return false;
  }
  return result?.stored === true;
}

/** Non-blocking readCache; queued after every earlier async read or write on the same database. */
function readCacheAsync(storageDir, absPath, type, options: CacheVariantOptions = {}) {
  return enqueueCacheTask(storageDir, async () => {
    const target = await statCacheTarget(absPath);
    if (!target) return null;
    const result = await runCacheStoreAsync(storageDir, getArgs(target.key, type, options));
    return result?.found === true ? result.payload : null;
  });
}

/** Non-blocking writeCache; resolves false (never rejects) when the entry is not stored. */
function writeCacheAsync(storageDir, absPath, type, data, options: CacheVariantOptions = {}) {
  const submission = { seq: currentInvalidationSeq(), target: captureWriteTarget(absPath) };
  return enqueueCacheTask(storageDir, () => (
    storeQueuedWrite(storageDir, absPath, submission, { type, data, options })
  )).then((stored) => stored === true, (err) => {
    // JSON.stringify may throw (cycle, BigInt): same outcome as writeCache, but logged.
    logDebug(`[static-cache] put en échec : ${err?.message || err}`);
    return false;
  });
}

function listCacheEntries(storageDir) {
  const payload = runCacheStore(storageDir, ['list']);
  return Array.isArray(payload?.entries) ? payload.entries : [];
}

function pruneCacheEntries(storageDir) {
  return Number(runCacheStore(storageDir, ['prune'])?.removed || 0);
}

function deleteBinaryArgs(binaryPath) {
  return ['delete-binary', '--binary-path', path.resolve(binaryPath)];
}

function clearCacheEntries(storageDir) {
  markInvalidated(getStaticCacheDbPath(storageDir));
  return Number(runCacheStore(storageDir, ['clear'])?.removed || 0);
}

function deleteCacheEntriesForBinary(storageDir, binaryPath) {
  markInvalidated(getStaticCacheDbPath(storageDir), binaryIdentitySync(binaryPath));
  return Number(runCacheStore(storageDir, deleteBinaryArgs(binaryPath))?.removed || 0);
}

module.exports = {
  readCache,
  writeCache,
  readCacheAsync,
  writeCacheAsync,
  getCacheKey,
  getCacheDir,
  getStaticCacheDbPath,
  listCacheEntries,
  pruneCacheEntries,
  clearCacheEntries,
  deleteCacheEntriesForBinary,
  CACHE_QUEUE_LIMIT,
};
