// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/** SQLite-only, bounded cache for static-analysis results. */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { getExtensionPath } = require('./utils');

const CACHE_DIR_NAME = 'static_cache';
const CACHE_DB_NAME = 'static-cache.sqlite3';

function getCacheKey(absPath) {
  try {
    const stat = fs.statSync(absPath);
    return crypto.createHash('sha256')
      .update(`${path.resolve(absPath)}:${stat.mtimeMs}:${stat.size}`)
      .digest('hex').slice(0, 16);
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

function detectPythonExecutable(root) {
  const base = getExtensionPath() || root;
  const candidates = [
    path.join(base, 'backends', '.venv', 'bin', 'python3'),
    path.join(base, 'backends', '.venv', 'Scripts', 'python.exe'),
    path.join(base, 'backends', '.venv', 'Scripts', 'python'),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) || 'python3';
}

function runCacheStore(storageDir, args, { input } = {}) {
  try {
    const extensionPath = getExtensionPath();
    const scriptPath = getCacheScriptPath(extensionPath);
    if (!fs.existsSync(scriptPath)) return null;
    fs.mkdirSync(getCacheDir(storageDir), { recursive: true });
    const result = cp.spawnSync(
      detectPythonExecutable(extensionPath),
      [scriptPath, '--db', getStaticCacheDbPath(storageDir), ...args],
      {
        cwd: storageDir,
        env: { ...process.env, PYTHONPATH: extensionPath || storageDir },
        encoding: 'utf8',
        input,
        timeout: 10000,
      }
    );
    if (result.error || result.status !== 0) return null;
    const stdout = String(result.stdout || '').trim();
    return stdout ? JSON.parse(stdout) : null;
  } catch {
    return null;
  }
}

function cacheVariant(type, options = {}) {
  if (type !== 'strings') return '';
  const enc = String(options.encoding || 'utf-8').replace(/[^a-z0-9-]/gi, '_');
  const section = String(options.section || '').replace(/[^a-z0-9._-]/gi, '_') || 'all';
  return `${options.minLen || 4}_${enc}_${section}_v2`;
}

function readCache(storageDir, absPath, type, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return null;
  const result = runCacheStore(storageDir, [
    'get', '--namespace', type, '--cache-key', key, '--variant', cacheVariant(type, options),
  ]);
  return result?.found === true ? result.payload : null;
}

function writeCache(storageDir, absPath, type, data, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return false;
  try {
    const stat = fs.statSync(absPath);
    const result = runCacheStore(storageDir, [
      'put', '--namespace', type, '--cache-key', key,
      '--variant', cacheVariant(type, options),
      '--binary-path', path.resolve(absPath),
      '--binary-mtime-ms', String(stat.mtimeMs),
      '--binary-size', String(stat.size),
    ], { input: JSON.stringify(data) });
    return result?.stored === true;
  } catch {
    return false;
  }
}

function listCacheEntries(storageDir) {
  const payload = runCacheStore(storageDir, ['list']);
  return Array.isArray(payload?.entries) ? payload.entries : [];
}

function pruneCacheEntries(storageDir) {
  return Number(runCacheStore(storageDir, ['prune'])?.removed || 0);
}

function clearCacheEntries(storageDir) {
  return Number(runCacheStore(storageDir, ['clear'])?.removed || 0);
}

function deleteCacheEntriesForBinary(storageDir, binaryPath) {
  return Number(runCacheStore(storageDir, [
    'delete-binary', '--binary-path', path.resolve(binaryPath),
  ])?.removed || 0);
}

module.exports = {
  readCache,
  writeCache,
  getCacheKey,
  getCacheDir,
  getStaticCacheDbPath,
  listCacheEntries,
  pruneCacheEntries,
  clearCacheEntries,
  deleteCacheEntriesForBinary,
};
