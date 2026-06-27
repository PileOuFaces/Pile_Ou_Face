// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file staticCache.js
 * @brief Cache persistant pour l'analyse statique (sections, infos, symboles, strings, CFG).
 * Similaire à Cutter : évite de relancer les outils à chaque ouverture d'onglet.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cp = require('child_process');
const { getExtensionPath } = require('./utils');

const CACHE_DIR_NAME = 'static_cache';
const META_FILE = 'meta.json';
const CACHE_INDEX_DB = 'cache-index.sqlite3';

/**
 * Génère une clé de cache à partir du chemin absolu et des métadonnées du fichier.
 * Invalide automatiquement si le binaire change (mtime, size).
 */
function getCacheKey(absPath) {
  try {
    const stat = fs.statSync(absPath);
    const input = `${absPath}:${stat.mtimeMs}:${stat.size}`;
    return crypto.createHash('sha256').update(input).digest('hex').slice(0, 16);
  } catch {
    return null;
  }
}

/**
 * Retourne le répertoire de cache pour un workspace.
 */
function getCacheDir(root) {
  return path.join(root, '.pile-ou-face', CACHE_DIR_NAME);
}

function getCacheIndexDbPath(root) {
  return path.join(getCacheDir(root), CACHE_INDEX_DB);
}

function getCacheIndexScriptPath(root) {
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

function runCacheIndex(root, args, { parseJson = true } = {}) {
  try {
    const scriptPath = getCacheIndexScriptPath(root);
    if (!fs.existsSync(scriptPath)) return null;
    const pythonExe = detectPythonExecutable(root);
    const result = cp.spawnSync(
      pythonExe,
      [scriptPath, '--db', getCacheIndexDbPath(root), ...args],
      {
        cwd: root,
        env: { ...process.env, PYTHONPATH: root },
        encoding: 'utf8',
        timeout: 10000,
      }
    );
    if (result.error || result.status !== 0) return null;
    const stdout = String(result.stdout || '').trim();
    if (!parseJson) return stdout;
    return stdout ? JSON.parse(stdout) : null;
  } catch {
    return null;
  }
}

/**
 * Lit le fichier meta.json pour vérifier la validité du cache.
 */
function readMeta(cacheDir, key) {
  const metaPath = path.join(cacheDir, key, META_FILE);
  try {
    const raw = fs.readFileSync(metaPath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Vérifie si le cache est valide pour le binaire.
 */
function isCacheValid(cacheDir, key, absPath) {
  const meta = readMeta(cacheDir, key);
  if (!meta) return false;
  try {
    const stat = fs.statSync(absPath);
    return meta.mtimeMs === stat.mtimeMs && meta.size === stat.size && meta.path === absPath;
  } catch {
    return false;
  }
}

/**
 * Lit les données en cache. Retourne null si absent ou invalide.
 * @param {string} root - Racine du workspace
 * @param {string} absPath - Chemin absolu du binaire
 * @param {string} type - 'sections' | 'info' | 'symbols' | 'strings' | 'cfg'
 * @param {object} options - Pour strings: { minLen }
 */
function readCache(root, absPath, type, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return null;

  const cacheDir = getCacheDir(root);
  if (!isCacheValid(cacheDir, key, absPath)) return null;

  let file = type;
  if (type === 'strings') {
    const enc = options.encoding || 'utf-8';
    const sec = (options.section || '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'all';
    file = `strings_${options.minLen || 4}_${enc.replace(/[^a-z0-9-]/g, '_')}_${sec}`;
  }
  const cachePath = path.join(cacheDir, key, `${file}.json`);
  try {
    const raw = fs.readFileSync(cachePath, 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Écrit les données en cache.
 */
function writeCache(root, absPath, type, data, options = {}) {
  const key = getCacheKey(absPath);
  if (!key) return;

  const cacheDir = getCacheDir(root);
  const keyDir = path.join(cacheDir, key);
  if (!fs.existsSync(keyDir)) {
    fs.mkdirSync(keyDir, { recursive: true });
  }

  try {
    const stat = fs.statSync(absPath);
    const meta = { path: absPath, mtimeMs: stat.mtimeMs, size: stat.size };
    fs.writeFileSync(path.join(keyDir, META_FILE), JSON.stringify(meta, null, 2), 'utf8');

    let file = type;
    if (type === 'strings') {
      const enc = options.encoding || 'utf-8';
      const sec = (options.section || '').replace(/[^a-zA-Z0-9._-]/g, '_') || 'all';
      file = `strings_${options.minLen || 4}_${enc.replace(/[^a-z0-9-]/g, '_')}_${sec}`;
    }
    const cachePath = path.join(keyDir, `${file}.json`);
    fs.writeFileSync(cachePath, JSON.stringify(data), 'utf8');
    const cacheStat = fs.statSync(cachePath);
    runCacheIndex(root, [
      'upsert',
      '--workspace-root', path.resolve(root),
      '--cache-key', key,
      '--binary-path', path.resolve(absPath),
      '--cache-type', type,
      '--cache-file', `${file}.json`,
      '--cache-path', cachePath,
      '--cache-dir', keyDir,
      '--payload-bytes', String(cacheStat.size),
      '--binary-mtime-ms', String(stat.mtimeMs),
      '--binary-size', String(stat.size),
      '--updated-at-ms', String(cacheStat.mtimeMs),
    ], { parseJson: false });
  } catch (err) {
    // Silently ignore cache write errors
  }
}

function listIndexedCacheEntries(root) {
  const payload = runCacheIndex(root, ['list', '--workspace-root', path.resolve(root)]);
  return Array.isArray(payload?.entries) ? payload.entries : null;
}

function pruneIndexedCacheEntries(root) {
  const payload = runCacheIndex(root, ['prune', '--workspace-root', path.resolve(root)]);
  return Number(payload?.removed || 0);
}

function clearIndexedCacheEntries(root) {
  const payload = runCacheIndex(root, ['clear', '--workspace-root', path.resolve(root)]);
  return Number(payload?.removed || 0);
}

module.exports = {
  readCache,
  writeCache,
  getCacheKey,
  getCacheDir,
  getCacheIndexDbPath,
  readMeta,
  listIndexedCacheEntries,
  pruneIndexedCacheEntries,
  clearIndexedCacheEntries,
};
