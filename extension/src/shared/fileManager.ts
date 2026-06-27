// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file fileManager.js
 * @brief Gestion centralisée des fichiers générés (.pile-ou-face/).
 * Artifacts (disasm, traces), cache statique, purge automatique.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const {
  getCacheDir,
  readMeta,
  listIndexedCacheEntries,
  pruneIndexedCacheEntries,
} = require('./staticCache');

const ARTIFACTS_DIR = '.pile-ou-face';
const CACHE_DIR_NAME = 'static_cache';
const DECOMPILE_CACHE_DIR_NAME = 'decompile_cache';
const ANNOTATIONS_DIR_NAME = 'annotations';
const PATCHES_DIR_NAME = 'patches';
const PFDB_DIR_NAME = 'pfdb';
const MANIFEST_FILE = 'manifest.json';
const META_FILE = 'meta.json';

// Fichiers/dossiers dans .pile-ou-face/ qui ne doivent JAMAIS être supprimés
// par le clean — configuration utilisateur persistante.
const PROTECTED_NAMES = new Set([
  'decompilers.json',
  'compilers.json',
  'licenses',
  'plugins',
  'annotations',
  'patches',
  'pfdb',
]);

/**
 * Retourne le chemin du dossier pile-ou-face.
 */
function getBaseDir(root) {
  return path.resolve(root, ARTIFACTS_DIR);
}

/**
 * Calcule la taille d'un fichier ou répertoire (récursif).
 */
function getSize(p) {
  try {
    const stat = fs.statSync(p);
    if (stat.isDirectory()) {
      let total = 0;
      for (const name of fs.readdirSync(p)) {
        total += getSize(path.join(p, name));
      }
      return total;
    }
    return stat.size;
  } catch {
    return 0;
  }
}

/**
 * Supprime récursivement un fichier ou dossier.
 */
function removeRecursive(p) {
  if (!fs.existsSync(p)) return;
  const stat = fs.statSync(p);
  if (stat.isDirectory()) {
    for (const name of fs.readdirSync(p)) {
      removeRecursive(path.join(p, name));
    }
    fs.rmdirSync(p);
  } else {
    fs.unlinkSync(p);
  }
}

function hash16(input) {
  return crypto.createHash('sha256').update(String(input)).digest('hex').slice(0, 16);
}

function sanitizePfdbFilename(name) {
  const safe = String(name || '').split('').map((ch) => (/[a-z0-9._-]/i.test(ch) ? ch : '_')).join('');
  return safe || 'binary';
}

function listWorkspaceFiles(root) {
  const results = [];
  const excludedDirs = new Set([
    '.pile-ou-face',
    '.git',
    'node_modules',
    'graphify-out',
    '.venv',
    '__pycache__',
  ]);
  const walk = (dirPath) => {
    if (!fs.existsSync(dirPath)) return;
    for (const name of fs.readdirSync(dirPath)) {
      const fullPath = path.join(dirPath, name);
      let stat;
      try {
        stat = fs.statSync(fullPath);
      } catch {
        continue;
      }
      if (stat.isDirectory()) {
        if (excludedDirs.has(name)) continue;
        walk(fullPath);
        continue;
      }
      results.push({
        path: path.resolve(fullPath),
        mtimeMs: stat.mtimeMs,
        size: stat.size,
        name: path.basename(fullPath),
      });
    }
  };
  walk(path.resolve(root));
  return results;
}

function buildWorkspaceStateFingerprints(root) {
  const files = listWorkspaceFiles(root);
  const annotationKeys = new Set();
  const patchKeys = new Set();
  const pfdbNames = new Set();
  for (const file of files) {
    annotationKeys.add(hash16(`${file.path}:${file.mtimeMs}:${file.size}`));
    patchKeys.add(hash16(file.path));
    pfdbNames.add(`${sanitizePfdbFilename(file.name)}.${hash16(file.path)}.pfdb`);
  }
  return { files, annotationKeys, patchKeys, pfdbNames };
}

function readJsonFile(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return null;
  }
}

function purgeStaleAnnotations(root, fingerprints) {
  const dir = path.join(getBaseDir(root), ANNOTATIONS_DIR_NAME);
  if (!fs.existsSync(dir)) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const key = name.replace(/\.json$/i, '');
    if (!fingerprints.annotationKeys.has(key)) {
      removeRecursive(path.join(dir, name));
      removed++;
    }
  }
  return removed;
}

function purgeStalePatches(root, fingerprints) {
  const dir = path.join(getBaseDir(root), PATCHES_DIR_NAME);
  if (!fs.existsSync(dir)) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const fullPath = path.join(dir, name);
    const key = name.replace(/\.json$/i, '');
    const payload = readJsonFile(fullPath);
    const binaryPath = String(payload?.binary || '').trim();
    const expectedKey = binaryPath ? hash16(path.resolve(binaryPath)) : '';
    const keep = expectedKey && key === expectedKey && fingerprints.patchKeys.has(expectedKey) && fs.existsSync(binaryPath);
    if (!keep) {
      removeRecursive(fullPath);
      removed++;
    }
  }
  return removed;
}

function purgeStaleDecompileCache(root) {
  const dir = path.join(getBaseDir(root), DECOMPILE_CACHE_DIR_NAME);
  if (!fs.existsSync(dir)) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(dir)) {
    if (!name.endsWith('.json')) continue;
    const fullPath = path.join(dir, name);
    const payload = readJsonFile(fullPath);
    const meta = payload?._cache_meta;
    if (!meta || typeof meta !== 'object') {
      removeRecursive(fullPath);
      removed++;
      continue;
    }
    const binaryPath = String(meta.binary_path || '').trim();
    if (!binaryPath || !fs.existsSync(binaryPath)) {
      removeRecursive(fullPath);
      removed++;
      continue;
    }
    try {
      const stat = fs.statSync(binaryPath);
      const sameMtime = Math.abs(Number(meta.binary_mtime_ms || 0) - Number(stat.mtimeMs || 0)) <= 0.001;
      const sameSize = Number(meta.binary_size || -1) === Number(stat.size || -2);
      if (!sameMtime || !sameSize) {
        removeRecursive(fullPath);
        removed++;
      }
    } catch {
      removeRecursive(fullPath);
      removed++;
    }
  }
  return removed;
}

function purgeStalePfdb(root, fingerprints) {
  const dir = path.join(getBaseDir(root), PFDB_DIR_NAME);
  if (!fs.existsSync(dir)) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(dir)) {
    const fullPath = path.join(dir, name);
    if (name.endsWith('.pfdb-journal')) {
      const basePath = fullPath.slice(0, -'-journal'.length);
      if (!fs.existsSync(basePath)) {
        removeRecursive(fullPath);
        removed++;
      }
      continue;
    }
    if (!name.endsWith('.pfdb')) continue;
    if (!fingerprints.pfdbNames.has(name)) {
      removeRecursive(fullPath);
      removed++;
      const journalPath = `${fullPath}-journal`;
      if (fs.existsSync(journalPath)) removeRecursive(journalPath);
    }
  }
  return removed;
}

function cleanupArtifactsForBinary(root, binaryPath) {
  const baseDir = getBaseDir(root);
  if (!fs.existsSync(baseDir)) return 0;
  const baseName = path.basename(String(binaryPath || '').trim());
  if (!baseName) return 0;
  let removed = 0;
  for (const name of fs.readdirSync(baseDir)) {
    if (PROTECTED_NAMES.has(name) || name === MANIFEST_FILE || name === CACHE_DIR_NAME) continue;
    if (name !== baseName && !name.startsWith(`${baseName}.`)) continue;
    const fullPath = path.join(baseDir, name);
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) continue;
    removeRecursive(fullPath);
    removed++;
  }
  return removed;
}

function cleanupCacheEntriesForBinary(root, binaryPath) {
  const target = path.resolve(String(binaryPath || '').trim());
  if (!target) return 0;
  let removed = 0;
  const seenPaths = new Set();
  for (const entry of listCacheEntries(root)) {
    const entryBinaryPath = String(entry?.binaryPath || '').trim();
    const entryPath = String(entry?.path || '').trim();
    if (!entryBinaryPath || !entryPath) continue;
    if (path.resolve(entryBinaryPath) !== target) continue;
    if (seenPaths.has(entryPath) || !fs.existsSync(entryPath)) continue;
    seenPaths.add(entryPath);
    removeRecursive(entryPath);
    removed++;
  }
  if (removed > 0) pruneIndexedCacheEntries(root);
  return removed;
}

function cleanupSupportFilesForBinary(root, binaryPath) {
  const target = path.resolve(String(binaryPath || '').trim());
  if (!target) return 0;
  const baseDir = getBaseDir(root);
  let removed = 0;

  const decompileDir = path.join(baseDir, DECOMPILE_CACHE_DIR_NAME);
  if (fs.existsSync(decompileDir)) {
    for (const name of fs.readdirSync(decompileDir)) {
      if (!name.endsWith('.json')) continue;
      const fullPath = path.join(decompileDir, name);
      const payload = readJsonFile(fullPath);
      const binaryPathInCache = String(payload?._cache_meta?.binary_path || '').trim();
      if (binaryPathInCache && path.resolve(binaryPathInCache) === target) {
        removeRecursive(fullPath);
        removed++;
      }
    }
  }

  const patchesDir = path.join(baseDir, PATCHES_DIR_NAME);
  if (fs.existsSync(patchesDir)) {
    for (const name of fs.readdirSync(patchesDir)) {
      if (!name.endsWith('.json')) continue;
      const fullPath = path.join(patchesDir, name);
      const payload = readJsonFile(fullPath);
      const patchBinaryPath = String(payload?.binary || '').trim();
      if (patchBinaryPath && path.resolve(patchBinaryPath) === target) {
        removeRecursive(fullPath);
        removed++;
      }
    }
  }

  const pfdbDir = path.join(baseDir, PFDB_DIR_NAME);
  if (fs.existsSync(pfdbDir)) {
    const pfdbName = `${sanitizePfdbFilename(path.basename(target))}.${hash16(target)}.pfdb`;
    const pfdbPath = path.join(pfdbDir, pfdbName);
    if (fs.existsSync(pfdbPath)) {
      removeRecursive(pfdbPath);
      removed++;
    }
    const journalPath = `${pfdbPath}-journal`;
    if (fs.existsSync(journalPath)) {
      removeRecursive(journalPath);
      removed++;
    }
  }

  return removed;
}

/**
 * Liste les artifacts (disasm, symbols, etc.) à la racine de .pile-ou-face/.
 */
function listArtifacts(root) {
  const baseDir = getBaseDir(root);
  const items = [];
  if (!fs.existsSync(baseDir)) return items;
  for (const name of fs.readdirSync(baseDir)) {
    if (PROTECTED_NAMES.has(name) || name === MANIFEST_FILE || name === CACHE_DIR_NAME) continue;
    const fullPath = path.join(baseDir, name);
    if (fs.statSync(fullPath).isFile()) {
      const ext = path.extname(name);
      const base = path.basename(name, ext);
      let type = 'artifact';
      if (name.endsWith('.disasm.asm')) type = 'disasm';
      else if (name.endsWith('.disasm.mapping.json')) type = 'mapping';
      else if (name.endsWith('.symbols.json')) type = 'symbols';
      else if (name === 'output.json') type = 'trace';
      else if (name === 'input.asm') type = 'input';
      items.push({
        name,
        path: fullPath,
        type,
        binary: base.replace(/\.(disasm|symbols)$/, ''),
        size: getSize(fullPath),
        mtime: fs.statSync(fullPath).mtimeMs,
      });
    }
  }
  return items.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Liste les entrées du cache statique (static_cache/).
 */
function listCacheEntries(root) {
  const indexedEntries = listIndexedCacheEntries(root);
  if (Array.isArray(indexedEntries)) {
    return indexedEntries.sort((a, b) => Number(b.mtime || 0) - Number(a.mtime || 0));
  }
  const cacheDir = getCacheDir(root);
  const items = [];
  if (!fs.existsSync(cacheDir)) return items;
  for (const key of fs.readdirSync(cacheDir)) {
    const keyDir = path.join(cacheDir, key);
    if (!fs.statSync(keyDir).isDirectory()) continue;
    const meta = readMeta(cacheDir, key);
    const binaryPath = meta?.path || '—';
    let binaryExists = false;
    let status = 'missing';
    if (meta?.path && fs.existsSync(meta.path)) {
      binaryExists = true;
      try {
        const stat = fs.statSync(meta.path);
        status = (meta.mtimeMs === stat.mtimeMs && meta.size === stat.size) ? 'ok' : 'stale';
      } catch {
        status = 'missing';
      }
    }
    let size = 0;
    const cacheTypes = [];
    for (const f of fs.readdirSync(keyDir)) {
      size += getSize(path.join(keyDir, f));
      if (f !== META_FILE && f.endsWith('.json')) {
        cacheTypes.push(f.replace(/\.json$/i, ''));
      }
    }
    items.push({
      key,
      path: keyDir,
      binaryPath,
      binaryExists,
      status,
      size,
      mtime: meta ? (fs.statSync(path.join(keyDir, 'meta.json')).mtimeMs || 0) : 0,
      cacheTypes: cacheTypes.sort(),
      fileCount: cacheTypes.length,
    });
  }
  return items.sort((a, b) => b.mtime - a.mtime);
}

/**
 * Récupère le résumé complet des fichiers générés.
 */
function listAll(root) {
  const baseDir = getBaseDir(root);
  const artifacts = listArtifacts(root);
  const cacheEntries = listCacheEntries(root);
  const totalSize = getSize(baseDir);
  const staleCache = cacheEntries.filter((e) => String(e.status || '') !== 'ok');
  return {
    baseDir,
    artifacts,
    cache: cacheEntries,
    staleCache,
    totalSize,
    totalFiles: artifacts.length + cacheEntries.reduce((n, e) => n + 1, 0),
  };
}

/**
 * Nettoie les artifacts (fichiers à la racine de .pile-ou-face/).
 * Ne touche pas au cache.
 */
function cleanupArtifacts(root) {
  const baseDir = getBaseDir(root);
  if (!fs.existsSync(baseDir)) return { removed: 0 };
  let removed = 0;
  for (const name of fs.readdirSync(baseDir)) {
    if (PROTECTED_NAMES.has(name)) continue;
    const fullPath = path.join(baseDir, name);
    if (fs.statSync(fullPath).isFile()) {
      removeRecursive(fullPath);
      removed++;
    }
  }
  return { removed };
}

/**
 * Purge le cache obsolète (binaires qui n'existent plus).
 */
function purgeStaleCache(root) {
  const fingerprints = buildWorkspaceStateFingerprints(root);
  const entries = listCacheEntries(root);
  let removed = 0;
  const seenPaths = new Set();
  for (const entry of entries) {
    if (String(entry.status || '') === 'ok') continue;
    const keyDir = String(entry.path || '').trim();
    if (!keyDir || seenPaths.has(keyDir)) continue;
    seenPaths.add(keyDir);
    if (fs.existsSync(keyDir)) {
      removeRecursive(keyDir);
      removed++;
    }
  }
  pruneIndexedCacheEntries(root);
  removed += purgeStaleAnnotations(root, fingerprints);
  removed += purgeStalePatches(root, fingerprints);
  removed += purgeStaleDecompileCache(root);
  removed += purgeStalePfdb(root, fingerprints);
  return { removed };
}

/**
 * Nettoie tout : artifacts + cache.
 */
function cleanupAll(root, options = {}) {
  const { artifactsOnly = false, cacheOnly = false, purgeStale = false } = options;
  let removedArtifacts = 0;
  let removedCache = 0;
  let purgedStale = 0;
  const baseDir = getBaseDir(root);
  const cacheDir = getCacheDir(root);
  if (!cacheOnly && fs.existsSync(baseDir)) {
    for (const name of fs.readdirSync(baseDir)) {
      if (name === CACHE_DIR_NAME) continue;
      if (PROTECTED_NAMES.has(name)) continue;
      const fullPath = path.join(baseDir, name);
      removeRecursive(fullPath);
      removedArtifacts++;
    }
  }
  if (!artifactsOnly && fs.existsSync(cacheDir)) {
    if (purgeStale) {
      for (const entry of listCacheEntries(root)) {
        if (String(entry.status || '') !== 'ok' && fs.existsSync(entry.path)) {
          const keyDir = entry.path;
          removeRecursive(keyDir);
          purgedStale++;
        }
      }
      pruneIndexedCacheEntries(root);
    } else {
      for (const name of fs.readdirSync(cacheDir)) {
        removeRecursive(path.join(cacheDir, name));
        removedCache++;
      }
    }
  }
  return { removedArtifacts, removedCache, purgedStale };
}

function cleanupForBinary(root, binaryPath, options = {}) {
  const { purgeStale = true } = options;
  const removedArtifacts = cleanupArtifactsForBinary(root, binaryPath);
  const removedCache = cleanupCacheEntriesForBinary(root, binaryPath);
  const removedSupport = cleanupSupportFilesForBinary(root, binaryPath);
  const purgedStale = purgeStale ? Number(purgeStaleCache(root).removed || 0) : 0;
  return {
    removedArtifacts,
    removedCache,
    removedSupport,
    purgedStale,
    total: removedArtifacts + removedCache + removedSupport + purgedStale,
  };
}

/**
 * Formatte une taille en octets en format lisible.
 */
function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

module.exports = {
  getBaseDir,
  getSize,
  formatSize,
  listArtifacts,
  listCacheEntries,
  listAll,
  cleanupArtifacts,
  purgeStaleCache,
  cleanupAll,
  cleanupForBinary,
  removeRecursive,
};
