// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file recentBinaries.js
 * @brief Historique des fichiers de travail pour l'ouverture rapide.
 */

const path = require('path');

const RECENT_BINARIES_KEY = 'reverse-workspace.recent-binaries';
const MAX_RECENT_BINARIES = 8;

function normalizeBinaryMeta(meta) {
  if (!meta || typeof meta !== 'object') return null;
  const kind = meta.kind === 'raw' ? 'raw' : 'native';
  const normalized = {
    kind,
    format: String(meta.format || (kind === 'raw' ? 'RAW' : '')).trim(),
    arch: String(meta.arch || '').trim(),
  };
  if (kind === 'raw') {
    const rawConfig = meta.rawConfig && typeof meta.rawConfig === 'object'
      ? {
          arch: String(meta.rawConfig.arch || meta.arch || '').trim(),
          endian: String(meta.rawConfig.endian || '').trim() || 'little',
          baseAddr: String(meta.rawConfig.baseAddr || '').trim() || '0x0',
        }
      : null;
    if (!rawConfig?.arch) return null;
    normalized.rawConfig = rawConfig;
    normalized.arch = normalized.arch || rawConfig.arch;
    normalized.format = 'RAW';
  }
  return normalized;
}

function normalizeRecentBinaryEntry(entry) {
  if (!entry || typeof entry !== 'object') return null;
  const targetPath = String(entry.path || '').trim();
  if (!targetPath) return null;
  const ts = Number(entry.ts);
  return {
    path: path.resolve(targetPath),
    meta: normalizeBinaryMeta(entry.meta || null),
    ts: Number.isFinite(ts) ? ts : Date.now(),
  };
}

function getRecentBinaries(context) {
  const raw = context?.workspaceState?.get(RECENT_BINARIES_KEY, []);
  if (!Array.isArray(raw)) return [];
  return raw
    .map((entry) => normalizeRecentBinaryEntry(entry))
    .filter(Boolean)
    .slice(0, MAX_RECENT_BINARIES);
}

async function setRecentBinaries(context, entries) {
  const normalized = Array.isArray(entries)
    ? entries
      .map((entry) => normalizeRecentBinaryEntry(entry))
      .filter(Boolean)
      .slice(0, MAX_RECENT_BINARIES)
    : [];
  await context.workspaceState.update(RECENT_BINARIES_KEY, normalized);
  return normalized;
}

async function rememberRecentBinary(context, binaryPath, binaryMeta) {
  const entry = normalizeRecentBinaryEntry({
    path: binaryPath,
    meta: binaryMeta,
    ts: Date.now(),
  });
  if (!entry) return getRecentBinaries(context);
  const next = [
    entry,
    ...getRecentBinaries(context).filter((item) => item.path !== entry.path),
  ].slice(0, MAX_RECENT_BINARIES);
  return setRecentBinaries(context, next);
}

async function forgetRecentBinary(context, binaryPath) {
  const targetPath = String(binaryPath || '').trim();
  if (!targetPath) return getRecentBinaries(context);
  const normalizedTarget = path.resolve(targetPath);
  const next = getRecentBinaries(context).filter((entry) => entry.path !== normalizedTarget);
  return setRecentBinaries(context, next);
}

async function clearRecentBinaries(context) {
  return setRecentBinaries(context, []);
}

function describeRecentBinaryMeta(meta) {
  if (!meta || typeof meta !== 'object') return 'Fichier déjà analysé';
  const parts = [];
  if (meta.kind === 'raw') parts.push('blob brut');
  if (meta.format) parts.push(String(meta.format));
  const arch = meta.kind === 'raw'
    ? String(meta.rawConfig?.arch || meta.arch || '').trim()
    : String(meta.arch || '').trim();
  if (arch) parts.push(arch);
  return parts.join(' · ') || 'Fichier déjà analysé';
}

module.exports = {
  RECENT_BINARIES_KEY,
  MAX_RECENT_BINARIES,
  normalizeBinaryMeta,
  normalizeRecentBinaryEntry,
  getRecentBinaries,
  setRecentBinaries,
  rememberRecentBinary,
  forgetRecentBinary,
  clearRecentBinaries,
  describeRecentBinaryMeta,
};
