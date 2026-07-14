// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * @file logger.ts
 * @brief Logique pure du logger à niveaux (extension). Pas de dépendance vscode
 * pour rester testable sans mock — voir shared/utils.ts pour le branchement
 * sur l'OutputChannel réel.
 */

const LEVELS = ['debug', 'info', 'warning', 'error'];
const DEFAULT_LEVEL = 'warning';

let currentLevel = DEFAULT_LEVEL;

function normalizeLevel(level) {
  const value = String(level || '').trim().toLowerCase();
  return LEVELS.includes(value) ? value : DEFAULT_LEVEL;
}

function setLevel(level) {
  currentLevel = normalizeLevel(level);
}

function getLevel() {
  return currentLevel;
}

function shouldLog(level) {
  const idx = LEVELS.indexOf(normalizeLevel(level));
  const currentIdx = LEVELS.indexOf(currentLevel);
  return idx >= currentIdx;
}

function formatLine(level, message) {
  const time = new Date().toTimeString().slice(0, 8);
  return `[${time}] [${normalizeLevel(level).toUpperCase()}] ${message}`;
}

// Règle transverse : jamais de secret en log, quel que soit le niveau.
const REDACTION_PATTERNS = [
  // JWT-like tokens (header.payload.signature, base64url segments).
  { pattern: /[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, replacement: '[REDACTED_JWT]' },
  // PEM blocks (private keys, certs, licenses signés).
  { pattern: /-----BEGIN [^-]+-----[\s\S]+?-----END [^-]+-----/g, replacement: '[REDACTED_PEM]' },
  // key=value / key: value pour password/token/secret/content_key,
  // même avec préfixe/suffixe applicatif.
  { pattern: /((?:[A-Za-z0-9_-]*(?:password|token|secret|content[_-]?key)[A-Za-z0-9_-]*)\s*[:=]\s*)\S+/gi, replacement: '$1[REDACTED]' },
];

function redact(text) {
  const value = String(text ?? '');
  return REDACTION_PATTERNS.reduce((acc, { pattern, replacement }) => acc.replace(pattern, replacement), value);
}

function mapLevelToEnv(level) {
  return normalizeLevel(level).toUpperCase();
}

module.exports = {
  LEVELS,
  DEFAULT_LEVEL,
  setLevel,
  getLevel,
  shouldLog,
  formatLine,
  redact,
  mapLevelToEnv,
};
