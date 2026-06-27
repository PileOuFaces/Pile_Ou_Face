// SPDX-License-Identifier: AGPL-3.0-only
// @ts-nocheck
/**
 * Helpers for choosing user-facing symbols without tying binary semantics to the
 * host OS running VS Code.
 */

function formatText(binaryInfoOrFormat = '') {
  if (typeof binaryInfoOrFormat === 'string') return binaryInfoOrFormat;
  return String(binaryInfoOrFormat?.format || binaryInfoOrFormat?.type || '').trim();
}

function isMachOFormat(binaryInfoOrFormat = '') {
  return /mach/i.test(formatText(binaryInfoOrFormat));
}

function preferredMainSymbol(binaryInfoOrFormat = '') {
  return isMachOFormat(binaryInfoOrFormat) ? '_main' : 'main';
}

function mainSymbolCandidates(binaryInfoOrFormat = '') {
  return isMachOFormat(binaryInfoOrFormat) ? ['_main', 'main'] : ['main', '_main'];
}

function symbolLookupCandidates(symbolName, binaryInfoOrFormat = '') {
  const raw = String(symbolName || '').trim();
  if (!raw) return [];
  if (raw === '__entry__') return [raw];

  const candidates = [];
  const push = (value) => {
    if (value && !candidates.includes(value)) candidates.push(value);
  };

  if (isMachOFormat(binaryInfoOrFormat)) {
    push(raw.startsWith('_') ? raw : `_${raw}`);
    push(raw);
  } else {
    if (raw === '_main') push('main');
    else if (raw.startsWith('_') && raw !== '_start') push(raw.slice(1));
    push(raw);
  }

  return candidates;
}

function normalizeStartSymbolForBinary(symbolName, binaryInfoOrFormat = '') {
  const raw = String(symbolName || '').trim() || preferredMainSymbol(binaryInfoOrFormat);
  if (raw === '__entry__') return raw;
  if (isMachOFormat(binaryInfoOrFormat)) {
    return raw.startsWith('_') ? raw : `_${raw}`;
  }
  if (raw === '_main') return 'main';
  return raw;
}

function findSymbolByCandidates(symbols, candidates) {
  const list = Array.isArray(symbols) ? symbols : [];
  for (const candidate of candidates || []) {
    const match = list.find((sym) => String(sym?.name || '') === candidate);
    if (match) return match.name;
  }
  return '';
}

module.exports = {
  findSymbolByCandidates,
  isMachOFormat,
  mainSymbolCandidates,
  normalizeStartSymbolForBinary,
  preferredMainSymbol,
  symbolLookupCandidates,
};
