import {
  classifyObservationSeedKind
} from './stackWorkspaceClassification.js';

export const NAMELESS_LABELS = new Set([
  'slot',
  'stack slot',
  'local slot',
  'payload slot',
  'sensitive slot',
  'frame'
]);

export const GENERIC_ARG_RE = /^arg_[0-9a-z]+h?$/i;

export const GENERIC_VAR_RE = /^var_[0-9a-f]+h?$/i;

export const GENERIC_STACK_RE = /^stack_[0-9a-f]+h?$/i;

export const GENERIC_LOCAL_RE = /^local_[0-9a-f]+h?$/i;

export const BUFFER_STYLE_LABEL_RE = /^local_buf_[0-9a-f]+h$/i;

export const SPECIAL_SAVED_BP_RE = /^(saved[_\s-]?(?:e|r)?bp|(?:e|r)?bp)$/i;

export const SPECIAL_RET_RE = /^(ret|ret_addr|return[_\s-]?address|return[_\s-]?addr)$/i;

export const SPECIAL_ARGUMENT_RE = /^(argc|argv|envp)$/i;

export const SPECIAL_ARGUMENT_NAMES = ['argc', 'argv', 'envp'];

export const POINTER_HEX_RE = /^0x[0-9a-f]+$/i;

export const PRINTABLE_ASCII_RE = /[A-Za-z0-9_ ./\\:@$*+-]/;

export const MAIN_ARGUMENT_NAMES = new Map([
  [8, 'argc'],
  [12, 'argv'],
  [16, 'envp']
]);

export const KIND_PRIORITY = {
  return_address: 0,
  saved_bp: 1,
  argument: 2,
  buffer: 3,
  modified: 4,
  local: 5,
  padding: 6,
  unknown: 7,
  slot: 8
};

export const KIND_LABELS = {
  saved_bp: 'saved bp',
  return_address: 'return address',
  argument: 'argument',
  buffer: 'buffer',
  modified: 'modified',
  local: 'local',
  padding: 'padding',
  unknown: 'unknown',
  slot: 'slot'
};

export const SOURCE_PRIORITY = {
  source_c: 540,
  dwarf: 500,
  debug: 480,
  symbol: 470,
  control: 450,
  mcp: 420,
  static: 360,
  auto: 300,
  runtime: 260,
  derived: 220,
  heuristic: 120,
  unknown: 40,
  fallback: 0
};

export const INTERNAL_SYMBOL_NAMES = new Set([
  '_start', '_init', '_fini',
  '__libc_csu_init', '__libc_csu_fini', '__libc_start_main', '__libc_start_call_main',
  'register_tm_clones', 'deregister_tm_clones',
  'frame_dummy', '__do_global_dtors_aux', 'completed.0',
]);

export function buildEntryKey(functionName, bpRegister, offset, size, kind, isSynthetic, start) {
  if (offset !== null) {
    return [
      normalizeFunctionName(functionName || ''),
      String(bpRegister || 'rbp').toLowerCase(),
      normalizeEntryKind(kind),
      offset,
      size,
      isSynthetic ? 'synthetic' : 'frame'
    ].join(':');
  }
  return [
    normalizeFunctionName(functionName || ''),
    String(bpRegister || 'rbp').toLowerCase(),
    normalizeEntryKind(kind),
    start !== null ? toHex(start) : 'unknown',
    size,
    isSynthetic ? 'synthetic' : 'frame'
  ].join(':');
}

export function buildSortIndex(offset, kind) {
  if (offset === null) return 999999;
  return offset * -1000 + (KIND_PRIORITY[normalizeEntryKind(kind)] ?? 99);
}

export function compareFrameEntries(left, right) {
  const leftOffset = left?.offset;
  const rightOffset = right?.offset;
  if (leftOffset === null && rightOffset !== null) return 1;
  if (leftOffset !== null && rightOffset === null) return -1;
  if (leftOffset !== null && rightOffset !== null && leftOffset !== rightOffset) {
    return rightOffset - leftOffset;
  }
  const kindDelta = (KIND_PRIORITY[normalizeEntryKind(left?.kind)] ?? 99) - (KIND_PRIORITY[normalizeEntryKind(right?.kind)] ?? 99);
  if (kindDelta !== 0) return kindDelta;
  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  if (leftSize !== rightSize) return rightSize - leftSize;
  return String(left?.preferredName || left?.name || '').localeCompare(String(right?.preferredName || right?.name || ''));
}

export function compareObservationsForSeeding(left, right) {
  const leftPriority = resolveSourcePriority(left?.modelSource || left?.source);
  const rightPriority = resolveSourcePriority(right?.modelSource || right?.source);
  if (leftPriority !== rightPriority) return rightPriority - leftPriority;

  const leftKindPriority = KIND_PRIORITY[classifyObservationSeedKind(left, '', 'rbp', { arch_bits: 64 })] ?? 99;
  const rightKindPriority = KIND_PRIORITY[classifyObservationSeedKind(right, '', 'rbp', { arch_bits: 64 })] ?? 99;
  if (leftKindPriority !== rightKindPriority) return leftKindPriority - rightKindPriority;

  const leftSize = readPositiveInt(left?.size) ?? 0;
  const rightSize = readPositiveInt(right?.size) ?? 0;
  if (leftSize !== rightSize) return rightSize - leftSize;
  return (left?.offset ?? 0) - (right?.offset ?? 0);
}

export function normalizeDisplayName(raw, kind, bpRegister) {
  const cleaned = clean(raw);
  if (!cleaned) return '';
  if (SPECIAL_SAVED_BP_RE.test(cleaned)) return canonicalSavedBpName(bpRegister);
  if (SPECIAL_RET_RE.test(cleaned)) return 'return address';
  if (NAMELESS_LABELS.has(cleaned.toLowerCase())) return '';
  if (cleaned.toLowerCase() === 'saved_bp') return canonicalSavedBpName(bpRegister);
  if (cleaned.toLowerCase() === 'return_address') return 'return address';
  if (SPECIAL_ARGUMENT_RE.test(cleaned)) return cleaned.toLowerCase();
  if (kind === 'saved_bp') return canonicalSavedBpName(bpRegister);
  if (kind === 'return_address') return 'return address';
  return cleaned;
}

export function isGenericName(name) {
  const raw = clean(name);
  if (!raw) return true;
  return GENERIC_ARG_RE.test(raw)
    || GENERIC_VAR_RE.test(raw)
    || GENERIC_STACK_RE.test(raw)
    || GENERIC_LOCAL_RE.test(raw)
    || BUFFER_STYLE_LABEL_RE.test(raw);
}

export function canonicalSavedBpName(bpRegister) {
  const registerName = String(bpRegister || 'rbp').toLowerCase();
  return registerName === 'ebp' ? 'saved ebp' : 'saved rbp';
}

export function normalizeEntryKind(kind) {
  const raw = clean(kind).toLowerCase();
  if (!raw) return 'unknown';
  if (raw === 'ret' || raw === 'return_address') return 'return_address';
  if (raw === 'saved_bp' || raw === 'control') return 'saved_bp';
  if (raw === 'arg' || raw === 'argument') return 'argument';
  if (raw === 'buffer') return 'buffer';
  if (raw === 'modified') return 'modified';
  if (raw === 'local' || raw === 'spill') return 'local';
  if (raw === 'padding') return 'padding';
  if (raw === 'slot') return 'slot';
  return 'unknown';
}

export function normalizeSource(source) {
  const raw = clean(source).toLowerCase();
  if (!raw) return 'unknown';
  if (raw.includes('dwarf')) return 'dwarf';
  if (raw.includes('debug')) return 'debug';
  if (raw.includes('symbol')) return 'symbol';
  if (raw.includes('control')) return 'control';
  if (raw.includes('mcp')) return 'mcp';
  if (raw.includes('static')) return 'static';
  if (raw.includes('auto')) return 'auto';
  if (raw.includes('runtime')) return 'runtime';
  if (raw.includes('heuristic')) return 'heuristic';
  if (raw.includes('derived')) return 'derived';
  return raw;
}

export function resolveSourcePriority(source) {
  const normalized = normalizeSource(source);
  return SOURCE_PRIORITY[normalized] ?? SOURCE_PRIORITY.unknown;
}

export function resolveBpRegister(slots, meta) {
  const fromSlot = (Array.isArray(slots) ? slots : [])
    .map((slot) => extractBasePointerName(slot?.offsetFromBpLabel))
    .find(Boolean);
  if (fromSlot) return fromSlot;
  return Number(meta?.arch_bits) === 32 ? 'ebp' : 'rbp';
}

export function extractBasePointerName(label) {
  const match = clean(label).match(/^([a-z0-9]+)\s*[+-]/i);
  return match ? match[1].toLowerCase() : '';
}

export function areKindsCompatible(entryKind, observationKind) {
  const left = normalizeEntryKind(entryKind);
  const right = normalizeEntryKind(observationKind);
  if (left === right) return true;
  if (left === 'local' && (right === 'slot' || right === 'unknown')) return true;
  if (left === 'buffer' && (right === 'local' || right === 'slot' || right === 'unknown')) return true;
  if (left === 'argument' && right === 'slot') return true;
  if (left === 'padding' && right === 'unknown') return true;
  return false;
}

export function areSizesCompatible(entrySize, observationSize) {
  const left = readPositiveInt(entrySize);
  const right = readPositiveInt(observationSize);
  if (left === null || right === null) return false;
  if (left === right) return true;
  const minSize = Math.min(left, right);
  const maxSize = Math.max(left, right);
  return minSize >= 4 && maxSize <= minSize * 2;
}

export function rangesOverlap(startA, endA, startB, endB) {
  if (startA === null || endA === null || startB === null || endB === null) return false;
  return startA < endB && startB < endA;
}

export function overlapByteCount(startA, endA, startB, endB) {
  if (!rangesOverlap(startA, endA, startB, endB)) return 0;
  const overlapStart = startA > startB ? startA : startB;
  const overlapEnd = endA < endB ? endA : endB;
  return Number(overlapEnd - overlapStart);
}

export function seedRangeStart(seed) {
  const start = parseBigIntAddr(seed?.start);
  if (start !== null) return start;
  if (Number.isFinite(seed?.offset)) return BigInt(Math.trunc(Number(seed.offset)));
  return null;
}

export function seedRangeEnd(seed) {
  const end = parseBigIntAddr(seed?.end);
  if (end !== null) return end;
  const start = seedRangeStart(seed);
  const size = readPositiveInt(seed?.size);
  if (start === null || size === null) return null;
  return start + BigInt(size);
}

export function observationRangeStart(observation) {
  const start = parseBigIntAddr(observation?.start);
  if (start !== null) return start;
  if (Number.isFinite(observation?.offset)) return BigInt(Math.trunc(Number(observation.offset)));
  return null;
}

export function observationRangeEnd(observation) {
  const end = parseBigIntAddr(observation?.end);
  if (end !== null) return end;
  const start = observationRangeStart(observation);
  const size = readPositiveInt(observation?.size);
  if (start === null || size === null) return null;
  return start + BigInt(size);
}

export function smallestObservationStart(observations) {
  let best = null;
  (Array.isArray(observations) ? observations : []).forEach((item) => {
    const start = parseBigIntAddr(item?.start);
    if (start === null) return;
    if (best === null || start < best) best = start;
  });
  return best;
}

export function parseBigIntAddr(value) {
  if (typeof value === 'bigint') return value;
  if (typeof value === 'number' && Number.isFinite(value)) return BigInt(Math.trunc(value));
  const raw = clean(value).toLowerCase();
  if (!raw) return null;
  try {
    if (raw.startsWith('0x') || raw.startsWith('-0x')) return BigInt(raw);
    if (/^-?\d+$/.test(raw)) return BigInt(raw);
  } catch (_) {
    return null;
  }
  return null;
}

export function toHex(value) {
  const addr = parseBigIntAddr(value);
  if (addr === null) return '';
  return `0x${addr.toString(16)}`;
}

export function addressesEqual(left, right) {
  const a = parseBigIntAddr(left);
  const b = parseBigIntAddr(right);
  return a !== null && b !== null && a === b;
}

export function readPositiveInt(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric) || numeric <= 0) return null;
  return Math.max(1, Math.trunc(numeric));
}

export function readNumeric(value) {
  const numeric = Number(value);
  return Number.isFinite(numeric) ? Math.trunc(numeric) : null;
}

export function readConfidence(value) {
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return null;
  return Math.max(0, Math.min(1, numeric));
}

export function normalizeFunctionName(name) {
  return clean(name)
    .replace(/^_+/, '')
    .replace(/@.*/, '')
    .replace(/[<>]/g, '')
    .toLowerCase();
}

export function displayFunctionName(name) {
  const raw = clean(name).replace(/@.*/, '').replace(/[<>]/g, '');
  if (!raw) return '';
  return raw.startsWith('_') && raw.length > 1 ? raw.slice(1) : raw;
}

export function sameFunction(left, right) {
  const a = normalizeFunctionName(left);
  const b = normalizeFunctionName(right);
  return Boolean(a && b && a === b);
}

export function pickFallbackFunction(snapshots) {
  const first = (Array.isArray(snapshots) ? snapshots : []).find((snap) => clean(snap?.func));
  return displayFunctionName(first?.func || '');
}

export function looksLikeBufferName(name) {
  const cleaned = clean(name).toLowerCase();
  if (!cleaned) return false;
  return cleaned === 'buffer'
    || cleaned.startsWith('buffer_')
    || cleaned.includes('buf')
    || BUFFER_STYLE_LABEL_RE.test(cleaned);
}

export function looksLikeArrayType(typeName) {
  const raw = clean(typeName).toLowerCase();
  if (!raw) return false;
  return /\[[0-9]+\]/.test(raw);
}

export function hasTrustedDisplayName(observation) {
  const candidate = firstNonEmpty(observation?.modelName, observation?.label);
  if (!candidate) return false;
  const cleaned = normalizeDisplayName(candidate, observation?.kind, 'rbp');
  if (!cleaned) return false;
  if (isGenericName(cleaned)) return false;
  return resolveSourcePriority(observation?.modelSource || observation?.source) >= SOURCE_PRIORITY.auto;
}

export function isStrongBufferObservation(observation) {
  if (!observation) return false;
  if (looksLikeBufferName(firstNonEmpty(observation?.modelName, observation?.label))) return true;
  if (looksLikeArrayType(firstNonEmpty(observation?.modelType, observation?.typeName))) return true;
  const size = readPositiveInt(observation?.size) ?? 0;
  const hasWriteSignal = Boolean(observation?.recentWrite || observation?.changed);
  return size >= 16 && hasWriteSignal && PRINTABLE_ASCII_RE.test(clean(observation?.ascii));
}

export function probableBufferFromObservation(observation) {
  if (!observation) return false;
  const size = readPositiveInt(observation?.size) ?? 0;
  return size >= 16 && (Boolean(clean(observation?.ascii)) || Boolean(clean(observation?.bytesHex)));
}

export function isProbableBuffer(entry, observations) {
  if (normalizeEntryKind(entry?.kind) === 'buffer') return true;
  if (looksLikeArrayType(entry?.typeName)) return true;
  if (looksLikeBufferName(entry?.label)) return true;
  return (Array.isArray(observations) ? observations : []).some((observation) => isStrongBufferObservation(observation));
}

export function hasCorruptionSignal(observations) {
  return (Array.isArray(observations) ? observations : []).some((item) => (
    uniqueStrings(item?.flags).includes('corrupted')
    || Boolean(item?.recentWrite)
    || Boolean(item?.changed)
  ));
}

export function isProtectedKind(kind) {
  const normalized = normalizeEntryKind(kind);
  return normalized === 'saved_bp' || normalized === 'return_address';
}

export function firstNonEmpty(...values) {
  for (const value of values) {
    const cleaned = clean(value);
    if (cleaned) return cleaned;
  }
  return '';
}

export function clean(value) {
  return String(value || '').trim();
}

export function cleanValue(value) {
  const raw = clean(value);
  if (!raw || raw === '??' || raw === '(unavailable)') return '';
  return raw;
}

export function uniqueStrings(values) {
  return [...new Set((Array.isArray(values) ? values : []).map((value) => clean(value)).filter(Boolean))];
}

export function formatSourceLabel(source) {
  const normalized = clean(source).toLowerCase();
  switch (normalized) {
    case 'source_c':
      return 'C';
    case 'mcp':
      return 'MCP';
    case 'control':
      return 'control';
    case 'static':
      return 'static';
    case 'runtime':
      return 'runtime';
    case 'derived':
      return 'derived';
    case 'heuristic':
      return 'inferred';
    default:
      return clean(source);
  }
}

export function collectFlags(observations) {
  const flags = [];
  (Array.isArray(observations) ? observations : []).forEach((item) => {
    uniqueStrings(item?.flags).forEach((flag) => flags.push(flag));
    if (item?.changed) flags.push('changed');
    if (item?.recentWrite) flags.push('recent_write');
    if (item?.recentRead) flags.push('recent_read');
    if (item?.payloadRelated) flags.push('payload');
  });
  return uniqueStrings(flags);
}

export function countEntryBands(entries) {
  return {
    positive: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'positive').length,
    base: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'base').length,
    negative: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'negative').length,
    unknown: (Array.isArray(entries) ? entries : []).filter((entry) => entry.offsetBand === 'unknown').length
  };
}

export function resolveOffsetBand(offset) {
  if (!Number.isFinite(offset)) return 'unknown';
  if (offset > 0) return 'positive';
  if (offset < 0) return 'negative';
  return 'base';
}

export function formatCanonicalOffsetLabel(bpRegister, offset) {
  const base = String(bpRegister || 'rbp').toLowerCase();
  if (!Number.isFinite(offset)) return '';
  const numeric = Number(offset);
  const sign = numeric < 0 ? '-' : '+';
  return `${base}${sign}0x${Math.abs(numeric).toString(16)}`;
}

export function resolveAbiVisualOffset(name, wordSize, argumentIndex = 0) {
  const normalized = clean(name).toLowerCase();
  switch (normalized) {
    case 'argc':
      return (readPositiveInt(wordSize) ?? 8) * 2;
    case 'argv':
      return (readPositiveInt(wordSize) ?? 8) * 3;
    case 'envp':
      return (readPositiveInt(wordSize) ?? 8) * 4;
    default:
      return (readPositiveInt(wordSize) ?? 8) * (2 + Math.max(0, Number(argumentIndex) || 0));
  }
}

export function buildValuePreview(primaryObservation) {
  const text = cleanValue(primaryObservation?.displayValue || primaryObservation?.rawValue);
  if (!text) return '';
  return text.length > 56 ? `${text.slice(0, 53)}...` : text;
}

export function pickPrimaryObservation(observations, offset, start) {
  return [...(Array.isArray(observations) ? observations : [])]
    .sort((left, right) => {
      const leftExactOffset = left?.offset === offset ? 0 : 1;
      const rightExactOffset = right?.offset === offset ? 0 : 1;
      if (leftExactOffset !== rightExactOffset) return leftExactOffset - rightExactOffset;

      const leftExactStart = addressesEqual(left?.start, start) ? 0 : 1;
      const rightExactStart = addressesEqual(right?.start, start) ? 0 : 1;
      if (leftExactStart !== rightExactStart) return leftExactStart - rightExactStart;

      const leftPriority = resolveSourcePriority(left?.modelSource || left?.source);
      const rightPriority = resolveSourcePriority(right?.modelSource || right?.source);
      if (leftPriority !== rightPriority) return rightPriority - leftPriority;

      const leftSize = readPositiveInt(left?.size) ?? 0;
      const rightSize = readPositiveInt(right?.size) ?? 0;
      return rightSize - leftSize;
    })[0] ?? null;
}

export function pickPointerValue(primaryObservation, size) {
  const value = clean(primaryObservation?.displayValue || primaryObservation?.rawValue);
  const pointerKind = clean(primaryObservation?.pointerKind);
  if (pointerKind && POINTER_HEX_RE.test(value)) return value;
  if (POINTER_HEX_RE.test(value) && Number(size || 0) >= 4) return value;
  return '';
}

export function resolvePointedEntry(pointerValue, allEntries, currentEntry) {
  const target = parseBigIntAddr(pointerValue);
  if (target === null) return null;
  return (Array.isArray(allEntries) ? allEntries : []).find((entry) => (
    entry !== currentEntry
    && addressesEqual(entry?.start, target)
  )) || null;
}

export function resolvePointedObservation(pointerValue, allObservations, currentEntry) {
  const target = parseBigIntAddr(pointerValue);
  if (target === null) return null;
  return (Array.isArray(allObservations) ? allObservations : []).find((observation) => (
    observation !== currentEntry?.primaryObservation
    && addressesEqual(observation?.start, target)
  )) || null;
}

export function pickAscii(observations) {
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.ascii))
    .find((value) => value && value !== '.'.repeat(value.length) && PRINTABLE_ASCII_RE.test(value)) || '';
}

export function pickHexValue(primaryObservation, observations) {
  if (clean(primaryObservation?.bytesHex)) return clean(primaryObservation.bytesHex);
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.bytesHex))
    .find(Boolean)
    || (clean(primaryObservation?.rawValue).startsWith('0x') ? clean(primaryObservation.rawValue) : '');
}

export function pickBytes(observations) {
  return (Array.isArray(observations) ? observations : [])
    .map((item) => clean(item?.bytesHex))
    .find(Boolean) || '';
}

export function observedRanges(observations) {
  return uniqueStrings((Array.isArray(observations) ? observations : []).map((item) => {
    const start = parseBigIntAddr(item?.start);
    const end = parseBigIntAddr(item?.end);
    if (start === null || end === null) return '';
    return `${toHex(start)}..${toHex(end)}`;
  }));
}

export function resolveRegisterArgumentLink(resolvedName, registerArguments) {
  const name = clean(resolvedName).toLowerCase();
  if (!name || !Array.isArray(registerArguments) || !registerArguments.length) return '';
  if (name === 'argc') {
    return registerArguments.find((item) => item.location === 'rdi' || item.location === 'edi')?.location || '';
  }
  if (name === 'argv') {
    return registerArguments.find((item) => item.location === 'rsi' || item.location === 'esi')?.location || '';
  }
  if (name === 'envp') {
    return registerArguments.find((item) => item.location === 'rdx' || item.location === 'edx')?.location || '';
  }
  return '';
}

export function isInternalSymbol(name) {
  const n = String(name || '').trim();
  if (INTERNAL_SYMBOL_NAMES.has(n)) return true;
  if (n.startsWith('_dl_')) return true;
  if (n.startsWith('__libc_')) return true;
  if (n === 'plt' || n === '.plt' || n.endsWith('.plt') || n.endsWith('@plt') || n.includes('@plt.')) return true;
  if (n === 'got' || n === '.got' || n.endsWith('.got') || n.endsWith('@got') || n.endsWith('@got.plt')) return true;
  return false;
}
