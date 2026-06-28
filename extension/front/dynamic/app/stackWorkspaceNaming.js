import {
  resolveRestrictedAbiArgumentName
} from './stackWorkspaceClassification.js';

import {
  buildCommentHints,
  buildEntryBadges,
  validateReturnAddressIntegrity
} from './stackWorkspaceCorruption.js';

import {
  buildDetailPayload,
  buildEntryDebugMetadata,
  resolveEntryConfidence,
  resolveEntryProvenance
} from './stackWorkspaceDebug.js';

import {
  GENERIC_ARG_RE,
  GENERIC_LOCAL_RE,
  GENERIC_STACK_RE,
  GENERIC_VAR_RE,
  NAMELESS_LABELS,
  POINTER_HEX_RE,
  SOURCE_PRIORITY,
  SPECIAL_ARGUMENT_NAMES,
  SPECIAL_ARGUMENT_RE,
  buildEntryKey,
  buildSortIndex,
  buildValuePreview,
  canonicalSavedBpName,
  clean,
  collectFlags,
  compareFrameEntries,
  formatCanonicalOffsetLabel,
  isGenericName,
  isProbableBuffer,
  normalizeDisplayName,
  normalizeEntryKind,
  normalizeFunctionName,
  normalizeSource,
  parseBigIntAddr,
  pickPrimaryObservation,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolveAbiVisualOffset,
  resolveOffsetBand,
  resolveRegisterArgumentLink,
  resolveSourcePriority,
  smallestObservationStart,
  toHex,
  uniqueStrings
} from './stackWorkspaceUtils.js';

export function finalizeEntryBase(entry, { functionName, bpRegister, bpAddress, registerArguments, meta } = {}) {
  if (!entry) return null;
  const kind = normalizeEntryKind(entry.kind);
  const offset = readNumeric(entry.offset);
  const size = readPositiveInt(entry.size) ?? 1;
  const start = parseBigIntAddr(entry.start)
    ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null)
    ?? smallestObservationStart(entry.observations);
  const end = start !== null ? start + BigInt(size) : null;
  const observations = Array.isArray(entry.observations) ? entry.observations : [];
  const primaryObservation = pickPrimaryObservation(observations, offset, start);
  const flags = collectFlags(observations);
  const typeName = resolveEntryType(entry, primaryObservation);
  const probableBuffer = isProbableBuffer(entry, observations);
  const nameInfo = resolveEntryName(entry, {
    functionName,
    bpRegister,
    meta,
    probableBuffer
  });
  const key = buildEntryKey(functionName, bpRegister, offset, size, kind, entry.isSynthetic, start);
  const returnAddressIntegrity = validateReturnAddressIntegrity({
    kind,
    start,
    size,
    observations
  });

  return {
    key,
    kind,
    offset,
    size,
    start,
    end,
    source: normalizeSource(entry?.source),
    confidence: readConfidence(entry?.confidence),
    typeName,
    typeSource: clean(entry?.typeName) ? normalizeSource(entry?.source) : normalizeSource(primaryObservation?.modelSource || primaryObservation?.source),
    observations,
    primaryObservation,
    flags,
    valuePreview: buildValuePreview(primaryObservation),
    bpRegister,
    offsetLabel: formatCanonicalOffsetLabel(bpRegister, offset),
    offsetBand: resolveOffsetBand(offset),
    isSynthetic: Boolean(entry.isSynthetic),
    isSensitive: kind === 'return_address' || kind === 'saved_bp' || kind === 'buffer' || kind === 'modified',
    preferredName: clean(nameInfo?.name),
    preferredNameSource: clean(nameInfo?.source),
    probableBuffer,
    returnAddressIntegrity,
    registerLink: resolveRegisterArgumentLink(nameInfo?.name, registerArguments),
    commentHints: buildCommentHints({ kind, probableBuffer }),
    seedContributors: Array.isArray(entry?.seedContributors) ? entry.seedContributors : [],
    sortIndex: buildSortIndex(offset, kind)
  };
}

export function finalizeDisplayEntry(entry, { functionName, bpRegister, registerArguments, allEntries, allObservations } = {}) {
  const detailPayload = buildDetailPayload({
    entry,
    functionName,
    bpRegister,
    registerArguments,
    allEntries,
    allObservations
  });
  return {
    key: entry.key,
    name: entry.name,
    kind: entry.kind,
    offset: entry.offset,
    offsetLabel: entry.offsetLabel,
    address: entry.start !== null ? toHex(entry.start) : '',
    size: entry.size,
    source: normalizeSource(entry?.source),
    provenance: resolveEntryProvenance(entry),
    confidence: resolveEntryConfidence(entry),
    valuePreview: entry.valuePreview,
    nameSource: entry.nameSource,
    detailPayload,
    sortIndex: entry.sortIndex,
    isSynthetic: entry.isSynthetic,
    bpRegister: entry.bpRegister,
    offsetBand: entry.offsetBand,
    debug: buildEntryDebugMetadata(entry),
    badges: buildEntryBadges(entry),
    changed: entry.flags.includes('changed'),
    recentWrite: entry.flags.includes('recent_write'),
    recentRead: entry.flags.includes('recent_read'),
    isSensitive: Boolean(entry.isSensitive)
  };
}

export function assignStableFallbackNames(entries, { functionName, bpRegister, meta } = {}) {
  const counters = new Map();
  (Array.isArray(entries) ? entries : []).forEach((entry) => {
    if (clean(entry?.preferredName)) {
      entry.name = entry.preferredName;
      entry.nameSource = entry.preferredNameSource || 'runtime';
      entry.registerLink = resolveRegisterArgumentLink(entry.name, []);
      return;
    }

    const bucket = resolveFallbackBucket(entry, functionName, bpRegister, meta);
    const index = counters.get(bucket) ?? 0;
    counters.set(bucket, index + 1);
    entry.name = `${bucket}_${index}`;
    entry.nameSource = 'fallback';
  });
}

export function buildLogicalArgumentEntries({ entries, registerArguments, model, bpRegister, wordSize, functionName, meta } = {}) {
  const namedArguments = buildNamedLogicalArguments({
    registerArguments,
    model,
    wordSize
  });

  if (!namedArguments.length) return [];

  const positiveNames = new Set(
    (Array.isArray(entries) ? entries : [])
      .filter((entry) => normalizeEntryKind(entry?.kind) === 'argument' && Number.isFinite(entry?.offset) && entry.offset > 0)
      .map((entry) => clean(entry?.name).toLowerCase())
      .filter(Boolean)
  );

  const candidates = [...(Array.isArray(entries) ? entries : [])]
    .filter((entry) => normalizeEntryKind(entry?.kind) === 'argument' && Number.isFinite(entry?.offset) && entry.offset < 0)
    .sort((left, right) => (right.offset ?? 0) - (left.offset ?? 0));

  const usedStorageKeys = new Set();
  const logicalEntries = [];

  namedArguments.forEach((argument) => {
    const normalizedName = clean(argument?.name).toLowerCase();
    if (positiveNames.has(normalizedName)) return;
    const storageEntry = pickLogicalArgumentStorageEntry(candidates, argument, usedStorageKeys);
    if (!storageEntry) return;
    usedStorageKeys.add(storageEntry.key);
    const visualOffset = resolveAbiVisualOffset(argument.name, wordSize, argument.index);
    logicalEntries.push({
      key: [
        normalizeFunctionName(functionName || ''),
        String(bpRegister || 'rbp').toLowerCase(),
        'logical_argument',
        normalizedName || `arg_${argument.index ?? logicalEntries.length}`
      ].join(':'),
      name: clean(argument?.name),
      kind: 'argument',
      size: readPositiveInt(storageEntry?.size) ?? argument.size ?? readPositiveInt(wordSize),
      offset: visualOffset,
      offsetLabel: formatCanonicalOffsetLabel(bpRegister, visualOffset),
      registerLocation: argument.location,
      storageKey: storageEntry.key,
      storageOffset: storageEntry.offset,
      storageOffsetLabel: storageEntry.offsetLabel || formatCanonicalOffsetLabel(bpRegister, storageEntry.offset),
      source: clean(argument?.source) || 'abi',
      cType: clean(argument?.cType),
      functionName: clean(functionName),
      archBits: Number(meta?.arch_bits) || 0
    });
  });

  return logicalEntries.sort(compareFrameEntries);
}

export function buildNamedLogicalArguments({ registerArguments, model, wordSize } = {}) {
  const safeWordSize = readPositiveInt(wordSize) ?? 8;
  const sourceParameters = (Array.isArray(model?.parameters) ? model.parameters : [])
    .map((parameter, index) => ({
      index,
      name: clean(parameter?.name),
      location: clean(registerArguments?.[index]?.location).toLowerCase(),
      size: readPositiveInt(parameter?.byteSize) ?? readPositiveInt(registerArguments?.[index]?.size) ?? safeWordSize,
      cType: clean(parameter?.cType),
      source: 'source_c'
    }))
    .filter((parameter) => isMeaningfulLogicalArgumentName(parameter?.name));

  if (sourceParameters.length) return sourceParameters;

  return (Array.isArray(registerArguments) ? registerArguments : [])
    .map((argument, index) => ({
      index,
      name: clean(argument?.name),
      location: clean(argument?.location).toLowerCase(),
      size: readPositiveInt(argument?.size) ?? safeWordSize,
      cType: '',
      source: normalizeSource(argument?.source) || 'abi'
    }))
    .filter((argument) => {
      const normalized = clean(argument?.name).toLowerCase();
      return Boolean(
        normalized
        && (SPECIAL_ARGUMENT_NAMES.includes(normalized) || isMeaningfulLogicalArgumentName(argument?.name))
      );
    });
}

export function isMeaningfulLogicalArgumentName(name) {
  const raw = clean(name);
  if (!raw) return false;
  if (GENERIC_ARG_RE.test(raw) || GENERIC_VAR_RE.test(raw) || GENERIC_STACK_RE.test(raw) || GENERIC_LOCAL_RE.test(raw)) {
    return false;
  }
  return !NAMELESS_LABELS.has(raw.toLowerCase());
}

export function pickLogicalArgumentStorageEntry(candidates, argument, usedStorageKeys) {
  const scored = [...(Array.isArray(candidates) ? candidates : [])]
    .filter((entry) => !usedStorageKeys.has(entry?.key))
    .map((entry, orderIndex) => ({
      entry,
      score: scoreLogicalArgumentStorageEntry(entry, argument, orderIndex)
    }))
    .filter((entry) => Number.isFinite(entry.score) && entry.score > 0)
    .sort((left, right) => right.score - left.score || compareFrameEntries(left.entry, right.entry));

  return scored[0]?.entry || null;
}

export function scoreLogicalArgumentStorageEntry(entry, argument, orderIndex) {
  if (!entry || !argument) return -Infinity;
  let score = 0;
  const size = readPositiveInt(entry?.size) ?? 0;
  const argSize = readPositiveInt(argument?.size) ?? 0;
  const hints = collectLogicalArgumentHints(entry);

  if (hints.includes(argument.name)) score += 1200;
  if (argument.location && hints.includes(argument.location)) score += 900;
  if (entry?.registerLink && clean(entry.registerLink).toLowerCase() === argument.location) score += 500;

  if (argSize && size === argSize) score += 220;
  else if (argument.name === 'argc' && size === 4) score += 180;
  else if (argument.name !== 'argc' && size >= 8) score += 160;

  if (argument.name === 'argv' && pointsToLikelyPointerData(entry)) score += 180;
  if (argument.name === 'argc' && !pointsToLikelyPointerData(entry)) score += 120;

  if (Number.isFinite(Number(argument?.index))) {
    score += Math.max(0, 120 - Math.abs(orderIndex - Number(argument.index)) * 40);
  }
  score += Math.max(0, 140 - orderIndex * 40);
  return score;
}

export function collectLogicalArgumentHints(entry) {
  return uniqueStrings([
    clean(entry?.name),
    clean(entry?.preferredName),
    ...(Array.isArray(entry?.seedContributors) ? entry.seedContributors.map((seed) => seed?.label) : []),
    ...(Array.isArray(entry?.observations) ? entry.observations.flatMap((observation) => [observation?.label, observation?.modelName]) : [])
  ].map((value) => clean(value).toLowerCase()).filter(Boolean));
}

export function pointsToLikelyPointerData(entry) {
  const value = clean(entry?.valuePreview);
  if (POINTER_HEX_RE.test(value)) return true;
  return (Array.isArray(entry?.observations) ? entry.observations : []).some((observation) => (
    Boolean(clean(observation?.pointerKind))
    || POINTER_HEX_RE.test(clean(observation?.displayValue || observation?.rawValue))
  ));
}

export function resolveEntryName(entry, { functionName, bpRegister, meta, probableBuffer } = {}) {
  const kind = normalizeEntryKind(entry?.kind);
  const offset = readNumeric(entry?.offset);
  if (kind === 'saved_bp') {
    return { name: canonicalSavedBpName(bpRegister), source: 'control' };
  }
  if (kind === 'return_address') {
    return { name: 'return address', source: 'control' };
  }

  const abiArgumentName = resolveRestrictedAbiArgumentName(entry, functionName, bpRegister, meta);
  if (abiArgumentName) {
    return { name: abiArgumentName, source: 'abi' };
  }

  const candidates = collectNameCandidates(entry);
  const winner = candidates
    .map((candidate) => scoreNameCandidate(candidate, {
      functionName,
      offset,
      kind,
      bpRegister,
      probableBuffer
    }))
    .filter(Boolean)
    .sort((left, right) => right.score - left.score || left.name.localeCompare(right.name))[0];

  if (winner?.name) {
    return {
      name: winner.name,
      source: winner.source
    };
  }
  return { name: '', source: '' };
}

export function collectNameCandidates(entry) {
  const candidates = [];
  const pushCandidate = (raw, source, priority, trusted) => {
    const value = clean(raw);
    if (!value) return;
    candidates.push({
      raw: value,
      source: normalizeSource(source),
      priority: Number(priority || 0),
      trusted: Boolean(trusted)
    });
  };

  pushCandidate(entry?.label, entry?.nameSource || entry?.source, resolveSourcePriority(entry?.source), true);

  (Array.isArray(entry?.observations) ? entry.observations : []).forEach((observation) => {
    pushCandidate(observation?.modelName, observation?.modelSource || observation?.source, resolveSourcePriority(observation?.modelSource || observation?.source), true);
    pushCandidate(observation?.label, observation?.source, observation?.sourcePriority, observation?.sourcePriority >= SOURCE_PRIORITY.auto);
  });

  return candidates;
}

export function scoreNameCandidate(candidate, { functionName, offset, kind, bpRegister, probableBuffer } = {}) {
  const raw = clean(candidate?.raw);
  if (!raw) return null;

  const normalized = normalizeDisplayName(raw, kind, bpRegister);
  if (!normalized) return null;
  if (isGenericName(normalized)) return null;
  if (NAMELESS_LABELS.has(normalized.toLowerCase())) return null;

  if (SPECIAL_ARGUMENT_RE.test(normalized)) {
    if (!(kind === 'argument' || Boolean(resolveRestrictedAbiArgumentName({ offset, kind }, functionName, bpRegister)))) {
      return null;
    }
  }

  let bonus = 0;
  if (kind === 'buffer' && normalized === 'buffer') bonus += 160;
  if (kind === 'modified' && normalized === 'modified') bonus += 150;
  if (kind === 'argument' && SPECIAL_ARGUMENT_RE.test(normalized)) bonus += 140;
  if (probableBuffer && normalized === 'buffer') bonus += 60;

  return {
    name: normalized,
    source: clean(candidate?.source) || 'runtime',
    score: Number(candidate?.priority || 0) + (candidate?.trusted ? 60 : 0) + bonus
  };
}

export function resolveFallbackBucket(entry, functionName, bpRegister, meta) {
  const kind = normalizeEntryKind(entry?.kind);
  if (kind === 'argument' && resolveRestrictedAbiArgumentName(entry, functionName, bpRegister, meta)) {
    return 'arg';
  }
  if (kind === 'argument') return 'arg';
  if (kind === 'buffer') return 'buffer';
  if (kind === 'padding') return 'padding';
  if (kind === 'unknown') return 'unknown';
  if (kind === 'slot') return 'slot';
  return 'local';
}

export function resolveEntryType(entry, primaryObservation) {
  if (clean(entry?.typeName)) return clean(entry.typeName);
  if (clean(primaryObservation?.modelType)) return clean(primaryObservation.modelType);
  if (clean(primaryObservation?.typeName)) return clean(primaryObservation.typeName);
  return '';
}
