import {
  classifyObservationSeedKind
} from './stackWorkspaceClassification.js';

import {
  compactCanonicalLayout,
  compareSeedsForLayout,
  countSeedSupport,
  isWeakStaticSeed,
  seedOffsetRange
} from './stackWorkspaceCompaction.js';

import {
  mergeSeedContributors
} from './stackWorkspaceDebug.js';

import {
  addSeed,
  normalizeSeed
} from './stackWorkspaceSeeds.js';

import {
  clean,
  displayFunctionName,
  firstNonEmpty,
  isProtectedKind,
  isStrongBufferObservation,
  normalizeEntryKind,
  normalizeSource,
  overlapByteCount,
  parseBigIntAddr,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolveSourcePriority,
  sameFunction,
  seedRangeEnd,
  seedRangeStart
} from './stackWorkspaceUtils.js';

export function buildFrameScope({
  analysis,
  snapshot,
  currentStep,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  seeds,
  meta
} = {}) {
  const ownerName = displayFunctionName(snapshot?.func || analysis?.function?.name || '');
  const ownerMatches = !clean(functionName) || !ownerName || sameFunction(ownerName, functionName);
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  const spAddress = parseBigIntAddr(analysis?.frame?.stackPointer);
  const observedDepth = (
    bpAddress !== null
    && spAddress !== null
    && spAddress <= bpAddress
  ) ? Number(spAddress - bpAddress) : null;
  const seedRanges = [...(Array.isArray(seeds) ? seeds : [])]
    .map((seed) => normalizeSeed(seed))
    .filter(Boolean)
    .map((seed) => ({
      kind: normalizeEntryKind(seed?.kind),
      source: normalizeSource(seed?.source),
      range: seedOffsetRange(seed)
    }))
    .filter((entry) => entry.range);

  let minNegativeOffset = Number.isFinite(frameSize) ? -frameSize : null;
  if (Number.isFinite(observedDepth) && observedDepth < 0) {
    minNegativeOffset = minNegativeOffset === null
      ? observedDepth
      : Math.min(minNegativeOffset, observedDepth);
  }
  let maxPositiveOffset = readPositiveInt(wordSize) ?? 0;
  seedRanges.forEach(({ range }) => {
    if (range.start < 0 && (minNegativeOffset === null || range.start < minNegativeOffset)) {
      minNegativeOffset = range.start;
    }
    if (range.end > 0 && range.end > maxPositiveOffset) {
      maxPositiveOffset = range.end;
    }
  });

  return {
    functionName: clean(functionName) || ownerName || '',
    ownerName,
    ownerMatches,
    currentStep: Number.isFinite(Number(currentStep)) ? Math.trunc(Number(currentStep)) : null,
    bpRegister: String(bpRegister || 'rbp').toLowerCase(),
    bpAddress: parseBigIntAddr(bpAddress),
    archBits: Number(meta?.arch_bits) || 0,
    wordSize: readPositiveInt(wordSize) ?? 0,
    frameSize,
    minNegativeOffset,
    maxPositiveOffset,
    seedRanges
  };
}

export function filterRuntimeObservationsForFrame(observations, frameScope) {
  return [...(Array.isArray(observations) ? observations : [])]
    .filter((observation) => doesObservationBelongToFrameScope(observation, frameScope));
}

export function doesObservationBelongToFrameScope(observation, frameScope) {
  if (!observation || !frameScope?.ownerMatches) return false;
  const range = seedOffsetRange(observation);
  if (!range) return false;
  return isOffsetRangeWithinFrameScope(range, frameScope);
}

export function isOffsetRangeWithinFrameScope(range, frameScope) {
  if (!range || !frameScope) return false;
  const minNegative = Number.isFinite(frameScope?.minNegativeOffset) ? frameScope.minNegativeOffset : null;
  const maxPositive = Number.isFinite(frameScope?.maxPositiveOffset) ? frameScope.maxPositiveOffset : null;
  if (range.start < 0) {
    if (minNegative !== null && range.start < minNegative) return false;
    if (range.end > 0) return false;
    return true;
  }
  if (range.start === 0 || range.start === (frameScope.wordSize || 0)) return true;
  if (maxPositive !== null && range.end <= maxPositive) {
    return doesRangeTouchStaticPositiveSeed(range, frameScope);
  }
  return false;
}

export function doesRangeTouchStaticPositiveSeed(range, frameScope) {
  if (!range || !frameScope) return false;
  return (Array.isArray(frameScope?.seedRanges) ? frameScope.seedRanges : []).some((entry) => {
    if (!entry?.range || entry.range.start < 0) return false;
    return entry.range.start < range.end && range.start < entry.range.end;
  });
}

export function recoverConcreteObjectExtents({
  seeds,
  observations,
  snapshots,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  frameScope
} = {}) {
  if (!frameScope?.ownerMatches) return Array.isArray(seeds) ? [...seeds] : [];
  const recoveredObjects = collectConcreteObjectExtents({
    snapshots,
    analysis,
    observations,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta,
    frameScope
  });
  if (!recoveredObjects.length) return Array.isArray(seeds) ? [...seeds] : [];

  const currentSeeds = [...(Array.isArray(seeds) ? seeds : [])].map((seed) => normalizeSeed(seed)).filter(Boolean);
  recoveredObjects.forEach((recovered) => {
    const match = chooseRecoveredSeedTarget(currentSeeds, recovered);
    if (match) {
      applyRecoveredExtentToSeed(match, recovered, observations, wordSize);
      return;
    }
    addSeed(currentSeeds, recoveredSeedToStaticSeed(recovered, bpAddress));
  });

  const compacted = compactCanonicalLayout({
    seeds: currentSeeds,
    observations,
    analysis,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });

  return compacted.filter((seed) => !isSeedAbsorbedByRecoveredObject(seed, recoveredObjects, observations));
}

export function collectConcreteObjectExtents({
  snapshots,
  analysis,
  observations,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  frameScope
} = {}) {
  const byOffset = new Map();

  (Array.isArray(snapshots) ? snapshots : [])
    .filter((snap) => sameFunction(snap?.func, functionName))
    .forEach((snap) => {
      const externalSymbol = clean(snap?.effects?.external_symbol).toLowerCase();
      if (!isConcreteObjectExtentCall(externalSymbol)) return;

      const bpValue = readSnapshotRegisterValue(snap, bpRegister);
      if (bpValue === null) return;

      collectRecoveredExtentCandidatesFromSnapshot({
        snapshot: snap,
        externalSymbol,
        bpValue,
        bpRegister,
        wordSize,
        meta,
        frameScope
      }).forEach((candidate) => {
        pushRecoveredExtentCandidate(byOffset, candidate);
      });
    });

  collectRecoveredExtentCandidatesFromAnalysis({
    analysis,
    observations,
    bpAddress,
    bpRegister,
    wordSize,
    frameScope
  }).forEach((candidate) => {
    pushRecoveredExtentCandidate(byOffset, candidate);
  });

  return [...byOffset.values()].sort((left, right) => left.offset - right.offset);
}

export function collectRecoveredExtentCandidatesFromSnapshot({
  snapshot,
  externalSymbol,
  bpValue,
  bpRegister,
  wordSize,
  meta,
  frameScope
} = {}) {
  const candidates = [];
  collectSnapshotWrites(snapshot).forEach((write) => {
    const candidate = recoveredCandidateFromRange({
      start: write?.addr,
      size: write?.size,
      bpValue,
      externalSymbol
    });
    if (candidate && recoveredCandidateBelongsToFrame(candidate, frameScope)) candidates.push(candidate);
  });

  const registerCandidate = recoveredCandidateFromCallRegisters({
    snapshot,
    externalSymbol,
    bpValue,
    bpRegister,
    wordSize,
    meta,
    frameScope
  });
  if (registerCandidate) candidates.push(registerCandidate);
  return candidates;
}

export function collectRecoveredExtentCandidatesFromAnalysis({ analysis, observations, bpAddress, bpRegister, wordSize, frameScope } = {}) {
  if (bpAddress === null) return [];
  const writes = Array.isArray(analysis?.delta?.writes) ? analysis.delta.writes : [];
  return writes
    .map((write) => recoveredCandidateFromRange({
      start: write?.addr,
      size: write?.size,
      bpValue: bpAddress,
      externalSymbol: ''
    }))
    .filter((candidate) => recoveredCandidateBelongsToFrame(candidate, frameScope))
    .filter((candidate) => shouldKeepRecoveredAnalysisCandidate(candidate, observations, bpRegister, wordSize));
}

export function collectSnapshotWrites(snapshot) {
  const memoryWrites = Array.isArray(snapshot?.memory?.writes) ? snapshot.memory.writes : [];
  const deltaWrites = Array.isArray(snapshot?.delta?.writes) ? snapshot.delta.writes : [];
  return [...memoryWrites, ...deltaWrites];
}

export function recoveredCandidateFromCallRegisters({
  snapshot,
  externalSymbol,
  bpValue,
  bpRegister,
  wordSize,
  meta,
  frameScope
} = {}) {
  const normalizedSymbol = clean(externalSymbol).toLowerCase();
  const archBits = Number(meta?.arch_bits) || (Number(wordSize) === 4 ? 32 : 64);
  if (archBits !== 64) return null;

  const destRegister = resolveDestinationRegisterForExternalCall(normalizedSymbol);
  const sizeRegister = resolveSizeRegisterForExternalCall(normalizedSymbol);
  if (!destRegister || !sizeRegister) return null;

  const start = readSnapshotRegisterValue(snapshot, destRegister);
  const sizeValue = readSnapshotRegisterValue(snapshot, sizeRegister);
  const size = sizeValue !== null ? Number(sizeValue) : null;
  if (start === null || !Number.isFinite(size) || size <= 0) return null;

  const candidate = recoveredCandidateFromRange({
    start,
    size,
    bpValue,
    externalSymbol,
    bpRegister
  });
  return recoveredCandidateBelongsToFrame(candidate, frameScope) ? candidate : null;
}

export function resolveDestinationRegisterForExternalCall(symbol) {
  switch (clean(symbol).toLowerCase()) {
    case 'read':
      return 'rsi';
    case 'memcpy':
    case 'memmove':
    case 'memset':
    case 'strcpy':
    case 'strncpy':
    case 'gets':
      return 'rdi';
    default:
      return '';
  }
}

export function resolveSizeRegisterForExternalCall(symbol) {
  switch (clean(symbol).toLowerCase()) {
    case 'memcpy':
    case 'memmove':
    case 'memset':
    case 'read':
    case 'strncpy':
      return 'rdx';
    default:
      return '';
  }
}

export function recoveredCandidateFromRange({ start, size, bpValue, externalSymbol } = {}) {
  const parsedStart = parseBigIntAddr(start);
  const parsedSize = readPositiveInt(size);
  if (parsedStart === null || parsedSize === null || bpValue === null) return null;
  const offset = Number(parsedStart - bpValue);
  if (!Number.isFinite(offset) || offset >= 0) return null;
  return {
    offset,
    size: parsedSize,
    kind: 'buffer',
    label: deriveRecoveredObjectLabel(offset, externalSymbol),
    typeName: '',
    source: 'derived',
    confidence: 1,
    symbol: clean(externalSymbol).toLowerCase()
  };
}

export function shouldKeepRecoveredAnalysisCandidate(candidate, observations, bpRegister, wordSize) {
  if (!candidate) return false;
  const size = readPositiveInt(candidate?.size);
  if (size === null || size < Math.max(8, Number(wordSize || 0))) return false;
  return (Array.isArray(observations) ? observations : []).some((observation) => {
    if (readNumeric(observation?.offset) !== readNumeric(candidate?.offset)) return false;
    const kind = classifyObservationSeedKind(observation, '', bpRegister, { arch_bits: Number(wordSize) === 4 ? 32 : 64 });
    return kind === 'buffer' || isStrongBufferObservation(observation);
  });
}

export function pushRecoveredExtentCandidate(byOffset, candidate) {
  if (!candidate || !(byOffset instanceof Map)) return;
  const key = `${candidate.offset}`;
  const existing = byOffset.get(key) || null;
  if (!existing) {
    byOffset.set(key, candidate);
    return;
  }

  const existingSize = readPositiveInt(existing?.size) ?? 0;
  const candidateSize = readPositiveInt(candidate?.size) ?? 0;
  if (candidateSize > existingSize) {
    byOffset.set(key, {
      ...candidate,
      label: clean(existing?.label) || clean(candidate?.label),
      source: existing?.source === 'derived' ? candidate.source : existing.source
    });
    return;
  }

  if (!clean(existing?.label) && clean(candidate?.label)) {
    byOffset.set(key, {
      ...existing,
      label: candidate.label
    });
  }
}

export function isConcreteObjectExtentCall(symbol) {
  return [
    'memset',
    'memcpy',
    'memmove',
    'strcpy',
    'strncpy',
    'gets',
    'read'
  ].includes(clean(symbol).toLowerCase());
}

export function readSnapshotRegisterValue(snapshot, bpRegister) {
  const registerName = String(bpRegister || 'rbp').toLowerCase();
  const cpuBefore = parseBigIntAddr(snapshot?.cpu?.before?.registers?.[registerName]);
  if (cpuBefore !== null) return cpuBefore;
  const listed = Array.isArray(snapshot?.registers)
    ? snapshot.registers.find((entry) => clean(entry?.name).toLowerCase() === registerName)
    : null;
  return parseBigIntAddr(listed?.value);
}

export function chooseRecoveredSeedTarget(seeds, recovered) {
  const entries = Array.isArray(seeds) ? seeds : [];
  return entries
    .filter((seed) => !isProtectedKind(seed?.kind))
    .map((seed) => ({
      seed,
      score: scoreRecoveredSeedTarget(seed, recovered)
    }))
    .filter((entry) => Number.isFinite(entry.score))
    .sort((left, right) => right.score - left.score || compareSeedsForLayout(left.seed, right.seed))
    .map((entry) => entry.seed)[0] ?? null;
}

export function scoreRecoveredSeedTarget(seed, recovered) {
  if (!seed || !recovered) return -Infinity;
  const seedRange = seedOffsetRange(seed);
  const recoveredRange = seedOffsetRange(recovered);
  if (!seedRange || !recoveredRange) return -Infinity;

  const exactOffset = readNumeric(seed?.offset) === readNumeric(recovered?.offset);
  const overlap = seedRange.start < recoveredRange.end && recoveredRange.start < seedRange.end;
  const contains = recoveredRange.start <= seedRange.start && recoveredRange.end >= seedRange.end;
  if (!exactOffset && !overlap && !contains) return -Infinity;

  let score = 0;
  if (exactOffset) score += 1000;
  if (contains) score += 220;
  if (overlap) score += 120;
  if (normalizeEntryKind(seed?.kind) === 'buffer') score += 120;
  if (normalizeEntryKind(seed?.kind) === 'local') score += 40;
  if (isWeakStaticSeed(seed)) score += 80;
  score += Math.min(100, resolveSourcePriority(seed?.source) / 5);
  score += Math.min(60, overlapByteCount(
    seedRangeStart(seed),
    seedRangeEnd(seed),
    recoveredRange.start !== null ? BigInt(recoveredRange.start) : null,
    recoveredRange.end !== null ? BigInt(recoveredRange.end) : null
  ));
  return score;
}

export function applyRecoveredExtentToSeed(seed, recovered, observations, wordSize) {
  if (!seed || !recovered) return;
  const recoveredSize = readPositiveInt(recovered?.size) ?? readPositiveInt(seed?.size) ?? wordSize;
  if (isSourceAnchoredSeed(seed)) {
    seed.seedContributors = mergeSeedContributors(seed?.seedContributors, [{
      offset: recovered.offset,
      size: recovered.size,
      kind: 'buffer',
      source: recovered.source,
      label: recovered.label,
      isSynthetic: false
    }]);
    return;
  }
  seed.kind = 'buffer';
  seed.size = recoveredSize;
  if (isWeakStaticSeed(seed) || !clean(seed?.label)) {
    seed.label = clean(recovered?.label) || seed.label;
  }
  seed.source = resolveSourcePriority(seed?.source) >= resolveSourcePriority(recovered?.source) ? seed.source : recovered.source;
  seed.end = seed.start !== null ? seed.start + BigInt(seed.size) : null;
  seed.seedContributors = mergeSeedContributors(seed?.seedContributors, [{
    offset: recovered.offset,
    size: recovered.size,
    kind: 'buffer',
    source: recovered.source,
    label: recovered.label,
    isSynthetic: false
  }]);

  const largerObservation = (Array.isArray(observations) ? observations : []).find((observation) => (
    readNumeric(observation?.offset) === readNumeric(recovered?.offset)
    && readPositiveInt(observation?.size) === recoveredSize
  ));
  if (largerObservation && !clean(seed?.label)) {
    seed.label = firstNonEmpty(largerObservation?.modelName, largerObservation?.label);
  }
}

export function recoveredSeedToStaticSeed(recovered, bpAddress) {
  const offset = readNumeric(recovered?.offset);
  const size = readPositiveInt(recovered?.size);
  return {
    offset,
    size,
    kind: 'buffer',
    start: bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null,
    source: 'derived',
    label: clean(recovered?.label),
    nameSource: 'derived',
    typeName: '',
    confidence: 1,
    isSynthetic: false
  };
}

export function isSeedAbsorbedByRecoveredObject(seed, recoveredObjects, observations) {
  if (!seed || isProtectedKind(seed?.kind)) return false;
  const seedRange = seedOffsetRange(seed);
  if (!seedRange) return false;
  return (Array.isArray(recoveredObjects) ? recoveredObjects : []).some((recovered) => {
    const recoveredRange = seedOffsetRange(recovered);
    if (!recoveredRange) return false;
    if (readNumeric(seed?.offset) === readNumeric(recovered?.offset)) return false;
    const insideRecovered = seedRange.start >= recoveredRange.start && seedRange.end <= recoveredRange.end;
    if (!insideRecovered) return false;
    if (normalizeEntryKind(seed?.kind) === 'modified') return false;
    if (!isWeakStaticSeed(seed) && normalizeEntryKind(seed?.kind) !== 'slot' && normalizeEntryKind(seed?.kind) !== 'unknown') {
      return false;
    }
    const support = countSeedSupport(seed, observations);
    if (
      support.exact > 0
      && normalizeEntryKind(seed?.kind) !== 'slot'
      && normalizeEntryKind(seed?.kind) !== 'unknown'
      && normalizeEntryKind(seed?.kind) !== 'padding'
    ) {
      return false;
    }
    if (seed?.isSynthetic) return true;
    if (normalizeEntryKind(seed?.kind) === 'slot' || normalizeEntryKind(seed?.kind) === 'unknown') {
      return !support.named;
    }
    return !support.named;
  });
}

export function deriveRecoveredObjectLabel(offset, symbol) {
  void offset;
  void symbol;
  return '';
}

export function recoveredCandidateBelongsToFrame(candidate, frameScope) {
  if (!candidate || !frameScope?.ownerMatches) return false;
  const range = seedOffsetRange(candidate);
  if (!range) return false;
  return isOffsetRangeWithinFrameScope(range, frameScope);
}

export function isFinalEntryAllowedInFrame(entry, frameScope) {
  if (!entry || !frameScope) return false;
  if (!frameScope.ownerMatches && normalizeEntryKind(entry?.kind) !== 'saved_bp' && normalizeEntryKind(entry?.kind) !== 'return_address') {
    return false;
  }
  const range = seedOffsetRange(entry);
  if (!range || !isOffsetRangeWithinFrameScope(range, frameScope)) return false;
  return true;
}

export function filterSourceSimpleFrameEntries(entries, { model } = {}) {
  if (!hasSourceBackedModel(model)) return Array.isArray(entries) ? entries : [];
  return (Array.isArray(entries) ? entries : [])
    .filter((entry) => !shouldHideSourceSimpleFrameEntry(entry));
}

export function hasSourceBackedModel(model) {
  if (!model || !model.sourceFunction) return false;
  return (Array.isArray(model?.locals) ? model.locals : [])
    .some((local) => normalizeSource(local?.source) === 'source_c');
}

export function shouldHideSourceSimpleFrameEntry(entry) {
  const kind = normalizeEntryKind(entry?.kind);
  if (isProtectedKind(kind) || kind === 'argument' || kind === 'buffer' || kind === 'modified') return false;

  const source = normalizeSource(entry?.source);
  const nameSource = normalizeSource(entry?.nameSource || entry?.preferredNameSource);
  if (source === 'source_c' || nameSource === 'source_c') return false;

  if (kind === 'padding') return true;
  if (entry?.isSynthetic && (kind === 'unknown' || kind === 'slot')) return true;
  return false;
}

export function isSourceAnchoredSeed(seed) {
  if (normalizeSource(seed?.source) !== 'source_c' && normalizeSource(seed?.nameSource) !== 'source_c') {
    return false;
  }
  const confidence = readConfidence(seed?.confidence);
  return confidence === null || confidence >= 0.9;
}
