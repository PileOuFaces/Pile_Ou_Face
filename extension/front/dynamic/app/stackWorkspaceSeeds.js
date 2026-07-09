import {
  doesObservationBelongToFrameScope,
  isSourceAnchoredSeed
} from './stackWorkspaceAnchoring.js';

import {
  classifyObservationSeedKind,
  classifySyntheticObservationKind,
  classifyTrustedSeedKind,
  isStrictStackSeedAllowed,
  resolveRestrictedAbiArgumentName
} from './stackWorkspaceClassification.js';

import {
  compactAdjacentSyntheticBufferEntries,
  compareSeedsForLayout,
  countSeedSupport,
  crossesFrameBase,
  findStructuralGapForObservation,
  isLikelyPointerSpillSeed,
  isObservationCompatible,
  isSeedInsideFrameBounds,
  isWeakStaticSeed,
  mergeCompactedSeeds,
  resolveNormalizedBufferSize,
  seedOffsetRange,
  shouldCompactSeeds,
  shouldDropWeakStaticSeed
} from './stackWorkspaceCompaction.js';

import {
  buildRuntimeEvidence
} from './stackWorkspaceRuntimeEvidence.js';

import {
  mergeSeedContributors,
  normalizeSeedContributors
} from './stackWorkspaceDebug.js';

import {
  SOURCE_PRIORITY,
  areKindsCompatible,
  canonicalSavedBpName,
  clean,
  compareObservationsForSeeding,
  firstNonEmpty,
  hasTrustedDisplayName,
  isGenericName,
  isProtectedKind,
  normalizeEntryKind,
  normalizeSource,
  observationRangeEnd,
  observationRangeStart,
  parseBigIntAddr,
  rangesOverlap,
  readConfidence,
  readNumeric,
  readPositiveInt,
  resolveSourcePriority,
  sameFunction,
  seedRangeEnd,
  seedRangeStart
} from './stackWorkspaceUtils.js';

export function buildControlSeeds({ analysis, bpRegister, bpAddress, wordSize } = {}) {
  const savedBpAddress = parseBigIntAddr(analysis?.control?.savedBpAddr)
    ?? parseBigIntAddr(analysis?.frame?.savedBpAddr)
    ?? bpAddress;
  const retAddress = parseBigIntAddr(analysis?.control?.retAddrAddr)
    ?? parseBigIntAddr(analysis?.frame?.retAddrAddr)
    ?? (savedBpAddress !== null ? savedBpAddress + BigInt(wordSize) : null);

  const seeds = [];
  addSeed(seeds, {
    offset: 0,
    size: wordSize,
    kind: 'saved_bp',
    start: savedBpAddress,
    source: 'control',
    label: canonicalSavedBpName(bpRegister),
    nameSource: 'control',
    confidence: 1,
    isSynthetic: false
  });
  addSeed(seeds, {
    offset: wordSize,
    size: wordSize,
    kind: 'return_address',
    start: retAddress,
    source: 'control',
    label: 'return address',
    nameSource: 'control',
    confidence: 1,
    isSynthetic: false
  });
  return seeds;
}

export function buildReliableStaticSeeds({
  analysis,
  observations,
  model,
  trustedModelSeeds,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta
} = {}) {
  const abiSeeds = buildMainAbiArgumentSeeds({
    analysis,
    model,
    functionName,
    bpRegister,
    bpAddress,
    wordSize,
    meta
  });
  const seeds = mergeSeedLists(trustedModelSeeds, abiSeeds);

  const runtimeCandidates = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => item.offset !== null && item.size > 0)
    .sort(compareObservationsForSeeding);

  runtimeCandidates.forEach((observation) => {
    if (!shouldCreateNamedSeed(observation, functionName, bpRegister, meta)) return;
    if (isCoveredByStableSeedLayout(seeds, observation)) return;
    if (isCoveredByExistingSeed(seeds, observation)) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: false,
      kindOverride: classifyObservationSeedKind(observation, functionName, bpRegister, meta)
    }));
  });

  runtimeCandidates.forEach((observation) => {
    if (!shouldCreateReliableSeed(observation, functionName, bpRegister, meta)) return;
    if (isCoveredByStableSeedLayout(seeds, observation)) return;
    if (isCoveredByExistingSeed(seeds, observation)) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: false,
      kindOverride: classifyObservationSeedKind(observation, functionName, bpRegister, meta)
    }));
  });

  void analysis;
  void wordSize;
  return seeds;
}

export function buildMainAbiArgumentSeeds({ analysis, model, functionName, bpRegister, bpAddress, wordSize, meta } = {}) {
  const isMainFunction = sameFunction(functionName, 'main');
  const is32BitBp = String(bpRegister || '').toLowerCase() === 'ebp' && Number(meta?.arch_bits || 0) === 32;
  if (!isMainFunction || !is32BitBp) return [];

  const existingOffsets = new Set(
    (Array.isArray(model?.locals) ? model.locals : [])
      .map((local) => readNumeric(local?.offset))
      .filter((offset) => Number.isFinite(offset) && offset > 0)
  );
  const seeds = [];
  [
    { offset: 8, label: 'argc', size: 4 },
    { offset: 12, label: 'argv', size: 4 }
  ].forEach((entry) => {
    if (existingOffsets.has(entry.offset)) return;
    addSeed(seeds, {
      offset: entry.offset,
      size: entry.size,
      kind: 'argument',
      start: bpAddress !== null ? bpAddress + BigInt(entry.offset) : null,
      source: 'static',
      label: entry.label,
      nameSource: 'static',
      confidence: 0.92,
      isSynthetic: false
    });
  });
  void analysis;
  void wordSize;
  return seeds;
}

export function buildTrustedModelSeeds({
  model,
  functionName,
  bpRegister,
  bpAddress,
  meta
} = {}) {
  const seeds = [];
  (Array.isArray(model?.locals) ? model.locals : []).forEach((local) => {
    const offset = readNumeric(local?.offset);
    if (offset === null) return;
    const size = readPositiveInt(local?.size) ?? 1;
    const source = normalizeSource(local?.source || 'mcp');
    const kind = classifyTrustedSeedKind({
      rawKind: local?.role,
      label: local?.name,
      typeName: local?.cType,
      offset,
      functionName,
      bpRegister,
      meta,
      source
    });
    if (!isStrictStackSeedAllowed({ offset, kind, functionName, bpRegister, meta })) return;
    addSeed(seeds, {
      offset,
      size,
      kind,
      start: bpAddress !== null ? bpAddress + BigInt(offset) : null,
      source,
      label: clean(local?.name),
      nameSource: source,
      typeName: clean(local?.cType),
      confidence: readConfidence(local?.confidence),
      isSynthetic: false
    });
  });
  return seeds;
}

export function normalizeStaticSeeds({
  seeds,
  observations,
  analysis,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  registerArguments
} = {}) {
  const frameSize = readPositiveInt(analysis?.frame?.frameSize);
  return [...(Array.isArray(seeds) ? seeds : [])]
    .map((seed) => normalizeStaticSeed(seed, {
      observations,
      frameSize,
      functionName,
      bpRegister,
      bpAddress,
      wordSize,
      meta,
      registerArguments
    }))
    .filter(Boolean)
    .sort(compareSeedsForLayout)
    .reduce((acc, seed) => {
      const previous = acc[acc.length - 1];
      if (previous && shouldCompactSeeds(previous, seed)) {
        acc[acc.length - 1] = mergeCompactedSeeds(previous, seed);
        return acc;
      }
      if (shouldDropWeakStaticSeed(seed, acc, observations, frameSize, wordSize)) {
        return acc;
      }
      acc.push(seed);
      return acc;
    }, []);
}

export function normalizeStaticSeed(seed, {
  observations,
  frameSize,
  functionName,
  bpRegister,
  bpAddress,
  wordSize,
  meta,
  registerArguments
} = {}) {
  const normalized = normalizeSeed(seed);
  if (!normalized) return null;
  if (isProtectedKind(normalized.kind)) return normalized;

  const pointerLike = isLikelyPointerSpillSeed(normalized, observations, wordSize, registerArguments);
  const range = seedOffsetRange(normalized);
  if (!range) return null;

  if (pointerLike && !isSourceAnchoredSeed(normalized)) {
    normalized.kind = 'argument';
    normalized.size = wordSize;
    normalized.end = normalized.start !== null ? normalized.start + BigInt(wordSize) : null;
  }

  if (normalized.kind === 'buffer' && !isSourceAnchoredSeed(normalized)) {
    const recoveredSize = resolveNormalizedBufferSize(normalized, observations, frameSize, wordSize);
    if (recoveredSize !== null) {
      normalized.size = recoveredSize;
      normalized.end = normalized.start !== null ? normalized.start + BigInt(recoveredSize) : null;
    }
  }

  if (!isSeedInsideFrameBounds(normalized, frameSize, wordSize)) return null;
  if (crossesFrameBase(normalized) && !pointerLike) return null;

  const supported = countSeedSupport(normalized, observations, {
    functionName,
    bpRegister,
    meta,
    bpAddress
  });
  if (!supported.exact && !supported.named && isWeakStaticSeed(normalized) && normalized.kind !== 'buffer' && normalized.kind !== 'argument') {
    return null;
  }

  return normalized;
}

export function buildSyntheticSeeds({ observations, existingEntries, functionName, bpRegister, bpAddress, meta, frameScope, frameIsReady = true } = {}) {
  // Before the frame is set up, "unmatched observations" are just the raw
  // snapshot.stack memory-window dump (no Evidence backing at all) -- never
  // synthesize seeds from it, regardless of what findStructuralGapForObservation
  // would otherwise accept.
  if (!frameIsReady) return [];
  const seeds = [];
  const candidates = [...(Array.isArray(observations) ? observations : [])]
    .filter((item) => item.offset !== null && item.size > 0)
    .sort(compareObservationsForSeeding);

  candidates.forEach((observation) => {
    if (shouldSuppressSyntheticObservation(observation, existingEntries)) return;
    const gap = findStructuralGapForObservation(observation, existingEntries);
    if (!gap) return;
    if (!doesObservationBelongToFrameScope(observation, frameScope)) return;
    const kind = classifySyntheticObservationKind(observation, functionName, bpRegister, meta, gap);
    if (!kind) return;
    if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return;
    addSeed(seeds, seedFromObservation(observation, bpAddress, {
      synthetic: true,
      kindOverride: kind
    }));
  });

  const entryState = buildRuntimeEvidence({
    seeds,
    observations: candidates
  });
  return compactAdjacentSyntheticBufferEntries(entryState.entries);
}

export function shouldSuppressSyntheticObservation(observation, existingEntries) {
  return (Array.isArray(existingEntries) ? existingEntries : []).some((entry) => {
    if (!entry) return false;
    if (entry?.offset !== null && observation?.offset !== null && entry.offset === observation.offset) return true;
    return rangesOverlap(
      seedRangeStart(entry),
      seedRangeEnd(entry),
      observationRangeStart(observation),
      observationRangeEnd(observation)
    );
  });
}

export function fitsStructuralGap(observation, existingEntries) {
  const gap = findStructuralGapForObservation(observation, existingEntries);
  if (!gap) return false;

  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return false;
  return observationRange.start >= gap.start && observationRange.end <= gap.end;
}

export function seedFromObservation(observation, bpAddress, { synthetic, kindOverride } = {}) {
  const offset = readNumeric(observation?.offset);
  const size = readPositiveInt(observation?.size) ?? 1;
  const start = parseBigIntAddr(observation?.start)
    ?? (bpAddress !== null && offset !== null ? bpAddress + BigInt(offset) : null);
  const source = normalizeSource(observation?.source);
  const kind = normalizeEntryKind(kindOverride || observation?.kind);
  return {
    offset,
    size,
    kind,
    start,
    source,
    label: synthetic ? '' : firstNonEmpty(observation?.modelName, observation?.label),
    nameSource: synthetic ? 'fallback' : normalizeSource(observation?.modelSource || observation?.source),
    typeName: firstNonEmpty(observation?.modelType, observation?.typeName),
    confidence: readConfidence(observation?.modelConfidence) ?? readConfidence(observation?.confidence),
    isSynthetic: Boolean(synthetic),
    // Passthrough only, never derived/defaulted here -- so a reliable
    // backend size verdict already on the observation survives onto the
    // seed for normalizeSeed / applyRecoveredExtentToSeed to see.
    size_exact: observation?.size_exact
  };
}

export function shouldCreateNamedSeed(observation, functionName, bpRegister, meta) {
  if (!observation || observation.offset === null) return false;
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind || kind === 'padding') return false;
  if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return false;
  if (observation.offset > 0) {
    return Boolean(resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta));
  }
  return hasTrustedDisplayName(observation);
}

export function shouldCreateReliableSeed(observation, functionName, bpRegister, meta) {
  if (!observation || observation.offset === null) return false;
  const kind = classifyObservationSeedKind(observation, functionName, bpRegister, meta);
  if (!kind || kind === 'padding') return false;
  if (!isStrictStackSeedAllowed({ offset: observation.offset, kind, functionName, bpRegister, meta })) return false;
  if (observation.offset > 0) {
    return Boolean(resolveRestrictedAbiArgumentName(observation, functionName, bpRegister, meta));
  }
  if (observation.sourcePriority >= SOURCE_PRIORITY.auto) return true;
  if (clean(observation?.modelName)) return true;
  return kind === 'buffer' || kind === 'modified' || kind === 'argument' || kind === 'local';
}

export function isCoveredByExistingSeed(seeds, observation) {
  return (Array.isArray(seeds) ? seeds : []).some((seed) => isObservationCompatible(seed, observation));
}

export function isCoveredByStableSeedLayout(seeds, observation) {
  const observationRange = seedOffsetRange(observation);
  if (!observationRange) return false;
  return (Array.isArray(seeds) ? seeds : []).some((seed) => {
    if (!seed || seed?.isSynthetic) return false;
    const range = seedOffsetRange(seed);
    if (!range) return false;
    if (!isStableGeometrySeed(seed)) return false;
    const exactOffset = readNumeric(seed?.offset) === readNumeric(observation?.offset);
    const contained = observationRange.start >= range.start && observationRange.end <= range.end;
    const overlap = range.start < observationRange.end && observationRange.start < range.end;
    if (exactOffset) return true;
    if (contained && areKindsCompatible(seed?.kind, observation?.kind)) return true;
    return normalizeEntryKind(seed?.kind) === 'buffer' && overlap;
  });
}

export function isStableGeometrySeed(seed) {
  if (isSourceAnchoredSeed(seed)) return true;
  const kind = normalizeEntryKind(seed?.kind);
  if (isProtectedKind(kind)) return true;
  if (kind === 'buffer' || kind === 'argument') return true;
  if (resolveSourcePriority(seed?.source) >= SOURCE_PRIORITY.mcp) return true;
  return Boolean(clean(seed?.label) && !isGenericName(seed?.label));
}

export function mergeSeedLists(...groups) {
  const merged = [];
  groups.forEach((group) => {
    (Array.isArray(group) ? group : []).forEach((seed) => addSeed(merged, seed));
  });
  return merged;
}

export function addSeed(seeds, seed) {
  if (!seed) return;
  const normalized = normalizeSeed(seed);
  if (!normalized) return;
  const existingIndex = (Array.isArray(seeds) ? seeds : []).findIndex((entry) => seedIdentity(entry) === seedIdentity(normalized));
  if (existingIndex < 0) {
    seeds.push(normalized);
    return;
  }
  seeds[existingIndex] = chooseBetterSeed(seeds[existingIndex], normalized);
}

export function normalizeSeed(seed) {
  const offset = readNumeric(seed?.offset);
  const size = readPositiveInt(seed?.size) ?? 1;
  const start = parseBigIntAddr(seed?.start);
  const kind = normalizeEntryKind(seed?.kind);
  if (offset === null && start === null) return null;
  return {
    offset,
    size,
    kind,
    start,
    end: start !== null ? start + BigInt(size) : null,
    source: normalizeSource(seed?.source),
    label: clean(seed?.label),
    nameSource: clean(seed?.nameSource) || normalizeSource(seed?.source),
    typeName: clean(seed?.typeName),
    confidence: readConfidence(seed?.confidence),
    isSynthetic: Boolean(seed?.isSynthetic),
    // Passthrough only -- never derived or defaulted here -- so that a
    // reliable backend role/size verdict already on this seed survives to
    // reach the code (e.g. stackWorkspaceAnchoring.js) deciding whether a
    // heuristic is still allowed to touch it.
    role: seed?.role,
    size_exact: seed?.size_exact,
    seedContributors: normalizeSeedContributors(seed?.seedContributors, {
      offset,
      size,
      kind,
      source: seed?.source,
      label: seed?.label,
      confidence: seed?.confidence,
      isSynthetic: seed?.isSynthetic
    })
  };
}

export function seedIdentity(seed) {
  return [
    normalizeEntryKind(seed?.kind),
    seed?.offset ?? 'none',
    seed?.size ?? 'none',
    seed?.isSynthetic ? 'synthetic' : 'real'
  ].join(':');
}

export function chooseBetterSeed(left, right) {
  const leftProtected = isProtectedKind(left?.kind) ? 1 : 0;
  const rightProtected = isProtectedKind(right?.kind) ? 1 : 0;
  if (rightProtected !== leftProtected) return rightProtected > leftProtected ? right : left;

  const leftSynthetic = left?.isSynthetic ? 1 : 0;
  const rightSynthetic = right?.isSynthetic ? 1 : 0;
  if (leftSynthetic !== rightSynthetic) return rightSynthetic < leftSynthetic ? right : left;

  const leftPriority = resolveSourcePriority(left?.source);
  const rightPriority = resolveSourcePriority(right?.source);
  if (rightPriority > leftPriority) return right;
  if (rightPriority < leftPriority) return left;

  const leftConfidence = Number(left?.confidence || 0);
  const rightConfidence = Number(right?.confidence || 0);
  if (rightConfidence > leftConfidence) return right;
  if (rightConfidence < leftConfidence) return left;

  const winner = String(right?.label || '').length > String(left?.label || '').length ? right : left;
  winner.seedContributors = mergeSeedContributors(left?.seedContributors, right?.seedContributors);
  return winner;
}
